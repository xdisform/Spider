---
name: attack-sqli
description: SQL injection — influence a backend query to read data or the DB banner as proof.
category: web-application
tags: [sqli, injection, database]
cwe_ids: [CWE-89]
tools: [sqlmap, arjun, wafrift, httpx, curl]
version: "1.1"
---

# SQL injection

## Objective
Prove a query is injectable by returning a value only the database can produce — `database()`,
`@@version`, or `current_user` — never a destructive or bulk-dump action.

## Methodology
1. **Find inputs.** Every parameter reaching a query: GET/POST/JSON/headers/cookies. Mine hidden
   ones with `arjun`. Prioritize search, filter, id, sort, and auth fields.
2. **Detect.** Boolean (`' AND 1=1` vs `' AND 1=2`), error-based (broken syntax → DB error),
   time-based (`SLEEP`/`pg_sleep` — small, single), UNION. Confirm the input changes query logic.
3. **Prove.** Extract a banner only: `database()` / `@@version` / `current_user`. That returned
   string is the proof. Use `sqlmap --batch` scoped to the one parameter for confirmation, but keep
   the final PoC to the banner — no dumping, no `--os-shell`, no writing.
4. **Note WAF.** If a WAF is present (from recon `wafw00f`), tampering may be needed; stay in policy.

## Escalation ladder — climb to max impact (do NOT stop at the banner)
A returned banner is the DETECTION oracle, not the ceiling. A senior keeps climbing until the next rung
needs a destructive/persistent action or a safeguard. Prove each rung's PRIMITIVE minimally (policy-safe),
then **mint the capability** so the scheduler unlocks the post-foothold graph. Pick the rung the DB engine
allows (check `@@version`/privileges first):
1. **Read data** (baseline) — `database()`/`@@version`/`current_user`, then a bounded cross-table read that
   proves confidentiality impact (one row of a sensitive table, not a dump).
2. **File read** — MySQL `LOAD_FILE('/etc/hostname')`, MSSQL `OPENROWSET(BULK ...)`, Postgres
   `pg_read_file()`/`COPY ... FROM`. Reading a benign server file = **file-read** primitive → provides
   `foothold:<host>` evidence; also seeds `attack-rce` (read app config/creds).
3. **File write → webshell** — MySQL `INTO OUTFILE`/`INTO DUMPFILE` into a web-served dir, Postgres large
   objects / `COPY ... TO PROGRAM`, MSSQL `sp_OACreate`. Write a minimal in-origin marker, confirm it is
   SERVED (`curl`), then (scope permitting) a one-line shell and run only `whoami`/`id`. Mints `shell:<host>`.
4. **Stacked queries / OS exec** — where the driver allows stacked queries: MSSQL `xp_cmdshell 'whoami'`
   (enable via `sp_configure` ONLY if policy permits), Postgres `COPY ... TO PROGRAM 'id'`, MySQL UDF.
   Command output = RCE oracle → mints `shell:<host>` + `foothold:<host>`; the post-foothold stage
   (internal-recon → privesc → loot → lateral) fires next wave automatically.
5. **Creds → lateral** — a recovered DB/app credential provides `creds:<principal>@<host>` (reuse on other
   in-scope hosts). An `sa`/superuser login is `admin:<host>`.
Honour the safe-PoC limit at EVERY rung (read one benign file, write one marker, run `whoami`). When the
next rung needs a destructive write, a config change the program forbids, or a safeguard — STOP and return
`proven_state:"blocked"` with the exact rung reached; a proven lower rung is still a finding.

## WAF in the way?
If a WAF blocks the injection, mutate the payload through `bin/wafrift` before giving up:
`tools/leashed.sh $T bin/wafrift scan --target "$U" --param <p> --payload "' UNION SELECT @@version-- -" --format json -o raw/<label>/wafrift.json` — it ladders encodings/grammars/content-type until one passes, then feed the winning pipeline back into sqlmap (`--tamper`) or hand-craft it. Stay within rate caps.

## What counts as a finding
- **Critical/High:** the DB banner/user returned via injection — proven, reproducible. **Critical** when the
  ladder reaches file-write-to-webshell / `xp_cmdshell`/`COPY TO PROGRAM` command output (RCE) or a sensitive
  cross-table read proving mass data exposure.
- **Lead only:** anomalous behavior (timing/errors) without a returned DB value.

## Evidence
The injecting request and the response containing the DB string, plus a minimal reproducible PoC,
under `raw/<label>/`. Respect the program's SQLi safe-PoC limit exactly.
