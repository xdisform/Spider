# Security & responsible use

Spider is an **authorized-security-testing** orchestrator. It automates the work of a
bug-bounty / penetration-testing engagement you are **already cleared to perform**. It is
not a tool for unauthorized access, and it is built to refuse to run without an explicit,
operator-attested scope and a human GO.

## Authorized use only

Use Spider **only** against assets you are permitted to test:

- public or private/invite-only **bug-bounty programs** you are enrolled in, within that
  program's published scope and rules;
- systems you are **contracted** to assess, with written authorization;
- **CTFs**, labs, and targets **you own**.

Every engagement is defined by a `targets/<target>/scope.yaml` that transcribes the
program's own in-scope list, required header, rate cap, safe-PoC limits, and forbidden
techniques. The `researcher` field attests that the operator is cleared for that scope.
**You are the accountable party for that attestation.** Testing anything the program marks
out of scope — or any asset you are not authorized to test — is unauthorized access
regardless of what the YAML says.

## Controls that stay on

- **One human GO** before the first live packet, per target.
- The **scope leash** (`tools/leash.py`) tags every HTTP request with the program header,
  returns 403 for off-scope hosts, enforces a global rate cap, and fails closed.
- Non-HTTP tools are host/CIDR-pinned by the **guard** (`tools/guard.py`).
- No destructive, denial-of-service, brute-force-of-others, social-engineering, or physical
  actions — ever, regardless of scope.
- Findings must be **proven** (oracle-validated), not asserted; safe-PoC limits are honored.

> Note on enforcement: the GO gate and leash **routing** are currently enforced by operator
> and orchestrator discipline (the leash is applied per-command via `tools/leashed.sh`), not
> by a kernel-level egress lock. Treat the leash as a strong convention and verify the audit
> log (`raw/leash.jsonl`) proves in-scope traffic before trusting a run.

## Do not commit engagement data

`targets/` (real scope, evidence, findings) and `bin/` (the arsenal) are git-ignored and
must **never** be published. A `.githooks/pre-commit` guard blocks accidental staging of
them; install it with `git config core.hooksPath .githooks`.

## Reporting an issue with Spider itself

If you find a security or safety defect in Spider (e.g. a way the leash can be bypassed, or
scope enforcement fails open), please open a private report to the maintainers rather than a
public issue. Do not include any real target's data in the report.
