---
description: Re-run recon + attack on a target from scratch but WITH full prior context — unwind everything the last run left open.
argument-hint: <target>
---

Re-run Spider deeper on: **$ARGUMENTS**

This is a fresh cycle **seeded with everything already known** about the target — it does not
restart from zero. Read `brain/spider.md` and follow the cycle, with these differences:

1. **Load the world.** Read `targets/<target>/state.json`, `docs/99-infra-final.md`, `killchain.md`
   and the open `leads`/`hypotheses`. This is the seed.
2. **Confirm scope + GO.** Scope is unchanged, but still confirm and get GO (fleet + model tier may
   be re-picked). No live traffic before GO.
3. **Recon-2 (deep), seeded.** Skip the broad recon-1 — go straight to `workflows/recon-2.mjs`
   seeded with the prior state, aimed at the open leads and unproven hypotheses. Synthesize an
   updated `docs/02-infra-hypotheses.md`.
4. **Attack, seeded.** Launch `workflows/attack.mjs` on the refreshed hypotheses + every open lead,
   pushing each toward proven impact. Re-synthesize `killchain.md` + `docs/99-infra-final.md`.
5. **Report the delta.** What's newly proven, what moved, what's still stuck. Then offer
   `/report`, `/triage`, or another `/again`.

Never restart context you already have. Never touch anything outside `scope.yaml`.
