# targets/

One folder per engagement: `targets/<target>/`. Everything about a target lives here and stays
local (git-ignored except this README) — scope, evidence, findings, synthesized docs.

`/spider <target>` creates and fills it. To start manually, copy the example scope in and go:

```bash
mkdir -p targets/acme
cp docs/scope.example.yaml targets/acme/scope.yaml   # then edit it for your program
# /spider acme
```

Layout (the data contract — see brain/schema.md):

```
targets/<target>/
  scope.yaml     authorized scope + rules (the only authority for what may be touched)
  leash.env      leash config, generated from scope.yaml
  run.json       GO decisions: fleet size, model tier, phases done
  state.json     world model: hosts, services, creds, leads, hypotheses, confirmed, refuted
  findings.jsonl canonical findings (written only by the synthesizer)
  raw/<agent>/   per-agent evidence + result.json
  docs/          01-recon-surface.md · 02-infra-hypotheses.md · 99-infra-final.md
  killchain.md   synthesized attack chain(s)
  report.md      submission-ready report (from /report)
```

**Only run against targets you are authorized to test.** No `scope.yaml`, no run.
