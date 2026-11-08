---
name: attack-saml
description: SAML testing (WSTG/ACS class) — assertion/response handling, ACS URL validation, signature validation, recipient/audience/conditions checks, and replay to reach an authenticated context you should not.
category: web-application
tags: [saml, sso, auth, signature, assertion]
cwe_ids: [CWE-347, CWE-287]
chains_with: [attack-auth-bypass, attack-jwt, attack-open-redirect]
tools: [curl]
version: "1.0"
---

# SAML testing

## Objective
Reach an authenticated context you are not entitled to by manipulating the SAML Response/Assertion the
Service Provider accepts — proven by landing in a session as (or with the rights of) an identity you don't
own, shown before/after the boundary is crossed. Target-facing HTTP goes through the leash:
`tools/leashed.sh $T curl …` (`$T` = target dir). `xmlsec1` is an optional, operator-supplied helper for
offline re-sign/verify — it is not in `bin/`; the flow below is doable with `curl` and manual base64/XML.

## Methodology
1. **Capture the flow.** Intercept AuthnRequest → IdP → the Response POST to the SP's ACS through the
   leash; base64-decode `SAMLResponse` to XML. Record the SP `entityID`, ACS URL, whether the Response,
   the Assertion, or both are signed, and the `NameID`/attribute claims that gate access.
2. **Signature validation.** Strip `<ds:Signature>` and resubmit; then try XML Signature Wrapping — inject
   a second `<Assertion>`/`<Response>` carrying attacker claims while leaving the original signed element
   where the verifier looks but the app reads the forged one. Acceptance of an unsigned or wrapped
   assertion is a signature-validation break (CWE-347).
3. **ACS URL validation.** Tamper `AssertionConsumerServiceURL` in the AuthnRequest and `Destination`/
   `Recipient` in the Response to an attacker URL; a hop that honors it delivers/accepts the assertion off
   the trusted endpoint (token theft / login CSRF) — chain `attack-open-redirect` on a trusted host.
4. **Recipient / Audience / Conditions.** Change `Recipient`, `Audience`, `NotBefore`/`NotOnOrAfter`, and
   `InResponseTo`; an SP that ignores the audience or the validity window accepts a token minted for
   another SP or long expired.
5. **Assertion content.** Retarget `NameID`/role attributes to another user or a privileged group; probe
   canonicalization gaps with comment/XML injection in `NameID` (e.g. `victim@corp<!---->.evil`) where the
   verifier and the parser read different values.
6. **Replay.** Resubmit a previously valid Response; an SP without one-time-use / `InResponseTo` binding
   re-authenticates you. Keep every attempt non-destructive and inside the program's safe-PoC limits.

## What counts as a finding
- **Critical/High:** a tampered, unsigned, wrapped, or replayed assertion the SP accepts, landing you in
  an authenticated session as an identity/role you don't own — before/after proving it (full ATO/admin =
  critical).
- **Lead only:** the SP rejects the tamper, or acceptance yields no session or privilege change — a
  `[UNCONFIRMED CANDIDATE]` per `poc-standard`.

## Evidence
Under `raw/saml/`: the decoded original vs tampered SAML XML, the exact ACS POST that was accepted, the
authenticated response you reached (session/identity proof), a note of which check failed, and a runnable
PoC. All target-facing HTTP goes through `tools/leashed.sh`.
