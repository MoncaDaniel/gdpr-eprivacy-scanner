# ADR-0004: Verdict vocabulary avoids "compliant"

- **Status:** Accepted
- **Date:** 2026-10-12
- **Source:** Design review §2.0, §2.3

## Context

Most GDPR obligations (Art. 28, 30, 32, 35, the validity of legal bases) are
invisible from outside the organisation. A label such as "GDPR: 82% compliant"
overclaims, and it is the first thing a privacy lawyer would attack (risk R9).

## Decision

Verdicts are `PASS` ("No issue detected"), `FAIL` ("Issue detected"),
`MANUAL_REVIEW` ("Review suggested", with a reason), `NOT_APPLICABLE` and
`ERROR`. The words "compliant" and "non-compliant", grade letters and "X%
compliant" never appear in any output. Scores are always shown next to their
**coverage** ("based on 9 of 11 checks"). A low-confidence `FAIL` is downgraded
to `MANUAL_REVIEW`.

## Consequences

- This departs from the original brief's "compliant / non-compliant" wording, on purpose.
- Reporting templates are tested for the banned vocabulary (Phase 2).
