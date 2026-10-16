# ADR-0015: Score and coverage definitions

- **Status:** Accepted
- **Date:** 2026-10-16
- **Source:** design review §2.3

## Decision

Per regulation:

```
score    = round(100 × Σ w(PASS) / Σ w(PASS ∪ FAIL))      w: high 5, medium 3, low 1
coverage = |PASS ∪ FAIL| / |rules catalogued for the regulation|
```

- The coverage denominator includes **every** catalogued rule: automated,
  manual (Tier M) and **planned** (not yet implemented). A version that
  implements fewer checks therefore shows lower coverage, instead of a high
  score on a silently reduced base.
- No score (`null`, shown "Not scored") when nothing produced PASS or FAIL,
  for example GDPR in Phase 2, or any page that could not be observed.
- The "always manual" items (Art. 30, 35, 28 …) are not catalogued checks.
  They are listed, never counted.
- The report always shows counts per verdict and "not yet evaluated" next to
  the score, and the formula on the page.

## Consequences

Phase 2 reports read "ePrivacy Directive: N / 100, based on at most 5 of 11
catalogued checks; GDPR: Not scored, based on 0 of 13". Coverage rises as
phases land, and the history of a site's reports cannot be misread as "it
got better" when only the catalog grew.
