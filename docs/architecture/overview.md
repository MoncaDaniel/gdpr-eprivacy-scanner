# Architecture overview

The source of truth for the product scope and the target architecture is the
[MVP design review](../design/0000-mvp-design-review.md). This page describes
**what exists now** (Phase 2) and how it fits that target.

## Data flow (Phase 2)

```
privacy-scanner scan <url>                                   (cli.py)
        │
        ▼
collector.service.collect()                          I/O, no judgement
   1. intake.url.normalize_url / SsrfGuard.check_host   (reject → exit 2)
   2. Chromium; S0 baseline session behind the EgressProxy (ADR-0010, 0011)
   3. capture: cookies (timed), requests, storage, DOM, consent-UI snapshot
      (ADR-0012), screenshot
   4. EvidenceBundle 1.1.0 → <out>/<scan_id>/evidence.json + artefacts
        │
        ▼
pipeline.assess(bundle)                              pure, re-runnable
   classifier.classify   → Classification     knowledge base (ADR-0013)
   rules.engine.evaluate → Findings            YAML catalog (ADR-0006, 0014, 0017)
   scoring.score_all     → score + coverage    (ADR-0015)
        │
        ▼
reporting.write_report → report.json (canonical) + report.html (ADR-0016)

privacy-scanner assess <evidence.json>  = the lower half only: re-judge a
stored scan with the current catalog, without visiting the site.
```

## Module map

| Module | Kind | Doc |
|---|---|---|
| `domain/` | Pure. Evidence, Classification and Report schemas; eTLD+1 semantics | [domain](../modules/domain.md) |
| `intake/` | Pure, except the injectable DNS resolver. URL normalisation, SSRF policy | [intake](../modules/intake.md) |
| `collector/` | I/O. Browser, egress proxy, recorders, capture, artefacts | [collector](../modules/collector.md) |
| `classifier/` | Pure. Knowledge base, categories, CMP and banner detection | [classifier](../modules/classifier.md) |
| `rules/` | Pure. YAML catalog, engine policies, checks | [rules](../modules/rules.md) |
| `scoring/`, `reporting/`, `pipeline.py` | Pure (+ file writing) | [scoring and reporting](../modules/scoring-and-reporting.md) |
| `config.py` | 12-factor settings (`PRIVACY_SCANNER_*`) | [local-dev runbook](../runbooks/local-dev.md) |
| `cli.py` | `scan`, `assess`, `collect`, `version`; exit codes 0/2/3 | [local-dev runbook](../runbooks/local-dev.md) |

Dependency rule: `domain` imports nothing from the project. `classifier`,
`rules`, `scoring`, `reporting` and `pipeline` import `domain` (and each
other, in that order), **never `collector`**, so judgement can run anywhere
without a browser (ADR-0003). Only `cli` wires collection and judgement.

## Still to come (by phase)

S1/S2 sessions, `policy/` (privacy notice, GD-01…GD-12), EP-06/07/08, PDF
(Phase 3); `api/`, `persistence/`, Docker and Cloud Run
(Phase 4); `web/` (Phase 5).
