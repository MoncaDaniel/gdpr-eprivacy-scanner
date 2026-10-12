# Architecture overview

The source of truth for the product scope and the target architecture is the
[MVP design review](../design/0000-mvp-design-review.md). This page describes
**what exists now** (Phase 1) and how it fits that target.

## Phase 1 data flow

```
privacy-scanner collect <url>                    (cli.py)
        │
        ▼
collector.service.collect()
   1. intake.url.normalize_url        → NormalizedUrl     (raises InvalidUrlError)
   2. SsrfGuard.check_host            → GuardDecision     (raises TargetRejectedError)
   3. launch Chromium
   4. sessions.run_baseline_session (S0)
        ├─ EgressProxy (127.0.0.1:ephemeral)  ← every connection, guard-checked
        ├─ isolated BrowserContext (proxy, no SW, FR desktop profile)
        ├─ NetworkRecorder  (route attribution + request/response events + EgressLog)
        ├─ CookieJarObserver (polls jar → first_observed_ms)
        ├─ navigate → load → network idle (best effort) → observation window
        └─ capture: storage, frames' DOM (incl. open shadow roots), screenshot
   5. EvidenceBundle (frozen Pydantic) → <out>/<scan_id>/evidence.json + artefacts
        │
        ▼
collector.summary.digest()  → factual table rendering (no judgement)
```

## Module map (Phase 1)

| Module | Kind | Doc |
|---|---|---|
| `domain/` | Pure. Evidence Bundle schema, site (eTLD+1) semantics | [domain](../modules/domain.md) |
| `intake/` | Pure, except the injectable DNS resolver. URL normalisation, SSRF policy | [intake](../modules/intake.md) |
| `collector/` | I/O. Browser, egress proxy, recorders, capture, persistence of artefacts | [collector](../modules/collector.md) |
| `config.py` | 12-factor settings (`PRIVACY_SCANNER_*`) | [local-dev runbook](../runbooks/local-dev.md) |
| `cli.py` | Typer CLI, exit codes 0/2/3 | [local-dev runbook](../runbooks/local-dev.md) |

Dependency rule: `domain` imports nothing from the project. `intake` imports
`domain`. `collector` imports both. Later modules (`classifier`, `rules`,
`scoring`) will consume `domain` only, never `collector` (ADR-0003).

## Still to come (by phase)

`classifier/`, `rules/`, `scoring/`, `reporting/` (Phase 2); S1/S2 sessions,
`policy/`, PDF (Phase 3); `api/`, `persistence/`, Docker and Cloud Run
(Phase 4); `web/` (Phase 5).
