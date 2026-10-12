# Module: `domain`

**Purpose:** the vocabulary every other module speaks. It has no I/O and no
project imports.

## `domain/evidence.py`: the Evidence Bundle (schema `1.0.0`)

The collector's only output and the rules engine's only input (ADR-0003).

| Model | Holds |
|---|---|
| `EvidenceBundle` | `scan_id`, `scanner_version`, `created_at`, `target`, `environment`, `sessions[]` |
| `BrowserEnvironment` | Engine/version, UA, viewport, locale, timezone, `Accept-Language`, headless, `vantage_point`: everything that can change a site's behaviour |
| `SessionEvidence` | `kind` (S0/S1/S2), `outcome`, timings, `navigation`, `obstruction`, `cookies`, `requests`, `storage`, `frames`, `screenshot`, `guard_violations` |
| `CookieRecord` | Attributes as stored, `value` fingerprint, `lifetime_seconds`, `first_observed_ms` |
| `RequestRecord` | Issue `sequence`, URL, type, timing, frame, redirect origin, `status`, `server_ip` (from the egress proxy), `failure`, `blocked_by` |
| `StorageRecord` | Origin, area, key, `value` fingerprint |
| `FrameRecord` / `ArtifactRef` | DOM snapshot reference (path, media type, SHA-256, size) |

**Invariants**

- All models are frozen and reject unknown fields (`extra="forbid"`).
- In-session times are integer ms since navigation start (`*_ms`). Absolute
  times are UTC-aware.
- Values are never stored in clear, only as `ValueFingerprint` (ADR-0008).
- `SessionOutcome`: `completed` | `obstructed` (challenge or HTTP error page) |
  `blocked` (network policy) | `failed` (timeout, DNS, crash). Only
  `completed` sessions are judgeable.

**Versioning:** `SCHEMA_VERSION` follows SemVer. Removing or renaming a field,
or changing its meaning, bumps MAJOR. Adding an optional field bumps MINOR.

## `domain/sites.py`: first vs. third party

`registrable_domain(host)` gives the eTLD+1 using the **bundled** Public Suffix
List snapshot (private section included, as browsers use it). The list is never
fetched at runtime, so results are reproducible and work offline. IP literals
are returned as they are. `same_site(a, b)` compares registrable domains.

"Third party" here is a technical fact about domains, **not** a legal
classification.

## Tests

`tests/unit/test_sites.py`; the bundle schema is exercised end to end by
`tests/integration/test_baseline_session.py::test_bundle_on_disk_round_trips_and_records_environment`.
