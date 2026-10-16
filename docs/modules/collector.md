# Module: `collector`

**Purpose:** observe what a page does on a first-time visitor's device, and
record it as an Evidence Bundle. It contains **no legal logic** (ADR-0003).

Public entry point: `collector.service.collect(url, settings, *, guard=None,
scan_id=None) -> CollectionResult`. It owns the Playwright and browser
lifecycle.

## Components

| File | Responsibility |
|---|---|
| `service.py` | Normalise, pre-flight guard check, launch browser, run sessions, persist bundle |
| `browser.py` | Launch flags (WebRTC lockdown, no background networking); honest desktop FR profile; isolated context **behind the session's proxy** |
| `egress.py` | `EgressProxy`: the session's only network exit and DNS resolver (ADR-0011). `EgressLog` records every decision |
| `sessions.py` | S0 protocol (ADR-0010). Outcome: completed / obstructed / blocked / failed |
| `network.py` | `NetworkRecorder`: route-level guard check for attribution, request/response/failure events, joined with the `EgressLog` for `server_ip` and proxy refusals |
| `cookies.py` | Polls the cookie jar so each cookie gets `first_observed_ms`. Keeps cookies that were set and then deleted |
| `capture.py` | Web Storage per origin (including third-party frames), DOM per frame with open shadow roots, **consent-UI snapshot** (visible overlay layers and their controls with geometry and computed colours, ADR-0012), viewport screenshot |
| `scripts/scan_consent_ui.js` | Read-only in-page script behind the consent-UI snapshot |
| `obstruction.py` | Pure recognition of bot challenges and HTTP error pages |
| `fingerprint.py` | Keyed HMAC value fingerprints (ADR-0008) |
| `artifacts.py` | `ArtifactStore` port and the local filesystem adapter (object storage in Phase 4) |
| `summary.py` | Factual digest for display: contacts grouped by site, first/third party |

## S0 timeline

```
t=0 navigate ─► domcontentloaded ─► load ─► network idle (≤10 s, best effort) ─► observe 6 s ─► capture
     └──────────── cookie jar polled every 250 ms throughout ────────────────────────────┘
```

## Failure modes

| Situation | Outcome | Evidence kept |
|---|---|---|
| Navigation refused by the guard (including a redirect hop) | `blocked`; `error` names the address | Requests with `blocked_by` |
| Peer address fails the post-connect re-check | `blocked` | `guard_violations` |
| Challenge page / HTTP ≥ 400 | `obstructed` | Full capture (so a human can see it) |
| Timeout, DNS failure, browser error | `failed` | Whatever was recorded |
| More than `max_requests_per_session` | Continues | `requests_dropped` count |

## Configuration

All `PRIVACY_SCANNER_*` settings are listed in the
[local-dev runbook](../runbooks/local-dev.md#configuration).

## Tests

`tests/integration/test_baseline_session.py` runs a real Chromium against
hermetic multi-host fixture sites (`tests/fixtures/`). Unit tests cover
`egress`, `obstruction`, `fingerprint` and `artifacts`.

## Known limitations (also stated in reports)

- One page load, one vantage point, no interaction. Scroll- or click-triggered
  tracking is not in S0.
- Cookie `first_observed_ms` is an upper bound, accurate to the poll interval.
- Closed shadow roots and cross-origin frames beyond `max_frames` are not captured.
- The consent-UI snapshot sees `button`/link/`role=button`/`onclick` controls;
  banners drawn on canvas or as images, or with role-less clickable `div`s,
  are missed.
- Browser fingerprinting (canvas, WebGL, audio) is not detected (design review §2.5).
- With a proxy configured Chromium does not use HTTP/3 (ADR-0011).
