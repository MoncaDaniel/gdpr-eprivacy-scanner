# GDPR + ePrivacy Website Scanner

**Evidence-based website privacy scanner.** It visits a page the way a
first-time EU visitor's browser would, and records what the site stores on
the device and which servers it contacts **before any consent**. The aim is
for every future finding to trace back to that evidence and to a specific
provision of the ePrivacy Directive or the GDPR.

> Technical observation, not legal advice. The scanner never says "compliant":
> not detecting an issue is not the same as compliance
> ([ADR-0004](docs/adr/0004-verdict-vocabulary.md)).

**Status: Phase 1 of 6 (evidence collector) complete.** See the
[design review](docs/design/0000-mvp-design-review.md) for the full plan.

## What it does today

```console
$ privacy-scanner collect https://www.lemonde.fr
╭─────────────── Session S0 — before any consent ───────────────╮
│ Outcome     completed                                         │
│ Observed    6.5s after load, no interaction                   │
│ Vantage     local · fr-FR · Chromium                          │
╰───────────────────────────────────────────────────────────────╯
Cookies stored (10)  … name, domain, first/third party, lifetime, first seen
Sites contacted (6, of which 5 third-party)  … per site, request types, first at
```

Each scan writes an immutable **Evidence Bundle** (`evidence.json` +
DOM/screenshot artefacts). It records cookies with the moment they first
appeared, every network request including those our guard refused, Web
Storage per origin (including third-party frames), the DOM with open shadow
roots, and the full browser environment, so the scan can be reproduced and
re-judged later. Cookie and storage values are kept only as keyed
fingerprints, never in clear.

## Engineering highlights

- **Evidence/judgement split** ([ADR-0003](docs/adr/0003-evidence-judgement-separation.md)):
  the collector makes no legal claims. Rules (Phase 2) are pure functions over
  stored bundles, so old scans can be re-judged against a newer rule catalog.
- **SSRF defence in depth for a browser pointed at user URLs**
  ([security](docs/architecture/security.md)). A per-session egress proxy is
  Chromium's only network exit *and* its only DNS resolver: every connection,
  including redirect hops that Playwright's request interception never sees,
  is checked and pinned to a vetted address
  ([ADR-0011](docs/adr/0011-egress-proxy.md)).
- **An honest browser** ([ADR-0010](docs/adr/0010-s0-baseline-protocol.md)): a
  realistic FR desktop profile, no stealth tricks. Bot challenges are reported
  as such, never analysed as if they were the site.
- **Hermetic tests:** a real Chromium against multi-host fixture sites. The
  guard's injected resolver is the whole DNS of the test world, so no test
  touches the internet.

## Quick start

```bash
make install browsers
make check                                   # ruff, mypy --strict, pytest
uv run privacy-scanner collect https://www.cnil.fr
```

Exit codes: `0` observed, `2` input refused, `3` page not observable
(blocked/obstructed/failed). More in the [local-dev runbook](docs/runbooks/local-dev.md).

## Documentation

| | |
|---|---|
| Design review (scope, debate, rule tiers, risks, plan) | [docs/design/0000-mvp-design-review.md](docs/design/0000-mvp-design-review.md) |
| Architecture overview | [docs/architecture/overview.md](docs/architecture/overview.md) |
| Security architecture / threat model | [docs/architecture/security.md](docs/architecture/security.md) |
| Decisions | [docs/adr/](docs/adr/README.md) |
| Modules | [domain](docs/modules/domain.md) · [intake](docs/modules/intake.md) · [collector](docs/modules/collector.md) |
| Runbooks | [local dev](docs/runbooks/local-dev.md) · [testing](docs/runbooks/testing.md) |
| Changelog | [docs/CHANGELOG.md](docs/CHANGELOG.md) |

## Roadmap

1. ✅ Foundations + evidence collector (S0)
2. Classification, ePrivacy rules, scoring, HTML report
3. Reject/accept sessions (S1/S2), privacy-notice analysis (GDPR Art. 13), PDF
4. FastAPI async API, persistence, Cloud Run `europe-west9` (Paris)
5. Next.js frontend
6. (Optional) LLM-assisted notice analysis with verified quotes

## Stack

Python 3.12 · Playwright/Chromium · Pydantic v2 · Typer · uv · ruff · mypy (strict) · pytest

## License

MIT
