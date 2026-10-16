# GDPR + ePrivacy Website Scanner

**Evidence-based website privacy scanner.** It visits a page the way a
first-time EU visitor's browser would, records what the site stores on the
device and which servers it contacts **before any consent**, and produces a
report in which every finding traces back to that evidence and to a specific
provision of the ePrivacy Directive or the GDPR.

> Technical observation, not legal advice. The scanner never says "compliant":
> not detecting an issue is not the same as compliance
> ([ADR-0004](docs/adr/0004-verdict-vocabulary.md)).

**Status: Phase 2 of 6 complete:** classification, ePrivacy rules, scoring
and a self-contained HTML report. See the
[design review](docs/design/0000-mvp-design-review.md) for the full plan.

## What it does today

```console
$ privacy-scanner scan https://www.example.fr
╭──────────── Website Privacy Exposure Score ─────────────╮
│ ePrivacy Directive  62 / 100, based on 5 of 11 checks │
│ GDPR                not scored, based on 0 of 13 checks │
╰─────────────────────────────────────────────────────────╯
EP-01  No non-essential cookies before consent        Issue detected
EP-02  No third-party tracking requests before consent No issue detected
EP-04  Consent mechanism present when trackers are used No issue detected
EP-05  Reject option on the first layer of the banner  Issue detected
EP-09  Audience-measurement cookie lifetime ≤ 13 months Not applicable
EP-10  No cookie wall                                   Review suggested (not automatable)
Report: scans/<scan_id>/report.html
```

1. **Observe:** session S0 records cookies (with the moment each appeared),
   every request, Web Storage, the DOM, the visible consent banner and its
   buttons (label, size, colours), and a screenshot. Values are stored only
   as keyed fingerprints. This is the immutable **Evidence Bundle**.
2. **Classify:** a curated, sourced knowledge base plus the Apache-2.0 Open
   Cookie Database label each cookie, key and host (analytics, marketing,
   strictly necessary…) with an exemption status. CMPs (Didomi, OneTrust,
   Axeptio, Usercentrics, Sourcepoint…) and the banner's
   accept/reject/settings controls are recognised in FR/EN/ES/DE.
3. **Judge:** a versioned YAML [rule catalog](docs/legal/rule-catalog.md)
   (EP-01/02/03/04/05/09 automated in this phase) produces findings with the
   binding provision, interpretive sources (EDPB, CJEU, CNIL, tagged EU/FR,
   each verified against the official text), the evidence, and a confidence.
4. **Report:** `report.json` (canonical) and a single-file `report.html` that
   loads nothing from the network, works at 390 px, and states its coverage,
   catalog hash and limitations.

`privacy-scanner assess evidence.json` re-judges a stored scan against the
current catalog **without visiting the site again**.

## Engineering highlights

- **Evidence/judgement split** ([ADR-0003](docs/adr/0003-evidence-judgement-separation.md)):
  the collector makes no legal claims. Classification, rules and scoring are
  pure functions over stored bundles (enforced by an architecture test), so
  old scans can be re-judged against a newer rule catalog.
- **Legally honest by construction:** no "compliant" anywhere (tested), a
  score always shown with its coverage, low-confidence findings downgraded to
  "Review suggested", unknown cookies never assumed harmless, "pay or
  consent" walls left to human judgement
  ([ADR-0014](docs/adr/0014-review-reasons-and-confidence.md)). Citations are
  verified against primary sources, and the catalog loader refuses
  unverified ones; verifying them narrowed two rules
  ([ADR-0017](docs/adr/0017-legal-scope-corrections.md)).
- **SSRF defence in depth for a browser pointed at user URLs**
  ([security](docs/architecture/security.md)). A per-session egress proxy is
  Chromium's only network exit *and* its only DNS resolver: every connection,
  including redirect hops that Playwright's request interception never sees,
  is checked and pinned to a vetted address
  ([ADR-0011](docs/adr/0011-egress-proxy.md)).
- **An honest browser** ([ADR-0010](docs/adr/0010-s0-baseline-protocol.md)): a
  realistic FR desktop profile, no stealth tricks. Bot challenges are reported
  as such, never analysed as if they were the site.
- **Hermetic tests:** a real Chromium against multi-host fixture sites, one
  per violation pattern (hidden second layer, banner in a shadow root or a
  cross-origin iframe, close-only, unknown cookie…). The guard's injected
  resolver is the whole DNS of the test world, so no test touches the
  internet. Golden tests pin the judgement of recorded bundles.

## Quick start

```bash
make install browsers
make check                                   # ruff, mypy --strict, pytest
uv run privacy-scanner scan https://www.cnil.fr
```

Exit codes: `0` observed and reported, `2` input refused, `3` page not
observable (blocked/obstructed/failed; the report says so and gives no score). More in the [local-dev runbook](docs/runbooks/local-dev.md).

## Documentation

| | |
|---|---|
| Design review (scope, debate, rule tiers, risks, plan) | [docs/design/0000-mvp-design-review.md](docs/design/0000-mvp-design-review.md) |
| Architecture overview | [docs/architecture/overview.md](docs/architecture/overview.md) |
| Security architecture / threat model | [docs/architecture/security.md](docs/architecture/security.md) |
| Decisions | [docs/adr/](docs/adr/README.md) |
| Legal: methodology, rule catalog, sources | [methodology](docs/legal/methodology.md) · [rule catalog](docs/legal/rule-catalog.md) · [sources and verification log](docs/legal/sources.md) |
| Modules | [domain](docs/modules/domain.md) · [intake](docs/modules/intake.md) · [collector](docs/modules/collector.md) · [classifier](docs/modules/classifier.md) · [rules](docs/modules/rules.md) · [scoring and reporting](docs/modules/scoring-and-reporting.md) |
| Runbooks | [local dev](docs/runbooks/local-dev.md) · [testing](docs/runbooks/testing.md) |
| Changelog | [docs/CHANGELOG.md](docs/CHANGELOG.md) |

## Roadmap

1. ✅ Foundations + evidence collector (S0)
2. ✅ Classification, ePrivacy rules, scoring, HTML report
3. Reject/accept sessions (S1/S2), privacy-notice analysis (GDPR Art. 13), PDF
4. FastAPI async API, persistence, Cloud Run `europe-west9` (Paris)
5. Next.js frontend
6. (Optional) LLM-assisted notice analysis with verified quotes

## Stack

Python 3.12 · Playwright/Chromium · Pydantic v2 · Jinja2 · PyYAML · Typer · uv · ruff · mypy (strict) · pytest

## License

MIT. The vendored Open Cookie Database snapshot is Apache-2.0
(`src/privacy_scanner/classifier/data/third_party/`).
