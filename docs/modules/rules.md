# Module: `rules`

**Purpose:** turn a `Classification` into legally referenced `Finding`s,
using a versioned YAML catalog that a lawyer can review without reading
Python (ADR-0006).

Entry point: `rules.engine.evaluate(bundle, classification, catalog, checks)
-> (findings, planned)`. `pipeline.assess()` wires it with the defaults.

## Components

| File | Responsibility |
|---|---|
| `catalog/catalog_meta.yaml` | Version, law-as-of date, instruments (EUR-Lex ELI), verified references, shared wording, disclaimer |
| `catalog/eprivacy.yaml`, `gdpr.yaml` | Rules: tier, severity, status (automated/manual/planned), legal basis, guidance with pinpoints, explanation templates, remediation hint, review prompt |
| `catalog/manual_items.yaml` | Obligations never observable from a website (always listed, never scored) |
| `catalog_loader.py` | Parse + validate (unknown refs, unverified citations on printed rules, missing templates, duplicate IDs); SHA-256 |
| `engine.py` | Runs checks; policies: unobserved → ERROR, low-confidence FAIL → review, crash → ERROR, Tier M → review |
| `checks/eprivacy.py` | EP-01, 02, 03, 04, 05, 09 |
| `checks/_common.py` | Evidence items and labels |
| `catalog_docs.py` | Generates `docs/legal/rule-catalog.md` (a test keeps it in sync) |

## Contract of a check

```python
def check(ctx: CheckContext) -> CheckResult:
    # ctx.baseline is a COMPLETED S0 session; ctx.classification is ready.
    return CheckResult(
        verdict, confidence, params={...}, template=None, review_reason=None, evidence=(...)
    )
```

- `params` fill the catalog template for the outcome. A missing placeholder
  raises (a programming error, caught by tests).
- MANUAL_REVIEW requires a `review_reason`.
- Checks never write wording; they supply facts.

## Phase 2 checks at a glance

| Rule | FAIL when | Review when | PASS / N/A |
|---|---|---|---|
| EP-01 | a `not_exempt` cookie in S0 | only `unknown`/`conditional` cookies | otherwise; exempt cookies listed |
| EP-02 | a `not_exempt` third-party host in S0 | `conditional` hosts, or unclassified **beacon-like** sites | otherwise; confidence medium if unclassified content hosts remain |
| EP-03 | a `not_exempt` storage key (medium confidence) | unknown keys from third-party origins or identifier-like names; `conditional` | otherwise |
| EP-04 | consent-requiring trackers and no banner (medium) | low-confidence banner, or CMP loaded but nothing visible | PASS with a usable banner; N/A without trackers or banner |
| EP-05 | accept but no reject on the first layer | low-confidence banner, close-only, refusal-like unrecognised label, **pay or consent** | PASS with a reject control; N/A without banner |
| EP-09 | analytics cookie lifetime > 396 days | — | PASS within; N/A without analytics cookies |

## Adding a rule

1. Add it to the YAML with `status: planned` and its citations
   (`verified_on` set only after checking the official source).
2. Write the check, register it in `checks/__init__.py`, switch to
   `status: automated`, add templates.
3. Unit tests for each outcome; a fixture site if it needs the browser;
   `make golden docs`; bump the catalog version.
