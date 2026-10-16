# Modules: `scoring`, `reporting`, `pipeline`

## `pipeline.assess(bundle, *, catalog=None, knowledge_base=None, now=None) -> Report`

Pure orchestration: classify → evaluate → score → `Report`. It never touches
the network, so `privacy-scanner assess evidence.json` re-judges a stored scan
against the current catalog and knowledge base (ADR-0003).

## `scoring.scorer`

Severity-weighted score and coverage per regulation (ADR-0015). The score is
`null` when no check produced PASS/FAIL.

## `reporting.render`

| Function | Output |
|---|---|
| `write_report(report, directory)` | `report.json` (canonical) + `report.html` next to the bundle; embeds the S0 screenshot if it lies inside `directory` |
| `render_html(report, screenshot_png=None, *, expand_all=False)` | Self-contained HTML (ADR-0016); `expand_all` for print/PDF |

Template: `reporting/templates/report.html.j2`, Meridian palette, system
fonts, no scripts, CSP `default-src 'none'`.

## Report sections

Header (page, address, time, vantage, catalog) → disclaimer → score cards with
coverage and verdict counts → first-screen screenshot and "before consent"
summary → findings (issues first, open) with legal basis, interpretation
(jurisdiction, binding or not), evidence, hint or review prompt → not yet
evaluated → always manual → inventory (cookies, third parties, storage) →
method and reproducibility (catalog and knowledge-base hashes, OCD commit,
browser, locale) → limitations.

## Tests

`tests/unit/test_scoring_and_reporting.py`: formula, banned vocabulary in
every output and source, no external fetches, HTML escaping of page text,
issue ordering, screenshot containment. `tests/golden/`: recorded bundles →
expected judgement (`make golden` after an intended change).
