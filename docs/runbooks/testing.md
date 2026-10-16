# Runbook: testing

```bash
make test               # everything
make test-unit          # pure modules + golden reports, ~2 s, no browser
make test-integration   # real Chromium against hermetic fixture sites (~80 s)
make golden             # regenerate golden reports after an intended change
make cov                # with branch coverage
```

## Layout

| Path | What |
|---|---|
| `tests/unit/` | Intake, SSRF, egress, obstruction, fingerprints, sites, CLI; knowledge base, classifier, every check outcome, engine policies, catalog integrity, scoring, rendering (vocabulary, no external fetches, escaping) |
| `tests/builders.py` | Evidence Bundle builders for pure tests (no browser) |
| `tests/integration/` | S0 collection and full assessment against fixture sites. Marked `integration` |
| `tests/golden/` | Recorded bundles (`tests/fixtures/evidence/`) → expected judgement JSON |
| `tests/fixtures/server.py` | One loopback HTTP server answering for virtual hosts `site.test`, `tracker.test`, `widget.test`, `cmp.test` |
| `tests/fixtures/sites/<host>/` | One page per pattern: clean, consent-first, tracking, no-reject (hidden 2nd layer), no-banner, iframe-banner, shadow-banner, close-only, unknown-cookie |
| `tests/fixtures/kb/` | Knowledge-base overlay classifying the fixture hosts (packaged data is never edited for tests) |

## How the hermetic network works

Integration tests inject a resolver into `SsrfGuard` that maps `*.test` to
`127.0.0.1` and fails everything else. Since the session's egress proxy is
the browser's only resolver (ADR-0011), that resolver is the **entire DNS of
the test world**. No test touches the internet. Tests relax the policy with
`allow_loopback=True` and any port, but link-local and private ranges stay
blocked, which is what the metadata and private-subresource tests rely on.

## Adding a fixture scenario

1. Add a page under `tests/fixtures/sites/<host>/`, or a dynamic reply
   (status, headers, redirect) to `_DYNAMIC` in `server.py`.
2. Collector facts go in `test_baseline_session.py`; expected verdicts in
   `test_assessment.py`.
3. For a golden case, add the page to `tests/fixtures/record_evidence.py`,
   run `uv run python -m tests.fixtures.record_evidence`, then `make golden`
   and review the diff.

## Quality gates (CI)

`ruff check`, `ruff format --check`, `mypy --strict` (on `src/`), and the
full test suite. Coverage is reported. The target is ≥ 90 % on pure modules
(design review §3.3).
