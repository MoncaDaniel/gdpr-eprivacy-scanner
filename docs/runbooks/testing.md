# Runbook: testing

```bash
make test               # everything
make test-unit          # pure modules, < 1 s, no browser
make test-integration   # real Chromium against hermetic fixture sites (~35 s)
make cov                # with branch coverage
```

## Layout

| Path | What |
|---|---|
| `tests/unit/` | URL intake, SSRF policy, egress proxy, obstruction signatures, fingerprints, artefact store, sites, CLI exit codes |
| `tests/integration/` | S0 end to end. Marked `integration` |
| `tests/fixtures/server.py` | One loopback HTTP server answering for virtual hosts `site.test`, `tracker.test`, `widget.test` |
| `tests/fixtures/sites/<host>/` | Static fixture pages. `{{PORT}}` is replaced at serve time |

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
2. Assert on the `SessionEvidence` in `test_baseline_session.py`. Assert
   facts, not judgements.

## Quality gates (CI)

`ruff check`, `ruff format --check`, `mypy --strict` (on `src/`), and the
full test suite. Coverage is reported. The target is ≥ 90 % on pure modules
(design review §3.3).
