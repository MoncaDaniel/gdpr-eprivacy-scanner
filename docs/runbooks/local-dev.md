# Runbook: local development

## Prerequisites

- [uv](https://docs.astral.sh/uv/) (it manages Python 3.12 from `.python-version`)
- Chromium for Playwright: `make browsers` (on a fresh Linux/WSL host, also
  `uv run playwright install-deps chromium`, which needs sudo)

## Setup

```bash
make install     # uv sync --all-groups
make browsers    # playwright install chromium
make check       # lint + types + all tests
```

## Run a scan

```bash
uv run privacy-scanner collect https://www.cnil.fr          # summary tables
uv run privacy-scanner collect example.fr --json > bundle.json
uv run privacy-scanner collect https://www.lemonde.fr -o /tmp/scans --observe 10 -v
```

Each scan writes `<out>/<scan_id>/evidence.json` plus artefacts (`s0_baseline/`
DOMs and the screenshot).

| Exit code | Meaning |
|---|---|
| 0 | Evidence collected, page observed |
| 2 | Input refused (invalid URL or forbidden destination). Nothing was fetched |
| 3 | Collection ran, but the page could not be observed (blocked / obstructed / failed) |

## Configuration

Environment variables with the prefix `PRIVACY_SCANNER_` (see `config.py`):

| Variable | Default | Notes |
|---|---|---|
| `VANTAGE_POINT` | `local` | Printed in every bundle. Prod: `gcp:europe-west9 (Paris, FR)` |
| `LOCALE` / `TIMEZONE` / `ACCEPT_LANGUAGE` | `fr-FR` / `Europe/Paris` / `fr-FR,fr;q=0.9,en;q=0.8` | First-time FR visitor |
| `VIEWPORT_WIDTH` / `VIEWPORT_HEIGHT` | 1366 / 768 | |
| `NAVIGATION_TIMEOUT_S` | 30 | |
| `NETWORK_IDLE_TIMEOUT_S` | 10 | 0 disables the wait |
| `OBSERVATION_WINDOW_S` | 6 | Also `--observe` |
| `COOKIE_POLL_INTERVAL_S` | 0.25 | |
| `MAX_REQUESTS_PER_SESSION` / `MAX_DOM_BYTES` / `MAX_FRAMES` | 3000 / 5 MB / 50 | |
| `HEADLESS` | true | |
| `EXTRA_CHROMIUM_ARGS` | — | Space-separated |
| `ALLOWED_PORTS` | `80,443` | `any` for tests only |
| `ALLOW_LOOPBACK` | false | **Tests only. Never in production** |
| `OUTPUT_DIR` | `scans` | Also `--out` |

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Executable doesn't exist at …/chromium` | `make browsers` |
| `error while loading shared libraries` | `uv run playwright install-deps chromium` |
| Every scan `obstructed` with a provider name | Your IP is challenged by that bot-protection vendor. Expected for some sites (ADR-0010) |
| `Refused: … resolves to 10.x` | Corporate DNS or VPN returns private addresses. Working as intended |
