# ADR-0016: Self-contained HTML report, JSON canonical

- **Status:** Accepted
- **Date:** 2026-10-16
- **Source:** design review §2.3, §2.4 (PDF via Chromium in Phase 3), risk R13

## Decision

- `report.json` (the `Report` model) is canonical. `report.html` is a Jinja2
  rendering of it. The Phase 3 PDF will print the same HTML with Chromium
  (`render_html(expand_all=True)` opens every finding for print).
- The HTML **makes no network request**: inline CSS, system font stack (no web
  fonts, which would send the reader's IP to a font host), screenshot embedded
  as a data URI (≤ 4 MB), no scripts, and a CSP of `default-src 'none';
  img-src data:; style-src 'unsafe-inline'`. A test enforces that only `data:`
  URIs are fetched.
- Autoescaping is on, and `StrictUndefined` catches template mistakes. Page
  text (titles, banner text, cookie names) is attacker-controlled and covered
  by an escaping test.
- Links go only to official sources and vendor documentation, never to hosts
  observed on the scanned page.
- Mobile-first layout, verified at 390 px and 1366 px with no horizontal page
  scroll. Wide tables scroll inside their own container.
- The vocabulary rule (ADR-0004) is enforced by tests over the rendered HTML,
  the JSON, the catalog YAML and the template source.

## Consequences

A report can be archived, e-mailed or attached to a ticket and shows the same
thing years later. The Next.js viewer (Phase 5) will read the same JSON.
