# MVP Design Review — GDPR + ePrivacy Web Compliance Scanner

| | |
|---|---|
| **Status** | Accepted by owner on 2026-10-12. Later changes are recorded as ADRs in `docs/adr/` |
| **Date** | 2026-10-12 |
| **Owner** | Daniel Moncada León |
| **Participants** | Product Owner / Legal-Tech (PO), Staff Software Engineer (SWE) |
| **Supersedes** | — |

> Legal citations in this document are the working set for design. Each one is
> re-checked against EUR-Lex / official authority sources when it is encoded
> into the rule catalog (Phase 2), the same verification standard applied in
> `eu-digital-compliance-reference`. Items marked **[verify]** have a status
> that may have changed after the drafting date.

---

## 1. Understanding of the MVP goal

A user pastes a public website URL. The system visits the site the way a
first-time EU visitor's browser would: it observes what the site stores on and
reads from the device, which third parties it contacts, how the consent banner
behaves, and what the privacy notice says. It then produces a report that
(a) lists findings, each tied to a specific provision of the GDPR or the
ePrivacy Directive, with a verdict and a plain-language explanation,
(b) gives a score per regulation, and (c) can be viewed on the web and
downloaded as a PDF.

Its real value is not "the score". It is **legally traceable, evidence-backed
findings**: "cookie `_ga` (Google Analytics, analytics category) was set
0.8 s after page load, before any interaction with the consent banner →
Art. 5(3) ePrivacy Directive", with the evidence attached. It is also honest
about what a machine cannot know. The audience is fintech/regtech recruiters
and potential clients in Paris/EU, so the bar is: a DPO or privacy lawyer
reading the report should find nothing legally overclaimed.

---

## 2. Product Owner ⟷ Staff Engineer debate

### 2.0 Viability flags raised before the debate (things that cannot be done *as framed*)

1. **"Compliance score per regulation" / verdict "compliant"**. **Not
   defensible as framed.** Most GDPR obligations cannot be seen from outside
   the organisation: the record of processing (Art. 30), DPIAs (Art. 35),
   processor contracts (Art. 28), security measures (Art. 32), retention
   actually applied, DSAR handling, and the validity of the legal basis.
   A website scan sees a thin slice. A "GDPR: 82% compliant" label would be
   the first thing a privacy lawyer attacks. **Alternative:** score only the
   automatable checks, call it a *Website Privacy Exposure Score*, always show
   it next to its **coverage** ("covers 14 of 29 catalogued checks"), and
   replace "compliant" with **"No issue detected"**, because not detecting an
   issue is not the same as being compliant. See §2.3.
2. **"Analysing a website"**. **Not achievable sitewide in an MVP.** Behaviour
   differs per page, per geography, per logged-in state and per A/B bucket.
   **Alternative:** the MVP analyses *one entry page* (the URL given) plus the
   *privacy notice it links to*, from a declared EU vantage point. The report
   states this scope explicitly.
3. **"Consistent with the MiCA POC stack (FastAPI, Pydantic, SQLAlchemy)"**.
   The POC (`crypto-compliance-engine`) uses **raw `sqlite3`, not
   SQLAlchemy**. Its actual module layout is `ingestion / parsing /
   extraction / rag / compliance / reporting / api`, not the six modules in
   the brief. It is also **not under git**, has **no tests**, and has an
   **empty README**. This project uses SQLAlchemy as you prefer, and §3 maps
   its modules onto the six-module mental model. I recommend migrating the POC
   to SQLAlchemy later, but I won't touch it without your say.
4. **"React or Streamlit, the same open question as MiCA"**. In code it is
   **already partly answered**: the POC has a Next.js 16 / React 19 / Tailwind
   frontend in `web/` with an `app/report/[assessmentId]` route. The
   recommendation in §2.4 therefore amounts to "confirm and keep Next.js".

### 2.1 What does "analysing a website" mean? (HTML scraping vs. screenshot + vision vs. both)

**PO:** ePrivacy Art. 5(3) is about what *happens on the device*: storing or
reading information before consent. The legally relevant facts are cookies,
localStorage, pixels, and requests to third parties at the moment of the first
visit. "Reject is as easy as accept" is a *visual* question: CNIL fined Google
€150M and Facebook €60M (deliberations of 31 Dec 2021) because refusing took
more clicks than accepting. I want the tool to "see" the banner like a user.
Vision models can do that.

**SWE:** Static HTML scraping (`httpx` + BeautifulSoup) is **disqualified for
the core problem**. Almost every tracker is injected by JavaScript, often
through a tag manager after the CMP loads, so a static fetch sees neither the
cookies nor the banner. We need a real browser: **Playwright + Chromium**,
capturing (1) the cookie jar, (2) every network request with its initiator,
(3) localStorage/sessionStorage, (4) the rendered DOM including shadow roots
and CMP iframes, and (5) a screenshot. On vision as a *decision* mechanism:
it is non-deterministic, it costs money per scan, it can't be regression-tested
reliably, and it hallucinates on the exact edge cases that matter (a grey
"Reject" link on a grey background). "Is reject as easy as accept" has
deterministic proxies in the DOM: is a reject control present *on the first
layer*, the number of clicks to reach it, its bounding-box area relative to
accept, its font size, and its colour contrast (computed styles).

**PO:** I accept that, provided the screenshot appears in the report as
evidence. A lawyer trusts what they can see.

**SWE:** Agreed. The screenshot is **evidence, not a judge**.

**Decision 2.1 — Real-browser behavioural observation; screenshot as evidence only; no vision in MVP.**
- The collector runs **up to three isolated browser sessions** per scan:
  - **S0 Baseline**: load the page, wait for network idle + a settle window,
    *no interaction*. This shows what happens before consent.
  - **S1 Reject**: fresh context, find and click the reject control on the
    first layer, then reload and wait. This shows whether the refusal is
    honoured.
  - **S2 Accept**: fresh context, click accept. This baseline shows *which*
    trackers the CMP gates, and so whether a banner was required at all.
- Static fetching is used only for the privacy notice text (with a
  rendered-DOM fallback).
- Vision/LLM-on-screenshot is deferred to a post-MVP *assistive* feature that
  can never set a verdict on its own (ADR-0002).
- **Collector and rules are strictly separated**: the collector produces an
  immutable, serialisable **Evidence Bundle** and makes no legal judgement.
  Rules are pure functions `Evidence → Finding`. That makes every rule
  unit-testable without a browser, lets old scans be re-evaluated when the
  rule catalog changes, and makes every finding point to concrete evidence
  (ADR-0003).

### 2.2 Which rules are reliably automatable, and which are "manual review suggested"?

**PO:** The non-negotiable principle is that we never simulate a legal
judgement we can't make. Some checks a machine does well (was `_fbp` set
before interaction?). Some it does partially (is there something that looks
like a reject button?). Some it can't do at all (is "legitimate interest" a
valid basis for this processing?). These need three tiers, and the report has
to show which tier each finding came from.

**SWE:** Tiers drive the verdict logic. A **FAIL** from a low-confidence
detector becomes **MANUAL_REVIEW ("possible issue detected")** with the
evidence attached. We downgrade instead of accusing. A false "non-compliant"
on a real company's site is a much worse failure for this product than a
false "please review".

**PO:** That's correct legally too. There is also a nuance most commercial
scanners get wrong: **a cookie banner is not required per se**. Art. 5(3)
requires consent only if non-exempt storage/access happens. A site with no
trackers and no banner is *fine*. "No banner" must be NOT_APPLICABLE when S2
shows no non-essential trackers, not FAIL.

**SWE:** S2 (accept) gives us exactly that signal. Unknown cookies we can't
classify are **never assumed essential**. They go to MANUAL_REVIEW, listed by
name.

**Decision 2.2 — MVP rule catalog, by automation tier.**

Tier **A** = deterministic, high confidence. Tier **B** = heuristic, so a FAIL
at low confidence is downgraded to MANUAL_REVIEW. Tier **M** = not automatable,
always MANUAL_REVIEW with a review prompt (no simulated verdict).

**ePrivacy Directive 2002/58/EC (as amended by 2009/136/EC)**

| ID | Check | Tier | Primary provision | Interpretive sources (non-binding unless noted) |
|---|---|---|---|---|
| EP-01 | No non-essential cookies set before consent (S0) | A* | Art. 5(3) | EDPB Guidelines 2/2023 (technical scope of Art. 5(3)); CJEU C-673/17 *Planet49* |
| EP-02 | No third-party tracking requests (pixels, beacons) before consent (S0) | A* | Art. 5(3) | EDPB Guidelines 2/2023 (covers pixels and tracking URLs, not just cookies) |
| EP-03 | No known tracker identifiers in localStorage/sessionStorage before consent | B | Art. 5(3) | EDPB Guidelines 2/2023 |
| EP-04 | Consent mechanism present **when non-exempt trackers exist** (N/A otherwise) | A | Art. 5(3) | — |
| EP-05 | Reject option on the **first layer** of the banner | B | Art. 5(3) with GDPR Art. 4(11), 7 | EDPB Cookie Banner Taskforce Report (Jan 2023); CNIL Recommendation 2020-092 |
| EP-06 | Reject comparable in prominence to accept (size, contrast, clicks) | B | Art. 5(3) with GDPR Art. 4(11), 7(3) | EDPB Taskforce Report; CNIL deliberations SAN-2021-023/024 (Google/Facebook) **[verify refs]** |
| EP-07 | Refusal honoured: no non-essential trackers after reject (S1) | A* | Art. 5(3) | — |
| EP-08 | Persistent way to withdraw/change consent (footer link, floating icon) | B | GDPR Art. 7(3) (applied via Art. 5(3)) | CNIL Guidelines 2020-091 |
| EP-09 | Tracker cookie lifetime ≤ 13 months | A | Art. 5(3) | **CNIL** recommendation (FR soft law, tagged "FR guidance") |
| EP-10 | No cookie wall (access conditioned on acceptance) | M | Art. 5(3) with GDPR Art. 7(4) | National divergence (FR: case by case after Conseil d'État 19 June 2020; ES/AT positions differ) |
| EP-11 | Granular purposes, no pre-ticked purpose toggles in second layer | M (MVP) → B later | GDPR Art. 4(11), Recital 32 | *Planet49* |

\*A where the cookie or domain is in the classification database. Unclassified
items go to MANUAL_REVIEW, listed individually.

**GDPR — Regulation (EU) 2016/679**

| ID | Check | Tier | Provision |
|---|---|---|---|
| GD-01 | Privacy notice reachable from the entry page | A | Art. 12(1) (easily accessible), Art. 13 |
| GD-02 | Controller identity and contact details mentioned | B | Art. 13(1)(a) |
| GD-03 | DPO contact mentioned (*whether a DPO is mandatory is M*) | B + M | Art. 13(1)(b), Art. 37 |
| GD-04 | Purposes **and** legal bases mentioned | B (mention) / M (validity) | Art. 13(1)(c), Art. 6 |
| GD-05 | Recipients / categories of recipients mentioned | B | Art. 13(1)(e) |
| GD-06 | International transfers mentioned | B | Art. 13(1)(f) |
| GD-07 | Retention period or criteria mentioned | B | Art. 13(2)(a) |
| GD-08 | Data subject rights listed (access, rectification, erasure, restriction, objection, portability) | B | Art. 13(2)(b), Arts. 15–21 |
| GD-09 | Right to withdraw consent mentioned | B | Art. 13(2)(c) |
| GD-10 | Right to lodge a complaint with a supervisory authority mentioned | B | Art. 13(2)(d) |
| GD-11 | Site served over HTTPS; forms not submitted over HTTP | A | Art. 5(1)(f), Art. 32 (**security signal only**; does not establish Art. 32 compliance) |
| GD-12 | No pre-ticked marketing/newsletter consent boxes in forms on the entry page | B | Art. 4(11), Art. 7, Recital 32, *Planet49* |
| GD-13 | Third-party requests to providers established outside the EEA | Informational → M | Arts. 44–46 (transfer mechanism, DPF certification and SCCs are not observable) |

**Always Tier M (listed in the report as "requires manual review" with the
reason; never scored):** validity of each legal basis and LIA balancing
(Art. 6(1)(f)); accuracy of the notice compared with actual processing; DPO
necessity (Art. 37); ROPA (Art. 30); DPIA (Art. 35); processor contracts
(Art. 28); security measures (Art. 32); retention actually applied; DSAR
handling; transfer-mechanism validity (Ch. V); joint controllership for
embedded third-party content (CJEU C-40/17 *Fashion ID*); cookie-wall
legitimacy; children's consent (Art. 8).

**Note on "mentioned" (GD-02 to GD-10):** these checks establish *presence of
the element in the text*, never *adequacy*. A PASS reads "Element identified
in the notice (quoted)". An adequacy review is always appended as a manual
item. The MVP detects elements deterministically (multilingual keyword and
pattern sets, FR/EN/ES/DE). LLM assistance is a later phase, see §2.4.

### 2.3 Output structure: score vs. checklist vs. both; legal traceability

**PO:** Recruiters want a number. Lawyers want the checklist. Both are needed,
but the number must not lie.

**SWE:** Then the number must be mechanically explainable. No ML-weighted
magic: a severity-weighted ratio over checks that actually produced a
PASS/FAIL, published with its formula.

**PO:** Severity should track enforcement reality. Trackers before consent and
an ignored refusal are what CNIL and other authorities actually fine for. A
missing "complaint to SA" sentence matters less.

**Decision 2.3 — Both, with coverage as a first-class number.**

- **Verdict vocabulary:** `PASS` (shown as "No issue detected"), `FAIL`
  ("Issue detected"), `MANUAL_REVIEW` ("Review suggested", carrying a
  `reason`: *not automatable* / *low-confidence signal* / *unclassified
  items*), `NOT_APPLICABLE` (e.g. no trackers, so no banner needed),
  `ERROR` (check could not run, e.g. page timeout). This deliberately departs
  from the brief's "compliant / non-compliant" (ADR-0004).
- **Per-finding fields:** `rule_id`, `title`, `verdict`, `severity`
  (high/medium/low), `confidence` (high/medium/low), `legal_basis[]`
  (`instrument`, `provision`, `binding: true`, EUR-Lex URL),
  `guidance[]` (authority, document, `binding: false`, `jurisdiction`
  such as `EU`/`FR`), `explanation` (plain language, ≤ 3 sentences),
  `evidence_refs[]` (cookie names and attributes, request URLs, DOM
  selector, screenshot, verbatim quote), `remediation_hint`,
  `rule_version`.
- **Score per regulation** = `100 × Σ w(PASS) / Σ w(PASS ∪ FAIL)` with
  weights high = 5, medium = 3, low = 1. MANUAL_REVIEW, NOT_APPLICABLE and
  ERROR are excluded from the denominator.
- **Coverage per regulation** = automated checks evaluated / checks in the
  catalog for that regulation. It is always shown *next to* the score,
  e.g. **"ePrivacy exposure score: 62 / 100, based on 9 of 11 checks"**.
- **No grade letters and no "X% compliant" wording anywhere**, including the
  PDF.
- **Report metadata, for reproducibility:** input URL, final URL after
  redirects, UTC timestamp, scanner version, **rule catalog version and
  content hash**, vantage point (cloud region and country), browser version,
  UA, viewport, `Accept-Language`, sessions executed (S0/S1/S2), and a fixed
  **Scope and limitations** section. If a CNIL guideline changes, an old
  report still states which rule set it was judged against.
- **Rule catalog as versioned data** (YAML) separate from detection code. A
  lawyer can review the catalog without reading Python, and
  `docs/legal/rule-catalog.md` is generated from it (ADR-0006).

### 2.4 Technical architecture: modules, data flow, stack, frontend

**SWE (frontend):** For **Streamlit**: fastest to build, Python-only, and
your other three demos already use it with the Meridian theme. Against: it
runs the Python in-process, so the FastAPI layer becomes decorative. Mobile
layout control is weak, which conflicts with your standing rule that
everything works at 390 px. And a report viewer with expandable evidence, a
screenshot lightbox and print CSS fights the framework. For **Next.js**:
it's the real-world architecture (typed API contract, stateless frontend,
independently deployable), you already have it in the MiCA POC *and* in
`zulia-mica-assessment`, and it shows range next to three Streamlit apps.

**PO:** From the recruiter's side: Paris fintech/regtech job specs ask for
"API + React" far more than Streamlit. The portfolio already proves Streamlit
three times.

**SWE (PDF):** The POC lists WeasyPrint, which needs Pango/Cairo system libs.
We already ship Chromium for scanning, so `page.pdf()` on a Jinja2-rendered
HTML template gives a print-quality PDF with zero extra system dependencies.

**SWE (execution model):** A scan takes about 15–60 s (three sessions). A
synchronous HTTP request is fragile, so the API contract is **asynchronous
from day one**: `POST /v1/scans` returns `202 {scan_id, status: queued}`,
then the client polls `GET /v1/scans/{id}`. Changing a public contract later
breaks clients, so we get it right now. *Implementation* for the MVP is an
in-process worker. On Cloud Run that needs instance-based billing ("CPU always
allocated") and a shared database, because polling may hit another instance.
The scale path is Cloud Tasks (ADR-0009).

**SWE (persistence):** Cloud Run's filesystem is per-instance and ephemeral,
so SQLite in production would lose the reports you link from your CV. We use
**SQLAlchemy 2.0 + Alembic**: SQLite for local dev and tests, **Neon Postgres
(EU region)** in production. You already run Neon for the Zulia app. That's
the concrete reason SQLAlchemy is worth having here, not just preference.

**SWE (region):** Many CMPs geo-target and show no banner to non-EU IPs.
Scanning from `us-central1` would produce systematically wrong results. We
deploy to **`europe-west9` (Paris)** and print the vantage point in every
report.

**Decision 2.4.** Architecture in §3. Frontend: **Next.js (React + TS +
Tailwind, Meridian palette)**. **Recommendation for the MiCA POC: keep its
existing Next.js `web/`. Don't move it to Streamlit** (ADR-0007).

### 2.5 Out of scope for the MVP (explicit)

- Multi-page crawling, sitemaps, and authenticated/logged-in areas.
  Single entry page plus the linked privacy notice only.
- Mobile apps and SDKs; server-side tracking (invisible from the client by
  definition); email tracking.
- Browser fingerprinting detection (canvas/WebGL/audio). It is in Art. 5(3)
  scope per EDPB 2/2023, but reliable detection is a research project. The
  report lists it as a known blind spot.
- IAB TCF consent-string decoding and vendor-list auditing (post-MVP).
- "Declared vs. observed" diff (cookies found but not listed in the cookie
  policy). It's a strong feature but post-MVP (Phase 6).
- Vision/LLM verdicts; LLM-assisted notice analysis is a later, optional,
  assistive-only phase.
- Per-member-state legal opinions. MVP baseline = EU law + EDPB, with
  **French CNIL guidance** layered on and tagged `FR`, since Paris is the
  target market. Other member states' divergences are named in limitations,
  not evaluated.
- Non-privacy French web obligations (LCEN *mentions légales*), DSA, AI Act,
  accessibility (RGAA/EAA).
- User accounts, multi-tenancy, scheduled re-scans/monitoring, batch scans,
  billing.
- Remediation beyond a one-line hint per finding. The tool indicates; it does
  not advise.
- The pending **ePrivacy Regulation** (Commission withdrawal announced in its
  2025 work programme **[verify formal withdrawal]**). The **Digital Omnibus
  proposal of Nov 2025**, which proposes moving parts of the terminal-equipment
  rules into the GDPR, is tracked in the limitations section and an ADR, not
  implemented **[verify current legislative status]**.

### Agreed outcome of the debate

Behavioural observation in a real browser from an EU vantage point. A strict
split between evidence and judgement. A three-tier rule catalog as versioned,
legally referenced data. A transparent, coverage-qualified score that never
says "compliant". Async FastAPI service with SQLAlchemy persistence. Next.js
frontend. Same-HTML web report and Chromium-printed PDF. Docker on Cloud Run
in Paris.

---

## 3. Final architecture

### 3.1 Modules (mapped to the MiCA six-module model)

| # | MiCA mental model | Module (`src/privacy_scanner/…`) | Responsibility | Pure? |
|---|---|---|---|---|
| 1 | Input & data modelling | `domain/`, `intake/` | Pydantic domain models (ScanRequest, EvidenceBundle, Finding, Report); URL normalisation; **SSRF guard** (resolve DNS, block private/link-local/metadata ranges, re-check on every redirect and sub-request) | yes |
| 2 | *(new, website-specific)* | `collector/` | Playwright sessions S0/S1/S2; captures cookies, requests (URL, initiator, timing, type), storage, DOM snapshot of banner region, screenshots; clicks consent controls. **No legal logic.** | no (I/O) |
| 3 | Classification engine | `classifier/` | Cookies to category (strictly necessary/functional/analytics/marketing/unknown) via Open Cookie Database plus curated overrides; first vs. third party (eTLD+1); tracker-domain matching; **CMP fingerprinting** (Didomi, Axeptio, OneTrust, Cookiebot, Usercentrics, Sourcepoint, Quantcast, TrustArc, Sirdata, Iubenda, Complianz, `__tcfapi`); generic banner heuristics; consent-button detection (multilingual) | yes |
| 4 | Document analysis (NLP/LLM) | `policy/` | Discover the privacy-notice link; fetch and extract main text; detect Art. 13 elements with deterministic multilingual patterns; *(Phase 6)* optional LLM locator with mandatory verbatim, grounding-verified quotes | yes (fetch isolated) |
| 5 | Risk assessment + compliance checker | `rules/` | YAML rule catalog (legal refs, severity, tier, explanation templates) + check functions `(EvidenceBundle, Classification, PolicyAnalysis) → Finding`; confidence-downgrade policy | yes |
| 6 | Decision engine & reporting | `scoring/`, `reporting/` | Score and coverage per regulation; JSON report (canonical); HTML via Jinja2; PDF via Chromium `page.pdf()` | yes / I/O for PDF |
| — | Delivery | `api/`, `persistence/`, `pipeline.py`, `cli.py` | FastAPI v1 (async job contract), SQLAlchemy repository, orchestration, CLI for local runs | — |
| — | Frontend | `web/` (Next.js) | Scan form, progress, interactive report viewer, PDF download; mobile + desktop | — |

### 3.2 End-to-end data flow

```
URL ─► intake (normalise + SSRF guard) ─► ScanJob(queued) persisted
                                              │ worker
                                              ▼
        collector:  S0 baseline ── S1 reject ── S2 accept      (Playwright, EU egress)
                                              │
                                              ▼
                 EvidenceBundle (immutable JSON + screenshots)  ──► persisted
                                              │
             ┌────────────────────────────────┼──────────────────────┐
             ▼                                ▼                      ▼
   classifier (cookies, requests,     policy (notice discovery,   (catalog v1.x
   CMP, banner, buttons)               text, Art.13 elements)      loaded from YAML)
             └────────────────────────────────┬──────────────────────┘
                                              ▼
                       rules engine → Finding[] (each → legal_basis + evidence_refs)
                                              ▼
                       scoring → per-regulation score + coverage
                                              ▼
                 Report (JSON canonical) ──► persisted ──► API ──► Next.js viewer
                                              └──► Jinja2 HTML ──► Chromium PDF
```

Because evidence is persisted, any stored scan can be **re-judged against a
newer rule catalog** without revisiting the site.

### 3.3 Stack (with justification)

| Layer | Choice | Why |
|---|---|---|
| Language | Python 3.12 | Matches the Playwright base image; your stack. Local 3.10 to 3.12 via `uv` |
| API | FastAPI + Pydantic v2 | Your stack; OpenAPI docs come free, which is the API documentation deliverable |
| Browser automation | Playwright (Python, async) + Chromium | Network/cookie/storage introspection, shadow DOM, iframes, PDF printing in one tool |
| HTML parsing | selectolax | Fast; deterministic DOM queries over snapshots |
| Main-text extraction | trafilatura | Robust boilerplate removal for privacy notices **[verify licence, believed Apache-2.0 since v1.8]** |
| Domain parsing | tldextract | Correct eTLD+1 for first/third-party classification |
| Cookie knowledge base | Open Cookie Database | **[verify licence, believed Apache-2.0]** Tracker-domain lists: DuckDuckGo Tracker Radar / Disconnect are **CC BY-NC-SA**, so they are not usable if the demo ever becomes commercial. We start with a curated, self-authored domain list and document the licence analysis in an ADR |
| Persistence | SQLAlchemy 2.0 + Alembic; SQLite (dev/test), Neon Postgres EU (prod) | Survives Cloud Run instance churn; one-line swap |
| Report | Jinja2 + Chromium print | Single template for web HTML and PDF; no WeasyPrint system libs |
| LLM (Phase 6, optional) | Anthropic Claude, tool-use structured output | Same pattern as Zulia (`{answer, confidence, citation, justification}`); feature-flagged off by default; exact model chosen at Phase 6 |
| Frontend | Next.js + TypeScript + Tailwind | §2.4 |
| Quality | pytest, pytest-asyncio, coverage, ruff, mypy (strict on `domain/`, `rules/`, `scoring/`) | Your existing standard is 96–98% coverage; we target ≥ 90% on pure modules |
| Packaging/infra | Docker on `mcr.microsoft.com/playwright/python`; Cloud Run `europe-west9`; Artifact Registry; GitHub Actions CI | Required constraints; EU vantage point |

---

## 4. Folder structure

```
gdpr-eprivacy-scanner/
├── README.md                      # case-study style, like the sibling repos
├── pyproject.toml                 # deps, ruff, mypy, pytest config
├── Makefile                       # make dev | test | lint | scan URL=… | docs
├── Dockerfile                     # playwright/python base, non-root user
├── docker-compose.yml             # api + postgres for prod-like local runs
├── .github/workflows/ci.yml       # lint, type-check, test, build image
├── src/privacy_scanner/
│   ├── domain/                    # models.py, enums.py (Verdict, Severity, Tier…)
│   ├── intake/                    # url.py, ssrf_guard.py
│   ├── collector/                 # browser.py, sessions.py, capture.py, consent_actions.py
│   ├── classifier/                # cookies.py, trackers.py, cmp.py, banner.py
│   │   └── data/                  # open_cookie_db.csv, tracker_domains.yaml, cmp_signatures.yaml, consent_lexicon.yaml
│   ├── policy/                    # discovery.py, extraction.py, elements.py, (llm.py — Phase 6)
│   ├── rules/
│   │   ├── catalog/               # eprivacy.yaml, gdpr.yaml, catalog_meta.yaml (version)
│   │   ├── engine.py
│   │   └── checks/                # eprivacy.py, gdpr.py
│   ├── scoring/                   # scorer.py
│   ├── reporting/                 # json_report.py, html.py, pdf.py, templates/
│   ├── persistence/               # db.py, orm.py, repository.py, migrations/ (alembic)
│   ├── api/                       # app.py, routers/{scans,health}.py, schemas.py, worker.py
│   ├── pipeline.py                # orchestration (collector → classifier → policy → rules → scoring)
│   ├── config.py                  # pydantic-settings
│   └── cli.py                     # `privacy-scanner scan https://…`
├── tests/
│   ├── unit/                      # pure modules, no browser
│   ├── integration/               # Playwright against local fixture sites
│   ├── fixtures/sites/            # hermetic test sites: clean, tracker-before-consent, no-reject, reject-ignored…
│   ├── fixtures/evidence/         # recorded EvidenceBundles for golden tests
│   └── golden/                    # expected reports
├── web/                           # Next.js frontend (Phase 5)
└── docs/
    ├── architecture/              # overview.md (C4: context/container/component), data-flow.md, security.md
    ├── adr/                       # 0001-record-architecture-decisions.md … (MADR format)
    ├── modules/                   # one page per module: purpose, inputs/outputs, deps, failure modes
    ├── legal/                     # methodology.md, rule-catalog.md (generated), limitations.md, sources.md
    ├── api/                       # endpoints.md, data-contracts.md, openapi.json (exported in CI)
    ├── runbooks/                  # local-dev.md, testing.md, deploy-cloud-run.md, incident-basics.md
    ├── design/                    # this document
    └── CHANGELOG.md
```

---

## 5. Risk register (technical and legal)

| # | Risk | Kind | Mitigation | If not fully mitigable, how the report says so |
|---|---|---|---|---|
| R1 | **False positives**: an essential cookie misclassified as tracking, leading to an accusation | Tech/Legal | Curated overrides; unknown means review, never fail; low-confidence FAIL downgraded to MANUAL_REVIEW; evidence attached to every FAIL | Each finding shows confidence and evidence; methodology page explains classification sources |
| R2 | **False negatives**: trackers loaded late, on scroll, or after a delay | Tech | Settle window plus scroll simulation; record timing | "Observed within N s on a single page load; later or interaction-triggered tracking may not be captured" |
| R3 | **Heavy JS / SPAs / bot protection** (Cloudflare, Akamai) blocking headless Chromium | Tech | Realistic UA and viewport, honest navigation; detect challenge pages and stop with ERROR rather than analysing a challenge page | Scan status "Blocked by bot protection: results unavailable", never a fake score |
| R4 | **CMP variety**: banners in shadow DOM, cross-origin iframes (Sourcepoint), delayed injection | Tech | CMP signature library; frame traversal; shadow-piercing selectors; fixture site per pattern | Banner-dependent checks become MANUAL_REVIEW ("banner not reliably identified") |
| R5 | **Multilingual buttons** ("Tout refuser", "Continuer sans accepter", "Ablehnen", "Rechazar") | Tech | Versioned consent lexicon FR/EN/ES/DE | Language outside lexicon means banner checks go to MANUAL_REVIEW |
| R6 | **Geo- and A/B-variance**: different behaviour per country/visit | Tech/Legal | Fixed EU egress (Paris), fixed `Accept-Language`, fresh profiles | Vantage point printed; "results reflect a single visit from FR" |
| R7 | **Member-state divergence** (cookie walls, analytics exemption, Google Fonts: LG München I 3 O 17493/20, DE TDDDG §25 vs FR Art. 82 LIL) | Legal | Baseline = EU instruments + EDPB; national guidance tagged by jurisdiction; contested topics set to Tier M | Jurisdiction tag on every guidance reference; limitations section lists known divergences |
| R8 | **Moving law** (Digital Omnibus, ePrivacy Reg withdrawal, DPF challenge: General Court *Latombe* T-553/23, appeal possible **[verify]**) | Legal | Catalog versioned and hashed; `sources.md` with retrieval dates; re-judge stored evidence | Report states catalog version and "law as of" date |
| R9 | **Overclaiming legal conclusions** | Legal | Verdict vocabulary (ADR-0004); coverage-qualified score; mandatory disclaimer | "Automated technical indication, not legal advice; covers X of Y checks" on every page and the PDF |
| R10 | **Defamation / disparagement risk** from publishing negative findings about named companies | Legal | No public gallery of scanned sites; reports by unguessable ID only; neutral factual wording; README demo uses fixture sites plus our own frontend | Report wording is factual ("cookie X observed at t=…"), not evaluative ("illegal") |
| R11 | **SSRF**: user-supplied URL makes our browser hit the GCP metadata server or internal IPs | Security | DNS-resolve and block private/link-local/loopback ranges; enforce on every redirect and sub-request via Playwright routing; no credentials on the Cloud Run SA beyond what is needed | n/a (security control, documented in `docs/architecture/security.md`) |
| R12 | **Abuse / cost** (using the service to hammer third-party sites; Chromium memory cost) | Security/Ops | Per-IP rate limit (reuse POC pattern), per-domain result cache (e.g. 24 h), Cloud Run max-instances cap, scan timeout | "Recent scan reused (scanned at …)" banner |
| R13 | **Our own GDPR exposure**: we store URLs and requester IPs | Legal | Store IPs hashed and short-lived for rate limiting only; our own privacy notice; no third-party analytics on our frontend | The frontend should pass its own scan, which we demo |
| R14 | **Data-source licences** (cookie DB, tracker lists) | Legal | Licence check per source before inclusion; ADR | `sources.md` lists each dataset and licence |
| R15 | **Clicking consent buttons triggers real state changes** on scanned sites (consent logs) | Legal/Ethics | Only consent controls are clicked, never forms or purchases; fresh contexts | Methodology discloses the interactions performed |
| R16 | **Playwright on Cloud Run** (cold start ~10 s, 2 GiB memory, CPU throttling for background work) | Ops | Instance-based billing, concurrency 1–2, max-instances cap, async job contract | Frontend progress UI states typical duration |

---

## 6. Phased delivery plan (each phase ends with a demonstrable, tested increment)

| Phase | Scope | Demonstrable at the end | Verification |
|---|---|---|---|
| **1. Foundations + evidence collector** | Repo, tooling, CI; domain models; intake + SSRF guard; Playwright **S0** session; EvidenceBundle JSON; CLI `privacy-scanner collect <url>`; ADRs 0001–0006; module docs for `domain`, `intake`, `collector` | CLI shows exactly what a real site stores and contacts before any consent | Unit tests (intake, SSRF ranges, models); integration tests against local fixture sites; manual scan of 2–3 real sites (e.g. cnil.fr, a major FR news site), results reported to you |
| **2. Classification + ePrivacy rules + scoring + HTML report** | Classifier (cookie DB, trackers, CMP + banner detection); rule catalog YAML with **verified** citations; EP-01/02/03/04/05/09; scorer; JSON + HTML report via CLI | A real HTML report with ePrivacy findings, legal refs, evidence and a coverage-qualified score | Golden tests on recorded evidence; one fixture site per violation pattern; manual real-site comparison |
| **3. Consent interaction + GDPR notice analysis + PDF** | Sessions **S1/S2**; EP-06/07/08; privacy-notice discovery and extraction; GD-01…GD-12; PDF via Chromium | Full two-regulation report, downloadable PDF | Fixtures: reject-ignored, no-reject-on-first-layer, multilingual notices; manual real-site run |
| **4. API + persistence + deployment** | FastAPI v1 async contract; worker; SQLAlchemy + Alembic; Docker; Cloud Run `europe-west9`; Neon; rate limiting and cache; API docs | **Public API URL** with OpenAPI docs; scans run from Paris | API contract tests; container smoke test; live deploy check |
| **5. Next.js frontend** | Scan form, progress, report viewer (filters, evidence drill-down, screenshot), PDF download; Meridian palette; own privacy notice | **Public web app** linkable from the CV | Playwright E2E at **390 px and desktop**; scan our own frontend (should be clean) |
| **6. (Optional) LLM-assisted notice analysis + declared-vs-observed** | Claude tool-use locator with verbatim, grounding-verified quotes (assistive only); cookie-policy vs. observed diff | "AI-assisted" toggle on report; mismatch table | Grounding tests (every quote must exist in the source text); cost cap |

After each phase: tests run, results reported, docs and ADRs updated,
`PORTFOLIO_TRACKER.md` updated, and any architecture adjustments made along
the way recorded as ADRs.
