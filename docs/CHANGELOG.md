# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The project
uses SemVer. The Evidence Bundle schema has its own version (`SCHEMA_VERSION`).

## [Unreleased] — Phase 2: classification, ePrivacy rules, scoring, HTML report

### Added
- Evidence Bundle schema `1.1.0`: `SessionEvidence.consent_ui`, a factual
  snapshot of visible overlay layers and their controls (label, geometry,
  computed colours), including open shadow roots and cross-origin frames
  (ADR-0012). 1.0.0 bundles still load.
- `classifier`: knowledge base (curated cookies, hosts, CMP signatures,
  FR/EN/ES/DE consent lexicon) + Open Cookie Database snapshot (Apache-2.0,
  pinned); exemption model exempt/conditional/not exempt/unknown; CMP and
  banner detection with confidence (ADR-0013).
- Rule catalog `1.0.0` as YAML: all 24 design-review checks (EP-01…EP-11,
  GD-01…GD-13) with verified citations; EP-01/02/03/04/05/09 automated,
  EP-10/11 manual, the rest planned. Loader validation and a generated
  `docs/legal/rule-catalog.md` (ADR-0006, ADR-0017).
- Rules engine policies: unobserved page → ERROR, low-confidence FAIL →
  review, crashing check → ERROR, Tier M → review; new review reason
  `configuration_not_observable` (ADR-0014).
- Score and coverage per regulation (ADR-0015).
- Report: canonical `report.json` and a self-contained `report.html` (no
  external requests, CSP, embedded screenshot, mobile-first) (ADR-0016).
- CLI `scan` (collect + judge + report) and `assess` (re-judge a stored bundle
  offline).
- Fixture sites per violation pattern, golden tests on recorded bundles,
  architecture test keeping judgement free of browser/collector imports.
- Docs: ADRs 0012–0017; module docs for classifier, rules, scoring and
  reporting; legal methodology, sources and verification log.

### Changed
- EP-09 narrowed to audience-measurement cookies, and EP-05 wording aligned
  with the EDPB Taskforce report and the CNIL recommendation as amended in
  Dec 2025, after primary-source verification (ADR-0017).
- `scanner_version()` moved to `privacy_scanner.version` (re-exported by the collector).

### Fixed
- Canonical form of IPv4-mapped IPv6 hosts no longer depends on the CPython
  patch release; CI uses uv-managed Python.

## Phase 1: foundations and evidence collector

### Added
- Evidence Bundle schema `1.0.0`: frozen Pydantic models; values fingerprinted (ADR-0003, ADR-0008).
- URL intake with WHATWG-equivalent host canonicalisation, including legacy IPv4 forms.
- `SsrfGuard` address and host policy (ADR-0005).
- Per-session `EgressProxy`: the browser's only network exit and DNS resolver,
  with DNS pinning and a post-connect peer re-check (ADR-0011).
- S0 baseline session: cookies with first-observed timing, every request
  (including blocked ones), Web Storage per origin, DOM with open shadow roots
  per frame, and a screenshot (ADR-0010).
- Bot-challenge and HTTP-error recognition (Cloudflare, DataDome, HUMAN, Imperva, Akamai).
- CLI `privacy-scanner collect` with stable exit codes 0/2/3.
- ADRs 0001–0011; architecture, security, module docs; runbooks; CI.

### Security
- Fixed: a redirect to a non-public address (e.g. the cloud metadata endpoint)
  was not covered by request interception, so Chromium opened the connection.
  All egress now goes through the guard-enforcing proxy (ADR-0011).

### Changed
- Cloudflare and Imperva challenge markers that also appear on ordinary pages
  (Turnstile widgets, Imperva's injected script) now count only with an error
  status, so normal pages are not reported as obstructed.
