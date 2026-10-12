# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The project
uses SemVer. The Evidence Bundle schema has its own version (`SCHEMA_VERSION`).

## [Unreleased] — Phase 1: foundations and evidence collector

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
