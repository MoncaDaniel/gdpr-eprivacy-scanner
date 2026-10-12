# ADR-0003: Strict separation of evidence collection and judgement

- **Status:** Accepted
- **Date:** 2026-10-12
- **Source:** Design review §2.1

## Context

The browser run is slow, non-deterministic and impossible to reproduce later
(sites change). The legal assessment must be fast, deterministic, unit-testable
and re-runnable when the rule catalog changes.

## Decision

The collector produces exactly one immutable, serialisable **Evidence Bundle**
per scan (`domain/evidence.py`) and expresses no opinion: no categories, no
"tracker", no verdict. Classification and rules are pure functions over a
bundle. Bundles are persisted with a `schema_version` (SemVer).

## Consequences

- Every rule can be tested against recorded bundles without a browser.
- Stored scans can be re-judged against a newer catalog without revisiting the site.
- Every finding can point to concrete evidence records.
- The bundle schema is a public contract: breaking changes bump MAJOR.
