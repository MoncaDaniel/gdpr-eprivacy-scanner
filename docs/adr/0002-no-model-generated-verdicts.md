# ADR-0002: No verdict is ever set by a vision model or LLM

- **Status:** Accepted
- **Date:** 2026-10-12
- **Source:** Design review §2.1

## Context

Vision/LLM analysis of banner screenshots is tempting ("does reject look as
easy as accept?"), but it is non-deterministic, costs money per scan, can't be
regression-tested reliably, and fails on exactly the edge cases that carry
legal weight (a grey "Refuser" link on a grey background).

## Decision

No `Finding.verdict` is ever set by a model. Verdicts come from deterministic
checks over the Evidence Bundle. Models may later (Phase 6, feature-flagged,
off by default) act as an *assistant*: they locate passages in a privacy
notice, and every quote they return must be found verbatim in the source text
before it is shown. The screenshot is evidence for humans, not an input to a
judge.

## Consequences

- Same evidence and same catalog version always give the same report.
- Some checks a model could attempt stay Tier M (manual review) in the MVP.
