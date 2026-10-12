# ADR-0006: Rule catalog as versioned, legally referenced data

- **Status:** Accepted (implementation: Phase 2)
- **Date:** 2026-10-12
- **Source:** Design review §2.2, §2.3

## Context

Legal reviewers must be able to audit what the scanner asserts without reading
Python. The law and the guidance move (risk R8), so a report has to say which
rule set judged it.

## Decision

Rules (ID, title, tier, severity, binding legal basis with EUR-Lex URL,
non-binding guidance with jurisdiction, explanation template) live in YAML
under `rules/catalog/`. Detection code lives separately in `rules/checks/`.
The catalog carries a version and a content hash, both printed in every report.
`docs/legal/rule-catalog.md` is generated from the YAML. Each citation is
verified against official sources when it is encoded.

## Consequences

- A citation change is a data change with its own review, not a code change.
- Old bundles can be re-judged against any catalog version.
