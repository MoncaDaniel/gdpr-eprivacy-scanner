# ADR-0001: Record architecture decisions

- **Status:** Accepted
- **Date:** 2026-10-12
- **Deciders:** Daniel Moncada León (owner)

## Context

This scanner makes claims about other organisations' websites with legal
vocabulary attached. Every design choice that changes what it observes or how
it judges must be explainable later, to a reviewer, a DPO or a future
maintainer, without re-deriving it from code.

## Decision

Record every non-trivial architectural or methodological decision as an ADR in
`docs/adr/`, using a lightweight [MADR](https://adr.github.io/madr/) layout:
Context, Decision, Consequences, and Alternatives where they were really
weighed. ADRs are immutable once accepted. A changed decision gets a new ADR
that supersedes the old one, and the old one's status is updated to point to it.

Code that implements a decision cites it (`ADR-00NN`) in its module docstring.

## Consequences

- Decisions are reviewable in pull requests like code.
- `docs/adr/README.md` is the index and must be updated with each new ADR.
