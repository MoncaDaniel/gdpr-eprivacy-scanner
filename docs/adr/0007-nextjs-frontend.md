# ADR-0007: Next.js frontend, not Streamlit

- **Status:** Accepted (implementation: Phase 5)
- **Date:** 2026-10-12
- **Source:** Design review §2.4

## Context

The owner's other demos use Streamlit. This product needs a typed API
contract, a report viewer with evidence drill-down and print CSS, and solid
layouts at 390 px.

## Decision

Next.js (React, TypeScript, Tailwind, Meridian palette) consuming the public
FastAPI v1 API. The same applies to the sibling MiCA POC
(`crypto-compliance-engine`): keep its existing Next.js `web/`.

## Consequences

- The API is a real, versioned contract, not an in-process call.
- The frontend is verified with end-to-end tests at 390 px and at desktop width.
