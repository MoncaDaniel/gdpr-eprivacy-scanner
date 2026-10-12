# ADR-0009: Asynchronous scan API contract; Cloud Tasks as the scale path

- **Status:** Accepted (implementation: Phase 4)
- **Date:** 2026-10-12
- **Source:** Design review §2.4

## Context

A full scan (S0–S2) takes about 15–60 s. Long synchronous HTTP requests are
fragile behind proxies and on mobile networks, and a public contract is
expensive to change later.

## Decision

`POST /v1/scans` returns `202 {scan_id, status: "queued"}`, and clients poll
`GET /v1/scans/{id}`. The MVP runs scans on an in-process worker. On Cloud Run
that needs instance-based billing and a shared database (Neon Postgres, EU),
because a poll may reach another instance. The scale path is Cloud Tasks
pushing to a worker service, with no change to the public contract.

## Consequences

- The frontend shows progress from day one.
- Max-instances and concurrency caps bound the Chromium memory cost (risk R16).
