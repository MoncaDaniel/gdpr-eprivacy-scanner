# ADR-0008: Stored values are fingerprinted, never persisted in clear

- **Status:** Accepted
- **Date:** 2026-10-12

## Context

Cookie and Web Storage values are often identifiers, sometimes personal data,
occasionally secrets (session tokens). The scanner itself is subject to the
GDPR (risk R13), and a bundle may be shared with third parties. The rules only
need to know that something was stored, how big it is, and whether the same
value appears again (e.g. an ID that survives a refusal).

## Decision

Values are reduced to a `ValueFingerprint`: length plus the first 16 hex
characters of HMAC-SHA256 under a 32-byte key that is random **per scan** and
never persisted. Equal values compare equal within one bundle, but cannot be
linked across scans or recovered by brute force from the bundle.

## Consequences

- Bundles can be stored and shared with much lower risk.
- Value-content heuristics (e.g. "looks like a GA client ID") must run inside
  the collector at capture time, if ever needed. They cannot run on a stored bundle.
- An integration test asserts known fixture values never appear in `evidence.json`.
