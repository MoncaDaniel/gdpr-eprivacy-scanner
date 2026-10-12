# ADR-0005: SSRF defence in depth

- **Status:** Accepted (layer 2 amended by [ADR-0011](0011-egress-proxy.md))
- **Date:** 2026-10-12
- **Source:** Design review risk R11

## Context

The service points a real browser at user-supplied URLs from inside a cloud
project. A malicious URL, or anything the page loads, redirects to or connects
to, could make Chromium reach the cloud metadata server (`169.254.169.254`,
which serves service-account tokens), loopback services, or the VPC.

## Decision

Four independent layers. Each one must hold on its own:

1. **Pre-flight** (`intake/`): normalise the URL exactly as the WHATWG parser
   does (including legacy IPv4 spellings such as `0xa9fea9fe`), resolve it,
   and require every resolved address to be globally routable.
2. **Per-connection**: every connection the browser opens is checked by
   `SsrfGuard`. A mixed public/private DNS answer is refused (rebinding setup),
   and IPv4 addresses embedded in IPv6 (mapped, NAT64, 6to4) are unwrapped.
3. **Post-connect**: the peer address actually used is re-checked.
4. **Infrastructure** (Phase 4): VPC egress firewall denying private and
   link-local ranges, and a least-privilege service account.

Plus, in the browser: WebRTC limited to proxied UDP, so it cannot probe local
interfaces. Only ports 80/443 are allowed in production.

## Consequences

- `allow_loopback` and "any port" exist for hermetic tests only. Even then,
  link-local and private ranges stay blocked.
- Blocked requests are recorded as evidence (`blocked_by`) rather than hidden.
