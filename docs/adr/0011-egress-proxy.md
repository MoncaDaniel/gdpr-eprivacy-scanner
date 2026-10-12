# ADR-0011: A per-session egress proxy is the browser's only network exit

- **Status:** Accepted
- **Date:** 2026-10-12
- **Amends:** [ADR-0005](0005-ssrf-defence-in-depth.md), layers 2 and 3

## Context

ADR-0005 layer 2 was first implemented with Playwright request interception
(`context.route`). An integration test, *redirect to the metadata endpoint is
blocked*, showed that this is not an enforcement boundary:

- **Redirect hops bypass `route`.** When a page answers `302 Location:
  http://169.254.169.254/…`, Chromium follows the redirect internally and the
  route handler is never called for the second hop. Chromium really opened a
  connection to the metadata address. The scanner only noticed afterwards,
  through a navigation timeout.
- **Chromium resolves DNS itself.** Our check resolved the name, then Chromium
  resolved it again. That gap between check and use is exactly what DNS
  rebinding exploits. Layer 3 (checking `response.server_addr()`) only detects
  this after the request has been sent.
- Anything else the interception API does not cover is unguarded by construction.

## Decision

Every browser session gets its own `EgressProxy` (`collector/egress.py`): an
asyncio HTTP proxy on `127.0.0.1:<ephemeral>`, set as the browser context's
proxy with `bypass: "<-loopback>"`. That removes Chromium's implicit
direct-connection exception for localhost.

- Chromium sends an HTTP proxy the **unresolved host name**, so the proxy is
  the session's only resolver. It resolves through `SsrfGuard` and connects
  only to an address the guard approved (**DNS pinning**). This removes the
  rebinding window rather than just detecting it.
- Every connection is checked: `CONNECT` tunnels (HTTPS, and all WebSockets,
  which Chromium always tunnels) and absolute-form plain HTTP, **including
  every redirect hop**.
- After connecting, the actual peer address is re-checked (layer 3). On
  failure the proxy closes the socket before relaying any byte and records a
  `GuardViolation`.
- Refused `CONNECT` → `403`. Refused plain HTTP → connection closed with no
  response, so a proxy error page can never be captured as the site's content.
- Plain HTTP is relayed one request per connection with `Connection: close`
  on both sides, so the proxy needs no HTTP/1.1 message framing beyond the head.
- The proxy logs every decision (`EgressLog`). The `NetworkRecorder` joins it
  with per-request records: `server_ip` comes from the proxy's real socket,
  and requests the proxy refused get `blocked_by`.

The `route`-level check stays, as an **attribution** layer: it blocks early
and ties the refusal to the exact Playwright request. It is no longer what
security depends on.

## Alternatives considered

- **`route.fetch()` + `route.fulfill()` for every request**, re-entering the
  route on each redirect. Rejected: the requests would be made by Playwright's
  network stack, not Chromium's (different TLS/HTTP fingerprint, no HTTP/2
  semantics, different cookie handling). That corrupts the evidence we exist
  to collect.
- **A CDP `Fetch` session alongside Playwright's.** Rejected: it conflicts with
  Playwright's own interception and is not a supported configuration.
- **Detection only** (post-hoc `server_addr` check plus timeouts). Rejected:
  the request has already left the machine by then. For the metadata endpoint,
  the request *is* the harm.
- **Off-the-shelf egress proxy (e.g. Smokescreen) as a sidecar.** A good fit
  for Phase 4 infrastructure, but it adds a process and deployment dependency
  to every local run and test. The in-process proxy keeps the guard logic in
  one tested Python module, and Phase 4 still adds the VPC egress firewall (ADR-0005 layer 4).

## Consequences

- The integration test for the metadata redirect passes. Unit tests cover the
  proxy directly: forwarding, refusals, the peer re-check, malformed input.
- Real-site validation (cnil.fr, lemonde.fr, leboncoin.fr over HTTPS/HTTP2):
  every response got its `server_ip` from the proxy, with no spurious blocks.
- Chromium never resolves names itself, so the test suite no longer needs
  `--host-resolver-rules`. The guard's injected resolver is the whole test DNS.
- With a proxy configured, Chromium disables QUIC/HTTP3. HTTP/2 over TLS is
  unaffected, since the proxy only tunnels bytes. This is a small fidelity
  change, accepted and recorded here.
- Plain-HTTP connection reuse is disabled. This matters little (production
  traffic is overwhelmingly HTTPS) and is invisible to the evidence.
