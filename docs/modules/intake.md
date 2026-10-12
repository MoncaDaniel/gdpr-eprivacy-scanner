# Module: `intake`

**Purpose:** turn untrusted input into a URL the browser will load *exactly
as checked*, and own the network policy (ADR-0005).

## `intake/url.py`

`normalize_url(raw) -> NormalizedUrl`

- Bare hosts get `https://`. Only `http`/`https` are accepted. The fragment
  is dropped and default ports are elided.
- Rejects: empty input, more than 2048 characters, whitespace or control
  characters, embedded credentials, invalid hosts.
- `canonical_host()` reproduces the WHATWG host parser: IDNA → punycode,
  trailing dot removed, and **legacy IPv4 forms** (`2130706433`, `0x7f.1`,
  `127.1`, octal) turned into dotted quads. A host whose last label is numeric
  must parse as IPv4, as in browsers.
- Raises `InvalidUrlError` (a `ValueError`) with a user-presentable message.

Known divergence: Python's `idna` codec implements IDNA 2003, while Chromium
uses UTS #46. They differ on a few characters (e.g. `ß`). That can only make
us *refuse* or normalise differently, never let a non-public address through,
because the guard checks resolved addresses, not names.

## `intake/ssrf_guard.py`

`SsrfGuard(policy, resolver)`

| Method | Use |
|---|---|
| `check_url(url)` | Scheme/host/port parsing, then `check_host`. `ws`/`wss` map to `http`/`https` |
| `check_host(host, port)` | Port policy, forbidden names (`localhost`, `*.local`, `*.internal`, `metadata.google.internal`, single-label), DNS resolution, **every** address public. Cached per `(host, port)` for 30 s |
| `address_reason(ip)` | Pure policy for one address. Used by the egress proxy after connecting |

`GuardDecision` carries `allowed`, `reason: BlockReason`, `detail`, and the
approved `addresses`. The egress proxy connects only to those addresses.

**Failure modes:** DNS failure or a 5 s timeout → `DNS_FAILURE` (fail closed).
Unparseable URL → `FORBIDDEN_HOST`.

`NetworkPolicy(allowed_ports={80, 443}, allow_loopback=False)` is the
production default. Both relaxations exist for tests only.

## Tests

`tests/unit/test_url.py`, `tests/unit/test_ssrf_guard.py`: metadata
addresses (v4/v6), IPv6-embedded IPv4, CGNAT, legacy spellings, mixed DNS
answers, forbidden names, caching.
