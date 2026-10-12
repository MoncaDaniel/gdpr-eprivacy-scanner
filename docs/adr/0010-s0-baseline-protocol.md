# ADR-0010: S0 baseline protocol and an honest browser profile

- **Status:** Accepted
- **Date:** 2026-10-12

## Context

S0 answers "what happens on the device before any consent?" (ePrivacy
Art. 5(3)). The answer is only meaningful if (a) nothing we do could count as
consent, (b) the browser looks like an ordinary first-time EU visitor, so
consent platforms behave as they would for a person, and (c) we never present
a bot-challenge page as if it were the site.

## Decision

- **Fresh, isolated profile per session:** no cookies, storage or cache.
  Service workers are blocked so they can't hide requests or replay state.
- **No interaction of any kind** during observation: no clicks, keys, mouse
  movement **or scrolling**. Some CMPs treat scrolling as consent.
- **Timing:** navigate (`domcontentloaded`), wait for `load`, then network-idle
  as a best effort (long-polling sites never reach it), then a fixed
  observation window (default 6 s) to catch deferred tags (risk R2). The cookie
  jar is polled throughout, so every cookie gets a `first_observed_ms`.
- **Profile:** desktop Chrome user agent without the `HeadlessChrome` token,
  1366×768, `fr-FR`, `Europe/Paris`, matching `Accept-Language`. Every value is
  copied into the bundle.
- **No anti-detection:** no `navigator.webdriver` patching, stealth plugins or
  CAPTCHA solving. Challenge pages (Cloudflare, DataDome, HUMAN, Imperva,
  Akamai) are recognised and the session is reported as `obstructed`.
  Signatures that also appear on ordinary pages (Turnstile widgets, Imperva's
  injected script) only count with an error status.

## Consequences

- Some sites can't be scanned from a datacentre IP. The report says so instead of guessing.
- Tracking triggered only by interaction or scrolling is out of S0's scope and
  is listed as a limitation.
