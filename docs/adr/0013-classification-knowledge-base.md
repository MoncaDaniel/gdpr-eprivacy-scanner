# ADR-0013: Classification knowledge base and the exemption model

- **Status:** Accepted
- **Date:** 2026-10-16
- **Source:** Phase 2; design review §3.3 (cookie knowledge base), risks R1, R14

## Context

Rules need to know whether a cookie, storage key or third-party host is a
tracker. Every available list has a cost. Crowdsourced lists are broad but
uneven. The best-known tracker-domain lists (Disconnect, DuckDuckGo Tracker
Radar) are CC BY-NC-SA, which would bar commercial use. And the EDPB Cookie
Banner Taskforce itself notes (report of 18 Jan 2023, §8 para 29) that tools
"do not allow to check the nature of the cookies but only to list" them.

## Decision

**Sources, in precedence order** (`classifier/data/`, loaded and hashed once):

1. `cmp.yaml`: CMP signatures (hosts, self-hosted script paths, container
   names, consent-record cookies) and generic consent records (TCF strings,
   Google Additional Consent, etc.).
2. `cookies.yaml` (curated): about 50 vendors, each with a documentation URL
   where one was verified. Generic names are restricted to the vendor's
   domain (`IDE` only on doubleclick.net).
3. The **Open Cookie Database**, Apache-2.0 (licence verified on GitHub),
   pinned at commit `b15fa5d`, vendored with its licence. Names shorter than 4
   characters are used only when the entry names a domain, so "id" is not
   attributed to whichever vendor was catalogued first. Matches carry the
   OCD entry ID.
4. `trackers.yaml` (curated, self-authored): hosts by label-boundary suffix,
   optionally narrowed by path (`facebook.com/tr`, `google.com/recaptcha/`).

**Exemption model.** Each match carries an `Exemption`:

| Category | Default | Why |
|---|---|---|
| strictly necessary, consent management, infrastructure | `exempt` | WP29 Opinion 04/2012; storing the consent choice is needed to honour it |
| functional | `conditional` | Depends on purpose and duration (WP29 04/2012 §3) |
| analytics | `not_exempt`, or `conditional` for tools offering a CNIL-exemption configuration (Matomo, Piano Analytics, Wysistat, Cloudflare Web Analytics) | CNIL audience-measurement exemption, configuration not observable |
| marketing | `not_exempt` | |
| unknown | `unknown` | **Never assumed exempt** (design review §2.2) |

`conditional` and `unknown` lead to "Review suggested", never to "No issue
detected" or "Issue detected".

**Specific calls:** Google Tag Manager is `infrastructure` (a container; the
tags it loads are judged individually). Google Fonts is `infrastructure`,
with a note on LG München I 3 O 17493/20, a member-state divergence (risk R7)
that is not evaluated. Error/performance monitoring is `functional`. A
page-supplied first-party proxy of a tracker is not detected.

**Confidence:** matches from the curated set give high confidence; Open
Cookie Database matches give medium. Each match records its `source` in the
report.

## Consequences

- Every report prints the knowledge-base version, SHA-256 and the OCD commit.
- Updating the data is a reviewed data change. Golden tests show its effect.
- Tests add hosts through an overlay directory, never by editing packaged data.
