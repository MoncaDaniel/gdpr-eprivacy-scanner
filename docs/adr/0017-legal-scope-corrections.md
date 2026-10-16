# ADR-0017: Legal-scope corrections made while verifying the catalog

- **Status:** Accepted
- **Date:** 2026-10-16
- **Source:** Phase 2 citation verification (design review header: "each citation
  is re-checked against official sources when encoded")

## Context

Verifying each citation against its primary source, rather than relying on
secondary summaries, changed three things in the design review's working set.

## Decisions

1. **EP-09 is narrowed to audience-measurement (analytics) cookies.** The
   CNIL's 13-month figure appears in the recommendation (2020-092 as amended
   by 2025-131, §5) for *audience-measurement trackers exempt from consent*:
   "une durée de vie … comme c'est le cas d'une durée de treize mois". The
   general 13-month rule of the 2013 recommendation was repealed. Applying 13
   months to every tracker would cite a rule that no longer exists. EP-09
   applies to analytics cookies set before consent (a site setting them
   either breaches Art. 5(3) or relies on the exemption, whose conditions
   include this lifetime), with low severity and an FR tag. 13 months is
   taken as 396 days. Chromium caps cookie lifetimes at 400 days, and reports
   say so when a lifetime is at the cap.
2. **EP-05 wording follows what the sources actually say.** The EDPB Cookie
   Banner Taskforce (§3, paras 6-8) records that a vast majority of
   authorities consider the absence of a refusal option *on any layer* an
   infringement. Placing it *on the first layer* is a CNIL recommendation
   ("recommande fortement", §2.3). The explanation states both separately.
   The CNIL's Figure 5 ("continuer sans accepter" as a link) was upheld by
   the Conseil d'État on 19 June 2026 (n° 501417), so that wording counts as
   a refusal option.
3. **Verification is enforced in code.** Each reference in
   `catalog_meta.yaml` has `verified_on`. The loader refuses a rule that is
   automated or manual (i.e. printed in reports) if it cites an unverified
   reference. Only planned rules may cite pending ones (currently CNIL
   SAN-2021-023/024 for EP-06). Verified dates and URLs are logged in
   `docs/legal/sources.md`.

Also recorded: EDPB Guidelines 2/2023 is cited as version 2.0, adopted
7 October 2024 (§3.1 covers URL and pixel tracking). The CNIL recommendation
is cited in its consolidated version, as amended on 18 December 2025.
