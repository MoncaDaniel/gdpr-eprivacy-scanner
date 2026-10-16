# ADR-0014: Review reasons, confidence and when the scanner refrains from concluding

- **Status:** Accepted
- **Date:** 2026-10-16
- **Source:** Phase 2; design review §2.2, ADR-0004

## Context

ADR-0004 fixed the verdicts and the rule that a low-confidence FAIL becomes
MANUAL_REVIEW. Real-site runs in Phase 2 showed further situations where a
confident verdict would overclaim.

## Decision

1. **Review reasons** (`ReviewReason`): `not_automatable`,
   `low_confidence_signal`, `unclassified_items`, and a new
   **`configuration_not_observable`**. The last is for items whose exemption
   depends on how they are configured (for example Matomo under the CNIL
   audience-measurement exemption). Calling that "unclassified" would be wrong.
2. **The engine enforces the downgrade**, not each check: any FAIL with low
   confidence becomes MANUAL_REVIEW, and its explanation starts with
   "Possible issue, from a low-confidence signal; please verify".
3. **Unobserved pages are never judged.** If S0 is obstructed, blocked or
   failed, every automated check is ERROR with the reason, and no score is
   computed (risk R3).
4. **EP-05 specifics:**
   - A banner with a close "×" control and no recognised reject control is a
     low-confidence FAIL, so it ends as review. The CNIL accepts closing as
     refusal only when the banner says so clearly (recommendation 2020-092,
     §2.3), and the scanner cannot read that reliably.
   - An unrecognised label containing a refusal hint ("Refuser les traceurs
     publicitaires") is also low confidence.
   - **"Pay or consent" walls** (Le Monde, Le Figaro) offer acceptance or a
     subscription instead of a refusal. EP-05 returns MANUAL_REVIEW
     (`not_automatable`) and points to EP-10. Whether a paid alternative gives
     a free choice is a legal assessment made case by case.
5. **Banner detection requires consent wording in the layer's own text**, not
   only inside a control label. On cnil.fr, a sticky navigation bar with a
   "Gestionnaire de cookies" link had been taken for a weak banner candidate.

## Consequences

Some real sites get more "Review suggested" verdicts. That is intended: per
the design review, a false "please review" is much cheaper than a false
"issue detected" on a named company.
