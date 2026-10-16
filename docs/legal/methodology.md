# Methodology

How the scanner reaches each statement in a report, written for a privacy
lawyer or DPO reviewing it. The rule-by-rule wording and citations are in the
[rule catalog](rule-catalog.md).

## 1. Observation

One page (the address given) is loaded once in Chromium with an empty
profile, as a first-time visitor from France (`fr-FR`, `Europe/Paris`,
1366×768 desktop). After `load` and network idle, the page is observed for 6
seconds **without any interaction**: no clicks, scrolling or key presses,
since some consent platforms treat scrolling as consent (ADR-0010). Recorded:

- every cookie, with the moment it first appeared (polled every 250 ms);
- every network request (address, type, timing, initiator frame);
- localStorage/sessionStorage keys per origin (values never stored, only a
  length and a per-scan keyed fingerprint);
- the visible overlay layers and their buttons/links: label, size, colours
  (ADR-0012);
- a screenshot of the first screen.

Everything in this session happened **before any consent**.

## 2. Classification

Each cookie, storage key and third-party host is matched against: consent-
platform signatures; a curated knowledge base with vendor documentation;
then the community Open Cookie Database (Apache-2.0, pinned version). Each
item gets a category and an exemption status (ADR-0013):

- **exempt:** strictly necessary, consent records, technical infrastructure;
- **conditional:** may be exempt depending on purpose or configuration (functional
  features; analytics tools that offer the CNIL audience-measurement
  configuration);
- **not exempt:** analytics without such a configuration, advertising,
  cross-site tracking;
- **unknown:** not classified, and **never assumed exempt**.

The report states which source classified each item. As the EDPB Cookie
Banner Taskforce notes, tools can list cookies but cannot prove their
purpose. Classification by name is an indication, and unknown items are
listed for review.

## 3. Judgement

Rules are applied to the classification. Each finding gets:

- a **verdict**: *Issue detected*, *No issue detected*, *Review suggested*
  (with a reason), *Not applicable*, *Could not be evaluated*. The words
  "compliant" and "non-compliant" are never used (ADR-0004);
- a **confidence**. An *Issue detected* with low confidence is automatically
  shown as *Review suggested* (ADR-0014);
- the **binding provision** (EUR-Lex) and the **interpretive sources**, each
  tagged with jurisdiction (EU/FR) and whether it is binding;
- the **evidence** it relies on.

The scanner refrains from concluding when an answer depends on things it
cannot see: configuration of an analytics tool, a "pay or consent" model, a
banner it cannot read reliably, a page behind a bot challenge.

## 4. Score

Per regulation: severity-weighted share of "No issue detected" among checks
that reached a verdict (high 5, medium 3, low 1), always printed with its
coverage ("based on 5 of 11 catalogued checks"). It describes exposure
visible from outside, not legal conformity (ADR-0015).

## 5. Reproducibility

Every report carries the catalog version and hash, the law-as-of date, the
knowledge-base hash, the Open Cookie Database commit, the browser version and
profile, and the vantage point. Evidence is kept, so a scan can be re-judged
later with `privacy-scanner assess` without revisiting the site.

## 6. Interactions with scanned sites

In Phase 2 the scanner does not click anything. From Phase 3 it will click
only the consent controls of the banner (accept or reject, each in its own
fresh session), never forms or purchases (risk R15).
