# ADR-0012: Consent-UI snapshot as evidence (bundle schema 1.1.0)

- **Status:** Accepted
- **Date:** 2026-10-16
- **Source:** Phase 2; design review §2.1, risk R4

## Context

EP-04 (is there a consent interface?) and EP-05 (is "reject" on the first
layer?) need to know what the visitor *sees*. The Phase 1 bundle holds the raw
DOM per frame, but judging a banner from the DOM alone is unreliable in ways
that would accuse sites wrongly:

- CMPs ship hidden templates. A `display:none` second layer containing "Tout
  refuser" would make a DOM-only check pass a banner that offers no refusal
  on screen. The `no-reject.html` fixture reproduces this.
- Visibility, position (fixed overlay vs page content), size, contrast and
  "is it on the first screen" exist only after layout, as computed styles.

Vision models were ruled out for verdicts (ADR-0002).

## Decision

At the end of the S0 observation window, the collector runs a read-only
script in every frame (`scan_consent_ui.js`) and records a **factual
snapshot**: `SessionEvidence.consent_ui: tuple[FrameUi, ...] | None`.

- **Controls:** visible `button`, `a[href]`, `input[type=button|submit]`,
  `[role=button|link]` and `[onclick]` elements, including those in open
  shadow roots. "Visible" means `checkVisibility()` (opacity, visibility) and
  a non-empty box. For each: label (text, else aria-label/value/title), box,
  in-viewport flag, font size and weight, text colour, effective background.
- **Layers:** each control is attached to its nearest `position: fixed|sticky`
  ancestor, open `<dialog>` / `role=dialog|alertdialog` / `aria-modal`, or,
  failing that, an ancestor whose id/class looks like a CMP container. Inside
  an embedded frame, the frame's document is the layer (CMPs in cross-origin
  iframes). The layer's visible text (≤ 2,000 chars) and an element hint are
  kept. The hint of an element in a shadow root is prefixed with its host
  (`div#usercentrics-root >> div`), because the host carries the CMP's name.
- Only controls inside a layer are detailed; others are counted. Limits: 300
  controls, 40 layers per frame.
- The snapshot makes **no judgement**: which layer is a banner and what a
  button means is decided later by the classifier (ADR-0003).
- Schema bump to **1.1.0** (additive). `None` means "not captured" (1.0.0
  bundles, or capture failed). An empty tuple means "captured, nothing found".
  Rules must tell those apart: a missing snapshot yields `ERROR`, never
  "no banner".

## Consequences

- EP-06 (prominence: size, contrast) in Phase 3 can use the same evidence
  without another collector change.
- Page text in the snapshot is public page content. It contains no visitor
  data, since the scanner is the only visitor.
- Blind spots, stated in report limitations: closed shadow roots, banners
  drawn on canvas or as images, controls that are plain `div`s with JS click
  handlers and no role.
