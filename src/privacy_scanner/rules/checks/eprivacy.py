"""ePrivacy Directive checks (Phase 2: EP-01/02/03/04/05/09).

Each check reads the baseline session (S0: no interaction, so everything in
it happened *before consent*) through the classification, and returns a
``CheckResult``. Wording lives in the catalog; checks only supply facts.
"""

from __future__ import annotations

import re

from privacy_scanner.classifier.knowledge import normalize_text
from privacy_scanner.domain.classification import (
    BannerConfidence,
    BannerDetection,
    Category,
    ClassifiedCookie,
    ClassifiedStorageKey,
    ControlRole,
    Exemption,
    Party,
    ThirdPartyContact,
)
from privacy_scanner.domain.evidence import SessionKind
from privacy_scanner.domain.report import (
    Confidence,
    EvidenceItem,
    EvidenceKind,
    ReviewReason,
    Verdict,
)
from privacy_scanner.rules.checks._common import (
    DAY_S,
    contact_evidence,
    cookie_evidence,
    describe,
    join_items,
    lifetime,
    match_confidence,
    seconds,
    storage_evidence,
)
from privacy_scanner.rules.engine import CheckContext, CheckResult

# CNIL: audience-measurement tracker lifetime "such as thirteen months"
# (recommendation 2020-092 as amended, §5). 13 x 30.4375 days, rounded up.
THIRTEEN_MONTHS_S = 396 * DAY_S
# Chromium caps cookie expiry at 400 days (since Chrome 104), so a longer
# lifetime set by the site is observed as ~400 days.
CHROMIUM_LIFETIME_CAP_S = 400 * DAY_S

_REVIEW_EXEMPTIONS = (Exemption.CONDITIONAL, Exemption.UNKNOWN)
_IDENTIFIER_KEY = re.compile(
    r"(^|[_\-.:/])(u?id|uuid|guid|cid|vid|visitor|user|device|client|anon\w*|fp|"
    r"fingerprint|track\w*|session)([_\-.:/]|$)|uuid|visitor|fingerprint|tracking|anonymous",
)
# Words that, inside an unrecognised control label, suggest it might be a
# refusal option the lexicon does not know. Normalised (accent-free) forms.
_REFUSAL_HINTS = re.compile(
    r"\b(refus\w*|reject\w*|declin\w*|deny|denied|sans|without|ohne|sin|non|no|nein|"
    r"ablehn\w*|rechaz\w*|necessaire\w*|necessar\w*|essential\w*|essenziel\w*|notwendig\w*|"
    r"erforderlich\w*|interdire|continuer|continue)\b"
)


def _baseline_items[Item: (ClassifiedCookie, ClassifiedStorageKey, ThirdPartyContact)](
    items: tuple[Item, ...],
) -> list[Item]:
    """Records from S0, i.e. observed before any consent interaction."""
    return [item for item in items if item.session is SessionKind.BASELINE]


def _review_reason(exemptions: list[Exemption]) -> ReviewReason:
    if Exemption.UNKNOWN in exemptions:
        return ReviewReason.UNCLASSIFIED_ITEMS
    return ReviewReason.CONFIGURATION_NOT_OBSERVABLE


# --------------------------------------------------------------------------- #
# EP-01
# --------------------------------------------------------------------------- #
def cookies_before_consent(ctx: CheckContext) -> CheckResult:
    cookies = _baseline_items(ctx.classification.cookies)
    blocking = [c for c in cookies if c.match.exemption is Exemption.NOT_EXEMPT]
    review = [c for c in cookies if c.match.exemption in _REVIEW_EXEMPTIONS]
    exempt = [c for c in cookies if c.match.exemption is Exemption.EXEMPT]

    def label(c: ClassifiedCookie) -> str:
        return f"{c.name} ({describe(c.match)}, {c.party.value}-party)"

    if blocking:
        return CheckResult(
            verdict=Verdict.FAIL,
            confidence=match_confidence([c.match for c in blocking]),
            params={"count": str(len(blocking)), "items": join_items([label(c) for c in blocking])},
            evidence=tuple(cookie_evidence(c) for c in [*blocking, *review]),
        )
    if review:
        return CheckResult(
            verdict=Verdict.MANUAL_REVIEW,
            confidence=Confidence.MEDIUM,
            review_reason=_review_reason([c.match.exemption for c in review]),
            params={"count": str(len(review)), "items": join_items([label(c) for c in review])},
            evidence=tuple(cookie_evidence(c) for c in review),
        )
    window = seconds(ctx.baseline.observation_window_ms)
    if exempt:
        summary = (
            f"{len(exempt)} cookie(s) were classified as strictly necessary or as a consent "
            f"record: {join_items([c.name for c in exempt])}."
        )
    else:
        summary = "No cookie was stored."
    return CheckResult(
        verdict=Verdict.PASS,
        confidence=Confidence.HIGH,
        params={"window": window, "exempt_summary": summary},
        evidence=tuple(cookie_evidence(c) for c in exempt),
    )


# --------------------------------------------------------------------------- #
# EP-02
# --------------------------------------------------------------------------- #
def tracking_requests_before_consent(ctx: CheckContext) -> CheckResult:
    contacts = _baseline_items(ctx.classification.third_parties)
    tracking = [c for c in contacts if c.match.exemption is Exemption.NOT_EXEMPT]
    conditional = [c for c in contacts if c.match.exemption is Exemption.CONDITIONAL]
    unknown = [c for c in contacts if c.match.exemption is Exemption.UNKNOWN]
    suspicious_unknown = [c for c in unknown if c.beacon_like]

    def label(c: ThirdPartyContact) -> str:
        vendor = c.match.vendor or c.site
        return f"{vendor} ({c.site}, first request at {seconds(c.first_request_ms)})"

    if tracking:
        return CheckResult(
            verdict=Verdict.FAIL,
            confidence=match_confidence([c.match for c in tracking]),
            params={"count": str(len(tracking)), "items": join_items([label(c) for c in tracking])},
            evidence=tuple(contact_evidence(c) for c in [*tracking, *suspicious_unknown]),
        )
    review = [*conditional, *suspicious_unknown]
    if review:
        return CheckResult(
            verdict=Verdict.MANUAL_REVIEW,
            confidence=Confidence.MEDIUM,
            review_reason=_review_reason([c.match.exemption for c in review]),
            params={"count": str(len(review)), "items": join_items([label(c) for c in review])},
            evidence=tuple(contact_evidence(c) for c in review),
        )
    others = [c for c in contacts if c not in unknown]
    parts = []
    if others:
        names = join_items([c.match.vendor or c.site for c in others])
        parts.append(f"Other third parties contacted: {names}.")
    if unknown:
        parts.append(
            f"{len(unknown)} unclassified third-party site(s) served content without "
            f"beacon-like requests: {join_items([c.site for c in unknown])}."
        )
    return CheckResult(
        verdict=Verdict.PASS,
        # Unclassified sites without beacons are probably content hosts, but we
        # cannot be sure: say so through confidence.
        confidence=Confidence.MEDIUM if unknown else Confidence.HIGH,
        params={"other_summary": " ".join(parts) or "No third-party site was contacted."},
        evidence=tuple(contact_evidence(c) for c in contacts),
    )


# --------------------------------------------------------------------------- #
# EP-03
# --------------------------------------------------------------------------- #
def _looks_like_identifier(item: ClassifiedStorageKey) -> bool:
    return item.party is Party.THIRD or bool(_IDENTIFIER_KEY.search(item.key.lower()))


def storage_before_consent(ctx: CheckContext) -> CheckResult:
    items = _baseline_items(ctx.classification.storage)
    tracking = [i for i in items if i.match.exemption is Exemption.NOT_EXEMPT]
    conditional = [i for i in items if i.match.exemption is Exemption.CONDITIONAL]
    unknown = [i for i in items if i.match.exemption is Exemption.UNKNOWN]
    suspicious = [i for i in unknown if _looks_like_identifier(i)]

    def label(i: ClassifiedStorageKey) -> str:
        return f"{i.key} ({i.area.value} of {i.origin})"

    if tracking:
        return CheckResult(
            verdict=Verdict.FAIL,
            # Tier B: key names are a weaker signal than cookie names.
            confidence=Confidence.MEDIUM,
            params={"count": str(len(tracking)), "items": join_items([label(i) for i in tracking])},
            evidence=tuple(storage_evidence(i) for i in [*tracking, *suspicious]),
        )
    review = [*conditional, *suspicious]
    if review:
        return CheckResult(
            verdict=Verdict.MANUAL_REVIEW,
            confidence=Confidence.MEDIUM,
            review_reason=_review_reason([i.match.exemption for i in review]),
            params={"count": str(len(review)), "items": join_items([label(i) for i in review])},
            evidence=tuple(storage_evidence(i) for i in review),
        )
    if items:
        summary = (
            f"{len(items)} other key(s) were written, none identified as a tracker: "
            f"{join_items([i.key for i in items])}."
        )
    else:
        summary = "No Web Storage key was written."
    return CheckResult(
        verdict=Verdict.PASS,
        confidence=Confidence.MEDIUM if unknown else Confidence.HIGH,
        params={"other_summary": summary},
        evidence=tuple(storage_evidence(i) for i in items),
    )


# --------------------------------------------------------------------------- #
# EP-04 / EP-05: consent interface
# --------------------------------------------------------------------------- #
def _consent_requiring(ctx: CheckContext) -> list[str]:
    """Labels of everything in S0 that requires consent (not-exempt)."""
    c = ctx.classification
    found = [
        f"cookie {x.name}"
        for x in _baseline_items(c.cookies)
        if x.match.exemption is Exemption.NOT_EXEMPT
    ]
    found += [
        f"{x.match.vendor or x.site} requests"
        for x in _baseline_items(c.third_parties)
        if x.match.exemption is Exemption.NOT_EXEMPT
    ]
    found += [
        f"storage key {x.key}"
        for x in _baseline_items(c.storage)
        if x.match.exemption is Exemption.NOT_EXEMPT
    ]
    return found


def _banner_evidence(banner: BannerDetection) -> tuple[EvidenceItem, ...]:
    items = [
        EvidenceItem(
            kind=EvidenceKind.BANNER,
            session=SessionKind.BASELINE,
            label=banner.cmp or "Consent interface",
            details=(
                ("Element", banner.element),
                ("Layer", banner.layer_kind.value),
                ("Frame", "main page" if banner.in_main_frame else banner.frame_url),
                ("Detection confidence", banner.confidence.value),
                ("Text (excerpt)", banner.text_excerpt),
            ),
        )
    ]
    items += [
        EvidenceItem(
            kind=EvidenceKind.CONTROL,
            session=SessionKind.BASELINE,
            label=control.label or "(no text)",
            details=(
                ("Interpreted as", control.role.value),
                ("Element", control.tag),
                ("Visible without scrolling", "yes" if control.in_viewport else "no"),
                ("Size", f"{control.box.width:.0f} x {control.box.height:.0f} px"),
                ("Font size", f"{control.font_size_px:g} px" if control.font_size_px else "—"),
                ("Text colour", control.color or "—"),
                ("Background", control.background_color or "—"),
            ),
        )
        for control in banner.controls
    ]
    return tuple(items)


def _describe_banner(banner: BannerDetection) -> str:
    roles = sorted({c.role.value for c in banner.controls if c.role is not ControlRole.OTHER})
    name = banner.cmp or "unidentified platform"
    return f"{name}; controls recognised: {', '.join(roles) or 'none'}"


def consent_mechanism_present(ctx: CheckContext) -> CheckResult:
    c = ctx.classification
    if not c.banner_evidence_captured:
        return CheckResult(
            verdict=Verdict.ERROR,
            confidence=Confidence.HIGH,
            params={"reason": "this evidence bundle has no consent-interface snapshot"},
        )
    requiring = _consent_requiring(ctx)
    banner = c.banner
    usable = banner is not None and banner.confidence is not BannerConfidence.LOW

    if banner is not None and usable:
        return CheckResult(
            verdict=Verdict.PASS,
            confidence=Confidence.HIGH
            if banner.confidence is BannerConfidence.HIGH
            else Confidence.MEDIUM,
            params={"banner": _describe_banner(banner)},
            evidence=_banner_evidence(banner),
        )
    if not requiring:
        return CheckResult(verdict=Verdict.NOT_APPLICABLE, confidence=Confidence.MEDIUM)
    if banner is not None:  # low-confidence banner
        return CheckResult(
            verdict=Verdict.MANUAL_REVIEW,
            confidence=Confidence.LOW,
            review_reason=ReviewReason.LOW_CONFIDENCE_SIGNAL,
            params={
                "detail": "Trackers requiring consent were observed "
                f"({join_items(requiring)}). An overlay with consent wording was found "
                f"({banner.element}), but none of its controls was recognised as accept or "
                "reject, so it is unclear whether it offers a consent choice."
            },
            evidence=_banner_evidence(banner),
        )
    if c.cmps:
        names = join_items([cmp.name for cmp in c.cmps])
        return CheckResult(
            verdict=Verdict.MANUAL_REVIEW,
            confidence=Confidence.LOW,
            review_reason=ReviewReason.LOW_CONFIDENCE_SIGNAL,
            params={
                "detail": "Trackers requiring consent were observed "
                f"({join_items(requiring)}). A consent platform was loaded ({names}), but no "
                "consent interface was visible on the first screen. It may be rendered in a "
                "way the scanner cannot see (for example a closed shadow root) or not shown."
            },
            evidence=tuple(
                EvidenceItem(
                    kind=EvidenceKind.CMP,
                    session=SessionKind.BASELINE,
                    label=cmp.name,
                    details=tuple(("Signal", s) for s in cmp.signals),
                )
                for cmp in c.cmps
            ),
        )
    return CheckResult(
        verdict=Verdict.FAIL,
        # Banner detection is heuristic (closed shadow roots, unusual markup),
        # hence medium rather than high.
        confidence=Confidence.MEDIUM,
        params={"trackers": join_items(requiring)},
    )


def _possible_refusal(label: str) -> bool:
    return bool(_REFUSAL_HINTS.search(normalize_text(label)))


def reject_on_first_layer(ctx: CheckContext) -> CheckResult:
    c = ctx.classification
    if not c.banner_evidence_captured:
        return CheckResult(
            verdict=Verdict.ERROR,
            confidence=Confidence.HIGH,
            params={"reason": "this evidence bundle has no consent-interface snapshot"},
        )
    banner = c.banner
    if banner is None:
        return CheckResult(
            verdict=Verdict.NOT_APPLICABLE,
            confidence=Confidence.MEDIUM,
            params={
                "detail": "No consent interface was detected, so there is no first layer to "
                "examine. Whether one is needed is covered by EP-04."
            },
        )
    evidence = _banner_evidence(banner)
    labels = [ctl.label for ctl in banner.controls]
    if banner.confidence is BannerConfidence.LOW:
        return CheckResult(
            verdict=Verdict.MANUAL_REVIEW,
            confidence=Confidence.LOW,
            review_reason=ReviewReason.LOW_CONFIDENCE_SIGNAL,
            params={
                "detail": f"An overlay with consent wording was found ({banner.element}), but "
                "none of its controls matched the French, English, Spanish or German consent "
                f"lexicon: {join_items(labels)}. Whether it offers a refusal option needs checking."
            },
            evidence=evidence,
        )

    accept = banner.controls_with(ControlRole.ACCEPT)
    reject = banner.controls_with(ControlRole.REJECT)
    base = Confidence.HIGH if banner.confidence is BannerConfidence.HIGH else Confidence.MEDIUM
    if reject:
        return CheckResult(
            verdict=Verdict.PASS,
            confidence=base,
            params={
                "reject": join_items([f"“{r.label}”" for r in reject]),
                "accept": join_items([f"“{a.label}”" for a in accept]) if accept else "none found",
            },
            evidence=evidence,
        )

    return _no_refusal_option(banner, base, evidence)


def _no_refusal_option(
    banner: BannerDetection, base: Confidence, evidence: tuple[EvidenceItem, ...]
) -> CheckResult:
    """EP-05 when no recognised reject control is on the first layer."""
    accept = banner.controls_with(ControlRole.ACCEPT)
    accept_text = join_items([f"“{a.label}”" for a in accept]) if accept else "none found"
    subscribe = banner.controls_with(ControlRole.SUBSCRIBE)
    if subscribe:
        return CheckResult(
            verdict=Verdict.MANUAL_REVIEW,
            confidence=base,
            review_reason=ReviewReason.NOT_AUTOMATABLE,
            params={
                "detail": f"The first layer offers acceptance ({accept_text}) or a paid "
                f"alternative ({join_items([f'“{s.label}”' for s in subscribe])}), but no free "
                "refusal option. Whether a “pay or consent” model leaves a genuinely free "
                "choice is a legal assessment made case by case; see EP-10 (cookie walls)."
            },
            evidence=evidence,
        )

    others = [ctl for ctl in banner.controls if ctl.role is not ControlRole.ACCEPT]
    ambiguous = [
        ctl for ctl in others if ctl.role is ControlRole.OTHER and _possible_refusal(ctl.label)
    ]
    # The CNIL accepts closing the banner as a refusal only when the banner
    # says so clearly; reading that sentence reliably is beyond the lexicon.
    # Either case is a low-confidence signal, which the engine downgrades.
    uncertain = bool(ambiguous) or bool(banner.controls_with(ControlRole.CLOSE))
    return CheckResult(
        verdict=Verdict.FAIL,
        confidence=Confidence.LOW if uncertain else base,
        params={
            "accept": accept_text,
            "others": join_items([f"“{o.label}” ({o.role.value})" for o in others])
            if others
            else "none",
        },
        evidence=evidence,
    )


# --------------------------------------------------------------------------- #
# EP-09
# --------------------------------------------------------------------------- #
def analytics_cookie_lifetime(ctx: CheckContext) -> CheckResult:
    analytics = [
        c
        for c in _baseline_items(ctx.classification.cookies)
        if c.match.category is Category.ANALYTICS
    ]
    if not analytics:
        return CheckResult(verdict=Verdict.NOT_APPLICABLE, confidence=Confidence.HIGH)

    def label(c: ClassifiedCookie) -> str:
        return f"{c.name} ({lifetime(c.lifetime_seconds)})"

    too_long = [c for c in analytics if (c.lifetime_seconds or 0) > THIRTEEN_MONTHS_S]
    if too_long:
        capped = any((c.lifetime_seconds or 0) >= CHROMIUM_LIFETIME_CAP_S - DAY_S for c in too_long)
        return CheckResult(
            verdict=Verdict.FAIL,
            confidence=match_confidence([c.match for c in too_long]),
            params={
                "count": str(len(too_long)),
                "items": join_items([label(c) for c in too_long]),
                "cap_note": "The browser used caps cookie lifetimes at 400 days, so the lifetime "
                "set by the site may be even longer."
                if capped
                else "",
            },
            evidence=tuple(cookie_evidence(c) for c in too_long),
        )
    return CheckResult(
        verdict=Verdict.PASS,
        confidence=match_confidence([c.match for c in analytics]),
        params={"items": join_items([label(c) for c in analytics])},
        evidence=tuple(cookie_evidence(c) for c in analytics),
    )
