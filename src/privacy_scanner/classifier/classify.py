"""Evidence Bundle -> Classification. Pure: no I/O beyond the knowledge base.

The classifier answers "what is this?" (an analytics cookie, a marketing
pixel, a consent banner with an accept and a reject button). It never answers
"is this lawful?": that is the rules engine's job (ADR-0003).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from privacy_scanner.classifier.knowledge import (
    CmpSignature,
    KnowledgeBase,
    default_knowledge_base,
    normalize_text,
)
from privacy_scanner.domain.classification import (
    BannerConfidence,
    BannerDetection,
    Category,
    Classification,
    ClassificationSource,
    ClassifiedCookie,
    ClassifiedStorageKey,
    CmpDetection,
    ConsentControl,
    ControlRole,
    Exemption,
    KnowledgeMatch,
    Party,
    ThirdPartyContact,
)
from privacy_scanner.domain.evidence import (
    EvidenceBundle,
    FrameUi,
    RequestRecord,
    SessionEvidence,
    SessionKind,
    UiControl,
    UiLayer,
    UiLayerKind,
)
from privacy_scanner.domain.sites import cookie_host, registrable_domain

MAX_SAMPLE_URLS = 3
MAX_SAMPLE_URL_CHARS = 200
BANNER_EXCERPT_CHARS = 300
_BEACON_TYPES = frozenset({"ping", "beacon"})
_FETCH_TYPES = frozenset({"xhr", "fetch"})

UNCLASSIFIED = KnowledgeMatch(
    category=Category.UNKNOWN,
    exemption=Exemption.UNKNOWN,
    source=ClassificationSource.NONE,
)

# How strongly a category points at tracking; used to label a site that
# serves several kinds of requests by its most tracking-like one.
_SEVERITY = {
    Category.MARKETING: 6,
    Category.ANALYTICS: 5,
    Category.UNKNOWN: 4,
    Category.FUNCTIONAL: 3,
    Category.CONSENT_MANAGEMENT: 2,
    Category.STRICTLY_NECESSARY: 1,
    Category.INFRASTRUCTURE: 0,
}


def page_site(bundle: EvidenceBundle) -> str:
    """Registrable domain of the page actually observed (after redirects)."""
    s0 = bundle.session(SessionKind.BASELINE)
    url = s0.navigation.final_url if s0 and s0.navigation else bundle.target.normalized_url
    host = urlsplit(url).hostname or ""
    return registrable_domain(host) if host else ""


def classify(bundle: EvidenceBundle, kb: KnowledgeBase | None = None) -> Classification:
    kb = kb or default_knowledge_base()
    site = page_site(bundle)
    cookies: list[ClassifiedCookie] = []
    storage: list[ClassifiedStorageKey] = []
    contacts: list[ThirdPartyContact] = []
    for session in bundle.sessions:
        cookies += _cookies(session, site, kb)
        storage += _storage(session, site, kb)
        contacts += _third_parties(session, site, kb)

    cmps = _detect_cmps(bundle, kb)
    s0 = bundle.session(SessionKind.BASELINE)
    captured = s0 is not None and s0.consent_ui is not None
    banner = _detect_banner(s0.consent_ui or (), kb, cmps) if s0 is not None else None
    return Classification(
        knowledge_base=kb.info,
        page_site=site,
        cookies=tuple(cookies),
        storage=tuple(storage),
        third_parties=tuple(contacts),
        cmps=cmps,
        banner=banner,
        banner_evidence_captured=captured,
    )


# --------------------------------------------------------------------------- #
# Cookies, storage, third parties
# --------------------------------------------------------------------------- #
def _party(host: str, site: str) -> Party:
    return Party.FIRST if registrable_domain(host) == site else Party.THIRD


def _cookies(session: SessionEvidence, site: str, kb: KnowledgeBase) -> list[ClassifiedCookie]:
    out = []
    for cookie in session.cookies:
        host = cookie_host(cookie.domain)
        out.append(
            ClassifiedCookie(
                session=session.kind,
                name=cookie.name,
                domain=cookie.domain,
                party=_party(host, site),
                lifetime_seconds=cookie.lifetime_seconds,
                first_observed_ms=cookie.first_observed_ms,
                match=kb.lookup_name(cookie.name, host, "cookie") or UNCLASSIFIED,
            )
        )
    return out


def _storage(session: SessionEvidence, site: str, kb: KnowledgeBase) -> list[ClassifiedStorageKey]:
    out = []
    for item in session.storage:
        host = urlsplit(item.origin).hostname or ""
        out.append(
            ClassifiedStorageKey(
                session=session.kind,
                origin=item.origin,
                area=item.area,
                key=item.key,
                party=_party(host, site),
                value_length=item.value.length,
                match=kb.lookup_name(item.key, host, "storage") or UNCLASSIFIED,
            )
        )
    return out


def _beacon_like(request: RequestRecord) -> bool:
    if request.resource_type in _BEACON_TYPES:
        return True
    if request.resource_type in _FETCH_TYPES and request.method.upper() == "POST":
        return True
    return request.resource_type == "image" and bool(urlsplit(request.url).query)


@dataclass(slots=True)
class _ContactAcc:
    match: KnowledgeMatch
    hosts: set[str]
    count: int = 0
    blocked: int = 0
    first_ms: int | None = None
    types: set[str] = field(default_factory=set)
    samples: list[str] = field(default_factory=list)
    beacon: bool = False


def _third_parties(
    session: SessionEvidence, site: str, kb: KnowledgeBase
) -> list[ThirdPartyContact]:
    groups: dict[tuple[str, str | None, Category], _ContactAcc] = {}
    for request in session.requests:
        parts = urlsplit(request.url)
        host = parts.hostname
        if not host or parts.scheme not in ("http", "https", "ws", "wss"):
            continue
        req_site = registrable_domain(host)
        if req_site == site:
            continue
        match = kb.lookup_host(host, parts.path or "/") or UNCLASSIFIED
        key = (req_site, match.vendor, match.category)
        acc = groups.get(key)
        if acc is None:
            acc = groups[key] = _ContactAcc(match=match, hosts=set())
        acc.hosts.add(host)
        acc.count += 1
        acc.types.add(request.resource_type)
        if request.blocked_by is not None:
            acc.blocked += 1
            continue
        acc.first_ms = (
            request.started_ms if acc.first_ms is None else min(acc.first_ms, request.started_ms)
        )
        acc.beacon = acc.beacon or _beacon_like(request)
        if len(acc.samples) < MAX_SAMPLE_URLS and request.url not in acc.samples:
            acc.samples.append(request.url[:MAX_SAMPLE_URL_CHARS])

    contacts = [
        ThirdPartyContact(
            session=session.kind,
            site=req_site,
            hosts=tuple(sorted(acc.hosts)),
            request_count=acc.count,
            blocked_count=acc.blocked,
            first_request_ms=acc.first_ms or 0,
            resource_types=tuple(sorted(acc.types)),
            sample_urls=tuple(acc.samples),
            beacon_like=acc.beacon,
            match=acc.match,
        )
        for (req_site, _, _), acc in groups.items()
        if acc.count > acc.blocked
    ]
    contacts.sort(key=lambda c: (-_SEVERITY[c.match.category], c.first_request_ms))
    return contacts


# --------------------------------------------------------------------------- #
# CMP detection
# --------------------------------------------------------------------------- #
def _detect_cmps(bundle: EvidenceBundle, kb: KnowledgeBase) -> tuple[CmpDetection, ...]:
    signals: dict[str, set[str]] = defaultdict(set)
    by_key = {sig.key: sig for sig in kb.cmps}
    for session in bundle.sessions:
        for request in session.requests:
            parts = urlsplit(request.url)
            host = parts.hostname or ""
            for sig in kb.cmps:
                if sig.matches_host(host):
                    signals[sig.key].add(f"request to {host}")
                elif sig.path_pattern is not None and sig.path_pattern.search(parts.path):
                    signals[sig.key].add(f"script {parts.path[:80]}")
        names = [c.name for c in session.cookies] + [s.key for s in session.storage]
        for sig in kb.cmps:
            for name in names:
                if _record_matches(sig, name):
                    signals[sig.key].add(f"consent record {name}")
        for frame in session.consent_ui or ():
            for layer in frame.layers:
                for sig in kb.cmps:
                    if sig.element_pattern is not None and sig.element_pattern.search(
                        layer.element
                    ):
                        signals[sig.key].add(f"banner element {layer.element[:60]}")
    return tuple(
        CmpDetection(name=by_key[key].name, signals=tuple(sorted(found)))
        for key, found in sorted(signals.items())
    )


def _record_matches(sig: CmpSignature, name: str) -> bool:
    return any(
        name.startswith(record[:-1]) if record.endswith("*") else name == record
        for record in sig.record_names
    )


# --------------------------------------------------------------------------- #
# Banner detection
# --------------------------------------------------------------------------- #
def control_role(control: UiControl, kb: KnowledgeBase) -> tuple[ControlRole, str | None]:
    """Role of a control from its label (or aria-label), and the lexicon language."""
    lexicon = kb.lexicon
    for raw in (control.label, control.aria_label or ""):
        text = normalize_text(raw)
        if not text:
            continue
        if text in lexicon.reject:
            return ControlRole.REJECT, lexicon.reject[text]
        if text in lexicon.accept:
            return ControlRole.ACCEPT, lexicon.accept[text]
        if text in lexicon.settings:
            return ControlRole.SETTINGS, lexicon.settings[text]
        if text in lexicon.close:
            return ControlRole.CLOSE, None
    for raw in (control.label, control.aria_label or ""):
        if lexicon.is_subscribe(normalize_text(raw)):
            return ControlRole.SUBSCRIBE, None
    return ControlRole.OTHER, None


@dataclass(frozen=True, slots=True)
class _Candidate:
    score: int
    area: float
    frame: FrameUi
    layer: UiLayer
    controls: tuple[ConsentControl, ...]
    languages: tuple[str, ...]
    cmp: str | None
    confidence: BannerConfidence


def _detect_banner(
    frames: tuple[FrameUi, ...], kb: KnowledgeBase, cmps: tuple[CmpDetection, ...]
) -> BannerDetection | None:
    candidates: list[_Candidate] = []
    for frame in frames:
        for layer in frame.layers:
            candidate = _evaluate_layer(frame, layer, kb)
            if candidate is not None:
                candidates.append(candidate)
    if not candidates:
        return None
    best = max(candidates, key=lambda c: (c.score, c.area))
    cmp_name = best.cmp or (cmps[0].name if len(cmps) == 1 else None)
    return BannerDetection(
        frame_index=best.frame.frame_index,
        frame_url=best.frame.frame_url,
        in_main_frame=best.frame.is_main,
        layer_id=best.layer.layer_id,
        layer_kind=best.layer.kind,
        element=best.layer.element,
        text_excerpt=best.layer.text[:BANNER_EXCERPT_CHARS],
        language_hits=best.languages,
        controls=best.controls,
        cmp=cmp_name,
        confidence=best.confidence,
    )


def _evaluate_layer(frame: FrameUi, layer: UiLayer, kb: KnowledgeBase) -> _Candidate | None:
    members = [c for c in frame.controls if c.layer_id == layer.layer_id]
    if not any(c.in_viewport for c in members):
        return None  # not visible to a first-time visitor without scrolling
    frame_host = "" if frame.is_main else (urlsplit(frame.frame_url).hostname or "")
    cmp_match = next(
        (
            sig.name
            for sig in kb.cmps
            if (sig.element_pattern is not None and sig.element_pattern.search(layer.element))
            or (frame_host and sig.matches_host(frame_host))
        ),
        None,
    )
    # Consent wording must appear in the layer's own prose, not only inside a
    # control: a navigation bar with a "Gestionnaire de cookies" link is not a
    # banner (found on cnil.fr, which shows no banner at all).
    prose = normalize_text(layer.text)
    for control in members:
        label = normalize_text(control.label)
        if label:
            prose = prose.replace(label, " ", 1)
    has_terms = bool(kb.lexicon.banner_languages(" ".join(prose.split())))
    controls: list[ConsentControl] = []
    languages: set[str] = set()
    for control in members:
        role, lang = control_role(control, kb)
        if lang:
            languages.add(lang)
        controls.append(
            ConsentControl(
                label=control.label or control.aria_label or "",
                role=role,
                tag=control.tag,
                in_viewport=control.in_viewport,
                box=control.box,
                font_size_px=control.font_size_px,
                color=control.color,
                background_color=control.background_color,
            )
        )
    roles = {c.role for c in controls}
    has_choice = bool(roles & {ControlRole.ACCEPT, ControlRole.REJECT})
    # A layer qualifies through consent wording or a known CMP container. A
    # lone "OK" button in a sticky header is not a consent banner.
    if not has_terms and cmp_match is None:
        return None

    score = (
        (4 if cmp_match else 0)
        + (3 if ControlRole.ACCEPT in roles else 0)
        + (2 if ControlRole.REJECT in roles else 0)
        + (1 if layer.kind in (UiLayerKind.FIXED, UiLayerKind.DIALOG, UiLayerKind.FRAME) else 0)
        + (1 if has_terms else 0)
    )
    if has_choice and cmp_match:
        confidence = BannerConfidence.HIGH
    elif has_choice:
        confidence = BannerConfidence.MEDIUM
    else:
        confidence = BannerConfidence.LOW
    return _Candidate(
        score=score,
        area=layer.box.width * layer.box.height,
        frame=frame,
        layer=layer,
        controls=tuple(controls),
        languages=tuple(sorted(languages)),
        cmp=cmp_match,
        confidence=confidence,
    )
