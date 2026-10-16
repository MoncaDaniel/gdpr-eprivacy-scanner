"""Formatting helpers shared by checks: plain-language lists and evidence items."""

from __future__ import annotations

from collections.abc import Sequence

from privacy_scanner.domain.classification import (
    ClassificationSource,
    ClassifiedCookie,
    ClassifiedStorageKey,
    KnowledgeMatch,
    ThirdPartyContact,
)
from privacy_scanner.domain.report import Confidence, EvidenceItem, EvidenceKind
from privacy_scanner.formatting import DAY_S, MAX_LISTED, join_items, lifetime, seconds

__all__ = [
    "DAY_S",
    "MAX_LISTED",
    "contact_evidence",
    "cookie_evidence",
    "describe",
    "join_items",
    "lifetime",
    "match_confidence",
    "seconds",
    "storage_evidence",
]


def describe(match: KnowledgeMatch) -> str:
    vendor = match.vendor or "unknown vendor"
    return f"{vendor}, {match.category.value.replace('_', ' ')}"


def match_confidence(matches: Sequence[KnowledgeMatch]) -> Confidence:
    """Curated matches are high confidence; community data is medium."""
    if all(m.source is ClassificationSource.CURATED for m in matches):
        return Confidence.HIGH
    return Confidence.MEDIUM


def _match_details(match: KnowledgeMatch) -> list[tuple[str, str]]:
    details = [
        ("Category", match.category.value.replace("_", " ")),
        ("Vendor", match.vendor or "—"),
        ("Exemption", match.exemption.value.replace("_", " ")),
        ("Classified by", match.source.value.replace("_", " ")),
    ]
    if match.source_ref:
        details.append(("Source", match.source_ref))
    if match.exemption_note:
        details.append(("Note", match.exemption_note))
    return details


def cookie_evidence(cookie: ClassifiedCookie) -> EvidenceItem:
    return EvidenceItem(
        kind=EvidenceKind.COOKIE,
        session=cookie.session,
        label=cookie.name,
        details=(
            ("Domain", cookie.domain),
            ("Party", cookie.party.value),
            ("Lifetime", lifetime(cookie.lifetime_seconds)),
            ("First observed", seconds(cookie.first_observed_ms) + " after navigation start"),
            *_match_details(cookie.match),
        ),
    )


def storage_evidence(item: ClassifiedStorageKey) -> EvidenceItem:
    return EvidenceItem(
        kind=EvidenceKind.STORAGE,
        session=item.session,
        label=item.key,
        details=(
            ("Origin", item.origin),
            ("Area", item.area.value),
            ("Party", item.party.value),
            ("Value length", str(item.value_length)),
            *_match_details(item.match),
        ),
    )


def contact_evidence(contact: ThirdPartyContact) -> EvidenceItem:
    return EvidenceItem(
        kind=EvidenceKind.THIRD_PARTY,
        session=contact.session,
        label=contact.match.vendor or contact.site,
        details=(
            ("Site", contact.site),
            ("Hosts", ", ".join(contact.hosts)),
            ("Requests", str(contact.request_count - contact.blocked_count)),
            ("First request", seconds(contact.first_request_ms) + " after navigation start"),
            ("Resource types", ", ".join(contact.resource_types)),
            ("Beacon-like", "yes" if contact.beacon_like else "no"),
            *_match_details(contact.match),
            *(("Example URL", url) for url in contact.sample_urls[:2]),
        ),
    )
