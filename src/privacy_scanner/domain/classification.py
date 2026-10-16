"""Classification: what the observed evidence *is*, still without legal verdicts.

The classifier turns an Evidence Bundle into these records: each cookie,
storage key and third-party site gets a category, a vendor and an
``Exemption`` status describing how the ePrivacy consent exemption is likely to
apply. Rules (``privacy_scanner.rules``) turn classifications into findings.

Classification is knowledge-base driven and therefore fallible. Every record
says where its category came from (``source``), so a reviewer can see whether
a cookie was matched by our curated list, by the Open Cookie Database, or not
at all (ADR-0013).
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from privacy_scanner.domain.evidence import Box, SessionKind, StorageArea, UiLayerKind


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Category(StrEnum):
    STRICTLY_NECESSARY = "strictly_necessary"
    """Needed for a service the user explicitly requested, or to transmit a communication."""
    FUNCTIONAL = "functional"
    """Preferences, embedded features, chat, monitoring: exemption depends on purpose."""
    ANALYTICS = "analytics"
    MARKETING = "marketing"
    """Advertising, retargeting, cross-site profiling, social-network tracking."""
    CONSENT_MANAGEMENT = "consent_management"
    """A consent management platform (CMP) or the record of the user's choice."""
    INFRASTRUCTURE = "infrastructure"
    """CDNs, font and library hosting, tag-manager containers (requests only)."""
    UNKNOWN = "unknown"


class Exemption(StrEnum):
    """How the Art. 5(3) consent exemption is likely to apply (ADR-0013)."""

    EXEMPT = "exempt"
    """Category normally covered by the strictly-necessary exemption."""
    CONDITIONAL = "conditional"
    """May be exempt depending on configuration or purpose: needs human review."""
    NOT_EXEMPT = "not_exempt"
    """Category that requires prior consent."""
    UNKNOWN = "unknown"
    """Not classified. Never assumed exempt."""


class Party(StrEnum):
    FIRST = "first"
    THIRD = "third"


class ClassificationSource(StrEnum):
    CURATED = "curated"
    """This project's reviewed knowledge base (``classifier/data``)."""
    OPEN_COOKIE_DATABASE = "open_cookie_database"
    """Community-maintained Open Cookie Database (Apache-2.0), pinned snapshot."""
    NONE = "none"


class KnowledgeMatch(_Model):
    """The knowledge-base entry a cookie, key or host matched."""

    category: Category
    vendor: str | None = None
    purpose: str | None = None
    exemption: Exemption
    exemption_note: str | None = None
    source: ClassificationSource
    source_ref: str | None = Field(
        default=None, description="Documentation URL or Open Cookie Database entry ID."
    )


class ClassifiedCookie(_Model):
    session: SessionKind
    name: str
    domain: str
    party: Party
    lifetime_seconds: int | None
    first_observed_ms: int
    match: KnowledgeMatch


class ClassifiedStorageKey(_Model):
    session: SessionKind
    origin: str
    area: StorageArea
    key: str
    party: Party
    value_length: int
    match: KnowledgeMatch


class ThirdPartyContact(_Model):
    """All requests of one session to one third-party site (eTLD+1)."""

    session: SessionKind
    site: str
    hosts: tuple[str, ...]
    request_count: int
    blocked_count: int
    first_request_ms: int
    resource_types: tuple[str, ...]
    sample_urls: tuple[str, ...] = Field(description="Up to three URLs, truncated.")
    beacon_like: bool = Field(
        description="Has beacon-shaped requests (ping, POST xhr/fetch, image with a query "
        "string). A signal for unclassified sites only, never a verdict on its own."
    )
    match: KnowledgeMatch


class CmpDetection(_Model):
    """A consent management platform recognised from its technical signature."""

    name: str
    signals: tuple[str, ...]


class ControlRole(StrEnum):
    ACCEPT = "accept"
    REJECT = "reject"
    SETTINGS = "settings"
    CLOSE = "close"
    SUBSCRIBE = "subscribe"
    """A paid alternative to consenting ("pay or consent" walls)."""
    OTHER = "other"


class ConsentControl(_Model):
    label: str
    role: ControlRole
    tag: str
    in_viewport: bool
    box: Box
    font_size_px: float | None
    color: str | None
    background_color: str | None


class BannerConfidence(StrEnum):
    HIGH = "high"
    """A known CMP's container, with a recognised accept or reject control."""
    MEDIUM = "medium"
    """Consent wording in an overlay with a recognised accept or reject control."""
    LOW = "low"
    """Consent wording in an overlay, but no control recognised by the lexicon."""


class BannerDetection(_Model):
    frame_index: int
    frame_url: str
    in_main_frame: bool
    layer_id: int
    layer_kind: UiLayerKind
    element: str
    text_excerpt: str
    language_hits: tuple[str, ...] = Field(description="Lexicon languages whose terms matched.")
    controls: tuple[ConsentControl, ...]
    cmp: str | None
    confidence: BannerConfidence

    def controls_with(self, role: ControlRole) -> tuple[ConsentControl, ...]:
        return tuple(c for c in self.controls if c.role is role)


class KnowledgeBaseInfo(_Model):
    version: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    open_cookie_database_commit: str


class Classification(_Model):
    knowledge_base: KnowledgeBaseInfo
    page_site: str
    cookies: tuple[ClassifiedCookie, ...] = ()
    storage: tuple[ClassifiedStorageKey, ...] = ()
    third_parties: tuple[ThirdPartyContact, ...] = ()
    cmps: tuple[CmpDetection, ...] = ()
    banner: BannerDetection | None = None
    banner_evidence_captured: bool = Field(
        description="False when the bundle has no consent-UI snapshot (schema < 1.1.0 or "
        "capture failed): banner absence then means 'unknown', not 'no banner'."
    )
