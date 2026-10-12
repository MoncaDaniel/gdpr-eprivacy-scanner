"""Evidence Bundle: the immutable, judgement-free record of what a site did.

The collector produces exactly one ``EvidenceBundle`` per scan. Nothing in this
module expresses a legal opinion: there are no categories, no verdicts and no
notion of "tracker". Those belong to the classifier and the rules engine, which
consume a bundle and can be re-run against it at any time (ADR-0003).

Conventions
-----------
* Every model is frozen and rejects unknown fields, so a bundle cannot be
  mutated after collection and schema drift fails loudly.
* Times inside a session are integer milliseconds since that session's
  navigation started (``*_ms``). Absolute times are timezone-aware UTC.
* Stored values (cookie values, Web Storage values) are never persisted in
  clear. They are reduced to a ``ValueFingerprint`` (ADR-0008).
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "1.0.0"
"""Semantic version of the bundle schema. Bump MAJOR on breaking changes."""

NonNegativeMs = Annotated[int, Field(ge=0)]


class _Record(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #
class SessionKind(StrEnum):
    """The isolated browser sessions a scan may run (design review §2.1)."""

    BASELINE = "S0_baseline"
    """Load the page and wait. No interaction of any kind."""
    REJECT = "S1_reject"
    """Fresh context; click the first-layer reject control. (Phase 3)"""
    ACCEPT = "S2_accept"
    """Fresh context; click the accept control. (Phase 3)"""


class SessionOutcome(StrEnum):
    COMPLETED = "completed"
    """The page loaded and the full observation window ran."""
    OBSTRUCTED = "obstructed"
    """The page answered, but with a bot challenge or an HTTP error page."""
    BLOCKED = "blocked"
    """The network guard refused the navigation or detected a violation."""
    FAILED = "failed"
    """The session could not run (timeout, DNS failure, browser crash)."""


class SameSite(StrEnum):
    STRICT = "Strict"
    LAX = "Lax"
    NONE = "None"


class StorageArea(StrEnum):
    LOCAL = "localStorage"
    SESSION = "sessionStorage"


class BlockReason(StrEnum):
    """Why the network guard refused a request (ADR-0005)."""

    FORBIDDEN_SCHEME = "forbidden_scheme"
    FORBIDDEN_PORT = "forbidden_port"
    FORBIDDEN_HOST = "forbidden_host"
    NON_PUBLIC_ADDRESS = "non_public_address"
    DNS_FAILURE = "dns_failure"


class ObstructionKind(StrEnum):
    BOT_CHALLENGE = "bot_challenge"
    HTTP_ERROR = "http_error"


# --------------------------------------------------------------------------- #
# Leaf records
# --------------------------------------------------------------------------- #
class ValueFingerprint(_Record):
    """A non-reversible stand-in for a stored value (ADR-0008).

    ``digest`` is a keyed hash whose key is random per scan and never stored,
    so equal values compare equal *within one bundle* (e.g. the same ID in S0
    and S1) but cannot be correlated across scans or brute-forced from the
    bundle alone.
    """

    length: int = Field(ge=0)
    digest: str = Field(pattern=r"^[0-9a-f]{16}$")


class ArtifactRef(_Record):
    """A binary or large text artefact stored next to the bundle."""

    path: str = Field(description="Path relative to the bundle's artefact root.")
    media_type: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0)


class CookieRecord(_Record):
    name: str
    domain: str = Field(
        description="Cookie domain as reported by the browser (may start with '.')."
    )
    path: str
    value: ValueFingerprint
    expires_at: datetime | None = Field(description="UTC expiry; null for a session cookie.")
    lifetime_seconds: int | None = Field(
        description="expires_at minus the observation time; null for a session cookie."
    )
    http_only: bool
    secure: bool
    same_site: SameSite | None
    first_observed_ms: NonNegativeMs = Field(
        description="First time the cookie jar was seen to contain this cookie. Upper bound on "
        "when it was set, accurate to the poll interval."
    )


class RequestRecord(_Record):
    sequence: int = Field(ge=0, description="Order in which the browser issued the request.")
    url: str
    method: str
    resource_type: str = Field(description="Playwright resource type (document, script, image…).")
    started_ms: NonNegativeMs
    frame_url: str | None
    is_navigation: bool
    redirected_from: str | None = None
    status: int | None = None
    server_ip: str | None = None
    failure: str | None = None
    blocked_by: BlockReason | None = None
    url_truncated: bool = False


class StorageRecord(_Record):
    origin: str
    area: StorageArea
    key: str
    value: ValueFingerprint


class FrameRecord(_Record):
    url: str
    name: str
    is_main: bool
    dom: ArtifactRef | None = Field(
        description="Serialised DOM including open shadow roots; null if not capturable."
    )
    dom_truncated: bool = False


class NavigationRecord(_Record):
    requested_url: str
    final_url: str
    status: int | None
    redirect_chain: tuple[str, ...] = ()
    page_title: str | None = None
    dom_content_loaded_ms: NonNegativeMs | None = None
    load_ms: NonNegativeMs | None = None
    network_idle_reached: bool = False


class Obstruction(_Record):
    kind: ObstructionKind
    detail: str
    provider: str | None = None


class GuardViolation(_Record):
    """A response that arrived from a non-public address despite pre-checks.

    Its presence means the guard was bypassed (e.g. DNS rebinding); the session
    is marked BLOCKED and its evidence must not be judged.
    """

    url: str
    server_ip: str
    reason: str


# --------------------------------------------------------------------------- #
# Aggregates
# --------------------------------------------------------------------------- #
class SessionEvidence(_Record):
    kind: SessionKind
    outcome: SessionOutcome
    started_at: datetime
    duration_ms: NonNegativeMs
    observation_window_ms: NonNegativeMs = Field(
        description="How long the page was observed after load, without interaction."
    )
    error: str | None = None
    navigation: NavigationRecord | None = None
    obstruction: Obstruction | None = None
    cookies: tuple[CookieRecord, ...] = ()
    requests: tuple[RequestRecord, ...] = ()
    requests_dropped: int = Field(
        default=0, ge=0, description="Requests not recorded because the per-session cap was hit."
    )
    storage: tuple[StorageRecord, ...] = ()
    frames: tuple[FrameRecord, ...] = ()
    screenshot: ArtifactRef | None = None
    guard_violations: tuple[GuardViolation, ...] = ()


class Viewport(_Record):
    width: int = Field(gt=0)
    height: int = Field(gt=0)


class BrowserEnvironment(_Record):
    """Everything about the vantage point that can change a site's behaviour."""

    engine: str
    engine_version: str
    user_agent: str
    viewport: Viewport
    locale: str
    timezone: str
    accept_language: str
    headless: bool
    vantage_point: str = Field(description="Where the scan ran from, e.g. 'gcp:europe-west9'.")


class ScanTarget(_Record):
    input_url: str = Field(description="Exactly what the requester submitted.")
    normalized_url: str = Field(pattern=r"^https?://", description="Canonical URL actually loaded.")


class EvidenceBundle(_Record):
    schema_version: str = SCHEMA_VERSION
    scan_id: str
    scanner_version: str
    created_at: datetime
    target: ScanTarget
    environment: BrowserEnvironment
    sessions: tuple[SessionEvidence, ...]

    def session(self, kind: SessionKind) -> SessionEvidence | None:
        """Return the session of the given kind, if it was run."""
        return next((s for s in self.sessions if s.kind is kind), None)
