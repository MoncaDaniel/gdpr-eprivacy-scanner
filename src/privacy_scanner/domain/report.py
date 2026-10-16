"""Report: findings, scores and reproducibility metadata (design review §2.3).

The JSON form of ``Report`` is canonical; HTML and PDF are renderings of it.
Vocabulary follows ADR-0004: no verdict, label or field ever says "compliant".
"""

from __future__ import annotations

import datetime as dt
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from privacy_scanner.domain.classification import Classification, KnowledgeBaseInfo
from privacy_scanner.domain.evidence import (
    BrowserEnvironment,
    ObstructionKind,
    SessionKind,
    SessionOutcome,
)

REPORT_SCHEMA_VERSION = "1.0.0"


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Regulation(StrEnum):
    EPRIVACY = "eprivacy"
    GDPR = "gdpr"


class Verdict(StrEnum):
    PASS = "pass"  # noqa: S105 - a verdict, not a credential
    FAIL = "fail"
    MANUAL_REVIEW = "manual_review"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"

    @property
    def label(self) -> str:
        return _VERDICT_LABELS[self]


_VERDICT_LABELS = {
    Verdict.PASS: "No issue detected",
    Verdict.FAIL: "Issue detected",
    Verdict.MANUAL_REVIEW: "Review suggested",
    Verdict.NOT_APPLICABLE: "Not applicable",
    Verdict.ERROR: "Could not be evaluated",
}


class ReviewReason(StrEnum):
    NOT_AUTOMATABLE = "not_automatable"
    LOW_CONFIDENCE_SIGNAL = "low_confidence_signal"
    UNCLASSIFIED_ITEMS = "unclassified_items"
    CONFIGURATION_NOT_OBSERVABLE = "configuration_not_observable"
    """The answer depends on a configuration or purpose that cannot be seen (ADR-0014)."""

    @property
    def label(self) -> str:
        return _REVIEW_LABELS[self]


_REVIEW_LABELS = {
    ReviewReason.NOT_AUTOMATABLE: "Not automatable",
    ReviewReason.LOW_CONFIDENCE_SIGNAL: "Low-confidence signal",
    ReviewReason.UNCLASSIFIED_ITEMS: "Unclassified items",
    ReviewReason.CONFIGURATION_NOT_OBSERVABLE: "Depends on configuration not visible from outside",
}


class Severity(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


SEVERITY_WEIGHT = {Severity.HIGH: 5, Severity.MEDIUM: 3, Severity.LOW: 1}


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Tier(StrEnum):
    A = "A"
    """Deterministic, high confidence."""
    B = "B"
    """Heuristic: a low-confidence FAIL is downgraded to MANUAL_REVIEW."""
    M = "M"
    """Not automatable: always MANUAL_REVIEW."""


class RuleStatus(StrEnum):
    AUTOMATED = "automated"
    MANUAL = "manual"
    PLANNED = "planned"


class LegalReference(_Model):
    instrument: str = Field(description="Short name, e.g. 'ePrivacy Directive'.")
    provision: str
    url: str
    binding: bool = True


class GuidanceReference(_Model):
    authority: str
    kind: str
    document: str
    date: dt.date | None = None
    jurisdiction: str
    binding: bool
    url: str | None
    pinpoint: str | None = None
    verified_on: dt.date | None


class EvidenceKind(StrEnum):
    COOKIE = "cookie"
    STORAGE = "storage"
    THIRD_PARTY = "third_party"
    BANNER = "banner"
    CONTROL = "control"
    CMP = "cmp"
    PAGE = "page"


class EvidenceItem(_Model):
    """One observed fact a finding relies on, as ordered label/value pairs."""

    kind: EvidenceKind
    session: SessionKind | None
    label: str
    details: tuple[tuple[str, str], ...] = ()


class Finding(_Model):
    rule_id: str
    regulation: Regulation
    title: str
    verdict: Verdict
    verdict_label: str
    review_reason: ReviewReason | None = None
    severity: Severity
    confidence: Confidence
    tier: Tier
    legal_basis: tuple[LegalReference, ...]
    guidance: tuple[GuidanceReference, ...] = ()
    explanation: str
    evidence: tuple[EvidenceItem, ...] = ()
    remediation_hint: str | None = None
    review_prompt: str | None = None
    rule_version: str


class PlannedRule(_Model):
    rule_id: str
    regulation: Regulation
    title: str
    planned_phase: int


class ManualReviewItem(_Model):
    item_id: str
    topic: str
    provision: str
    reason: str


class RegulationScore(_Model):
    """Score and coverage for one regulation (ADR-0015).

    ``score = 100 * sum(w(PASS)) / sum(w(PASS or FAIL))`` with weights
    high=5, medium=3, low=1. ``scored`` (PASS + FAIL) over ``catalogued`` is the
    coverage printed next to the score.
    """

    regulation: Regulation
    title: str
    score: int | None = Field(description="0-100, or null when no check produced PASS/FAIL.")
    catalogued: int
    scored: int
    passed: int
    failed: int
    manual_review: int
    not_applicable: int
    errors: int
    not_yet_evaluated: int

    @property
    def coverage_label(self) -> str:
        return f"based on {self.scored} of {self.catalogued} catalogued checks"


class CatalogInfo(_Model):
    version: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    law_as_of: dt.date


class ScanFacts(_Model):
    scan_id: str
    input_url: str
    normalized_url: str
    final_url: str | None
    http_status: int | None
    page_title: str | None
    outcome: SessionOutcome
    outcome_detail: str | None
    obstruction: ObstructionKind | None
    sessions_executed: tuple[SessionKind, ...]
    observation_window_ms: int
    evidence_created_at: dt.datetime
    evidence_schema_version: str
    scanner_version: str
    screenshot_path: str | None = Field(description="Relative to the scan directory.")


class Report(_Model):
    report_schema_version: str = REPORT_SCHEMA_VERSION
    generated_at: dt.datetime
    generator_version: str
    catalog: CatalogInfo
    knowledge_base: KnowledgeBaseInfo
    scan: ScanFacts
    environment: BrowserEnvironment
    scores: tuple[RegulationScore, ...]
    findings: tuple[Finding, ...]
    not_yet_evaluated: tuple[PlannedRule, ...]
    manual_review_items: tuple[ManualReviewItem, ...]
    classification: Classification
    limitations: tuple[str, ...]
    disclaimer: str

    def score_for(self, regulation: Regulation) -> RegulationScore | None:
        return next((s for s in self.scores if s.regulation is regulation), None)

    def finding(self, rule_id: str) -> Finding | None:
        return next((f for f in self.findings if f.rule_id == rule_id), None)
