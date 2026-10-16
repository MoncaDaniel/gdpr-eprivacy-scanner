"""Judgement pipeline: Evidence Bundle -> Report. Pure and re-runnable.

Collection (I/O, browser) and judgement are separate entry points (ADR-0003):
``collect`` produces a bundle once; ``assess`` can be run on it any number of
times, e.g. after a rule-catalog update, without revisiting the site.
"""

from __future__ import annotations

from datetime import UTC, datetime

from privacy_scanner.classifier.classify import classify
from privacy_scanner.classifier.knowledge import KnowledgeBase, default_knowledge_base
from privacy_scanner.domain.evidence import EvidenceBundle, SessionKind, SessionOutcome
from privacy_scanner.domain.report import Report, ScanFacts
from privacy_scanner.rules.catalog_loader import RuleCatalog, default_catalog
from privacy_scanner.rules.checks import REGISTRY
from privacy_scanner.rules.engine import evaluate
from privacy_scanner.scoring.scorer import score_all
from privacy_scanner.version import scanner_version

LIMITATIONS = (
    "One page (the address given) was observed, once, from one vantage point, as a first-time "
    "visitor with an empty browser profile. Other pages, returning visitors, logged-in areas, "
    "other countries and A/B variants may behave differently.",
    "Only the period before any interaction was observed. Trackers loaded on scroll, click or "
    "after the observation window, and behaviour after accepting or refusing, are not covered "
    "by this version.",
    "Classification relies on a curated knowledge base and the community Open Cookie Database. "
    "Cookies and services they do not know are listed for review and never assumed harmless.",
    "Server-side tracking, browser fingerprinting and tracking inside mobile apps or emails are "
    "not observable with this method.",
    "Consent interfaces rendered in closed shadow roots, canvases or images, or worded outside "
    "French, English, Spanish and German, may not be recognised; related checks then ask for "
    "review rather than conclude.",
    "Guidance from the French CNIL is applied where EU-level guidance is silent and is tagged FR. "
    "Positions of other member states' authorities can differ (for example on cookie walls and "
    "audience measurement) and are not evaluated.",
    "The privacy notice and other GDPR transparency obligations are not yet analysed by this "
    "version; they are listed as not yet evaluated and excluded from coverage.",
)


def _facts(bundle: EvidenceBundle) -> ScanFacts:
    s0 = bundle.session(SessionKind.BASELINE)
    nav = s0.navigation if s0 else None
    return ScanFacts(
        scan_id=bundle.scan_id,
        input_url=bundle.target.input_url,
        normalized_url=bundle.target.normalized_url,
        final_url=nav.final_url if nav else None,
        http_status=nav.status if nav else None,
        page_title=nav.page_title if nav else None,
        outcome=s0.outcome if s0 else SessionOutcome.FAILED,
        outcome_detail=s0.error if s0 else "baseline session not run",
        obstruction=s0.obstruction.kind if s0 and s0.obstruction else None,
        sessions_executed=tuple(s.kind for s in bundle.sessions),
        observation_window_ms=s0.observation_window_ms if s0 else 0,
        evidence_created_at=bundle.created_at,
        evidence_schema_version=bundle.schema_version,
        scanner_version=bundle.scanner_version,
        screenshot_path=s0.screenshot.path if s0 and s0.screenshot else None,
    )


def assess(
    bundle: EvidenceBundle,
    *,
    catalog: RuleCatalog | None = None,
    knowledge_base: KnowledgeBase | None = None,
    now: datetime | None = None,
) -> Report:
    catalog = catalog or default_catalog()
    kb = knowledge_base or default_knowledge_base()
    classification = classify(bundle, kb)
    findings, planned = evaluate(bundle, classification, catalog, REGISTRY)
    return Report(
        generated_at=now or datetime.now(UTC),
        generator_version=scanner_version(),
        catalog=catalog.info,
        knowledge_base=kb.info,
        scan=_facts(bundle),
        environment=bundle.environment,
        scores=score_all(catalog, findings, planned),
        findings=findings,
        not_yet_evaluated=planned,
        manual_review_items=catalog.manual_items,
        classification=classification,
        limitations=LIMITATIONS,
        disclaimer=catalog.disclaimer,
    )
