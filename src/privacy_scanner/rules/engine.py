"""Rules engine: (Evidence, Classification, Catalog) -> Findings. Pure.

Policies applied here, uniformly, so individual checks cannot forget them:

* If the baseline session did not complete (blocked, obstructed, failed), no
  automated check runs: each one is ``ERROR`` with the reason. A bot-challenge
  page is never judged as if it were the site (risk R3).
* A ``FAIL`` with low confidence is downgraded to ``MANUAL_REVIEW``
  ("low-confidence signal"): a false "issue detected" on a real company's
  site is worse than a false "review suggested" (design review §2.2, ADR-0004).
* Tier M rules always produce ``MANUAL_REVIEW`` with their review prompt.
* A check that raises does not abort the report: the finding becomes ``ERROR``.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from privacy_scanner.domain.classification import Classification
from privacy_scanner.domain.evidence import (
    EvidenceBundle,
    SessionEvidence,
    SessionKind,
    SessionOutcome,
)
from privacy_scanner.domain.report import (
    Confidence,
    EvidenceItem,
    Finding,
    PlannedRule,
    ReviewReason,
    RuleStatus,
    Verdict,
)
from privacy_scanner.rules.catalog_loader import RuleCatalog, RuleDefinition

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class CheckContext:
    bundle: EvidenceBundle
    classification: Classification
    baseline: SessionEvidence


@dataclass(frozen=True, slots=True)
class CheckResult:
    verdict: Verdict
    confidence: Confidence
    params: Mapping[str, str] = field(default_factory=dict)
    template: str | None = None
    """Explanation key in the catalog; defaults to the verdict's value."""
    review_reason: ReviewReason | None = None
    evidence: tuple[EvidenceItem, ...] = ()


CheckFn = Callable[[CheckContext], CheckResult]


class _Params(dict[str, str]):
    def __missing__(self, key: str) -> str:
        raise KeyError(f"explanation placeholder {{{key}}} not provided by the check")


def evaluate(
    bundle: EvidenceBundle,
    classification: Classification,
    catalog: RuleCatalog,
    checks: Mapping[str, CheckFn],
) -> tuple[tuple[Finding, ...], tuple[PlannedRule, ...]]:
    findings: list[Finding] = []
    planned: list[PlannedRule] = []
    baseline = bundle.session(SessionKind.BASELINE)
    unavailable = _unavailable_reason(baseline)

    for rule in catalog.rules:
        if rule.status is RuleStatus.PLANNED:
            planned.append(
                PlannedRule(
                    rule_id=rule.rule_id,
                    regulation=rule.regulation,
                    title=rule.title,
                    planned_phase=rule.planned_phase or 0,
                )
            )
            continue
        if rule.status is RuleStatus.MANUAL:
            findings.append(_manual(rule, catalog))
            continue

        if unavailable is not None or baseline is None:
            result = _error(unavailable or "the baseline session was not run")
        else:
            check = checks.get(rule.check or "")
            if check is None:
                raise LookupError(f"{rule.rule_id}: no check registered as {rule.check!r}")
            try:
                result = check(CheckContext(bundle, classification, baseline))
            except Exception:
                logger.exception("check %s failed", rule.rule_id)
                result = _error("an internal error occurred while evaluating it")
        findings.append(_finding(rule, catalog, result))
    return tuple(findings), tuple(planned)


def _unavailable_reason(baseline: SessionEvidence | None) -> str | None:
    if baseline is None:
        return "the baseline session was not run"
    if baseline.outcome is SessionOutcome.COMPLETED:
        return None
    detail = baseline.error or baseline.outcome.value
    if baseline.outcome is SessionOutcome.OBSTRUCTED:
        return f"the site answered with a bot-protection or error page ({detail})"
    if baseline.outcome is SessionOutcome.BLOCKED:
        return f"the page was blocked by the scanner's network policy ({detail})"
    return f"the page could not be loaded ({detail})"


def _error(reason: str) -> CheckResult:
    return CheckResult(verdict=Verdict.ERROR, confidence=Confidence.HIGH, params={"reason": reason})


def _apply_downgrade(result: CheckResult) -> CheckResult:
    if result.verdict is Verdict.FAIL and result.confidence is Confidence.LOW:
        return CheckResult(
            verdict=Verdict.MANUAL_REVIEW,
            confidence=Confidence.LOW,
            params=result.params,
            template="fail",
            review_reason=ReviewReason.LOW_CONFIDENCE_SIGNAL,
            evidence=result.evidence,
        )
    return result


def _render(rule: RuleDefinition, catalog: RuleCatalog, result: CheckResult) -> str:
    key = result.template or result.verdict.value
    template = rule.explanation(key)
    if template is None and result.verdict is Verdict.ERROR:
        template = catalog.common("error")
    if template is None:
        raise KeyError(f"{rule.rule_id}: no explanation template {key!r}")
    text = template.format_map(_Params(result.params))
    if result.review_reason is ReviewReason.LOW_CONFIDENCE_SIGNAL and key == "fail":
        text = "Possible issue, from a low-confidence signal; please verify. " + text
    return " ".join(text.split())


def _finding(rule: RuleDefinition, catalog: RuleCatalog, result: CheckResult) -> Finding:
    result = _apply_downgrade(result)
    if result.verdict is Verdict.MANUAL_REVIEW and result.review_reason is None:
        raise ValueError(f"{rule.rule_id}: MANUAL_REVIEW needs a review_reason")
    return Finding(
        rule_id=rule.rule_id,
        regulation=rule.regulation,
        title=rule.title,
        verdict=result.verdict,
        verdict_label=result.verdict.label,
        review_reason=result.review_reason,
        severity=rule.severity,
        confidence=result.confidence,
        tier=rule.tier,
        legal_basis=rule.legal_basis,
        guidance=rule.guidance,
        explanation=_render(rule, catalog, result),
        evidence=result.evidence,
        remediation_hint=rule.remediation_hint
        if result.verdict in (Verdict.FAIL, Verdict.MANUAL_REVIEW)
        else None,
        rule_version=rule.version,
    )


def _manual(rule: RuleDefinition, catalog: RuleCatalog) -> Finding:
    return Finding(
        rule_id=rule.rule_id,
        regulation=rule.regulation,
        title=rule.title,
        verdict=Verdict.MANUAL_REVIEW,
        verdict_label=Verdict.MANUAL_REVIEW.label,
        review_reason=ReviewReason.NOT_AUTOMATABLE,
        severity=rule.severity,
        confidence=Confidence.HIGH,
        tier=rule.tier,
        legal_basis=rule.legal_basis,
        guidance=rule.guidance,
        explanation=catalog.common("manual"),
        review_prompt=rule.review_prompt,
        rule_version=rule.version,
    )
