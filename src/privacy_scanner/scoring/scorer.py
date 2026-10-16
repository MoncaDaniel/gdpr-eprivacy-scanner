"""Website Privacy Exposure Score and coverage, per regulation (ADR-0015).

score    = round(100 * sum(w(PASS)) / sum(w(PASS) + w(FAIL)))
weights  = high 5, medium 3, low 1
coverage = (PASS + FAIL) / catalogued rules for the regulation

MANUAL_REVIEW, NOT_APPLICABLE, ERROR and not-yet-evaluated rules are outside
the denominator but always reported, so a high score on few checks is visibly
a high score on few checks. No score is produced when nothing was scored.
"""

from __future__ import annotations

from collections.abc import Sequence

from privacy_scanner.domain.report import (
    SEVERITY_WEIGHT,
    Finding,
    PlannedRule,
    Regulation,
    RegulationScore,
    Verdict,
)
from privacy_scanner.rules.catalog_loader import RuleCatalog


def score_regulation(
    regulation: Regulation,
    catalog: RuleCatalog,
    findings: Sequence[Finding],
    planned: Sequence[PlannedRule],
) -> RegulationScore:
    own = [f for f in findings if f.regulation is regulation]

    def count(verdict: Verdict) -> int:
        return sum(1 for f in own if f.verdict is verdict)

    passed_w = sum(SEVERITY_WEIGHT[f.severity] for f in own if f.verdict is Verdict.PASS)
    failed_w = sum(SEVERITY_WEIGHT[f.severity] for f in own if f.verdict is Verdict.FAIL)
    total_w = passed_w + failed_w
    passed, failed = count(Verdict.PASS), count(Verdict.FAIL)
    return RegulationScore(
        regulation=regulation,
        title=catalog.title_of(regulation),
        score=round(100 * passed_w / total_w) if total_w else None,
        catalogued=len(catalog.for_regulation(regulation)),
        scored=passed + failed,
        passed=passed,
        failed=failed,
        manual_review=count(Verdict.MANUAL_REVIEW),
        not_applicable=count(Verdict.NOT_APPLICABLE),
        errors=count(Verdict.ERROR),
        not_yet_evaluated=sum(1 for p in planned if p.regulation is regulation),
    )


def score_all(
    catalog: RuleCatalog, findings: Sequence[Finding], planned: Sequence[PlannedRule]
) -> tuple[RegulationScore, ...]:
    return tuple(score_regulation(r, catalog, findings, planned) for r in Regulation)
