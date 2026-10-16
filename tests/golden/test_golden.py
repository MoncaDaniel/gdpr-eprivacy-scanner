"""Golden tests: recorded Evidence Bundles must keep producing the same judgement.

A diff here means a rule, the catalog wording or the knowledge base changed
what the scanner says about a known situation. If intended, regenerate with

    UPDATE_GOLDEN=1 uv run pytest tests/golden

and review the JSON diff like any other legal-content change (ADR-0006).
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from privacy_scanner.classifier.knowledge import build_knowledge_base
from privacy_scanner.domain.evidence import EvidenceBundle
from privacy_scanner.domain.report import Report
from privacy_scanner.pipeline import assess

EVIDENCE = Path(__file__).parents[1] / "fixtures" / "evidence"
OVERLAY = Path(__file__).parents[1] / "fixtures" / "kb"
GOLDEN = Path(__file__).parent
BUNDLES = sorted(EVIDENCE.glob("*.json"))


def summarize(report: Report) -> dict[str, Any]:
    """The judgement, without volatile metadata (timestamps, hashes, versions)."""
    banner = report.classification.banner
    return {
        "scores": [s.model_dump(mode="json", exclude={"title"}) for s in report.scores],
        "banner": None
        if banner is None
        else {
            "element": banner.element,
            "cmp": banner.cmp,
            "confidence": banner.confidence.value,
            "controls": [[c.label, c.role.value] for c in banner.controls],
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "verdict": f.verdict.value,
                "confidence": f.confidence.value,
                "review_reason": f.review_reason.value if f.review_reason else None,
                "explanation": f.explanation,
                "evidence": [e.label for e in f.evidence],
            }
            for f in report.findings
        ],
        "not_yet_evaluated": [p.rule_id for p in report.not_yet_evaluated],
    }


@pytest.mark.parametrize("bundle_path", BUNDLES, ids=[p.stem for p in BUNDLES])
def test_golden(bundle_path: Path) -> None:
    bundle = EvidenceBundle.model_validate_json(bundle_path.read_bytes())
    report = assess(
        bundle,
        knowledge_base=build_knowledge_base([OVERLAY]),
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    actual = summarize(report)
    golden_path = GOLDEN / bundle_path.name
    if os.environ.get("UPDATE_GOLDEN") == "1":
        golden_path.write_text(json.dumps(actual, indent=2, ensure_ascii=False) + "\n", "utf-8")
    expected = json.loads(golden_path.read_text("utf-8"))
    assert actual == expected


def test_every_bundle_has_a_golden_file() -> None:
    assert BUNDLES, "no recorded evidence"
    assert {p.name for p in BUNDLES} == {p.name for p in GOLDEN.glob("*.json")}


def test_schema_1_0_bundle_still_loads_and_is_judged_honestly() -> None:
    """Bundles from Phase 1 have no consent-UI snapshot: banner checks say so."""
    raw = json.loads((EVIDENCE / "tracking.json").read_text("utf-8"))
    raw["schema_version"] = "1.0.0"
    for session in raw["sessions"]:
        session.pop("consent_ui", None)
    report = assess(
        EvidenceBundle.model_validate(raw), knowledge_base=build_knowledge_base([OVERLAY])
    )
    for rule_id in ("EP-04", "EP-05"):
        finding = report.finding(rule_id)
        assert finding is not None
        assert finding.verdict.value == "error"
    assert report.finding("EP-01").verdict.value == "fail"  # type: ignore[union-attr]
