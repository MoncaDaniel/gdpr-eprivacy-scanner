"""Rules engine policies and rule-catalog integrity."""

from __future__ import annotations

from importlib import resources
from pathlib import Path

import pytest

from privacy_scanner.classifier.classify import classify
from privacy_scanner.domain.evidence import SessionOutcome
from privacy_scanner.domain.report import (
    Confidence,
    Regulation,
    ReviewReason,
    RuleStatus,
    Tier,
    Verdict,
)
from privacy_scanner.rules.catalog_docs import render
from privacy_scanner.rules.catalog_loader import CatalogError, build_catalog, default_catalog
from privacy_scanner.rules.checks import REGISTRY
from privacy_scanner.rules.engine import CheckContext, CheckResult, evaluate
from tests import builders as b

CATALOG = default_catalog()


def _raw(name: str) -> bytes:
    return resources.files("privacy_scanner.rules.catalog").joinpath(name).read_bytes()


# --------------------------------------------------------------------------- catalog
def test_catalog_has_the_design_review_rule_set() -> None:
    ids = [r.rule_id for r in CATALOG.rules]
    assert ids == [f"EP-{i:02d}" for i in range(1, 12)] + [f"GD-{i:02d}" for i in range(1, 14)]
    assert len(CATALOG.for_regulation(Regulation.EPRIVACY)) == 11
    assert len(CATALOG.for_regulation(Regulation.GDPR)) == 13
    assert len(CATALOG.manual_items) == 12


def test_phase_two_automates_exactly_the_planned_rules() -> None:
    automated = {r.rule_id for r in CATALOG.rules if r.status is RuleStatus.AUTOMATED}
    assert automated == {"EP-01", "EP-02", "EP-03", "EP-04", "EP-05", "EP-09"}
    assert {r.rule_id for r in CATALOG.rules if r.status is RuleStatus.MANUAL} == {"EP-10", "EP-11"}


def test_every_automated_rule_has_a_registered_check() -> None:
    for rule in CATALOG.rules:
        if rule.status is RuleStatus.AUTOMATED:
            assert rule.check in REGISTRY, rule.rule_id
    used = {r.check for r in CATALOG.rules if r.check}
    assert set(REGISTRY) == used, "registered checks that no rule uses"


def test_citations_are_verified_and_official() -> None:
    for rule in CATALOG.rules:
        assert rule.legal_basis, rule.rule_id
        for legal in rule.legal_basis:
            assert legal.url.startswith("https://eur-lex.europa.eu/eli/"), rule.rule_id
            assert legal.binding
        if rule.status is RuleStatus.PLANNED:
            continue
        for g in rule.guidance:
            assert g.verified_on is not None, (rule.rule_id, g.document)
            assert g.url and g.url.startswith("https://"), (rule.rule_id, g.document)


def test_french_guidance_is_tagged_fr_and_non_binding() -> None:
    for rule in CATALOG.rules:
        for g in rule.guidance:
            if g.authority == "CNIL":
                assert g.jurisdiction == "FR"
                assert not g.binding


def test_catalog_hash_is_stable_and_content_sensitive() -> None:
    assert build_catalog().info == CATALOG.info
    edited = _raw("eprivacy.yaml").replace(b"No non-essential cookies", b"No non essential cookies")
    assert build_catalog({"eprivacy.yaml": edited}).info.sha256 != CATALOG.info.sha256


@pytest.mark.parametrize(
    ("file", "find", "replace", "message"),
    [
        ("eprivacy.yaml", b"- id: EP-02", b"- id: EP-01", "duplicate"),
        ("eprivacy.yaml", b"check: cookies_before_consent", b"", "without a check"),
        ("eprivacy.yaml", b"{ref: edpb_g_2_2023}", b"{ref: nope}", "unknown reference"),
        (
            "eprivacy.yaml",
            b"{instrument: eprivacy, provision: Art. 5(3)}",
            b"{instrument: lcen, provision: Art. 6}",
            "unknown instrument",
        ),
        ("eprivacy.yaml", b"severity: high", b"severity: critical", "critical"),
        ("gdpr.yaml", b"planned_phase: 3", b"planned_phase: null", "planned_phase"),
        (
            "catalog_meta.yaml",
            b"verified_on: 2026-10-16\n  edpb_cookie_banner_taskforce",
            b"verified_on: null\n  edpb_cookie_banner_taskforce",
            "not verified",
        ),
    ],
)
def test_malformed_catalog_is_rejected(
    file: str, find: bytes, replace: bytes, message: str
) -> None:
    raw = _raw(file)
    assert find in raw
    with pytest.raises(CatalogError, match=message):
        build_catalog({file: raw.replace(find, replace, 1)})


# --------------------------------------------------------------------------- engine
def _evaluate(bundle_kwargs: dict[str, object], checks: dict[str, object]) -> dict[str, object]:
    bundle = b.bundle(**bundle_kwargs)
    findings, planned = evaluate(bundle, classify(bundle), CATALOG, {**REGISTRY, **checks})  # type: ignore[dict-item]
    return {"findings": {f.rule_id: f for f in findings}, "planned": planned}


def test_planned_rules_are_listed_not_judged() -> None:
    out = _evaluate({}, {})
    planned = out["planned"]
    assert {p.rule_id for p in planned} == {  # type: ignore[attr-defined]
        "EP-06",
        "EP-07",
        "EP-08",
        *(f"GD-{i:02d}" for i in range(1, 14)),
    }
    assert "GD-01" not in out["findings"]  # type: ignore[operator]


def test_manual_rules_always_ask_for_review_with_a_prompt() -> None:
    f = _evaluate({}, {})["findings"]["EP-10"]  # type: ignore[index]
    assert f.verdict is Verdict.MANUAL_REVIEW
    assert f.review_reason is ReviewReason.NOT_AUTOMATABLE
    assert f.tier is Tier.M
    assert f.review_prompt


@pytest.mark.parametrize(
    "outcome", [SessionOutcome.OBSTRUCTED, SessionOutcome.BLOCKED, SessionOutcome.FAILED]
)
def test_unobserved_page_is_never_judged(outcome: SessionOutcome) -> None:
    bundle = b.bundle(b.session(outcome=outcome, cookies=(b.cookie("_ga"),)))
    findings, _ = evaluate(bundle, classify(bundle), CATALOG, REGISTRY)
    automated = [f for f in findings if f.tier is not Tier.M]
    assert automated
    assert all(f.verdict is Verdict.ERROR for f in automated)
    assert all("could not run" in f.explanation for f in automated)


def test_low_confidence_fail_is_downgraded_by_the_engine() -> None:
    def shaky(_: CheckContext) -> CheckResult:
        return CheckResult(
            verdict=Verdict.FAIL,
            confidence=Confidence.LOW,
            params={"count": "1", "items": "x"},
        )

    f = _evaluate({}, {"cookies_before_consent": shaky})["findings"]["EP-01"]  # type: ignore[index]
    assert f.verdict is Verdict.MANUAL_REVIEW
    assert f.review_reason is ReviewReason.LOW_CONFIDENCE_SIGNAL
    assert f.explanation.startswith("Possible issue")


def test_crashing_check_becomes_error_not_a_crash() -> None:
    def boom(_: CheckContext) -> CheckResult:
        raise RuntimeError("bug")

    f = _evaluate({}, {"storage_before_consent": boom})["findings"]["EP-03"]  # type: ignore[index]
    assert f.verdict is Verdict.ERROR
    assert "internal error" in f.explanation


def test_missing_placeholder_is_a_programming_error() -> None:
    def incomplete(_: CheckContext) -> CheckResult:
        return CheckResult(verdict=Verdict.FAIL, confidence=Confidence.HIGH, params={})

    with pytest.raises(KeyError, match="placeholder"):
        _evaluate({}, {"cookies_before_consent": incomplete})


def test_manual_review_without_reason_is_rejected() -> None:
    def reasonless(_: CheckContext) -> CheckResult:
        return CheckResult(
            verdict=Verdict.MANUAL_REVIEW,
            confidence=Confidence.MEDIUM,
            params={"count": "1", "items": "x"},
        )

    with pytest.raises(ValueError, match="review_reason"):
        _evaluate({}, {"cookies_before_consent": reasonless})


def test_committed_rule_catalog_doc_is_up_to_date() -> None:
    doc = Path(__file__).parents[2] / "docs" / "legal" / "rule-catalog.md"
    assert doc.read_text("utf-8") == render(CATALOG), "run `make docs`"
