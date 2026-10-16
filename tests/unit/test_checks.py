"""ePrivacy checks, through the full pure pipeline (classify -> rules -> report).

Each test states the evidence pattern and the verdict a privacy lawyer would
expect the scanner to give, including when it must refrain from concluding.
"""

from __future__ import annotations

import pytest

from privacy_scanner.domain.evidence import EvidenceBundle
from privacy_scanner.domain.report import Confidence, Finding, ReviewReason, Verdict
from privacy_scanner.pipeline import assess
from tests import builders as b

DAY = b.DAY


def finding(bundle: EvidenceBundle, rule_id: str) -> Finding:
    found = assess(bundle).finding(rule_id)
    assert found is not None, rule_id
    return found


# --------------------------------------------------------------------------- EP-01
def test_ep01_fail_on_analytics_cookie_before_consent() -> None:
    f = finding(b.bundle(cookies=(b.cookie("_ga"), b.cookie("PHPSESSID"))), "EP-01")
    assert f.verdict is Verdict.FAIL
    assert f.confidence is Confidence.HIGH
    assert "_ga (Google Analytics, analytics, first-party)" in f.explanation
    assert [e.label for e in f.evidence] == ["_ga"]
    assert f.remediation_hint


def test_ep01_review_when_only_unclassified_cookies() -> None:
    f = finding(b.bundle(cookies=(b.cookie("zz_prefs"),)), "EP-01")
    assert f.verdict is Verdict.MANUAL_REVIEW
    assert f.review_reason is ReviewReason.UNCLASSIFIED_ITEMS
    assert "zz_prefs" in f.explanation


def test_ep01_review_when_exemption_depends_on_configuration() -> None:
    f = finding(b.bundle(cookies=(b.cookie("_pk_id.1.abcd"),)), "EP-01")
    assert f.verdict is Verdict.MANUAL_REVIEW
    assert f.review_reason is ReviewReason.CONFIGURATION_NOT_OBSERVABLE


def test_ep01_pass_lists_exempt_cookies() -> None:
    f = finding(b.bundle(cookies=(b.cookie("__cf_bm"), b.cookie("didomi_token"))), "EP-01")
    assert f.verdict is Verdict.PASS
    assert "__cf_bm" in f.explanation
    assert f.remediation_hint is None


def test_ep01_confidence_reflects_classification_source() -> None:
    curated = finding(b.bundle(cookies=(b.cookie("lidc", ".linkedin.com"),)), "EP-01")
    assert curated.verdict is Verdict.FAIL
    assert curated.confidence is Confidence.HIGH
    # Reddit's _rdt_uuid is only in the community Open Cookie Database.
    community = finding(b.bundle(cookies=(b.cookie("_rdt_uuid"),)), "EP-01")
    assert community.verdict is Verdict.FAIL
    assert community.confidence is Confidence.MEDIUM


# --------------------------------------------------------------------------- EP-02
def test_ep02_fail_on_known_tracker_request() -> None:
    f = finding(
        b.bundle(requests=(b.request("https://connect.facebook.net/en_US/fbevents.js"),)), "EP-02"
    )
    assert f.verdict is Verdict.FAIL
    assert "Meta (Facebook) Pixel" in f.explanation


def test_ep02_review_on_unclassified_beacon() -> None:
    f = finding(
        b.bundle(requests=(b.request("https://px.unknown.io/p.gif?u=1", resource_type="image"),)),
        "EP-02",
    )
    assert f.verdict is Verdict.MANUAL_REVIEW
    assert f.review_reason is ReviewReason.UNCLASSIFIED_ITEMS


def test_ep02_pass_with_infrastructure_and_unclassified_content_hosts() -> None:
    f = finding(
        b.bundle(
            requests=(
                b.request(
                    "https://fonts.googleapis.com/css2?family=Inter", resource_type="stylesheet"
                ),
                b.request("https://static.someshop-cdn.io/app.js"),
            )
        ),
        "EP-02",
    )
    assert f.verdict is Verdict.PASS
    assert f.confidence is Confidence.MEDIUM  # an unclassified host remains
    assert "Google Fonts" in f.explanation
    assert "someshop-cdn.io" in f.explanation


def test_ep02_conditional_vendor_is_reviewed() -> None:
    f = finding(
        b.bundle(requests=(b.request("https://static.cloudflareinsights.com/beacon.min.js"),)),
        "EP-02",
    )
    assert f.verdict is Verdict.MANUAL_REVIEW
    assert f.review_reason is ReviewReason.CONFIGURATION_NOT_OBSERVABLE


# --------------------------------------------------------------------------- EP-03
@pytest.mark.parametrize(
    ("items", "verdict"),
    [
        ((b.storage("ajs_user_id"),), Verdict.FAIL),
        ((b.storage("visitor_uid"),), Verdict.MANUAL_REVIEW),
        ((b.storage("cart", origin="https://widgets.other.io"),), Verdict.MANUAL_REVIEW),
        ((b.storage("theme"), b.storage("cartCount")), Verdict.PASS),
        ((), Verdict.PASS),
    ],
)
def test_ep03(items: tuple[object, ...], verdict: Verdict) -> None:
    f = finding(b.bundle(storage_items=items), "EP-03")  # type: ignore[arg-type]
    assert f.verdict is verdict


# --------------------------------------------------------------------------- EP-04
def test_ep04_not_applicable_without_trackers_or_banner() -> None:
    f = finding(b.bundle(), "EP-04")
    assert f.verdict is Verdict.NOT_APPLICABLE
    assert "not an issue in itself" in f.explanation


def test_ep04_fail_trackers_without_banner() -> None:
    f = finding(b.bundle(cookies=(b.cookie("_fbp"),)), "EP-04")
    assert f.verdict is Verdict.FAIL
    assert f.confidence is Confidence.MEDIUM
    assert "_fbp" in f.explanation


def test_ep04_review_when_cmp_loaded_but_no_visible_banner() -> None:
    f = finding(
        b.bundle(
            cookies=(b.cookie("_fbp"),),
            requests=(b.request("https://cdn.cookielaw.org/scripttemplates/otSDKStub.js"),),
        ),
        "EP-04",
    )
    assert f.verdict is Verdict.MANUAL_REVIEW
    assert f.review_reason is ReviewReason.LOW_CONFIDENCE_SIGNAL
    assert "OneTrust" in f.explanation


def test_ep04_pass_with_banner() -> None:
    f = finding(
        b.bundle(cookies=(b.cookie("_fbp"),), consent_ui=b.banner("Tout accepter", "Tout refuser")),
        "EP-04",
    )
    assert f.verdict is Verdict.PASS


def test_ep04_error_without_snapshot() -> None:
    f = finding(b.bundle(cookies=(b.cookie("_fbp"),), consent_ui=None), "EP-04")
    assert f.verdict is Verdict.ERROR
    assert "consent-interface snapshot" in f.explanation


# --------------------------------------------------------------------------- EP-05
@pytest.mark.parametrize(
    ("labels", "verdict", "reason"),
    [
        (("Tout accepter", "Tout refuser"), Verdict.PASS, None),
        (("Accepter", "Continuer sans accepter"), Verdict.PASS, None),
        (("Alle akzeptieren", "Nur notwendige Cookies"), Verdict.PASS, None),
        (("Accept all", "Manage preferences"), Verdict.FAIL, None),
        # A close button may be a valid refusal if the banner says so: not concluded.
        (("J'accepte", "×"), Verdict.MANUAL_REVIEW, ReviewReason.LOW_CONFIDENCE_SIGNAL),
        # An unrecognised label that hints at refusal: not concluded.
        (
            ("Accepter", "Refuser les traceurs publicitaires"),
            Verdict.MANUAL_REVIEW,
            ReviewReason.LOW_CONFIDENCE_SIGNAL,
        ),
        # Nothing recognised at all (unsupported language): banner is low confidence.
        (("Accetta", "Rifiuta"), Verdict.MANUAL_REVIEW, ReviewReason.LOW_CONFIDENCE_SIGNAL),
    ],
)
def test_ep05(labels: tuple[str, ...], verdict: Verdict, reason: ReviewReason | None) -> None:
    f = finding(b.bundle(consent_ui=b.banner(*labels)), "EP-05")
    assert f.verdict is verdict
    assert f.review_reason is reason


def test_ep05_downgraded_finding_says_it_is_uncertain() -> None:
    f = finding(b.bundle(consent_ui=b.banner("J'accepte", "×")), "EP-05")
    assert f.explanation.startswith("Possible issue, from a low-confidence signal")


def test_ep05_not_applicable_without_banner() -> None:
    assert finding(b.bundle(), "EP-05").verdict is Verdict.NOT_APPLICABLE


# --------------------------------------------------------------------------- EP-09
@pytest.mark.parametrize(
    ("lifetime_s", "verdict"),
    [
        (395 * DAY, Verdict.PASS),
        (396 * DAY, Verdict.PASS),
        (397 * DAY, Verdict.FAIL),
        (400 * DAY, Verdict.FAIL),
        (None, Verdict.PASS),  # session cookie
    ],
)
def test_ep09_thirteen_month_boundary(lifetime_s: int | None, verdict: Verdict) -> None:
    f = finding(b.bundle(cookies=(b.cookie("_ga", lifetime_s=lifetime_s),)), "EP-09")
    assert f.verdict is verdict


def test_ep09_mentions_browser_cap_and_skips_marketing() -> None:
    f = finding(b.bundle(cookies=(b.cookie("_ga", lifetime_s=400 * DAY),)), "EP-09")
    assert "400 days" in f.explanation
    f = finding(b.bundle(cookies=(b.cookie("_fbp", lifetime_s=400 * DAY),)), "EP-09")
    assert f.verdict is Verdict.NOT_APPLICABLE


@pytest.mark.parametrize(
    "labels",
    [
        ("Accepter et continuer", "S’abonner", "Se connecter"),
        ("ACCEPTER ET CONTINUER", "Refuser et s'abonner"),
        ("Accept and continue", "Subscribe"),
    ],
)
def test_ep05_pay_or_consent_is_not_concluded(labels: tuple[str, ...]) -> None:
    f = finding(b.bundle(consent_ui=b.banner(*labels)), "EP-05")
    assert f.verdict is Verdict.MANUAL_REVIEW
    assert f.review_reason is ReviewReason.NOT_AUTOMATABLE
    assert "pay or consent" in f.explanation
    assert "EP-10" in f.explanation
