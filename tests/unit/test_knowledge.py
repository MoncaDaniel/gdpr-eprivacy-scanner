"""Knowledge base: loading, precedence, matching semantics, lexicon."""

from __future__ import annotations

from pathlib import Path

import pytest

from privacy_scanner.classifier.knowledge import (
    KnowledgeBaseError,
    NameMatcher,
    build_knowledge_base,
    default_knowledge_base,
    normalize_text,
)
from privacy_scanner.domain.classification import (
    Category,
    ClassificationSource,
    Exemption,
    KnowledgeMatch,
)

KB = default_knowledge_base()


@pytest.mark.parametrize(
    ("name", "domain", "category", "vendor"),
    [
        ("_ga", "www.example.fr", Category.ANALYTICS, "Google Analytics"),
        ("_ga_G7XYZ12", "example.fr", Category.ANALYTICS, "Google Analytics"),
        ("_gcl_au", "example.fr", Category.MARKETING, "Google Ads / Floodlight"),
        ("_fbp", ".example.fr", Category.MARKETING, "Meta (Facebook) Pixel"),
        ("IDE", ".doubleclick.net", Category.MARKETING, "Google Ads / Floodlight"),
        ("_hjSessionUser_123", "example.fr", Category.ANALYTICS, "Hotjar"),
        ("PHPSESSID", "example.fr", Category.STRICTLY_NECESSARY, None),
        ("__cf_bm", ".example.fr", Category.STRICTLY_NECESSARY, None),
        ("didomi_token", "example.fr", Category.CONSENT_MANAGEMENT, "Didomi"),
        ("euconsent-v2", "example.fr", Category.CONSENT_MANAGEMENT, None),
        ("ASPSESSIONIDQASDCRTB", "example.fr", Category.STRICTLY_NECESSARY, None),
    ],
)
def test_curated_and_cmp_cookies(
    name: str, domain: str, category: Category, vendor: str | None
) -> None:
    match = KB.lookup_name(name, domain, "cookie")
    assert match is not None
    assert match.category is category
    assert match.source is ClassificationSource.CURATED
    if vendor:
        assert match.vendor == vendor


def test_domain_restricted_names_do_not_match_elsewhere() -> None:
    assert KB.lookup_name("IDE", "www.example.fr", "cookie") is None
    assert KB.lookup_name("fr", "example.fr", "cookie") is None
    fr = KB.lookup_name("fr", ".facebook.com", "cookie")
    assert fr is not None and fr.category is Category.MARKETING


def test_matomo_is_conditional_with_a_note_for_cookies_and_storage() -> None:
    for kind in ("cookie", "storage"):
        match = KB.lookup_name("_pk_id.1.a1b2", "example.fr", kind)  # type: ignore[arg-type]
        assert match is not None
        assert match.exemption is Exemption.CONDITIONAL
        assert match.exemption_note and "CNIL" in match.exemption_note


def test_curated_beats_open_cookie_database() -> None:
    # Both sources know PHPSESSID; OCD calls it "Functional", curated says necessary.
    match = KB.lookup_name("PHPSESSID", "example.fr", "cookie")
    assert match is not None and match.source is ClassificationSource.CURATED
    assert match.exemption is Exemption.EXEMPT


def test_open_cookie_database_fallback_and_short_name_guard() -> None:
    lang = KB.lookup_name("lang", ".linkedin.com", "cookie")
    assert lang is not None and lang.source is ClassificationSource.OPEN_COOKIE_DATABASE
    assert lang.source_ref  # OCD entry id
    # Short, generic, unrestricted names are not attributed to a random vendor.
    assert KB.lookup_name("td", "example.fr", "cookie") is None


def test_storage_kind_is_respected() -> None:
    # The curated _ga entry is cookie-only; storage lookups never hit it.
    ga = KB.lookup_name("_ga", "example.fr", "storage")
    assert ga is None or ga.source is ClassificationSource.OPEN_COOKIE_DATABASE
    segment = KB.lookup_name("ajs_anonymous_id", "example.fr", "storage")
    assert segment is not None and segment.category is Category.ANALYTICS


@pytest.mark.parametrize(
    ("host", "path", "category", "vendor"),
    [
        ("region1.google-analytics.com", "/g/collect", Category.ANALYTICS, "Google Analytics"),
        ("stats.g.doubleclick.net", "/", Category.MARKETING, "Google Ads / DoubleClick"),
        ("www.facebook.com", "/tr/", Category.MARKETING, "Meta (Facebook) Pixel"),
        ("www.google.com", "/recaptcha/api.js", Category.FUNCTIONAL, "Google reCAPTCHA"),
        ("fonts.gstatic.com", "/s/inter.woff2", Category.INFRASTRUCTURE, "Google Fonts"),
        ("www.gstatic.com", "/recaptcha/r.js", Category.FUNCTIONAL, "Google reCAPTCHA"),
        ("www.gstatic.com", "/images/x.png", Category.INFRASTRUCTURE, None),
        ("sdk.privacy-center.org", "/loader.js", Category.CONSENT_MANAGEMENT, "Didomi"),
        ("www.googletagmanager.com", "/gtm.js", Category.INFRASTRUCTURE, "Google Tag Manager"),
    ],
)
def test_host_matching(host: str, path: str, category: Category, vendor: str | None) -> None:
    match = KB.lookup_host(host, path)
    assert match is not None
    assert match.category is category
    if vendor:
        assert match.vendor == vendor


def test_hosts_need_a_label_boundary_and_paths_are_honoured() -> None:
    assert KB.lookup_host("evilgoogle-analytics.com") is None
    assert KB.lookup_host("www.facebook.com", "/plugins/like.php") is None
    assert KB.lookup_host("www.google.com", "/search") is None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("J’accepte", "j accepte"),
        ("  Tout   REFUSER › ", "tout refuser"),
        ("Paramétrer", "parametrer"),
        ("Accepter & fermer", "accepter fermer"),
        ("×", "x"),
        ("Präferenzen", "praferenzen"),
    ],
)
def test_normalize_text(raw: str, expected: str) -> None:
    assert normalize_text(raw) == expected


def test_lexicon_is_disjoint_and_covers_cnil_refusal_wording() -> None:
    lex = KB.lexicon
    assert not lex.accept.keys() & lex.reject.keys()
    assert lex.reject["continuer sans accepter"] == "fr"
    assert lex.reject["accept only essential cookies"] == "en"
    assert "accepter" in lex.accept
    assert lex.banner_languages("we use cookies") != ()
    assert lex.banner_languages("privacy policy") == ()
    # Word-start matching: "consentement" counts, "unconsented" does not start a word.
    assert "fr" in lex.banner_languages("votre consentement")


def test_info_is_stable_and_overlays_change_the_hash(tmp_path: Path) -> None:
    again = build_knowledge_base()
    assert again.info == KB.info
    (tmp_path / "trackers.yaml").write_text(
        "vendors:\n  t:\n    name: T\n    category: marketing\n    hosts: [t.example]\n"
    )
    overlaid = build_knowledge_base([tmp_path])
    assert overlaid.info.sha256 != KB.info.sha256
    assert overlaid.info.version.endswith("+overlay")
    hit = overlaid.lookup_host("cdn.t.example")
    assert hit is not None and hit.vendor == "T"


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("vendors: [", "invalid YAML"),
        ("vendors:\n  x:\n    name: X\n    category: nope\n    hosts: [a.b]\n", "category"),
        ("vendors:\n  x:\n    name: X\n    category: marketing\n", "no hosts"),
    ],
)
def test_malformed_overlay_fails_at_load(tmp_path: Path, content: str, message: str) -> None:
    (tmp_path / "trackers.yaml").write_text(content)
    with pytest.raises(KnowledgeBaseError, match=message):
        build_knowledge_base([tmp_path])


def test_name_matcher_rejects_ambiguous_entries() -> None:
    match = KnowledgeMatch(
        category=Category.ANALYTICS,
        exemption=Exemption.NOT_EXEMPT,
        source=ClassificationSource.CURATED,
    )
    matcher = NameMatcher()
    with pytest.raises(KnowledgeBaseError, match="exactly one"):
        matcher.add({"name": "a", "prefix": "a"}, match, "t")
    with pytest.raises(KnowledgeBaseError, match="kinds"):
        matcher.add({"name": "a", "kinds": ["dom"]}, match, "t")
    with pytest.raises(KnowledgeBaseError, match="bad pattern"):
        matcher.add({"pattern": "("}, match, "t")


def test_name_tiers_fall_through_when_domain_restriction_fails() -> None:
    def m(vendor: str) -> KnowledgeMatch:
        return KnowledgeMatch(
            category=Category.MARKETING,
            vendor=vendor,
            exemption=Exemption.NOT_EXEMPT,
            source=ClassificationSource.CURATED,
        )

    matcher = NameMatcher()
    matcher.add({"name": "abc", "domains": ["only.example"]}, m("exact"), "t")
    matcher.add({"prefix": "ab"}, m("prefix"), "t")
    matcher.finalize()
    assert matcher.lookup("abc", "only.example", "cookie").vendor == "exact"  # type: ignore[union-attr]
    assert matcher.lookup("abc", "other.example", "cookie").vendor == "prefix"  # type: ignore[union-attr]
