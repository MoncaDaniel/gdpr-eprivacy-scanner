"""Classifier: evidence -> categories, parties, CMPs and the consent banner."""

from __future__ import annotations

from privacy_scanner.classifier.classify import classify, page_site
from privacy_scanner.domain.classification import (
    BannerConfidence,
    Category,
    ControlRole,
    Exemption,
    Party,
)
from privacy_scanner.domain.evidence import UiLayerKind
from tests import builders as b


def test_page_site_uses_final_url_after_redirects() -> None:
    bundle = b.bundle(final_url="https://shop.example.co.uk/home")
    assert page_site(bundle) == "example.co.uk"


def test_cookie_party_and_category() -> None:
    bundle = b.bundle(
        cookies=(
            b.cookie("_ga", ".example.fr"),
            b.cookie("IDE", ".doubleclick.net"),
            b.cookie("mystery", "www.example.fr"),
        )
    )
    cookies = {c.name: c for c in classify(bundle).cookies}
    assert cookies["_ga"].party is Party.FIRST
    assert cookies["_ga"].match.category is Category.ANALYTICS
    assert cookies["IDE"].party is Party.THIRD
    assert cookies["IDE"].match.exemption is Exemption.NOT_EXEMPT
    assert cookies["mystery"].match.category is Category.UNKNOWN
    assert cookies["mystery"].match.exemption is Exemption.UNKNOWN


def test_third_parties_grouped_by_site_and_vendor_with_beacon_signal() -> None:
    bundle = b.bundle(
        requests=(
            b.request("https://www.example.fr/app.js"),  # first party: ignored
            b.request("https://cdn.example.fr/x.js"),  # same site: ignored
            b.request("https://www.google-analytics.com/g/collect?v=2", resource_type="ping"),
            b.request(
                "https://region1.google-analytics.com/g/collect",
                method="POST",
                resource_type="fetch",
                started_ms=50,
            ),
            b.request("https://www.facebook.com/tr/?id=1", resource_type="image"),
            b.request("https://www.facebook.com/plugins/like.php", resource_type="document"),
            b.request("https://cdn.unknown-widget.io/w.js"),
            b.request("https://pixel.unknown-ads.io/p.gif?u=1", resource_type="image"),
            b.request("https://blocked.example.net/x", blocked=True),
        )
    )
    contacts = classify(bundle).third_parties
    by_key = {(c.site, c.match.vendor): c for c in contacts}
    ga = by_key[("google-analytics.com", "Google Analytics")]
    assert ga.request_count == 2
    assert ga.first_request_ms == 50
    assert ga.beacon_like
    assert set(ga.hosts) == {"www.google-analytics.com", "region1.google-analytics.com"}
    # facebook.com /tr is the pixel; /plugins is not classified: separate rows.
    assert by_key[("facebook.com", "Meta (Facebook) Pixel")].match.category is Category.MARKETING
    assert by_key[("facebook.com", None)].match.category is Category.UNKNOWN
    assert not by_key[("unknown-widget.io", None)].beacon_like
    assert by_key[("unknown-ads.io", None)].beacon_like
    # Only-blocked sites never happened, so they are not contacts.
    assert ("example.net", None) not in by_key
    # Most tracking-like first.
    assert contacts[0].match.category is Category.MARKETING


def test_storage_classification_and_party() -> None:
    bundle = b.bundle(
        storage_items=(
            b.storage("ajs_anonymous_id"),
            b.storage("theme"),
            b.storage("_hjid", origin="https://vars.hotjar.com"),
        )
    )
    items = {s.key: s for s in classify(bundle).storage}
    assert items["ajs_anonymous_id"].match.category is Category.ANALYTICS
    assert items["theme"].match.category is Category.UNKNOWN
    assert items["_hjid"].party is Party.THIRD


def test_cmp_detected_from_requests_cookies_and_elements() -> None:
    bundle = b.bundle(
        requests=(b.request("https://sdk.privacy-center.org/loader.js"),),
        cookies=(b.cookie("OptanonConsent"),),
        consent_ui=b.banner("J'accepte", element="div#axeptio_overlay"),
    )
    cmps = {c.name: c.signals for c in classify(bundle).cmps}
    assert any("sdk.privacy-center.org" in s for s in cmps["Didomi"])
    assert any("OptanonConsent" in s for s in cmps["OneTrust"])
    assert any("axeptio" in s for s in cmps["Axeptio"])


def test_cmp_path_signature_for_self_hosted_scripts() -> None:
    bundle = b.bundle(
        requests=(b.request("https://www.example.fr/wp-content/plugins/complianz-gdpr/x.js"),)
    )
    assert [c.name for c in classify(bundle).cmps] == ["Complianz"]


def test_banner_roles_from_labels_and_aria() -> None:
    frames = (
        b.frame_ui(
            (b.layer("Nous utilisons des cookies et traceurs."),),
            (
                b.control("Tout accepter"),
                b.control("Continuer sans accepter"),
                b.control("Personnaliser"),
                b.control("", aria="Fermer"),
                b.control("Politique de confidentialité"),
            ),
        ),
    )
    banner = classify(b.bundle(consent_ui=frames)).banner
    assert banner is not None
    roles = [c.role for c in banner.controls]
    assert roles == [
        ControlRole.ACCEPT,
        ControlRole.REJECT,
        ControlRole.SETTINGS,
        ControlRole.CLOSE,
        ControlRole.OTHER,
    ]
    assert banner.confidence is BannerConfidence.MEDIUM
    assert banner.language_hits == ("fr",)


def test_known_cmp_container_gives_high_confidence() -> None:
    banner = classify(
        b.bundle(consent_ui=b.banner("Accept all", "Reject all", element="div#onetrust-banner-sdk"))
    ).banner
    assert banner is not None
    assert banner.cmp == "OneTrust"
    assert banner.confidence is BannerConfidence.HIGH


def test_layers_without_consent_wording_or_cmp_are_not_banners() -> None:
    # A sticky header with an "OK" button and a privacy link is not a banner.
    frames = (b.frame_ui((b.layer("Home Privacy policy Contact"),), (b.control("OK"),)),)
    classification = classify(b.bundle(consent_ui=frames))
    assert classification.banner is None
    assert classification.banner_evidence_captured


def test_offscreen_layers_are_ignored() -> None:
    frames = (
        b.frame_ui(
            (b.layer("We use cookies"),),
            (b.control("Accept all", in_viewport=False),),
        ),
    )
    assert classify(b.bundle(consent_ui=frames)).banner is None


def test_best_candidate_wins_and_unknown_language_is_low_confidence() -> None:
    frames = (
        b.frame_ui(
            (
                b.layer("Cookie notice footer", 0, kind=UiLayerKind.STICKY),
                b.layer("Utilizziamo i cookie", 1),
            ),
            (b.control("Leggi di più", 0), b.control("Accetta", 1)),
        ),
    )
    banner = classify(b.bundle(consent_ui=frames)).banner
    assert banner is not None
    # Neither layer has a recognised control; the fixed layer outranks the sticky one.
    assert banner.layer_id == 1
    assert banner.confidence is BannerConfidence.LOW


def test_banner_in_cross_origin_frame() -> None:
    frames = (
        b.frame_ui(),
        b.frame_ui(
            (b.layer("We use cookies. Do you consent?", kind=UiLayerKind.FRAME, element="body"),),
            (b.control("Accept all"), b.control("Reject all")),
            frame_index=1,
            url="https://cmp.example.net/banner",
            is_main=False,
        ),
    )
    banner = classify(b.bundle(consent_ui=frames)).banner
    assert banner is not None
    assert not banner.in_main_frame
    assert banner.frame_url == "https://cmp.example.net/banner"


def test_missing_snapshot_is_distinguished_from_no_banner() -> None:
    classification = classify(b.bundle(consent_ui=None))
    assert classification.banner is None
    assert not classification.banner_evidence_captured


def test_consent_word_only_inside_a_control_is_not_a_banner() -> None:
    # cnil.fr: a sticky nav whose only "cookie" is the "Gestionnaire de cookies" link.
    frames = (
        b.frame_ui(
            (b.layer("PARTICULIERS PROFESSIONNELS Fr En Gestionnaire de cookies"),),
            (
                b.control("PARTICULIERS"),
                b.control("PROFESSIONNELS"),
                b.control("Gestionnaire de cookies"),
            ),
        ),
    )
    assert classify(b.bundle(consent_ui=frames)).banner is None


def test_subscribe_controls_are_recognised_but_not_login_links() -> None:
    frames = b.banner(
        "Accepter et continuer",
        "S’abonner",
        "Refuser et s'abonner",
        "Déjà abonné ? Connectez-vous",
        text="L'accès gratuit est subordonné à votre consentement aux cookies.",
    )
    banner = classify(b.bundle(consent_ui=frames)).banner
    assert banner is not None
    assert [c.role for c in banner.controls] == [
        ControlRole.ACCEPT,
        ControlRole.SUBSCRIBE,
        ControlRole.SUBSCRIBE,
        ControlRole.OTHER,
    ]


def test_cmp_attributed_from_the_iframe_host() -> None:
    frames = (
        b.frame_ui(),
        b.frame_ui(
            (b.layer("Nous utilisons des cookies.", kind=UiLayerKind.FRAME, element="body"),),
            (b.control("Accepter et continuer"),),
            frame_index=1,
            url="https://collector.appconsent.io/notice",
            is_main=False,
        ),
    )
    banner = classify(b.bundle(consent_ui=frames)).banner
    assert banner is not None
    assert banner.cmp == "AppConsent (SFBX)"
    assert banner.confidence is BannerConfidence.HIGH
