"""Check registry: catalog ``check`` names -> functions."""

from __future__ import annotations

from types import MappingProxyType

from privacy_scanner.rules.checks import eprivacy
from privacy_scanner.rules.engine import CheckFn

REGISTRY: MappingProxyType[str, CheckFn] = MappingProxyType(
    {
        "cookies_before_consent": eprivacy.cookies_before_consent,
        "tracking_requests_before_consent": eprivacy.tracking_requests_before_consent,
        "storage_before_consent": eprivacy.storage_before_consent,
        "consent_mechanism_present": eprivacy.consent_mechanism_present,
        "reject_on_first_layer": eprivacy.reject_on_first_layer,
        "analytics_cookie_lifetime": eprivacy.analytics_cookie_lifetime,
    }
)
