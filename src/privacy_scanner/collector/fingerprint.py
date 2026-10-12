"""Keyed, non-reversible fingerprints of stored values (ADR-0008)."""

from __future__ import annotations

import hashlib
import hmac
import secrets

from privacy_scanner.domain.evidence import ValueFingerprint

DIGEST_HEX_CHARS = 16


class ValueFingerprinter:
    """HMAC-SHA256 under a per-scan random key that is never persisted."""

    def __init__(self, key: bytes | None = None) -> None:
        self._key = key if key is not None else secrets.token_bytes(32)

    def fingerprint(self, value: str, *, length: int | None = None) -> ValueFingerprint:
        """Fingerprint ``value``.

        ``length`` overrides the recorded length when ``value`` is a prefix of a
        larger value (Web Storage values are transferred truncated).
        """
        mac = hmac.new(self._key, value.encode("utf-8", "surrogatepass"), hashlib.sha256)
        return ValueFingerprint(
            length=len(value) if length is None else length,
            digest=mac.hexdigest()[:DIGEST_HEX_CHARS],
        )
