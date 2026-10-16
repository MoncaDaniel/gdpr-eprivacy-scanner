"""Normalisation of user-submitted URLs.

The goal is to turn untrusted input into the *same* URL Chromium will load, so
that what the SSRF guard checks is what the browser fetches. In particular,
legacy IPv4 spellings (``2130706433``, ``0x7f.1``, ``127.1``) are canonicalised
here exactly as the WHATWG URL parser does, instead of being left for the
browser to reinterpret after our checks.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

MAX_URL_LENGTH = 2048
DEFAULT_PORTS = {"http": 80, "https": 443}

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_HOST_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_NUMERIC_LABEL_RE = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$")


class InvalidUrlError(ValueError):
    """The input cannot be scanned as a public http(s) URL."""


@dataclass(frozen=True, slots=True)
class NormalizedUrl:
    url: str
    scheme: str
    host: str
    """ASCII host: lower-case IDNA (punycode) name, dotted IPv4 or bare IPv6."""
    port: int

    @property
    def is_ip_literal(self) -> bool:
        try:
            ipaddress.ip_address(self.host)
        except ValueError:
            return False
        return True


def normalize_url(raw: str) -> NormalizedUrl:
    """Validate and canonicalise ``raw``.

    Accepts a bare host (``example.com``) and assumes https. Rejects other
    schemes, embedded credentials, control characters and over-long input.
    Port policy is *not* enforced here; that is the guard's job.
    """
    candidate = raw.strip()
    if not candidate:
        raise InvalidUrlError("URL is empty")
    if len(candidate) > MAX_URL_LENGTH:
        raise InvalidUrlError(f"URL exceeds {MAX_URL_LENGTH} characters")
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in candidate):
        raise InvalidUrlError("URL contains whitespace or control characters")
    if not _SCHEME_RE.match(candidate):
        candidate = "https://" + candidate

    try:
        parts = urlsplit(candidate)
        port = parts.port
    except ValueError as exc:
        raise InvalidUrlError(f"Malformed URL: {exc}") from exc

    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        raise InvalidUrlError(f"Only http and https URLs can be scanned, got '{scheme}'")
    if parts.username is not None or parts.password is not None:
        raise InvalidUrlError("URLs with embedded credentials are not accepted")
    if not parts.hostname:
        raise InvalidUrlError("URL has no host")

    host = canonical_host(parts.hostname)
    effective_port = port if port is not None else DEFAULT_PORTS[scheme]

    netloc_host = f"[{host}]" if ":" in host else host
    netloc = (
        netloc_host
        if effective_port == DEFAULT_PORTS[scheme]
        else f"{netloc_host}:{effective_port}"
    )
    url = urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))
    return NormalizedUrl(url=url, scheme=scheme, host=host, port=effective_port)


def canonical_host(hostname: str) -> str:
    """Return the canonical ASCII form of a hostname or IP literal.

    ``urlsplit`` has already lower-cased the host and removed IPv6 brackets.
    """
    host = hostname.rstrip(".")
    if not host:
        raise InvalidUrlError("URL has an empty host")

    if ":" in host:  # IPv6 literal (brackets already stripped)
        try:
            ip = ipaddress.IPv6Address(host.split("%", 1)[0])
        except ValueError as exc:
            raise InvalidUrlError(f"Invalid IPv6 address '{host}'") from exc
        # str() of an IPv4-mapped address changed within 3.12.x patch releases
        # (hex vs dotted tail); spell it explicitly so the canonical form, which
        # keys egress-log lookups, does not depend on the interpreter build.
        if ip.ipv4_mapped is not None:
            return f"::ffff:{ip.ipv4_mapped}"
        return str(ip)

    labels = host.split(".")
    if _NUMERIC_LABEL_RE.match(labels[-1]):
        # WHATWG: a host whose last label is numeric must parse as IPv4.
        return _parse_legacy_ipv4(host)

    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidUrlError(f"Invalid internationalised host '{host}'") from exc
    if len(ascii_host) > 253 or not all(_HOST_LABEL_RE.match(lbl) for lbl in ascii_host.split(".")):
        raise InvalidUrlError(f"Invalid host '{host}'")
    return ascii_host


def _parse_legacy_ipv4(host: str) -> str:
    """Parse decimal/octal/hex and 1-4 part IPv4 forms the way browsers do."""
    try:
        packed = socket.inet_aton(host)
    except OSError as exc:
        raise InvalidUrlError(f"Invalid IPv4 address '{host}'") from exc
    return str(ipaddress.IPv4Address(packed))
