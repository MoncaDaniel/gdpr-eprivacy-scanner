"""Browser "site" semantics (eTLD+1), computed offline.

First- vs third-party is defined by the registrable domain, the same notion
browsers use for SameSite and storage partitioning. We use the bundled Public
Suffix List snapshot shipped with ``tldextract`` (private section included, as
browsers do, so ``a.github.io`` and ``b.github.io`` are different sites) and
never fetch the list at runtime: scans must be reproducible and work offline.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache

import tldextract

_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)


@lru_cache(maxsize=4096)
def registrable_domain(host: str) -> str:
    """Return the eTLD+1 of ``host``; IP literals and bare suffixes are returned as-is."""
    host = host.strip("[]").rstrip(".").lower()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return host
    parts = _EXTRACT(host)
    return parts.top_domain_under_public_suffix or host


def cookie_host(domain: str) -> str:
    """Normalise a cookie ``Domain`` attribute (``.example.com``) to a host."""
    return domain.lstrip(".").lower()


def same_site(host_a: str, host_b: str) -> bool:
    return registrable_domain(host_a) == registrable_domain(host_b)
