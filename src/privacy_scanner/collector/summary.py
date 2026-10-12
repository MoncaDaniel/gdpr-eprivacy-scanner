"""Factual, judgement-free digest of a session for human consumption.

Groups what the browser did by site (eTLD+1) relative to the scanned page.
"First-party"/"third-party" here is a technical fact about registrable domains,
not a legal classification: a third-party host can be a processor, and a
first-party cookie can be a tracker. Classification is Phase 2.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from urllib.parse import urlsplit

from privacy_scanner.domain.evidence import CookieRecord, SessionEvidence
from privacy_scanner.domain.sites import cookie_host, registrable_domain


@dataclass(frozen=True, slots=True)
class SiteContact:
    site: str
    first_party: bool
    hosts: tuple[str, ...]
    requests: int
    blocked: int
    resource_types: tuple[tuple[str, int], ...]
    first_request_ms: int


@dataclass(frozen=True, slots=True)
class SessionDigest:
    page_site: str
    cookies: tuple[tuple[CookieRecord, bool], ...]
    """Each cookie with whether its domain is first-party."""
    contacts: tuple[SiteContact, ...]
    third_party_sites: int
    storage_keys: int


def digest(session: SessionEvidence) -> SessionDigest:
    page_url = session.navigation.final_url if session.navigation else ""
    page_host = urlsplit(page_url).hostname or ""
    page_site = registrable_domain(page_host) if page_host else ""

    by_site: dict[str, list[tuple[str, str, int, bool]]] = defaultdict(list)
    for req in session.requests:
        host = urlsplit(req.url).hostname
        if not host:
            continue
        by_site[registrable_domain(host)].append(
            (host, req.resource_type, req.started_ms, req.blocked_by is not None)
        )

    contacts = []
    for site, items in by_site.items():
        types = Counter(t for _, t, _, _ in items)
        contacts.append(
            SiteContact(
                site=site,
                first_party=site == page_site,
                hosts=tuple(sorted({h for h, _, _, _ in items})),
                requests=len(items),
                blocked=sum(1 for *_, b in items if b),
                resource_types=tuple(types.most_common()),
                first_request_ms=min(ms for _, _, ms, _ in items),
            )
        )
    contacts.sort(key=lambda c: (not c.first_party, c.first_request_ms))

    cookies = tuple(
        (c, registrable_domain(cookie_host(c.domain)) == page_site) for c in session.cookies
    )
    return SessionDigest(
        page_site=page_site,
        cookies=cookies,
        contacts=tuple(contacts),
        third_party_sites=sum(1 for c in contacts if not c.first_party),
        storage_keys=len(session.storage),
    )
