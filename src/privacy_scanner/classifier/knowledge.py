"""Knowledge base: curated YAML + pinned Open Cookie Database snapshot (ADR-0013).

Everything the classifier "knows" is data under ``classifier/data``. It is
loaded once, validated, indexed for lookup, and hashed: the hash goes into
every report, so a classification can always be traced to the exact data that
produced it.

Lookup precedence for cookie names and storage keys:
1. Consent records of known CMPs (``cmp.yaml``)
2. Curated vendors (``cookies.yaml``)
3. Open Cookie Database (third-party snapshot)
Within one source: exact name > longest prefix > regex, and an entry
restricted to the cookie's domain beats an unrestricted one.
"""

from __future__ import annotations

import csv
import hashlib
import io
import re
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from functools import cache
from importlib import resources
from pathlib import Path
from typing import Any, Literal

import yaml

from privacy_scanner.domain.classification import (
    Category,
    ClassificationSource,
    Exemption,
    KnowledgeBaseInfo,
    KnowledgeMatch,
)
from privacy_scanner.domain.sites import registrable_domain

KNOWLEDGE_BASE_VERSION = "2026.10.16"
OPEN_COOKIE_DATABASE_COMMIT = "b15fa5db770e1e2fbd13ab08fa3983bcc5b521a2"
OCD_FILE = "third_party/open-cookie-database.csv"
DATA_FILES = ("cookies.yaml", "trackers.yaml", "cmp.yaml", "consent_lexicon.yaml")

# Open Cookie Database names shorter than this are only used when the entry is
# tied to a domain: "id" or "td" alone would attribute any site's cookie to
# whichever vendor happened to be catalogued first.
OCD_MIN_UNRESTRICTED_NAME = 4

Kind = Literal["cookie", "storage"]

_DEFAULT_EXEMPTION = {
    Category.STRICTLY_NECESSARY: Exemption.EXEMPT,
    Category.CONSENT_MANAGEMENT: Exemption.EXEMPT,
    Category.INFRASTRUCTURE: Exemption.EXEMPT,
    Category.FUNCTIONAL: Exemption.CONDITIONAL,
    Category.ANALYTICS: Exemption.NOT_EXEMPT,
    Category.MARKETING: Exemption.NOT_EXEMPT,
    Category.UNKNOWN: Exemption.UNKNOWN,
}

_OCD_CATEGORY = {
    "Functional": Category.FUNCTIONAL,
    "Personalization": Category.FUNCTIONAL,
    "Analytics": Category.ANALYTICS,
    "Marketing": Category.MARKETING,
    "Security": Category.STRICTLY_NECESSARY,
    "Necessary": Category.STRICTLY_NECESSARY,
}


class KnowledgeBaseError(ValueError):
    """The knowledge-base data is malformed. Raised at load time, never during a scan."""


def default_exemption(category: Category) -> Exemption:
    return _DEFAULT_EXEMPTION[category]


# --------------------------------------------------------------------------- #
# Text normalisation (shared with the banner classifier)
# --------------------------------------------------------------------------- #
# Glyphs used as "close" buttons: multiplication sign, ballot/heavy X, box cross, cross product.
_CLOSE_GLYPHS = str.maketrans(dict.fromkeys("\u00d7\u2715\u2716\u2573\u2a2f", "x"))
_NON_WORD = re.compile(r"[^0-9a-z]+")


def normalize_text(text: str) -> str:
    """Lower-case, accent-free, punctuation-free, single-spaced text."""
    text = unicodedata.normalize("NFKD", text.translate(_CLOSE_GLYPHS))
    text = "".join(ch for ch in text if not unicodedata.combining(ch)).lower()
    return _NON_WORD.sub(" ", text).strip()


# --------------------------------------------------------------------------- #
# Name matching (cookies, storage keys)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class _NameRule:
    domains: frozenset[str] | None
    kinds: frozenset[str]
    match: KnowledgeMatch
    pattern: re.Pattern[str] | None = None


@dataclass(slots=True)
class NameMatcher:
    """Exact / prefix / regex index over cookie names and storage keys."""

    exact: dict[str, list[_NameRule]] = field(default_factory=dict)
    prefixes: list[tuple[str, _NameRule]] = field(default_factory=list)
    patterns: list[_NameRule] = field(default_factory=list)

    def add(self, entry: Mapping[str, Any], match: KnowledgeMatch, origin: str) -> None:
        domains = entry.get("domains")
        rule_kw: dict[str, Any] = {
            "domains": frozenset(str(d).lower() for d in domains) if domains else None,
            "kinds": frozenset(entry.get("kinds", ["cookie"])),
            "match": match,
        }
        if not rule_kw["kinds"] <= {"cookie", "storage"}:
            raise KnowledgeBaseError(f"{origin}: kinds must be cookie/storage: {entry}")
        keys = [k for k in ("name", "prefix", "pattern") if k in entry]
        if len(keys) != 1:
            raise KnowledgeBaseError(f"{origin}: exactly one of name/prefix/pattern: {entry}")
        key = keys[0]
        value = str(entry[key])
        if key == "name":
            self.exact.setdefault(value, []).append(_NameRule(**rule_kw))
        elif key == "prefix":
            self.prefixes.append((value, _NameRule(**rule_kw)))
        else:
            try:
                compiled = re.compile(value)
            except re.error as exc:
                raise KnowledgeBaseError(f"{origin}: bad pattern {value!r}: {exc}") from exc
            self.patterns.append(_NameRule(pattern=compiled, **rule_kw))

    def finalize(self) -> None:
        self.prefixes.sort(key=lambda item: len(item[0]), reverse=True)

    def lookup(self, name: str, site: str, kind: Kind) -> KnowledgeMatch | None:
        tiers: tuple[Iterable[_NameRule], ...] = (
            self.exact.get(name, ()),
            (rule for prefix, rule in self.prefixes if name.startswith(prefix)),
            (r for r in self.patterns if r.pattern is not None and r.pattern.fullmatch(name)),
        )
        for tier in tiers:
            usable = [
                r for r in tier if kind in r.kinds and (r.domains is None or site in r.domains)
            ]
            if usable:
                # Domain-restricted entries are more specific than generic ones.
                usable.sort(key=lambda r: r.domains is None)
                return usable[0].match
        return None


# --------------------------------------------------------------------------- #
# Host matching (requests)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class _HostRule:
    suffix: str
    path_prefix: str | None
    match: KnowledgeMatch


@dataclass(slots=True)
class HostMatcher:
    rules: list[_HostRule] = field(default_factory=list)

    def add(self, suffix: str, path_prefix: str | None, match: KnowledgeMatch) -> None:
        self.rules.append(_HostRule(suffix.lower().lstrip("."), path_prefix, match))

    def lookup(self, host: str, path: str = "/") -> KnowledgeMatch | None:
        host = host.lower().rstrip(".")
        best: tuple[int, int, KnowledgeMatch] | None = None
        for rule in self.rules:
            if host != rule.suffix and not host.endswith("." + rule.suffix):
                continue
            if rule.path_prefix is not None and not path.startswith(rule.path_prefix):
                continue
            rank = (len(rule.suffix), 1 if rule.path_prefix else 0)
            if best is None or rank > best[:2]:
                best = (*rank, rule.match)
        return best[2] if best else None

    def has_path_rules_for(self, host: str) -> bool:
        host = host.lower()
        return any(
            r.path_prefix and (host == r.suffix or host.endswith("." + r.suffix))
            for r in self.rules
        )


# --------------------------------------------------------------------------- #
# CMP signatures and lexicon
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class CmpSignature:
    key: str
    name: str
    hosts: tuple[str, ...]
    path_pattern: re.Pattern[str] | None
    element_pattern: re.Pattern[str] | None
    record_names: tuple[str, ...]
    """Exact names and prefixes (suffixed with '*') of its consent records."""

    def matches_host(self, host: str) -> bool:
        host = host.lower()
        return any(host == h or host.endswith("." + h) for h in self.hosts)


@dataclass(frozen=True, slots=True)
class Lexicon:
    banner_terms: Mapping[str, tuple[str, ...]]
    accept: Mapping[str, str]
    """Normalised phrase -> language."""
    reject: Mapping[str, str]
    settings: Mapping[str, str]
    close: frozenset[str]
    subscribe_stems: tuple[str, ...] = ()
    login_stems: tuple[str, ...] = ()

    @staticmethod
    def _has_stem(normalized: str, stems: tuple[str, ...]) -> bool:
        padded = " " + normalized
        return any(" " + stem in padded for stem in stems)

    def is_subscribe(self, normalized_label: str) -> bool:
        return self._has_stem(normalized_label, self.subscribe_stems) and not self._has_stem(
            normalized_label, self.login_stems
        )

    def banner_languages(self, normalized_text: str) -> tuple[str, ...]:
        """Languages whose banner terms occur at a word start in the text."""
        padded = " " + normalized_text
        return tuple(
            lang
            for lang, terms in self.banner_terms.items()
            if any(" " + term in padded for term in terms)
        )


# --------------------------------------------------------------------------- #
# Knowledge base
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class KnowledgeBase:
    consent_records: NameMatcher
    curated: NameMatcher
    open_cookie_database: NameMatcher
    hosts: HostMatcher
    cmps: tuple[CmpSignature, ...]
    lexicon: Lexicon
    info: KnowledgeBaseInfo

    def lookup_name(self, name: str, domain_or_host: str, kind: Kind) -> KnowledgeMatch | None:
        site = registrable_domain(domain_or_host.lstrip(".")) if domain_or_host else ""
        for matcher in (self.consent_records, self.curated, self.open_cookie_database):
            found = matcher.lookup(name, site, kind)
            if found is not None:
                return found
        return None

    def lookup_host(self, host: str, path: str = "/") -> KnowledgeMatch | None:
        return self.hosts.lookup(host, path)


def _read_data(name: str) -> bytes:
    return resources.files("privacy_scanner.classifier.data").joinpath(name).read_bytes()


def _yaml(raw: bytes, origin: str) -> dict[str, Any]:
    try:
        data = yaml.safe_load(raw) or {}
    except yaml.YAMLError as exc:
        raise KnowledgeBaseError(f"{origin}: invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise KnowledgeBaseError(f"{origin}: top level must be a mapping")
    return data


def _vendor_match(vendor: Mapping[str, Any], origin: str) -> KnowledgeMatch:
    try:
        category = Category(vendor["category"])
        exemption = Exemption(vendor.get("exemption") or default_exemption(category))
    except (KeyError, ValueError) as exc:
        raise KnowledgeBaseError(f"{origin}: bad category/exemption: {exc}") from exc
    return KnowledgeMatch(
        category=category,
        vendor=vendor.get("name"),
        purpose=vendor.get("purpose"),
        exemption=exemption,
        exemption_note=" ".join(str(vendor["exemption_note"]).split())
        if vendor.get("exemption_note")
        else None,
        source=ClassificationSource.CURATED,
        source_ref=vendor.get("source"),
    )


def _load_cookie_vendors(data: Mapping[str, Any], matcher: NameMatcher, origin: str) -> None:
    for key, vendor in (data.get("vendors") or {}).items():
        match = _vendor_match(vendor, f"{origin}:{key}")
        for entry in vendor.get("entries", []):
            matcher.add(entry, match, f"{origin}:{key}")


def _load_host_vendors(data: Mapping[str, Any], matcher: HostMatcher, origin: str) -> None:
    for key, vendor in (data.get("vendors") or {}).items():
        match = _vendor_match(vendor, f"{origin}:{key}")
        hosts = vendor.get("hosts") or []
        if not hosts:
            raise KnowledgeBaseError(f"{origin}:{key}: no hosts")
        for host in hosts:
            matcher.add(str(host), vendor.get("path_prefix"), match)


def _load_cmps(
    data: Mapping[str, Any], records: NameMatcher, hosts: HostMatcher, origin: str
) -> list[CmpSignature]:
    signatures = []
    for key, cmp in (data.get("cmps") or {}).items():
        name = str(cmp["name"])
        match = KnowledgeMatch(
            category=Category.CONSENT_MANAGEMENT,
            vendor=name,
            purpose="Consent management platform / stores the visitor's consent choice",
            exemption=Exemption.EXEMPT,
            source=ClassificationSource.CURATED,
        )
        names: list[str] = []
        for entry in cmp.get("cookies") or []:
            records.add(entry, match, f"{origin}:{key}")
            names.append(str(entry.get("name") or f"{entry.get('prefix')}*"))
        for host in cmp.get("hosts") or []:
            hosts.add(str(host), None, match)
        signatures.append(
            CmpSignature(
                key=key,
                name=name,
                hosts=tuple(str(h).lower() for h in cmp.get("hosts") or ()),
                path_pattern=re.compile(cmp["path_pattern"]) if cmp.get("path_pattern") else None,
                element_pattern=re.compile(cmp["element_pattern"], re.IGNORECASE)
                if cmp.get("element_pattern")
                else None,
                record_names=tuple(names),
            )
        )
    generic = KnowledgeMatch(
        category=Category.CONSENT_MANAGEMENT,
        purpose="Stores the visitor's consent choice",
        exemption=Exemption.EXEMPT,
        source=ClassificationSource.CURATED,
    )
    for entry in data.get("generic_consent_records") or []:
        records.add(entry, generic, f"{origin}:generic_consent_records")
    return signatures


def _phrases(section: Mapping[str, Iterable[str]]) -> dict[str, str]:
    table: dict[str, str] = {}
    for lang, phrases in section.items():
        for phrase in phrases:
            table.setdefault(normalize_text(str(phrase)), lang)
    return table


def _load_lexicon(data: Mapping[str, Any]) -> Lexicon:
    accept, reject = _phrases(data["accept"]), _phrases(data["reject"])
    clash = accept.keys() & reject.keys()
    if clash:
        raise KnowledgeBaseError(f"consent_lexicon: phrases both accept and reject: {clash}")
    return Lexicon(
        banner_terms={
            lang: tuple(normalize_text(t) for t in terms)
            for lang, terms in data["banner_terms"].items()
        },
        accept=accept,
        reject=reject,
        settings=_phrases(data["settings"]),
        close=frozenset(_phrases(data["close"])),
        subscribe_stems=tuple(normalize_text(x) for x in data.get("subscribe_stems") or ()),
        login_stems=tuple(normalize_text(x) for x in data.get("login_stems") or ()),
    )


def _load_ocd(raw: bytes) -> NameMatcher:
    matcher = NameMatcher()
    reader = csv.DictReader(io.StringIO(raw.decode("utf-8")))
    for row in reader:
        name = (row.get("Cookie / Data Key name") or "").strip()
        category = _OCD_CATEGORY.get((row.get("Category") or "").strip())
        if not name or category is None:
            continue
        domain_field = (row.get("Domain") or "").strip().split(" ", 1)[0].lower()
        domains = (
            [registrable_domain(domain_field)]
            if domain_field and "*" not in domain_field and "." in domain_field
            else None
        )
        if domains is None and len(name) < OCD_MIN_UNRESTRICTED_NAME:
            continue
        description = " ".join((row.get("Description") or "").split())
        match = KnowledgeMatch(
            category=category,
            vendor=(row.get("Platform") or "").strip() or None,
            purpose=description[:240] or None,
            exemption=default_exemption(category),
            source=ClassificationSource.OPEN_COOKIE_DATABASE,
            source_ref=(row.get("ID") or "").strip() or None,
        )
        entry: dict[str, Any] = {
            "prefix" if (row.get("Wildcard match") or "0").strip() == "1" else "name": name,
            "kinds": ["cookie", "storage"],
        }
        if domains:
            entry["domains"] = domains
        matcher.add(entry, match, "open-cookie-database")
    return matcher


def build_knowledge_base(overlays: Sequence[Path] = ()) -> KnowledgeBase:
    """Load the packaged data, plus optional overlay directories (tests, deployments).

    An overlay directory may contain ``cookies.yaml`` and/or ``trackers.yaml``
    in the packaged format; their vendors are added to the curated set.
    """
    digest = hashlib.sha256()
    raw = {name: _read_data(name) for name in (*DATA_FILES, OCD_FILE)}
    for name in (*DATA_FILES, OCD_FILE):
        digest.update(name.encode() + b"\0" + raw[name] + b"\0")

    consent_records, curated, hosts = NameMatcher(), NameMatcher(), HostMatcher()
    cmps = _load_cmps(_yaml(raw["cmp.yaml"], "cmp.yaml"), consent_records, hosts, "cmp.yaml")
    _load_cookie_vendors(_yaml(raw["cookies.yaml"], "cookies.yaml"), curated, "cookies.yaml")
    _load_host_vendors(_yaml(raw["trackers.yaml"], "trackers.yaml"), hosts, "trackers.yaml")
    for overlay in overlays:
        for name, loader in (("cookies.yaml", "cookies"), ("trackers.yaml", "trackers")):
            path = overlay / name
            if not path.is_file():
                continue
            data = path.read_bytes()
            digest.update(f"overlay:{name}".encode() + b"\0" + data + b"\0")
            parsed = _yaml(data, str(path))
            if loader == "cookies":
                _load_cookie_vendors(parsed, curated, str(path))
            else:
                _load_host_vendors(parsed, hosts, str(path))
    for matcher in (consent_records, curated):
        matcher.finalize()
    ocd = _load_ocd(raw[OCD_FILE])
    ocd.finalize()

    return KnowledgeBase(
        consent_records=consent_records,
        curated=curated,
        open_cookie_database=ocd,
        hosts=hosts,
        cmps=tuple(cmps),
        lexicon=_load_lexicon(_yaml(raw["consent_lexicon.yaml"], "consent_lexicon.yaml")),
        info=KnowledgeBaseInfo(
            version=KNOWLEDGE_BASE_VERSION + ("+overlay" if overlays else ""),
            sha256=digest.hexdigest(),
            open_cookie_database_commit=OPEN_COOKIE_DATABASE_COMMIT,
        ),
    )


@cache
def default_knowledge_base() -> KnowledgeBase:
    """The packaged knowledge base, loaded once per process."""
    return build_knowledge_base()
