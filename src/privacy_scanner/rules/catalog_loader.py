"""Load and validate the YAML rule catalog (ADR-0006).

Validation happens at load time, so a malformed catalog fails CI rather than
a scan: unknown references, unverified citations on rules that produce
verdicts, missing templates, and duplicate IDs are all rejected.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import date
from functools import cache
from importlib import resources
from typing import Any

import yaml

from privacy_scanner.domain.report import (
    CatalogInfo,
    GuidanceReference,
    LegalReference,
    ManualReviewItem,
    Regulation,
    RuleStatus,
    Severity,
    Tier,
)

CATALOG_FILES = ("catalog_meta.yaml", "eprivacy.yaml", "gdpr.yaml", "manual_items.yaml")
REGULATION_FILES = {Regulation.EPRIVACY: "eprivacy.yaml", Regulation.GDPR: "gdpr.yaml"}


class CatalogError(ValueError):
    """The rule catalog is malformed or cites unverified sources."""


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    rule_id: str
    regulation: Regulation
    title: str
    tier: Tier
    severity: Severity
    status: RuleStatus
    version: str
    legal_basis: tuple[LegalReference, ...]
    guidance: tuple[GuidanceReference, ...]
    check: str | None = None
    explanations: tuple[tuple[str, str], ...] = ()
    remediation_hint: str | None = None
    review_prompt: str | None = None
    planned_phase: int | None = None

    def explanation(self, key: str) -> str | None:
        return dict(self.explanations).get(key)


@dataclass(frozen=True, slots=True)
class RuleCatalog:
    info: CatalogInfo
    regulation_titles: tuple[tuple[Regulation, str], ...]
    rules: tuple[RuleDefinition, ...]
    manual_items: tuple[ManualReviewItem, ...]
    common_explanations: tuple[tuple[str, str], ...]
    disclaimer: str

    def for_regulation(self, regulation: Regulation) -> tuple[RuleDefinition, ...]:
        return tuple(r for r in self.rules if r.regulation is regulation)

    def title_of(self, regulation: Regulation) -> str:
        return dict(self.regulation_titles)[regulation]

    def common(self, key: str) -> str:
        return dict(self.common_explanations)[key]

    def rule(self, rule_id: str) -> RuleDefinition:
        return next(r for r in self.rules if r.rule_id == rule_id)


def _fold(text: Any) -> str:
    """YAML folded scalars keep a trailing newline; normalise whitespace."""
    return " ".join(str(text).split())


def _load_yaml(raw: bytes, name: str) -> dict[str, Any]:
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise CatalogError(f"{name}: invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise CatalogError(f"{name}: top level must be a mapping")
    return data


def _guidance(
    entry: dict[str, Any], references: dict[str, Any], rule_id: str, status: RuleStatus
) -> GuidanceReference:
    key = entry.get("ref")
    if key not in references:
        raise CatalogError(f"{rule_id}: unknown reference {key!r}")
    ref = references[key]
    if ref.get("verified_on") is None and status is not RuleStatus.PLANNED:
        raise CatalogError(
            f"{rule_id}: reference {key!r} is not verified; only planned rules may cite it"
        )
    return GuidanceReference(
        authority=ref["authority"],
        kind=ref["kind"],
        document=_fold(ref["document"]),
        date=ref.get("date"),
        jurisdiction=ref["jurisdiction"],
        binding=bool(ref["binding"]),
        url=ref.get("url"),
        pinpoint=entry.get("pinpoint"),
        verified_on=ref.get("verified_on"),
    )


def _rule(raw: dict[str, Any], regulation: Regulation, meta: dict[str, Any]) -> RuleDefinition:
    rule_id = str(raw["id"])
    try:
        status = RuleStatus(raw["status"])
        tier = Tier(raw["tier"])
        severity = Severity(raw["severity"])
    except (KeyError, ValueError) as exc:
        raise CatalogError(f"{rule_id}: {exc}") from exc
    instruments = meta["instruments"]
    legal_basis = []
    for item in raw.get("legal_basis") or []:
        instrument = instruments.get(item["instrument"])
        if instrument is None:
            raise CatalogError(f"{rule_id}: unknown instrument {item['instrument']!r}")
        legal_basis.append(
            LegalReference(
                instrument=instrument["short"], provision=item["provision"], url=instrument["url"]
            )
        )
    if not legal_basis:
        raise CatalogError(f"{rule_id}: every rule needs at least one binding provision")
    guidance = tuple(
        _guidance(g, meta["references"], rule_id, status) for g in raw.get("guidance") or []
    )
    explanations = tuple((k, _fold(v)) for k, v in (raw.get("explanations") or {}).items())

    if status is RuleStatus.AUTOMATED:
        if not raw.get("check"):
            raise CatalogError(f"{rule_id}: automated rule without a check")
        if tier is Tier.M:
            raise CatalogError(f"{rule_id}: tier M rules cannot be automated")
        if not {"pass", "fail"} <= dict(explanations).keys():
            raise CatalogError(f"{rule_id}: automated rule needs pass and fail explanations")
    if status is RuleStatus.MANUAL and not raw.get("review_prompt"):
        raise CatalogError(f"{rule_id}: manual rule needs a review_prompt")
    if status is RuleStatus.PLANNED and not raw.get("planned_phase"):
        raise CatalogError(f"{rule_id}: planned rule needs planned_phase")

    return RuleDefinition(
        rule_id=rule_id,
        regulation=regulation,
        title=str(raw["title"]),
        tier=tier,
        severity=severity,
        status=status,
        version=str(raw["version"]),
        legal_basis=tuple(legal_basis),
        guidance=guidance,
        check=raw.get("check"),
        explanations=explanations,
        remediation_hint=_fold(raw["remediation_hint"]) if raw.get("remediation_hint") else None,
        review_prompt=_fold(raw["review_prompt"]) if raw.get("review_prompt") else None,
        planned_phase=raw.get("planned_phase"),
    )


def build_catalog(files: dict[str, bytes] | None = None) -> RuleCatalog:
    """Parse the catalog. ``files`` overrides the packaged files (tests)."""
    package = resources.files("privacy_scanner.rules.catalog")
    raw = {name: package.joinpath(name).read_bytes() for name in CATALOG_FILES}
    raw.update(files or {})

    digest = hashlib.sha256()
    for name in CATALOG_FILES:
        digest.update(name.encode() + b"\0" + raw[name] + b"\0")

    meta = _load_yaml(raw["catalog_meta.yaml"], "catalog_meta.yaml")
    rules: list[RuleDefinition] = []
    titles: list[tuple[Regulation, str]] = []
    for regulation, name in REGULATION_FILES.items():
        data = _load_yaml(raw[name], name)
        if data.get("regulation") != regulation.value:
            raise CatalogError(f"{name}: regulation must be {regulation.value!r}")
        titles.append((regulation, str(data["title"])))
        rules += [_rule(r, regulation, meta) for r in data.get("rules") or []]

    ids = [r.rule_id for r in rules]
    duplicates = {i for i in ids if ids.count(i) > 1}
    if duplicates:
        raise CatalogError(f"duplicate rule ids: {sorted(duplicates)}")

    manual = _load_yaml(raw["manual_items.yaml"], "manual_items.yaml")
    law_as_of = meta["law_as_of"]
    if not isinstance(law_as_of, date):
        raise CatalogError("catalog_meta.yaml: law_as_of must be a date")
    return RuleCatalog(
        info=CatalogInfo(
            version=str(meta["version"]), sha256=digest.hexdigest(), law_as_of=law_as_of
        ),
        regulation_titles=tuple(titles),
        rules=tuple(rules),
        manual_items=tuple(
            ManualReviewItem(
                item_id=i["id"], topic=i["topic"], provision=i["provision"], reason=i["reason"]
            )
            for i in manual["items"]
        ),
        common_explanations=tuple((k, _fold(v)) for k, v in meta["common_explanations"].items()),
        disclaimer=_fold(meta["disclaimer"]),
    )


@cache
def default_catalog() -> RuleCatalog:
    return build_catalog()
