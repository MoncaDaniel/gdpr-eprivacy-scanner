"""Stored-value fingerprints (ADR-0008) and the local artefact store."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from privacy_scanner.collector.artifacts import LocalArtifactStore
from privacy_scanner.collector.fingerprint import ValueFingerprinter


def test_fingerprints_are_stable_within_a_scan_and_unlinkable_across_scans() -> None:
    scan_a, scan_b = ValueFingerprinter(), ValueFingerprinter()
    value = "GA1.1.123456789.1700000000"

    assert scan_a.fingerprint(value) == scan_a.fingerprint(value)
    assert scan_a.fingerprint(value).digest != scan_b.fingerprint(value).digest
    assert value not in scan_a.fingerprint(value).model_dump_json()


def test_fingerprint_records_length_and_accepts_override_for_truncated_values() -> None:
    fp = ValueFingerprinter(key=b"k" * 32)
    assert fp.fingerprint("abc").length == 3
    assert fp.fingerprint("abc", length=10_000).length == 10_000
    assert fp.fingerprint("\ud800").length == 1  # lone surrogates from JS strings don't crash


def test_artifact_store_writes_content_addressed_refs(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path)
    ref = store.put("s0/dom/main.html", b"<html/>", "text/html")

    assert (tmp_path / "s0" / "dom" / "main.html").read_bytes() == b"<html/>"
    assert ref.path == "s0/dom/main.html"
    assert ref.sha256 == hashlib.sha256(b"<html/>").hexdigest()
    assert ref.size_bytes == 7


@pytest.mark.parametrize("path", ["/etc/passwd", "../escape.html", "a/../../b"])
def test_artifact_store_refuses_paths_outside_its_root(tmp_path: Path, path: str) -> None:
    with pytest.raises(ValueError, match="contained"):
        LocalArtifactStore(tmp_path / "scan").put(path, b"x", "text/plain")
