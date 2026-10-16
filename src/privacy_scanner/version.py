"""Installed package version, shared by evidence bundles and reports."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version


def scanner_version() -> str:
    try:
        return version("privacy-scanner")
    except PackageNotFoundError:  # running from a source tree without install
        return "0.0.0+unknown"
