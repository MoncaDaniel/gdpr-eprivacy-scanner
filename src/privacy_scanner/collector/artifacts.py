"""Artefact storage for evidence that does not belong inline in the bundle JSON.

The store is a port (``ArtifactStore``) so Phase 4 can swap the local
filesystem for object storage without touching the collector.
"""

from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
from typing import Protocol

from privacy_scanner.domain.evidence import ArtifactRef


class ArtifactStore(Protocol):
    def put(self, path: str, data: bytes, media_type: str) -> ArtifactRef: ...


class LocalArtifactStore:
    """Writes artefacts under ``root``; paths in refs are relative to it."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def put(self, path: str, data: bytes, media_type: str) -> ArtifactRef:
        relative = PurePosixPath(path)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"artefact path must be relative and contained: {path!r}")
        target = self.root.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return ArtifactRef(
            path=relative.as_posix(),
            media_type=media_type,
            sha256=hashlib.sha256(data).hexdigest(),
            size_bytes=len(data),
        )
