#!/usr/bin/env python3
# Copyright (C) 2025-2026 Pablo Ruiz García <pablo.ruiz@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later OR AGPL-3.0-or-later

"""Append-only per-file sweep records under itemdb/files/.

Inspired by DeepSec's FileRecord: a re-run appends history instead of
erasing what a previous pass concluded. Resume skips a file only when the
latest entry hashed the bytes that are on disk now.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


def file_blob(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def record_path(files_root: Path, rel: str) -> Path:
    return files_root / f"{rel}.yml"


def load_record(files_root: Path, rel: str) -> dict[str, Any] | None:
    path = record_path(files_root, rel)
    if yaml is None or not path.exists():
        return None
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        return None
    return data


def latest_blob(record: dict[str, Any] | None) -> str | None:
    if not record:
        return None
    history = record.get("history")
    if not isinstance(history, list) or not history:
        return None
    last = history[-1]
    if not isinstance(last, dict):
        return None
    blob = last.get("blob")
    return str(blob) if isinstance(blob, str) and blob else None


def is_current(files_root: Path, source: Path, rel: str) -> bool:
    """True when the latest record hashed the file's current bytes."""
    if not source.is_file():
        return False
    record = load_record(files_root, rel)
    current = file_blob(source)
    return latest_blob(record) == current


def append_entry(
    files_root: Path,
    rel: str,
    *,
    blob: str,
    model: str = "",
    candidates: list[dict[str, Any]] | None = None,
    finding_ids: list[str] | None = None,
    fingerprints: list[str] | None = None,
) -> Path:
    if yaml is None:
        raise RuntimeError("PyYAML is not installed. Run: make init")
    path = record_path(files_root, rel)
    path.parent.mkdir(parents=True, exist_ok=True)
    record = load_record(files_root, rel) or {"path": rel, "history": []}
    history = record.get("history")
    if not isinstance(history, list):
        history = []
    history.append(
        {
            "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "blob": blob,
            "model": model,
            "candidates": list(candidates or []),
            "finding_ids": list(finding_ids or []),
            "fingerprints": list(fingerprints or []),
        }
    )
    record["path"] = rel
    record["history"] = history
    path.write_text(yaml.safe_dump(record, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return path
