#!/usr/bin/env python3
# Copyright (C) 2025-2026 Pablo Ruiz García <pablo.ruiz@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later OR AGPL-3.0-or-later

"""Write itemdb/notes/candidates.yml from the deterministic matcher pass."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _colors as C
from matchers import scan_tree

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "itemdb" / "notes" / "candidates.yml"


def load_scope(root: Path) -> tuple[list[str], list[str]]:
    config_path = root / "codecome.yml"
    if yaml is None:
        raise RuntimeError("PyYAML is not installed. Run: make init")
    if not config_path.exists():
        return ["src/**"], []
    data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        return ["src/**"], []
    audit = data.get("audit") if isinstance(data.get("audit"), dict) else {}
    scope = audit.get("scope") if isinstance(audit.get("scope"), dict) else {}
    include = scope.get("include") if isinstance(scope.get("include"), list) else ["src/**"]
    exclude = scope.get("exclude") if isinstance(scope.get("exclude"), list) else []
    include = [str(item) for item in include if str(item).strip()]
    exclude = [str(item) for item in exclude if str(item).strip()]
    return include or ["src/**"], exclude


def render_document(document: dict[str, Any]) -> str:
    if yaml is None:
        raise RuntimeError("PyYAML is not installed. Run: make init")
    body = yaml.safe_dump(document, sort_keys=False, allow_unicode=True)
    header = (
        "# Deterministic matcher hits. A hit selects a file for sweep.\n"
        "# It is not a finding. Inspired by DeepSec's free scan pass;\n"
        "# the patterns in tools/matchers.py are original.\n"
    )
    return header + body


def write_candidates(root: Path, output: Path) -> dict[str, Any]:
    include, exclude = load_scope(root)
    document = scan_tree(root, include=include, exclude=exclude)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_document(document), encoding="utf-8")
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan source files for matcher hits")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="candidates.yml path")
    parser.add_argument("--dry-run", action="store_true", help="Print counts without writing")
    args = parser.parse_args()

    output = Path(args.output)
    if not output.is_absolute():
        output = ROOT / output

    try:
        if args.dry_run:
            include, exclude = load_scope(ROOT)
            document = scan_tree(ROOT, include=include, exclude=exclude)
        else:
            document = write_candidates(ROOT, output)
    except Exception as exc:  # noqa: BLE001
        print(C.fail(str(exc)), file=sys.stderr)
        return 1

    files = document.get("files") if isinstance(document.get("files"), list) else []
    tech = document.get("tech") if isinstance(document.get("tech"), list) else []
    print(C.header("Matcher scan"))
    print(f"  tech: {', '.join(tech) if tech else '(none detected)'}")
    print(f"  files with hits: {len(files)}")
    for entry in files:
        if not isinstance(entry, dict):
            continue
        matches = entry.get("matches") if isinstance(entry.get("matches"), list) else []
        slugs = ", ".join(str(item.get("slug")) for item in matches if isinstance(item, dict))
        flag = " test" if entry.get("in_test") else ""
        print(f"  {C.SYM_BULLET} {entry.get('path')}{flag} — {slugs}")
    if not args.dry_run:
        print(f"Wrote {output.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
