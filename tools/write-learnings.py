#!/usr/bin/env python3
# Copyright (C) 2025-2026 Pablo Ruiz García <pablo.ruiz@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later OR AGPL-3.0-or-later

"""Write itemdb/notes/learnings.md from decided findings.

Inspired by Mantis's reflect step. The note is a list later phases can
read. It does not store a separate knowledge database.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _colors as C
from findings.constants import FindingsContext
from findings.frontmatter import load_frontmatter
from findings.ids import iter_findings

ROOT = Path(__file__).resolve().parents[1]


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _sinks(data: dict[str, Any]) -> str:
    sinks = data.get("sinks")
    if not isinstance(sinks, list):
        return ""
    parts = [_text(item) for item in sinks if _text(item)]
    return "; ".join(parts)


def render_learnings(ctx: FindingsContext) -> str:
    rejected: list[str] = []
    confirmed: list[str] = []
    blocked: list[str] = []

    for status, bucket in (
        ("REJECTED", rejected),
        ("CONFIRMED", confirmed),
        ("EXPLOITED", confirmed),
        ("NEEDS_VALIDATION", blocked),
    ):
        for path in iter_findings(status, findings_root=ctx.findings_root):
            data = load_frontmatter(path)
            if not isinstance(data, dict):
                continue
            finding_id = _text(data.get("id")) or path.stem
            title = _text(data.get("title")) or path.stem
            fingerprint = _text(data.get("fingerprint"))
            if status == "REJECTED":
                label = f"`{fingerprint}`" if fingerprint else finding_id
                bucket.append(f"- {label} — {title}")
            elif status in {"CONFIRMED", "EXPLOITED"}:
                sinks = _sinks(data)
                extra = f" — sink: {sinks}" if sinks else ""
                bucket.append(f"- {finding_id} — {title}{extra}")
            else:
                bucket.append(f"- {finding_id} — {title}")

    lines = [
        "# Learnings",
        "",
        "Written from decided findings. Phase 2 must not re-file a fingerprint listed under Do not re-file.",
        "",
        "## Do not re-file",
        "",
    ]
    lines.extend(rejected or ["- (none)"])
    lines.extend(["", "## Confirmed sinks", ""])
    lines.extend(confirmed or ["- (none)"])
    lines.extend(["", "## Blocked on an external fact", ""])
    lines.extend(blocked or ["- (none)"])
    lines.append("")
    return "\n".join(lines)


def write_learnings(ctx: FindingsContext | None = None, output: Path | None = None) -> Path:
    ctx = ctx or FindingsContext.default()
    destination = output or (ctx.notes_root / "learnings.md")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_learnings(ctx), encoding="utf-8")
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description="Refresh itemdb/notes/learnings.md")
    parser.add_argument("--output", default="", help="Override the output path")
    args = parser.parse_args()
    output = Path(args.output) if args.output else None
    if output is not None and not output.is_absolute():
        output = ROOT / output
    try:
        path = write_learnings(output=output)
    except Exception as exc:  # noqa: BLE001
        print(C.fail(str(exc)), file=sys.stderr)
        return 1
    print(C.info(f"Wrote {path.relative_to(ROOT) if path.is_relative_to(ROOT) else path}"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
