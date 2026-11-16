#!/usr/bin/env python3
# Copyright (C) 2025-2026 Pablo Ruiz García <pablo.ruiz@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later OR AGPL-3.0-or-later

"""File one PENDING chain hypothesis from confirmed findings.

Inspired by Mantis's chainer. The result is a normal finding with
gate: chained. It claims only that the confirmed members might compose.
Phase 4 and Phase 5 still have to demonstrate that.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _colors as C
from findings.constants import LIVE_STATUSES, FindingsContext
from findings.create import create_finding
from findings.frontmatter import load_frontmatter, replace_nested_value, replace_scalar_frontmatter
from findings.ids import iter_findings

ROOT = Path(__file__).resolve().parents[1]


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def chain_fingerprint(ids: list[str]) -> str:
    joined = "chain:" + "+".join(ids)
    if len(joined) <= 200:
        return joined
    digest = hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]
    return f"chain:{digest}"


def confirmed_members(ctx: FindingsContext) -> list[dict[str, Any]]:
    members: list[dict[str, Any]] = []
    for status in ("CONFIRMED", "EXPLOITED"):
        for path in iter_findings(status, findings_root=ctx.findings_root):
            data = load_frontmatter(path)
            if not isinstance(data, dict):
                continue
            finding_id = _text(data.get("id"))
            if not finding_id:
                continue
            members.append(
                {
                    "id": finding_id,
                    "title": _text(data.get("title")) or finding_id,
                    "path": path,
                    "status": status,
                }
            )
    members.sort(key=lambda item: str(item["id"]))
    return members


def existing_fingerprint(ctx: FindingsContext, fingerprint: str) -> Path | None:
    for path in iter_findings(findings_root=ctx.findings_root):
        data = load_frontmatter(path)
        if not isinstance(data, dict):
            continue
        if _text(data.get("fingerprint")) != fingerprint:
            continue
        if _text(data.get("status")) in LIVE_STATUSES:
            return path
    return None


def _fill(content: str, members: list[dict[str, Any]], fingerprint: str) -> str:
    content = replace_scalar_frontmatter(content, "fingerprint", fingerprint)
    content = replace_nested_value(content, "gate", "chained")
    content = replace_scalar_frontmatter(content, "category", "Exploit chain")
    content = replace_scalar_frontmatter(content, "target_area", "confirmed findings")
    lines = ["This hypothesis asks whether the following confirmed findings compose.", ""]
    for member in members:
        lines.append(f"- {member['id']} ({member['status']}): {member['title']}")
    lines.extend(
        [
            "",
            "A member list is not a demonstrated chain. Validation must show an input that reaches one finding's effect only because another finding changed a boundary, grant, or check.",
            "",
            "Set disposition to live only when that composition is reachable in the shipped configuration.",
        ]
    )
    return content.replace("Pending.", "\n".join(lines), 1)


def write_chain(ctx: FindingsContext | None = None, *, dry_run: bool = False) -> Path | None:
    ctx = ctx or FindingsContext.default()
    members = confirmed_members(ctx)
    if len(members) < 2:
        return None
    fingerprint = chain_fingerprint([str(item["id"]) for item in members])
    prior = existing_fingerprint(ctx, fingerprint)
    if prior is not None:
        return prior
    if dry_run:
        return None
    title = "Possible chain across " + ", ".join(str(item["id"]) for item in members)
    args = argparse.Namespace(
        title=title,
        id=None,
        slug="exploit-chain",
        confidence="LOW",
        category="Exploit chain",
        language="unknown",
        target_area="confirmed findings",
        force=False,
    )
    path = create_finding(args, ctx=ctx)
    content = _fill(path.read_text(encoding="utf-8"), members, fingerprint)
    path.write_text(content, encoding="utf-8")
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description="File a chain hypothesis from confirmed findings")
    parser.add_argument("--dry-run", action="store_true", help="Print members without writing a finding")
    args = parser.parse_args()
    ctx = FindingsContext.default()
    members = confirmed_members(ctx)
    print(C.header("Chain hypothesis"))
    if len(members) < 2:
        print(C.warn(f"{len(members)} confirmed or exploited finding(s); a chain needs two."))
        return 0
    for member in members:
        print(f"  {C.SYM_BULLET} {member['id']} — {member['title']}")
    fingerprint = chain_fingerprint([str(item["id"]) for item in members])
    prior = existing_fingerprint(ctx, fingerprint)
    if prior is not None:
        try:
            shown = prior.relative_to(ROOT)
        except ValueError:
            shown = prior
        print(C.info(f"Chain already filed: {shown}"))
        return 0
    if args.dry_run:
        print(C.info(f"Would file fingerprint {fingerprint}"))
        return 0
    path = write_chain(ctx)
    if path is None:
        print(C.warn("No chain written."))
        return 0
    print(C.info(f"Wrote {path.relative_to(ROOT)}"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
