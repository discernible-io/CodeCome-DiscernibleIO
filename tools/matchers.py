#!/usr/bin/env python3
# Copyright (C) 2025-2026 Pablo Ruiz García <pablo.ruiz@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later OR AGPL-3.0-or-later

"""Deterministic candidate matchers.

The pass is inspired by DeepSec's split between a free regex scan and a
paid review. The patterns and highlight lines here are original. They are
not copied from the DeepSec matcher catalog.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

SKIP_DIRS = {
    ".git",
    ".hg",
    ".next",
    ".svn",
    "bin",
    "build",
    "dist",
    "node_modules",
    "obj",
    "target",
    "vendor",
}

SOURCE_SUFFIXES = {
    ".blade.php",
    ".cjs",
    ".cs",
    ".go",
    ".java",
    ".js",
    ".jsx",
    ".mjs",
    ".php",
    ".py",
    ".rb",
    ".ts",
    ".tsx",
}

# (pattern, suffixes or None for any source suffix, slug, reason, required tech or None)
_RULES: list[tuple[re.Pattern[str], set[str] | None, str, str, str | None]] = [
    (
        re.compile(r"\beval\s*\("),
        {".js", ".mjs", ".cjs", ".ts", ".py"},
        "eval-call",
        "eval() executes a string as code.",
        None,
    ),
    (
        re.compile(r"dangerouslySetInnerHTML"),
        {".js", ".jsx", ".ts", ".tsx"},
        "dangerous-html",
        "dangerouslySetInnerHTML inserts HTML into the page.",
        None,
    ),
    (
        re.compile(r"\.innerHTML\s*="),
        {".js", ".jsx", ".ts", ".tsx"},
        "innerhtml-assign",
        "An innerHTML assignment can parse markup.",
        None,
    ),
    (
        re.compile(r"\bchild_process\b|\bexecSync\s*\("),
        {".js", ".mjs", ".cjs", ".ts", ".tsx"},
        "child-process",
        "This file starts a child process.",
        None,
    ),
    (
        re.compile(r"os\.system\s*\(|shell\s*=\s*True"),
        {".py"},
        "shell-exec",
        "A shell command is started from Python.",
        None,
    ),
    (
        re.compile(r"pickle\.loads?\s*\("),
        {".py"},
        "pickle-load",
        "pickle.load deserializes arbitrary objects.",
        None,
    ),
    (
        re.compile(r"DB::raw|whereRaw\s*\("),
        {".php", ".blade.php"},
        "laravel-raw-sql",
        "A raw SQL fragment is passed to the query builder.",
        "laravel",
    ),
    (
        re.compile(r"\{!!"),
        {".php", ".blade.php"},
        "blade-raw",
        "A Blade raw echo writes unescaped HTML.",
        "laravel",
    ),
    (
        re.compile(r"@csrf_exempt|mark_safe\s*\("),
        {".py"},
        "django-trust-escape",
        "A Django CSRF or escaping check is bypassed.",
        "django",
    ),
    (
        re.compile(r"html_safe|skip_before_action"),
        {".rb"},
        "rails-trust-escape",
        "A Rails escaping or auth callback is skipped.",
        "rails",
    ),
]

HIGHLIGHTS: dict[str, list[str]] = {
    "nextjs": [
        "A Server Action is a reachable POST. middleware.ts alone does not authorize it.",
    ],
    "express": [
        "Middleware registered after a route does not run for that route.",
    ],
    "django": [
        "csrf_exempt and mark_safe opt out of framework protections.",
    ],
    "laravel": [
        "DB::raw and {!! !!} skip parameter binding and HTML escaping.",
    ],
    "rails": [
        "skip_before_action and html_safe drop an auth callback or escaping.",
    ],
    "gin": [
        "Middleware registered on a group does not cover routes mounted outside that group.",
    ],
}

_TEST_PARTS = {"test", "tests", "__tests__", "spec", "fixtures", "testdata"}
_TEST_SUFFIXES = (".test.js", ".test.ts", ".test.tsx", ".spec.js", ".spec.ts", ".spec.tsx", "_test.py")
_MAX_MATCHES = 5
_MAX_BYTES = 1_000_000


def is_test_path(rel: str) -> bool:
    parts = set(Path(rel).parts)
    if parts & _TEST_PARTS:
        return True
    return rel.endswith(_TEST_SUFFIXES)


def _suffix(rel: str) -> str:
    if rel.endswith(".blade.php"):
        return ".blade.php"
    return Path(rel).suffix


def _skipped(rel: str) -> bool:
    return bool(set(Path(rel).parts) & SKIP_DIRS)


def detect_tech(root: Path) -> list[str]:
    """Return framework tags found from sentinel files under root."""
    tags: set[str] = set()
    for path in _sentinel_files(root):
        rel = str(path.relative_to(root))
        if _skipped(rel):
            continue
        name = path.name
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if name == "package.json":
            tags.update(_package_json_tags(text))
        elif name in {"requirements.txt", "pyproject.toml", "setup.py"}:
            tags.update(_python_tags(text))
        elif name == "manage.py":
            tags.add("django")
        elif name == "composer.json":
            if "laravel" in text.lower():
                tags.add("laravel")
        elif name == "Gemfile":
            if re.search(r"""['"]rails['"]""", text):
                tags.add("rails")
        elif name == "go.mod":
            if "github.com/gin-gonic/gin" in text:
                tags.add("gin")
    return sorted(tags)


def _package_json_tags(text: str) -> set[str]:
    tags: set[str] = set()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        lowered = text.lower()
        if '"next"' in lowered:
            tags.add("nextjs")
        if '"express"' in lowered:
            tags.add("express")
        return tags
    deps: dict[str, object] = {}
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        block = data.get(key)
        if isinstance(block, dict):
            deps.update(block)
    names = {str(name) for name in deps}
    if "next" in names:
        tags.add("nextjs")
    if "express" in names:
        tags.add("express")
    return tags


def _python_tags(text: str) -> set[str]:
    tags: set[str] = set()
    lowered = text.lower()
    if "django" in lowered:
        tags.add("django")
    if "flask" in lowered:
        tags.add("flask")
    if "fastapi" in lowered:
        tags.add("fastapi")
    return tags


def _sentinel_files(root: Path) -> Iterable[Path]:
    names = {
        "Gemfile",
        "composer.json",
        "go.mod",
        "manage.py",
        "package.json",
        "pyproject.toml",
        "requirements.txt",
        "setup.py",
    }
    if not root.exists():
        return []
    found: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.name not in names:
            continue
        try:
            rel = path.relative_to(root)
        except ValueError:
            continue
        if _skipped(str(rel)):
            continue
        found.append(path)
    return found


def match_text(rel: str, text: str, tech: set[str]) -> list[dict[str, object]]:
    suffix = _suffix(rel)
    if suffix not in SOURCE_SUFFIXES:
        return []
    matches: list[dict[str, object]] = []
    seen: set[str] = set()
    for pattern, suffixes, slug, reason, required in _RULES:
        if slug in seen:
            continue
        if suffixes is not None and suffix not in suffixes:
            continue
        if required is not None and required not in tech:
            continue
        hit = pattern.search(text)
        if hit is None:
            continue
        line = text.count("\n", 0, hit.start()) + 1
        matches.append({"slug": slug, "line": line, "reason": reason})
        seen.add(slug)
        if len(matches) >= _MAX_MATCHES:
            break
    return matches


def scan_tree(
    root: Path,
    *,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
) -> dict[str, object]:
    """Scan source files and return the candidates document."""
    include = include or ["src/**"]
    exclude = exclude or []
    tech = detect_tech(root)
    tech_set = set(tech)
    files: list[dict[str, object]] = []
    for rel in _iter_included(root, include, exclude):
        path = root / rel
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        matches = match_text(rel, text, tech_set)
        if not matches:
            continue
        files.append(
            {
                "path": rel,
                "in_test": is_test_path(rel),
                "matches": matches,
            }
        )
    files.sort(key=lambda item: str(item["path"]))
    highlights = {tag: HIGHLIGHTS[tag] for tag in tech if tag in HIGHLIGHTS}
    return {
        "version": 1,
        "tech": tech,
        "highlights": highlights,
        "files": files,
    }


def _iter_included(root: Path, include: list[str], exclude: list[str]) -> list[str]:
    import glob

    excluded: set[str] = set()
    for pattern in exclude:
        excluded.update(glob.glob(pattern, root_dir=str(root), recursive=True))
    found: list[str] = []
    seen: set[str] = set()
    for pattern in include:
        matches = glob.glob(pattern, root_dir=str(root), recursive=True)
        for rel in matches:
            if rel in seen or rel in excluded or _skipped(rel):
                continue
            seen.add(rel)
            found.append(rel)
    return found
