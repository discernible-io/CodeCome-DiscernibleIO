"""Tests for the matcher scan, file records, chain hypothesis, and learnings."""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from conftest import load_tool_module


def _sweep():
    return load_tool_module("run_sweep_candidates", "tools/run-sweep.py")


def _matchers():
    return load_tool_module("matchers_under_test", "tools/matchers.py")


def _records():
    return load_tool_module("file_records_under_test", "tools/file_records.py")


def _learnings():
    return load_tool_module("write_learnings_under_test", "tools/write-learnings.py")


def _chain():
    return load_tool_module("chain_findings_under_test", "tools/chain-findings.py")


def _write_finding(directory: Path, finding_id: str, title: str, *, fingerprint: str, status: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    body = textwrap.dedent(
        f"""\
        ---
        id: "{finding_id}"
        title: "{title}"
        fingerprint: "{fingerprint}"
        status: "{status}"
        sinks:
          - "example sink"
        ---

        # Summary

        {title}
        """
    )
    (directory / f"{finding_id}-example.md").write_text(body, encoding="utf-8")


class TestMatchers:
    def test_scan_records_eval_and_express(self, tmp_path: Path):
        module = _matchers()
        source = tmp_path / "src"
        source.mkdir()
        (source / "package.json").write_text(
            '{"dependencies": {"express": "4.0.0"}}',
            encoding="utf-8",
        )
        (source / "app.js").write_text("function run(input) {\n  return eval(input);\n}\n", encoding="utf-8")
        (source / "tests").mkdir()
        (source / "tests" / "app.test.js").write_text("eval('fixture')\n", encoding="utf-8")

        document = module.scan_tree(tmp_path, include=["src/**"], exclude=[])

        assert "express" in document["tech"]
        by_path = {entry["path"]: entry for entry in document["files"]}
        assert by_path["src/app.js"]["matches"][0]["slug"] == "eval-call"
        assert by_path["src/app.js"]["matches"][0]["line"] == 2
        assert by_path["src/tests/app.test.js"]["in_test"] is True
        assert "express" in document["highlights"]

    def test_django_rule_stays_off_without_django(self, tmp_path: Path):
        module = _matchers()
        source = tmp_path / "src"
        source.mkdir()
        (source / "app.py").write_text("html = mark_safe(name)\n", encoding="utf-8")
        document = module.scan_tree(tmp_path, include=["src/**"], exclude=[])
        assert document["files"] == []


class TestFileRecords:
    def test_append_then_skip_until_bytes_change(self, tmp_path: Path):
        records = _records()
        sweep = _sweep()
        source = tmp_path / "src" / "a.py"
        source.parent.mkdir(parents=True)
        source.write_text("one\n", encoding="utf-8")
        files_root = tmp_path / "files"
        sweep.ROOT = tmp_path
        sweep.FILES_ROOT = files_root
        sweep.CANDIDATES_PATH = tmp_path / "missing-candidates.yml"

        assert sweep.should_skip("src/a.py", {"src/a.py"}, False) is True
        records.append_entry(files_root, "src/a.py", blob=records.file_blob(source), model="test")
        assert sweep.should_skip("src/a.py", set(), False) is True

        source.write_text("two\n", encoding="utf-8")
        assert sweep.should_skip("src/a.py", {"src/a.py"}, False) is False
        assert sweep.should_skip("src/a.py", {"src/a.py"}, True) is False

    def test_candidate_selection_skips_tests(self, tmp_path: Path):
        sweep = _sweep()
        document = {
            "files": [
                {"path": "src/app.js", "in_test": False, "matches": [{"slug": "eval-call"}]},
                {"path": "src/tests/app.test.js", "in_test": True, "matches": [{"slug": "eval-call"}]},
            ]
        }
        path = tmp_path / "candidates.yml"
        path.write_text(yaml.safe_dump(document), encoding="utf-8")
        assert sweep.candidate_files(path, include_tests=False) == ["src/app.js"]
        assert sweep.candidate_files(path, include_tests=True) == [
            "src/app.js",
            "src/tests/app.test.js",
        ]

    def test_budget_reads_zero_as_unlimited(self, tmp_path: Path):
        sweep = _sweep()
        config = tmp_path / "codecome.yml"
        config.write_text("audit:\n  budget:\n    max_files: 0\n    max_wall_clock_seconds: 30\n", encoding="utf-8")
        assert sweep.load_budget(config) == (0, 30)

    def test_prompt_includes_matcher_hit(self, tmp_path: Path):
        sweep = _sweep()
        sweep.TMP_DIR = tmp_path / "prompts"
        sweep.PROMPT_TEMPLATE = tmp_path / "template.md"
        sweep.PROMPT_TEMPLATE.write_text("Target: FILE_PATH_OR_ID\n", encoding="utf-8")
        path = sweep.build_prompt_for_file(
            "src/app.js",
            hits="- line 2: `eval-call` — eval() executes a string as code.",
            fingerprints="- `injection:src/app.js#run`",
        )
        content = path.read_text(encoding="utf-8")
        assert "src/app.js" in content
        assert "eval-call" in content
        assert "injection:src/app.js#run" in content
        assert "FILE_PATH_OR_ID" not in content


class TestLearningsAndChain:
    def _context(self, tmp_path: Path):
        from findings.constants import FindingsContext

        itemdb = tmp_path / "itemdb"
        return FindingsContext(
            root=tmp_path,
            itemdb_root=itemdb,
            findings_root=itemdb / "findings",
            evidence_root=itemdb / "evidence",
            notes_root=itemdb / "notes",
            reports_root=itemdb / "reports",
            template_path=ROOT / "templates" / "finding.md",
        )

    def test_learnings_lists_rejected_fingerprint(self, tmp_path: Path):
        module = _learnings()
        ctx = self._context(tmp_path)
        _write_finding(
            ctx.findings_root / "REJECTED",
            "CC-0002",
            "Rejected eval",
            fingerprint="codeinj:src/app.js#run",
            status="REJECTED",
        )
        text = module.render_learnings(ctx)
        assert "`codeinj:src/app.js#run`" in text
        assert "Do not re-file" in text

    def test_chain_requires_two_confirmed_findings(self, tmp_path: Path):
        module = _chain()
        ctx = self._context(tmp_path)
        _write_finding(
            ctx.findings_root / "CONFIRMED",
            "CC-0001",
            "First",
            fingerprint="authz:src/a.js#one",
            status="CONFIRMED",
        )
        assert module.write_chain(ctx) is None
        _write_finding(
            ctx.findings_root / "EXPLOITED",
            "CC-0003",
            "Second",
            fingerprint="authz:src/b.js#two",
            status="EXPLOITED",
        )
        created = module.write_chain(ctx)
        assert created is not None
        content = created.read_text(encoding="utf-8")
        assert 'fingerprint: "chain:CC-0001+CC-0003"' in content
        assert 'gate: "chained"' in content
        assert "CC-0001" in content and "CC-0003" in content
        again = module.write_chain(ctx)
        assert again == created


class TestPromptContracts:
    def test_phase_prompts_mention_the_new_checks(self):
        phase3 = (ROOT / "prompts" / "phase-3-review.md").read_text(encoding="utf-8")
        phase4 = (ROOT / "prompts" / "phase-4-validate.md").read_text(encoding="utf-8")
        phase2 = (ROOT / "prompts" / "phase-2-audit.md").read_text(encoding="utf-8")
        assert "capability.disposition" in phase3
        assert "not-shipped" in phase3
        assert "Proof-only rerun" in phase4
        assert "learnings.md" in phase2
