"""Tests for the command-line interface (__main__.py)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from security.workflow.__main__ import main
from security.workflow.analyzer import analyze_paths
from security.workflow.constants import (
    EVENT_SCHEMA_VERSION,
    SARIF_SCHEMA_VERSION,
    ExitCode,
)

LABS_DIR = Path(__file__).resolve().parent.parent / "labs"
LABS_SECURE = LABS_DIR / "secure"
LABS_VULN = LABS_DIR / "vulnerable"


class TestCliDirectInvocation:
    def test_help_invocation(self) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main(["--help"])
        assert exc_info.value.code == ExitCode.SUCCESS

    def test_missing_subcommand_exits_3(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main([])
        assert exit_code == ExitCode.ERROR
        captured = capsys.readouterr()
        assert "Error: Subcommand required" in captured.err

    def test_bad_args_exits_3(self) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main(["scan", "--invalid-flag"])
        assert exc_info.value.code == ExitCode.ERROR

    def test_scan_text_format(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["scan", str(LABS_SECURE), "--format", "text"])
        assert exit_code == ExitCode.SUCCESS
        out = capsys.readouterr().out
        assert "PipelineGuard Workflow Security Report" in out

    def test_scan_json_format(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["scan", str(LABS_SECURE), "--format", "json"])
        assert exit_code == ExitCode.SUCCESS
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["schema_version"] == EVENT_SCHEMA_VERSION

    def test_scan_sarif_format(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["scan", str(LABS_SECURE), "--format", "sarif"])
        assert exit_code == ExitCode.SUCCESS
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["version"] == SARIF_SCHEMA_VERSION

    def test_vulnerable_scan_exits_1(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["scan", str(LABS_VULN), "--format", "text"])
        assert exit_code == ExitCode.BLOCK

    def test_vulnerable_fail_on_never_exits_0(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["scan", str(LABS_VULN), "--fail-on", "never"])
        assert exit_code == ExitCode.SUCCESS

    def test_warn_only_fail_on_warn_exits_2(self, tmp_path: Path) -> None:
        wf = tmp_path / "warn_wf.yml"
        # Create a workflow that only has a detector error or warning rule
        # By configuring severity override to WARN:
        wf.write_text("name: Test\non: push\njobs: {}\n", encoding="utf-8")
        cfg_file = tmp_path / "pipelineguard.yml"
        cfg_file.write_text(
            "rules:\n  PG-WF-001:\n    action: WARN\n", encoding="utf-8"
        )
        # Add finding that triggers PG-WF-001
        wf.write_text(
            "name: Test\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n",
            encoding="utf-8",
        )
        exit_code = main([
            "scan", str(wf),
            "--config", str(cfg_file),
            "--fail-on", "warn",
        ])
        assert exit_code == ExitCode.WARN

    def test_baseline_flow(self, tmp_path: Path) -> None:
        baseline_file = tmp_path / "baseline.json"

        # 1. Write baseline
        exit_code = main([
            "scan", str(LABS_VULN),
            "--write-baseline", str(baseline_file),
        ])
        assert exit_code == ExitCode.BLOCK
        assert baseline_file.is_file()

        # 2. Rescan using baseline -> findings are baselined, exits 0
        exit_code = main([
            "scan", str(LABS_VULN),
            "--baseline", str(baseline_file),
        ])
        assert exit_code == ExitCode.SUCCESS

    def test_atomic_output_file(self, tmp_path: Path) -> None:
        out_file = tmp_path / "report.json"
        exit_code = main([
            "scan", str(LABS_SECURE),
            "--format", "json",
            "--output", str(out_file),
        ])
        assert exit_code == ExitCode.SUCCESS
        assert out_file.is_file()
        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert data["summary"]["total_findings"] == 0

    def test_invalid_repository_name_exits_3(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main([
            "scan", str(LABS_SECURE),
            "--repository", "invalid repo with spaces",
        ])
        assert exit_code == ExitCode.ERROR
        err = capsys.readouterr().err
        assert "Invalid repository name" in err


class TestCliSubprocess:
    def test_subprocess_execution(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "security.workflow", "scan", str(LABS_SECURE), "--format", "json"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == ExitCode.SUCCESS
        data = json.loads(result.stdout)
        assert data["schema_version"] == EVENT_SCHEMA_VERSION

    def test_subprocess_vulnerable_exit_1(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "security.workflow", "scan", str(LABS_VULN)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == ExitCode.BLOCK

    def test_missing_baseline_file_exits_3(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["scan", str(LABS_SECURE), "--baseline", "nonexistent.json"])
        assert exit_code == ExitCode.ERROR
        err = capsys.readouterr().err
        assert "Baseline file not found" in err

    def test_malformed_baseline_json_exits_3(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("invalid json {", encoding="utf-8")
        exit_code = main(["scan", str(LABS_SECURE), "--baseline", str(bad_file)])
        assert exit_code == ExitCode.ERROR
        err = capsys.readouterr().err
        assert "Failed to parse baseline" in err

    def test_invalid_baseline_format_exits_3(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        bad_file = tmp_path / "bad.json"
        bad_file.write_text('"a string not list or dict"', encoding="utf-8")
        exit_code = main(["scan", str(LABS_SECURE), "--baseline", str(bad_file)])
        assert exit_code == ExitCode.ERROR
        err = capsys.readouterr().err
        assert "Invalid baseline file format" in err

    def test_baseline_list_format_accepted(self, tmp_path: Path) -> None:
        analysis = analyze_paths(LABS_VULN)
        list_file = tmp_path / "list_base.json"
        fps = [f.fingerprint() for f in analysis.findings]
        list_file.write_text(json.dumps(fps), encoding="utf-8")

        exit_code = main(["scan", str(LABS_VULN), "--baseline", str(list_file)])
        assert exit_code == ExitCode.SUCCESS

    def test_bad_config_exits_3(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["scan", str(LABS_SECURE), "--config", "missing_config.yml"])
        assert exit_code == ExitCode.ERROR
        err = capsys.readouterr().err
        assert "Configuration file not found" in err

    def test_output_symlink_refused(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
        from unittest.mock import patch
        fake_symlink = tmp_path / "symlink_report.txt"
        with patch.object(Path, "is_symlink", return_value=True):
            exit_code = main(["scan", str(LABS_SECURE), "--output", str(fake_symlink)])
            assert exit_code == ExitCode.ERROR
            err = capsys.readouterr().err
            assert "Refusing to write output to a symlink" in err

    def test_write_atomic_failure(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        from unittest.mock import patch
        out_file = tmp_path / "out.txt"
        with patch.object(Path, "replace", side_effect=OSError("Read-only filesystem")):
            exit_code = main(["scan", str(LABS_SECURE), "--output", str(out_file)])
            assert exit_code == ExitCode.ERROR
            err = capsys.readouterr().err
            assert "Failed to write output" in err

    def test_unexpected_exception_exits_3(self, capsys: pytest.CaptureFixture[str]) -> None:
        from unittest.mock import patch
        with patch("security.workflow.__main__.analyze_paths", side_effect=RuntimeError("Fatal error")):
            exit_code = main(["scan", str(LABS_SECURE)])
            assert exit_code == ExitCode.ERROR
            err = capsys.readouterr().err
            assert "Fatal error" in err

    def test_unexpected_exception_with_debug_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        from unittest.mock import patch
        with patch("security.workflow.__main__.analyze_paths", side_effect=RuntimeError("Fatal error")):
            exit_code = main(["scan", str(LABS_SECURE), "--debug"])
            assert exit_code == ExitCode.ERROR
            err = capsys.readouterr().err
            assert "Traceback" in err or "Fatal error" in err

