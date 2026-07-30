"""A scanner that did not produce evidence must never read as a clean scan.

Absence of scanner output is absence of evidence, not evidence of absence.
Every case here previously reported zero findings.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from launchguardian.scanners.base import (
    ScannerExecutionError,
    read_raw_scanner_output,
)
from launchguardian.scanners.gitleaks import _normalize_gitleaks_output
from launchguardian.scanners.semgrep import (
    _engine_diagnostic,
    _normalize_semgrep_output,
)
from launchguardian.scanners.trivy import _normalize_trivy_output


NORMALIZERS = [
    pytest.param(_normalize_semgrep_output, "Semgrep", id="semgrep"),
    pytest.param(_normalize_gitleaks_output, "Gitleaks", id="gitleaks"),
    pytest.param(_normalize_trivy_output, "Trivy", id="trivy"),
]


@pytest.mark.parametrize(("normalize", "scanner"), NORMALIZERS)
def test_missing_raw_report_is_an_execution_failure(
    tmp_path: Path, normalize, scanner: str
) -> None:
    with pytest.raises(ScannerExecutionError, match="no raw report file"):
        normalize(tmp_path / "absent.json")


@pytest.mark.parametrize(("normalize", "scanner"), NORMALIZERS)
@pytest.mark.parametrize("body", ["", "   ", "\n\t\n"])
def test_empty_raw_report_is_an_execution_failure(
    tmp_path: Path, normalize, scanner: str, body: str
) -> None:
    path = tmp_path / "empty.json"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(ScannerExecutionError, match="empty raw report"):
        normalize(path)


@pytest.mark.parametrize(("normalize", "scanner"), NORMALIZERS)
def test_truncated_raw_report_is_an_execution_failure(
    tmp_path: Path, normalize, scanner: str
) -> None:
    path = tmp_path / "torn.json"
    path.write_text('{"results": [', encoding="utf-8")
    with pytest.raises(ScannerExecutionError):
        normalize(path)


def test_semgrep_error_level_entries_block_an_incomplete_scan(
    tmp_path: Path,
) -> None:
    path = tmp_path / "semgrep-results.json"
    path.write_text(
        json.dumps(
            {
                "results": [],
                "errors": [
                    {
                        "level": "error",
                        "type": "SourceParseError",
                        "message": "could not parse 412 files",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ScannerExecutionError, match="did not fully run"):
        _normalize_semgrep_output(path)


def test_semgrep_warning_level_entries_do_not_block(tmp_path: Path) -> None:
    path = tmp_path / "semgrep-results.json"
    path.write_text(
        json.dumps(
            {
                "results": [],
                "errors": [{"level": "warn", "message": "skipped a large file"}],
            }
        ),
        encoding="utf-8",
    )
    assert _normalize_semgrep_output(path) == []


def test_semgrep_clean_report_with_no_errors_is_accepted(tmp_path: Path) -> None:
    path = tmp_path / "semgrep-results.json"
    path.write_text(json.dumps({"results": [], "errors": []}), encoding="utf-8")
    assert _normalize_semgrep_output(path) == []


def test_windows_socketpair_failure_is_explained_not_silent() -> None:
    stderr = "[ERROR]: Error: exception Unix_error: Invalid argument socketpair"
    diagnostic = _engine_diagnostic(stderr, "")
    assert "platform limitation" in diagnostic
    assert "no scan rather than a clean scan" in diagnostic


def test_unrelated_failure_gets_no_platform_diagnostic() -> None:
    assert _engine_diagnostic("some other failure", None) == ""


def test_reader_returns_body_when_report_has_content(tmp_path: Path) -> None:
    path = tmp_path / "ok.json"
    path.write_text('{"results": []}', encoding="utf-8")
    assert read_raw_scanner_output(path, scanner="Semgrep") == '{"results": []}'
