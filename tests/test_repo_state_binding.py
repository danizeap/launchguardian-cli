"""A report must say which commit it scanned, or say it does not know.

An unbound report cannot prove anything about the code being shipped, and an
unknown commit must never be reported as a known one.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from launchguardian.models import ValidationReport
from launchguardian.repo_state import COMMIT_PATTERN, describe, scanned_commit, worktree_clean


def _git(repo: Path, *arguments: str) -> None:
    subprocess.run(["git", *arguments], cwd=repo, check=True, capture_output=True)


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "Test")
    _git(tmp_path, "config", "core.autocrlf", "false")
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-q", "-m", "initial")
    return tmp_path


def test_clean_repository_binds_to_its_exact_head(repo: Path) -> None:
    commit, clean = describe(repo)
    assert commit is not None
    assert COMMIT_PATTERN.fullmatch(commit)
    assert clean is True

    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, check=True
    ).stdout.strip()
    assert commit == head


def test_tracked_modification_is_not_clean(repo: Path) -> None:
    (repo / "app.py").write_text("print('changed')\n", encoding="utf-8")
    assert worktree_clean(repo) is False


def test_untracked_file_is_not_clean(repo: Path) -> None:
    (repo / "stray.py").write_text("x = 1\n", encoding="utf-8")
    assert worktree_clean(repo) is False


def test_non_repository_reports_unknown_not_clean(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    commit, clean = describe(plain)
    assert commit is None
    assert clean is None, "unknown must never be recorded as clean"


def test_report_serializes_its_binding(repo: Path) -> None:
    commit, clean = describe(repo)
    report = ValidationReport(target=repo, scanned_commit=commit, worktree_clean=clean)
    payload = json.loads(json.dumps(report.to_dict()))
    assert payload["scanned_commit"] == commit
    assert payload["worktree_clean"] is True


def test_unbound_report_defaults_to_unknown() -> None:
    report = ValidationReport(target=Path("."))
    payload = report.to_dict()
    assert payload["scanned_commit"] is None
    assert payload["worktree_clean"] is None
