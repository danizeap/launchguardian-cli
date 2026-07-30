"""Bind a scan report to the exact repository state it examined.

A report that does not say which commit it scanned cannot prove anything
about the code you are about to ship. Consumers of these reports treat an
unknown commit, or a commit scanned from a dirty worktree, as no evidence.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path


COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def _git(target: Path, arguments: list[str]) -> str | None:
    executable = shutil.which("git")
    if not executable:
        return None
    try:
        result = subprocess.run(
            [executable, *arguments],
            cwd=str(target),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout


def scanned_commit(target: Path) -> str | None:
    """Return the exact HEAD commit of the scanned target, or None."""
    raw = _git(target, ["rev-parse", "HEAD"])
    if raw is None:
        return None
    candidate = raw.strip()
    return candidate if COMMIT_PATTERN.fullmatch(candidate) else None


def worktree_clean(target: Path) -> bool | None:
    """Return True only when Git reports no tracked or untracked changes.

    None means cleanliness could not be established, which is not the same as
    clean and must never be read as clean.
    """
    raw = _git(target, ["status", "--porcelain=v1", "--untracked-files=all"])
    if raw is None:
        return None
    return raw.strip() == ""


def describe(target: Path) -> tuple[str | None, bool | None]:
    """Return (scanned_commit, worktree_clean) for the target."""
    return scanned_commit(target), worktree_clean(target)
