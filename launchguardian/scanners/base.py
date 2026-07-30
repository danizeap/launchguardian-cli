from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Finding


class ScannerExecutionError(RuntimeError):
    """Raised when an installed scanner fails unexpectedly."""


def utf8_scanner_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment["PYTHONUTF8"] = "1"
    environment["PYTHONIOENCODING"] = "utf-8"
    return environment


def read_raw_scanner_output(raw_output_path: Path, *, scanner: str) -> str:
    """Return a scanner's raw report text, or fail closed.

    A missing, unreadable, or empty report is an execution failure, never zero
    findings. Absence of output does not prove absence of findings.
    """
    if not raw_output_path.exists():
        raise ScannerExecutionError(
            f"{scanner} produced no raw report file, so the scan cannot be "
            "treated as complete."
        )
    try:
        text = raw_output_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ScannerExecutionError(
            f"{scanner} produced invalid UTF-8 JSON output."
        ) from exc
    except OSError as exc:
        raise ScannerExecutionError(
            f"{scanner} raw report could not be read: {exc}"
        ) from exc
    if not text.strip():
        raise ScannerExecutionError(
            f"{scanner} wrote an empty raw report, so a clean result cannot be "
            "proven."
        )
    return text


@dataclass(frozen=True)
class ScannerResult:
    name: str
    available: bool
    findings: list[Finding] = field(default_factory=list)
    detected_count: int = 0
    raw_output_path: Path | None = None
