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


@dataclass(frozen=True)
class ScannerResult:
    name: str
    available: bool
    findings: list[Finding] = field(default_factory=list)
    detected_count: int = 0
    raw_output_path: Path | None = None
