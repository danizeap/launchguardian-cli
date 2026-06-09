from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..models import Finding


class ScannerExecutionError(RuntimeError):
    """Raised when an installed scanner fails unexpectedly."""


@dataclass(frozen=True)
class ScannerResult:
    name: str
    available: bool
    findings: list[Finding] = field(default_factory=list)
    detected_count: int = 0
    raw_output_path: Path | None = None
