from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal


Severity = Literal["critical", "high", "medium", "low", "info"]
FindingStatus = Literal["open", "fixed", "accepted", "false_positive", "needs_review"]


@dataclass(frozen=True)
class Finding:
    title: str
    severity: Severity
    status: FindingStatus
    category: str
    source: str
    description: str
    risk: str
    recommendation: str
    related_gate: str = ""
    blocks_launch: bool = False
    file_path: str = ""
    line: int | None = None
    endpoint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "category": self.category,
            "source": self.source,
            "file_path": self.file_path,
            "line": self.line,
            "endpoint": self.endpoint,
            "description": self.description,
            "risk": self.risk,
            "recommendation": self.recommendation,
            "related_gate": self.related_gate,
            "blocks_launch": self.blocks_launch,
        }


@dataclass(frozen=True)
class DiscoveredConfig:
    target: Path
    gate_applicability: Path | None
    scope_contract: Path | None
    launch_decision: Path | None
    missing_files: tuple[str, ...] = ()
    framework_files: tuple[Path, ...] = ()
    missing_framework_files: tuple[str, ...] = ()


@dataclass
class ValidationReport:
    target: Path
    mode: str = "project"
    findings: list[Finding] = field(default_factory=list)
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )

    @property
    def blocked(self) -> bool:
        return any(finding.blocks_launch and finding.status == "open" for finding in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_name": "launchguardian.report",
            "schema_version": "0.1.0",
            "generated_at": self.generated_at,
            "launchguardian_version": "0.1.0",
            "target": str(self.target),
            "mode": self.mode,
            "blocked": self.blocked,
            "findings": [finding.to_dict() for finding in self.findings],
        }
