from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from . import __version__

# The report JSON schema version is independent of the package version and is
# bumped only when the report shape changes.
REPORT_SCHEMA_VERSION = "0.2.0"


Severity = Literal["critical", "high", "medium", "low", "info"]
FindingStatus = Literal[
    "open",
    "fixed",
    "accepted",
    "false_positive",
    "not_applicable",
    "needs_review",
]
DispositionStatus = Literal["not_applicable"]
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


@dataclass(frozen=True)
class FindingDisposition:
    source: str
    rule_id: str
    status: DispositionStatus
    reason: str
    evidence: str
    approved_by: str
    approved_on: str

    def to_dict(self) -> dict[str, str]:
        return {
            "source": self.source,
            "rule_id": self.rule_id,
            "status": self.status,
            "reason": self.reason,
            "evidence": self.evidence,
            "approved_by": self.approved_by,
            "approved_on": self.approved_on,
        }


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
    endpoint_or_route: str = ""
    package_name: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    vulnerability_id: str = ""
    rule_id: str = ""
    disposition: FindingDisposition | None = None

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
            "endpoint_or_route": self.endpoint_or_route,
            "package_name": self.package_name,
            "installed_version": self.installed_version,
            "fixed_version": self.fixed_version,
            "vulnerability_id": self.vulnerability_id,
            "rule_id": self.rule_id,
            "description": self.description,
            "risk": self.risk,
            "recommendation": self.recommendation,
            "related_gate": self.related_gate,
            "blocks_launch": self.blocks_launch,
            "disposition": self.disposition.to_dict() if self.disposition else None,
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
    validation_mode: str = "project"
    scan_mode: str = "none"
    lgf_validation_skipped: bool = False
    strict_scanners: bool = False
    findings: list[Finding] = field(default_factory=list)
    lgf_config_valid: bool = True
    scanner_availability: dict[str, str] = field(default_factory=dict)
    scanner_counts: dict[str, int] = field(default_factory=dict)
    scanner_blocking_counts: dict[str, int] = field(default_factory=dict)
    launchguardian_config: dict[str, Any] = field(default_factory=dict)
    scanned_commit: str | None = None
    worktree_clean: bool | None = None
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )

    @property
    def blocked(self) -> bool:
        return any(finding.blocks_launch and finding.status == "open" for finding in self.findings)

    @property
    def launch_status(self) -> str:
        if self.blocked:
            return "BLOCKED"
        if any(
            status in {"unavailable", "execution_failed", "failed", "disabled"}
            for status in self.scanner_availability.values()
        ):
            return "INCOMPLETE"
        if self.lgf_validation_skipped:
            return "SCANNED_WITHOUT_LGF"
        if any(
            finding.status == "open" and finding.category == "scanner_unavailable"
            for finding in self.findings
        ):
            return "INCOMPLETE"
        if any(finding.disposition is not None for finding in self.findings):
            return "APPROVED_WITH_DISPOSITIONS"
        return "APPROVED"

    @property
    def lgf_validation_status(self) -> str:
        if self.lgf_validation_skipped:
            return "skipped"
        return "valid" if self.lgf_config_valid else "blocked"

    @property
    def counts_by_severity(self) -> dict[str, int]:
        counts = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    @property
    def counts_by_scanner(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.source] = counts.get(finding.source, 0) + 1
        return counts

    @property
    def counts_by_status(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.status] = counts.get(finding.status, 0) + 1
        return counts

    @property
    def counts_by_gate(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            gate = finding.related_gate or "Unmapped"
            counts[gate] = counts.get(gate, 0) + 1
        return counts

    @property
    def blocking_findings(self) -> list[Finding]:
        return [
            finding
            for finding in self.findings
            if finding.blocks_launch and finding.status == "open"
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_name": "launchguardian.report",
            "schema_version": REPORT_SCHEMA_VERSION,
            "generated_at": self.generated_at,
            "launchguardian_version": __version__,
            "target": str(self.target),
            "scanned_commit": self.scanned_commit,
            "worktree_clean": self.worktree_clean,
            "mode": self.mode,
            "validation_mode": self.validation_mode,
            "scan_mode": self.scan_mode,
            "lgf_validation_skipped": self.lgf_validation_skipped,
            "strict_scanners": self.strict_scanners,
            "launch_status": self.launch_status,
            "lgf_config_valid": self.lgf_config_valid,
            "lgf_validation_status": self.lgf_validation_status,
            "scanner_availability": self.scanner_availability,
            "scanner_counts": self.scanner_counts,
            "scanner_blocking_counts": self.scanner_blocking_counts,
            "counts_by_severity": self.counts_by_severity,
            "counts_by_scanner": self.counts_by_scanner,
            "counts_by_status": self.counts_by_status,
            "counts_by_gate": self.counts_by_gate,
            "blocking_findings": [finding.to_dict() for finding in self.blocking_findings],
            "launchguardian_config": self.launchguardian_config,
            "blocked": self.blocked,
            "findings": [finding.to_dict() for finding in self.findings],
        }
