from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from ..models import Finding
from .base import ScannerExecutionError, ScannerResult


TRIVY_SUPPLY_CHAIN_GATE = "Gate 10 — Dependency, SBOM & Supply Chain"
TRIVY_INFRA_GATE = "Gate 11 — Infrastructure, DNS, TLS & Web Hardening"
TRIVY_SECRETS_GATE = "Gate 4 — Secrets & Config Hygiene"


class TrivyScanner:
    name = "trivy"

    def is_available(self) -> bool:
        return shutil.which("trivy") is not None

    def scan(self, target: Path, report_dir: Path, *, strict_scanners: bool = False) -> ScannerResult:
        raw_dir = report_dir / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        raw_output_path = raw_dir / "trivy-results.json"

        if not self.is_available():
            return ScannerResult(
                name=self.name,
                available=False,
                raw_output_path=raw_output_path,
                findings=[_scanner_unavailable_finding(blocks_launch=strict_scanners)],
            )

        command = [
            "trivy",
            "fs",
            "--format",
            "json",
            "--output",
            str(raw_output_path),
            str(target),
        ]
        result = subprocess.run(command, cwd=str(target), capture_output=True, text=True)
        if result.returncode not in {0, 1}:
            raise ScannerExecutionError("Trivy failed while scanning the local target path.")

        if not raw_output_path.exists():
            raw_output_path.write_text('{"Results": []}\n', encoding="utf-8")

        findings = _normalize_trivy_output(raw_output_path)
        return ScannerResult(
            name=self.name,
            available=True,
            raw_output_path=raw_output_path,
            findings=findings,
            detected_count=len(findings),
        )


def _scanner_unavailable_finding(*, blocks_launch: bool = False) -> Finding:
    return Finding(
        title="Trivy scanner unavailable",
        severity="medium",
        status="open",
        category="scanner_unavailable",
        source="trivy",
        description="Trivy is not installed or is not available on PATH, so local dependency, filesystem, container, and IaC scanning was not run.",
        risk="Dependency, container, filesystem, or infrastructure configuration issues may exist without being detected by this local scan.",
        recommendation="Install Trivy and rerun `launchguardian scan --target .` before relying on scan results.",
        related_gate=TRIVY_SUPPLY_CHAIN_GATE,
        blocks_launch=blocks_launch,
    )


def _normalize_trivy_output(raw_output_path: Path) -> list[Finding]:
    try:
        raw_data = json.loads(raw_output_path.read_text(encoding="utf-8") or "{}")
    except json.JSONDecodeError as exc:
        raise ScannerExecutionError("Trivy produced invalid JSON output.") from exc

    results = raw_data.get("Results", []) if isinstance(raw_data, dict) else []
    if not isinstance(results, list):
        raise ScannerExecutionError("Trivy JSON output used an unsupported shape.")

    findings: list[Finding] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        findings.extend(_normalize_vulnerabilities(result))
        findings.extend(_normalize_misconfigurations(result))
        findings.extend(_normalize_secrets(result))
    return findings


def _normalize_vulnerabilities(result: dict[str, Any]) -> list[Finding]:
    vulnerabilities = result.get("Vulnerabilities") or []
    if not isinstance(vulnerabilities, list):
        return []

    findings: list[Finding] = []
    target = _safe_text(result.get("Target"))
    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue
        severity = _map_severity(item.get("Severity"))
        vulnerability_id = _safe_text(item.get("VulnerabilityID"))
        package_name = _safe_text(item.get("PkgName"))
        installed_version = _safe_text(item.get("InstalledVersion"))
        fixed_version = _safe_text(item.get("FixedVersion"))
        title = _safe_text(item.get("Title") or vulnerability_id or package_name or "Trivy vulnerability")
        description = _safe_text(item.get("Description") or title)
        findings.append(
            Finding(
                title=f"Trivy vulnerability: {title}",
                severity=severity,
                status="open",
                category="dependency_vulnerability",
                source="trivy",
                file_path=target,
                package_name=package_name,
                installed_version=installed_version,
                fixed_version=fixed_version,
                vulnerability_id=vulnerability_id,
                description=description,
                risk="A vulnerable dependency or package may expose the project to known security issues.",
                recommendation=_vulnerability_recommendation(fixed_version),
                related_gate=TRIVY_SUPPLY_CHAIN_GATE,
                blocks_launch=severity in {"critical", "high"},
            )
        )
    return findings


def _normalize_misconfigurations(result: dict[str, Any]) -> list[Finding]:
    misconfigurations = result.get("Misconfigurations") or []
    if not isinstance(misconfigurations, list):
        return []

    findings: list[Finding] = []
    target = _safe_text(result.get("Target"))
    for item in misconfigurations:
        if not isinstance(item, dict):
            continue
        severity = _map_severity(item.get("Severity"))
        rule_id = _safe_text(item.get("ID") or item.get("AVDID"))
        title = _safe_text(item.get("Title") or rule_id or "Trivy misconfiguration")
        description = _safe_text(item.get("Description") or item.get("Message") or title)
        findings.append(
            Finding(
                title=f"Trivy misconfiguration: {title}",
                severity=severity,
                status="open",
                category="iac_misconfiguration",
                source="trivy",
                file_path=target,
                vulnerability_id=rule_id,
                description=description,
                risk="Infrastructure or configuration weaknesses may expose deployed systems or data.",
                recommendation=_safe_text(
                    item.get("Resolution")
                    or "Review the Trivy misconfiguration, update the IaC/configuration, or document an accepted risk."
                ),
                related_gate=TRIVY_INFRA_GATE,
                blocks_launch=severity in {"critical", "high"},
            )
        )
    return findings


def _normalize_secrets(result: dict[str, Any]) -> list[Finding]:
    secrets = result.get("Secrets") or []
    if not isinstance(secrets, list):
        return []

    findings: list[Finding] = []
    target = _safe_text(result.get("Target"))
    for item in secrets:
        if not isinstance(item, dict):
            continue
        rule_id = _safe_text(item.get("RuleID") or item.get("ID") or "secret")
        line = _safe_int(item.get("StartLine") or item.get("EndLine"))
        findings.append(
            Finding(
                title=f"Trivy secret detected: {rule_id}",
                severity="critical",
                status="open",
                category="secrets",
                source="trivy",
                file_path=target,
                line=line,
                vulnerability_id=rule_id,
                description="Trivy detected a potential secret. Secret values are not included in normalized findings.",
                risk="Committed secrets can allow unauthorized access to systems, data, or third-party services.",
                recommendation="Remove the secret, rotate the credential, and verify history and deployment configuration.",
                related_gate=TRIVY_SECRETS_GATE,
                blocks_launch=True,
            )
        )
    return findings


def _map_severity(value: Any) -> str:
    normalized = str(value or "").strip().upper()
    if normalized == "CRITICAL":
        return "critical"
    if normalized == "HIGH":
        return "high"
    if normalized == "MEDIUM":
        return "medium"
    if normalized == "LOW":
        return "low"
    return "medium"


def _vulnerability_recommendation(fixed_version: str) -> str:
    if fixed_version:
        return f"Update the affected package to a fixed version: {fixed_version}."
    return "Review the vulnerability, update or replace the affected package, or document an accepted risk."


def _safe_text(value: Any) -> str:
    return str(value or "").strip()


def _safe_int(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None
