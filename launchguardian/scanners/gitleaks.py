from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from ..models import Finding
from .base import ScannerExecutionError, ScannerResult


GITLEAKS_RELATED_GATE = "Gate 4 — Secrets & Config Hygiene"


class GitleaksScanner:
    name = "gitleaks"

    def is_available(self) -> bool:
        return shutil.which("gitleaks") is not None

    def scan(self, target: Path, report_dir: Path, *, strict_scanners: bool = False) -> ScannerResult:
        raw_dir = report_dir / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        raw_output_path = raw_dir / "gitleaks-results.json"

        if not self.is_available():
            return ScannerResult(
                name=self.name,
                available=False,
                raw_output_path=raw_output_path,
                findings=[_scanner_unavailable_finding(blocks_launch=strict_scanners)],
            )

        command = [
            "gitleaks",
            "detect",
            "--source",
            str(target),
            "--report-format",
            "json",
            "--report-path",
            str(raw_output_path),
            "--redact",
            "--exit-code",
            "0",
            "--no-banner",
        ]
        try:
            result = subprocess.run(
                command, cwd=str(target), capture_output=True, text=True, timeout=300
            )
        except subprocess.TimeoutExpired as exc:
            raise ScannerExecutionError(
                f"Gitleaks timed out after 300 seconds while scanning the local target path."
            ) from exc
        if result.returncode != 0:
            raise ScannerExecutionError("Gitleaks failed while scanning the local target path.")

        if not raw_output_path.exists():
            raw_output_path.write_text("[]\n", encoding="utf-8")

        findings = _normalize_gitleaks_output(raw_output_path)
        return ScannerResult(
            name=self.name,
            available=True,
            raw_output_path=raw_output_path,
            findings=findings,
            detected_count=len(findings),
        )


def _scanner_unavailable_finding(*, blocks_launch: bool = False) -> Finding:
    return Finding(
        title="Gitleaks scanner unavailable",
        severity="medium",
        status="open",
        category="scanner_unavailable",
        source="gitleaks",
        description="Gitleaks is not installed or is not available on PATH, so local secret scanning was not run.",
        risk="Secrets may exist in the target repository without being detected by this local scan.",
        recommendation="Install Gitleaks and rerun `launchguardian scan --target .` before relying on scan results.",
        related_gate=GITLEAKS_RELATED_GATE,
        blocks_launch=blocks_launch,
    )


def _normalize_gitleaks_output(raw_output_path: Path) -> list[Finding]:
    try:
        raw_data = json.loads(raw_output_path.read_text(encoding="utf-8") or "[]")
    except json.JSONDecodeError as exc:
        raise ScannerExecutionError("Gitleaks produced invalid JSON output.") from exc

    leaks = raw_data if isinstance(raw_data, list) else raw_data.get("findings", [])
    if not isinstance(leaks, list):
        raise ScannerExecutionError("Gitleaks JSON output used an unsupported shape.")

    findings: list[Finding] = []
    for leak in leaks:
        if not isinstance(leak, dict):
            continue
        findings.append(_normalize_leak(leak))
    return findings


def _normalize_leak(leak: dict[str, Any]) -> Finding:
    rule_id = _safe_text(leak.get("RuleID") or leak.get("rule_id") or "secret")
    description = _safe_text(leak.get("Description") or leak.get("description") or "Potential secret")
    file_path = _safe_text(leak.get("File") or leak.get("file") or leak.get("file_path"))
    line = _safe_int(leak.get("StartLine") or leak.get("line"))
    redacted_values = _secret_values(leak)

    title = _redact(f"Gitleaks secret detected: {rule_id}", redacted_values)
    safe_description = _redact(
        f"Gitleaks detected a potential secret using rule `{rule_id}`. "
        f"Rule description: {description}. Secret values are redacted.",
        redacted_values,
    )
    safe_risk = _redact(
        "Committed secrets can allow unauthorized access to systems, data, or third-party services.",
        redacted_values,
    )
    safe_recommendation = _redact(
        "Remove the secret from the repository, rotate the credential, and verify history and deployment config.",
        redacted_values,
    )

    return Finding(
        title=title,
        severity="critical",
        status="open",
        category="secrets",
        source="gitleaks",
        file_path=_redact(file_path, redacted_values),
        line=line,
        description=safe_description,
        risk=safe_risk,
        recommendation=safe_recommendation,
        related_gate=GITLEAKS_RELATED_GATE,
        blocks_launch=True,
    )


def _secret_values(leak: dict[str, Any]) -> tuple[str, ...]:
    values = []
    for key in ("Secret", "secret", "Match", "match"):
        value = str(leak.get(key) or "")
        if value:
            values.append(value)
    return tuple(values)


def _redact(value: str, secrets: tuple[str, ...]) -> str:
    redacted = str(value)
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "[REDACTED]")
    return redacted


def _safe_text(value: Any) -> str:
    return str(value or "").strip()


def _safe_int(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None
