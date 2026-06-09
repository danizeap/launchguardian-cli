from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from ..models import Finding
from .base import ScannerExecutionError, ScannerResult


SEMGREP_CODE_GATE = "Gate 3 — Code Security"
SEMGREP_INJECTION_GATE = "Gate 7 — Injection & Input Safety"
SEMGREP_AUTH_GATE = "Gate 8 — Auth, Sessions & CSRF"


class SemgrepScanner:
    name = "semgrep"

    def is_available(self) -> bool:
        return shutil.which("semgrep") is not None

    def scan(self, target: Path, report_dir: Path, *, strict_scanners: bool = False) -> ScannerResult:
        raw_dir = report_dir / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        raw_output_path = raw_dir / "semgrep-results.json"

        if not self.is_available():
            return ScannerResult(
                name=self.name,
                available=False,
                raw_output_path=raw_output_path,
                findings=[_scanner_unavailable_finding(blocks_launch=strict_scanners)],
            )

        command = [
            "semgrep",
            "scan",
            "--config",
            "auto",
            "--json",
            "--output",
            str(raw_output_path),
            str(target),
        ]
        result = subprocess.run(command, cwd=str(target), capture_output=True, text=True)
        if result.returncode not in {0, 1}:
            raise ScannerExecutionError("Semgrep failed while scanning the local target path.")

        if not raw_output_path.exists():
            raw_output_path.write_text('{"results": []}\n', encoding="utf-8")

        findings = _normalize_semgrep_output(raw_output_path)
        return ScannerResult(
            name=self.name,
            available=True,
            raw_output_path=raw_output_path,
            findings=findings,
            detected_count=len(findings),
        )


def _scanner_unavailable_finding(*, blocks_launch: bool = False) -> Finding:
    return Finding(
        title="Semgrep scanner unavailable",
        severity="medium",
        status="open",
        category="scanner_unavailable",
        source="semgrep",
        description="Semgrep is not installed or is not available on PATH, so local static code scanning was not run.",
        risk="Code security issues may exist in the target repository without being detected by this local scan.",
        recommendation="Install Semgrep and rerun `launchguardian scan --target .` before relying on scan results.",
        related_gate=SEMGREP_CODE_GATE,
        blocks_launch=blocks_launch,
    )


def _normalize_semgrep_output(raw_output_path: Path) -> list[Finding]:
    try:
        raw_data = json.loads(raw_output_path.read_text(encoding="utf-8") or "{}")
    except json.JSONDecodeError as exc:
        raise ScannerExecutionError("Semgrep produced invalid JSON output.") from exc

    results = raw_data.get("results", []) if isinstance(raw_data, dict) else []
    if not isinstance(results, list):
        raise ScannerExecutionError("Semgrep JSON output used an unsupported shape.")

    findings: list[Finding] = []
    for result in results:
        if isinstance(result, dict):
            findings.append(_normalize_result(result))
    return findings


def _normalize_result(result: dict[str, Any]) -> Finding:
    extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
    metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
    severity = _map_severity(extra.get("severity") or metadata.get("severity"))
    rule_id = _safe_text(result.get("check_id") or result.get("rule_id") or "semgrep finding")
    message = _safe_text(extra.get("message") or metadata.get("message") or rule_id)
    file_path = _safe_text(result.get("path"))
    line = _safe_int(_nested_get(result, "start", "line"))
    related_gate = _related_gate(rule_id=rule_id, message=message, metadata=metadata)

    return Finding(
        title=f"Semgrep finding: {rule_id}",
        severity=severity,
        status="open",
        category="code_security",
        source="semgrep",
        file_path=file_path,
        line=line,
        description=message or "Semgrep detected a static analysis security finding.",
        risk="Static analysis identified code that may introduce a security weakness.",
        recommendation=_safe_text(
            metadata.get("fix")
            or metadata.get("recommendation")
            or "Review the Semgrep finding, confirm exploitability, and remediate or document an accepted risk."
        ),
        related_gate=related_gate,
        blocks_launch=severity == "high",
    )


def _map_severity(value: Any) -> str:
    normalized = str(value or "").strip().upper()
    if normalized in {"ERROR", "HIGH", "CRITICAL"}:
        return "high"
    if normalized in {"WARNING", "MEDIUM"}:
        return "medium"
    if normalized in {"INFO", "LOW"}:
        return "low"
    return "medium"


def _related_gate(*, rule_id: str, message: str, metadata: dict[str, Any]) -> str:
    haystack = " ".join(
        [
            rule_id,
            message,
            _flatten_metadata(metadata),
        ]
    ).lower()
    if any(term in haystack for term in ("injection", "sql injection", "xss", "command injection")):
        return SEMGREP_INJECTION_GATE
    if any(term in haystack for term in ("auth", "csrf", "session", "cookie")):
        return SEMGREP_AUTH_GATE
    return SEMGREP_CODE_GATE


def _flatten_metadata(metadata: dict[str, Any]) -> str:
    parts: list[str] = []
    for value in metadata.values():
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, list):
            parts.extend(str(item) for item in value)
        elif isinstance(value, dict):
            parts.append(_flatten_metadata(value))
    return " ".join(parts)


def _nested_get(data: dict[str, Any], *keys: str) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _safe_text(value: Any) -> str:
    return str(value or "").strip()


def _safe_int(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None
