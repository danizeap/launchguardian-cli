from __future__ import annotations

import json
import re
from pathlib import Path

from ..config import LaunchGuardianConfig, is_excluded
from ..models import Finding
from .base import ScannerResult


FRONTEND_GATE = "Gate 5 — Frontend Exposure"
SECRETS_GATE = "Gate 4 — Secrets & Config Hygiene"
AUTH_GATE = "Gate 8 — Auth, Sessions & CSRF"

IGNORED_DIRECTORIES = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}
IGNORED_PARTS = {("reports", "launchguardian")}
FRONTEND_SUFFIXES = {".html", ".js", ".jsx", ".ts", ".tsx", ".map"}
CONFIG_NAME_PATTERNS = (
    re.compile(r"^\.env.*$"),
    re.compile(r"^vite\.config\..+$"),
    re.compile(r"^next\.config\..+$"),
)
FRONTEND_ENV_PATTERN = re.compile(r"\b(?:VITE|NEXT_PUBLIC|REACT_APP)_[A-Z0-9_]+\b")
SECRET_NAME_PATTERN = re.compile(r"(SECRET|TOKEN|KEY|PASSWORD|PRIVATE|CLIENT_SECRET)", re.IGNORECASE)
LOCAL_DEBUG_PATTERN = re.compile(r"(localhost|127\.0\.0\.1|staging|debug=true)", re.IGNORECASE)
STORAGE_PATTERN = re.compile(r"\b(?:localStorage|sessionStorage)\b")
STORAGE_SENSITIVE_PATTERN = re.compile(r"(token|secret|password|jwt|apiKey)", re.IGNORECASE)
PRIVATE_FILE_PATTERN = re.compile(r"(\.env|secret|private|token|password|client_secret)", re.IGNORECASE)


class FrontendExposureScanner:
    name = "frontend_exposure"

    def __init__(self, config: LaunchGuardianConfig | None = None) -> None:
        self.config = config

    def scan(self, target: Path, report_dir: Path, *, strict_scanners: bool = False) -> ScannerResult:
        raw_dir = report_dir / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        raw_output_path = raw_dir / "frontend-exposure-results.json"

        raw_results: list[dict] = []
        findings: list[Finding] = []
        for path in _iter_frontend_files(target, self.config):
            relative_path = path.relative_to(target)
            if path.suffix.lower() == ".map":
                raw_results.append(_raw_result("source_map", relative_path, None, "source map file"))
                findings.append(_source_map_finding(relative_path))
                continue

            if _is_public_build_path(relative_path) and PRIVATE_FILE_PATTERN.search(str(relative_path)):
                raw_results.append(
                    _raw_result("public_private_filename", relative_path, None, "private-looking public filename")
                )
                findings.append(_public_private_confusion_finding(relative_path, None, "private-looking filename"))

            for line_number, line in _safe_read_lines(path):
                redacted_line = _redact_assignment(line)
                for env_name in FRONTEND_ENV_PATTERN.findall(line):
                    if SECRET_NAME_PATTERN.search(env_name):
                        raw_results.append(
                            _raw_result("frontend_secret_env_name", relative_path, line_number, redacted_line)
                        )
                        findings.append(_frontend_secret_env_finding(relative_path, line_number, env_name))
                    else:
                        raw_results.append(
                            _raw_result("frontend_public_env_name", relative_path, line_number, redacted_line)
                        )

                if LOCAL_DEBUG_PATTERN.search(line) and _is_frontend_source(path):
                    pattern = LOCAL_DEBUG_PATTERN.search(line).group(1)
                    raw_results.append(_raw_result("frontend_debug_url", relative_path, line_number, redacted_line))
                    findings.append(_debug_url_finding(relative_path, line_number, pattern))

                if STORAGE_PATTERN.search(line) and STORAGE_SENSITIVE_PATTERN.search(line):
                    raw_results.append(
                        _raw_result("sensitive_browser_storage", relative_path, line_number, redacted_line)
                    )
                    findings.append(_browser_storage_finding(relative_path, line_number))

                if _is_public_build_path(relative_path) and ".env" in line.lower():
                    raw_results.append(_raw_result("public_env_reference", relative_path, line_number, redacted_line))
                    findings.append(_public_private_confusion_finding(relative_path, line_number, ".env reference"))

        raw_output_path.write_text(
            json.dumps(
                {
                    "schema_name": "launchguardian.frontend_exposure.raw",
                    "schema_version": "0.1.0",
                    "results": raw_results,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return ScannerResult(
            name=self.name,
            available=True,
            findings=findings,
            detected_count=len(findings),
            raw_output_path=raw_output_path,
        )


def _iter_frontend_files(target: Path, config: LaunchGuardianConfig | None = None):
    for path in target.rglob("*"):
        if not path.is_file() or _is_ignored(path, target, config):
            continue
        if _is_likely_frontend_file(path, target):
            yield path


def _is_ignored(path: Path, target: Path, config: LaunchGuardianConfig | None = None) -> bool:
    relative_parts = path.relative_to(target).parts
    if any(part in IGNORED_DIRECTORIES for part in relative_parts):
        return True
    if any(_has_part_sequence(relative_parts, ignored) for ignored in IGNORED_PARTS):
        return True
    return bool(config and is_excluded(path, target, config))


def _has_part_sequence(parts: tuple[str, ...], sequence: tuple[str, ...]) -> bool:
    return any(parts[index : index + len(sequence)] == sequence for index in range(len(parts)))


def _is_likely_frontend_file(path: Path, target: Path) -> bool:
    relative_parts = path.relative_to(target).parts
    name = path.name
    if path.suffix.lower() in FRONTEND_SUFFIXES:
        return True
    if name == "package.json":
        return True
    if any(pattern.match(name) for pattern in CONFIG_NAME_PATTERNS):
        return True
    return any(part in {"public", "dist", "build", ".next", "out"} for part in relative_parts)


def _is_frontend_source(path: Path) -> bool:
    return path.suffix.lower() in {".html", ".js", ".jsx", ".ts", ".tsx", ".map"}


def _is_public_build_path(relative_path: Path) -> bool:
    return any(part in {"public", "dist", "build", ".next", "out"} for part in relative_path.parts)


def _safe_read_lines(path: Path):
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for index, line in enumerate(handle, start=1):
                yield index, line.rstrip("\n")
    except OSError:
        return


def _raw_result(pattern_label: str, relative_path: Path, line: int | None, evidence: str) -> dict:
    return {
        "pattern_label": pattern_label,
        "file_path": str(relative_path),
        "line": line,
        "evidence": evidence,
    }


def _redact_assignment(line: str) -> str:
    if "=" not in line:
        return line.strip()
    left, _right = line.split("=", 1)
    return f"{left.strip()}=[REDACTED]"


def _source_map_finding(relative_path: Path) -> Finding:
    return Finding(
        title="Frontend source map present",
        severity="medium",
        status="open",
        category="frontend_exposure",
        source="frontend_exposure",
        file_path=str(relative_path),
        description="A source map file is present in the scanned frontend files or build output.",
        risk="Source maps can expose original source structure and implementation details in shipped frontend artifacts.",
        recommendation="Confirm source maps are intended for the target environment, or exclude them from production artifacts.",
        related_gate=FRONTEND_GATE,
        blocks_launch=False,
    )


def _frontend_secret_env_finding(relative_path: Path, line: int, env_name: str) -> Finding:
    return Finding(
        title="Frontend-exposed secret-like environment variable",
        severity="critical",
        status="open",
        category="secrets",
        source="frontend_exposure",
        file_path=str(relative_path),
        line=line,
        description=(
            f"Frontend-exposed environment variable name `{env_name}` looks secret-bearing. "
            "Variable values are not included in findings."
        ),
        risk="Frontend public environment variables are bundled for browser access and must not contain secrets.",
        recommendation="Move the secret to server-side configuration and expose only non-sensitive public values to frontend code.",
        related_gate=SECRETS_GATE,
        blocks_launch=True,
    )


def _debug_url_finding(relative_path: Path, line: int, pattern: str) -> Finding:
    severity = "medium" if str(pattern).lower() in {"staging", "debug=true"} else "low"
    return Finding(
        title="Frontend debug or non-production URL reference",
        severity=severity,
        status="open",
        category="frontend_exposure",
        source="frontend_exposure",
        file_path=str(relative_path),
        line=line,
        description=f"Frontend file references `{pattern}`, which may indicate debug or non-production configuration.",
        risk="Debug, localhost, or staging references can leak implementation context or break production behavior.",
        recommendation="Confirm the reference is intentional and gated from production builds where appropriate.",
        related_gate=FRONTEND_GATE,
        blocks_launch=False,
    )


def _browser_storage_finding(relative_path: Path, line: int) -> Finding:
    return Finding(
        title="Sensitive-looking browser storage usage",
        severity="high",
        status="open",
        category="auth_session",
        source="frontend_exposure",
        file_path=str(relative_path),
        line=line,
        description="Browser storage usage references sensitive-looking token, secret, password, JWT, or API key names.",
        risk="Sensitive values in localStorage or sessionStorage can be exposed to browser-side script access.",
        recommendation="Use safer session handling patterns and avoid storing sensitive credentials in browser storage.",
        related_gate=AUTH_GATE,
        blocks_launch=True,
    )


def _public_private_confusion_finding(relative_path: Path, line: int | None, pattern: str) -> Finding:
    return Finding(
        title="Private-looking asset in public frontend output",
        severity="high",
        status="open",
        category="frontend_exposure",
        source="frontend_exposure",
        file_path=str(relative_path),
        line=line,
        description=f"Public or build output path contains a private-looking frontend exposure pattern: {pattern}.",
        risk="Files under public or build output directories can be shipped to browsers or static hosting.",
        recommendation="Remove private-looking files or references from public/build output and verify frontend packaging.",
        related_gate=FRONTEND_GATE,
        blocks_launch=True,
    )
