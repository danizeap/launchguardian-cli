from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field, replace
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from .models import Finding, FindingDisposition


CONFIG_FILE_NAME = "launchguardian.yml"
DEFAULT_OUTPUT_DIR = Path("reports") / "launchguardian"
DEFAULT_SCANNERS = {
    "gitleaks": True,
    "semgrep": True,
    "trivy": True,
    "frontend_exposure": True,
    "api_surface": True,
}
DEFAULT_SEVERITY_POLICY = {
    "critical_blocks": True,
    "high_blocks": True,
    "medium_blocks": False,
    "low_blocks": False,
}
EXTERNAL_SCANNERS = {"gitleaks", "semgrep", "trivy"}
SCANNER_GATES = {
    "gitleaks": "Gate 4 — Secrets & Config Hygiene",
    "semgrep": "Gate 3 — Code Security",
    "trivy": "Gate 10 — Dependency, SBOM & Supply Chain",
    "frontend_exposure": "Gate 5 — Frontend Exposure",
    "api_surface": "Gate 6 — API Auth & Object Authorization",
}


@dataclass(frozen=True)
class ScannerConfig:
    enabled: bool = True
    reason: str = ""
    allow_disabled_in_strict: bool = False


@dataclass(frozen=True)
class LaunchGuardianConfig:
    target: Path
    path: Path | None = None
    output_dir: Path = DEFAULT_OUTPUT_DIR
    include_tests: bool = True
    strict_scanners: bool = False
    exclude_paths: tuple[str, ...] = ("node_modules", ".git", "reports/launchguardian")
    exclude_globs: tuple[str, ...] = ("**/*.min.js", "**/fixtures/**")
    scanners: dict[str, ScannerConfig] = field(default_factory=dict)
    severity_policy: dict[str, bool] = field(default_factory=lambda: dict(DEFAULT_SEVERITY_POLICY))
    finding_dispositions: tuple[FindingDisposition, ...] = ()
    config_findings: tuple[Finding, ...] = ()

    @property
    def found(self) -> bool:
        return self.path is not None

    def scanner_enabled(self, name: str) -> bool:
        return self.scanners.get(name, ScannerConfig()).enabled

    def scanner_reason(self, name: str) -> str:
        return self.scanners.get(name, ScannerConfig()).reason

    def scanner_allows_disabled_in_strict(self, name: str) -> bool:
        scanner = self.scanners.get(name, ScannerConfig())
        return scanner.allow_disabled_in_strict and bool(scanner.reason.strip())

    def disabled_scanners(self) -> dict[str, str]:
        disabled = {}
        for name, scanner in self.scanners.items():
            if not scanner.enabled:
                disabled[name] = scanner.reason or "No reason provided."
        return disabled

    def to_report_dict(self, effective_output_dir: Path | None = None) -> dict[str, Any]:
        return {
            "found": self.found,
            "path": str(self.path) if self.path else "",
            "configured_output_dir": str(self.output_dir),
            "effective_output_dir": str(effective_output_dir) if effective_output_dir else "",
            "include_tests": self.include_tests,
            "strict_scanners": self.strict_scanners,
            "disabled_scanners": self.disabled_scanners(),
            "exclude": {
                "paths": list(self.exclude_paths),
                "globs": list(self.exclude_globs),
            },
            "severity_policy": self.severity_policy,
            "finding_dispositions": [
                disposition.to_dict() for disposition in self.finding_dispositions
            ],
        }


def load_launchguardian_config(target: Path) -> LaunchGuardianConfig:
    resolved_target = target.resolve()
    config_path = resolved_target / CONFIG_FILE_NAME
    if not config_path.is_file():
        return _default_config(resolved_target)

    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        finding = Finding(
            title="LaunchGuardian config YAML is invalid",
            severity="high",
            status="open",
            category="config_policy",
            source="config",
            file_path=str(config_path),
            description=f"Could not parse launchguardian.yml: {exc}",
            risk="Invalid scanner configuration prevents reliable local scan behavior.",
            recommendation="Fix YAML syntax in launchguardian.yml and rerun LaunchGuardian.",
            related_gate="Gate 20 — Launch Decision",
            blocks_launch=True,
        )
        return _default_config(resolved_target, path=config_path, findings=(finding,))

    if not isinstance(raw, dict):
        raw = {}

    finding_dispositions, disposition_findings = _finding_dispositions(
        raw.get("finding_dispositions"), config_path
    )
    config = LaunchGuardianConfig(
        target=resolved_target,
        path=config_path,
        output_dir=_path_value(_nested_dict(raw, "scan").get("output_dir"), DEFAULT_OUTPUT_DIR),
        include_tests=_bool_value(_nested_dict(raw, "scan").get("include_tests"), True),
        strict_scanners=_bool_value(_nested_dict(raw, "scan").get("strict_scanners"), False),
        exclude_paths=_string_tuple(_nested_dict(raw, "exclude").get("paths"), ("node_modules", ".git", "reports/launchguardian")),
        exclude_globs=_string_tuple(_nested_dict(raw, "exclude").get("globs"), ("**/*.min.js", "**/fixtures/**")),
        scanners=_scanner_configs(_nested_dict(raw, "scanners")),
        severity_policy=_severity_policy(_nested_dict(raw, "severity_policy")),
        finding_dispositions=finding_dispositions,
    )
    return LaunchGuardianConfig(
        target=config.target,
        path=config.path,
        output_dir=config.output_dir,
        include_tests=config.include_tests,
        strict_scanners=config.strict_scanners,
        exclude_paths=config.exclude_paths,
        exclude_globs=config.exclude_globs,
        scanners=config.scanners,
        severity_policy=config.severity_policy,
        finding_dispositions=config.finding_dispositions,
        config_findings=tuple(
            [*_config_policy_findings(config), *disposition_findings]
        ),
    )


def apply_finding_dispositions(
    findings: list[Finding], config: LaunchGuardianConfig
) -> tuple[list[Finding], list[Finding]]:
    configured = {
        (disposition.source, disposition.rule_id): disposition
        for disposition in config.finding_dispositions
    }
    matched: set[tuple[str, str]] = set()
    resolved: list[Finding] = []
    policy_findings: list[Finding] = []

    for finding in findings:
        key = (finding.source, finding.rule_id)
        disposition = configured.get(key)
        if disposition is None:
            resolved.append(finding)
            continue

        matched.add(key)
        if finding.severity == "critical":
            resolved.append(finding)
            policy_findings.append(
                _disposition_policy_finding(
                    title="Critical finding disposition was refused",
                    severity="high",
                    status="open",
                    config_path=config.path,
                    description=(
                        f"The configured disposition for {finding.source}:{finding.rule_id} "
                        "matched a Critical finding and was not applied."
                    ),
                    risk=(
                        "Critical findings are canonical launch blockers and cannot be "
                        "downgraded by launchguardian.yml."
                    ),
                    recommendation=(
                        "Remediate the Critical finding or remove the affected feature "
                        "from launch scope."
                    ),
                    blocks_launch=True,
                )
            )
            continue

        resolved.append(
            replace(
                finding,
                status=disposition.status,
                disposition=disposition,
            )
        )

    for key, disposition in configured.items():
        if key in matched:
            continue
        policy_findings.append(
            _disposition_policy_finding(
                title="Configured finding disposition was not used",
                severity="info",
                status="needs_review",
                config_path=config.path,
                description=(
                    f"No current finding matched the exact disposition key "
                    f"{disposition.source}:{disposition.rule_id}."
                ),
                risk=(
                    "An unused disposition may be stale, but it cannot hide a renamed "
                    "or different finding because matching is exact."
                ),
                recommendation=(
                    "Confirm the rule is intentionally absent and remove stale "
                    "dispositions when they are no longer needed."
                ),
                blocks_launch=False,
            )
        )

    return resolved, policy_findings


def is_excluded(path: Path, target: Path, config: LaunchGuardianConfig) -> bool:
    relative = _relative_posix(path, target)
    for excluded_path in config.exclude_paths:
        normalized = _normalize_pattern(excluded_path)
        if not normalized:
            continue
        if relative == normalized or relative.startswith(f"{normalized}/"):
            return True
    for glob in config.exclude_globs:
        normalized = _normalize_pattern(glob)
        if normalized and fnmatch.fnmatch(relative, normalized):
            return True
    if not config.include_tests and _is_test_path(relative):
        return True
    return False


def _default_config(
    target: Path, *, path: Path | None = None, findings: tuple[Finding, ...] = ()
) -> LaunchGuardianConfig:
    return LaunchGuardianConfig(
        target=target,
        path=path,
        scanners={name: ScannerConfig(enabled=enabled) for name, enabled in DEFAULT_SCANNERS.items()},
        config_findings=findings,
    )


def _scanner_configs(data: dict[str, Any]) -> dict[str, ScannerConfig]:
    configs = {name: ScannerConfig(enabled=enabled) for name, enabled in DEFAULT_SCANNERS.items()}
    for name in DEFAULT_SCANNERS:
        item = data.get(name)
        if isinstance(item, dict):
            configs[name] = ScannerConfig(
                enabled=_bool_value(item.get("enabled"), DEFAULT_SCANNERS[name]),
                reason=str(item.get("reason") or item.get("disabled_reason") or "").strip(),
                allow_disabled_in_strict=_bool_value(item.get("allow_disabled_in_strict"), False),
            )
        elif item is not None:
            configs[name] = ScannerConfig(enabled=_bool_value(item, DEFAULT_SCANNERS[name]))
    return configs


def _finding_dispositions(
    value: Any, config_path: Path
) -> tuple[tuple[FindingDisposition, ...], list[Finding]]:
    if value is None:
        return (), []
    if not isinstance(value, list):
        return (), [
            _invalid_disposition_finding(
                config_path,
                "finding_dispositions must be a YAML list of exact reviewed rule entries.",
            )
        ]

    dispositions: list[FindingDisposition] = []
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for index, item in enumerate(value, start=1):
        if not isinstance(item, dict):
            findings.append(
                _invalid_disposition_finding(
                    config_path,
                    f"finding_dispositions entry {index} must be a mapping.",
                )
            )
            continue

        source = str(item.get("source") or "").strip().lower()
        rule_id = str(item.get("rule_id") or "").strip()
        status = str(item.get("status") or "").strip().lower()
        reason = str(item.get("reason") or "").strip()
        evidence = str(item.get("evidence") or "").strip()
        approved_by = str(item.get("approved_by") or "").strip()
        approved_on = str(item.get("approved_on") or "").strip()
        errors: list[str] = []

        if source != "semgrep":
            errors.append("source must be exactly 'semgrep'")
        if not rule_id:
            errors.append("rule_id is required")
        elif any(character in rule_id for character in "*?[]"):
            errors.append("rule_id must be exact; wildcard characters are forbidden")
        if status != "not_applicable":
            errors.append("status must be exactly 'not_applicable'")
        if not _meaningful_review_text(reason):
            errors.append("reason must be non-empty and non-placeholder")
        if not _meaningful_review_text(evidence):
            errors.append("evidence must be non-empty and non-placeholder")
        if not _meaningful_review_text(approved_by):
            errors.append("approved_by must identify a reviewer")
        if not _valid_approval_date(approved_on):
            errors.append(
                "approved_on must be a valid, non-future ISO date (YYYY-MM-DD)"
            )

        key = (source, rule_id)
        if source and rule_id:
            if key in seen:
                errors.append("duplicate source and rule_id")
            seen.add(key)

        if errors:
            findings.append(
                _invalid_disposition_finding(
                    config_path,
                    f"finding_dispositions entry {index} is invalid: "
                    + "; ".join(errors)
                    + ".",
                )
            )
            continue

        dispositions.append(
            FindingDisposition(
                source=source,
                rule_id=rule_id,
                status="not_applicable",
                reason=reason,
                evidence=evidence,
                approved_by=approved_by,
                approved_on=approved_on,
            )
        )
    return tuple(dispositions), findings


def _severity_policy(data: dict[str, Any]) -> dict[str, bool]:
    policy = dict(DEFAULT_SEVERITY_POLICY)
    for key, default in DEFAULT_SEVERITY_POLICY.items():
        policy[key] = _bool_value(data.get(key), default)
    return policy


def _config_policy_findings(config: LaunchGuardianConfig) -> list[Finding]:
    findings: list[Finding] = []
    if not config.severity_policy.get("critical_blocks", True):
        findings.append(
            Finding(
                title="Critical findings cannot be configured as non-blocking",
                severity="high",
                status="open",
                category="config_policy",
                source="config",
                file_path=str(config.path or ""),
                description="launchguardian.yml sets severity_policy.critical_blocks: false.",
                risk="Critical findings are canonical LaunchGuardian launch blockers and cannot be silently downgraded by local configuration.",
                recommendation="Set severity_policy.critical_blocks: true. Exceptional overrides require explicit owner approval and documented compensating controls outside normal config.",
                related_gate="Gate 20 — Launch Decision",
                blocks_launch=True,
            )
        )
    return findings


def _invalid_disposition_finding(config_path: Path, description: str) -> Finding:
    return _disposition_policy_finding(
        title="Finding disposition configuration is invalid",
        severity="high",
        status="open",
        config_path=config_path,
        description=description,
        risk=(
            "Malformed or broad disposition configuration could make scanner review "
            "ambiguous, so it is rejected without changing any finding."
        ),
        recommendation=(
            "Use an exact Semgrep rule ID and provide status, reason, evidence, "
            "approved_by, and approved_on."
        ),
        blocks_launch=True,
    )


def _disposition_policy_finding(
    *,
    title: str,
    severity: str,
    status: str,
    config_path: Path | None,
    description: str,
    risk: str,
    recommendation: str,
    blocks_launch: bool,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        status=status,
        category="config_policy",
        source="config",
        file_path=str(config_path or ""),
        description=description,
        risk=risk,
        recommendation=recommendation,
        related_gate="Gate 20 — Launch Decision",
        blocks_launch=blocks_launch,
    )


def _meaningful_review_text(value: str) -> bool:
    normalized = value.strip().lower()
    return bool(normalized) and normalized not in {
        "-",
        "?",
        "n/a",
        "na",
        "none",
        "not applicable",
        "tbd",
        "todo",
        "unknown",
    }


def _valid_approval_date(value: str) -> bool:
    try:
        parsed = date.fromisoformat(value)
    except (TypeError, ValueError):
        return False
    return parsed.isoformat() == value and parsed <= date.today()


def _nested_dict(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    return value if isinstance(value, dict) else {}


def _path_value(value: Any, default: Path) -> Path:
    if value is None or str(value).strip() == "":
        return default
    return Path(str(value).strip())


def _string_tuple(value: Any, default: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(value, list):
        return default
    return tuple(str(item).strip() for item in value if str(item).strip())


def _bool_value(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "1", "on"}:
            return True
        if normalized in {"false", "no", "0", "off"}:
            return False
    if value is None:
        return default
    return bool(value)


def _relative_posix(path: Path, target: Path) -> str:
    try:
        relative = path.relative_to(target)
    except ValueError:
        relative = path
    return relative.as_posix().lstrip("./")


def _normalize_pattern(value: str) -> str:
    return str(value).replace("\\", "/").strip().strip("/")


def _is_test_path(relative: str) -> bool:
    parts = relative.split("/")
    name = parts[-1] if parts else relative
    return (
        any(part in {"test", "tests", "__tests__"} for part in parts)
        or ".test." in name
        or ".spec." in name
    )
