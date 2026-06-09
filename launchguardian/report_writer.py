from __future__ import annotations

import json
from pathlib import Path

from .models import Finding, ValidationReport


DEFAULT_OUTPUT_DIR = Path("reports") / "launchguardian"


def write_reports(report: ValidationReport, output_dir: Path | None = None) -> tuple[Path, Path]:
    report_dir = output_dir or report.target / DEFAULT_OUTPUT_DIR
    report_dir.mkdir(parents=True, exist_ok=True)

    markdown_path = report_dir / "launchguardian-report.md"
    json_path = report_dir / "launchguardian-report.json"

    markdown_path.write_text(_render_markdown(report), encoding="utf-8")
    json_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    return markdown_path, json_path


def write_normalized_findings(findings: list[Finding], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    normalized_path = output_dir / "normalized-findings.json"
    normalized_path.write_text(
        json.dumps(
            {
                "schema_name": "launchguardian.normalized_findings",
                "schema_version": "0.1.0",
                "findings": [finding.to_dict() for finding in findings],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return normalized_path


def _render_markdown(report: ValidationReport) -> str:
    scanner_availability = report.scanner_availability or {"none": "not_run"}
    scanner_counts = report.scanner_counts or {}
    scanner_blocking_counts = report.scanner_blocking_counts or {}
    lg_config = report.launchguardian_config or {}
    exclude_config = lg_config.get("exclude", {}) if isinstance(lg_config.get("exclude"), dict) else {}
    disabled_scanners = lg_config.get("disabled_scanners", {})
    severity_policy = lg_config.get("severity_policy", {})
    config_findings = [finding for finding in report.findings if finding.source == "config"]
    gitleaks_count = scanner_counts.get("gitleaks", 0)
    semgrep_count = scanner_counts.get("semgrep", 0)
    trivy_count = scanner_counts.get("trivy", 0)
    frontend_exposure_count = scanner_counts.get("frontend_exposure", 0)
    api_surface_count = scanner_counts.get("api_surface", 0)
    gitleaks_blocking_count = scanner_blocking_counts.get("gitleaks", 0)
    semgrep_blocking_count = scanner_blocking_counts.get("semgrep", 0)
    trivy_blocking_count = scanner_blocking_counts.get("trivy", 0)
    frontend_exposure_blocking_count = scanner_blocking_counts.get("frontend_exposure", 0)
    api_surface_blocking_count = scanner_blocking_counts.get("api_surface", 0)
    blocking_findings = [
        finding for finding in report.findings if finding.blocks_launch and finding.status == "open"
    ]
    scanner_finding_count = sum(scanner_counts.values())
    lines = [
        "# LaunchGuardian Report",
        "",
        f"- Target: `{report.target}`",
        f"- Mode: `{report.mode}`",
        f"- Validation mode: `{report.validation_mode}`",
        f"- Scan mode: `{report.scan_mode}`",
        f"- Generated at: `{report.generated_at}`",
        f"- Launch status: **{report.launch_status}**",
        f"- LGF validation status: **{report.lgf_validation_status}**",
        f"- Strict scanners: **{str(report.strict_scanners).lower()}**",
        f"- Config file found: **{str(bool(lg_config.get('found'))).lower()}**",
        f"- Config file: `{lg_config.get('path', '') or 'not found'}`",
        f"- Configured output dir: `{lg_config.get('configured_output_dir', '') or 'reports/launchguardian'}`",
        f"- Effective output dir: `{lg_config.get('effective_output_dir', '') or 'reports/launchguardian'}`",
        "- Disabled scanners: "
        + (
            ", ".join(f"`{name}: {reason}`" for name, reason in disabled_scanners.items())
            if disabled_scanners
            else "`none`"
        ),
        "- Active exclusions: "
        + "`paths="
        + ", ".join(exclude_config.get("paths", []))
        + "; globs="
        + ", ".join(exclude_config.get("globs", []))
        + "`",
        "- Severity policy: "
        + (
            ", ".join(f"`{name}: {str(value).lower()}`" for name, value in severity_policy.items())
            if severity_policy
            else "`default`"
        ),
        f"- Config warnings/blockers: **{len(config_findings)}**",
        "- Scanner availability: "
        + ", ".join(f"`{name}: {status}`" for name, status in scanner_availability.items()),
        f"- Gitleaks findings: **{gitleaks_count}**",
        f"- Gitleaks blocking findings: **{gitleaks_blocking_count}**",
        f"- Semgrep findings: **{semgrep_count}**",
        f"- Semgrep blocking findings: **{semgrep_blocking_count}**",
        f"- Trivy findings: **{trivy_count}**",
        f"- Trivy blocking findings: **{trivy_blocking_count}**",
        f"- Frontend Exposure findings: **{frontend_exposure_count}**",
        f"- Frontend Exposure blocking findings: **{frontend_exposure_blocking_count}**",
        f"- API Surface findings: **{api_surface_count}**",
        f"- API Surface blocking findings: **{api_surface_blocking_count}**",
        f"- Total normalized scanner findings: **{scanner_finding_count}**",
        f"- Blocking findings: **{len(blocking_findings)}**",
        "",
        "## Findings",
        "",
    ]
    if not report.findings:
        lines.append("No findings.")
    else:
        lines.extend(
            [
                "| Severity | Blocks Launch | Related Gate | Title | Recommendation |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for finding in report.findings:
            lines.append(
                "| {severity} | {blocks} | {gate} | {title} | {recommendation} |".format(
                    severity=finding.severity,
                    blocks="yes" if finding.blocks_launch else "no",
                    gate=_escape_table(finding.related_gate),
                    title=_escape_table(finding.title),
                    recommendation=_escape_table(finding.recommendation),
                )
            )
    lines.append("")
    return "\n".join(lines)


def _escape_table(value: str) -> str:
    return str(value).replace("|", "\\|")
