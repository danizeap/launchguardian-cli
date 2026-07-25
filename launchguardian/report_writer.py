from __future__ import annotations

import json
import re
from pathlib import Path

from .models import Finding, ValidationReport


DEFAULT_OUTPUT_DIR = Path("reports") / "launchguardian"
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


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
                "schema_version": "0.2.0",
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
    configured_dispositions = lg_config.get("finding_dispositions", [])
    if not isinstance(configured_dispositions, list):
        configured_dispositions = []
    config_findings = [finding for finding in report.findings if finding.source == "config"]
    disposed_findings = [
        finding for finding in report.findings if finding.disposition is not None
    ]
    blocking_findings = report.blocking_findings
    scanner_finding_count = sum(scanner_counts.values())
    lines = [
        "# LaunchGuardian Report",
        "",
        "## Launch Decision",
        "",
        f"**{report.launch_status}**",
        "",
        _decision_sentence(report, scanner_finding_count, len(blocking_findings)),
        "",
        "## Executive Summary",
        "",
        f"- Target: `{report.target}`",
        f"- Mode: `{report.mode}`",
        f"- Validation mode: `{report.validation_mode}`",
        f"- Scan mode: `{report.scan_mode}`",
        f"- Generated at: `{report.generated_at}`",
        f"- LGF validation status: **{report.lgf_validation_status}**",
        f"- Strict scanners: **{str(report.strict_scanners).lower()}**",
        f"- Total findings: **{len(report.findings)}**",
        f"- Scanner findings: **{scanner_finding_count}**",
        f"- Blocking findings: **{len(blocking_findings)}**",
        f"- Severity counts: {_inline_counts(report.counts_by_severity)}",
        f"- Finding status counts: {_inline_status_counts(report.counts_by_status)}",
        "",
        "## Scanner Summary",
        "",
        "| Scanner | Status | Findings | Blocking Findings |",
        "| --- | --- | ---: | ---: |",
    ]
    for scanner_name in sorted(scanner_availability):
        lines.append(
            "| {scanner} | {status} | {count} | {blocking} |".format(
                scanner=_escape_table(scanner_name),
                status=_escape_table(scanner_availability.get(scanner_name, "not_run")),
                count=scanner_counts.get(scanner_name, 0),
                blocking=scanner_blocking_counts.get(scanner_name, 0),
            )
        )

    lines.extend(
        [
            "",
            "## Top Blockers",
            "",
        ]
    )
    if blocking_findings:
        lines.extend(_render_finding_table(blocking_findings[:10], include_gate=True, include_location=True))
        if len(blocking_findings) > 10:
            lines.append(f"Additional blocking findings: **{len(blocking_findings) - 10}**")
    else:
        lines.append("No open blocking findings.")

    lines.extend(
        [
            "",
            "## Recommended Next Actions",
            "",
        ]
    )
    lines.extend(_recommended_actions(report))

    lines.extend(
        [
            "",
            "## Findings By Severity",
            "",
        ]
    )
    for severity in SEVERITY_ORDER:
        findings = [finding for finding in report.findings if finding.severity == severity]
        if not findings:
            continue
        lines.extend(
            [
                f"### {severity.title()} ({len(findings)})",
                "",
                *_render_finding_table(findings, include_gate=True, include_location=True),
                "",
            ]
        )
    if not report.findings:
        lines.append("No findings.")

    lines.extend(
        [
            "",
            "## Findings By Gate",
            "",
        ]
    )
    for gate, findings in _findings_by_gate(report.findings).items():
        lines.extend(
            [
                f"### {gate} ({len(findings)})",
                "",
                *_render_finding_table(findings, include_gate=False, include_location=True),
                "",
            ]
        )
    if not report.findings:
        lines.append("No findings.")

    lines.extend(
        [
            "",
            "## Configuration",
            "",
        ]
    )
    lines.extend(
        [
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
        f"- Reviewed finding dispositions configured: **{len(configured_dispositions)}**",
        f"- Findings with applied dispositions: **{len(disposed_findings)}**",
        ]
    )

    lines.extend(
        [
        "",
        "## Reviewed Finding Dispositions",
        "",
    ])
    if configured_dispositions:
        lines.extend(
            _render_disposition_table(
                configured_dispositions,
                disposed_findings,
            )
        )
    else:
        lines.append("No reviewed finding dispositions are configured.")

    lines.extend(
        [
        "",
        "## All Findings",
        "",
    ])
    if not report.findings:
        lines.append("No findings.")
    else:
        lines.extend(_render_finding_table(report.findings, include_gate=True, include_location=True))
    lines.append("")
    return "\n".join(lines)


def _escape_table(value: str) -> str:
    return str(value).replace("|", "\\|")


def _decision_sentence(report: ValidationReport, scanner_finding_count: int, blocking_count: int) -> str:
    if report.launch_status == "BLOCKED":
        return (
            f"Launch is blocked by **{blocking_count}** open blocking finding(s). "
            "Fix the issue, remove the affected feature from scope, or document an approved exceptional override before launch."
        )
    if report.launch_status == "INCOMPLETE":
        return (
            "LaunchGuardian could not produce a complete approval because required validation or scanner coverage is incomplete."
        )
    if report.launch_status == "SCANNED_WITHOUT_LGF":
        return (
            f"Scan completed with **{scanner_finding_count}** scanner finding(s), but LGF validation was skipped."
        )
    if report.launch_status == "APPROVED_WITH_DISPOSITIONS":
        disposed_count = sum(
            1 for finding in report.findings if finding.disposition is not None
        )
        return (
            f"No open blocking findings remain, and **{disposed_count}** finding(s) "
            "use exact reviewed dispositions. The recorded approver metadata is "
            "auditable project evidence, not authenticated proof of human identity."
        )
    return "No open blocking findings were found by the enabled local checks."


def _inline_counts(counts: dict[str, int]) -> str:
    return ", ".join(f"**{name}**: {counts.get(name, 0)}" for name in SEVERITY_ORDER)


def _inline_status_counts(counts: dict[str, int]) -> str:
    return ", ".join(
        f"**{name}**: {count}" for name, count in sorted(counts.items())
    ) or "**none**: 0"


def _render_finding_table(
    findings: list[Finding], *, include_gate: bool, include_location: bool
) -> list[str]:
    headers = ["Severity", "Blocks", "Status", "Source"]
    if include_gate:
        headers.append("Gate")
    if include_location:
        headers.append("Location")
    headers.extend(["Finding", "Why It Matters", "Review Or Fix"])

    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for finding in findings:
        row = [
            finding.severity,
            "yes" if finding.blocks_launch else "no",
            finding.status,
            finding.source,
        ]
        if include_gate:
            row.append(finding.related_gate or "Unmapped")
        if include_location:
            row.append(_finding_location(finding))
        row.extend([finding.title, finding.risk, finding.recommendation])
        lines.append("| " + " | ".join(_escape_table(value) for value in row) + " |")
    return lines


def _render_disposition_table(
    dispositions: list[dict], disposed_findings: list[Finding]
) -> list[str]:
    headers = [
        "Source",
        "Rule ID",
        "Status",
        "Approved",
        "Reason",
        "Evidence",
        "Applied Findings",
    ]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for disposition in dispositions:
        source = str(disposition.get("source") or "")
        rule_id = str(disposition.get("rule_id") or "")
        applied_count = sum(
            1
            for finding in disposed_findings
            if finding.source == source and finding.rule_id == rule_id
        )
        approved = " by ".join(
            part
            for part in (
                str(disposition.get("approved_on") or ""),
                str(disposition.get("approved_by") or ""),
            )
            if part
        )
        row = [
            source,
            rule_id,
            str(disposition.get("status") or ""),
            approved,
            str(disposition.get("reason") or ""),
            str(disposition.get("evidence") or ""),
            str(applied_count),
        ]
        lines.append("| " + " | ".join(_escape_table(value) for value in row) + " |")
    return lines


def _finding_location(finding: Finding) -> str:
    location = finding.file_path or finding.endpoint_or_route or finding.endpoint or ""
    if finding.line is not None and location:
        return f"{location}:{finding.line}"
    if location:
        return location
    return "n/a"


def _findings_by_gate(findings: list[Finding]) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        gate = finding.related_gate or "Unmapped"
        grouped.setdefault(gate, []).append(finding)
    return dict(sorted(grouped.items(), key=lambda item: _gate_sort_key(item[0])))


def _recommended_actions(report: ValidationReport) -> list[str]:
    actions: list[str] = []
    if report.blocking_findings:
        actions.append(
            f"Resolve or explicitly remove from launch scope the **{len(report.blocking_findings)}** open blocking finding(s)."
        )
    unavailable = [
        name
        for name, status in report.scanner_availability.items()
        if status in {"unavailable", "failed", "execution_failed"}
    ]
    if unavailable:
        actions.append(
            "Restore scanner coverage for: " + ", ".join(f"`{name}`" for name in unavailable) + "."
        )
    if report.lgf_validation_skipped:
        actions.append("Run again without `--skip-lgf-validation` before making a launch decision.")
    if report.launch_status == "INCOMPLETE":
        actions.append("Complete missing scanner or LGF coverage before treating this as approved.")
    if any(finding.disposition is not None for finding in report.findings):
        actions.append(
            "Reconfirm each reviewed finding disposition when its rule, evidence, "
            "supported-runtime boundary, or launch scope changes."
        )
    if not actions:
        actions.append("Review non-blocking findings and decide whether to fix, accept, or monitor them.")
    actions.append("Re-run `launchguardian scan --target .` after remediation and attach the updated report.")
    return [f"{index}. {action}" for index, action in enumerate(actions, start=1)]


def _gate_sort_key(gate: str) -> tuple[int, str]:
    match = re.search(r"Gate\s+(\d+)", gate)
    if match:
        return int(match.group(1)), gate
    return 999, gate
