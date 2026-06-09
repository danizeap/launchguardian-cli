from __future__ import annotations

import json
from pathlib import Path

from .models import ValidationReport


DEFAULT_OUTPUT_DIR = Path("reports") / "launchguardian"


def write_reports(report: ValidationReport, output_dir: Path | None = None) -> tuple[Path, Path]:
    report_dir = output_dir or report.target / DEFAULT_OUTPUT_DIR
    report_dir.mkdir(parents=True, exist_ok=True)

    markdown_path = report_dir / "launchguardian-report.md"
    json_path = report_dir / "launchguardian-report.json"

    markdown_path.write_text(_render_markdown(report), encoding="utf-8")
    json_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    return markdown_path, json_path


def _render_markdown(report: ValidationReport) -> str:
    status = "BLOCKED" if report.blocked else "VALID"
    lines = [
        "# LaunchGuardian Report",
        "",
        f"- Target: `{report.target}`",
        f"- Generated at: `{report.generated_at}`",
        f"- Status: **{status}**",
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
