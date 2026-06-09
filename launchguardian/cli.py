from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config_discovery import (
    discover_config,
    framework_mode_findings,
    missing_file_findings,
    validate_target,
)
from .launch_policy import validate_gate_applicability
from .models import ValidationReport
from .report_writer import DEFAULT_OUTPUT_DIR, write_normalized_findings, write_reports
from .scanners.base import ScannerExecutionError
from .scanners.gitleaks import GitleaksScanner


EXIT_VALID = 0
EXIT_BLOCKED = 1
EXIT_TOOL_FAILURE = 2
EXIT_CONFIG_ERROR = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="launchguardian")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate-lgf", help="Validate LGF project files.")
    validate.add_argument("--target", default=".", help="Project path to validate.")
    validate.add_argument(
        "--output-dir",
        default=None,
        help="Report output directory. Defaults to <target>/reports/launchguardian.",
    )
    validate.add_argument(
        "--framework-mode",
        action="store_true",
        help="Validate LaunchGuardian framework/templates instead of project-specific LGF records.",
    )

    scan = subparsers.add_parser("scan", help="Run LGF validation and local security scanners.")
    scan.add_argument("--target", default=".", help="Local project path to scan.")
    scan.add_argument(
        "--output-dir",
        default=None,
        help="Report output directory. Defaults to <target>/reports/launchguardian.",
    )
    scan.add_argument(
        "--framework-mode",
        action="store_true",
        help="Validate LaunchGuardian framework/templates and run local scanner availability checks.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "validate-lgf":
        return validate_lgf(
            Path(args.target),
            Path(args.output_dir) if args.output_dir else None,
            framework_mode=args.framework_mode,
        )
    if args.command == "scan":
        return scan_target(
            Path(args.target),
            Path(args.output_dir) if args.output_dir else None,
            framework_mode=args.framework_mode,
        )

    parser.error(f"Unsupported command: {args.command}")
    return EXIT_CONFIG_ERROR


def validate_lgf(
    target: Path, output_dir: Path | None = None, *, framework_mode: bool = False
) -> int:
    target_finding = validate_target(target)
    if target_finding is not None:
        report = ValidationReport(
            target=target.resolve(),
            mode="framework" if framework_mode else "project",
            findings=[target_finding],
            lgf_config_valid=False,
        )
        write_reports(report, output_dir)
        return EXIT_CONFIG_ERROR

    config = discover_config(target)
    findings = _lgf_findings(config, framework_mode=framework_mode)

    report = ValidationReport(
        target=config.target,
        mode="framework" if framework_mode else "project",
        findings=findings,
        lgf_config_valid=not _has_blocking_open_findings(findings),
    )
    markdown_path, json_path = write_reports(report, output_dir)

    print(f"LaunchGuardian report written: {markdown_path}")
    print(f"LaunchGuardian JSON written: {json_path}")
    if report.blocked:
        print("LaunchGuardian status: BLOCKED")
        return EXIT_BLOCKED
    print("LaunchGuardian status: VALID")
    return EXIT_VALID


def scan_target(
    target: Path, output_dir: Path | None = None, *, framework_mode: bool = False
) -> int:
    target_finding = validate_target(target)
    report_target = target.resolve()
    report_dir = output_dir or report_target / DEFAULT_OUTPUT_DIR
    if target_finding is not None:
        report = ValidationReport(
            target=report_target,
            mode="framework" if framework_mode else "project",
            findings=[target_finding],
            lgf_config_valid=False,
        )
        write_reports(report, output_dir)
        write_normalized_findings(report.findings, report_dir)
        return EXIT_CONFIG_ERROR

    config = discover_config(target)
    lgf_findings = _lgf_findings(config, framework_mode=framework_mode)
    scanner = GitleaksScanner()
    try:
        scanner_result = scanner.scan(config.target, report_dir)
    except ScannerExecutionError as exc:
        failure_report = ValidationReport(
            target=config.target,
            mode="framework" if framework_mode else "project",
            findings=lgf_findings,
            lgf_config_valid=not _has_blocking_open_findings(lgf_findings),
            scanner_availability={"gitleaks": "execution_failed"},
            scanner_counts={"gitleaks": 0},
        )
        markdown_path, json_path = write_reports(failure_report, output_dir)
        write_normalized_findings(failure_report.findings, report_dir)
        print(f"LaunchGuardian report written: {markdown_path}")
        print(f"LaunchGuardian JSON written: {json_path}")
        print(f"LaunchGuardian scanner failure: {exc}")
        return EXIT_TOOL_FAILURE

    findings = [*lgf_findings, *scanner_result.findings]
    report = ValidationReport(
        target=config.target,
        mode="framework" if framework_mode else "project",
        findings=findings,
        lgf_config_valid=not _has_blocking_open_findings(lgf_findings),
        scanner_availability={
            "gitleaks": "available" if scanner_result.available else "unavailable"
        },
        scanner_counts={"gitleaks": scanner_result.detected_count},
    )
    markdown_path, json_path = write_reports(report, output_dir)
    normalized_path = write_normalized_findings(report.findings, report_dir)

    print(f"LaunchGuardian report written: {markdown_path}")
    print(f"LaunchGuardian JSON written: {json_path}")
    print(f"LaunchGuardian normalized findings written: {normalized_path}")
    print(f"LaunchGuardian status: {report.launch_status}")
    if report.blocked:
        return EXIT_BLOCKED
    return EXIT_VALID


def _lgf_findings(config, *, framework_mode: bool):
    findings = []
    if framework_mode:
        findings.extend(framework_mode_findings(config))
    else:
        findings.extend(missing_file_findings(config))
        findings.extend(validate_gate_applicability(config.gate_applicability))
    return findings


def _has_blocking_open_findings(findings) -> bool:
    return any(finding.blocks_launch and finding.status == "open" for finding in findings)


if __name__ == "__main__":
    sys.exit(main())
