from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .config import (
    EXTERNAL_SCANNERS,
    SCANNER_GATES,
    LaunchGuardianConfig,
    apply_finding_dispositions,
    load_launchguardian_config,
)
from .config_discovery import (
    discover_config,
    framework_mode_findings,
    missing_file_findings,
    validate_target,
)
from .launch_policy import validate_gate_applicability
from .models import Finding, ValidationReport
from .report_writer import write_normalized_findings, write_reports
from .scanners.api_surface import ApiSurfaceScanner
from .scanners.base import ScannerExecutionError
from .scanners.frontend_exposure import FrontendExposureScanner
from .scanners.gitleaks import GitleaksScanner
from .scanners.semgrep import SemgrepScanner
from .scanners.trivy import TrivyScanner


EXIT_VALID = 0
EXIT_BLOCKED = 1
EXIT_TOOL_FAILURE = 2
EXIT_CONFIG_ERROR = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="launchguardian")
    parser.add_argument(
        "--version",
        action="version",
        version=__version__,
        help="Show LaunchGuardian version and exit.",
    )
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
    scan.add_argument(
        "--skip-lgf-validation",
        action="store_true",
        help="Skip LGF config validation and run local scanners only.",
    )
    scan.add_argument(
        "--strict-scanners",
        action="store_true",
        help="Treat missing expected scanners as blocking findings.",
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
            skip_lgf_validation=args.skip_lgf_validation,
            strict_scanners=args.strict_scanners,
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
            validation_mode="framework" if framework_mode else "project",
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
        validation_mode="framework" if framework_mode else "project",
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
    target: Path,
    output_dir: Path | None = None,
    *,
    framework_mode: bool = False,
    skip_lgf_validation: bool = False,
    strict_scanners: bool = False,
) -> int:
    target_finding = validate_target(target)
    report_target = target.resolve()
    scanner_config = load_launchguardian_config(report_target)
    report_dir = _effective_report_dir(report_target, scanner_config, output_dir)
    effective_strict_scanners = strict_scanners or scanner_config.strict_scanners
    validation_mode = _scan_validation_mode(
        framework_mode=framework_mode, skip_lgf_validation=skip_lgf_validation
    )
    if target_finding is not None:
        report = ValidationReport(
            target=report_target,
            mode=validation_mode,
            validation_mode=validation_mode,
            scan_mode="local",
            lgf_validation_skipped=skip_lgf_validation,
            strict_scanners=effective_strict_scanners,
            findings=[target_finding, *scanner_config.config_findings],
            lgf_config_valid=False,
            launchguardian_config=scanner_config.to_report_dict(report_dir),
        )
        write_reports(report, report_dir)
        write_normalized_findings(report.findings, report_dir)
        return EXIT_CONFIG_ERROR

    config = discover_config(target)
    scanner_config = load_launchguardian_config(config.target)
    report_dir = _effective_report_dir(config.target, scanner_config, output_dir)
    effective_strict_scanners = strict_scanners or scanner_config.strict_scanners
    lgf_findings = _scan_lgf_findings(
        config,
        framework_mode=framework_mode,
        skip_lgf_validation=skip_lgf_validation,
    )
    scanner_findings, scanner_availability, scanner_counts, scanner_blocking_counts, scanner_failures = (
        _run_scanners(
            config.target,
            report_dir,
            strict_scanners=effective_strict_scanners,
            scanner_config=scanner_config,
        )
    )
    scanner_findings, disposition_policy_findings = apply_finding_dispositions(
        scanner_findings, scanner_config
    )
    for scanner_name, availability in scanner_availability.items():
        if availability == "disabled":
            continue
        scanner_blocking_counts[scanner_name] = sum(
            1
            for finding in scanner_findings
            if finding.source == scanner_name
            and finding.blocks_launch
            and finding.status == "open"
        )
    findings = [
        *lgf_findings,
        *scanner_config.config_findings,
        *disposition_policy_findings,
        *scanner_findings,
    ]
    validation_findings = [
        *lgf_findings,
        *scanner_config.config_findings,
        *disposition_policy_findings,
    ]
    report = ValidationReport(
        target=config.target,
        mode=validation_mode,
        validation_mode=validation_mode,
        scan_mode="local",
        lgf_validation_skipped=skip_lgf_validation,
        strict_scanners=effective_strict_scanners,
        findings=findings,
        lgf_config_valid=not _has_blocking_open_findings(validation_findings),
        scanner_availability=scanner_availability,
        scanner_counts=scanner_counts,
        scanner_blocking_counts=scanner_blocking_counts,
        launchguardian_config=scanner_config.to_report_dict(report_dir),
    )
    markdown_path, json_path = write_reports(report, report_dir)
    normalized_path = write_normalized_findings(report.findings, report_dir)

    print(f"LaunchGuardian report written: {markdown_path}")
    print(f"LaunchGuardian JSON written: {json_path}")
    print(f"LaunchGuardian normalized findings written: {normalized_path}")
    print(f"LaunchGuardian status: {report.launch_status}")
    if scanner_failures:
        print("LaunchGuardian scanner failure: " + "; ".join(scanner_failures))
        return EXIT_TOOL_FAILURE
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


def _scan_lgf_findings(config, *, framework_mode: bool, skip_lgf_validation: bool):
    if skip_lgf_validation:
        return []
    if framework_mode:
        return []
    return _lgf_findings(config, framework_mode=False)


def _scan_validation_mode(*, framework_mode: bool, skip_lgf_validation: bool) -> str:
    if skip_lgf_validation:
        return "skipped"
    if framework_mode:
        return "framework"
    return "project"


def _run_scanners(
    target: Path,
    report_dir: Path,
    *,
    strict_scanners: bool,
    scanner_config: LaunchGuardianConfig,
):
    findings = []
    availability: dict[str, str] = {}
    counts: dict[str, int] = {}
    blocking_counts: dict[str, int] = {}
    failures: list[str] = []
    for scanner in (
        GitleaksScanner(),
        SemgrepScanner(),
        TrivyScanner(),
        FrontendExposureScanner(scanner_config),
        ApiSurfaceScanner(scanner_config),
    ):
        if not scanner_config.scanner_enabled(scanner.name):
            disabled_finding = _disabled_scanner_finding(
                scanner.name,
                strict_scanners=strict_scanners,
                scanner_config=scanner_config,
            )
            findings.append(disabled_finding)
            availability[scanner.name] = "disabled"
            counts[scanner.name] = 0
            blocking_counts[scanner.name] = 1 if disabled_finding.blocks_launch else 0
            continue

        try:
            result = scanner.scan(target, report_dir, strict_scanners=strict_scanners)
        except ScannerExecutionError as exc:
            availability[scanner.name] = "failed"
            counts[scanner.name] = 0
            blocking_counts[scanner.name] = 0
            failures.append(f"{scanner.name}: {exc}")
            continue

        findings.extend(result.findings)
        availability[result.name] = "ran" if result.available else "unavailable"
        counts[result.name] = result.detected_count
        blocking_counts[result.name] = sum(
            1
            for finding in result.findings
            if finding.blocks_launch and finding.status == "open"
        )
    return findings, availability, counts, blocking_counts, failures


def _disabled_scanner_finding(
    scanner_name: str, *, strict_scanners: bool, scanner_config: LaunchGuardianConfig
):
    is_external = scanner_name in EXTERNAL_SCANNERS
    blocks_launch = (
        strict_scanners
        and is_external
        and not scanner_config.scanner_allows_disabled_in_strict(scanner_name)
    )
    reason = scanner_config.scanner_reason(scanner_name)
    scanner_label = scanner_name.replace("_", " ").title()
    return Finding(
        title=f"{scanner_label} scanner disabled by config",
        severity="high" if blocks_launch else "info",
        status="open",
        category="scanner_disabled",
        source="config",
        description=(
            f"{scanner_name} is disabled in launchguardian.yml."
            + (f" Reason: {reason}" if reason else " No reason was provided.")
        ),
        risk="Disabled scanners reduce LaunchGuardian coverage and can leave launch risks unreviewed.",
        recommendation=(
            "Re-enable the scanner, or document a reason and explicit strict-mode allowance when the disablement is intentional."
        ),
        related_gate=SCANNER_GATES.get(scanner_name, "Gate 20 — Launch Decision"),
        blocks_launch=blocks_launch,
    )


def _effective_report_dir(
    target: Path, scanner_config: LaunchGuardianConfig, output_dir: Path | None
) -> Path:
    configured = scanner_config.output_dir
    report_dir = output_dir or configured
    if report_dir.is_absolute():
        return report_dir
    return target / report_dir


def _has_blocking_open_findings(findings) -> bool:
    return any(finding.blocks_launch and finding.status == "open" for finding in findings)


if __name__ == "__main__":
    sys.exit(main())
