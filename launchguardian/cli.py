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
from .report_writer import write_reports


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

    parser.error(f"Unsupported command: {args.command}")
    return EXIT_CONFIG_ERROR


def validate_lgf(
    target: Path, output_dir: Path | None = None, *, framework_mode: bool = False
) -> int:
    target_finding = validate_target(target)
    if target_finding is not None:
        report = ValidationReport(
            target=target.resolve(), mode="framework" if framework_mode else "project", findings=[target_finding]
        )
        write_reports(report, output_dir)
        return EXIT_CONFIG_ERROR

    config = discover_config(target)
    findings = []
    if framework_mode:
        findings.extend(framework_mode_findings(config))
    else:
        findings.extend(missing_file_findings(config))
        findings.extend(validate_gate_applicability(config.gate_applicability))

    report = ValidationReport(target=config.target, mode="framework" if framework_mode else "project", findings=findings)
    markdown_path, json_path = write_reports(report, output_dir)

    print(f"LaunchGuardian report written: {markdown_path}")
    print(f"LaunchGuardian JSON written: {json_path}")
    if report.blocked:
        print("LaunchGuardian status: BLOCKED")
        return EXIT_BLOCKED
    print("LaunchGuardian status: VALID")
    return EXIT_VALID


if __name__ == "__main__":
    sys.exit(main())
