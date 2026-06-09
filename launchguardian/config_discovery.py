from __future__ import annotations

from pathlib import Path

from .models import DiscoveredConfig, Finding


SECURITY_DIR = Path("sdd-plus") / "security"
FRAMEWORK_FILES = (
    Path("sdd-plus") / "specs" / "launchguardian-framework.md",
    Path("sdd-plus") / "specs" / "lgf-gate-applicability-system.md",
    Path("sdd-plus") / "specs" / "lgf-project-onboarding.md",
    Path("sdd-plus") / "specs" / "launchguardian-cli-product-spec.md",
    Path("sdd-plus") / "standards" / "security-shipping-standards.md",
    SECURITY_DIR / "gate-applicability.template.yml",
    SECURITY_DIR / "gate-applicability.output.template.yml",
    SECURITY_DIR / "project-security-readiness.template.md",
    SECURITY_DIR / "launch-decision.template.md",
)


def discover_config(target: Path) -> DiscoveredConfig:
    resolved_target = target.resolve()
    security_dir = resolved_target / SECURITY_DIR

    gate_applicability = _existing_file(security_dir / "gate-applicability.yml")
    scope_contract = _existing_file(security_dir / "scope-contract.yml")
    launch_decision = _first_existing(
        security_dir / "launch-decision.md",
        security_dir / "launch-decision.yml",
    )

    missing: list[str] = []
    if gate_applicability is None:
        missing.append(str(SECURITY_DIR / "gate-applicability.yml"))
    if scope_contract is None:
        missing.append(str(SECURITY_DIR / "scope-contract.yml"))
    if launch_decision is None:
        missing.append(
            f"{SECURITY_DIR / 'launch-decision.md'} or {SECURITY_DIR / 'launch-decision.yml'}"
        )

    framework_files = tuple(resolved_target / path for path in FRAMEWORK_FILES if (resolved_target / path).is_file())
    missing_framework_files = tuple(
        str(path) for path in FRAMEWORK_FILES if not (resolved_target / path).is_file()
    )

    return DiscoveredConfig(
        target=resolved_target,
        gate_applicability=gate_applicability,
        scope_contract=scope_contract,
        launch_decision=launch_decision,
        missing_files=tuple(missing),
        framework_files=framework_files,
        missing_framework_files=missing_framework_files,
    )


def validate_target(target: Path) -> Finding | None:
    if not target.exists():
        return Finding(
            title="Target path does not exist",
            severity="high",
            status="open",
            category="scope_permission",
            source="config_discovery",
            file_path=str(target),
            description=f"Target path was not found: {target}",
            risk="LaunchGuardian cannot validate a project outside an existing approved target path.",
            recommendation="Provide an existing project path with --target.",
            related_gate="Gate 0 — Scope & Permission",
            blocks_launch=True,
        )
    if not target.is_dir():
        return Finding(
            title="Target path is not a directory",
            severity="high",
            status="open",
            category="scope_permission",
            source="config_discovery",
            file_path=str(target),
            description=f"Target path is not a directory: {target}",
            risk="LaunchGuardian needs a project directory as its validation boundary.",
            recommendation="Provide a project directory with --target.",
            related_gate="Gate 0 — Scope & Permission",
            blocks_launch=True,
        )
    return None


def missing_file_findings(config: DiscoveredConfig) -> list[Finding]:
    findings: list[Finding] = []
    for missing in config.missing_files:
        findings.append(
            Finding(
                title="Required LGF file is missing",
                severity="high",
                status="open",
                category="lgf_config",
                source="config_discovery",
                file_path=missing,
                description=f"Required LGF project file is missing: {missing}",
                risk="LaunchGuardian cannot make a reliable launch decision without required LGF project records.",
                recommendation="Create the missing LGF file from the SDD+ LaunchGuardian templates.",
                related_gate="Gate 20 — Launch Decision",
                blocks_launch=True,
            )
        )
    if config.framework_files and config.missing_files:
        findings.append(
            Finding(
                title="Framework/template repo detected",
                severity="info",
                status="open",
                category="lgf_config",
                source="config_discovery",
                description=(
                    "This target contains LaunchGuardian framework/template files, but project-specific "
                    "LGF records are missing."
                ),
                risk="Templates are not project truth and should not be treated as launch evidence.",
                recommendation=(
                    "Use --framework-mode to validate the framework/template repo, or create project-specific "
                    "LGF files before project validation."
                ),
                related_gate="Gate 20 — Launch Decision",
                blocks_launch=False,
            )
        )
    return findings


def framework_mode_findings(config: DiscoveredConfig) -> list[Finding]:
    findings: list[Finding] = []
    for missing in config.missing_framework_files:
        findings.append(
            Finding(
                title="Required framework file is missing",
                severity="high",
                status="open",
                category="framework_config",
                source="config_discovery",
                file_path=missing,
                description=f"Required LaunchGuardian framework/template file is missing: {missing}",
                risk="Framework mode cannot validate the foundation when expected framework files are missing.",
                recommendation="Restore the missing framework/spec/template file.",
                related_gate="Gate 20 — Launch Decision",
                blocks_launch=True,
            )
        )
    if not findings:
        findings.append(
            Finding(
                title="Framework/template repo validated",
                severity="info",
                status="open",
                category="framework_config",
                source="config_discovery",
                description=(
                    "Framework mode validated expected LaunchGuardian specs/templates. "
                    "No project-specific LGF files were treated as project truth."
                ),
                risk="None. Framework mode is not a project launch decision.",
                recommendation="Use project mode against a project that has project-specific LGF files.",
                related_gate="Gate 20 — Launch Decision",
                blocks_launch=False,
            )
        )
    return findings


def _existing_file(path: Path) -> Path | None:
    return path if path.is_file() else None


def _first_existing(*paths: Path) -> Path | None:
    for path in paths:
        if path.is_file():
            return path
    return None
