from __future__ import annotations

from pathlib import Path

from .models import DiscoveredConfig, Finding


SECURITY_DIR = Path("sdd-plus") / "security"


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

    return DiscoveredConfig(
        target=resolved_target,
        gate_applicability=gate_applicability,
        scope_contract=scope_contract,
        launch_decision=launch_decision,
        missing_files=tuple(missing),
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
    return findings


def _existing_file(path: Path) -> Path | None:
    return path if path.is_file() else None


def _first_existing(*paths: Path) -> Path | None:
    for path in paths:
        if path.is_file():
            return path
    return None
