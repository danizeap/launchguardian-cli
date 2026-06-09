from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .models import Finding


REQUIRED_SKIP_FIELDS = (
    "human_confirmation_required",
    "confirmed_by",
    "confirmed_at",
    "reason",
    "evidence",
)


def validate_gate_applicability(path: Path | None) -> list[Finding]:
    if path is None:
        return []

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        return [
            Finding(
                title="Gate applicability YAML is invalid",
                severity="high",
                status="open",
                category="lgf_config",
                source="launch_policy",
                file_path=str(path),
                description=f"Could not parse gate applicability YAML: {exc}",
                risk="Invalid LGF config prevents reliable launch policy validation.",
                recommendation="Fix YAML syntax in gate-applicability.yml.",
                related_gate="Gate 20 — Launch Decision",
                blocks_launch=True,
            )
        ]

    gates = _extract_gates(data)
    findings: list[Finding] = []
    for gate in gates:
        if _is_false(gate.get("applies")) and _is_high_risk(gate):
            missing = _missing_skip_fields(gate)
            if missing:
                gate_label = _gate_label(gate)
                findings.append(
                    Finding(
                        title="High-risk skipped gate is missing human confirmation",
                        severity="high",
                        status="open",
                        category="gate_applicability",
                        source="launch_policy",
                        file_path=str(path),
                        description=(
                            f"{gate_label} is marked applies: false but is missing "
                            f"required confirmation fields: {', '.join(missing)}."
                        ),
                        risk="Skipped high-risk gates without human confirmation can hide launch blockers.",
                        recommendation=(
                            "Set human_confirmation_required: true and fill confirmed_by, "
                            "confirmed_at, reason, and evidence, or mark the gate applies: unknown."
                        ),
                        related_gate=gate_label,
                        blocks_launch=True,
                    )
                )
    return findings


def _extract_gates(data: dict[str, Any]) -> list[dict[str, Any]]:
    gates = data.get("gates", [])
    if isinstance(gates, list):
        return [gate for gate in gates if isinstance(gate, dict)]
    if isinstance(gates, dict):
        extracted = []
        for key, gate in gates.items():
            if isinstance(gate, dict):
                gate.setdefault("key", key)
                extracted.append(gate)
        return extracted
    return []


def _missing_skip_fields(gate: dict[str, Any]) -> list[str]:
    missing: list[str] = []
    if not _is_true(gate.get("human_confirmation_required")):
        missing.append("human_confirmation_required: true")
    for field_name in ("confirmed_by", "confirmed_at", "reason"):
        if not str(gate.get(field_name) or "").strip():
            missing.append(field_name)
    evidence = gate.get("evidence")
    if not _has_evidence(evidence):
        missing.append("evidence")
    return missing


def _is_high_risk(gate: dict[str, Any]) -> bool:
    value = gate.get("high_risk")
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in {"false", "no", "low"}:
        return False
    return True


def _has_evidence(value: Any) -> bool:
    if isinstance(value, list):
        return any(bool(item) for item in value)
    if isinstance(value, dict):
        return any(bool(item) for item in value.values())
    return bool(str(value or "").strip())


def _is_false(value: Any) -> bool:
    return value is False or (isinstance(value, str) and value.strip().lower() == "false")


def _is_true(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def _gate_label(gate: dict[str, Any]) -> str:
    name = str(gate.get("gate_name") or gate.get("name") or "").strip()
    if name:
        return name
    gate_id = gate.get("gate_id", gate.get("gate"))
    if gate_id is not None:
        return f"Gate {gate_id}"
    return str(gate.get("key") or "Unknown gate")
