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
        findings.extend(_trifecta_findings(gate, path))
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


TRIFECTA_LEGS = ("private_data_access", "untrusted_content_exposure", "outbound_channel")

# A mitigation or broken_leg written as one of these placeholders does NOT clear a
# lethal trifecta. Without this, a lazy "TODO" / "none" silently un-blocks the one
# "lethal" gate — the most realistic false-negative for this check.
_TRIFECTA_NON_MITIGATIONS = frozenset({
    "none", "n/a", "na", "n.a.", "todo", "to do", "to-do", "tbd", "tba", "tbc",
    "pending", "wip", "later", "fixme", "xxx", "nil", "null", "?", "-", "--",
    "not implemented", "not implemented yet", "none yet", "unknown", "n/a.",
})


def _is_meaningful_mitigation(value: Any) -> bool:
    """A broken_leg / mitigation clears the trifecta only if it is a real, non-empty,
    non-placeholder value."""
    text = str(value or "").strip()
    return bool(text) and text.casefold() not in _TRIFECTA_NON_MITIGATIONS


def _trifecta_findings(gate: dict[str, Any], path: Path) -> list[Finding]:
    """Flag an unmitigated lethal trifecta (LaunchGuardian Framework, Gate 15):
    all three legs present with no broken leg and no mitigation recorded. Silent
    when the block is absent, a leg is not explicitly true, or a mitigation/broken
    leg is recorded — the CLI validates what the project stated, it does not infer
    the legs (that is the applicability-detection feature)."""
    block = gate.get("lethal_trifecta")
    if not isinstance(block, dict):
        return []
    if not all(_is_true(block.get(leg)) for leg in TRIFECTA_LEGS):
        return []
    if _is_meaningful_mitigation(block.get("broken_leg")) or _is_meaningful_mitigation(block.get("mitigation")):
        return []
    label = _gate_label(gate)
    return [
        Finding(
            title="Unmitigated lethal trifecta",
            severity="high",
            status="open",
            category="gate_applicability",
            source="launch_policy",
            file_path=str(path),
            description=(
                f"{label} records all three lethal-trifecta legs — access to private data, "
                "exposure to untrusted content, and an outbound channel — with no broken leg "
                "and no mitigation. Prompt injection in the untrusted content can exfiltrate "
                "the private data through the outbound channel."
            ),
            risk=(
                "An AI agent, MCP server, or LLM tool-chain with all three legs is exploitable "
                "regardless of Row-Level Security or read-only settings (the documented Supabase "
                "MCP exfiltration class)."
            ),
            recommendation=(
                "Break a leg: scope data access to the requesting user, isolate untrusted content "
                "from the tool-calling context, or remove/human-gate the outbound channel. Record "
                "the broken_leg or mitigation in the Gate 15 lethal_trifecta block."
            ),
            related_gate="Gate 15 — AI/RAG/Agent Security",
            blocks_launch=True,
        )
    ]


def _gate_label(gate: dict[str, Any]) -> str:
    name = str(gate.get("gate_name") or gate.get("name") or "").strip()
    if name:
        return name
    gate_id = gate.get("gate_id", gate.get("gate"))
    if gate_id is not None:
        return f"Gate {gate_id}"
    return str(gate.get("key") or "Unknown gate")
