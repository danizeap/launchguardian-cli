from __future__ import annotations

import json
import subprocess
from pathlib import Path

from launchguardian.cli import EXIT_BLOCKED, EXIT_VALID, main


def test_missing_gate_applicability_file(tmp_path: Path) -> None:
    security_dir = tmp_path / "sdd-plus" / "security"
    security_dir.mkdir(parents=True)
    (security_dir / "scope-contract.yml").write_text("project: test\n", encoding="utf-8")
    (security_dir / "launch-decision.md").write_text("# Launch Decision\n", encoding="utf-8")

    exit_code = main(["validate-lgf", "--target", str(tmp_path)])

    assert exit_code == EXIT_BLOCKED
    report = _read_report(tmp_path)
    assert report["blocked"] is True
    assert report["mode"] == "project"
    assert any("gate-applicability.yml" in finding["file_path"] for finding in report["findings"])


def test_high_risk_skipped_gate_missing_confirmation(tmp_path: Path) -> None:
    _write_required_files(
        tmp_path,
        gate_applicability="""
gates:
  - gate_id: 14
    gate_name: "Gate 14 — Privacy, Legal & Data Lifecycle"
    applies: false
    confidence: "high"
    reason: ""
    evidence: []
""",
    )

    exit_code = main(["validate-lgf", "--target", str(tmp_path)])

    assert exit_code == EXIT_BLOCKED
    report = _read_report(tmp_path)
    assert any(
        finding["title"] == "High-risk skipped gate is missing human confirmation"
        for finding in report["findings"]
    )


def test_valid_high_risk_skip(tmp_path: Path) -> None:
    _write_required_files(
        tmp_path,
        gate_applicability="""
gates:
  - gate_id: 14
    gate_name: "Gate 14 — Privacy, Legal & Data Lifecycle"
    applies: false
    confidence: "high"
    human_confirmation_required: true
    confirmed_by: "Owner"
    confirmed_at: "2026-06-09"
    reason: "No personal or sensitive data is processed."
    evidence:
      - type: "human_statement"
        detail: "Owner confirmed no personal data exists."
""",
    )

    exit_code = main(["validate-lgf", "--target", str(tmp_path)])

    assert exit_code == EXIT_VALID
    report = _read_report(tmp_path)
    assert report["blocked"] is False
    assert report["findings"] == []


def test_report_generation(tmp_path: Path) -> None:
    _write_required_files(tmp_path, gate_applicability="gates: []\n")

    exit_code = main(["validate-lgf", "--target", str(tmp_path)])

    assert exit_code == EXIT_VALID
    report_dir = tmp_path / "reports" / "launchguardian"
    assert (report_dir / "launchguardian-report.md").is_file()
    assert (report_dir / "launchguardian-report.json").is_file()


def test_validating_real_project_with_required_lgf_files(tmp_path: Path) -> None:
    _write_required_files(
        tmp_path,
        gate_applicability="""
gates:
  - gate_id: 20
    gate_name: "Gate 20 — Launch Decision"
    applies: true
    confidence: "high"
    evidence:
      - type: "human_statement"
        detail: "Launch decision exists."
""",
    )

    exit_code = main(["validate-lgf", "--target", str(tmp_path)])

    assert exit_code == EXIT_VALID
    report = _read_report(tmp_path)
    assert report["mode"] == "project"
    assert report["blocked"] is False


def test_validating_framework_template_repo(tmp_path: Path) -> None:
    _write_framework_files(tmp_path)

    exit_code = main(["validate-lgf", "--target", str(tmp_path), "--framework-mode"])

    assert exit_code == EXIT_VALID
    report = _read_report(tmp_path)
    assert report["mode"] == "framework"
    assert report["blocked"] is False
    assert any(
        finding["title"] == "Framework/template repo validated"
        for finding in report["findings"]
    )


def test_missing_project_files_produce_clear_blocked_result(tmp_path: Path) -> None:
    _write_framework_files(tmp_path)

    exit_code = main(["validate-lgf", "--target", str(tmp_path)])

    assert exit_code == EXIT_BLOCKED
    report = _read_report(tmp_path)
    assert report["mode"] == "project"
    assert report["blocked"] is True
    assert any(finding["title"] == "Required LGF file is missing" for finding in report["findings"])
    assert any(finding["title"] == "Framework/template repo detected" for finding in report["findings"])


def test_scan_gitleaks_missing_produces_scanner_unavailable_finding(
    tmp_path: Path, monkeypatch
) -> None:
    _write_required_files(tmp_path, gate_applicability="gates: []\n")
    monkeypatch.setattr("launchguardian.scanners.gitleaks.shutil.which", lambda _: None)

    exit_code = main(["scan", "--target", str(tmp_path)])

    assert exit_code == EXIT_VALID
    report = _read_report(tmp_path)
    assert report["launch_status"] == "INCOMPLETE"
    assert report["scanner_availability"] == {"gitleaks": "unavailable"}
    assert any(
        finding["title"] == "Gitleaks scanner unavailable"
        and finding["category"] == "scanner_unavailable"
        and finding["blocks_launch"] is False
        for finding in report["findings"]
    )


def test_scan_mocked_gitleaks_secret_produces_critical_blocking_finding(
    tmp_path: Path, monkeypatch
) -> None:
    _write_required_files(tmp_path, gate_applicability="gates: []\n")
    _mock_gitleaks_with_findings(
        monkeypatch,
        [
            {
                "RuleID": "generic-api-key",
                "Description": "Generic API key",
                "File": "settings.py",
                "StartLine": 7,
                "Secret": "super-secret-token",
                "Match": "API_KEY=super-secret-token",
            }
        ],
    )

    exit_code = main(["scan", "--target", str(tmp_path)])

    assert exit_code == EXIT_BLOCKED
    report = _read_report(tmp_path)
    secret_findings = [finding for finding in report["findings"] if finding["source"] == "gitleaks"]
    assert len(secret_findings) == 1
    finding = secret_findings[0]
    assert finding["severity"] == "critical"
    assert finding["blocks_launch"] is True
    assert finding["related_gate"] == "Gate 4 — Secrets & Config Hygiene"
    assert "super-secret-token" not in json.dumps(finding)


def test_scan_command_writes_raw_normalized_markdown_and_json_reports(
    tmp_path: Path, monkeypatch
) -> None:
    _write_required_files(tmp_path, gate_applicability="gates: []\n")
    _mock_gitleaks_with_findings(monkeypatch, [])

    exit_code = main(["scan", "--target", str(tmp_path)])

    assert exit_code == EXIT_VALID
    report_dir = tmp_path / "reports" / "launchguardian"
    assert (report_dir / "raw" / "gitleaks-results.json").is_file()
    assert (report_dir / "normalized-findings.json").is_file()
    assert (report_dir / "launchguardian-report.md").is_file()
    assert (report_dir / "launchguardian-report.json").is_file()


def test_scan_exits_1_when_critical_secret_is_found(tmp_path: Path, monkeypatch) -> None:
    _write_required_files(tmp_path, gate_applicability="gates: []\n")
    _mock_gitleaks_with_findings(
        monkeypatch,
        [
            {
                "RuleID": "private-key",
                "File": "id_rsa",
                "StartLine": 1,
                "Secret": "-----BEGIN PRIVATE KEY-----",
            }
        ],
    )

    exit_code = main(["scan", "--target", str(tmp_path)])

    assert exit_code == EXIT_BLOCKED
    report = _read_report(tmp_path)
    assert report["launch_status"] == "BLOCKED"


def _write_required_files(tmp_path: Path, gate_applicability: str) -> None:
    security_dir = tmp_path / "sdd-plus" / "security"
    security_dir.mkdir(parents=True)
    (security_dir / "gate-applicability.yml").write_text(gate_applicability, encoding="utf-8")
    (security_dir / "scope-contract.yml").write_text("project: test\n", encoding="utf-8")
    (security_dir / "launch-decision.md").write_text("# Launch Decision\n", encoding="utf-8")


def _write_framework_files(tmp_path: Path) -> None:
    specs_dir = tmp_path / "sdd-plus" / "specs"
    standards_dir = tmp_path / "sdd-plus" / "standards"
    security_dir = tmp_path / "sdd-plus" / "security"
    specs_dir.mkdir(parents=True)
    standards_dir.mkdir(parents=True)
    security_dir.mkdir(parents=True)
    for path in (
        specs_dir / "launchguardian-framework.md",
        specs_dir / "lgf-gate-applicability-system.md",
        specs_dir / "lgf-project-onboarding.md",
        specs_dir / "launchguardian-cli-product-spec.md",
        standards_dir / "security-shipping-standards.md",
        security_dir / "gate-applicability.template.yml",
        security_dir / "gate-applicability.output.template.yml",
        security_dir / "project-security-readiness.template.md",
        security_dir / "launch-decision.template.md",
    ):
        path.write_text("placeholder\n", encoding="utf-8")


def _read_report(tmp_path: Path) -> dict:
    report_path = tmp_path / "reports" / "launchguardian" / "launchguardian-report.json"
    return json.loads(report_path.read_text(encoding="utf-8"))


def _mock_gitleaks_with_findings(monkeypatch, findings: list[dict]) -> None:
    monkeypatch.setattr("launchguardian.scanners.gitleaks.shutil.which", lambda _: "gitleaks")

    def fake_run(command, cwd, capture_output, text):
        report_path = Path(command[command.index("--report-path") + 1])
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(findings), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr("launchguardian.scanners.gitleaks.subprocess.run", fake_run)
