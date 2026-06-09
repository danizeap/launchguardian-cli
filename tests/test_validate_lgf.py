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
    _mock_scanners(monkeypatch, gitleaks_findings=None, semgrep_findings=[])

    exit_code = main(["scan", "--target", str(tmp_path)])

    assert exit_code == EXIT_VALID
    report = _read_report(tmp_path)
    assert report["launch_status"] == "INCOMPLETE"
    assert report["scanner_availability"]["gitleaks"] == "unavailable"
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
    _mock_scanners(
        monkeypatch,
        gitleaks_findings=[
            {
                "RuleID": "generic-api-key",
                "Description": "Generic API key",
                "File": "settings.py",
                "StartLine": 7,
                "Secret": "super-secret-token",
                "Match": "API_KEY=super-secret-token",
            }
        ],
        semgrep_findings=[],
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
    _mock_scanners(monkeypatch, gitleaks_findings=[], semgrep_findings=[], trivy_results=[])

    exit_code = main(["scan", "--target", str(tmp_path)])

    assert exit_code == EXIT_VALID
    report_dir = tmp_path / "reports" / "launchguardian"
    assert (report_dir / "raw" / "gitleaks-results.json").is_file()
    assert (report_dir / "raw" / "semgrep-results.json").is_file()
    assert (report_dir / "raw" / "trivy-results.json").is_file()
    assert (report_dir / "normalized-findings.json").is_file()
    assert (report_dir / "launchguardian-report.md").is_file()
    assert (report_dir / "launchguardian-report.json").is_file()


def test_scan_exits_1_when_critical_secret_is_found(tmp_path: Path, monkeypatch) -> None:
    _write_required_files(tmp_path, gate_applicability="gates: []\n")
    _mock_scanners(
        monkeypatch,
        gitleaks_findings=[
            {
                "RuleID": "private-key",
                "File": "id_rsa",
                "StartLine": 1,
                "Secret": "-----BEGIN PRIVATE KEY-----",
            }
        ],
        semgrep_findings=[],
    )

    exit_code = main(["scan", "--target", str(tmp_path)])

    assert exit_code == EXIT_BLOCKED
    report = _read_report(tmp_path)
    assert report["launch_status"] == "BLOCKED"


def test_scan_framework_mode_does_not_require_project_lgf_files(
    tmp_path: Path, monkeypatch
) -> None:
    _mock_scanners(monkeypatch, gitleaks_findings=None, semgrep_findings=None)

    exit_code = main(["scan", "--target", str(tmp_path), "--framework-mode"])

    assert exit_code == EXIT_VALID
    report = _read_report(tmp_path)
    assert report["validation_mode"] == "framework"
    assert report["scan_mode"] == "local"
    assert report["launch_status"] == "INCOMPLETE"
    assert not any(
        finding["title"] == "Required LGF file is missing"
        for finding in report["findings"]
    )


def test_scan_skip_lgf_validation_writes_clear_skipped_status(
    tmp_path: Path, monkeypatch
) -> None:
    _mock_scanners(monkeypatch, gitleaks_findings=[], semgrep_findings=[])

    exit_code = main(["scan", "--target", str(tmp_path), "--skip-lgf-validation"])

    assert exit_code == EXIT_VALID
    report = _read_report(tmp_path)
    assert report["validation_mode"] == "skipped"
    assert report["lgf_validation_skipped"] is True
    assert report["lgf_validation_status"] == "skipped"
    assert report["launch_status"] == "SCANNED_WITHOUT_LGF"


def test_scan_strict_scanners_makes_missing_gitleaks_blocking(
    tmp_path: Path, monkeypatch
) -> None:
    _write_required_files(tmp_path, gate_applicability="gates: []\n")
    _mock_scanners(monkeypatch, gitleaks_findings=None, semgrep_findings=[])

    exit_code = main(["scan", "--target", str(tmp_path), "--strict-scanners"])

    assert exit_code == EXIT_BLOCKED
    report = _read_report(tmp_path)
    assert report["strict_scanners"] is True
    assert report["launch_status"] == "BLOCKED"
    assert any(
        finding["title"] == "Gitleaks scanner unavailable"
        and finding["blocks_launch"] is True
        for finding in report["findings"]
    )


def test_default_scan_missing_lgf_files_remains_blocked(
    tmp_path: Path, monkeypatch
) -> None:
    _mock_scanners(monkeypatch, gitleaks_findings=[], semgrep_findings=[])

    exit_code = main(["scan", "--target", str(tmp_path)])

    assert exit_code == EXIT_BLOCKED
    report = _read_report(tmp_path)
    assert report["validation_mode"] == "project"
    assert report["lgf_config_valid"] is False
    assert report["launch_status"] == "BLOCKED"
    assert any(
        finding["title"] == "Required LGF file is missing"
        for finding in report["findings"]
    )


def test_scan_semgrep_missing_produces_scanner_unavailable_finding(
    tmp_path: Path, monkeypatch
) -> None:
    _write_required_files(tmp_path, gate_applicability="gates: []\n")
    _mock_scanners(monkeypatch, gitleaks_findings=[], semgrep_findings=None)

    exit_code = main(["scan", "--target", str(tmp_path)])

    assert exit_code == EXIT_VALID
    report = _read_report(tmp_path)
    assert report["launch_status"] == "INCOMPLETE"
    assert report["scanner_availability"]["semgrep"] == "unavailable"
    assert any(
        finding["title"] == "Semgrep scanner unavailable"
        and finding["category"] == "scanner_unavailable"
        and finding["blocks_launch"] is False
        for finding in report["findings"]
    )


def test_scan_mocked_semgrep_high_finding_blocks_launch(
    tmp_path: Path, monkeypatch
) -> None:
    _write_required_files(tmp_path, gate_applicability="gates: []\n")
    _mock_scanners(
        monkeypatch,
        gitleaks_findings=[],
        semgrep_findings=[
            {
                "check_id": "python.sql-injection",
                "path": "app.py",
                "start": {"line": 12},
                "extra": {
                    "severity": "ERROR",
                    "message": "Possible SQL injection.",
                    "metadata": {"category": "security", "technology": ["sql-injection"]},
                },
            }
        ],
    )

    exit_code = main(["scan", "--target", str(tmp_path)])

    assert exit_code == EXIT_BLOCKED
    report = _read_report(tmp_path)
    semgrep_findings = [finding for finding in report["findings"] if finding["source"] == "semgrep"]
    assert len(semgrep_findings) == 1
    assert semgrep_findings[0]["severity"] == "high"
    assert semgrep_findings[0]["blocks_launch"] is True
    assert semgrep_findings[0]["related_gate"] == "Gate 7 — Injection & Input Safety"
    assert report["scanner_counts"]["semgrep"] == 1
    assert report["scanner_blocking_counts"]["semgrep"] == 1


def test_scan_mocked_semgrep_medium_finding_is_non_blocking(
    tmp_path: Path, monkeypatch
) -> None:
    _write_required_files(tmp_path, gate_applicability="gates: []\n")
    _mock_scanners(
        monkeypatch,
        gitleaks_findings=[],
        semgrep_findings=[
            {
                "check_id": "python.audit",
                "path": "app.py",
                "start": {"line": 4},
                "extra": {
                    "severity": "WARNING",
                    "message": "Review this security-sensitive code path.",
                    "metadata": {"category": "security"},
                },
            }
        ],
    )

    exit_code = main(["scan", "--target", str(tmp_path)])

    assert exit_code == EXIT_VALID
    report = _read_report(tmp_path)
    semgrep_findings = [finding for finding in report["findings"] if finding["source"] == "semgrep"]
    assert len(semgrep_findings) == 1
    assert semgrep_findings[0]["severity"] == "medium"
    assert semgrep_findings[0]["blocks_launch"] is False


def test_scan_strict_scanners_makes_missing_semgrep_blocking(
    tmp_path: Path, monkeypatch
) -> None:
    _write_required_files(tmp_path, gate_applicability="gates: []\n")
    _mock_scanners(monkeypatch, gitleaks_findings=[], semgrep_findings=None)

    exit_code = main(["scan", "--target", str(tmp_path), "--strict-scanners"])

    assert exit_code == EXIT_BLOCKED
    report = _read_report(tmp_path)
    assert any(
        finding["title"] == "Semgrep scanner unavailable"
        and finding["blocks_launch"] is True
        for finding in report["findings"]
    )


def test_scan_writes_raw_semgrep_output_when_semgrep_runs(
    tmp_path: Path, monkeypatch
) -> None:
    _write_required_files(tmp_path, gate_applicability="gates: []\n")
    _mock_scanners(monkeypatch, gitleaks_findings=[], semgrep_findings=[])

    exit_code = main(["scan", "--target", str(tmp_path)])

    assert exit_code == EXIT_VALID
    assert (tmp_path / "reports" / "launchguardian" / "raw" / "semgrep-results.json").is_file()


def test_scan_trivy_missing_produces_scanner_unavailable_finding(
    tmp_path: Path, monkeypatch
) -> None:
    _write_required_files(tmp_path, gate_applicability="gates: []\n")
    _mock_scanners(monkeypatch, gitleaks_findings=[], semgrep_findings=[], trivy_results=None)

    exit_code = main(["scan", "--target", str(tmp_path)])

    assert exit_code == EXIT_VALID
    report = _read_report(tmp_path)
    assert report["launch_status"] == "INCOMPLETE"
    assert report["scanner_availability"]["trivy"] == "unavailable"
    assert any(
        finding["title"] == "Trivy scanner unavailable"
        and finding["category"] == "scanner_unavailable"
        and finding["blocks_launch"] is False
        for finding in report["findings"]
    )


def test_scan_mocked_trivy_critical_vulnerability_blocks_launch(
    tmp_path: Path, monkeypatch
) -> None:
    _write_required_files(tmp_path, gate_applicability="gates: []\n")
    _mock_scanners(
        monkeypatch,
        gitleaks_findings=[],
        semgrep_findings=[],
        trivy_results=[
            _trivy_result_with_vulnerability(
                vulnerability_id="CVE-2099-0001",
                severity="CRITICAL",
                package_name="unsafe-lib",
            )
        ],
    )

    exit_code = main(["scan", "--target", str(tmp_path)])

    assert exit_code == EXIT_BLOCKED
    report = _read_report(tmp_path)
    trivy_findings = [finding for finding in report["findings"] if finding["source"] == "trivy"]
    assert len(trivy_findings) == 1
    assert trivy_findings[0]["severity"] == "critical"
    assert trivy_findings[0]["blocks_launch"] is True
    assert trivy_findings[0]["related_gate"] == "Gate 10 — Dependency, SBOM & Supply Chain"
    assert trivy_findings[0]["package_name"] == "unsafe-lib"
    assert trivy_findings[0]["vulnerability_id"] == "CVE-2099-0001"


def test_scan_mocked_trivy_high_vulnerability_blocks_launch(
    tmp_path: Path, monkeypatch
) -> None:
    _write_required_files(tmp_path, gate_applicability="gates: []\n")
    _mock_scanners(
        monkeypatch,
        gitleaks_findings=[],
        semgrep_findings=[],
        trivy_results=[
            _trivy_result_with_vulnerability(
                vulnerability_id="CVE-2099-0002",
                severity="HIGH",
                package_name="risky-lib",
            )
        ],
    )

    exit_code = main(["scan", "--target", str(tmp_path)])

    assert exit_code == EXIT_BLOCKED
    report = _read_report(tmp_path)
    trivy_findings = [finding for finding in report["findings"] if finding["source"] == "trivy"]
    assert trivy_findings[0]["severity"] == "high"
    assert trivy_findings[0]["blocks_launch"] is True


def test_scan_mocked_trivy_medium_vulnerability_is_non_blocking(
    tmp_path: Path, monkeypatch
) -> None:
    _write_required_files(tmp_path, gate_applicability="gates: []\n")
    _mock_scanners(
        monkeypatch,
        gitleaks_findings=[],
        semgrep_findings=[],
        trivy_results=[
            _trivy_result_with_vulnerability(
                vulnerability_id="CVE-2099-0003",
                severity="MEDIUM",
                package_name="medium-lib",
            )
        ],
    )

    exit_code = main(["scan", "--target", str(tmp_path)])

    assert exit_code == EXIT_VALID
    report = _read_report(tmp_path)
    trivy_findings = [finding for finding in report["findings"] if finding["source"] == "trivy"]
    assert trivy_findings[0]["severity"] == "medium"
    assert trivy_findings[0]["blocks_launch"] is False


def test_scan_strict_scanners_makes_missing_trivy_blocking(
    tmp_path: Path, monkeypatch
) -> None:
    _write_required_files(tmp_path, gate_applicability="gates: []\n")
    _mock_scanners(monkeypatch, gitleaks_findings=[], semgrep_findings=[], trivy_results=None)

    exit_code = main(["scan", "--target", str(tmp_path), "--strict-scanners"])

    assert exit_code == EXIT_BLOCKED
    report = _read_report(tmp_path)
    assert any(
        finding["title"] == "Trivy scanner unavailable"
        and finding["blocks_launch"] is True
        for finding in report["findings"]
    )


def test_scan_writes_raw_trivy_output_when_trivy_runs(
    tmp_path: Path, monkeypatch
) -> None:
    _write_required_files(tmp_path, gate_applicability="gates: []\n")
    _mock_scanners(monkeypatch, gitleaks_findings=[], semgrep_findings=[], trivy_results=[])

    exit_code = main(["scan", "--target", str(tmp_path)])

    assert exit_code == EXIT_VALID
    assert (tmp_path / "reports" / "launchguardian" / "raw" / "trivy-results.json").is_file()


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


def _mock_scanners(
    monkeypatch,
    *,
    gitleaks_findings: list[dict] | None,
    semgrep_findings: list[dict] | None,
    trivy_results=(),
) -> None:
    def fake_which(name):
        if name == "gitleaks" and gitleaks_findings is not None:
            return "gitleaks"
        if name == "semgrep" and semgrep_findings is not None:
            return "semgrep"
        if name == "trivy" and trivy_results is not None:
            return "trivy"
        return None

    def fake_run(command, cwd, capture_output, text):
        if command[0] == "gitleaks":
            report_path = Path(command[command.index("--report-path") + 1])
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(json.dumps(gitleaks_findings or []), encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        if command[0] == "semgrep":
            report_path = Path(command[command.index("--output") + 1])
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(json.dumps({"results": semgrep_findings or []}), encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        if command[0] == "trivy":
            report_path = Path(command[command.index("--output") + 1])
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(json.dumps({"Results": list(trivy_results or [])}), encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="unexpected command")

    monkeypatch.setattr("launchguardian.scanners.gitleaks.shutil.which", fake_which)
    monkeypatch.setattr("launchguardian.scanners.semgrep.shutil.which", fake_which)
    monkeypatch.setattr("launchguardian.scanners.trivy.shutil.which", fake_which)
    monkeypatch.setattr("launchguardian.scanners.gitleaks.subprocess.run", fake_run)
    monkeypatch.setattr("launchguardian.scanners.semgrep.subprocess.run", fake_run)
    monkeypatch.setattr("launchguardian.scanners.trivy.subprocess.run", fake_run)


def _trivy_result_with_vulnerability(
    *, vulnerability_id: str, severity: str, package_name: str
) -> dict:
    return {
        "Target": "requirements.txt",
        "Type": "pip",
        "Vulnerabilities": [
            {
                "VulnerabilityID": vulnerability_id,
                "PkgName": package_name,
                "InstalledVersion": "1.0.0",
                "FixedVersion": "1.0.1",
                "Severity": severity,
                "Title": f"{package_name} vulnerability",
                "Description": "Mock Trivy vulnerability for tests.",
            }
        ],
    }
