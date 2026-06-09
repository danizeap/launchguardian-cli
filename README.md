# LaunchGuardian CLI

LaunchGuardian CLI is the implementation companion to the LaunchGuardian Framework (LGF). It validates LGF project files and runs local, permission-bound security checks against target paths provided by the user.

Implemented commands:

```bash
launchguardian validate-lgf --target .
launchguardian validate-lgf --target . --framework-mode
launchguardian scan --target .
launchguardian scan --target . --framework-mode
launchguardian scan --target . --skip-lgf-validation
launchguardian scan --target . --strict-scanners
```

Framework/template repos can be validated without pretending templates are project truth:

```bash
launchguardian validate-lgf --target ../sdd-plus-project-starter --framework-mode
```

`validate-lgf` validates required LGF project files, checks skipped high-risk gates for required human confirmation, and writes reports to:

```text
reports/launchguardian/
|-- launchguardian-report.md
`-- launchguardian-report.json
```

`scan` runs LGF validation first by default, then runs the currently supported scanner integrations.

## Current Scope

LaunchGuardian currently supports local Gitleaks secret scanning, local Semgrep static code security scanning, local Trivy dependency/filesystem/container/IaC scanning, a native frontend exposure scanner, and a native API surface scanner. It does not perform active web scanning, exploit testing, credential guessing, or any offensive workflow.

## Exit Codes

| Code | Meaning |
| --- | --- |
| 0 | Valid LGF config and no blocking issue. |
| 1 | Invalid LGF config, detected secrets, or blocked launch policy. |
| 2 | Tool/scanner execution failure. |
| 3 | Scope, permission, or configuration error. |

## Required LGF Files

In normal project validation mode, `validate-lgf` looks for these files under the target project:

- `sdd-plus/security/gate-applicability.yml`
- `sdd-plus/security/scope-contract.yml`
- `sdd-plus/security/launch-decision.md` or `sdd-plus/security/launch-decision.yml`

Missing project LGF files mean the project is incomplete for LaunchGuardian validation. The command reports each missing file and exits with code `1`.

If the target is the SDD+ starter or another framework/template repo, use `--framework-mode`. Framework mode validates expected LaunchGuardian specs/templates and does not treat templates as project-specific launch evidence.

For `scan`, `--framework-mode` is more permissive: it treats the target as a framework, template, or tool repo, skips project-specific LGF file requirements, and still runs local scanners.

Use `--skip-lgf-validation` only when you intentionally want scanner results without LGF project records. Reports will set `lgf_validation_skipped: true` and use `SCANNED_WITHOUT_LGF` or `INCOMPLETE` instead of `APPROVED`.

## Reports

Reports are generated under the target project by default:

```text
<target>/reports/launchguardian/
|-- launchguardian-report.md
|-- launchguardian-report.json
|-- normalized-findings.json
`-- raw/
    |-- gitleaks-results.json
    |-- semgrep-results.json
    |-- trivy-results.json
    |-- frontend-exposure-results.json
    `-- api-surface-results.json
```

The JSON report includes schema metadata, `validation_mode`, `scan_mode`, `lgf_validation_skipped`, `strict_scanners`, LGF config validation result, scanner availability, scanner finding counts, launch status, blocked status, target path, and normalized findings. The Markdown report is the human-readable summary.

Use `--output-dir` to write reports somewhere else:

```bash
launchguardian validate-lgf --target . --output-dir reports/launchguardian
launchguardian scan --target . --output-dir reports/launchguardian
```

## Local Scanning

Run a local scan against a project you control:

```bash
launchguardian scan --target .
launchguardian scan --target . --framework-mode
launchguardian scan --target . --skip-lgf-validation
launchguardian scan --target . --strict-scanners
```

LaunchGuardian runs its native frontend exposure and API surface scanners without external dependencies. If Gitleaks, Semgrep, and Trivy are installed, LaunchGuardian also runs those scanner integrations:

- LGF validation.
- Local Gitleaks secret scanning against the target path.
- Local Semgrep static code security scanning against the target path.
- Local Trivy dependency, filesystem, container, and IaC scanning against the target path.
- Native frontend exposure checks against likely frontend source and build output files.
- Native API route, auth, object authorization, injection, CSRF/session, and business-logic heuristic checks.
- Raw Gitleaks JSON output to `reports/launchguardian/raw/gitleaks-results.json`.
- Raw Semgrep JSON output to `reports/launchguardian/raw/semgrep-results.json`.
- Raw Trivy JSON output to `reports/launchguardian/raw/trivy-results.json`.
- Raw frontend exposure JSON output to `reports/launchguardian/raw/frontend-exposure-results.json`.
- Raw API surface JSON output to `reports/launchguardian/raw/api-surface-results.json`.
- Normalized findings to `reports/launchguardian/normalized-findings.json`.
- Markdown and JSON launch reports.

If Gitleaks is not installed, LaunchGuardian emits a `scanner_unavailable` finding for `Gate 4 — Secrets & Config Hygiene`. In local mode this warning does not block launch by itself, but the report status is `INCOMPLETE` so the missing scan is visible.

If Semgrep is not installed, LaunchGuardian emits a `scanner_unavailable` finding for `Gate 3 — Code Security`. In local mode this warning does not block launch by itself, but the report status is `INCOMPLETE` so the missing scan is visible.

If Trivy is not installed, LaunchGuardian emits a `scanner_unavailable` finding for `Gate 10 — Dependency, SBOM & Supply Chain`. In local mode this warning does not block launch by itself, but the report status is `INCOMPLETE` so the missing scan is visible.

Use `--strict-scanners` when missing expected external scanners should block. In strict mode, missing Gitleaks, Semgrep, or Trivy sets `blocks_launch: true` and exits with code `1`.

Secret values are not copied into normalized findings. LaunchGuardian runs Gitleaks with redaction enabled and avoids using raw `Secret` or `Match` values when creating normalized report entries.

## Semgrep Scanning

Install Semgrep before running static code scans:

```bash
python -m pip install semgrep
```

LaunchGuardian invokes Semgrep locally with:

```bash
semgrep scan --config auto --json --output <raw_output_path> <target>
```

Semgrep checks source code for static security signals such as unsafe APIs, injection patterns, auth/session mistakes, and other rule-driven code risks. LaunchGuardian maps High/Critical Semgrep results to blocking High findings, while Medium and Low findings are tracked but do not block by default.

Semgrep findings are static analysis signals and may require human review to confirm impact, false positives, accepted risk, or remediation priority.

## Trivy Scanning

Install Trivy before running dependency, filesystem, container, and IaC scans. On Windows, use the official Trivy install options such as Scoop, Chocolatey, or a downloaded release binary.

LaunchGuardian invokes Trivy locally with:

```bash
trivy fs --format json --output <raw_output_path> <target>
```

Trivy checks dependency manifests, lockfiles, filesystem contents, container-related files, and IaC/configuration files for known vulnerabilities, misconfigurations, and secret findings. LaunchGuardian maps Critical and High Trivy vulnerability findings to blocking findings, Medium and Low vulnerability findings to non-blocking review items, IaC/config misconfigurations to `Gate 11 — Infrastructure, DNS, TLS & Web Hardening`, and Trivy secret findings to Critical blocking findings under `Gate 4 — Secrets & Config Hygiene`.

Trivy findings may require human review. Dependency updates can introduce compatibility changes, so remediation should include appropriate regression testing before release.

## Frontend Exposure Scanning

LaunchGuardian includes a native frontend exposure scanner that does not require external tools. It recursively inspects likely frontend source files and build outputs such as `.html`, `.js`, `.jsx`, `.ts`, `.tsx`, `.map`, `.env*`, `vite.config.*`, `next.config.*`, `package.json`, and files under `public/`, `dist/`, `build/`, `.next/`, and `out/`.

The scanner checks for:

- Source maps committed or shipped in frontend output.
- Secret-looking public frontend environment variable names such as `NEXT_PUBLIC_SECRET`, `VITE_PRIVATE_KEY`, or `REACT_APP_TOKEN`.
- Hardcoded localhost, staging, or debug references.
- Sensitive-looking `localStorage` or `sessionStorage` usage for tokens, JWTs, passwords, secrets, or API keys.
- Private-looking files or `.env` references under public/build output directories.

Public frontend prefixes such as `NEXT_PUBLIC_`, `VITE_`, and `REACT_APP_` are intentionally exposed to browser code by their frameworks. They must never contain secrets, tokens, private keys, passwords, or client secrets. LaunchGuardian reports only the variable name, file path, line number, and safe explanation; it does not copy raw secret values into normalized findings.

## API Surface Scanning

LaunchGuardian includes a native API surface scanner that does not require external tools. It recursively inspects likely backend and API files such as `.py`, `.js`, `.jsx`, `.ts`, `.tsx`, `.go`, `.java`, `.cs`, `.rb`, `.php`, and route files under `api/`, `app/api/`, `pages/api/`, `routes/`, `controllers/`, `server/`, `backend/`, `functions/`, `supabase/functions/`, `netlify/functions/`, and detectable Vercel function paths.

The scanner checks for heuristic launch-review signals:

- API routes with no nearby recognizable auth guard.
- Admin, billing, payment, invite, role, permission, or organization-management routes with no nearby role/admin check.
- Object lookups by user-controlled IDs without nearby ownership, user, org, tenant, account, or team filters.
- Raw SQL string construction near SQL keywords.
- State-changing cookie/session routes with no nearby CSRF or SameSite signal.
- Business-sensitive endpoints without an explicit nearby policy or guard comment.

API surface findings are static heuristics. They are not proof of a vulnerability, and they are not proof of safety when absent. Treat them as launch-review signals that should be confirmed by a human reviewer against the actual framework, middleware, and authorization architecture.

## Current Limitations

- Only the Gitleaks, Semgrep, Trivy, frontend exposure, and API surface scanners are implemented.
- No active web scanning is implemented.
- No offensive tooling is included.
- Semgrep findings are static analysis signals and may require review.
- Trivy findings may require review, and dependency updates may need compatibility testing.
- Frontend exposure findings may require review to distinguish intentional development-only references from production exposure.
- API surface findings are heuristic review signals, not proof of vulnerability.
- `validate-lgf` only validates required LGF files and high-risk skipped gate confirmation.
- `validate-lgf --framework-mode` validates template presence only; it is not a project launch decision.
- `scan --framework-mode` scans framework, template, or tool repos without requiring project-specific LGF files.

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m launchguardian.cli validate-lgf --target .
python -m launchguardian.cli validate-lgf --target . --framework-mode
python -m launchguardian.cli scan --target .
python -m launchguardian.cli scan --target . --framework-mode
python -m launchguardian.cli scan --target . --skip-lgf-validation
python -m launchguardian.cli scan --target . --strict-scanners
```
