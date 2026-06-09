# LaunchGuardian CLI v0.1.0 MVP

LaunchGuardian CLI v0.1.0 is a local, permission-bound MVP for validating LaunchGuardian Framework files and running defensive scanner checks against repositories you control.

## What v0.1.0 Does

- Validates required LGF project files.
- Validates high-risk skipped gate confirmation requirements.
- Runs local Gitleaks, Semgrep, and Trivy integrations when installed.
- Runs native Frontend Exposure and API Surface scanners without external dependencies.
- Supports `launchguardian.yml` for scanner configuration and native scanner exclusions.
- Writes Markdown, JSON, normalized findings, and raw scanner outputs.
- Provides GitHub Actions templates for CI adoption before package publishing.

## What v0.1.0 Does Not Do Yet

- It does not publish a pip package.
- It does not run active web scanning.
- It does not run OWASP ZAP or staging URL checks.
- It does not exploit vulnerabilities.
- It does not replace human security review.
- It does not prove an application is secure when findings are absent.

## Safe-Use Boundaries

Use LaunchGuardian only against local target paths you own or have explicit permission to assess. Do not scan third-party systems. Do not add real secrets to fixtures or demo projects. Treat scanner output as defensive review evidence.

## Local-Only Scanning

The MVP scans local files and local repository paths. It does not perform active probing of deployed websites or remote services.

## Expected False Positives

The native scanners and static scanner integrations may report false positives or review signals. Findings should be reviewed against the actual framework, middleware, deployment model, and business context before remediation decisions are finalized.

## Recommended First Use

For framework, template, or tool repositories:

```bash
launchguardian scan --target . --framework-mode
```

## Recommended Project Use

For a project with LGF files:

```bash
launchguardian scan --target .
```

## Recommended CI Use

For CI release gates:

```bash
launchguardian scan --target . --strict-scanners
```

Strict scanner mode makes missing expected external scanners blocking, which helps prevent a green CI build from silently skipping secret, code, or dependency scanning.
