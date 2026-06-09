# Demo Vulnerable App Sample Reports

These sample reports were generated from the intentionally vulnerable `launchguardian-demo-vulnerable-app` repo.

The demo scan is expected to be `BLOCKED`. The findings are fake, local-only examples for defensive LaunchGuardian report review. No real credentials or real service targets are included.

Expected scanner signals include:

- `frontend_exposure` findings for source maps, fake public secret-like names, browser storage, and debug URL references.
- `api_surface` findings for auth, role, object authorization, injection, and session/CSRF review signals.

Local machine path fragments were replaced with `<demo-repo>` in these sample files.
