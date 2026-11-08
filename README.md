# skill-vetting

Scans third-party Claude Code skills and plugins on an ephemeral GitHub Actions runner, returns PASS, REVIEW or FAIL, and keeps an allowlist of approved `owner/repo@SHA` entries. Local machines install only what is on that allowlist.

Status: scaffold only. The vet, approve, install, override and rescan flows will be documented here as they are built.
