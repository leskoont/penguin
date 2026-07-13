# Security Policy

## Scope and legal use

penguin is a reconnaissance automation framework. It is intended **only** for:

- Assets you own, or
- Assets you are explicitly authorized to test (signed pentest engagement,
  bug bounty program in scope, CTF infrastructure).

Running penguin against targets you are not authorized to test may be illegal
in your jurisdiction (e.g. unauthorized access / computer misuse laws).
Contributors and users are solely responsible for obtaining proper
authorization and respecting each program's scope and rules of engagement.

## Reporting a vulnerability in penguin itself

If you find a security issue in the penguin codebase (e.g. a bug that leaks
API keys/credentials, injects unsanitized input into a shell command, or
otherwise weakens the tool's own security), please report it privately:

- Open a [GitHub Security Advisory](../../security/advisories/new) on this
  repository (preferred), or
- Email the maintainer listed in the repository profile.

Please do not open a public issue for security-sensitive bugs until a fix is
available. We aim to acknowledge reports within 5 business days.

## API keys and credentials

- Paid/OSINT API keys are read from environment variables only and must never
  be committed to `config/config.yaml`, targets files, or run artifacts.
- `results/` and `reports/` (per-run output) are `.gitignore`d by default —
  do not force-add files from those directories to version control, they may
  contain scan output about real, potentially sensitive targets.
