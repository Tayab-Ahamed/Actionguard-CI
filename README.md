# ActionGuard AutoAudit

**Detection -> Evidence -> Severity -> Suggested fix -> Patch preview -> Final report -> Email notification**

ActionGuard extends [zizmor](https://github.com/zizmorcore/zizmor) with agentic workflow-injection rules, committed environment and secret detection, artifact upload checks, code-quality/dependency integrations, normalized risk scoring, remediation planning, self-contained HTML/JSON reporting, optional email, and GitHub Actions automation.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
pip install zizmor ruff bandit pip-audit
actionguard audit . --html reports/actionguard-report.html --json reports/actionguard-report.json
```

The audit continues if an optional scanner is missing or fails. Its status appears in JSON and the terminal summary.

## Commands

```bash
actionguard audit .
actionguard scan .
actionguard report --json actionguard-report.json --html actionguard-report.html
python -m actionguard.cli audit . --html report.html --json report.json
```

Add `--email` to send the HTML report when `MAIL_USERNAME`, `MAIL_PASSWORD`, and `REPORT_TO_EMAIL` exist. Optional: `MAIL_HOST` (default `smtp.gmail.com`) and `MAIL_PORT` (default `465`). Missing SMTP configuration never fails the audit.

## Architecture

```text
GitHub push / PR / manual dispatch
  -> checkout (contents: read)
  -> ActionGuard orchestrator
      - zizmor GitHub Actions audit
      - 5 agentic AI rules
      - env + secret redaction audit
      - artifact upload audit
      - Ruff + Bandit
      - npm audit + pip-audit
      - repository hygiene
  -> normalized Finding[]
  -> category + overall scores
  -> remediation and patch previews
  -> self-contained HTML + JSON
  -> 7-day GitHub artifact + optional SMTP email
```

## Safety model

- Secret evidence is always redacted to the first six characters plus `...redacted`.
- Binary files, files over 1 MB, generated reports, and high-volume build/dependency directories are skipped.
- Findings distinguish safe patch suggestions from changes requiring manual review.
- ActionGuard never deletes `.env`, rotates credentials, changes production permissions, or executes patches automatically.

## Demo

```bash
actionguard audit examples/demo-vulnerable-repo \
  --html reports/demo-report.html --json reports/demo-report.json
```

Expected top findings include AI-generated shell execution, write-all permissions, untrusted comment input, secret exposure, whole-repository artifact upload, and long retention.

The demo intentionally commits fake seeded credentials in `examples/demo-vulnerable-repo/.env` so secret detection and redaction can be reproduced. These values are non-functional and must not be replaced with real credentials.

`reports/demo-report.html`, `reports/demo-report-rerendered.html`, and `reports/demo-report.json` are committed demo artifacts even though normal generated reports are ignored by `.gitignore`.

## Tests

```bash
pytest -q
```

## Upstream attribution

ActionGuard uses zizmor as its base GitHub Actions scanner and does not reimplement its audit suite. See `NOTICE.md`. zizmor remains subject to its upstream license.
