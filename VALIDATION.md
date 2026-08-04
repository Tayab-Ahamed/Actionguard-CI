# Strict validation record

## Executed locally

- Python syntax compilation: **passed** (`python -m compileall -q actionguard tests`).
- Focused acceptance harness: **passed** for AG-AI-001 through AG-AI-005, whole-repository artifact upload, long retention, committed `.env`, secret detection/redaction, and scoring.
- Demo CLI audit: **passed** and generated self-contained HTML plus valid JSON.
- Secret non-disclosure assertion: **passed** for both HTML and JSON.
- Report re-render from JSON: **passed**.
- Presentation package/materialization/design audits: **passed** with zero issues or warnings.
- HTML structural capture: **passed** with no horizontal overflow, clipped elements, console errors, or failed resources.

## Demo result

- Overall score: 0 / 100
- Critical: 7
- High: 3
- Medium: 4
- Low: 3
- Info: 1
- All five custom agentic rules triggered.
- Full demo secret printed: **no**.

## Environment-bound checks

`zizmor`, Ruff, Bandit, npm audit, and pip-audit are isolated integrations. In this sandbox, unavailable tools were correctly marked failed/skipped while the audit continued. The GitHub Actions workflow installs these tools before execution and runs the pytest suite. SMTP delivery requires the documented repository secrets and was correctly skipped when they were absent.
