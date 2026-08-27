<div align="center">

# 🛡️ ActionGuard AutoAudit

<a href="https://git.io/typing-svg">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=24&pause=1000&color=38BDF8&center=true&vcenter=true&width=600&height=50&lines=Automated+GitHub+CI%2FCD+Security+Auditing;5+Custom+Agentic+AI+Workflow+Rules;Normalized+Risk+Scoring+%26+Redaction;Self-Contained+HTML+%26+JSON+Reports" alt="Typing SVG" />
</a>

<p align="center">
  <b>Detection &nbsp;➔&nbsp; Evidence &nbsp;➔&nbsp; Severity &nbsp;➔&nbsp; Suggested Fix &nbsp;➔&nbsp; Patch Preview &nbsp;➔&nbsp; HTML Report</b>
</p>

[![ActionGuard AutoAudit](https://github.com/Tayab-Ahamed/Actionguard-CI/actions/workflows/actionguard-autoaudit.yml/badge.svg?branch=main)](https://github.com/Tayab-Ahamed/Actionguard-CI/actions/workflows/actionguard-autoaudit.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge&logo=opensourceinitiative&logoColor=white)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Ruff](https://img.shields.io/badge/Code%20Style-Ruff-261230.svg?style=for-the-badge&logo=ruff&logoColor=white)](https://github.com/astral-sh/ruff)
[![Security: Bandit](https://img.shields.io/badge/Security-Bandit-yellow.svg?style=for-the-badge&logo=python&logoColor=black)](https://github.com/PyCQA/bandit)

---

</div>

ActionGuard extends [zizmor](https://github.com/zizmorcore/zizmor) with agentic workflow-injection detection, committed secret redaction, artifact upload security checks, multi-scanner integrations, normalized risk scoring, and interactive HTML/JSON reporting.

---

## ⚡ Quick Start

```bash
# Set up virtual environment and install ActionGuard
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]' zizmor

# Run security audit on current repository
actionguard audit . --html reports/actionguard-report.html --json reports/actionguard-report.json
```

> **Note**: Missing optional scanners fail gracefully without breaking the audit run.

---

## 🤖 5 Agentic AI Workflow Security Rules

| Rule ID | Name | Threat Category | Description |
| :--- | :--- | :--- | :--- |
| `AG-AI-001` | **Issue Comment Trigger** | Untrusted Trigger | Detects `issue_comment` triggers vulnerable to prompt injection |
| `AG-AI-002` | **Write-All Permissions** | Excessive Privilege | Flags `permissions: write-all` on AI workflow runners |
| `AG-AI-003` | **Unescaped Input in Shell** | Shell Injection | Identifies unescaped `${{ github.event.comment.body }}` in `run:` |
| `AG-AI-004` | **Dynamic Script Execution** | Code Execution | Detects AI generating and executing temporary shell scripts |
| `AG-AI-005` | **Secret Injected to AI** | Credential Exposure | Flags secrets passed to untrusted AI agent execution context |

---

## 📊 Pipeline Architecture & Workflow

```mermaid
%%{init: {'theme': 'dark', 'themeVariables': { 'primaryColor': '#1e293b', 'edgeLabelBackground':'#0f172a'}}}%%
flowchart TD
    Trigger["🚀 GitHub Push / PR Event"] --> Checkout["📦 Checkout Repository"]
    Checkout --> Orchestrator["🛡️ ActionGuard Engine"]
    
    subgraph Scanners["Scanners & Audit Modules"]
        direction TB
        Zizmor["zizmor GitHub Actions Scanner"]
        AgenticRules["5 Custom Agentic AI Rules"]
        SecretAudit["Secret Redaction Audit"]
        ArtifactAudit["Artifact Retention Audit"]
        CodeQuality["Ruff & Bandit Integration"]
    end
    
    Orchestrator --> Scanners
    Scanners --> Findings["📋 Normalized Findings"]
    Findings --> Scoring["📈 Risk Scoring (0-100)"]
    Scoring --> Remediation["🔧 Patch & Remediation Plan"]
    Remediation --> OutputJSON["📄 actionguard-report.json"]
    Remediation --> OutputHTML["📊 actionguard-report.html"]
```

---

## 🛠️ Security Rules & Multi-Scanner Integration

```mermaid
%%{init: {'theme': 'dark'}}%%
graph LR
    Core["🛡️ ActionGuard Engine"] --> Native["Built-in Security Scanners"]
    Core --> External["External Security Scanners"]

    Native --> R1["Agentic AI Workflow Audit"]
    Native --> R2["Env & Secret Exposure"]
    Native --> R3["Artifact Upload Security"]
    Native --> R4["Repository Hygiene"]

    External --> E1["zizmor (Actions Security)"]
    External --> E2["Ruff (Python Linter)"]
    External --> E3["Bandit (Code Security)"]
    External --> E4["npm audit & pip-audit"]
```

---

<details>
<summary><b>💻 Available CLI Commands</b> (Click to expand)</summary>

```bash
# Complete audit (HTML + JSON report)
actionguard audit .

# Alias for audit
actionguard scan .

# Re-render HTML from an existing JSON report
actionguard report --json actionguard-report.json --html actionguard-report.html

# Run via python module
python -m actionguard.cli audit . --html report.html --json report.json
```

Add `--email` to send HTML reports via SMTP when `MAIL_USERNAME`, `MAIL_PASSWORD`, and `REPORT_TO_EMAIL` environment variables are configured.

</details>

<details>
<summary><b>🔒 Safety & Redaction Model</b> (Click to expand)</summary>

- **Secret Redaction**: Credentials are automatically truncated to first six characters followed by `...redacted`.
- **Scan Safeguards**: Skips binary files, files > 1 MB, and build output directories (`node_modules`, `.venv`, `dist`).
- **Non-destructive**: ActionGuard never deletes `.env` files, rotates keys, or alters repository permissions automatically.

</details>

<details>
<summary><b>🧪 Demo & Test Fixtures</b> (Click to expand)</summary>

```bash
# Run audit on demo vulnerable repository
actionguard audit examples/demo-vulnerable-repo \
  --html reports/demo-report.html --json reports/demo-report.json

# Run unit test suite
pytest -q
```

</details>

---

## 🤝 Contributing

Contributions are very welcome! Whether it's adding new security rules, improving report visualizations, or integrating additional static analysis scanners:

1. Check out our [Contributing Guide](CONTRIBUTING.md) for local setup and testing instructions.
2. Open an issue or pull request using our templates.

---

## 📜 Upstream Attribution & License

ActionGuard uses [zizmor](https://github.com/zizmorcore/zizmor) as its core GitHub Actions scanner integration under its upstream license. See [NOTICE.md](NOTICE.md).

Distributed under the [MIT License](LICENSE).
