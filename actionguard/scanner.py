from pathlib import Path
from actionguard.rules import agentic, artifacts, env_files, hygiene, secrets
from actionguard.integrations import zizmor, ruff, bandit, npm_audit, pip_audit
from actionguard.scoring import calculate_scores


class AuditResult:
    def __init__(self, findings, statuses):
        self.findings = findings
        self.statuses = statuses
        self.scores = calculate_scores(findings)


def audit(repo_path: Path):
    repo_path = repo_path.resolve()
    findings = []
    statuses = {}
    for name, module in [
        ("env_files", env_files),
        ("secrets", secrets),
        ("artifacts", artifacts),
        ("agentic", agentic),
        ("hygiene", hygiene),
    ]:
        try:
            found = module.scan(repo_path)
            findings.extend(found)
            statuses[name] = {"status": "ok", "count": len(found)}
        except Exception as e:
            statuses[name] = {"status": "failed", "detail": str(e)}
    for name, module in [
        ("zizmor", zizmor),
        ("ruff", ruff),
        ("bandit", bandit),
        ("npm_audit", npm_audit),
        ("pip_audit", pip_audit),
    ]:
        try:
            found, status = module.scan(repo_path)
            findings.extend(found)
            statuses[name] = status
        except Exception as e:
            statuses[name] = {"status": "failed", "detail": str(e)}
    return AuditResult(findings, statuses)
