import json

from actionguard.models import Finding, Severity

from .common import run_tool, tool_failure

M = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}


def scan(repo):
    if not any(repo.rglob("*.py")):
        return [], {"status": "skipped"}
    p, s = run_tool("bandit", ["-r", "actionguard", "-f", "json"], repo)
    if not p:
        return [tool_failure("bandit", s)], {"status": "failed"}
    try:
        data = json.loads(p.stdout or "{}").get("results", [])
    except (json.JSONDecodeError, ValueError, AttributeError):
        return [tool_failure("bandit", "parse error")], {"status": "failed"}
    return [
        Finding(
            "BANDIT-" + x.get("test_id", ""),
            "bandit",
            "code_quality",
            M.get(x.get("issue_severity"), Severity.MEDIUM),
            x.get("issue_text", "Bandit finding"),
            x.get("filename", ""),
            x.get("line_number", 1),
            x.get("code", "")[:240],
            "Potentially insecure Python construct.",
            x.get("more_info", "Review and replace the risky construct."),
        )
        for x in data
    ], {"status": "ok", "count": len(data)}
