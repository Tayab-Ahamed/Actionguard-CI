import json
from actionguard.models import Finding, Severity
from .common import run_tool, tool_failure

M = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def scan(repo):
    if not (repo / "package-lock.json").exists():
        return [], {"status": "skipped"}
    p, s = run_tool("npm", ["audit", "--json"], repo)
    if not p:
        return [tool_failure("npm audit", s, "dependencies")], {"status": "failed"}
    try:
        v = json.loads(p.stdout or "{}").get("vulnerabilities", {})
    except (json.JSONDecodeError, ValueError, AttributeError):
        return [tool_failure("npm audit", "parse error", "dependencies")], {"status": "failed"}
    out = [
        Finding(
            "NPM-" + name.upper(),
            "npm-audit",
            "dependencies",
            M.get(x.get("severity"), Severity.MEDIUM),
            f"Vulnerable Node dependency: {name}",
            "package-lock.json",
            1,
            str(x.get("via", ""))[:300],
            "A vulnerable dependency can compromise runtime or build systems.",
            f"Upgrade {name} to a non-vulnerable version and retest.",
            True,
            False,
        )
        for name, x in v.items()
    ]
    return out, {"status": "ok", "count": len(out)}
