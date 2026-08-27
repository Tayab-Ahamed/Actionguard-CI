import json
from actionguard.models import Finding, Severity
from .common import run_tool, tool_failure


def scan(repo):
    manifest = "requirements.txt" if (repo / "requirements.txt").exists() else None
    if not manifest:
        return [], {"status": "skipped"}
    p, s = run_tool("pip-audit", ["-r", manifest, "-f", "json"], repo)
    if not p:
        return [tool_failure("pip-audit", s, "dependencies")], {"status": "failed"}
    try:
        data = json.loads(p.stdout or "{}").get("dependencies", [])
    except (json.JSONDecodeError, ValueError, AttributeError):
        return [tool_failure("pip-audit", "parse error", "dependencies")], {"status": "failed"}
    out = []
    for dep in data:
        for v in dep.get("vulns", []):
            out.append(
                Finding(
                    "PIP-" + v.get("id", ""),
                    "pip-audit",
                    "dependencies",
                    Severity.HIGH,
                    f"Vulnerable Python dependency: {dep.get('name')}",
                    manifest,
                    1,
                    v.get("description", "")[:400],
                    "Known dependency vulnerability.",
                    "Upgrade to a fixed version: " + ", ".join(v.get("fix_versions", []) or ["see advisory"]),
                    True,
                    False,
                )
            )
    return out, {"status": "ok", "count": len(out)}
