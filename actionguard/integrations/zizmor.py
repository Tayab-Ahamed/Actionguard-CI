from pathlib import Path
import json
from actionguard.models import Finding, Severity
from .common import run_tool, tool_failure

MAP = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "info": Severity.INFO,
    "critical": Severity.CRITICAL,
}


def scan(repo: Path):
    p, status = run_tool("zizmor", ["--format=json-v1", "--no-exit-codes", "."], repo)
    if not p:
        return [tool_failure("zizmor", status, "cicd")], {"status": "failed", "detail": status}
    try:
        data = json.loads(p.stdout)
    except Exception:
        return [tool_failure("zizmor", f"parse error; exit {p.returncode}", "cicd")], {
            "status": "failed",
            "detail": "parse error",
        }
    out = []
    for item in data:
        locs = item.get("locations", [])
        primary = next((x for x in locs if x.get("symbolic", {}).get("kind") == "Primary"), locs[0] if locs else {})
        key = primary.get("symbolic", {}).get("key", {})
        local = key.get("Local", {}) if isinstance(key, dict) else {}
        file = local.get("verbatim_path", "")
        pt = primary.get("concrete", {}).get("location", {}).get("start_point", {})
        line = int(pt.get("row", 0)) + 1
        sev = MAP.get(str(item.get("determinations", {}).get("severity", "medium")).lower(), Severity.MEDIUM)
        out.append(
            Finding(
                "ZIZMOR-" + item.get("ident", "unknown").upper(),
                "zizmor",
                "cicd",
                sev,
                item.get("ident", "zizmor finding").replace("-", " ").title(),
                file,
                line,
                item.get("desc", ""),
                item.get("desc", "GitHub Actions security weakness."),
                f"Follow zizmor guidance: {item.get('url','https://docs.zizmor.sh/audits/')}",
                bool(item.get("fix")),
                False,
                metadata={"rule_url": item.get("url", "")},
            )
        )
    return out, {"status": "ok", "count": len(out)}
