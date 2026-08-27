import re
from pathlib import Path

from actionguard.models import Finding, Severity
from actionguard.utils.yaml_utils import load_yaml

UNTRUSTED = [
    "github.event.issue.body",
    "github.event.issue.title",
    "github.event.pull_request.body",
    "github.event.pull_request.title",
    "github.event.comment.body",
]
AI = ["agent", "llm", "openai", "anthropic", "gemini", "copilot", "review-bot", "triage-bot", "ai-review", "autofix"]


def has_write(x):
    s = str(x).lower()
    return "write-all" in s or re.search(r"\bwrite\b", s) is not None


def line(text, needle):
    for i, s in enumerate(text.splitlines(), 1):
        if needle in s:
            return i
    return 1


def scan(repo_path: Path):
    out = []
    wd = repo_path / ".github/workflows"
    for p in list(wd.glob("*.y*ml")) if wd.exists() else []:
        data = load_yaml(p)
        text = p.read_text(errors="ignore")
        rp = p.relative_to(repo_path).as_posix()
        trigger = str(data.get("on", ""))
        global_perms = data.get("permissions", "")
        for name, job in (data.get("jobs", {}) or {}).items():
            js = str(job)
            low = (name + " " + js).lower()
            ai = any(k in low for k in AI)
            untrusted = [u for u in UNTRUSTED if u in js]
            secrets = "secrets." in js
            write = has_write(job.get("permissions", global_perms))
            if ai and untrusted:
                sev = Severity.CRITICAL if write or secrets else Severity.HIGH
                out.append(
                    Finding(
                        "AG-AI-001",
                        "actionguard",
                        "agentic",
                        sev,
                        "Untrusted event text reaches an AI agent",
                        rp,
                        line(text, untrusted[0]),
                        "Untrusted contexts: " + ", ".join(untrusted),
                        "An attacker can steer an agent through issue, PR, or comment content.",
                        "Treat event text as untrusted data, delimit it, validate instructions, and isolate the agent in a read-only job.",
                        True,
                        False,
                        "# Pass untrusted content through a validated data file; keep the agent job read-only.",
                    )
                )
            runs = "\n".join(str(s.get("run", "")) for s in (job.get("steps", []) or []))
            writes_agent_commands = re.search(
                r"(agent|llm|openai|anthropic|gemini).*?>\s*commands\.sh", runs, re.IGNORECASE | re.DOTALL
            )
            executes_commands = re.search(r"(?:bash|sh)\s+commands\.sh|\./commands\.sh", runs, re.IGNORECASE)
            evals_agent_output = re.search(r'eval\s+["\']?\$\([^)]*(?:agent|llm)', runs, re.IGNORECASE)
            if (writes_agent_commands and executes_commands) or evals_agent_output:
                out.append(
                    Finding(
                        "AG-AI-002",
                        "actionguard",
                        "agentic",
                        Severity.CRITICAL,
                        "AI output is executed as shell",
                        rp,
                        line(text, "commands.sh"),
                        "Agent output is written to or evaluated by a shell.",
                        "Prompt injection can become arbitrary code execution.",
                        "Never execute model output. Use a strict typed allowlist and require human approval for privileged operations.",
                        True,
                        False,
                        "- bash commands.sh\n+ python validate_plan.py commands.json\n+ # require_environment_approval",
                    )
                )
            cond = str(job.get("if", ""))
            if (
                ("issue_comment" in trigger or "issue_comment" in text)
                and "github.event.comment.body" in cond
                and "author_association" not in cond
            ):
                out.append(
                    Finding(
                        "AG-AI-003",
                        "actionguard",
                        "agentic",
                        Severity.HIGH,
                        "Comment-triggered privileged action lacks trust check",
                        rp,
                        line(text, "github.event.comment.body"),
                        "Comment command is accepted without author_association validation.",
                        "Any commenter may trigger a sensitive workflow.",
                        "Require OWNER, MEMBER, or COLLABORATOR association and use environment approval.",
                        True,
                        False,
                        """if: >\n  contains(github.event.comment.body, '/deploy') &&\n  contains(fromJson('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association)""",
                    )
                )
            if ai and write:
                out.append(
                    Finding(
                        "AG-AI-004",
                        "actionguard",
                        "agentic",
                        Severity.CRITICAL,
                        "AI agent job has write permissions",
                        rp,
                        line(text, "permissions:"),
                        "AI-related job can write repository resources.",
                        "Compromised model instructions can alter code, releases, or deployments.",
                        "Split analysis into a read-only job; gate writes behind a reviewed, narrowly-scoped job.",
                        True,
                        False,
                        "permissions:\n  contents: read",
                    )
                )
            if ai and secrets and untrusted:
                out.append(
                    Finding(
                        "AG-AI-005",
                        "actionguard",
                        "agentic",
                        Severity.CRITICAL,
                        "Secrets exposed to agent consuming untrusted input",
                        rp,
                        line(text, "secrets."),
                        "The same AI job receives secrets and attacker-controlled text.",
                        "Prompt injection may cause credential disclosure or misuse.",
                        "Remove secrets from the analysis job; use short-lived, scoped credentials only after approval.",
                        True,
                        False,
                        "# Remove secrets from the untrusted-input job and pass only approved outputs forward.",
                    )
                )
    return out
