import re
from pathlib import Path

from actionguard.models import Finding, Severity
from actionguard.utils.file_utils import iter_files, read_text, rel
from actionguard.utils.redaction import redact

PATTERNS = [
    ("GitHub token", r"\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    ("AWS access key", r"\bAKIA[0-9A-Z]{16}\b"),
    ("OpenAI API key", r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    ("Google API key", r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    ("Private key", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ("JWT token", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ("Database URL with password", r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s:/]+:[^\s@]+@[^\s]+"),
    ("SMTP password", r'(?i)\b(?:SMTP_PASSWORD|MAIL_PASSWORD)\s*[:=]\s*["\']?[^\s"\']{8,}'),
    ("Stripe live key", r"\bsk_live_[A-Za-z0-9]{16,}\b"),
]


def scan(repo_path: Path):
    out = []
    for p in iter_files(repo_path):
        if p.name.startswith("actionguard-report"):
            continue
        text = read_text(p)
        if text is None:
            continue
        for label, rx in PATTERNS:
            for m in re.finditer(rx, text):
                line = text.count("\n", 0, m.start()) + 1
                preview = redact(m.group(0))
                out.append(
                    Finding(
                        "AG-SEC-001",
                        "actionguard",
                        "secrets",
                        Severity.CRITICAL,
                        f"{label} detected",
                        rel(p, repo_path),
                        line,
                        f"Redacted match: {preview}",
                        "A usable credential may be exposed to anyone with repository access.",
                        "Revoke or rotate the credential immediately, remove it from history, and use GitHub encrypted secrets.",
                        False,
                        False,
                        manual_review_required=True,
                    )
                )
    return out
