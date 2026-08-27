from pathlib import Path

from actionguard.models import Finding, Severity
from actionguard.utils.yaml_utils import load_yaml

AI_GLOBS = [".env", "*.pem", "*.key", "credentials.json", "service-account.json", "logs/", "coverage/"]


def _line(text, needle):
    for i, s in enumerate(text.splitlines(), 1):
        if needle in s:
            return i
    return 1


def scan(repo_path: Path):
    out = []
    for p in (
        list((repo_path / ".github/workflows").glob("*.y*ml")) if (repo_path / ".github/workflows").exists() else []
    ):
        data = load_yaml(p)
        text = p.read_text(errors="ignore")
        rp = p.relative_to(repo_path).as_posix()
        for job in (data.get("jobs", {}) or {}).values():
            for step in job.get("steps", []) or []:
                if "actions/upload-artifact" not in str(step.get("uses", "")):
                    continue
                cfg = step.get("with", {}) or {}
                path = str(cfg.get("path", ""))
                retention = cfg.get("retention-days", cfg.get("retention_days"))
                if path.strip() in {".", "./", "${{ github.workspace }}"} or any(
                    x.strip() == "." for x in path.splitlines()
                ):
                    out.append(
                        Finding(
                            "AG-ART-001",
                            "actionguard",
                            "artifacts",
                            Severity.HIGH,
                            "Artifact uploads the whole repository",
                            rp,
                            _line(text, "upload-artifact"),
                            f"upload-artifact path: {path!r}",
                            "Secrets, source, and local configuration may be published as an artifact.",
                            "Upload an explicit allowlist of build outputs and exclude secret-bearing extensions.",
                            True,
                            False,
                            "path: |\n  dist/**\n  !dist/**/*.env\n  !dist/**/*.key\n  !dist/**/*.pem\nretention-days: 7",
                        )
                    )
                if any(s.lower() in path.lower() for s in AI_GLOBS):
                    out.append(
                        Finding(
                            "AG-ART-002",
                            "actionguard",
                            "artifacts",
                            Severity.HIGH,
                            "Sensitive artifact path",
                            rp,
                            _line(text, "path:"),
                            f"Artifact path may include sensitive content: {path}",
                            "Build artifacts can disclose credentials or operational logs.",
                            "Replace with an explicit output allowlist and exclusions.",
                            True,
                            False,
                            "path: |\n  dist/**\n  !dist/**/*.env\n  !dist/**/*.pem\n  !dist/**/*.key",
                        )
                    )
                try:
                    days = int(retention) if retention is not None else 0
                except (ValueError, TypeError):
                    days = 0
                if days > 30:
                    out.append(
                        Finding(
                            "AG-ART-003",
                            "actionguard",
                            "artifacts",
                            Severity.HIGH,
                            "Artifact retention is too long",
                            rp,
                            _line(text, "retention-days"),
                            f"retention-days: {days}",
                            "Sensitive data remains downloadable longer than necessary.",
                            "Reduce retention to 7 days or the minimum required.",
                            True,
                            True,
                            f"- retention-days: {days}\n+ retention-days: 7",
                            False,
                        )
                    )
    return out
