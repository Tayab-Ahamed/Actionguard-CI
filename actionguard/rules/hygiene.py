from pathlib import Path
from actionguard.models import Finding, Severity

CHECKS = [
    ("README.md", Severity.LOW),
    ("LICENSE", Severity.LOW),
    (".gitignore", Severity.MEDIUM),
    ("SECURITY.md", Severity.LOW),
    ("CODEOWNERS", Severity.LOW),
    (".github/dependabot.yml", Severity.MEDIUM),
]


def scan(repo_path: Path):
    out = []
    for name, sev in CHECKS:
        exists = (repo_path / name).exists() or (name == "CODEOWNERS" and (repo_path / ".github/CODEOWNERS").exists())
        if not exists:
            out.append(
                Finding(
                    "AG-HYG-001",
                    "actionguard",
                    "hygiene",
                    sev,
                    f"Missing {name}",
                    name,
                    1,
                    f"{name} was not found.",
                    "Repository governance and maintenance controls are incomplete.",
                    f"Add {name} using the provided template.",
                    True,
                    True,
                    f"+++ {name}\n+# Add project-appropriate content",
                    False,
                )
            )
    wd = repo_path / ".github/workflows"
    if not wd.exists() or not any(wd.glob("*.y*ml")):
        out.append(
            Finding(
                "AG-HYG-002",
                "actionguard",
                "cicd",
                Severity.MEDIUM,
                "No CI workflow",
                ".github/workflows",
                1,
                "No workflow YAML found.",
                "Changes may merge without automated validation.",
                "Add a least-privilege test and audit workflow.",
                True,
                True,
                "+++ .github/workflows/ci.yml\n+permissions:\n+  contents: read",
                False,
            )
        )
    if (repo_path / "package.json").exists() and not (repo_path / "package-lock.json").exists():
        out.append(
            Finding(
                "AG-HYG-003",
                "actionguard",
                "dependencies",
                Severity.MEDIUM,
                "Node lockfile missing",
                "package-lock.json",
                1,
                "package.json exists without package-lock.json.",
                "Dependency resolution is not reproducible.",
                "Generate and commit a lockfile.",
                False,
                False,
            )
        )
    if ((repo_path / "requirements.txt").exists() or (repo_path / "pyproject.toml").exists()) and not any(
        (repo_path / x).exists() for x in ["uv.lock", "poetry.lock", "Pipfile.lock"]
    ):
        out.append(
            Finding(
                "AG-HYG-004",
                "actionguard",
                "dependencies",
                Severity.LOW,
                "Python lockfile missing",
                "",
                1,
                "Python dependency manifest exists without a recognized lockfile.",
                "Builds may resolve different transitive versions.",
                "Generate and commit a lockfile appropriate to the package manager.",
                False,
                False,
            )
        )
    return out
