from pathlib import Path
from actionguard.rules.env_files import scan


def test_env_and_gitignore(tmp_path: Path):
    (tmp_path / ".env").write_text("X=y")
    findings = scan(tmp_path)
    assert any(f.id == "AG-ENV-001" and f.severity.value == "critical" for f in findings)
    assert any(f.id == "AG-ENV-002" for f in findings)
