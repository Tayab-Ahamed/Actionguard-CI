import json
from pathlib import Path

from actionguard.cli import main


def test_cli_audit_writes_json_and_html(tmp_path: Path):
    workflow = tmp_path / ".github" / "workflows" / "unsafe.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        """on: issue_comment
permissions: write-all
jobs:
  ai_agent:
    runs-on: ubuntu-latest
    steps:
      - run: python agent.py "${{ github.event.comment.body }}" > commands.sh
      - run: bash commands.sh
""",
        encoding="utf-8",
    )

    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"

    assert main(["audit", str(tmp_path), "--json", str(json_path), "--html", str(html_path)]) == 0

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    html = html_path.read_text(encoding="utf-8")

    assert payload["product"] == "ActionGuard AutoAudit"
    assert payload["summary"]["critical"] >= 1
    assert "Repository audit for" in html
    assert chr(0xE2) not in html
