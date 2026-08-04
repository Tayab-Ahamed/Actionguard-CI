from pathlib import Path
from actionguard.rules.agentic import scan
def test_all_agentic_rules_detected(tmp_path:Path):
    p=tmp_path/'.github/workflows/x.yml';p.parent.mkdir(parents=True);p.write_text("""on: issue_comment
permissions: write-all
jobs:
  ai_agent:
    if: contains(github.event.comment.body, '/deploy')
    runs-on: ubuntu-latest
    steps:
      - env:
          API: ${{ secrets.API }}
        run: |
          python agent.py "${{ github.event.comment.body }}" > commands.sh
          bash commands.sh
""")
    ids={f.id for f in scan(tmp_path)}
    assert {'AG-AI-001','AG-AI-002','AG-AI-003','AG-AI-004','AG-AI-005'} <= ids
