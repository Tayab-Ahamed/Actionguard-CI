from pathlib import Path
from actionguard.rules.artifacts import scan
def test_whole_repo_and_retention(tmp_path:Path):
    p=tmp_path/'.github/workflows/a.yml';p.parent.mkdir(parents=True);p.write_text("""on: push
jobs:
  x:
    steps:
      - uses: actions/upload-artifact@v4
        with:
          path: .
          retention-days: 90
""")
    ids={f.id for f in scan(tmp_path)}; assert {'AG-ART-001','AG-ART-003'}<=ids
