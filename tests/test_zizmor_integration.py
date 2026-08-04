import json
from types import SimpleNamespace

from actionguard.integrations import zizmor
from actionguard.models import Severity


def test_zizmor_json_v1_is_normalized(monkeypatch, tmp_path):
    raw = [
        {
            "ident": "template-injection",
            "desc": "Untrusted expression reaches a shell.",
            "url": "https://docs.zizmor.sh/audits/template-injection/",
            "determinations": {"severity": "high"},
            "locations": [
                {
                    "symbolic": {
                        "kind": "Primary",
                        "key": {"Local": {"verbatim_path": ".github/workflows/ci.yml"}},
                    },
                    "concrete": {"location": {"start_point": {"row": 6}}},
                }
            ],
            "fix": {"kind": "manual"},
        }
    ]

    def fake_run_tool(name, args, cwd):
        return SimpleNamespace(stdout=json.dumps(raw), returncode=0), 0

    monkeypatch.setattr(zizmor, "run_tool", fake_run_tool)

    findings, status = zizmor.scan(tmp_path)

    assert status == {"status": "ok", "count": 1}
    assert findings[0].id == "ZIZMOR-TEMPLATE-INJECTION"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].file == ".github/workflows/ci.yml"
    assert findings[0].line == 7
    assert findings[0].patch_available is True
