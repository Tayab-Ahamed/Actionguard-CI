from pathlib import Path

import yaml

from actionguard.utils.yaml_utils import load_yaml


def test_actions_loader_does_not_change_global_safe_loader(tmp_path: Path):
    workflow = tmp_path / "workflow.yml"
    workflow.write_text("on: push\njobs: {}\n", encoding="utf-8")

    assert load_yaml(workflow)["on"] == "push"
    assert yaml.safe_load("enabled: true\n") == {"enabled": True}
    assert yaml.safe_load("enabled: false\n") == {"enabled": False}
