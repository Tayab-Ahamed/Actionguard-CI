from pathlib import Path
import yaml
class ActionsLoader(yaml.SafeLoader): pass
for ch, resolvers in list(ActionsLoader.yaml_implicit_resolvers.items()):
    ActionsLoader.yaml_implicit_resolvers[ch]=[(tag,rx) for tag,rx in resolvers if tag!='tag:yaml.org,2002:bool']
def load_yaml(path: Path):
    try:
        res = yaml.load(path.read_text(encoding='utf-8'), Loader=ActionsLoader)
        return res if isinstance(res, dict) else {}
    except Exception:
        return {}
