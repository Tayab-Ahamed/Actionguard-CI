from pathlib import Path
from actionguard.rules.secrets import scan
def test_secret_never_printed(tmp_path:Path):
    secret='ghp_1234567890abcdefghijklmnopqrstuvwxyz';(tmp_path/'x.txt').write_text(secret)
    out=scan(tmp_path); blob=str([f.to_dict() for f in out])
    assert out and secret not in blob and '...redacted' in blob
