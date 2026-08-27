from pathlib import Path
from actionguard.config import MAX_TEXT_BYTES, SKIP_DIRS


def iter_files(root: Path):
    for p in root.rglob("*"):
        if not p.is_file() or any(part in SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        if p.stat().st_size > MAX_TEXT_BYTES:
            continue
        yield p


def read_text(path: Path):
    try:
        data = path.read_bytes()
        if b"\x00" in data[:4096]:
            return None
        return data.decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def rel(path: Path, root: Path):
    return path.relative_to(root).as_posix()
