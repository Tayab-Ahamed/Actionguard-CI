from pathlib import Path

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "dist", "build", "coverage", ".next", ".cache", ".tox", "target"}
MAX_TEXT_BYTES = 1_000_000
WORKFLOW_GLOBS = (".github/workflows/*.yml", ".github/workflows/*.yaml", "action.yml", "action.yaml")
TOOL_TIMEOUT = 180
REPORT_DIR = Path("reports")
