from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    id: str
    source: str
    category: str
    severity: Severity
    title: str
    file: str = ""
    line: int = 1
    evidence: str = ""
    risk: str = ""
    recommendation: str = ""
    patch_available: bool = False
    auto_fix_safe: bool = False
    patch_preview: str = ""
    manual_review_required: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        d = asdict(self)
        d["severity"] = self.severity.value
        return d
