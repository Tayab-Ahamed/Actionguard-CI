def prioritize(findings):
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(findings, key=lambda f: (order[f.severity.value], f.category, f.file, f.line))


def checklist(findings):
    seen = set()
    out = []
    for f in prioritize(findings):
        if f.recommendation and f.recommendation not in seen:
            out.append(
                {
                    "finding_id": f.id,
                    "severity": f.severity.value,
                    "title": f.title,
                    "action": f.recommendation,
                    "auto_fix_safe": f.auto_fix_safe,
                    "manual_review_required": f.manual_review_required,
                    "patch_preview": f.patch_preview,
                }
            )
            seen.add(f.recommendation)
    return out
