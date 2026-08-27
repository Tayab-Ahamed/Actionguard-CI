from collections import Counter

WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}
CATEGORIES = {
    "cicd": "cicd",
    "agentic": "cicd",
    "secrets": "secrets",
    "artifacts": "artifacts",
    "code_quality": "code_quality",
    "dependencies": "dependencies",
    "hygiene": "hygiene",
}


def calculate_scores(findings):
    def score(items):
        return max(0, 100 - sum(WEIGHTS[f.severity.value] for f in items))

    scores = {"overall": score(findings)}
    for out in ["cicd", "secrets", "artifacts", "code_quality", "dependencies", "hygiene"]:
        scores[out] = score([f for f in findings if CATEGORIES.get(f.category) == out])
    return scores


def severity_counts(findings):
    c = Counter(f.severity.value for f in findings)
    return {x: c.get(x, 0) for x in WEIGHTS}
