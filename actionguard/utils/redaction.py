def redact(value: str) -> str:
    if not value:
        return "...redacted"
    return value[:6] + "...redacted"
