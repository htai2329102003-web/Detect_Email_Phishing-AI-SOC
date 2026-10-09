def normalize_domain(value: str) -> str:
    """Normalize a domain for deterministic comparison."""
    return value.strip().rstrip(".").lower()
