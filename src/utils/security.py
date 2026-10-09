import secrets


def constant_time_equal(left: str, right: str) -> bool:
    """Compare security-sensitive strings in constant time."""
    return secrets.compare_digest(left.encode(), right.encode())
