import hashlib


def sha256_bytes(content: bytes) -> str:
    """Return a lowercase SHA-256 digest for immutable byte content."""
    return hashlib.sha256(content).hexdigest()
