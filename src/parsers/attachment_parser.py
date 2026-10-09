from typing import Any

from src.utils.hashing import sha256_bytes


def parse_attachment(
    filename: str | None,
    content: bytes,
    *,
    content_type: str = "application/octet-stream",
    disposition: str | None = None,
    content_id: str | None = None,
) -> dict[str, Any]:
    """Raw metadata/content for local analyzers; filename is never a filesystem path."""
    return {
        "filename": filename,
        "size": len(content),
        "content_type": content_type,
        "disposition": disposition,
        "content_id": content_id,
        "sha256": sha256_bytes(content),
        "content": content,  # Raw-only analyzer bytes; never included in the API/LLM response.
    }
