import io
import re
import zipfile
from pathlib import PurePosixPath
from typing import Any

from src.analyzers.common import finding, ioc_evidence
from src.evidence.models import Evidence
from src.services.ioc_store import IOCClient, UnconfiguredIOCClient
from src.utils.hashing import sha256_bytes

MAX_ARCHIVE_ENTRIES = 100
MAX_ARCHIVE_DEPTH = 2
MAX_ARCHIVE_EXPANDED = 20 * 1024 * 1024
MAX_NESTED_READ = 1024 * 1024
MAX_NESTED_BUDGET = 4 * 1024 * 1024
EXECUTABLE = {
    ".exe",
    ".com",
    ".scr",
    ".pif",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".jse",
    ".wsf",
    ".lnk",
    ".msi",
    ".hta",
}
ARCHIVES = {".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar"}
MAGIC_EXTENSIONS = {
    ".pdf": "pdf",
    ".png": "png",
    ".jpg": "jpeg",
    ".jpeg": "jpeg",
    ".gif": "gif",
    ".zip": "zip",
    ".docx": "zip",
    ".xlsx": "zip",
    ".pptx": "zip",
    ".docm": "zip",
    ".xlsm": "zip",
    ".pptm": "zip",
    ".doc": "ole",
    ".xls": "ole",
    ".ppt": "ole",
    ".exe": "pe",
}
MIME_TYPES = {
    ".pdf": {"application/pdf"},
    ".png": {"image/png"},
    ".jpg": {"image/jpeg"},
    ".jpeg": {"image/jpeg"},
    ".gif": {"image/gif"},
    ".zip": {"application/zip", "application/x-zip-compressed"},
    ".txt": {"text/plain"},
    ".csv": {"text/csv", "text/plain"},
    ".exe": {"application/x-msdownload", "application/vnd.microsoft.portable-executable"},
}
MAGIC_MIMES = {
    "pdf": {"application/pdf"},
    "png": {"image/png"},
    "jpeg": {"image/jpeg"},
    "gif": {"image/gif"},
    "pe": {"application/x-msdownload", "application/vnd.microsoft.portable-executable"},
}


def detect_magic(content: bytes) -> str | None:
    signatures = (
        (b"MZ", "pe"),
        (b"\x7fELF", "elf"),
        (b"%PDF-", "pdf"),
        (b"\x89PNG\r\n\x1a\n", "png"),
        (b"\xff\xd8\xff", "jpeg"),
        (b"GIF87a", "gif"),
        (b"GIF89a", "gif"),
        (b"PK\x03\x04", "zip"),
        (b"PK\x05\x06", "zip"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    )
    return next((kind for signature, kind in signatures if content.startswith(signature)), None)


def _zip_metadata(content: bytes) -> tuple[dict[str, Any], str]:
    """List ZIP contents; read only bounded nested ZIPs, never extract to disk."""
    metadata = {
        "entries": [],
        "limit_exceeded": False,
        "encrypted": False,
        "macro_members": [],
        "dangerous_members": [],
    }
    budget = {"entries": 0, "expanded": 0, "read": 0}

    def visit(data, depth):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) + budget["entries"] > MAX_ARCHIVE_ENTRIES:
                metadata["limit_exceeded"] = True
                return
            for item in infos:
                budget["entries"] += 1
                budget["expanded"] += item.file_size
                if budget["expanded"] > MAX_ARCHIVE_EXPANDED or item.file_size > max(1, item.compress_size) * 100:
                    metadata["limit_exceeded"] = True
                    return
                name = item.filename
                suffix = PurePosixPath(name.replace("\\", "/")).suffix.lower()
                metadata["entries"].append(
                    {"name": name, "size": item.file_size, "compressed_size": item.compress_size, "depth": depth}
                )
                if item.flag_bits & 1:
                    metadata["encrypted"] = True
                if name.lower().endswith("vbaproject.bin"):
                    metadata["macro_members"].append(name)
                if (
                    suffix in EXECUTABLE
                    or ".." in PurePosixPath(name.replace("\\", "/")).parts
                    or name.startswith(("/", "\\"))
                ):
                    metadata["dangerous_members"].append(name)
                if suffix in ARCHIVES and not item.is_dir():
                    if (
                        suffix != ".zip"
                        or depth >= MAX_ARCHIVE_DEPTH
                        or item.file_size > MAX_NESTED_READ
                        or item.flag_bits & 1
                    ):
                        metadata["limit_exceeded"] = True
                        return
                    if budget["read"] + item.file_size > MAX_NESTED_BUDGET:
                        metadata["limit_exceeded"] = True
                        return
                    with archive.open(item) as stream:
                        nested = stream.read(MAX_NESTED_READ + 1)
                    budget["read"] += len(nested)
                    if len(nested) > MAX_NESTED_READ:
                        metadata["limit_exceeded"] = True
                        return
                    visit(nested, depth + 1)

    try:
        visit(content, 0)
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError, ValueError, EOFError):
        metadata["invalid_archive"] = True
        return metadata, "UNKNOWN"
    return metadata, "UNKNOWN" if metadata["limit_exceeded"] or metadata["encrypted"] else "PASS"


def analyze_attachments(parsed_email: dict[str, Any], *, ioc_client: IOCClient | None = None) -> list[Evidence]:
    """Read bounded bytes only; no execution, file uploads, or active PDF/OLE parsing."""
    output: list[Evidence] = []
    complete = True
    client = ioc_client if ioc_client is not None else UnconfiguredIOCClient()
    attachments = parsed_email.get("attachments", [])
    for index, item in enumerate(attachments):
        content = item.get("content")
        indicator = f"attachment:{index}:{item.get('sha256', 'unknown')}"
        if not isinstance(content, bytes):
            complete = False
            continue
        digest = sha256_bytes(content)
        filename = item.get("filename") or ""
        suffixes = PurePosixPath(filename.replace("\\", "/")).suffixes
        extension = suffixes[-1].lower() if suffixes else ""
        mime = (item.get("content_type") or "application/octet-stream").lower()
        magic = detect_magic(content)
        metadata = {
            "filename": filename,
            "extension": extension,
            "mime": mime,
            "magic": magic,
            "sha256": digest,
            "size": len(content),
        }
        output.append(finding("attachment", "ATTACHMENT_METADATA", "attachment", indicator, metadata, "PASS"))
        signals = []
        if extension in EXECUTABLE or magic in {"pe", "elf"}:
            signals.append("ATTACHMENT_EXECUTABLE")
        if len(suffixes) >= 2 and extension in EXECUTABLE:
            signals.append("ATTACHMENT_DOUBLE_EXTENSION")
        if ".." in PurePosixPath(filename.replace("\\", "/")).parts or any(
            char in filename for char in "\u202a\u202b\u202d\u202e\u2066\u2067\u2068\u2069"
        ):
            signals.append("ATTACHMENT_FILENAME_DECEPTION")
        if mime != "application/octet-stream" and extension in MIME_TYPES and mime not in MIME_TYPES[extension]:
            signals.append("ATTACHMENT_MIME_MISMATCH")
        if (extension in MAGIC_EXTENSIONS and MAGIC_EXTENSIONS[extension] != magic) or (
            magic in MAGIC_MIMES and mime not in MAGIC_MIMES[magic] | {"application/octet-stream"}
        ):
            signals.append("ATTACHMENT_MAGIC_MISMATCH")
        if magic == "pdf":
            # Lexical indicators only; not a complete parser of compressed/encrypted PDF objects.
            tokens = sorted(
                set(
                    match.decode("ascii")
                    for match in re.findall(rb"/(?:JavaScript|JS|OpenAction|AA|Launch|EmbeddedFile)\b", content)
                )
            )
            if tokens:
                output.append(
                    finding(
                        "attachment",
                        "PDF_ACTIVE_METADATA",
                        "attachment",
                        indicator,
                        {"tokens": tokens, "inspection": "lexical_only"},
                        confidence=0.8,
                    )
                )
        if magic == "zip":
            archive, status = _zip_metadata(content)
            output.append(finding("attachment", "ARCHIVE_INSPECTION", "attachment", indicator, archive, status))
            if status == "UNKNOWN":
                complete = False
            if archive["macro_members"]:
                signals.append("OFFICE_MACRO_MEMBER")
            if archive["dangerous_members"]:
                signals.append("ARCHIVE_DANGEROUS_MEMBER")
        elif extension in ARCHIVES or magic == "ole":
            complete = False
            output.append(
                finding(
                    "attachment",
                    "ARCHIVE_INSPECTION",
                    "attachment",
                    indicator,
                    {"inspection": "unsupported_archive_or_ole", "magic": magic},
                    "UNKNOWN",
                )
            )
        for signal in signals:
            output.append(finding("attachment", signal, "attachment", indicator, metadata))
        output.extend(ioc_evidence("attachment", indicator, [("hash", digest)], client, "ATTACHMENT_IOC_CHECK"))
    output.append(
        finding(
            "attachment",
            "ATTACHMENT_ANALYSIS",
            "attachment",
            "attachment:static_checks",
            {"checked": len(attachments)},
            "PASS" if complete else "UNKNOWN",
        )
    )
    return output
