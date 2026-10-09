import base64
import io
import re
from typing import Any, Protocol

import zxingcpp
from PIL import Image

from src.analyzers.attachment_analyzer import detect_magic
from src.analyzers.common import finding
from src.analyzers.url_analyzer import analyze_urls
from src.evidence.models import Evidence
from src.services.ioc_store import IOCClient

MAX_IMAGE_BYTES = 2 * 1024 * 1024
MAX_IMAGE_PIXELS = 4_000_000
MAX_IMAGES = 20
MAX_QR_PAYLOAD = 4096


class QRDecoder(Protocol):
    def decode(self, content: bytes) -> list[str]: ...


class LocalQRDecoder:
    def decode(self, content: bytes) -> list[str]:
        if len(content) > MAX_IMAGE_BYTES:
            raise ValueError("IMAGE_BYTE_LIMIT")
        with Image.open(io.BytesIO(content)) as image:
            if image.width * image.height > MAX_IMAGE_PIXELS or getattr(image, "n_frames", 1) != 1:
                raise ValueError("IMAGE_PIXEL_OR_FRAME_LIMIT")
            grayscale = image.convert("L")
            try:
                results = zxingcpp.read_barcodes(grayscale, formats=zxingcpp.BarcodeFormat.QRCode)
                if len(results) > 20 or any(len(result.text) > MAX_QR_PAYLOAD for result in results):
                    raise ValueError("QR_PAYLOAD_LIMIT")
                return [result.text for result in results]
            finally:
                grayscale.close()


def analyze_qr_codes(
    parsed_email: dict[str, Any],
    *,
    decoder: QRDecoder | None = None,
    ioc_client: IOCClient | None = None,
    protected_domains: tuple[str, ...] = (),
) -> list[Evidence]:
    """Decode bounded inline/attached images and pass URLs into local URL analysis."""
    decoder = decoder if decoder is not None else LocalQRDecoder()
    images: list[tuple[str, bytes]] = []
    output: list[Evidence] = []
    complete = True
    for index, item in enumerate(parsed_email.get("attachments", [])):
        content = item.get("content")
        if (item.get("content_type") or "").startswith("image/") or (
            isinstance(content, bytes) and detect_magic(content) in {"png", "jpeg", "gif"}
        ):
            if isinstance(content, bytes):
                images.append((f"image:attachment:{index}", content))
            else:
                complete = False
    for index, resource in enumerate(parsed_email.get("html", {}).get("resources", [])):
        if resource.lower().startswith("data:image/"):
            try:
                prefix, encoded = resource.split(",", 1)
                if not prefix.lower().endswith(";base64") or len(encoded) > MAX_IMAGE_BYTES * 4 // 3 + 4:
                    raise ValueError("Unsupported or oversized inline image")
                images.append((f"image:data-uri:{index}", base64.b64decode(encoded, validate=True)))
            except ValueError:
                complete = False
    if len(images) > MAX_IMAGES:
        complete = False
    for indicator, content in images[:MAX_IMAGES]:
        try:
            payloads = decoder.decode(content)
            if len(payloads) > 20 or any(len(text) > MAX_QR_PAYLOAD for text in payloads):
                raise ValueError("QR_PAYLOAD_LIMIT")
        except Exception:
            complete = False
            output.append(
                finding(
                    "qr",
                    "QR_DECODE",
                    "qr",
                    indicator,
                    {"error_code": "QR_DECODE_FAILED"},
                    "UNKNOWN",
                    status="ERROR",
                    tool="local_qr_decoder",
                )
            )
            continue
        output.append(
            finding(
                "qr",
                "QR_DECODE",
                "qr",
                indicator,
                {"decoded_payloads": payloads, "payload_count": len(payloads)},
                "PASS",
                tool="local_qr_decoder",
            )
        )
        urls = [url for text in payloads for url in re.findall(r"https?://[^\s<>]+", text, re.IGNORECASE)]
        if urls:
            output.extend(
                analyze_urls({"urls": urls}, ioc_client=ioc_client, protected_domains=protected_domains, analyzer="qr")
            )
    output.append(
        finding(
            "qr",
            "QR_ANALYSIS",
            "qr",
            "qr:local_checks",
            {"images": len(images)},
            "PASS" if complete else "UNKNOWN",
            tool="local_qr_decoder",
        )
    )
    return output
