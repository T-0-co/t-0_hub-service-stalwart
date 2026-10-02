"""Attachment content for the model: text extraction, images, embedded mails."""

from __future__ import annotations

import asyncio
import base64
import io
from typing import Any

from .render import html_to_text, truncate

TEXT_TYPES = (
    "text/",
    "application/json",
    "application/xml",
    "application/x-yaml",
    "application/yaml",
    "application/csv",
    "application/ics",
    "application/x-sh",
    "application/javascript",
    "message/delivery-status",
    "message/disposition-notification",
)
TEXT_EXTENSIONS = (".txt", ".csv", ".tsv", ".json", ".xml", ".ics", ".md", ".log", ".yaml", ".yml", ".eml", ".vcf", ".html", ".htm")
IMAGE_TYPES = ("image/png", "image/jpeg", "image/gif", "image/webp")
MAX_IMAGE_EDGE = 1568
MAX_IMAGE_BYTES = 1_000_000
MAX_PDF_PAGES = 60
EXTRACT_TIMEOUT = 20.0


def kind_of(mime: str | None, name: str | None) -> str:
    mime = (mime or "").lower()
    name = (name or "").lower()
    if mime == "message/rfc822" or name.endswith(".eml"):
        return "email"
    if mime == "application/pdf" or name.endswith(".pdf"):
        return "pdf"
    if mime in IMAGE_TYPES or name.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp")):
        return "image"
    if mime.startswith(TEXT_TYPES) or name.endswith(TEXT_EXTENSIONS):
        return "html" if ("html" in mime or name.endswith((".html", ".htm"))) else "text"
    return "binary"


def decode_text(data: bytes, charset: str | None) -> str:
    for enc in [charset, "utf-8", "cp1252", "latin-1"]:
        if not enc:
            continue
        try:
            return data.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue
    return data.decode("utf-8", errors="replace")


def _pdf_text(data: bytes) -> tuple[str, int, int]:
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(data))
    pages = len(reader.pages)
    chunks = []
    for i, page in enumerate(reader.pages[:MAX_PDF_PAGES], start=1):
        try:
            text = page.extract_text() or ""
        except Exception:  # pypdf raises a zoo of errors on broken PDFs
            text = "[page could not be read]"
        chunks.append(f"--- page {i} ---\n{text.strip()}")
    return "\n\n".join(chunks), pages, min(pages, MAX_PDF_PAGES)


def _image(data: bytes) -> tuple[str, str, dict[str, Any]]:
    """Downscale to what a vision model can use. Returns (base64, mime, info)."""
    from PIL import Image

    with Image.open(io.BytesIO(data)) as img:
        info = {"width": img.width, "height": img.height, "format": img.format}
        img = img.convert("RGB") if img.mode not in ("RGB", "L") else img
        if max(img.size) > MAX_IMAGE_EDGE:
            img.thumbnail((MAX_IMAGE_EDGE, MAX_IMAGE_EDGE))
        for quality in (85, 70, 55):
            buf = io.BytesIO()
            img.save(buf, format="JPEG", quality=quality, optimize=True)
            if buf.tell() <= MAX_IMAGE_BYTES:
                break
        info["sent_as"] = f"{img.width}x{img.height} JPEG"
        return base64.b64encode(buf.getvalue()).decode(), "image/jpeg", info


async def extract(kind: str, data: bytes, *, charset: str | None, max_chars: int) -> dict[str, Any]:
    """Run the (blocking) extraction off the event loop with a time limit."""

    def work() -> dict[str, Any]:
        if kind == "pdf":
            text, pages, read = _pdf_text(data)
            text, cut = truncate(text, max_chars)
            return {"text": text, "pages": pages, "pages_read": read, "truncated": cut or None}
        if kind in ("text", "html"):
            text = decode_text(data, charset)
            if kind == "html":
                text = html_to_text(text)
            text, cut = truncate(text, max_chars)
            return {"text": text, "truncated": cut or None}
        if kind == "image":
            b64, mime, info = _image(data)
            return {"image_b64": b64, "image_mime": mime, "image": info}
        return {}

    return await asyncio.wait_for(asyncio.to_thread(work), timeout=EXTRACT_TIMEOUT)
