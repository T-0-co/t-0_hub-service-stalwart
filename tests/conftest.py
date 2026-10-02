from __future__ import annotations

import io

import httpx
import pytest

from stalwart_mcp import jmap as jmap_module
from stalwart_mcp.config import Config
from stalwart_mcp.credentials import credential_from_headers
from stalwart_mcp.jmap import Jmap, Runtime
from tests.fake_jmap import FakeStalwart

USER = "techlog@example.com"
PASSWORD = "app-pass"


@pytest.fixture
def fake() -> FakeStalwart:
    f = FakeStalwart()
    acc = f.add_account(USER, password=PASSWORD, name=USER)
    f.add_identity(acc, USER, "Tech Log")
    f.add_identity(acc, "jd@example.com", "office/jd")
    f.acc_id = acc  # type: ignore[attr-defined]
    return f


@pytest.fixture
async def runtime(fake: FakeStalwart, monkeypatch):
    monkeypatch.setattr(jmap_module, "RATE_BACKOFF_SECONDS", 0.0)
    http = httpx.AsyncClient(transport=httpx.ASGITransport(app=fake.app), base_url="http://fake", follow_redirects=True)
    rt = Runtime(Config(stalwart_url="http://fake", max_rps=0, max_concurrent=4), http=http)
    yield rt
    await rt.aclose()


@pytest.fixture
def j(runtime: Runtime) -> Jmap:
    return Jmap(runtime, credential_from_headers({"authorization": f"Bearer {USER}:{PASSWORD}"}))


def tiny_pdf(text: str = "Hello PDF") -> bytes:
    content = f"BT /F1 24 Tf 72 720 Td ({text}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = b"%PDF-1.4\n"
    offsets = []
    for number, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    for offset in offsets:
        out += b"%010d 00000 n \n" % offset
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref)
    return out


def png_bytes(width: int = 2000, height: int = 1000) -> bytes:
    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGB", (width, height), (200, 30, 30)).save(buf, format="PNG")
    return buf.getvalue()
