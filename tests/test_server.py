"""End to end through the HTTP app, the way a hub calls the sidecar."""

from __future__ import annotations

import base64
import contextlib
import json

import httpx

from stalwart_mcp.config import Config
from stalwart_mcp.server import build_app
from tests.conftest import PASSWORD, USER, png_bytes

HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


@contextlib.asynccontextmanager
async def serve(runtime):
    """Run the app's lifespan inside the test task.

    @gotcha Not a fixture: the MCP session managers use anyio task groups, which must be
            entered and exited in the same task. pytest-asyncio may tear an async fixture
            down in a different task ("Attempted to exit cancel scope in a different task").
    """
    app = build_app(Config(stalwart_url="http://fake"), runtime=runtime)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://stalwart-mcp:8000") as c:
            yield c


async def rpc(client, path, method, params=None, token=f"{USER}:{PASSWORD}"):
    headers = dict(HEADERS)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    resp = await client.post(path, headers=headers, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})
    assert resp.status_code == 200, resp.text
    return resp.json()["result"]


async def test_health_and_auth_check(runtime, fake):
    async with serve(runtime) as client:
        assert (await client.get("/health")).json()["status"] == "ok"
        ok = await client.get("/auth-check", headers={"Authorization": f"Bearer {USER}:{PASSWORD}"})
        assert ok.status_code == 200 and ok.json()["username"] == USER
        assert (await client.get("/auth-check")).status_code == 400
        bad = await client.get("/auth-check", headers={"Authorization": f"Bearer {USER}:wrong"})
        assert bad.status_code == 401 and bad.json()["error"] == "AUTH_REJECTED"
        again = await client.get("/auth-check", headers={"Authorization": f"Bearer {USER}:wrong"})
        assert again.status_code == 401 and fake.auth_failures == 1  # quarantined, not retried


async def test_tools_lists_on_both_endpoints(runtime):
    async with serve(runtime) as client:
        mail = await rpc(client, "/mcp", "tools/list")
        admin = await rpc(client, "/admin/mcp", "tools/list")
        assert len(mail["tools"]) == 21 and len(admin["tools"]) == 24
        send = next(t for t in mail["tools"] if t["name"] == "send_email")
        assert send["annotations"]["openWorldHint"] is True and "confirm_recipients" in send["inputSchema"]["required"]


async def test_tool_call_success_error_and_image(runtime, fake):
    async with serve(runtime) as client:
        fake.add_email(
            fake.acc_id,
            subject="Pic",
            from_=("A", "a@ext.org"),
            to=[("T", USER)],
            text="see",
            attachments=[("p.png", "image/png", png_bytes(400, 300))],
        )
        result = await rpc(client, "/mcp", "tools/call", {"name": "search_emails", "arguments": {"detail": "subjects"}})
        data = json.loads(result["content"][0]["text"])
        assert result.get("isError") in (None, False) and data["emails"][0]["subject"] == "Pic"
        eid = data["emails"][0]["id"]
        read = json.loads(
            (await rpc(client, "/mcp", "tools/call", {"name": "read_email", "arguments": {"email_ids": [eid]}}))["content"][0]["text"]
        )
        part = read["emails"][0]["attachments"][0]["partId"]
        loaded = await rpc(client, "/mcp", "tools/call", {"name": "load_attachment", "arguments": {"email_id": eid, "part_id": part}})
        image = loaded["content"][1]
        assert image["type"] == "image" and image["mimeType"] == "image/jpeg" and base64.b64decode(image["data"])[:2] == b"\xff\xd8"
        missing = await rpc(client, "/mcp", "tools/call", {"name": "account_info", "arguments": {}}, token=None)
        assert missing["isError"] is True and json.loads(missing["content"][0]["text"])["error"] == "CREDENTIAL_MISSING"
