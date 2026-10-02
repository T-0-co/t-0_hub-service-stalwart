"""Live tests against a real Stalwart account. Opt-in:

    STALWART_LIVE_URL=https://mail.example.com \
    STALWART_LIVE_USER=test@example.com STALWART_LIVE_PASS=app-password \
    uv run pytest -m live tests/test_live.py -v

@warn Use a throwaway mailbox. The tests send mail to the account itself, create and
      delete a folder and a Sieve script, and move/delete the mails they sent.
@warn One wrong password can get the source IP banned by Stalwart (for every account
      behind it). The first test checks the credential once; every later test is
      skipped if that fails, and the client never retries a rejected credential.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid

import pytest

from stalwart_mcp import ops
from stalwart_mcp.config import Config
from stalwart_mcp.credentials import credential_from_headers
from stalwart_mcp.errors import AuthRejected
from stalwart_mcp.jmap import Jmap, Runtime

pytestmark = pytest.mark.live

URL = os.environ.get("STALWART_LIVE_URL", "")
USER = os.environ.get("STALWART_LIVE_USER", "")
PASS = os.environ.get("STALWART_LIVE_PASS", "")
STATE: dict = {}


def client() -> Jmap:
    if not (URL and USER and PASS):
        pytest.skip("STALWART_LIVE_URL/USER/PASS not set")
    if STATE.get("auth_failed"):
        pytest.skip("credential was rejected in the first test")
    runtime = Runtime(Config(stalwart_url=URL.rstrip("/"), max_rps=2, max_concurrent=2))
    return Jmap(runtime, credential_from_headers({"authorization": f"Bearer {USER}:{PASS}"}))


async def _wait_for(j: Jmap, subject: str, mailbox: str = "inbox", tries: int = 15) -> dict:
    for _ in range(tries):
        found = await ops.search_emails(j, subject=subject, mailbox=mailbox, detail="summary", limit=5)
        if found["emails"]:
            return found["emails"][0]
        await asyncio.sleep(2)
    raise AssertionError(f"mail '{subject}' did not arrive in {mailbox}")


async def test_01_credential_once():
    j = client()
    try:
        session = await j.session()
    except AuthRejected:
        STATE["auth_failed"] = True
        raise
    assert session.username
    info = await ops.account_info(j)
    STATE["identity"] = info["identities"][0]["email"]
    assert info["identities"]


async def test_02_read_paths():
    j = client()
    boxes = await ops.list_mailboxes(j)
    assert any(b.get("role") == "inbox" for b in boxes["mailboxes"])
    found = await ops.search_emails(j, detail="subjects", limit=3)
    if found["emails"]:
        eid = found["emails"][0]["id"]
        full = await ops.read_email(j, [eid])
        assert full["emails"][0]["id"] == eid
        headers = await ops.read_email(j, [eid], detail="headers")
        assert headers["emails"][0].get("headers")
        thread = await ops.get_thread(j, email_id=eid)
        assert thread["count"] >= 1


async def test_03_send_to_self_move_flag_delete():
    j = client()
    me = STATE["identity"]
    tag = f"stalwart-mcp live {uuid.uuid4().hex[:8]}"
    start = await ops.list_changes(j)
    draft = await ops.write_email(j, to=[me], subject=tag, body="Live test. Safe to delete.")
    sent = await ops.send_email(j, draft["draft_id"], [me])
    assert sent["sent"]
    received = await _wait_for(j, tag)
    changes = await ops.list_changes(j, since_state=start["state"])
    assert received["id"] in [e["id"] for e in changes["created"] + changes["updated"]]

    folder = f"MCP-Test-{int(time.time())}"
    made = await ops.manage_mailbox(j, "create", name=folder)
    try:
        moved = await ops.move_emails(j, [received["id"]], folder)
        assert moved["moved"] == 1
        await ops.set_flags(j, [received["id"]], flagged=True, seen=True)
        again = await ops.read_email(j, [received["id"]], detail="summary")
        assert "flagged" in again["emails"][0]["flags"]
        await ops.delete_emails(j, [received["id"]])
        await ops.delete_emails(j, [received["id"]], permanent=True)
    finally:
        await ops.delete_mailbox(j, made["id"])
    sent_copy = await _wait_for(j, tag, mailbox="sent", tries=3)
    await ops.delete_emails(j, [sent_copy["id"]])
    await ops.delete_emails(j, [sent_copy["id"]], permanent=True)


async def test_04_sieve_roundtrip_inactive():
    j = client()
    name = f"mcp-live-{uuid.uuid4().hex[:6]}"
    script = 'require ["fileinto"];\nif header :contains "subject" "mcp-live-never-matches" { fileinto "INBOX"; }\n'
    saved = await ops.save_filter(j, name, script, activate=False)
    assert saved["saved"] and saved["valid"]
    listed = await ops.list_filters(j)
    assert any(f["name"] == name for f in listed["filters"])
    bad = await ops.save_filter(j, name, "if { broken", activate=False)
    assert bad["saved"] is False
    await ops.delete_filter(j, name)
    leftovers = [f["name"] for f in (await ops.list_filters(j, include_content=False))["filters"]]
    if f"{name}.previous" in leftovers:
        await ops.delete_filter(j, f"{name}.previous")
