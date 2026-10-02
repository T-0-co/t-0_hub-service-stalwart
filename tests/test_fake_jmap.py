"""Self-tests for the Stalwart JMAP fake (tests/fake_jmap.py)."""

from __future__ import annotations

import base64
import email
import email.policy
from urllib.parse import quote

import httpx
import pytest

from tests.fake_jmap import BLOB, CORE, MAIL, QUOTA, SIEVE, SUBMISSION, VACATION, FakeStalwart

pytestmark = pytest.mark.asyncio

USER, PASSWORD, TOKEN = "techlog@example.com", "app-pass", "tok-123"
ALL = [CORE, MAIL, SUBMISSION, VACATION, SIEVE, QUOTA, BLOB]


def make_fake() -> tuple[FakeStalwart, str]:
    fake = FakeStalwart()
    acc = fake.add_account(username=USER, password=PASSWORD, name=USER, tokens=[TOKEN])
    fake.add_identity(acc, email=USER, name="Tech Log")
    fake.add_identity(acc, email="alias@example.com", name="office/jd")
    return fake, acc


def seed_hello(fake: FakeStalwart, acc: str) -> str:
    return fake.add_email(
        acc,
        mailboxes=["inbox"],
        subject="Hello",
        from_=("Alice", "alice@ext.org"),
        to=[("Tech Log", USER)],
        text="plain body",
        html="<p>plain <b>body</b></p>",
        attachments=[("invoice.pdf", "application/pdf", b"%PDF-1.4 ...")],
        received_at="2026-09-30T10:00:00Z",
        keywords={"$seen": True},
        headers={
            "List-Unsubscribe": "<https://ext.org/u/1>, <mailto:unsub@ext.org>",
            "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
        },
        message_id="m1@ext.org",
    )


def client(fake: FakeStalwart, auth: object = (USER, PASSWORD)) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=fake.app), base_url="http://fake", auth=auth)


async def call(c: httpx.AsyncClient, calls: list, using: list[str] | None = None) -> list:
    r = await c.post("/jmap/", json={"using": using or ALL, "methodCalls": calls})
    assert r.status_code == 200, r.text
    return r.json()["methodResponses"]


async def one(c: httpx.AsyncClient, name: str, args: dict, using: list[str] | None = None) -> dict:
    [[resp_name, resp, _]] = await call(c, [[name, args, "0"]], using)
    assert resp_name == name, resp
    return resp


# ---------------------------------------------------------------- session & auth


async def test_redirect_and_session() -> None:
    fake, acc = make_fake()
    async with client(fake) as c:
        r = await c.get("/.well-known/jmap")
        assert r.status_code == 307
        assert r.headers["location"] == "http://fake/jmap/session"
        r = await c.get("/.well-known/jmap", follow_redirects=True)
        session = r.json()
    assert set(session["capabilities"]) == set(ALL)
    assert session["capabilities"][CORE]["maxCallsInRequest"] == 16
    assert session["capabilities"][CORE]["maxObjectsInGet"] == 500
    assert session["capabilities"][SUBMISSION] == {"maxDelayedSend": 0, "submissionExtensions": {}}
    account = session["accounts"][acc]
    assert account["isPersonal"] is True and account["isReadOnly"] is False
    assert account["accountCapabilities"][MAIL]["mayCreateTopLevelMailbox"] is True
    assert "subject" in account["accountCapabilities"][MAIL]["emailQuerySortOptions"]
    assert all(session["primaryAccounts"][cap] == acc for cap in ALL)
    assert session["username"] == USER
    assert session["apiUrl"] == "http://fake/jmap/"
    assert session["downloadUrl"] == "http://fake/jmap/download/{accountId}/{blobId}/{name}?accept={type}"
    assert session["uploadUrl"] == "http://fake/jmap/upload/{accountId}/"
    assert "{types}" in session["eventSourceUrl"] and session["state"]


async def test_basic_and_bearer_auth_and_401_counter() -> None:
    fake, _ = make_fake()
    async with client(fake, auth=None) as c:
        basic = base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
        r = await c.get("/jmap/session", headers={"Authorization": f"Basic {basic}"})
        assert r.status_code == 200
        r = await c.get("/jmap/session", headers={"Authorization": f"Bearer {TOKEN}"})
        assert r.status_code == 200 and r.json()["username"] == USER
        r = await c.get("/jmap/session", headers={"Authorization": "Bearer nope"})
        assert r.status_code == 401
        assert r.json() == {"type": "about:blank", "status": 401, "title": "Unauthorized", "detail": "You have to authenticate first."}
        wrong = base64.b64encode(f"{USER}:wrong".encode()).decode()
        r = await c.post("/jmap/", headers={"Authorization": f"Basic {wrong}"}, json={})
        assert r.status_code == 401
        r = await c.get("/jmap/session")
        assert r.status_code == 401
    assert fake.auth_failures == 3
    assert fake.http_log[0] == ("GET", "/jmap/session", 200, True)
    assert fake.http_log[-1] == ("GET", "/jmap/session", 401, False)


async def test_request_level_errors_and_capability_gating() -> None:
    fake, acc = make_fake()
    async with client(fake) as c:
        # Identity/get needs the submission capability; Stalwart answers unknownMethod.
        [resp] = await call(c, [["Identity/get", {"accountId": acc}, "0"]], [CORE, MAIL])
        assert resp == ["error", {"type": "unknownMethod"}, "0"]
        identities = await one(c, "Identity/get", {"accountId": acc}, [CORE, MAIL, SUBMISSION])
        assert [i["email"] for i in identities["list"]] == [USER, "alias@example.com"]
        assert identities["list"][1]["name"] == "office/jd"
        [resp] = await call(c, [["Nope/get", {"accountId": acc}, "0"]])
        assert resp[1] == {"type": "unknownMethod"}
        [resp] = await call(c, [["Mailbox/get", {"accountId": "a999"}, "0"]])
        assert resp[1] == {"type": "accountNotFound"}

        r = await c.post("/jmap/", content=b"{not json")
        assert r.status_code == 400 and r.json()["type"] == "urn:ietf:params:jmap:error:notJSON"
        r = await c.post("/jmap/", json={"using": [CORE], "methodCalls": [["Core/echo", {}]]})
        assert r.status_code == 400 and r.json()["type"] == "urn:ietf:params:jmap:error:notRequest"
        r = await c.post("/jmap/", json={"using": ["urn:example:nope"], "methodCalls": []})
        assert r.status_code == 400 and r.json()["type"] == "urn:ietf:params:jmap:error:unknownCapability"
        r = await c.post("/jmap/", json={"using": [CORE], "methodCalls": [["Core/echo", {}, str(i)] for i in range(17)]})
        assert r.status_code == 400
        assert r.json()["type"] == "urn:ietf:params:jmap:error:limit"
        assert r.json()["limit"] == "maxCallsInRequest"
        echo = await one(c, "Core/echo", {"hello": True}, [CORE])
        assert echo == {"hello": True}
    assert fake.calls[:3] == ["Identity/get", "Identity/get", "Nope/get"]


# ---------------------------------------------------------------- Email/query


async def test_query_filters_sorting_and_header_quirk() -> None:
    fake, acc = make_fake()
    e1 = seed_hello(fake, acc)
    e2 = fake.add_email(
        acc,
        subject="Invoice March",
        from_=("Billing", "billing@shop.example"),
        to=[USER],
        cc=[("Carl", "carl@ext.org")],
        text="Your invoice is attached.",
        received_at="2026-09-29T08:00:00Z",
    )
    e3 = fake.add_email(
        acc,
        mailboxes=["archive"],
        subject="archived note",
        from_="zed@ext.org",
        to=[USER],
        text="nothing",
        received_at="2026-09-28T08:00:00Z",
        keywords={"$Flagged": True, "$seen": True},
    )
    async with client(fake) as c:

        async def ids(flt: dict | None = None, **kw: object) -> list[str]:
            return (await one(c, "Email/query", {"accountId": acc, "filter": flt, **kw}))["ids"]

        assert await ids() == [e1, e2, e3]  # default: receivedAt descending
        assert await ids({"inMailbox": fake.mailbox_id(acc, "inbox")}) == [e1, e2]
        assert await ids({"inMailboxOtherThan": [fake.mailbox_id(acc, "inbox")]}) == [e3]
        assert await ids({"from": "ALICE"}) == [e1]
        assert await ids({"cc": "carl@"}) == [e2]
        assert await ids({"text": "invoice"}) == [e2]  # subject + body
        assert await ids({"text": "billing@shop"}) == [e2]  # address
        assert await ids({"body": "plain"}) == [e1]
        assert await ids({"subject": "march"}) == [e2]
        assert await ids({"notKeyword": "$seen"}) == [e2]
        assert await ids({"hasKeyword": "$flagged"}) == [e3]
        assert await ids({"hasAttachment": True}) == [e1]
        assert await ids({"after": "2026-09-29T08:00:00Z"}) == [e1, e2]
        assert await ids({"before": "2026-09-29T08:00:00Z"}) == [e3]
        assert await ids({"minSize": fake.email(acc, e1)["size"]}) == [e1]
        assert await ids({"operator": "OR", "conditions": [{"from": "alice"}, {"from": "zed"}]}) == [e1, e3]
        assert await ids({"operator": "NOT", "conditions": [{"from": "alice"}]}) == [e2, e3]
        assert await ids(sort=[{"property": "subject", "isAscending": True}]) == [e3, e1, e2]
        assert await ids(sort=[{"property": "receivedAt"}]) == [e3, e2, e1]  # isAscending defaults to true

        page = await one(c, "Email/query", {"accountId": acc, "position": 1, "limit": 1, "calculateTotal": True})
        assert page["ids"] == [e2] and page["total"] == 3 and page["position"] == 1
        assert page["canCalculateChanges"] is True and page["queryState"] == fake.email_state(acc)

        # QUIRK: any `header` condition silently matches nothing, without an error.
        quirk = await one(
            c,
            "Email/query",
            {
                "accountId": acc,
                "calculateTotal": True,
                "filter": {"operator": "OR", "conditions": [{"from": "alice"}, {"header": ["List-Unsubscribe"]}]},
            },
        )
        assert quirk["ids"] == [] and quirk["total"] == 0

        [err] = await call(c, [["Email/query", {"accountId": acc, "filter": {"bogus": 1}}, "0"]])
        assert err[1]["type"] == "unsupportedFilter"
        [err] = await call(c, [["Email/query", {"accountId": acc, "sort": [{"property": "nope"}]}, "0"]])
        assert err[1]["type"] == "unsupportedSort"


async def test_collapse_threads() -> None:
    fake, acc = make_fake()
    root = fake.add_email(
        acc, subject="Topic", from_="a@ext.org", to=[USER], text="1", message_id="root@ext.org", received_at="2026-09-01T00:00:00Z"
    )
    reply = fake.add_email(
        acc,
        subject="Re: Topic",
        from_="b@ext.org",
        to=[USER],
        text="2",
        in_reply_to="root@ext.org",
        references=["root@ext.org"],
        received_at="2026-09-02T00:00:00Z",
    )
    other = fake.add_email(acc, subject="Other", from_="c@ext.org", to=[USER], text="3", received_at="2026-09-03T00:00:00Z")
    assert fake.email(acc, root)["threadId"] == fake.email(acc, reply)["threadId"]
    assert fake.email(acc, other)["threadId"] != fake.email(acc, root)["threadId"]
    async with client(fake) as c:
        full = await one(c, "Email/query", {"accountId": acc})
        collapsed = await one(c, "Email/query", {"accountId": acc, "collapseThreads": True, "calculateTotal": True})
        threads = await one(c, "Thread/get", {"accountId": acc, "ids": [fake.email(acc, root)["threadId"]]})
    assert full["ids"] == [other, reply, root]
    assert collapsed["ids"] == [other, reply] and collapsed["total"] == 2
    assert threads["list"] == [{"id": fake.email(acc, root)["threadId"], "emailIds": [root, reply]}]


# ---------------------------------------------------------------- Email/get


async def test_email_get_structure_headers_and_quirks_a_b() -> None:
    fake, acc = make_fake()
    e1 = seed_hello(fake, acc)
    text_only = fake.add_email(acc, subject="t", from_="x@ext.org", to=[USER], text="just text")
    html_only = fake.add_email(acc, subject="h", from_="x@ext.org", to=[USER], html="<div>Hi <i>there</i></div>")
    async with client(fake) as c:
        full = await one(
            c,
            "Email/get",
            {
                "accountId": acc,
                "ids": [e1, "nope"],
                "fetchTextBodyValues": True,
                "fetchHTMLBodyValues": True,
                "properties": [
                    "subject",
                    "from",
                    "to",
                    "messageId",
                    "sentAt",
                    "receivedAt",
                    "keywords",
                    "hasAttachment",
                    "preview",
                    "bodyStructure",
                    "textBody",
                    "htmlBody",
                    "attachments",
                    "bodyValues",
                    "headers",
                    "header:List-Unsubscribe:asURLs",
                    "header:List-Unsubscribe-Post:asText",
                    "header:Subject:all",
                    "header:From:asAddresses",
                    "header:Message-ID:asMessageIds",
                ],
            },
        )
        assert full["notFound"] == ["nope"]
        [msg] = full["list"]
        assert msg["id"] == e1 and msg["subject"] == "Hello"
        assert msg["from"] == [{"name": "Alice", "email": "alice@ext.org"}]
        assert msg["messageId"] == ["m1@ext.org"] and msg["sentAt"] == "2026-09-30T10:00:00Z"
        assert msg["receivedAt"] == "2026-09-30T10:00:00Z" and msg["keywords"] == {"$seen": True}
        assert msg["hasAttachment"] is True and msg["preview"] == "plain body"
        assert msg["header:List-Unsubscribe:asURLs"] == ["https://ext.org/u/1", "mailto:unsub@ext.org"]
        assert msg["header:List-Unsubscribe-Post:asText"] == "List-Unsubscribe=One-Click"
        assert msg["header:Subject:all"] == [" Hello"]  # Raw form keeps the leading space
        assert msg["header:From:asAddresses"] == [{"name": "Alice", "email": "alice@ext.org"}]
        assert msg["header:Message-ID:asMessageIds"] == ["m1@ext.org"]
        assert {"name": "List-Unsubscribe-Post", "value": " List-Unsubscribe=One-Click"} in msg["headers"]
        structure = msg["bodyStructure"]
        assert structure["type"] == "multipart/mixed" and structure["partId"] is None
        assert [p["type"] for p in structure["subParts"]] == ["multipart/alternative", "application/pdf"]
        assert [p["type"] for p in msg["textBody"]] == ["text/plain"]
        assert [p["type"] for p in msg["htmlBody"]] == ["text/html"]
        [att] = msg["attachments"]
        assert att["name"] == "invoice.pdf" and att["type"] == "application/pdf"
        assert att["disposition"] == "attachment" and att["size"] == len(b"%PDF-1.4 ...")
        assert att["charset"] is None and att["blobId"]
        text_part, html_part = msg["textBody"][0]["partId"], msg["htmlBody"][0]["partId"]
        assert msg["bodyValues"][text_part] == {"value": "plain body", "isEncodingProblem": False, "isTruncated": False}
        assert msg["bodyValues"][html_part]["value"] == "<p>plain <b>body</b></p>"

        # QUIRK A: properties without bodyValues -> no bodyValues, fetch flags notwithstanding.
        [lean] = (
            await one(c, "Email/get", {"accountId": acc, "ids": [e1], "fetchAllBodyValues": True, "properties": ["subject", "textBody"]})
        )["list"]
        assert "bodyValues" not in lean and set(lean) == {"id", "subject", "textBody"}

        # QUIRK B: bodyProperties trims every body part list, attachments included.
        [trim] = (
            await one(
                c,
                "Email/get",
                {"accountId": acc, "ids": [e1], "bodyProperties": ["partId", "type"], "properties": ["attachments", "textBody"]},
            )
        )["list"]
        assert trim["attachments"] == [{"partId": att["partId"], "type": "application/pdf"}]
        assert trim["textBody"] == [{"partId": text_part, "type": "text/plain"}]

        [cut] = (
            await one(
                c,
                "Email/get",
                {"accountId": acc, "ids": [e1], "fetchTextBodyValues": True, "maxBodyValueBytes": 5, "properties": ["bodyValues"]},
            )
        )["list"]
        assert cut["bodyValues"][text_part] == {"value": "plain", "isEncodingProblem": False, "isTruncated": True}

        defaults = await one(c, "Email/get", {"accountId": acc, "ids": [text_only, html_only]})
        plain, html = defaults["list"]
        assert "headers" not in plain and "bodyStructure" not in plain and plain["bodyValues"] == {}
        assert plain["textBody"] == plain["htmlBody"] and plain["textBody"][0]["type"] == "text/plain"
        assert plain["attachments"] == [] and plain["hasAttachment"] is False
        # HTML-only: textBody falls back to the HTML part (RFC 8621 4.1.4).
        assert [p["type"] for p in html["textBody"]] == ["text/html"] and html["preview"] == "Hi there"

        [err] = await call(c, [["Email/get", {"accountId": acc, "ids": [e1], "properties": ["bogus"]}, "0"]])
        assert err[1]["type"] == "invalidArguments"


# ---------------------------------------------------------------- Email/set


async def test_create_draft_quirk_c_and_valid_draft() -> None:
    fake, acc = make_fake()
    original = seed_hello(fake, acc)
    drafts = fake.mailbox_id(acc, "drafts")
    async with client(fake) as c:
        r = await c.post(f"/jmap/upload/{acc}/", content=b"col1,col2\n1,2\n", headers={"Content-Type": "text/csv"})
        upload = r.json()
        assert upload["accountId"] == acc and upload["type"] == "text/csv" and upload["size"] == 14
        common = {
            "mailboxIds": {drafts: True},
            "keywords": {"$draft": True, "$Seen": True},
            "from": [{"name": "Tech Log", "email": USER}],
            "to": [{"name": "Alice", "email": "alice@ext.org"}],
            "bcc": [{"name": None, "email": "boss@example.com"}],
            "subject": "Re: Hello",
            "inReplyTo": ["m1@ext.org"],
            "references": ["m1@ext.org"],
        }
        resp = await one(
            c,
            "Email/set",
            {
                "accountId": acc,
                "create": {
                    # QUIRK C: partId + charset on any body part -> invalidProperties ["bodyStructure"].
                    "bad": {
                        **common,
                        "bodyStructure": {"type": "text/plain", "partId": "1", "charset": "utf-8"},
                        "bodyValues": {"1": {"value": "Hi"}},
                    },
                    "bad2": {
                        **common,
                        "textBody": [{"partId": "t", "type": "text/plain", "charset": "utf-8"}],
                        "bodyValues": {"t": {"value": "Hi"}},
                    },
                    "good": {
                        **common,
                        "header:X-Mailer:asText": "fake-client/1.0",
                        "textBody": [{"partId": "t", "type": "text/plain"}],
                        "htmlBody": [{"partId": "h", "type": "text/html"}],
                        "attachments": [{"blobId": upload["blobId"], "type": "text/csv", "name": "data.csv"}],
                        "bodyValues": {"t": {"value": "Thanks Alice!\n"}, "h": {"value": "<p>Thanks Alice!</p>"}},
                    },
                    "nobox": {**common, "mailboxIds": {}, "textBody": [{"partId": "t"}], "bodyValues": {"t": {"value": "x"}}},
                    "noblob": {**common, "attachments": [{"blobId": "bnope", "type": "image/png"}]},
                },
            },
        )
    assert resp["notCreated"]["bad"]["type"] == "invalidProperties"
    assert resp["notCreated"]["bad"]["properties"] == ["bodyStructure"]
    assert resp["notCreated"]["bad2"]["properties"] == ["bodyStructure"]
    assert resp["notCreated"]["nobox"]["properties"] == ["mailboxIds"]
    assert resp["notCreated"]["noblob"] == {"type": "blobNotFound", "notFound": ["bnope"]}
    created = resp["created"]["good"]
    assert set(created) == {"id", "blobId", "threadId", "size"}
    assert resp["oldState"] != resp["newState"] == fake.email_state(acc)
    stored = fake.email(acc, created["id"])
    assert created["threadId"] == fake.email(acc, original)["threadId"]  # threaded via inReplyTo
    assert stored["keywords"] == {"$draft": True, "$seen": True}
    assert stored["bcc"] == [{"name": None, "email": "boss@example.com"}]
    assert b"\r\nBcc: boss@example.com\r\n" in stored["raw"] and b"X-Mailer: fake-client/1.0" in stored["raw"]
    assert stored["size"] == len(stored["raw"]) == created["size"]
    assert [a["name"] for a in stored["attachments"]] == ["data.csv"]
    assert stored["bodyStructure"]["type"] == "multipart/mixed"
    assert stored["preview"] == "Thanks Alice!" and stored["hasAttachment"] is True
    parsed = email.message_from_bytes(stored["raw"], policy=email.policy.default)
    assert parsed["In-Reply-To"] == "<m1@ext.org>"


async def test_email_patch_updates_lowercase_keywords_and_destroy() -> None:
    fake, acc = make_fake()
    eid = seed_hello(fake, acc)
    inbox, archive = fake.mailbox_id(acc, "inbox"), fake.mailbox_id(acc, "archive")
    async with client(fake) as c:
        resp = await one(
            c,
            "Email/set",
            {
                "accountId": acc,
                "update": {
                    eid: {"keywords/$Junk": True, "keywords/$seen": None, f"mailboxIds/{archive}": True, f"mailboxIds/{inbox}": None}
                },
            },
        )
        assert resp["updated"] == {eid: None} and resp["notUpdated"] is None
        assert fake.email(acc, eid)["keywords"] == {"$junk": True}
        assert fake.email(acc, eid)["mailboxIds"] == {archive: True}
        await one(c, "Email/set", {"accountId": acc, "update": {eid: {"keywords": {"$Flagged": True}}}})
        assert fake.email(acc, eid)["keywords"] == {"$flagged": True}
        resp = await one(c, "Email/set", {"accountId": acc, "update": {eid: {f"mailboxIds/{archive}": None}, "nope": {"keywords": {}}}})
        assert resp["notUpdated"][eid]["type"] == "invalidProperties"  # would leave mailboxIds empty
        assert resp["notUpdated"][eid]["properties"] == ["mailboxIds"]
        assert resp["notUpdated"]["nope"]["type"] == "notFound"
        resp = await one(c, "Email/set", {"accountId": acc, "update": {eid: {"subject": "changed"}}})
        assert resp["notUpdated"][eid]["properties"] == ["subject"]
        [err] = await call(c, [["Email/set", {"accountId": acc, "ifInState": "s0", "destroy": [eid]}, "0"]])
        assert err[1]["type"] == "stateMismatch"
        resp = await one(c, "Email/set", {"accountId": acc, "destroy": [eid, "nope"]})
        assert resp["destroyed"] == [eid] and resp["notDestroyed"]["nope"]["type"] == "notFound"
    assert fake.account(acc).threads == {}


# ---------------------------------------------------------------- Email/changes


async def test_email_changes_and_max_changes() -> None:
    fake, acc = make_fake()
    e1 = seed_hello(fake, acc)
    since = fake.email_state(acc)
    e2 = fake.add_email(acc, subject="two", from_="x@ext.org", to=[USER], text="2")
    async with client(fake) as c:
        await one(c, "Email/set", {"accountId": acc, "update": {e1: {"keywords/$flagged": True}}})
        e3 = fake.add_email(acc, subject="three", from_="x@ext.org", to=[USER], text="3")
        await one(c, "Email/set", {"accountId": acc, "destroy": [e3]})
        changes = await one(c, "Email/changes", {"accountId": acc, "sinceState": since})
        assert changes["oldState"] == since and changes["newState"] == fake.email_state(acc)
        assert changes["created"] == [e2] and changes["updated"] == [e1] and changes["destroyed"] == []
        assert changes["hasMoreChanges"] is False
        first = await one(c, "Email/changes", {"accountId": acc, "sinceState": since, "maxChanges": 1})
        assert first["created"] == [e2] and first["updated"] == [] and first["hasMoreChanges"] is True
        rest = await one(c, "Email/changes", {"accountId": acc, "sinceState": first["newState"], "maxChanges": 5})
        assert rest["updated"] == [e1] and rest["hasMoreChanges"] is False
        assert rest["newState"] == fake.email_state(acc)
        noop = await one(c, "Email/changes", {"accountId": acc, "sinceState": fake.email_state(acc)})
        assert noop["created"] == noop["updated"] == noop["destroyed"] == []


async def test_email_changes_unknown_state_quirk_d_and_method_error_mode() -> None:
    fake, acc = make_fake()
    seed_hello(fake, acc)
    batch = [["Mailbox/get", {"accountId": acc}, "m"], ["Email/changes", {"accountId": acc, "sinceState": "bogus"}, "c"]]
    async with client(fake) as c:
        # QUIRK D: an unknown sinceState fails the WHOLE request with HTTP 400.
        r = await c.post("/jmap/", json={"using": ALL, "methodCalls": batch})
        assert r.status_code == 400
        assert r.json()["type"] == "urn:ietf:params:jmap:error:invalidArguments"
        fake.changes_mode = "method_error"
        responses = await call(c, batch)
    assert responses[0][0] == "Mailbox/get"
    assert responses[1] == ["error", {"type": "cannotCalculateChanges"}, "c"]


# ---------------------------------------------------------------- result references


async def test_back_references() -> None:
    fake, acc = make_fake()
    root = fake.add_email(
        acc, subject="Topic", from_="a@ext.org", to=[USER], text="1", message_id="r@ext.org", received_at="2026-09-01T00:00:00Z"
    )
    reply = fake.add_email(
        acc, subject="Re: Topic", from_="b@ext.org", to=[USER], text="2", references=["r@ext.org"], received_at="2026-09-02T00:00:00Z"
    )
    async with client(fake) as c:
        responses = await call(
            c,
            [
                ["Email/query", {"accountId": acc, "collapseThreads": True}, "q"],
                [
                    "Email/get",
                    {"accountId": acc, "properties": ["threadId"], "#ids": {"resultOf": "q", "name": "Email/query", "path": "/ids"}},
                    "g1",
                ],
                ["Thread/get", {"accountId": acc, "#ids": {"resultOf": "g1", "name": "Email/get", "path": "/list/*/threadId"}}, "t"],
                [
                    "Email/get",
                    {
                        "accountId": acc,
                        "properties": ["subject"],
                        "#ids": {"resultOf": "t", "name": "Thread/get", "path": "/list/*/emailIds"},
                    },
                    "g2",
                ],
                ["Email/get", {"accountId": acc, "#ids": {"resultOf": "q", "name": "Email/get", "path": "/ids"}}, "bad-name"],
                ["Email/get", {"accountId": acc, "#ids": {"resultOf": "q", "name": "Email/query", "path": "/nope"}}, "bad-path"],
                ["Email/get", {"accountId": acc, "#ids": {"resultOf": "zzz", "name": "Email/query", "path": "/ids"}}, "bad-call"],
            ],
        )
    assert responses[1][1]["list"] == [{"id": reply, "threadId": fake.email(acc, root)["threadId"]}]
    assert [m["id"] for m in responses[3][1]["list"]] == [root, reply]
    for response in responses[4:]:
        assert response[0] == "error" and response[1] == {"type": "invalidResultReference"}


# ---------------------------------------------------------------- EmailSubmission


def draft(acc: str, fake: FakeStalwart, sender: str = USER, **extra: object) -> dict:
    return {
        "mailboxIds": {fake.mailbox_id(acc, "drafts"): True},
        "keywords": {"$draft": True, "$seen": True},
        "from": [{"name": "Tech Log", "email": sender}],
        "to": [{"name": "Alice", "email": "alice@ext.org"}],
        "cc": [{"email": "carl@ext.org"}],
        "bcc": [{"email": "boss@example.com"}],
        "subject": "Report",
        "textBody": [{"partId": "1", "type": "text/plain"}],
        "bodyValues": {"1": {"value": "Done."}},
        **extra,
    }


async def test_submission_success_with_on_success_update_email() -> None:
    fake, acc = make_fake()
    identity = next(i for i, v in fake.account(acc).identities.items() if v["email"] == USER)
    drafts, sent = fake.mailbox_id(acc, "drafts"), fake.mailbox_id(acc, "sent")
    async with client(fake) as c:
        responses = await call(
            c,
            [
                ["Email/set", {"accountId": acc, "create": {"draft": draft(acc, fake)}}, "0"],
                [
                    "EmailSubmission/set",
                    {
                        "accountId": acc,
                        "create": {"sub": {"emailId": "#draft", "identityId": identity}},
                        "onSuccessUpdateEmail": {
                            "#sub": {f"mailboxIds/{drafts}": None, f"mailboxIds/{sent}": True, "keywords/$draft": None}
                        },
                    },
                    "1",
                ],
            ],
        )
    assert [r[0] for r in responses] == ["Email/set", "EmailSubmission/set", "Email/set"]
    email_id = responses[0][1]["created"]["draft"]["id"]
    created = responses[1][1]["created"]["sub"]
    assert created["undoStatus"] == "final" and created["id"] and created["sendAt"]
    assert responses[2][2] == "1" and responses[2][1]["updated"] == {email_id: None}
    assert fake.email(acc, email_id)["mailboxIds"] == {sent: True}
    assert fake.email(acc, email_id)["keywords"] == {"$seen": True}
    [out] = fake.outbox
    assert out["account"] == acc and out["email_id"] == email_id and out["identity_id"] == identity
    assert out["envelope"] == {"mailFrom": USER, "rcptTo": ["alice@ext.org", "carl@ext.org", "boss@example.com"]}
    assert b"Bcc: boss@example.com" in out["raw"]  # stored raw is transmitted as-is
    async with client(fake) as c:
        subs = await one(c, "EmailSubmission/get", {"accountId": acc, "ids": None})
    assert subs["list"][0]["envelope"]["rcptTo"][0] == {"email": "alice@ext.org", "parameters": None}


async def test_submission_forbidden_from_and_no_recipients() -> None:
    fake, acc = make_fake()
    ids = {v["email"]: i for i, v in fake.account(acc).identities.items()}
    async with client(fake) as c:
        responses = await call(
            c,
            [
                ["Email/set", {"accountId": acc, "create": {"d1": draft(acc, fake), "d2": draft(acc, fake, to=[], cc=[], bcc=[])}}, "0"],
                [
                    "EmailSubmission/set",
                    {
                        "accountId": acc,
                        "create": {
                            "wrong": {"emailId": "#d1", "identityId": ids["alias@example.com"]},
                            "empty": {"emailId": "#d2", "identityId": ids[USER]},
                            "noid": {"emailId": "#d1", "identityId": "i999"},
                        },
                    },
                    "1",
                ],
            ],
        )
    not_created = responses[1][1]["notCreated"]
    assert not_created["wrong"]["type"] == "forbiddenFrom"
    assert not_created["empty"]["type"] == "noRecipients"
    assert not_created["noid"]["type"] == "invalidProperties"
    assert responses[1][1]["created"] is None and fake.outbox == []


async def test_submission_invalid_result_reference_quirk() -> None:
    fake, acc = make_fake()
    identity = next(iter(fake.account(acc).identities))
    broken = draft(acc, fake, textBody=[{"partId": "1", "type": "text/plain", "charset": "utf-8"}])
    async with client(fake) as c:
        responses = await call(
            c,
            [
                ["Email/set", {"accountId": acc, "create": {"draft": broken}}, "0"],
                [
                    "EmailSubmission/set",
                    {
                        "accountId": acc,
                        "create": {"sub": {"emailId": "#draft", "identityId": identity}},
                        "onSuccessUpdateEmail": {"#sub": {"keywords/$draft": None}},
                    },
                    "1",
                ],
            ],
        )
    assert responses[0][1]["notCreated"]["draft"]["type"] == "invalidProperties"
    # QUIRK: a method-level error, not an EmailSubmission/set response with notCreated.
    assert responses[1] == ["error", {"type": "invalidResultReference"}, "1"]
    assert len(responses) == 2 and fake.outbox == []


# ---------------------------------------------------------------- Sieve & Blob

VALID_SIEVE = 'require ["fileinto"];\nif header :contains "subject" "[spam]" {\n  fileinto "Junk";\n}\n'


async def test_blob_upload_reference_and_sieve_lifecycle() -> None:
    fake, acc = make_fake()
    async with client(fake) as c:
        responses = await call(
            c,
            [
                [
                    "Blob/upload",
                    {
                        "accountId": acc,
                        "create": {
                            "k": {"data": [{"data:asText": VALID_SIEVE}], "type": "application/sieve"},
                            "bad": {"data": [{"data:asBase64": base64.b64encode(b"if true { stop;").decode()}]},
                        },
                    },
                    "0",
                ],
                [
                    "SieveScript/set",
                    {"accountId": acc, "create": {"s": {"name": "main", "blobId": "#k"}}, "onSuccessActivateScript": "#s"},
                    "1",
                ],
                ["SieveScript/validate", {"accountId": acc, "blobId": "#k"}, "2"],
                ["SieveScript/validate", {"accountId": acc, "blobId": "#bad"}, "3"],
                ["SieveScript/set", {"accountId": acc, "create": {"x": {"name": "broken", "blobId": "#bad"}}}, "4"],
            ],
        )
        uploaded = responses[0][1]["created"]
        assert uploaded["k"]["type"] == "application/sieve" and uploaded["k"]["size"] == len(VALID_SIEVE)
        script = responses[1][1]["created"]["s"]
        assert script["isActive"] is True and script["blobId"] == uploaded["k"]["id"]
        assert responses[2][1] == {"accountId": acc, "error": None}
        assert responses[3][1]["error"]["type"] == "invalidSieve"
        assert responses[4][1]["notCreated"]["x"]["type"] == "invalidSieve"
        assert fake.blob(acc, script["blobId"]).decode() == VALID_SIEVE

        second = fake.add_sieve_script(acc, "vacation", 'if anyof (true) { keep; } # "comment\n')
        resp = await one(c, "SieveScript/set", {"accountId": acc, "destroy": [script["id"]]})
        assert resp["notDestroyed"][script["id"]]["type"] == "scriptIsActive"
        resp = await one(c, "SieveScript/set", {"accountId": acc, "onSuccessActivateScript": second})
        assert resp["updated"] == {script["id"]: {"isActive": False}, second: {"isActive": True}}
        active = await one(c, "SieveScript/query", {"accountId": acc, "filter": {"isActive": True}})
        assert active["ids"] == [second]
        resp = await one(c, "SieveScript/set", {"accountId": acc, "destroy": [script["id"]], "onSuccessDeactivateScript": True})
        assert resp["destroyed"] == [script["id"]] and resp["updated"] == {second: {"isActive": False}}
        scripts = await one(c, "SieveScript/get", {"accountId": acc, "ids": None})
        assert [(s["name"], s["isActive"]) for s in scripts["list"]] == [("vacation", False)]
        dup = await one(
            c, "SieveScript/set", {"accountId": acc, "create": {"d": {"name": "vacation", "blobId": scripts["list"][0]["blobId"]}}}
        )
        assert dup["notCreated"]["d"]["type"] == "alreadyExists"
        bad = fake.add_sieve_script(acc, "tmp", "keep;")
        upd = await one(c, "SieveScript/set", {"accountId": acc, "update": {bad: {"isActive": True}}})
        assert upd["notUpdated"][bad]["type"] == "invalidProperties"
        for text in ('keep "unterminated;', "if true { keep; ]", "SYNTAX_ERROR"):
            blob_id = (await c.post(f"/jmap/upload/{acc}/", content=text.encode())).json()["blobId"]
            result = await one(c, "SieveScript/validate", {"accountId": acc, "blobId": blob_id})
            assert result["error"]["type"] == "invalidSieve", text


async def test_blob_upload_used_as_attachment_and_blob_get() -> None:
    fake, acc = make_fake()
    png = b"\x89PNG\r\n\x1a\nfake"
    async with client(fake) as c:
        responses = await call(
            c,
            [
                [
                    "Blob/upload",
                    {
                        "accountId": acc,
                        "create": {"img": {"data": [{"data:asBase64": base64.b64encode(png).decode()}], "type": "image/png"}},
                    },
                    "0",
                ],
                [
                    "Email/set",
                    {
                        "accountId": acc,
                        "create": {
                            "e": {
                                "mailboxIds": {fake.mailbox_id(acc, "drafts"): True},
                                "from": [{"email": USER}],
                                "subject": "pic",
                                "bodyStructure": {
                                    "type": "multipart/mixed",
                                    "subParts": [
                                        {"partId": "1", "type": "text/plain"},
                                        {"blobId": "#img", "type": "image/png", "name": "pic.png", "disposition": "attachment"},
                                    ],
                                },
                                "bodyValues": {"1": {"value": "see pic"}},
                            }
                        },
                    },
                    "1",
                ],
                ["Blob/get", {"accountId": acc, "ids": ["#img"], "properties": ["data:asBase64", "size"]}, "2"],
            ],
        )
    email_id = responses[1][1]["created"]["e"]["id"]
    [att] = fake.email(acc, email_id)["attachments"]
    assert att["type"] == "image/png" and att["name"] == "pic.png" and fake.blob(acc, att["blobId"]) == png
    [item] = responses[2][1]["list"]
    assert base64.b64decode(item["data:asBase64"]) == png and item["size"] == len(png)


async def test_download_attachment_and_raw_message() -> None:
    fake, acc = make_fake()
    other = fake.add_account(username="other@example.com", password="pw")
    eid = seed_hello(fake, acc)
    stored = fake.email(acc, eid)
    [att] = stored["attachments"]
    async with client(fake) as c:
        session = (await c.get("/.well-known/jmap", follow_redirects=True)).json()
        template = session["downloadUrl"]

        def url(account: str, blob: str, name: str, type_: str) -> str:
            return (
                template.replace("{accountId}", account)
                .replace("{blobId}", blob)
                .replace("{name}", name)
                .replace("{type}", type_.replace("/", "%2F"))
            )

        r = await c.get(url(acc, att["blobId"], "invoice.pdf", "application/pdf"))
        assert r.status_code == 200 and r.content == b"%PDF-1.4 ..."
        assert r.headers["content-type"] == "application/pdf"
        r = await c.get(url(acc, att["blobId"], quote("Rechnung März/2026.pdf", safe=""), "application/pdf"))
        assert r.status_code == 200 and r.content == b"%PDF-1.4 ..."
        assert r.headers["content-disposition"] == "attachment; filename*=UTF-8''" + quote("Rechnung März/2026.pdf")
        r = await c.get(url(acc, stored["blobId"], "msg.eml", "message/rfc822"))
        assert r.status_code == 200 and r.content == stored["raw"]
        assert r.content.startswith(b"From: Alice <alice@ext.org>\r\n")
        assert (await c.get(url(acc, "bnope", "x", "application/octet-stream"))).status_code == 404
        assert (await c.get(url(other, att["blobId"], "x", "text/plain"))).status_code == 404


async def test_email_parse_of_attached_message() -> None:
    fake, acc = make_fake()
    original = seed_hello(fake, acc)
    fwd = fake.add_email(
        acc,
        subject="Fwd: Hello",
        from_=USER,
        to=["bob@ext.org"],
        text="see below",
        attachments=[("hello.eml", "message/rfc822", fake.email(acc, original)["raw"])],
    )
    async with client(fake) as c:
        [msg] = (await one(c, "Email/get", {"accountId": acc, "ids": [fwd], "properties": ["attachments"]}))["list"]
        [att] = msg["attachments"]
        assert att["type"] == "message/rfc822" and att["name"] == "hello.eml"
        pdf_blob = fake.email(acc, original)["attachments"][0]["blobId"]
        parsed = await one(c, "Email/parse", {"accountId": acc, "blobIds": [att["blobId"], pdf_blob, "bnope"], "fetchTextBodyValues": True})
    inner = parsed["parsed"][att["blobId"]]
    assert inner["subject"] == "Hello" and inner["from"] == [{"name": "Alice", "email": "alice@ext.org"}]
    assert inner["messageId"] == ["m1@ext.org"] and inner["hasAttachment"] is True
    assert inner["attachments"][0]["name"] == "invoice.pdf"
    assert inner["bodyValues"][inner["textBody"][0]["partId"]]["value"] == "plain body"
    assert "id" not in inner and "blobId" not in inner  # RFC 8621 4.9 default properties
    assert parsed["notParsable"] == [pdf_blob] and parsed["notFound"] == ["bnope"]


# ---------------------------------------------------------------- Mailbox


async def test_mailbox_counts_and_set_rules() -> None:
    fake, acc = make_fake()
    projects = fake.add_mailbox(acc, name="Projects")
    child = fake.add_mailbox(acc, name="2026", parent_id=projects)
    eid = fake.add_email(acc, mailboxes=[child, "inbox"], subject="x", from_="a@ext.org", to=[USER], text="x")
    fake.add_email(acc, mailboxes=[child], subject="y", from_="a@ext.org", to=[USER], text="y", keywords={"$seen": True})
    async with client(fake) as c:
        boxes = await one(
            c, "Mailbox/get", {"accountId": acc, "ids": [child], "properties": ["name", "totalEmails", "unreadEmails", "myRights"]}
        )
        [box] = boxes["list"]
        assert (box["totalEmails"], box["unreadEmails"]) == (2, 1) and box["myRights"]["mayDelete"] is True
        assert set(box) == {"id", "name", "totalEmails", "unreadEmails", "myRights"}
        roles = {m["role"] for m in (await one(c, "Mailbox/get", {"accountId": acc, "ids": None}))["list"]}
        assert {"inbox", "drafts", "sent", "trash", "junk", "archive"} <= roles

        resp = await one(
            c,
            "Mailbox/set",
            {"accountId": acc, "create": {"dup": {"name": "Projects", "parentId": None}, "new": {"name": "Clients", "parentId": projects}}},
        )
        assert resp["notCreated"]["dup"]["type"] == "invalidProperties"
        new_id = resp["created"]["new"]["id"]
        resp = await one(
            c,
            "Mailbox/set",
            {"accountId": acc, "update": {new_id: {"name": "Customers"}}, "destroy": [projects, fake.mailbox_id(acc, "inbox"), child]},
        )
        assert resp["updated"] == {new_id: None}
        assert resp["notDestroyed"][projects]["type"] == "mailboxHasChild"
        assert resp["notDestroyed"][fake.mailbox_id(acc, "inbox")]["type"] == "forbidden"
        assert resp["notDestroyed"][child]["type"] == "mailboxHasEmail"
        resp = await one(c, "Mailbox/set", {"accountId": acc, "destroy": [child], "onDestroyRemoveEmails": True})
        assert resp["destroyed"] == [child]
    assert list(fake.account(acc).emails) == [eid]  # only the multi-mailbox email survives
    assert fake.email(acc, eid)["mailboxIds"] == {fake.mailbox_id(acc, "inbox"): True}


# ---------------------------------------------------------------- failure injection & sharing


async def test_failure_injection() -> None:
    fake, _ = make_fake()
    fake.inject(status=429, body="banned: too many authentication failures", times=1)
    fake.inject(status=503, body='{"type":"urn:ietf:params:jmap:error:limit"}', times=2)
    fake.inject(status=429, body="rate limit exceeded", headers={"Retry-After": "2"})
    async with client(fake) as c:
        r = await c.get("/jmap/session")
        assert r.status_code == 429 and r.text == "banned: too many authentication failures"
        r1 = await c.post("/jmap/", json={"using": [CORE], "methodCalls": []})
        r2 = await c.get("/nowhere")
        assert (r1.status_code, r2.status_code) == (503, 503)
        assert r1.json() == {"type": "urn:ietf:params:jmap:error:limit"}
        r = await c.get("/jmap/session")
        assert (r.status_code, r.text, r.headers["retry-after"]) == (429, "rate limit exceeded", "2")
        assert (await c.get("/jmap/session")).status_code == 200
    assert [entry[2] for entry in fake.http_log] == [429, 503, 503, 429, 200]
    assert fake.calls == [] and fake.auth_failures == 0


async def test_shared_read_only_account() -> None:
    fake, owner = make_fake()
    reader = fake.add_account(username="reader@example.com", password="pw")
    eid = seed_hello(fake, owner)
    fake.share(owner, reader, read_only=True)
    async with client(fake, auth=("reader@example.com", "pw")) as c:
        session = (await c.get("/jmap/session")).json()
        assert session["accounts"][owner]["isPersonal"] is False
        assert session["accounts"][owner]["isReadOnly"] is True
        assert session["accounts"][reader]["isPersonal"] is True and session["primaryAccounts"][MAIL] == reader
        got = await one(c, "Email/get", {"accountId": owner, "ids": [eid], "properties": ["subject"]})
        assert got["list"] == [{"id": eid, "subject": "Hello"}]
        [err] = await call(c, [["Email/set", {"accountId": owner, "update": {eid: {"keywords": {}}}}, "0"]])
        assert err[1] == {"type": "accountReadOnly"}
        [box] = (await one(c, "Mailbox/get", {"accountId": owner, "ids": [fake.mailbox_id(owner, "inbox")]}))["list"]
        assert box["myRights"]["mayReadItems"] is True and box["myRights"]["mayDelete"] is False
        blob = fake.email(owner, eid)["blobId"]
        assert (await c.get(f"/jmap/download/{owner}/{blob}/m.eml?accept=message%2Frfc822")).status_code == 200
        assert (await c.post(f"/jmap/upload/{owner}/", content=b"x")).status_code == 403
    async with client(fake, auth=("reader@example.com", "pw")) as c:
        [err] = await call(c, [["Email/get", {"accountId": "a999", "ids": []}, "0"]])
        assert err[1] == {"type": "accountNotFound"}


# ---------------------------------------------------------------- snippets, vacation, quota


async def test_snippets_vacation_and_quota() -> None:
    fake, acc = make_fake()
    eid = seed_hello(fake, acc)
    other = fake.add_email(acc, subject="Unrelated <tag>", from_="x@ext.org", to=[USER], text="nothing here")
    async with client(fake) as c:
        snippets = await one(c, "SearchSnippet/get", {"accountId": acc, "filter": {"text": "plain"}, "emailIds": [eid, other, "nope"]})
        first, second = snippets["list"]
        assert first == {"emailId": eid, "subject": None, "preview": "<mark>plain</mark> body"}
        assert second == {"emailId": other, "subject": None, "preview": None}
        assert snippets["notFound"] == ["nope"]
        subj = await one(c, "SearchSnippet/get", {"accountId": acc, "filter": {"subject": "tag"}, "emailIds": [other]})
        assert subj["list"][0]["subject"] == "Unrelated &lt;<mark>tag</mark>&gt;"

        vac = await one(c, "VacationResponse/get", {"accountId": acc, "ids": None})
        assert vac["list"][0]["id"] == "singleton" and vac["list"][0]["isEnabled"] is False
        resp = await one(
            c,
            "VacationResponse/set",
            {
                "accountId": acc,
                "update": {
                    "singleton": {"isEnabled": True, "subject": "Away", "textBody": "Back Monday", "fromDate": "2026-10-01T00:00:00Z"}
                },
            },
        )
        assert resp["updated"] == {"singleton": None}
        resp = await one(c, "VacationResponse/set", {"accountId": acc, "create": {"x": {}}})
        assert resp["notCreated"]["x"]["type"] == "singleton"
        vac = await one(c, "VacationResponse/get", {"accountId": acc, "ids": ["singleton"]})
        assert vac["list"][0]["subject"] == "Away" and vac["list"][0]["isEnabled"] is True

        quota = await one(c, "Quota/get", {"accountId": acc, "ids": None})
        [q] = quota["list"]
        used = fake.email(acc, eid)["size"] + fake.email(acc, other)["size"]
        assert q == {
            "id": q["id"],
            "resourceType": "octets",
            "used": used,
            "hardLimit": 1073741824,
            "scope": "account",
            "name": "Storage",
            "types": ["Mail"],
        }
