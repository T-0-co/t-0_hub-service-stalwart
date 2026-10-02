"""Mail operations. Plain async functions on a Jmap client; the MCP layer wraps them.

Write rules that apply everywhere here:

@gotcha Email/set always as a patch ("mailboxIds/<id>": true, "keywords/<kw>": true).
        Replacing the whole mailboxIds or keywords object silently drops multiple
        mailbox placement and any flags the request did not mention.
@gotcha JMAP keywords are lowercase (RFC 8621 §4.1.1). Send `$junk`, never `$Junk`:
        the server does not reject the uppercase form, it creates a second keyword.
@warn   The `header` condition of Email/query returns total=0 on Stalwart instead of an
        error. It is deliberately not offered; header-based checks use Email/get.
"""

from __future__ import annotations

import base64
import binascii
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from . import attachments as att
from . import compose, render, sieve_guard
from . import unsubscribe as unsub
from .errors import InvalidInput, MethodError, NotFound, Refused, ResyncRequired, SetError, Unsupported
from .jmap import BLOB, MAIL, QUOTA, SIEVE, SUBMISSION, VACATION, Jmap, ref
from .mailboxes import drop_mailbox_cache, mailbox_index

MAX_SEARCH_LIMIT = 200
MAX_READ_IDS = 20
MAX_SET_IDS = 500
MAX_THREAD_EMAILS = 30
MAX_INLINE_ATTACHMENT_BYTES = 10 * 1024 * 1024

_DATE_ONLY = re.compile(r"^\d{4}-\d{2}-\d{2}$")


# ---------------------------------------------------------------------- helpers


def utc_date(value: str | None) -> str | None:
    """'2026-10-01' or ISO datetime -> JMAP UTCDate ('2026-10-01T00:00:00Z')."""
    if value is None or value == "":
        return None
    value = value.strip()
    try:
        if _DATE_ONLY.match(value):
            dt = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=UTC)
        else:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
    except ValueError as exc:
        raise InvalidInput(f"Not a date: {value!r} (use YYYY-MM-DD or ISO 8601).") from exc
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ids(values: list[str] | str | None, limit: int, what: str = "email_ids") -> list[str]:
    if isinstance(values, str):
        values = [values]
    ids = list(dict.fromkeys(v.strip() for v in values or [] if v and v.strip()))
    if not ids:
        raise InvalidInput(f"{what} is empty.")
    if len(ids) > limit:
        raise InvalidInput(f"At most {limit} {what} per call (got {len(ids)}).")
    return ids


def _set_errors(result: dict[str, Any], key: str) -> dict[str, str]:
    return {
        oid: (err.get("type", "error") + (f": {err['description']}" if err.get("description") else ""))
        for oid, err in (result.get(key) or {}).items()
    }


def _require(j_session: Any, capability: str, what: str) -> None:
    if not j_session.has(capability):
        raise Unsupported(f"This server does not offer {what} ({capability}).")


async def _get_emails(j: Jmap, account_id: str, ids: list[str], properties: list[str]) -> tuple[list[dict], list[str]]:
    res = await j.one("Email/get", {"accountId": account_id, "ids": ids, "properties": ["id", *properties]}, [MAIL])
    return res.get("list", []), res.get("notFound") or []


# ---------------------------------------------------------------------- account


async def account_info(j: Jmap, *, account: str | None = None) -> dict[str, Any]:
    s = await j.session()
    acc = await j.account_id(account)
    calls: list = []
    using = {MAIL}
    if s.has(SUBMISSION):
        calls.append(("Identity/get", {"accountId": acc, "ids": None}, "identities"))
        using.add(SUBMISSION)
    if s.has(QUOTA):
        calls.append(("Quota/get", {"accountId": acc, "ids": None}, "quota"))
        using.add(QUOTA)
    if s.has(VACATION):
        calls.append(("VacationResponse/get", {"accountId": acc, "ids": ["singleton"]}, "vacation"))
        using.add(VACATION)
    if s.has(SIEVE):
        calls.append(("SieveScript/get", {"accountId": acc, "ids": None, "properties": ["name", "isActive"]}, "sieve"))
        using.add(SIEVE)
    out: dict[str, Any] = {
        "username": s.username,
        "account": {"id": acc, "name": s.accounts.get(acc, {}).get("name")},
        "accounts": [
            render.compact(
                {
                    "id": aid,
                    "name": a.get("name"),
                    "shared": (not a.get("isPersonal", True)) or None,
                    "readOnly": a.get("isReadOnly") or None,
                }
            )
            for aid, a in s.accounts.items()
        ],
    }
    notes = []
    if calls:
        res = await j.call(calls, using)
        for _method, _args, cid in calls:
            if err := res.error(cid):
                notes.append(f"{cid}: {err.get('type')}")
        if not res.error("identities") and s.has(SUBMISSION):
            out["identities"] = [
                render.compact({"id": i["id"], "email": i.get("email"), "name": i.get("name")})
                for i in res.get("identities").get("list", [])
            ]
        if not res.error("quota") and s.has(QUOTA):
            out["quota"] = [
                render.compact(
                    {
                        "name": q.get("name"),
                        "type": q.get("resourceType"),
                        "used": q.get("used"),
                        "limit": q.get("hardLimit"),
                    }
                )
                for q in res.get("quota").get("list", [])
            ]
        if not res.error("vacation") and s.has(VACATION):
            v = (res.get("vacation").get("list") or [{}])[0]
            out["vacation"] = render.compact(
                {
                    "enabled": bool(v.get("isEnabled")),
                    "from": v.get("fromDate"),
                    "to": v.get("toDate"),
                    "subject": v.get("subject"),
                }
            ) or {"enabled": False}
        if not res.error("sieve") and s.has(SIEVE):
            out["filters"] = [{"name": f.get("name"), "active": bool(f.get("isActive"))} for f in res.get("sieve").get("list", [])]
    out["server"] = {
        "capabilities": sorted(c.rsplit(":", 1)[-1] for c in s.capabilities),
        "limits": {
            k: s.core_limit(k, 0)
            for k in ("maxObjectsInGet", "maxObjectsInSet", "maxCallsInRequest", "maxSizeUpload", "maxConcurrentRequests")
        },
    }
    if notes:
        out["notes"] = notes
    return out


async def list_mailboxes(j: Jmap, *, account: str | None = None) -> dict[str, Any]:
    acc = await j.account_id(account)
    idx = await mailbox_index(j, acc, refresh=True)
    rows = []
    for mb in idx.list:
        rows.append(
            render.compact(
                {
                    "id": mb["id"],
                    "path": idx.path(mb["id"]),
                    "role": mb.get("role"),
                    "total": mb.get("totalEmails"),
                    "unread": mb.get("unreadEmails") or None,
                    "subscribed": False if mb.get("isSubscribed") is False else None,
                }
            )
        )
    rows.sort(key=lambda r: (r.get("role") != "inbox", r["path"].lower()))
    return {"account": acc, "count": len(rows), "mailboxes": rows}


# ---------------------------------------------------------------------- reading


async def search_emails(
    j: Jmap,
    *,
    account: str | None = None,
    text: str | None = None,
    sender: str | None = None,
    to: str | None = None,
    subject: str | None = None,
    body: str | None = None,
    mailbox: str | None = None,
    after: str | None = None,
    before: str | None = None,
    unread: bool | None = None,
    flagged: bool | None = None,
    has_attachment: bool | None = None,
    min_size: int | None = None,
    max_size: int | None = None,
    include_junk_and_trash: bool = False,
    detail: str = "summary",
    collapse_threads: bool = False,
    snippets: bool = False,
    limit: int = 25,
    position: int = 0,
) -> dict[str, Any]:
    if detail not in ("subjects", "summary", "headers"):
        raise InvalidInput("detail must be 'subjects', 'summary' or 'headers' (bodies: read_email).")
    acc = await j.account_id(account)
    idx = await mailbox_index(j, acc)
    conds: list[dict[str, Any]] = []
    for key, value in (("text", text), ("from", sender), ("to", to), ("subject", subject), ("body", body)):
        if value:
            conds.append({key: value})
    if mailbox:
        conds.append({"inMailbox": idx.resolve(mailbox)["id"]})
    elif not include_junk_and_trash:
        excluded = [mb["id"] for role in ("junk", "trash") if (mb := idx.by_role(role))]
        if excluded:
            conds.append({"inMailboxOtherThan": excluded})
    if after:
        conds.append({"after": utc_date(after)})
    if before:
        conds.append({"before": utc_date(before)})
    if unread is not None:
        conds.append({"notKeyword" if unread else "hasKeyword": "$seen"})
    if flagged is not None:
        conds.append({"hasKeyword" if flagged else "notKeyword": "$flagged"})
    if has_attachment is not None:
        conds.append({"hasAttachment": has_attachment})
    if min_size:
        conds.append({"minSize": int(min_size)})
    if max_size:
        conds.append({"maxSize": int(max_size)})
    filt: dict[str, Any] | None = None
    if len(conds) == 1:
        filt = conds[0]
    elif conds:
        filt = {"operator": "AND", "conditions": conds}

    limit = max(1, min(int(limit or 25), MAX_SEARCH_LIMIT))
    position = max(0, int(position or 0))
    query: dict[str, Any] = {
        "accountId": acc,
        "sort": [{"property": "receivedAt", "isAscending": False}],
        "position": position,
        "limit": limit,
        "calculateTotal": True,
        "collapseThreads": bool(collapse_threads),
    }
    if filt:
        query["filter"] = filt
    get_args = render.email_get_args(acc, detail)  # type: ignore[arg-type]
    get_args["#ids"] = ref("q", "Email/query", "/ids")
    calls = [("Email/query", query, "q"), ("Email/get", get_args, "g")]
    want_snippets = snippets and bool(text or body or subject)
    if want_snippets:
        calls.append(("SearchSnippet/get", {"accountId": acc, "filter": filt, "#emailIds": ref("q", "Email/query", "/ids")}, "s"))
    res = await j.call(calls, [MAIL])
    q = res.get("q", "Email/query")
    found = {e["id"]: e for e in res.get("g", "Email/get").get("list", [])}
    snips = {}
    if want_snippets and not res.error("s"):
        snips = {s["emailId"]: s for s in res.get("s", "SearchSnippet/get").get("list", [])}
    items = []
    for eid in q.get("ids", []):
        if eid not in found:
            continue
        item = render.summarize(found[eid], detail, idx)  # type: ignore[arg-type]
        snip = snips.get(eid)
        if snip and (snip.get("preview") or snip.get("subject")):
            item["match"] = snip.get("preview") or snip.get("subject")
        items.append(item)
    total = q.get("total")
    out: dict[str, Any] = {"total": total, "position": position, "count": len(items), "emails": items}
    if total is not None and position + len(items) < total:
        out["next_position"] = position + len(items)
    if items:
        out["notice"] = render.UNTRUSTED_NOTICE
    return out


async def read_email(
    j: Jmap,
    email_ids: list[str] | str,
    *,
    account: str | None = None,
    detail: str = "full",
    max_chars: int = 6000,
    prefer_html: bool = False,
    strip_quotes: bool = False,
) -> dict[str, Any]:
    if detail not in ("summary", "headers", "full"):
        raise InvalidInput("detail must be 'summary', 'headers' or 'full'.")
    ids = _ids(email_ids, MAX_READ_IDS)
    acc = await j.account_id(account)
    idx = await mailbox_index(j, acc)
    max_chars = max(200, min(int(max_chars or 6000), 100_000))
    args = render.email_get_args(acc, detail, max_body_bytes=min(max(max_chars * 8, 65536), 2_000_000), prefer_html=prefer_html)  # type: ignore[arg-type]
    if detail == "headers":
        args["properties"] = list(dict.fromkeys(args["properties"] + ["attachments"]))
        args["bodyProperties"] = render.BODY_PROPERTIES
    args["ids"] = ids
    res = await j.one("Email/get", args, [MAIL])
    out = []
    for e in res.get("list", []):
        item = render.summarize(e, detail, idx)  # type: ignore[arg-type]
        if detail == "full":
            text, source = render.body_text(e, prefer_html=prefer_html)
            if strip_quotes:
                text, removed = render.strip_quoted(text)
                if removed:
                    item["quotes_removed"] = True
            text, cut = render.truncate(text, max_chars)
            item["body"] = text
            item["body_format"] = source
            if cut:
                item["truncated"] = True
        attachments = render.attachment_list(e)
        if attachments:
            item["attachments"] = attachments
        out.append(item)
    result: dict[str, Any] = {"emails": out, "notice": render.UNTRUSTED_NOTICE}
    if res.get("notFound"):
        result["not_found"] = res["notFound"]
    return result


async def get_thread(
    j: Jmap,
    *,
    email_id: str | None = None,
    thread_id: str | None = None,
    account: str | None = None,
    detail: str = "summary",
    max_chars_per_email: int = 1500,
    strip_quotes: bool = True,
    max_emails: int = MAX_THREAD_EMAILS,
) -> dict[str, Any]:
    if not (email_id or thread_id):
        raise InvalidInput("Pass email_id or thread_id.")
    if detail not in ("subjects", "summary", "full"):
        raise InvalidInput("detail must be 'subjects', 'summary' or 'full'.")
    acc = await j.account_id(account)
    idx = await mailbox_index(j, acc)
    calls: list = []
    if thread_id:
        calls.append(("Thread/get", {"accountId": acc, "ids": [thread_id]}, "t"))
    else:
        calls.append(("Email/get", {"accountId": acc, "ids": [email_id], "properties": ["threadId"]}, "e"))
        calls.append(("Thread/get", {"accountId": acc, "#ids": ref("e", "Email/get", "/list/*/threadId")}, "t"))
    max_chars = max(100, min(int(max_chars_per_email or 1500), 20_000))
    get_args = render.email_get_args(acc, detail, max_body_bytes=min(max(max_chars * 8, 32768), 1_000_000))  # type: ignore[arg-type]
    get_args["#ids"] = ref("t", "Thread/get", "/list/*/emailIds")
    calls.append(("Email/get", get_args, "g"))
    res = await j.call(calls, [MAIL])
    if not thread_id and not res.get("e", "Email/get").get("list"):
        raise NotFound(f"No email '{email_id}'.")
    threads = res.get("t", "Thread/get").get("list", [])
    if not threads:
        raise NotFound("Thread not found.")
    order = threads[0].get("emailIds", [])
    found = {e["id"]: e for e in res.get("g", "Email/get").get("list", [])}
    shown = order[-max(1, int(max_emails)) :]
    items = []
    for eid in shown:
        e = found.get(eid)
        if not e:
            continue
        item = render.summarize(e, "summary" if detail == "full" else detail, idx)  # type: ignore[arg-type]
        if detail == "full":
            text, _ = render.body_text(e)
            if strip_quotes:
                text, _removed = render.strip_quoted(text)
            item["body"], cut = render.truncate(text, max_chars)
            item.pop("preview", None)
            if cut:
                item["truncated"] = True
        items.append(item)
    out: dict[str, Any] = {"thread": threads[0]["id"], "count": len(order), "emails": items, "notice": render.UNTRUSTED_NOTICE}
    if len(order) > len(shown):
        out["omitted_older"] = len(order) - len(shown)
    return out


async def load_attachment(
    j: Jmap,
    email_id: str,
    *,
    part_id: str | None = None,
    blob_id: str | None = None,
    raw: bool = False,
    account: str | None = None,
    max_chars: int = 20000,
) -> tuple[dict[str, Any], dict[str, str] | None]:
    """Returns (data, image) where image is {"data": base64, "mimeType": ...} or None."""
    acc = await j.account_id(account)
    limit = j.rt.config.max_attachment_bytes
    max_chars = max(500, min(int(max_chars or 20000), 200_000))
    res = await j.one(
        "Email/get",
        {
            "accountId": acc,
            "ids": [email_id],
            "properties": ["id", "subject", "blobId", "size", "attachments", "bodyStructure"],
            "bodyProperties": render.BODY_PROPERTIES + ["subParts"],
        },
        [MAIL],
    )
    if not res.get("list"):
        raise NotFound(f"No email '{email_id}'.")
    email = res["list"][0]
    if raw:
        if (email.get("size") or 0) > limit:
            raise Refused(f"The message is larger than {limit} bytes.")
        data = await j.download(acc, email["blobId"], name="message.eml", mime="message/rfc822", max_bytes=limit)
        text, cut = render.truncate(att.decode_text(data, "utf-8"), max_chars)
        return {
            "email_id": email_id,
            "kind": "raw message",
            "size": len(data),
            "text": text,
            "truncated": cut or None,
            "notice": render.UNTRUSTED_NOTICE,
        }, None

    parts = list(email.get("attachments") or [])

    def walk(part: dict[str, Any] | None) -> None:
        if not part:
            return
        if part.get("blobId") and part not in parts and not (part.get("type") or "").startswith("multipart/"):
            parts.append(part)
        for sub in part.get("subParts") or []:
            walk(sub)

    walk(email.get("bodyStructure"))
    if not (part_id or blob_id):
        raise InvalidInput("Pass part_id or blob_id (see read_email → attachments), or raw=true.")
    part = next((p for p in parts if (part_id and p.get("partId") == part_id) or (blob_id and p.get("blobId") == blob_id)), None)
    if not part:
        raise NotFound(
            "Attachment not found in this email.",
            details={
                "available": [render.compact({"partId": p.get("partId"), "name": p.get("name"), "type": p.get("type")}) for p in parts]
            },
        )
    size = part.get("size") or 0
    meta = render.compact(
        {"email_id": email_id, "name": part.get("name"), "type": part.get("type"), "size": size, "partId": part.get("partId")}
    )
    if size > limit:
        raise Refused(f"Attachment is {size} bytes, above the limit of {limit}.", details=meta)
    kind = att.kind_of(part.get("type"), part.get("name"))
    meta["kind"] = kind
    if kind == "email":
        props = render.PROPS_FULL
        parsed = await j.one(
            "Email/parse",
            {
                "accountId": acc,
                "blobIds": [part["blobId"]],
                "properties": [p for p in props if p not in ("id", "threadId", "mailboxIds", "keywords", "receivedAt", "blobId")]
                + ["receivedAt"],
                "bodyProperties": render.BODY_PROPERTIES,
                "fetchTextBodyValues": True,
                "maxBodyValueBytes": min(max_chars * 8, 1_000_000),
            },
            [MAIL],
        )
        msg = (parsed.get("parsed") or {}).get(part["blobId"])
        if not msg:
            raise Refused("The embedded message could not be parsed.", details=meta)
        msg = {**msg, "id": None}
        item = render.summarize(msg, "full")
        text, _ = render.body_text(msg)
        item["body"], cut = render.truncate(text, max_chars)
        if cut:
            item["truncated"] = True
        if atts := render.attachment_list(msg):
            item["attachments"] = atts
        return {**meta, "message": item, "notice": render.UNTRUSTED_NOTICE}, None
    if kind == "binary":
        return {**meta, "note": "Binary format; content is not extracted. Metadata only."}, None
    data = await j.download(
        acc, part["blobId"], name=part.get("name") or "file", mime=part.get("type") or "application/octet-stream", max_bytes=limit
    )
    try:
        extracted = await att.extract(kind, data, charset=part.get("charset"), max_chars=max_chars)
    except TimeoutError:
        return {**meta, "note": "Extraction timed out."}, None
    except Exception as exc:  # broken files are common; report, don't crash
        return {**meta, "note": f"Could not read the file: {type(exc).__name__}."}, None
    image = None
    if "image_b64" in extracted:
        image = {"data": extracted.pop("image_b64"), "mimeType": extracted.pop("image_mime")}
    return {**meta, **render.compact(extracted), "notice": render.UNTRUSTED_NOTICE}, image


async def list_changes(
    j: Jmap,
    *,
    since_state: str | None = None,
    account: str | None = None,
    limit: int = 50,
    detail: str = "subjects",
) -> dict[str, Any]:
    if detail not in ("subjects", "summary"):
        raise InvalidInput("detail must be 'subjects' or 'summary'.")
    acc = await j.account_id(account)

    async def current_state() -> str:
        return (await j.one("Email/get", {"accountId": acc, "ids": [], "properties": ["id"]}, [MAIL]))["state"]

    if not since_state:
        return {"state": await current_state(), "note": "Starting point. Pass this value as since_state next time."}
    limit = max(1, min(int(limit or 50), 500))
    try:
        changes = await j.one("Email/changes", {"accountId": acc, "sinceState": since_state, "maxChanges": limit}, [MAIL], isolated=True)
    except ResyncRequired:
        changes = None
    except MethodError as exc:
        if exc.type != "cannotCalculateChanges":
            raise
        changes = None
    if changes is None:
        return {
            "resync_required": True,
            "state": await current_state(),
            "note": "The state is unknown or too old. Run a normal search for the period you need, then continue from this state.",
        }
    created, updated = changes.get("created", []), changes.get("updated", [])
    wanted = list(dict.fromkeys(created + updated))[:limit]
    by_id: dict[str, dict] = {}
    if wanted:
        idx = await mailbox_index(j, acc)
        args = render.email_get_args(acc, detail)  # type: ignore[arg-type]
        args["ids"] = wanted
        got = await j.one("Email/get", args, [MAIL])
        by_id = {e["id"]: render.summarize(e, detail, idx) for e in got.get("list", [])}  # type: ignore[arg-type]
    out = {
        "since_state": since_state,
        "state": changes.get("newState"),
        "has_more": bool(changes.get("hasMoreChanges")),
        "created": [by_id[i] for i in created if i in by_id],
        "updated": [by_id[i] for i in updated if i in by_id and i not in created],
        "destroyed": changes.get("destroyed", []),
    }
    if out["has_more"]:
        out["note"] = "More changes are waiting; call again with the new state."
    if by_id:
        out["notice"] = render.UNTRUSTED_NOTICE
    return out


# ---------------------------------------------------------------------- writing


async def _upload_attachments(j: Jmap, acc: str, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalise attachment inputs to {blobId, type, name}; uploads text/base64 items."""
    s = await j.session()
    ready: list[dict[str, Any]] = []
    uploads: list[tuple[str, bytes, str, str]] = []
    for n, item in enumerate(items):
        name = (item.get("name") or "").strip() or f"attachment-{n + 1}"
        mime = (item.get("type") or "").strip() or "application/octet-stream"
        if item.get("blob_id"):
            ready.append({"blobId": item["blob_id"], "type": item.get("type") or None, "name": item.get("name") or None})
            continue
        if item.get("text") is not None:
            data = str(item["text"]).encode("utf-8")
            if mime == "application/octet-stream":
                mime = "text/plain"
        elif item.get("base64"):
            try:
                data = base64.b64decode(item["base64"], validate=True)
            except (binascii.Error, ValueError) as exc:
                raise InvalidInput(f"Attachment '{name}': base64 is invalid.") from exc
        else:
            raise InvalidInput(f"Attachment '{name}' needs blob_id, text or base64.")
        if len(data) > MAX_INLINE_ATTACHMENT_BYTES:
            raise InvalidInput(f"Attachment '{name}' is larger than {MAX_INLINE_ATTACHMENT_BYTES} bytes.")
        uploads.append((f"u{n}", data, mime, name))
    if not uploads:
        return ready
    if s.has(BLOB):
        create = {key: {"data": [{"data:asBase64": base64.b64encode(data).decode()}], "type": mime} for key, data, mime, _ in uploads}
        res = await j.one("Blob/upload", {"accountId": acc, "create": create}, [BLOB])
        if res.get("notCreated"):
            raise SetError("Attachment upload failed.", details=_set_errors(res, "notCreated"))
        for key, _data, mime, name in uploads:
            ready.append({"blobId": res["created"][key]["id"], "type": mime, "name": name})
    else:
        for _key, data, mime, name in uploads:
            up = await j.upload(acc, data, mime)
            ready.append({"blobId": up["blobId"], "type": mime, "name": name})
    return ready


async def write_email(
    j: Jmap,
    *,
    mode: str = "new",
    to: list[str] | None = None,
    cc: list[str] | None = None,
    subject: str | None = None,
    body: str = "",
    html_body: str | None = None,
    email_id: str | None = None,
    from_email: str | None = None,
    from_name: str | None = None,
    attachments: list[dict[str, Any]] | None = None,
    quote_original: bool = False,
    account: str | None = None,
) -> dict[str, Any]:
    if mode not in ("new", "reply", "reply_all", "forward"):
        raise InvalidInput("mode must be new, reply, reply_all or forward.")
    if mode != "new" and not email_id:
        raise InvalidInput(f"mode={mode} needs email_id of the original mail.")
    s = await j.session()
    _require(s, SUBMISSION, "sending (identities)")
    acc = await j.account_id(account)
    idx = await mailbox_index(j, acc)
    drafts = idx.require_role("drafts")
    calls: list = [("Identity/get", {"accountId": acc, "ids": None}, "i")]
    if email_id:
        o_args = {
            "accountId": acc,
            "ids": [email_id],
            "properties": [
                "id",
                "subject",
                "messageId",
                "references",
                "from",
                "to",
                "cc",
                "replyTo",
                "sentAt",
                "receivedAt",
                "blobId",
                "size",
                "textBody",
                "htmlBody",
                "bodyValues",
            ],
            "bodyProperties": render.BODY_PROPERTIES,
            "fetchTextBodyValues": bool(quote_original),
            "maxBodyValueBytes": 100_000,
        }
        calls.append(("Email/get", o_args, "o"))
    res = await j.call(calls, [MAIL, SUBMISSION])
    identities = res.get("i", "Identity/get").get("list", [])
    original = None
    if email_id:
        found = res.get("o", "Email/get").get("list", [])
        if not found:
            raise NotFound(f"No email '{email_id}'.")
        original = found[0]
    identity = compose.pick_identity(identities, from_email=from_email, original=original, username=s.username)
    to_list = compose.normalize_addresses(to)
    cc_list = compose.normalize_addresses(cc)
    extra: dict[str, Any] = {}
    files = list(attachments or [])
    text = body or ""
    if mode in ("reply", "reply_all"):
        auto_to, auto_cc = compose.reply_recipients(original, identities, reply_all=mode == "reply_all")  # type: ignore[arg-type]
        to_list = to_list or auto_to
        if cc is None and mode == "reply_all":
            cc_list = auto_cc
        final_subject = subject or compose.reply_subject(original.get("subject"))  # type: ignore[union-attr]
        extra.update(compose.threading_headers(original))  # type: ignore[arg-type]
        if quote_original:
            text += compose.quote_block(original, render.body_text(original)[0])  # type: ignore[arg-type]
    elif mode == "forward":
        if not to_list:
            raise InvalidInput("forward needs 'to'.")
        final_subject = subject or compose.forward_subject(original.get("subject"))  # type: ignore[union-attr]
        safe = re.sub(r"[^\w.\- ]+", "_", final_subject)[:80].strip() or "message"
        files.insert(0, {"blob_id": original["blobId"], "type": "message/rfc822", "name": f"{safe}.eml"})  # type: ignore[index]
    else:
        final_subject = subject or ""
    blobs = await _upload_attachments(j, acc, files)
    structure, values = compose.body_structure(text, html_body, blobs)
    name = compose.display_name(identity, from_name)
    draft: dict[str, Any] = {
        "mailboxIds": {drafts["id"]: True},
        "keywords": {"$draft": True, "$seen": True},
        "from": [{"email": identity["email"], **({"name": name} if name else {})}],
        "subject": final_subject,
        "bodyStructure": structure,
        "bodyValues": values,
        **extra,
    }
    if to_list:
        draft["to"] = to_list
    if cc_list:
        draft["cc"] = cc_list
    created = await j.one("Email/set", {"accountId": acc, "create": {"draft": draft}}, [MAIL])
    if "draft" not in (created.get("created") or {}):
        raise SetError("The draft was not created.", details=_set_errors(created, "notCreated"))
    recipients = [a["email"] for a in to_list + cc_list]
    return {
        "draft_id": created["created"]["draft"]["id"],
        "mode": mode,
        "from": render.addr(draft["from"][0]),
        "to": [render.addr(a) for a in to_list],
        "cc": [render.addr(a) for a in cc_list] or None,
        "subject": final_subject,
        "attachments": [b.get("name") or b.get("type") for b in blobs] or None,
        "saved_in": idx.path(drafts["id"]),
        "next": "Show the draft to the user. Only after explicit approval call send_email with this draft_id and "
        f"confirm_recipients={recipients} (plus any bcc addresses, which are passed to send_email, not stored in the draft).",
    }


async def send_email(
    j: Jmap,
    draft_id: str,
    confirm_recipients: list[str],
    *,
    bcc: list[str] | None = None,
    account: str | None = None,
) -> dict[str, Any]:
    s = await j.session()
    _require(s, SUBMISSION, "sending")
    acc = await j.account_id(account)
    idx = await mailbox_index(j, acc)
    res = await j.call(
        [
            (
                "Email/get",
                {"accountId": acc, "ids": [draft_id], "properties": ["id", "from", "to", "cc", "bcc", "subject", "keywords", "mailboxIds"]},
                "e",
            ),
            ("Identity/get", {"accountId": acc, "ids": None}, "i"),
        ],
        [MAIL, SUBMISSION],
    )
    found = res.get("e", "Email/get").get("list", [])
    if not found:
        raise NotFound(f"No draft '{draft_id}'.")
    draft = found[0]
    if "$draft" not in {k.lower() for k, v in (draft.get("keywords") or {}).items() if v}:
        raise Refused("This email is not a draft; only drafts are sent.")
    if draft.get("bcc"):
        # @warn Stalwart sends the stored message as is. A Bcc header in the stored draft
        #       could reach every recipient. Drafts from write_email never contain one.
        raise Refused(
            "This draft contains a Bcc header; refusing to send it.",
            hint="Recreate it with write_email (no bcc) and pass the bcc addresses to send_email.",
        )
    bcc_list = compose.normalize_addresses(bcc)
    actual = {a["email"].lower() for a in (draft.get("to") or []) + (draft.get("cc") or []) + bcc_list}
    if not actual:
        raise Refused("The draft has no recipients.")
    confirmed = {r.strip().lower() for r in confirm_recipients or [] if r and r.strip()}
    if confirmed != actual:
        raise Refused(
            "confirm_recipients does not match the draft's recipients; nothing was sent.",
            details={
                "draft_recipients": sorted(actual),
                "missing_from_confirmation": sorted(actual - confirmed) or None,
                "not_in_draft": sorted(confirmed - actual) or None,
            },
        )
    sender = ((draft.get("from") or [{}])[0].get("email") or "").lower()
    identity = compose.pick_identity(res.get("i", "Identity/get").get("list", []), from_email=sender)
    sent = idx.require_role("sent")
    submission: dict[str, Any] = {"emailId": draft_id, "identityId": identity["id"]}
    if bcc_list:
        submission["envelope"] = {
            "mailFrom": {"email": identity["email"], "parameters": None},
            "rcptTo": [{"email": r, "parameters": None} for r in sorted(actual)],
        }
    patch: dict[str, Any] = {f"mailboxIds/{sent['id']}": True, "keywords/$draft": None}
    for mid, on in (draft.get("mailboxIds") or {}).items():
        if on and mid != sent["id"]:
            patch[f"mailboxIds/{mid}"] = None
    out = await j.call(
        [("EmailSubmission/set", {"accountId": acc, "create": {"sub": submission}, "onSuccessUpdateEmail": {"#sub": patch}}, "s")],
        [MAIL, SUBMISSION],
    )
    if err := out.error("s"):
        # @gotcha When the referenced email cannot be used, Stalwart answers with a method
        #         error (e.g. invalidResultReference) and NO notCreated. Success is judged on
        #         `created`, never on the absence of `notCreated`.
        raise MethodError("EmailSubmission/set", err.get("type", "error"), err.get("description"))
    result = out.get("s", "EmailSubmission/set")
    created = (result.get("created") or {}).get("sub")
    if not created:
        raise SetError("Stalwart did not accept the submission; nothing was sent.", details=_set_errors(result, "notCreated"))
    drop_mailbox_cache(j)
    return render.compact(
        {
            "sent": True,
            "submission_id": created.get("id"),
            "from": identity["email"],
            "to": [a["email"] for a in draft.get("to") or []],
            "cc": [a["email"] for a in draft.get("cc") or []],
            "bcc": [a["email"] for a in bcc_list],
            "subject": draft.get("subject"),
            "status": created.get("undoStatus"),
        }
    )


async def _current_mailboxes(j: Jmap, acc: str, ids: list[str]) -> tuple[dict[str, dict[str, bool]], list[str]]:
    found, missing = await _get_emails(j, acc, ids, ["mailboxIds"])
    return {e["id"]: e.get("mailboxIds") or {} for e in found}, missing


async def _apply_updates(j: Jmap, acc: str, update: dict[str, dict[str, Any]]) -> tuple[list[str], dict[str, str]]:
    if not update:
        return [], {}
    res = await j.one("Email/set", {"accountId": acc, "update": update}, [MAIL])
    return list((res.get("updated") or {}).keys()), _set_errors(res, "notUpdated")


def _move_patch(current: dict[str, bool], target_id: str, only_from: str | None = None) -> dict[str, Any]:
    patch: dict[str, Any] = {f"mailboxIds/{target_id}": True}
    for mid, on in current.items():
        if on and mid != target_id and (only_from is None or mid == only_from):
            patch[f"mailboxIds/{mid}"] = None
    return patch


async def move_emails(
    j: Jmap, email_ids: list[str], to_mailbox: str, *, from_mailbox: str | None = None, account: str | None = None
) -> dict[str, Any]:
    ids = _ids(email_ids, MAX_SET_IDS)
    acc = await j.account_id(account)
    idx = await mailbox_index(j, acc)
    target = idx.resolve(to_mailbox)
    source = idx.resolve(from_mailbox) if from_mailbox else None
    current, missing = await _current_mailboxes(j, acc, ids)
    update, skipped = {}, []
    for eid, mbs in current.items():
        if source and not mbs.get(source["id"]):
            skipped.append(eid)
            continue
        update[eid] = _move_patch(mbs, target["id"], source["id"] if source else None)
    moved, failed = await _apply_updates(j, acc, update)
    drop_mailbox_cache(j)
    return render.compact(
        {
            "moved": len(moved),
            "to": idx.path(target["id"]),
            "not_in_source": skipped,
            "failed": failed,
            "not_found": missing,
        }
    )


async def set_flags(
    j: Jmap,
    email_ids: list[str],
    *,
    seen: bool | None = None,
    flagged: bool | None = None,
    answered: bool | None = None,
    account: str | None = None,
) -> dict[str, Any]:
    ids = _ids(email_ids, MAX_SET_IDS)
    patch: dict[str, Any] = {}
    for keyword, value in (("$seen", seen), ("$flagged", flagged), ("$answered", answered)):
        if value is not None:
            patch[f"keywords/{keyword}"] = True if value else None
    if not patch:
        raise InvalidInput("Set at least one of seen, flagged, answered.")
    acc = await j.account_id(account)
    updated, failed = await _apply_updates(j, acc, {eid: dict(patch) for eid in ids})
    drop_mailbox_cache(j)
    return render.compact({"updated": len(updated), "failed": failed})


async def report_spam(j: Jmap, email_ids: list[str], *, spam: bool = True, account: str | None = None) -> dict[str, Any]:
    ids = _ids(email_ids, MAX_SET_IDS)
    acc = await j.account_id(account)
    idx = await mailbox_index(j, acc)
    target = idx.require_role("junk" if spam else "inbox")
    current, missing = await _current_mailboxes(j, acc, ids)
    update = {}
    for eid, mbs in current.items():
        patch = _move_patch(mbs, target["id"])
        patch["keywords/$junk"] = True if spam else None
        patch["keywords/$notjunk"] = None if spam else True
        update[eid] = patch
    done, failed = await _apply_updates(j, acc, update)
    drop_mailbox_cache(j)
    return render.compact(
        {
            "reported": len(done),
            "as": "spam" if spam else "not spam",
            "moved_to": idx.path(target["id"]),
            "failed": failed,
            "not_found": missing,
            "note": "The server's spam filter learns from these marks on its next training run.",
        }
    )


async def delete_emails(j: Jmap, email_ids: list[str], *, permanent: bool = False, account: str | None = None) -> dict[str, Any]:
    ids = _ids(email_ids, MAX_SET_IDS)
    acc = await j.account_id(account)
    idx = await mailbox_index(j, acc)
    trash = idx.require_role("trash")
    current, missing = await _current_mailboxes(j, acc, ids)
    if not permanent:
        update = {eid: _move_patch(mbs, trash["id"]) for eid, mbs in current.items()}
        moved, failed = await _apply_updates(j, acc, update)
        drop_mailbox_cache(j)
        return render.compact({"moved_to_trash": len(moved), "failed": failed, "not_found": missing})
    allowed = {trash["id"]} | ({junk["id"]} if (junk := idx.by_role("junk")) else set())
    outside = [eid for eid, mbs in current.items() if not {m for m, on in mbs.items() if on} <= allowed]
    if outside:
        raise Refused(
            "Permanent deletion is only allowed for emails that are in Trash or Junk.",
            hint="Delete without permanent=true first (moves to Trash).",
            details={"not_in_trash_or_junk": outside},
        )
    res = await j.one("Email/set", {"accountId": acc, "destroy": list(current)}, [MAIL])
    drop_mailbox_cache(j)
    return render.compact(
        {"deleted_permanently": len(res.get("destroyed") or []), "failed": _set_errors(res, "notDestroyed"), "not_found": missing}
    )


# ---------------------------------------------------------------------- mailboxes


async def manage_mailbox(
    j: Jmap,
    action: str,
    *,
    name: str | None = None,
    mailbox: str | None = None,
    parent: str | None = None,
    new_name: str | None = None,
    account: str | None = None,
) -> dict[str, Any]:
    acc = await j.account_id(account)
    idx = await mailbox_index(j, acc, refresh=True)
    args: dict[str, Any] = {"accountId": acc}
    if action == "create":
        if not name or not name.strip():
            raise InvalidInput("create needs name.")
        parent_id = idx.resolve(parent)["id"] if parent else None
        # @gotcha isSubscribed=true, otherwise IMAP clients may not show the new folder.
        args["create"] = {"mb": {"name": name.strip(), "parentId": parent_id, "isSubscribed": True}}
    elif action in ("rename", "move"):
        if not mailbox:
            raise InvalidInput(f"{action} needs mailbox.")
        mb = idx.resolve(mailbox)
        if mb.get("role"):
            raise Refused(f"'{idx.path(mb['id'])}' is a system mailbox ({mb['role']}) and stays where it is.")
        if action == "rename":
            if not new_name or not new_name.strip():
                raise InvalidInput("rename needs new_name.")
            args["update"] = {mb["id"]: {"name": new_name.strip()}}
        else:
            new_parent = idx.resolve(parent)["id"] if parent else None
            probe = new_parent
            while probe:
                if probe == mb["id"]:
                    raise InvalidInput("A mailbox cannot be moved into itself or one of its subfolders.")
                probe = idx.by_id.get(probe, {}).get("parentId")
            args["update"] = {mb["id"]: {"parentId": new_parent}}
    else:
        raise InvalidInput("action must be create, rename or move.")
    res = await j.one("Mailbox/set", args, [MAIL])
    errors = _set_errors(res, "notCreated") | _set_errors(res, "notUpdated")
    if errors:
        raise SetError(f"Mailbox {action} failed.", details=errors)
    drop_mailbox_cache(j)
    idx = await mailbox_index(j, acc, refresh=True)
    mailbox_id = res["created"]["mb"]["id"] if action == "create" else next(iter(args["update"]))
    return {"action": action, "id": mailbox_id, "path": idx.path(mailbox_id)}


async def delete_mailbox(j: Jmap, mailbox: str, *, remove_emails: bool = False, account: str | None = None) -> dict[str, Any]:
    acc = await j.account_id(account)
    idx = await mailbox_index(j, acc, refresh=True)
    mb = idx.resolve(mailbox)
    path = idx.path(mb["id"])
    if mb.get("role"):
        raise Refused(f"'{path}' is a system mailbox ({mb['role']}) and cannot be deleted.")
    if children := idx.children(mb["id"]):
        raise Refused(f"'{path}' has subfolders.", details={"subfolders": [idx.path(c["id"]) for c in children]})
    res = await j.one("Mailbox/set", {"accountId": acc, "destroy": [mb["id"]], "onDestroyRemoveEmails": bool(remove_emails)}, [MAIL])
    err = (res.get("notDestroyed") or {}).get(mb["id"])
    if err:
        if err.get("type") == "mailboxHasEmail":
            raise Refused(
                f"'{path}' still contains {mb.get('totalEmails', 'some')} emails.",
                hint="Move them first, or pass remove_emails=true: emails that are only in this mailbox are then deleted for good.",
            )
        raise SetError(f"Deleting '{path}' failed.", details={mb["id"]: err.get("type")})
    drop_mailbox_cache(j)
    return render.compact({"deleted": path, "emails_removed": mb.get("totalEmails") if remove_emails else None})


# ---------------------------------------------------------------------- filters (Sieve)


async def _sieve_account(j: Jmap, account: str | None) -> str:
    s = await j.session()
    _require(s, SIEVE, "Sieve filter management")
    return await j.account_id(account, SIEVE if s.primary(SIEVE) else MAIL)


async def list_filters(j: Jmap, *, account: str | None = None, include_content: bool = True, max_chars: int = 20000) -> dict[str, Any]:
    acc = await _sieve_account(j, account)
    res = await j.one("SieveScript/get", {"accountId": acc, "ids": None}, [SIEVE])
    out = []
    for script in res.get("list", []):
        item: dict[str, Any] = {"id": script["id"], "name": script.get("name"), "active": bool(script.get("isActive"))}
        if include_content and script.get("blobId"):
            data = await j.download(acc, script["blobId"], name=f"{script.get('name') or 'script'}.sieve", mime="application/sieve")
            item["content"], cut = render.truncate(att.decode_text(data, "utf-8"), max_chars)
            if cut:
                item["truncated"] = True
        out.append(item)
    return {"filters": out, "note": "Only one Sieve script can be active at a time."}


async def _own_domains(j: Jmap, acc: str) -> set[str]:
    domains = set(j.rt.config.internal_domains)
    s = await j.session()
    if s.has(SUBMISSION):
        res = await j.one("Identity/get", {"accountId": acc, "ids": None}, [MAIL, SUBMISSION])
        domains |= {(i.get("email") or "").rsplit("@", 1)[-1].lower() for i in res.get("list", []) if "@" in (i.get("email") or "")}
    if s.username and "@" in s.username:
        domains.add(s.username.rsplit("@", 1)[1].lower())
    return domains


async def save_filter(
    j: Jmap,
    name: str,
    script: str,
    *,
    activate: bool = True,
    allow_external_redirect: bool = False,
    deactivate_other: bool = False,
    account: str | None = None,
) -> dict[str, Any]:
    name = (name or "").strip()
    if not name:
        raise InvalidInput("name is empty.")
    if name.endswith(".previous"):
        raise InvalidInput("Names ending in '.previous' are reserved for backups.")
    acc = await _sieve_account(j, account)
    external = sieve_guard.external_targets(script, await _own_domains(j, acc))
    if external and not allow_external_redirect:
        raise Refused(
            "The script forwards mail to addresses outside this account's own domains.",
            hint="Only proceed if the user explicitly asked for exactly this forwarding; then call again with "
            "allow_external_redirect=true.",
            details={"targets": external},
        )
    s = await j.session()
    if s.has(BLOB):
        up = await j.one(
            "Blob/upload",
            {"accountId": acc, "create": {"k": {"data": [{"data:asText": script}], "type": "application/sieve"}}},
            [BLOB],
        )
        if "k" not in (up.get("created") or {}):
            raise SetError("Uploading the script failed.", details=_set_errors(up, "notCreated"))
        blob_id = up["created"]["k"]["id"]
    else:
        blob_id = (await j.upload(acc, script.encode("utf-8"), "application/sieve"))["blobId"]
    res = await j.call(
        [
            ("SieveScript/validate", {"accountId": acc, "blobId": blob_id}, "v"),
            ("SieveScript/get", {"accountId": acc, "ids": None}, "l"),
        ],
        [SIEVE],
    )
    verdict = res.get("v", "SieveScript/validate")
    if verdict.get("error"):
        err = verdict["error"]
        return {"saved": False, "valid": False, "error": err.get("description") or err.get("type")}
    scripts = res.get("l", "SieveScript/get").get("list", [])
    by_name = {sc.get("name"): sc for sc in scripts}
    existing = by_name.get(name)
    active_other = [sc.get("name") for sc in scripts if sc.get("isActive") and sc.get("name") != name]
    if activate and active_other and not deactivate_other:
        raise Refused(
            f"Another script is active ({', '.join(active_other)}); only one can be active.",
            hint="Merge the rules into the active script, or call again with deactivate_other=true "
            "(the other script stays saved, but inactive).",
        )
    set_args: dict[str, Any] = {"accountId": acc}
    backup_name = f"{name}.previous"
    if existing:
        backup = by_name.get(backup_name)
        set_args["update"] = {existing["id"]: {"blobId": blob_id}}
        if backup:
            set_args["update"][backup["id"]] = {"blobId": existing["blobId"]}
        else:
            set_args["create"] = {"bak": {"name": backup_name, "blobId": existing["blobId"]}}
        target = existing["id"]
    else:
        set_args["create"] = {"new": {"name": name, "blobId": blob_id}}
        target = "#new"
    if activate:
        set_args["onSuccessActivateScript"] = target
    result = await j.one("SieveScript/set", set_args, [SIEVE])
    errors = _set_errors(result, "notCreated") | _set_errors(result, "notUpdated")
    if errors:
        raise SetError("Saving the script failed.", details=errors)
    return render.compact(
        {
            "saved": True,
            "valid": True,
            "name": name,
            "active": activate,
            "backup_of_previous_version": backup_name if existing else None,
            "deactivated": active_other if activate else None,
            "forwards_to": external or None,
        }
    )


async def delete_filter(j: Jmap, name: str, *, account: str | None = None) -> dict[str, Any]:
    acc = await _sieve_account(j, account)
    scripts = (await j.one("SieveScript/get", {"accountId": acc, "ids": None}, [SIEVE])).get("list", [])
    target = next((sc for sc in scripts if sc.get("name") == name), None)
    if not target:
        raise NotFound(f"No filter '{name}'.", hint="Existing: " + ", ".join(sc.get("name", "?") for sc in scripts))
    calls: list = []
    if target.get("isActive"):
        calls.append(("SieveScript/set", {"accountId": acc, "onSuccessDeactivateScript": True}, "d"))
    calls.append(("SieveScript/set", {"accountId": acc, "destroy": [target["id"]]}, "x"))
    res = await j.call(calls, [SIEVE])
    out = res.get("x", "SieveScript/set")
    if errors := _set_errors(out, "notDestroyed"):
        raise SetError(f"Deleting '{name}' failed.", details=errors)
    return render.compact(
        {
            "deleted": name,
            "was_active": bool(target.get("isActive")) or None,
            "kept_backup": f"{name}.previous" if any(sc.get("name") == f"{name}.previous" for sc in scripts) else None,
        }
    )


async def set_vacation(
    j: Jmap,
    *,
    enabled: bool,
    subject: str | None = None,
    text: str | None = None,
    html: str | None = None,
    from_date: str | None = None,
    to_date: str | None = None,
    account: str | None = None,
) -> dict[str, Any]:
    s = await j.session()
    _require(s, VACATION, "vacation responses")
    acc = await j.account_id(account, VACATION if s.primary(VACATION) else MAIL)
    patch: dict[str, Any] = {"isEnabled": bool(enabled)}
    if subject is not None:
        patch["subject"] = subject or None
    if text is not None:
        patch["textBody"] = text or None
    if html is not None:
        patch["htmlBody"] = html or None
    if from_date is not None:
        patch["fromDate"] = utc_date(from_date)
    if to_date is not None:
        patch["toDate"] = utc_date(to_date)
    res = await j.call(
        [
            ("VacationResponse/set", {"accountId": acc, "update": {"singleton": patch}}, "s"),
            ("VacationResponse/get", {"accountId": acc, "ids": ["singleton"]}, "g"),
        ],
        [VACATION],
    )
    if errors := _set_errors(res.get("s", "VacationResponse/set"), "notUpdated"):
        raise SetError("Updating the vacation response failed.", details=errors)
    v = (res.get("g", "VacationResponse/get").get("list") or [{}])[0]
    return render.compact(
        {
            "enabled": bool(v.get("isEnabled")),
            "from": v.get("fromDate"),
            "to": v.get("toDate"),
            "subject": v.get("subject"),
            "text": v.get("textBody"),
            "html": bool(v.get("htmlBody")) or None,
        }
    ) | {"enabled": bool(v.get("isEnabled"))}


# ---------------------------------------------------------------------- unsubscribe


async def unsubscribe(j: Jmap, email_id: str, *, confirm: bool = False, account: str | None = None) -> dict[str, Any]:
    acc = await j.account_id(account)
    found, _ = await _get_emails(
        j, acc, [email_id], ["subject", "from", "header:List-Unsubscribe:asURLs", "header:List-Unsubscribe-Post:asText"]
    )
    if not found:
        raise NotFound(f"No email '{email_id}'.")
    email = found[0]
    info = unsub.parse_header(email.get("header:List-Unsubscribe:asURLs"), email.get("header:List-Unsubscribe-Post:asText"))
    base = {
        "email_id": email_id,
        "sender": render.addr((email.get("from") or [None])[0]),
        "subject": email.get("subject"),
    }
    if info["one_click"]:
        url = info["https"][0]
        host = urlsplit(url).hostname
        if not confirm:
            return {
                **base,
                "method": "one-click",
                "host": host,
                "next": "Call again with confirm=true to unsubscribe. This also tells the sender that the address is read.",
            }
        result = await unsub.one_click(url, timeout=10.0)
        return {**base, "method": "one-click", "host": host, **render.compact(result)}
    if info["mailto"]:
        target = unsub.parse_mailto(info["mailto"][0])
        return {
            **base,
            "method": "mailto",
            "mailto": target,
            "next": "No one-click link. Create a draft with write_email (to/subject/body above) and send it after the user agreed.",
        }
    if info["https"] or info["http"]:
        return {
            **base,
            "method": "manual",
            "url": (info["https"] or info["http"])[0],
            "next": "Only a web page without one-click support. It is not opened automatically; the user has to open it.",
        }
    return {**base, "method": None, "note": "This email has no List-Unsubscribe header."}
