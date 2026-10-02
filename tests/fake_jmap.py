"""In-memory test double of Stalwart's JMAP API.

`FakeStalwart().app` is an ASGI app meant to be driven through
``httpx.AsyncClient(transport=httpx.ASGITransport(app=fake.app), base_url="http://fake")``.

It implements a pragmatic subset of RFC 8620 (core), RFC 8621 (mail, submission,
vacation), RFC 9661 (sieve), RFC 9404 (blob) and RFC 9425 (quota) with the
camelCase wire format of the RFCs, plus a handful of deliberate Stalwart quirks
that bit real clients (marked ``QUIRK`` below).

Messages are real RFC 5322 bytes generated with Python's ``email`` package; every
Email object (seeded, created via Email/set, or parsed via Email/parse) is derived
by parsing those bytes, so the raw blob and the JSON view never disagree.
"""

from __future__ import annotations

import base64
import copy
import email
import email.errors
import email.policy
import hashlib
import html as html_lib
import io
import itertools
import json
import quopri
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.generator import BytesGenerator
from email.header import decode_header, make_header
from email.headerregistry import HeaderRegistry
from email.message import EmailMessage
from email.utils import format_datetime, formataddr, parsedate_to_datetime
from typing import Any
from urllib.parse import quote, unquote

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Route

CORE = "urn:ietf:params:jmap:core"
MAIL = "urn:ietf:params:jmap:mail"
SUBMISSION = "urn:ietf:params:jmap:submission"
VACATION = "urn:ietf:params:jmap:vacationresponse"
SIEVE = "urn:ietf:params:jmap:sieve"
QUOTA = "urn:ietf:params:jmap:quota"
BLOB = "urn:ietf:params:jmap:blob"
PRINCIPALS = "urn:ietf:params:jmap:principals"

MAX_SIZE_UPLOAD = 50_000_000
MAX_SIZE_REQUEST = 10_000_000
MAX_CALLS_IN_REQUEST = 16
MAX_OBJECTS_IN_GET = 500
MAX_OBJECTS_IN_SET = 500
QUOTA_HARD_LIMIT = 1_073_741_824

CAPABILITIES: dict[str, dict[str, Any]] = {
    CORE: {
        "maxSizeUpload": MAX_SIZE_UPLOAD,
        "maxConcurrentUpload": 4,
        "maxSizeRequest": MAX_SIZE_REQUEST,
        "maxConcurrentRequests": 4,
        "maxCallsInRequest": MAX_CALLS_IN_REQUEST,
        "maxObjectsInGet": MAX_OBJECTS_IN_GET,
        "maxObjectsInSet": MAX_OBJECTS_IN_SET,
        "collationAlgorithms": ["i;ascii-casemap"],
    },
    MAIL: {},
    SUBMISSION: {"maxDelayedSend": 0, "submissionExtensions": {}},
    VACATION: {},
    SIEVE: {},
    QUOTA: {},
    BLOB: {},
    PRINCIPALS: {},
}

# Stalwart 0.16 answers `forbidden` for these in accounts shared with the caller.
OWNER_ONLY_PREFIXES = ("Identity/", "EmailSubmission/", "SieveScript/", "VacationResponse/", "Quota/")

ERR_PREFIX = "urn:ietf:params:jmap:error:"
ROLE_MAILBOXES = [("Inbox", "inbox"), ("Drafts", "drafts"), ("Sent", "sent"), ("Trash", "trash"), ("Junk", "junk"), ("Archive", "archive")]
EMAIL_SORT_PROPERTIES = ["receivedAt", "sentAt", "size", "from", "to", "subject"]

DEFAULT_EMAIL_PROPS = [
    "id",
    "blobId",
    "threadId",
    "mailboxIds",
    "keywords",
    "size",
    "receivedAt",
    "messageId",
    "inReplyTo",
    "references",
    "sender",
    "from",
    "to",
    "cc",
    "bcc",
    "replyTo",
    "subject",
    "sentAt",
    "hasAttachment",
    "preview",
    "bodyValues",
    "textBody",
    "htmlBody",
    "attachments",
]
ALL_EMAIL_PROPS = set(DEFAULT_EMAIL_PROPS) | {"headers", "bodyStructure"}
DEFAULT_PARSE_PROPS = DEFAULT_EMAIL_PROPS[7:]  # RFC 8621 4.9: messageId .. attachments
DEFAULT_BODY_PROPS = ["partId", "blobId", "size", "name", "type", "charset", "disposition", "cid", "language", "location"]
ALL_BODY_PROPS = set(DEFAULT_BODY_PROPS) | {"headers", "subParts"}
HEADER_FORMS = {"Raw", "Text", "Addresses", "GroupedAddresses", "MessageIds", "Date", "URLs"}
MAILBOX_RIGHTS = [
    "mayReadItems",
    "mayAddItems",
    "mayRemoveItems",
    "maySetSeen",
    "maySetKeywords",
    "mayCreateChild",
    "mayRename",
    "mayDelete",
    "maySubmit",
    "mayShare",
]
_PROPS = {  # gettable properties per data type (generic /get)
    "Mailbox": {
        "id",
        "name",
        "parentId",
        "role",
        "sortOrder",
        "totalEmails",
        "unreadEmails",
        "totalThreads",
        "unreadThreads",
        "myRights",
        "isSubscribed",
        "shareWith",
    },
    "Identity": {"id", "name", "email", "replyTo", "bcc", "textSignature", "htmlSignature", "mayDelete"},
    "Thread": {"id", "emailIds"},
    "EmailSubmission": {
        "id",
        "identityId",
        "emailId",
        "threadId",
        "envelope",
        "sendAt",
        "undoStatus",
        "deliveryStatus",
        "dsnBlobIds",
        "mdnBlobIds",
    },
    "SieveScript": {"id", "name", "blobId", "isActive"},
    "VacationResponse": {"id", "isEnabled", "fromDate", "toDate", "subject", "textBody", "htmlBody"},
    "Quota": {"id", "resourceType", "used", "hardLimit", "scope", "name", "types", "warnLimit", "softLimit", "description"},
}

# Generation uses CRLF (wire format); parsing uses the modern policy.
_POLICY = email.policy.default
_SMTP = email.policy.SMTP
_REGISTRY = HeaderRegistry()
_KEYWORD_FORBIDDEN = set('(){]%*"\\')  # RFC 8621 4.1.1


def _valid_keyword(kw: Any) -> bool:
    return isinstance(kw, str) and 0 < len(kw) <= 255 and all(0x21 <= ord(c) <= 0x7E and c not in _KEYWORD_FORBIDDEN for c in kw)


# ---------------------------------------------------------------- exceptions


class _RequestError(Exception):
    """Aborts the whole HTTP request with a problem-details response."""

    def __init__(self, status: int, type_: str, detail: str, **extra: Any) -> None:
        super().__init__(detail)
        self.status, self.type, self.detail, self.extra = status, type_, detail, extra


class _MethodError(Exception):
    """Turns one method call into ``["error", {...}, callId]``."""

    def __init__(self, type_: str, **extra: Any) -> None:
        super().__init__(type_)
        self.type, self.extra = type_, extra


class _SetError(Exception):
    """A per-object SetError (notCreated / notUpdated / notDestroyed)."""

    def __init__(self, type_: str, description: str | None = None, **extra: Any) -> None:
        super().__init__(type_)
        self.body = {"type": type_, **({"description": description} if description else {}), **extra}


def _problem(status: int, type_: str, detail: str, **extra: Any) -> JSONResponse:
    body = {"type": type_, "status": status, "detail": detail, **extra}
    return JSONResponse(body, status_code=status, media_type="application/problem+json")


# ---------------------------------------------------------------- dates


def _parse_utc(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _fmt_utc(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fmt_date(dt: datetime) -> str:
    """RFC 3339 date-time keeping the original offset (JMAP ``Date`` type)."""
    off = dt.utcoffset() or timedelta(0)
    base = dt.strftime("%Y-%m-%dT%H:%M:%S")
    if not off:
        return base + "Z"
    minutes = int(abs(off.total_seconds())) // 60
    return f"{base}{'+' if off > timedelta(0) else '-'}{minutes // 60:02d}:{minutes % 60:02d}"


# ---------------------------------------------------------------- headers


def _unfold(raw: str) -> str:
    return re.sub(r"\r?\n(?=[ \t])", "", raw)


def _decode_text(raw: str) -> str:
    unfolded = _unfold(raw)
    try:
        return str(make_header(decode_header(unfolded))).strip()
    except Exception:  # malformed encoded-words: fall back to the unfolded value
        return unfolded.strip()


def _addresses(raw: str) -> list[dict[str, Any]]:
    try:
        header = _REGISTRY("To", _unfold(raw).strip())
    except Exception:
        return []
    return [{"name": a.display_name or None, "email": a.addr_spec} for a in header.addresses]


def _grouped_addresses(raw: str) -> list[dict[str, Any]]:
    try:
        header = _REGISTRY("To", _unfold(raw).strip())
    except Exception:
        return []
    groups: list[dict[str, Any]] = []
    for g in header.groups:
        addrs = [{"name": a.display_name or None, "email": a.addr_spec} for a in g.addresses]
        if g.display_name is None and groups and groups[-1]["name"] is None:
            groups[-1]["addresses"].extend(addrs)  # merge consecutive ungrouped addresses
        else:
            groups.append({"name": g.display_name, "addresses": addrs})
    return groups


def _header_form(raw: str, form: str) -> Any:
    """Convert a Raw header value into one of the RFC 8621 4.1.2 parsed forms."""
    if form == "Raw":
        return raw
    if form == "Text":
        return _decode_text(raw)
    if form == "Addresses":
        return _addresses(raw)
    if form == "GroupedAddresses":
        return _grouped_addresses(raw)
    if form == "MessageIds":
        ids = re.findall(r"<([^<>\s]+)>", _unfold(raw))
        return ids or None
    if form == "URLs":
        urls = [u.strip() for u in re.findall(r"<([^>]*)>", _unfold(raw))]
        return urls or None
    if form == "Date":
        try:
            dt = parsedate_to_datetime(_decode_text(raw))
        except (TypeError, ValueError, IndexError):
            return None
        return _fmt_date(dt if dt.tzinfo else dt.replace(tzinfo=UTC))
    raise ValueError(form)


def _parse_header_prop(prop: str) -> tuple[str, str, bool]:
    """``header:List-Unsubscribe:asURLs:all`` -> ("List-Unsubscribe", "URLs", True)."""
    parts = prop.split(":")
    if len(parts) < 2 or parts[0] != "header" or not parts[1]:
        raise _MethodError("invalidArguments", description=f"invalid property {prop}")
    form, all_ = "Raw", False
    for extra in parts[2:]:
        if extra == "all":
            all_ = True
        elif extra.startswith("as") and extra[2:] in HEADER_FORMS:
            form = extra[2:]
        else:
            raise _MethodError("invalidArguments", description=f"invalid property {prop}")
    return parts[1], form, all_


def _header_value(headers: list[dict[str, str]], prop: str) -> Any:
    name, form, all_ = _parse_header_prop(prop)
    values = [h["value"] for h in headers if h["name"].lower() == name.lower()]
    if all_:
        return [_header_form(v, form) for v in values]
    return _header_form(values[-1], form) if values else None


def _raw_header_fields(raw: bytes) -> list[tuple[str, str]]:
    """Exact (name, Raw value) pairs of the top-level header block (no unfolding)."""
    match = re.search(rb"\r?\n\r?\n", raw)
    block = raw[: match.start()] if match else raw
    fields: list[list[bytes]] = []
    for line in re.split(rb"\r?\n", block):
        if line[:1] in (b" ", b"\t") and fields:
            fields[-1][1] += b"\r\n" + line
        elif b":" in line:
            name, _, value = line.partition(b":")
            fields.append([name.strip(), value])
    return [(n.decode("utf-8", "replace"), v.decode("utf-8", "replace")) for n, v in fields]


def _looks_like_message(data: bytes) -> bool:
    return re.match(rb"[!-9;-~]+:", data) is not None


# ---------------------------------------------------------------- text helpers


def _html_to_text(markup: str) -> str:
    markup = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", markup)
    markup = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</li>|</tr>", "\n", markup)
    return html_lib.unescape(re.sub(r"<[^>]+>", " ", markup))


def _squash(text: str) -> str:
    return " ".join(text.split())


def _decode_bytes(data: bytes, charset: str | None) -> tuple[str, bool]:
    try:
        return data.decode(charset or "us-ascii"), False
    except (LookupError, UnicodeDecodeError):
        try:
            return data.decode("utf-8"), charset not in (None, "us-ascii")
        except UnicodeDecodeError:
            return data.decode("utf-8", "replace"), True


def _mark(text: str | None, terms: list[str], excerpt: bool) -> str | None:
    """Escape ``text`` and wrap every case-insensitive match of ``terms`` in <mark>."""
    if not text or not terms:
        return None
    spans = sorted((m.start(), m.end()) for t in terms if t for m in re.finditer(re.escape(t), text, re.IGNORECASE))
    if not spans:
        return None
    merged: list[list[int]] = []
    for s, e in spans:
        if merged and s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])

    def build(lo: int, hi: int) -> str:
        out, pos = [], lo
        for s, e in merged:
            if e <= lo or s >= hi:
                continue
            s, e = max(s, lo), min(e, hi)
            out.append(html_lib.escape(text[pos:s], quote=False))
            out.append(f"<mark>{html_lib.escape(text[s:e], quote=False)}</mark>")
            pos = e
        out.append(html_lib.escape(text[pos:hi], quote=False))
        return "".join(out)

    if not excerpt:
        return build(0, len(text))
    first_start, first_end = merged[0]
    lo = max(0, first_start - 40)
    hi = min(len(text), max(lo + 200, first_end))
    result = build(lo, hi)
    while len(result.encode()) > 255 and hi > first_end:  # RFC 8621 5.1: <= 255 octets
        hi = max(first_end, hi - 10)
        result = build(lo, hi)
    return result


def _unescape_pointer(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


def _json_pointer(value: Any, path: str) -> Any:
    """RFC 6901 pointer with the RFC 8620 3.7 ``*`` array-mapping extension."""
    if path == "":
        return value
    if not path.startswith("/"):
        raise _MethodError("invalidResultReference")
    return _walk_pointer(value, [_unescape_pointer(t) for t in path[1:].split("/")])


def _walk_pointer(value: Any, tokens: list[str]) -> Any:
    if not tokens:
        return value
    token, rest = tokens[0], tokens[1:]
    if isinstance(value, list):
        if token == "*":
            out: list[Any] = []
            for item in value:
                res = _walk_pointer(item, rest)
                out.extend(res) if isinstance(res, list) else out.append(res)
            return out
        if token.isdigit() and int(token) < len(value):
            return _walk_pointer(value[int(token)], rest)
    elif isinstance(value, dict) and token in value:
        return _walk_pointer(value[token], rest)
    raise _MethodError("invalidResultReference")


def _sieve_error(text: str) -> str | None:
    """Toy Sieve validator: balanced quotes/brackets/braces and no ``SYNTAX_ERROR`` token."""
    if "SYNTAX_ERROR" in text:
        return "Unexpected token 'SYNTAX_ERROR'"
    pairs, stack, i, n = {"}": "{", "]": "[", ")": "("}, [], 0, len(text)
    while i < n:
        c = text[i]
        if c == "#":
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                return "Unterminated comment"
            i = j + 1
        elif text.startswith("text:", i):
            m = re.compile(r"\r?\n\.\r?\n").search(text, i)
            if not m:
                return "Unterminated multi-line string"
            i = m.end() - 1
        elif c == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
            if i >= n:
                return "Unbalanced quotes"
        elif c in "{[(":
            stack.append(c)
        elif c in "}])":
            if not stack or stack.pop() != pairs[c]:
                return f"Unexpected '{c}'"
        i += 1
    return f"Unclosed '{stack[-1]}'" if stack else None


# ---------------------------------------------------------------- MIME building
#
# A body tree to render is ("multipart", subtype, [children]) or
# ("leaf", content_type, data: str | bytes, opts: dict).


def _fmt_addrs(items: Any) -> str:
    """Accepts EmailAddress dicts, (name, email) tuples or bare strings."""
    out = []
    for item in items:
        if isinstance(item, dict):
            name, addr = item.get("name"), item.get("email")
        elif isinstance(item, (tuple, list)):
            name, addr = item
        else:
            name, addr = None, item
        if not isinstance(addr, str) or not addr:
            raise ValueError("address without email")
        out.append(formataddr((name or "", addr), charset="utf-8"))
    return ", ".join(out)


def _fill(part: EmailMessage, node: tuple, next_boundary: Any) -> None:
    if node[0] == "multipart":
        kids = []
        for child in node[2]:
            kid = EmailMessage(policy=_POLICY)
            _fill(kid, child, next_boundary)
            kids.append(kid)
        part["Content-Type"] = f"multipart/{node[1]}"
        part.set_param("boundary", next_boundary())
        part.set_payload(kids)
        return
    _, ctype, data, opts = node
    part["Content-Type"] = ctype
    if isinstance(data, str) and ctype.startswith("text/"):
        charset = opts.get("charset") or "utf-8"
        text = data.replace("\r\n", "\n")
        encoded = text.encode(charset)
        part.set_param("charset", charset)
        if all(b < 128 for b in encoded) and all(len(line) <= 998 for line in encoded.split(b"\n")):
            part["Content-Transfer-Encoding"] = "7bit"
            part.set_payload(text)
        else:
            part["Content-Transfer-Encoding"] = "quoted-printable"
            part.set_payload(quopri.encodestring(encoded).decode("ascii"))
    else:
        raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        if opts.get("charset"):
            part.set_param("charset", opts["charset"])
        if ctype == "message/rfc822":  # RFC 2046 5.2.1: identity encodings only
            raw = re.sub(rb"\r?\n", b"\r\n", raw)
            part["Content-Transfer-Encoding"] = "8bit" if any(b > 127 for b in raw) else "7bit"
            part.set_payload(raw.decode("ascii", "surrogateescape"))  # written verbatim
        else:
            part["Content-Transfer-Encoding"] = "base64"
            part.set_payload(base64.encodebytes(raw).decode("ascii"))
    if opts.get("disposition") or opts.get("name"):
        params = {"filename": opts["name"]} if opts.get("name") else {}
        part.add_header("Content-Disposition", opts.get("disposition") or "attachment", **params)
    if opts.get("cid"):
        part["Content-ID"] = f"<{opts['cid'].strip('<>')}>"
    if opts.get("language"):
        part["Content-Language"] = ", ".join(opts["language"])
    if opts.get("location"):
        part["Content-Location"] = opts["location"]
    for name, value in opts.get("headers") or ():
        part[name] = value


def _render(headers: list[tuple[str, str]], body: tuple, next_boundary: Any) -> bytes:
    msg = EmailMessage(policy=_POLICY)
    for name, value in headers:
        msg[name] = value
    msg["MIME-Version"] = "1.0"
    _fill(msg, body, next_boundary)
    return msg.as_bytes(policy=_SMTP)


def _body_tree(alternatives: list[tuple], attachments: list[tuple]) -> tuple:
    """One text or HTML part -> single part; both -> multipart/alternative;
    any attachments -> wrapped in multipart/mixed."""
    if not alternatives:
        body: tuple = ("leaf", "text/plain", "", {})
    elif len(alternatives) == 1:
        body = alternatives[0]
    else:
        body = ("multipart", "alternative", alternatives)
    return ("multipart", "mixed", [body, *attachments]) if attachments else body


# ---------------------------------------------------------------- MIME parsing


def _flatten(msg: Any) -> bytes:
    buf = io.BytesIO()
    BytesGenerator(buf, mangle_from_=False, policy=_SMTP).flatten(msg)
    return buf.getvalue()


def _clean(value: Any) -> str:
    return str(value).encode("utf-8", "surrogateescape").decode("utf-8", "replace")


def _is_inline_media(ctype: str) -> bool:
    return ctype.startswith(("image/", "audio/", "video/"))


def _parse_structure(
    parts: list[dict], multipart_type: str, in_alternative: bool, html_body: list | None, text_body: list | None, attachments: list
) -> None:
    """Literal port of the RFC 8621 4.1.4 textBody/htmlBody/attachments algorithm."""
    text_length = len(text_body) if text_body is not None else -1
    html_length = len(html_body) if html_body is not None else -1
    for i, part in enumerate(parts):
        ctype = part["type"]
        is_inline = (
            part["disposition"] != "attachment"
            and (ctype in ("text/plain", "text/html") or _is_inline_media(ctype))
            and (i == 0 or (multipart_type != "related" and (_is_inline_media(ctype) or not part["name"])))
        )
        if ctype.startswith("multipart/"):
            sub = ctype.split("/", 1)[1]
            _parse_structure(part["subParts"], sub, in_alternative or sub == "alternative", html_body, text_body, attachments)
        elif is_inline:
            if multipart_type == "alternative":
                if ctype == "text/plain" and text_body is not None:
                    text_body.append(part)
                elif ctype == "text/html" and html_body is not None:
                    html_body.append(part)
                else:
                    attachments.append(part)
                continue
            if in_alternative:
                if ctype == "text/plain":
                    html_body = None
                if ctype == "text/html":
                    text_body = None
            if text_body is not None:
                text_body.append(part)
            if html_body is not None:
                html_body.append(part)
            if (text_body is None or html_body is None) and _is_inline_media(ctype):
                attachments.append(part)
        else:
            attachments.append(part)
    if multipart_type == "alternative" and text_body is not None and html_body is not None:
        if text_length == len(text_body) and html_length != len(html_body):
            text_body.extend(html_body[html_length:])
        if html_length == len(html_body) and text_length != len(text_body):
            html_body.extend(text_body[text_length:])


def _leaves(part: dict) -> list[dict]:
    if part.get("subParts") is None:
        return [part]
    return [leaf for sub in part["subParts"] for leaf in _leaves(sub)]


def _parse_message(raw: bytes, put_blob: Any) -> dict[str, Any]:
    """Parse RFC 5322 bytes into the JMAP Email properties that derive from content.

    ``put_blob(data, type) -> blobId`` registers every leaf part's decoded octets.
    Also returns the private keys ``_values`` (partId -> (text, encodingProblem))
    plus ``_text`` / ``_body`` (snippet source / searchable plain text).
    """
    msg = email.message_from_bytes(raw, policy=_POLICY)
    headers = [{"name": n, "value": v} for n, v in _raw_header_fields(raw)]
    counter = itertools.count(1)
    values: dict[str, tuple[str, bool]] = {}

    def walk(part: Any, part_headers: list[dict[str, str]]) -> dict[str, Any]:
        ctype = part.get_content_type()
        charset = part.get_content_charset() if ctype.startswith("text/") else part.get_param("charset")
        if ctype.startswith("text/") and not charset:
            charset = "us-ascii"  # RFC 2046 implicit charset
        cid, lang, loc = part.get("Content-ID"), part.get("Content-Language"), part.get("Content-Location")
        name = part.get_filename()
        node: dict[str, Any] = {
            "partId": None,
            "blobId": None,
            "size": 0,
            "headers": part_headers,
            "name": _clean(name) if name else None,
            "type": ctype,
            "charset": _clean(charset) if charset else None,
            "disposition": part.get_content_disposition(),
            "cid": _clean(cid).strip().strip("<>") if cid else None,
            "language": [t.strip() for t in _clean(lang).split(",") if t.strip()] if lang else None,
            "location": _clean(loc).strip() if loc else None,
        }
        payload = part.get_payload()
        if ctype.startswith("multipart/"):
            subs = payload if isinstance(payload, list) else []
            node["subParts"] = [walk(p, [{"name": n, "value": " " + _clean(v)} for n, v in p.raw_items()]) for p in subs]
            return node
        if ctype == "message/rfc822" and isinstance(payload, list) and payload:
            data = _flatten(payload[0])
        else:
            data = part.get_payload(decode=True) or b""
        node.update(partId=str(next(counter)), blobId=put_blob(data, ctype), size=len(data))
        if ctype.startswith("text/"):
            text, problem = _decode_bytes(data, charset)
            values[node["partId"]] = (text.replace("\r\n", "\n"), problem)
        return node

    root = walk(msg, headers)
    text_body: list[dict] = []
    html_body: list[dict] = []
    attachments: list[dict] = []
    _parse_structure([root], "mixed", False, html_body, text_body, attachments)

    def plain(part: dict) -> str:
        value = values.get(part["partId"])
        if value is None:
            return ""
        return _html_to_text(value[0]) if part["type"] == "text/html" else value[0]

    def last(name: str, form: str) -> Any:
        found = [h["value"] for h in headers if h["name"].lower() == name.lower()]
        return _header_form(found[-1], form) if found else None

    return {
        "messageId": last("Message-ID", "MessageIds"),
        "inReplyTo": last("In-Reply-To", "MessageIds"),
        "references": last("References", "MessageIds"),
        "sender": last("Sender", "Addresses"),
        "from": last("From", "Addresses"),
        "to": last("To", "Addresses"),
        "cc": last("Cc", "Addresses"),
        "bcc": last("Bcc", "Addresses"),
        "replyTo": last("Reply-To", "Addresses"),
        "subject": last("Subject", "Text"),
        "sentAt": last("Date", "Date"),
        "headers": headers,
        "bodyStructure": root,
        "textBody": text_body,
        "htmlBody": html_body,
        "attachments": attachments,
        "hasAttachment": any(p["disposition"] != "inline" for p in attachments),
        "preview": _squash(" ".join(plain(p) for p in text_body))[:256],
        "_values": values,
        "_text": _squash(" ".join(plain(p) for p in text_body)),  # snippet source
        "_body": " ".join(plain(p) for p in _leaves(root)),  # search haystack (all text parts)
    }


# ---------------------------------------------------------------- Email helpers

EMAIL_FILTER_KEYS = {
    "inMailbox",
    "inMailboxOtherThan",
    "before",
    "after",
    "minSize",
    "maxSize",
    "allInThreadHaveKeyword",
    "someInThreadHaveKeyword",
    "noneInThreadHaveKeyword",
    "hasKeyword",
    "notKeyword",
    "hasAttachment",
    "text",
    "from",
    "to",
    "cc",
    "bcc",
    "subject",
    "body",
    "header",
}
EMAIL_CREATE_KEYS = {
    "mailboxIds",
    "keywords",
    "receivedAt",
    "from",
    "sender",
    "to",
    "cc",
    "bcc",
    "replyTo",
    "subject",
    "sentAt",
    "messageId",
    "inReplyTo",
    "references",
    "headers",
    "bodyStructure",
    "bodyValues",
    "textBody",
    "htmlBody",
    "attachments",
}


def _render_part(part: dict, props: list[str], structure: bool) -> dict:
    """EmailBodyPart restricted to ``props`` (QUIRK B: applies to every part list)."""
    out = {}
    for prop in props:
        if prop != "subParts":
            out[prop] = _header_value(part["headers"], prop) if prop.startswith("header:") else copy.deepcopy(part.get(prop))
    if part.get("subParts") is not None and (structure or "subParts" in props):
        out["subParts"] = [_render_part(sub, props, structure) for sub in part["subParts"]]
    elif "subParts" in props:
        out["subParts"] = None
    return out


def _json_parts(node: Any) -> Any:
    """Yield every body-part dict of an Email/set create payload (any nesting)."""
    if isinstance(node, dict):
        yield node
        for sub in node.get("subParts") or []:
            yield from _json_parts(sub)
    elif isinstance(node, list):
        for item in node:
            yield from _json_parts(item)


def _keywords(value: Any) -> dict[str, bool]:
    if not isinstance(value, dict):
        raise _SetError("invalidProperties", "keywords must be an object", properties=["keywords"])
    out = {}
    for kw, flag in value.items():
        if flag is not True or not _valid_keyword(kw):
            raise _SetError("invalidProperties", f"invalid keyword {kw!r}", properties=["keywords"])
        out[kw.lower()] = True  # JMAP keywords are case-insensitive; stored lowercase
    return out


def _render_header_value(value: Any, form: str) -> str:
    """Inverse of _header_form for ``header:Name:asForm`` values in Email/set create."""
    if form in ("Raw", "Text"):
        if not isinstance(value, str):
            raise ValueError("string expected")
        return _unfold(value).strip()
    if form == "Addresses":
        return _fmt_addrs(value)
    if form == "GroupedAddresses":
        return _fmt_addrs([a for group in value for a in group["addresses"]])
    if form == "MessageIds":
        return " ".join(f"<{i}>" for i in value)
    if form == "URLs":
        return ", ".join(f"<{u}>" for u in value)
    dt = _parse_utc(value)
    if dt is None:
        raise ValueError("invalid date")
    return format_datetime(dt)


# ---------------------------------------------------------------- state containers


def _vacation_default() -> dict[str, Any]:
    return {"id": "singleton", "isEnabled": False, "fromDate": None, "toDate": None, "subject": None, "textBody": None, "htmlBody": None}


@dataclass
class _Account:
    id: str
    username: str
    password: str | None
    name: str
    tokens: set[str]
    identities: dict[str, dict] = field(default_factory=dict)
    mailboxes: dict[str, dict] = field(default_factory=dict)
    emails: dict[str, dict] = field(default_factory=dict)
    threads: dict[str, list[str]] = field(default_factory=dict)
    blobs: dict[str, tuple[bytes, str]] = field(default_factory=dict)
    scripts: dict[str, dict] = field(default_factory=dict)
    submissions: dict[str, dict] = field(default_factory=dict)
    vacation: dict[str, Any] = field(default_factory=_vacation_default)
    states: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    changes: dict[str, list[tuple[int, str, str]]] = field(default_factory=lambda: defaultdict(list))


@dataclass
class _Ctx:
    """Per-request processing context."""

    user: str
    using: set[str]
    access: dict[str, bool]
    request_created: dict[str, str] = field(default_factory=dict)
    responses: list[list] = field(default_factory=list)
    created: dict[str, dict[str, str]] = field(default_factory=lambda: defaultdict(dict))
    implicit: list[tuple[str, dict]] = field(default_factory=list)

    def resolve(self, type_: str, value: Any) -> Any:
        """Resolve a ``#creationId`` reference to an object created earlier in this request."""
        if isinstance(value, str) and value.startswith("#"):
            return self.created[type_].get(value[1:]) or self.request_created.get(value[1:])
        return value

    def remember(self, type_: str, creation_id: str, real_id: str) -> None:
        self.created[type_][creation_id] = real_id


# ---------------------------------------------------------------- the fake


class FakeStalwart:
    """A Stalwart-flavoured JMAP server living entirely in memory."""

    def __init__(self, base_url: str = "http://fake") -> None:
        self.base_url = base_url.rstrip("/")
        self.outbox: list[dict[str, Any]] = []
        self.http_log: list[tuple[str, str, int, bool]] = []
        self.calls: list[str] = []
        self.requests: list[Any] = []
        self.auth_failures = 0
        self.changes_mode = "request_error"  # or "method_error"
        self.now = lambda: datetime.now(UTC).replace(microsecond=0)
        self._accounts: dict[str, _Account] = {}
        self._shares: dict[tuple[str, str], bool] = {}
        self._injections: list[list[Any]] = []
        self._counters: dict[str, Any] = defaultdict(lambda: itertools.count(1))
        self._methods: dict[str, tuple[str, Any, bool]] = {
            "Core/echo": (CORE, lambda ctx, acc, args: args, False),
            "Mailbox/get": (MAIL, self._mailbox_get, False),
            "Mailbox/set": (MAIL, self._mailbox_set, True),
            "Email/query": (MAIL, self._email_query, False),
            "Email/get": (MAIL, self._email_get, False),
            "Email/set": (MAIL, self._email_set, True),
            "Email/changes": (MAIL, self._email_changes, False),
            "Email/parse": (MAIL, self._email_parse, False),
            "Thread/get": (MAIL, self._thread_get, False),
            "SearchSnippet/get": (MAIL, self._snippet_get, False),
            "Identity/get": (SUBMISSION, self._identity_get, False),
            "EmailSubmission/get": (SUBMISSION, self._submission_get, False),
            "EmailSubmission/set": (SUBMISSION, self._submission_set, True),
            "SieveScript/get": (SIEVE, self._sieve_get, False),
            "SieveScript/query": (SIEVE, self._sieve_query, False),
            "SieveScript/set": (SIEVE, self._sieve_set, True),
            "SieveScript/validate": (SIEVE, self._sieve_validate, False),
            "Blob/upload": (BLOB, self._blob_upload, True),
            "Blob/get": (BLOB, self._blob_get, False),
            "VacationResponse/get": (VACATION, self._vacation_get, False),
            "VacationResponse/set": (VACATION, self._vacation_set, True),
            "Quota/get": (QUOTA, self._quota_get, False),
            "Principal/query": (PRINCIPALS, self._principal_query, False),
            "Principal/get": (PRINCIPALS, self._principal_get, False),
        }
        methods = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
        self.app = Starlette(routes=[Route("/{path:path}", self._handle, methods=methods)])

    # ------------------------------------------------------------ seeding API

    def add_account(self, username: str, password: str | None = None, name: str | None = None, tokens: Any = ()) -> str:
        acc = _Account(self._next("a"), username, password, name or username, set(tokens))
        self._accounts[acc.id] = acc
        for mb_name, role in ROLE_MAILBOXES:
            self.add_mailbox(acc.id, mb_name, role=role)
        return acc.id

    def add_identity(
        self,
        account_id: str,
        email: str,
        name: str = "",
        *,
        reply_to: Any = None,
        bcc: Any = None,
        text_signature: str = "",
        html_signature: str = "",
        may_delete: bool = True,
    ) -> str:
        acc = self._acc(account_id)
        iid = self._next("i")
        acc.identities[iid] = {
            "id": iid,
            "name": name,
            "email": email,
            "replyTo": reply_to,
            "bcc": bcc,
            "textSignature": text_signature,
            "htmlSignature": html_signature,
            "mayDelete": may_delete,
        }
        self._touch(acc, "Identity", iid, "created")
        return iid

    def add_mailbox(
        self,
        account_id: str,
        name: str,
        role: str | None = None,
        parent_id: str | None = None,
        *,
        sort_order: int = 0,
        is_subscribed: bool = True,
    ) -> str:
        acc = self._acc(account_id)
        parent = self.mailbox_id(account_id, parent_id) if parent_id else None
        mid = self._next("m")
        acc.mailboxes[mid] = {
            "id": mid,
            "name": name,
            "parentId": parent,
            "role": role,
            "sortOrder": sort_order,
            "isSubscribed": is_subscribed,
            "shareWith": {},
        }
        self._touch(acc, "Mailbox", mid, "created")
        return mid

    def mailbox_id(self, account_id: str, role_or_name: str) -> str:
        """Resolve a mailbox id, role or (case-insensitive) name to the mailbox id."""
        acc = self._acc(account_id)
        if role_or_name in acc.mailboxes:
            return role_or_name
        for key in ("role", "name"):
            for mb in acc.mailboxes.values():
                if (mb[key] or "").lower() == str(role_or_name).lower():
                    return mb["id"]
        raise KeyError(f"no mailbox {role_or_name!r} in account {account_id}")

    def add_email(
        self,
        account_id: str,
        *,
        mailboxes: Any = ("inbox",),
        subject: str | None = "",
        from_: Any = None,
        to: Any = (),
        cc: Any = (),
        bcc: Any = (),
        reply_to: Any = (),
        text: str | None = None,
        html: str | None = None,
        attachments: Any = (),
        received_at: Any = None,
        sent_at: Any = None,
        keywords: dict | None = None,
        headers: Any = None,
        message_id: str | None = None,
        in_reply_to: Any = None,
        references: Any = None,
    ) -> str:
        """Seed a message. ``attachments`` items are ``(name, type, data[, opts])``; use type
        ``message/rfc822`` with another email's ``raw`` bytes to attach a whole message."""
        acc = self._acc(account_id)
        received = _parse_utc(received_at) if received_at else self.now()
        sent = _parse_utc(sent_at) if sent_at else received
        if received is None or sent is None:
            raise ValueError(f"invalid received_at/sent_at: {received_at!r} / {sent_at!r}")
        hdrs: list[tuple[str, str]] = []
        if from_:
            hdrs.append(("From", _fmt_addrs([from_])))
        for hname, items in (("To", to), ("Cc", cc), ("Bcc", bcc), ("Reply-To", reply_to)):
            if items:
                hdrs.append((hname, _fmt_addrs(items)))
        if subject is not None:
            hdrs.append(("Subject", subject))
        hdrs.append(("Date", format_datetime(sent)))
        hdrs.append(("Message-ID", f"<{message_id or self._message_id(from_)}>"))
        for hname, ids in (("In-Reply-To", in_reply_to), ("References", references)):
            if ids:
                ids = [ids] if isinstance(ids, str) else ids
                hdrs.append((hname, " ".join(f"<{i.strip('<>')}>" for i in ids)))
        hdrs.extend(headers.items() if isinstance(headers, dict) else (headers or []))
        alternatives = [
            ("leaf", ctype, content, {}) for ctype, content in (("text/plain", text), ("text/html", html)) if content is not None
        ]
        leaves = [
            ("leaf", ctype.lower(), data, {"name": name, "disposition": "attachment", **(opts[0] if opts else {})})
            for name, ctype, data, *opts in attachments
        ]
        raw = _render(hdrs, _body_tree(alternatives, leaves), self._boundary)
        mailbox_ids = {self.mailbox_id(account_id, m): True for m in mailboxes}
        kws = {k.lower(): True for k, v in (keywords or {}).items() if v}
        return self._store_email(acc, raw, mailbox_ids, kws, _fmt_utc(received))["id"]

    def add_sieve_script(self, account_id: str, name: str, content: str, active: bool = False) -> str:
        acc = self._acc(account_id)
        sid = self._next("sc")
        if active:
            for script in acc.scripts.values():
                script["isActive"] = False
        acc.scripts[sid] = {
            "id": sid,
            "name": name,
            "isActive": active,
            "blobId": self._put_blob(acc, content.encode(), "application/sieve"),
        }
        self._touch(acc, "SieveScript", sid, "created")
        return sid

    def share(self, owner_account: str, with_account: str, read_only: bool = False) -> None:
        """Make ``owner_account`` visible in ``with_account``'s session (isPersonal: false)."""
        for account_id in (owner_account, with_account):
            self._acc(account_id)  # KeyError for unknown accounts
        self._shares[(owner_account, with_account)] = read_only

    def inject(self, status: int, body: Any = "", times: int = 1, headers: dict | None = None) -> None:
        """The next ``times`` HTTP requests (any path) get this canned response."""
        self._injections.append([status, body, times, headers or {}])

    # ------------------------------------------------------------ inspection API

    def account(self, account_id: str) -> _Account:
        return self._acc(account_id)

    def email(self, account_id: str, email_id: str) -> dict[str, Any]:
        return self._acc(account_id).emails[email_id]

    def email_state(self, account_id: str) -> str:
        return self._state(self._acc(account_id), "Email")

    def blob(self, account_id: str, blob_id: str) -> bytes:
        return self._acc(account_id).blobs[blob_id][0]

    # ------------------------------------------------------------ internals: storage

    def _acc(self, account_id: str) -> _Account:
        try:
            return self._accounts[account_id]
        except KeyError:
            raise KeyError(f"unknown account {account_id!r}") from None

    def _next(self, prefix: str) -> str:
        return f"{prefix}{next(self._counters[prefix])}"

    def _boundary(self) -> str:
        return f"=_fake-boundary-{next(self._counters['boundary'])}"

    def _message_id(self, from_: Any) -> str:
        if isinstance(from_, (tuple, list)):
            addr = from_[1]
        else:
            addr = from_.get("email") if isinstance(from_, dict) else from_
        domain = addr.rsplit("@", 1)[-1] if isinstance(addr, str) and "@" in addr else "stalwart.fake"
        return f"{self._next('fake-')}@{domain}"

    def _state(self, acc: _Account, type_: str) -> str:
        return f"s{acc.states[type_]}"

    def _touch(self, acc: _Account, type_: str, obj_id: str, kind: str) -> None:
        acc.states[type_] += 1
        acc.changes[type_].append((acc.states[type_], obj_id, kind))

    def _email_changed(self, acc: _Account, email_id: str, kind: str) -> None:
        self._touch(acc, "Email", email_id, kind)
        for dependent in ("Mailbox", "Thread", "Quota"):  # counts / membership / usage
            acc.states[dependent] += 1

    def _put_blob(self, acc: _Account, data: bytes, type_: str) -> str:
        blob_id = "b" + hashlib.sha1(data).hexdigest()
        acc.blobs.setdefault(blob_id, (data, type_))
        return blob_id

    def _thread_for(self, acc: _Account, info: dict[str, Any]) -> str:
        refs = set((info["references"] or []) + (info["inReplyTo"] or []))
        own = set(info["messageId"] or [])
        for other in acc.emails.values():
            if refs & set(other["messageId"] or []):
                return other["threadId"]
        for other in acc.emails.values():
            if own & set((other["references"] or []) + (other["inReplyTo"] or [])):
                return other["threadId"]
        return self._next("t")

    def _store_email(self, acc: _Account, raw: bytes, mailbox_ids: dict, keywords: dict, received_at: str) -> dict[str, Any]:
        info = _parse_message(raw, lambda data, type_: self._put_blob(acc, data, type_))
        thread_id = self._thread_for(acc, info)
        stored = {
            "id": self._next("e"),
            "blobId": self._put_blob(acc, raw, "message/rfc822"),
            "threadId": thread_id,
            "mailboxIds": mailbox_ids,
            "keywords": keywords,
            "size": len(raw),
            "receivedAt": received_at,
            **info,
            "raw": raw,
        }
        acc.emails[stored["id"]] = stored
        acc.threads.setdefault(thread_id, []).append(stored["id"])
        self._email_changed(acc, stored["id"], "created")
        return stored

    def _destroy_email(self, acc: _Account, email_id: str) -> None:
        stored = acc.emails.pop(email_id)
        members = acc.threads.get(stored["threadId"], [])
        if email_id in members:
            members.remove(email_id)
        if not members:
            acc.threads.pop(stored["threadId"], None)
        self._email_changed(acc, email_id, "destroyed")

    def _access(self, user: str) -> dict[str, bool]:
        """Account ids the authenticated user can see -> isReadOnly."""
        access = {user: False}
        access.update({owner: ro for (owner, grantee), ro in self._shares.items() if grantee == user})
        for owner, acc in self._accounts.items():
            granted = [mb["shareWith"][user] for mb in acc.mailboxes.values() if user in mb.get("shareWith", {})]
            if owner != user and granted and owner not in access:
                writable = ("mayAddItems", "mayRemoveItems", "maySetSeen", "maySetKeywords")
                access[owner] = not any(g.get(r) for g in granted for r in writable)
        return access

    # ------------------------------------------------------------ internals: HTTP

    async def _handle(self, request: Request) -> Response:
        method, path = request.method, request.url.path
        user = self._authenticate(request)
        if self._injections:
            status, body, _, headers = injection = self._injections[0]
            injection[2] -= 1
            if injection[2] <= 0:
                self._injections.pop(0)
            if isinstance(body, (dict, list)):
                body = json.dumps(body)
            text = body.decode() if isinstance(body, bytes) else str(body)
            media = "application/json" if text.lstrip()[:1] in ("{", "[") else "text/plain"
            self.http_log.append((method, path, status, user is not None))
            return Response(text, status_code=status, media_type=media, headers=headers)
        if user is None:
            self.auth_failures += 1
            response: Response = JSONResponse(
                {"type": "about:blank", "status": 401, "title": "Unauthorized", "detail": "You have to authenticate first."},
                status_code=401,
                media_type="application/problem+json",
                headers={"WWW-Authenticate": 'Basic realm="Stalwart Server"'},
            )
        else:
            try:
                response = await self._route(request, user)
            except _RequestError as err:
                response = _problem(err.status, err.type, err.detail, **err.extra)
        self.http_log.append((method, path, response.status_code, user is not None))
        return response

    def _authenticate(self, request: Request) -> str | None:
        scheme, _, credentials = request.headers.get("authorization", "").partition(" ")
        credentials = credentials.strip()
        if scheme.lower() == "basic":
            try:
                username, _, password = base64.b64decode(credentials).decode("utf-8").partition(":")
            except (ValueError, UnicodeDecodeError):
                return None
            for acc in self._accounts.values():
                if acc.username == username and acc.password is not None and acc.password == password:
                    return acc.id
        elif scheme.lower() == "bearer" and credentials:
            for acc in self._accounts.values():
                if credentials in acc.tokens:
                    return acc.id
        return None

    async def _route(self, request: Request, user: str) -> Response:
        method, path = request.method, request.url.path
        raw_path = request.scope.get("raw_path") or path.encode()
        segs = [unquote(s) for s in raw_path.decode("latin-1").split("?")[0].split("/")]
        if method == "GET" and re.fullmatch(r"/\.well-known/jmap/?", path):
            return RedirectResponse(self.base_url + "/jmap/session", status_code=307)
        if method == "GET" and re.fullmatch(r"/jmap/session/?", path):
            return JSONResponse(self._session(user))
        if method == "POST" and re.fullmatch(r"/jmap/?", path):
            return await self._api(request, user)
        if method == "GET" and segs[1:3] == ["jmap", "download"] and len(segs) >= 6:
            return self._download(request, user, segs[3], segs[4], "/".join(segs[5:]))
        if method == "POST" and segs[1:3] == ["jmap", "upload"] and len(segs) >= 4:
            return await self._upload(request, user, segs[3])
        return _problem(404, "about:blank", "The requested resource does not exist on this server.")

    def _session(self, user: str) -> dict[str, Any]:
        accounts = {}
        for acc_id, read_only in self._access(user).items():
            caps: dict[str, Any] = {cap: {} for cap in CAPABILITIES if cap != CORE}
            caps[MAIL] = {
                "maxMailboxesPerEmail": None,
                "maxMailboxDepth": 10,
                "maxSizeMailboxName": 255,
                "maxSizeAttachmentsPerEmail": MAX_SIZE_UPLOAD,
                "emailQuerySortOptions": EMAIL_SORT_PROPERTIES,
                "mayCreateTopLevelMailbox": not read_only,
            }
            caps[SUBMISSION] = CAPABILITIES[SUBMISSION]
            accounts[acc_id] = {
                "name": self._accounts[acc_id].name,
                "isPersonal": acc_id == user,
                "isReadOnly": read_only,
                "accountCapabilities": caps,
            }
        base = self.base_url
        session: dict[str, Any] = {
            "capabilities": CAPABILITIES,
            "accounts": accounts,
            "primaryAccounts": {cap: user for cap in CAPABILITIES},
            "username": self._accounts[user].username,
            "apiUrl": f"{base}/jmap/",
            "downloadUrl": f"{base}/jmap/download/{{accountId}}/{{blobId}}/{{name}}?accept={{type}}",
            "uploadUrl": f"{base}/jmap/upload/{{accountId}}/",
            "eventSourceUrl": f"{base}/jmap/eventsource/?types={{types}}&closeafter={{closeafter}}&ping={{ping}}",
        }
        session["state"] = hashlib.sha1(json.dumps(session, sort_keys=True).encode()).hexdigest()[:16]
        return copy.deepcopy(session)

    def _download(self, request: Request, user: str, account_id: str, blob_id: str, name: str) -> Response:
        acc = self._accounts.get(account_id)
        if account_id not in self._access(user) or acc is None or blob_id not in acc.blobs:
            return _problem(404, "about:blank", "The requested resource does not exist on this server.")
        data, type_ = acc.blobs[blob_id]
        media = request.query_params.get("accept") or type_ or "application/octet-stream"
        return Response(data, media_type=media, headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(name)}"})

    async def _upload(self, request: Request, user: str, account_id: str) -> Response:
        access = self._access(user)
        if account_id not in access:
            return _problem(404, "about:blank", "Account not found.")
        if access[account_id]:
            return _problem(403, "about:blank", "Account is read-only.")
        data = await request.body()
        if len(data) > MAX_SIZE_UPLOAD:
            return _problem(400, ERR_PREFIX + "limit", "Upload too large.", limit="maxSizeUpload")
        type_ = request.headers.get("content-type") or "application/octet-stream"
        blob_id = self._put_blob(self._accounts[account_id], data, type_)
        return JSONResponse({"accountId": account_id, "blobId": blob_id, "type": type_, "size": len(data)})

    # ------------------------------------------------------------ internals: JMAP request

    async def _api(self, request: Request, user: str) -> Response:
        body = await request.body()
        if len(body) > MAX_SIZE_REQUEST:
            raise _RequestError(400, ERR_PREFIX + "limit", "Request too large.", limit="maxSizeRequest")
        try:
            req = json.loads(body)
        except ValueError:
            raise _RequestError(400, ERR_PREFIX + "notJSON", "Request body is not valid JSON.") from None
        self.requests.append(req)
        calls = req.get("methodCalls") if isinstance(req, dict) else None
        using = req.get("using") if isinstance(req, dict) else None
        if not (
            isinstance(using, list)
            and all(isinstance(u, str) for u in using)
            and isinstance(calls, list)
            and all(
                isinstance(c, list) and len(c) == 3 and isinstance(c[0], str) and isinstance(c[1], dict) and isinstance(c[2], str)
                for c in calls
            )
        ):
            raise _RequestError(400, ERR_PREFIX + "notRequest", "Body is not a JMAP Request object.")
        unknown = [u for u in using if u not in CAPABILITIES]
        if unknown:
            raise _RequestError(400, ERR_PREFIX + "unknownCapability", f"Unknown capability '{unknown[0]}'.")
        if len(calls) > MAX_CALLS_IN_REQUEST:
            raise _RequestError(400, ERR_PREFIX + "limit", "Too many method calls.", limit="maxCallsInRequest")
        given = req.get("createdIds") if isinstance(req.get("createdIds"), dict) else {}
        ctx = _Ctx(user, set(using) | {CORE}, self._access(user), dict(given))
        for name, args, call_id in calls:
            self._dispatch(ctx, name, args, call_id)
        out: dict[str, Any] = {"methodResponses": ctx.responses, "sessionState": self._session(user)["state"]}
        if "createdIds" in req:
            out["createdIds"] = {**ctx.request_created, **{k: v for ids in ctx.created.values() for k, v in ids.items()}}
        return JSONResponse(out)

    def _dispatch(self, ctx: _Ctx, name: str, args: dict, call_id: str) -> None:
        self.calls.append(name)
        entry = self._methods.get(name)
        try:
            # Stalwart answers unknownMethod when the method's capability is not in `using`.
            if entry is None or entry[0] not in ctx.using:
                raise _MethodError("unknownMethod")
            _, handler, writes = entry
            args = self._resolve_refs(ctx, args)
            acc = None if name == "Core/echo" else self._account_for(ctx, args, writes)
            if acc is not None and acc.id != ctx.user and name.startswith(OWNER_ONLY_PREFIXES):
                raise _MethodError("forbidden", description=f"You are not an owner of account {acc.id}")
            result = handler(ctx, acc, args)
        except _MethodError as err:
            ctx.implicit.clear()
            ctx.responses.append(["error", {"type": err.type, **err.extra}, call_id])
            return
        ctx.responses.append([name, result, call_id])
        ctx.responses.extend([n, r, call_id] for n, r in ctx.implicit)
        ctx.implicit.clear()

    def _resolve_refs(self, ctx: _Ctx, args: dict) -> dict:
        """RFC 8620 3.7 result references (``"#ids": {resultOf, name, path}``)."""
        out = {}
        for key, value in args.items():
            if not key.startswith("#"):
                out[key] = value
                continue
            if key[1:] in args:
                raise _MethodError("invalidArguments", description=f"both '{key[1:]}' and '{key}' given")
            if not (isinstance(value, dict) and all(isinstance(value.get(k), str) for k in ("resultOf", "name", "path"))):
                raise _MethodError("invalidResultReference")
            for name, result, call_id in ctx.responses:
                if call_id == value["resultOf"]:  # the FIRST response with that call id
                    if name != value["name"]:
                        raise _MethodError("invalidResultReference")
                    out[key[1:]] = copy.deepcopy(_json_pointer(result, value["path"]))
                    break
            else:
                raise _MethodError("invalidResultReference")
        return out

    def _account_for(self, ctx: _Ctx, args: dict, writes: bool) -> _Account:
        account_id = args.get("accountId")
        if not isinstance(account_id, str):
            raise _MethodError("invalidArguments", description="accountId is required")
        if account_id not in ctx.access:
            raise _MethodError("accountNotFound")
        if writes and ctx.access[account_id]:
            raise _MethodError("accountReadOnly")
        return self._accounts[account_id]

    # ------------------------------------------------------------ generic /get and /set

    def _get(self, acc: _Account, args: dict, objects: dict[str, dict], type_: str) -> dict:
        ids = args.get("ids")
        if ids is None:
            ids = list(objects)
        elif not isinstance(ids, list):
            raise _MethodError("invalidArguments", description="ids must be a list or null")
        if len(ids) > MAX_OBJECTS_IN_GET:
            raise _MethodError("requestTooLarge")
        props = args.get("properties")
        if props is not None:
            if not isinstance(props, list) or any(p not in _PROPS[type_] for p in props):
                raise _MethodError("invalidArguments", description=f"unknown {type_} property")
            props = ["id", *[p for p in props if p != "id"]]
        found, not_found = [], []
        for oid in ids:
            obj = objects.get(oid) if isinstance(oid, str) else None
            if obj is None:
                not_found.append(oid)
            else:
                found.append(copy.deepcopy(obj if props is None else {p: obj.get(p) for p in props}))
        return {"accountId": acc.id, "state": self._state(acc, type_), "list": found, "notFound": not_found}

    def _run_set(
        self, ctx: _Ctx, acc: _Account, args: dict, type_: str, create: Any = None, update: Any = None, destroy: Any = None
    ) -> dict:
        """Run create/update/destroy callbacks; callbacks raise _SetError on failure.

        ``create(obj) -> (id, createdInfo)``, ``update(id, patch) -> dict | None``, ``destroy(id)``.
        Returns the raw result; pass it through ``_finish_set`` after any post-processing.
        """
        if args.get("ifInState") is not None and args["ifInState"] != self._state(acc, type_):
            raise _MethodError("stateMismatch")
        for key, kind in (("create", dict), ("update", dict), ("destroy", list)):
            if args.get(key) is not None and not isinstance(args[key], kind):
                raise _MethodError("invalidArguments", description=f"'{key}' has the wrong type")
        if sum(len(args.get(k) or ()) for k in ("create", "update", "destroy")) > MAX_OBJECTS_IN_SET:
            raise _MethodError("requestTooLarge")
        res: dict[str, Any] = {
            "accountId": acc.id,
            "oldState": self._state(acc, type_),
            "newState": None,
            "created": {},
            "updated": {},
            "destroyed": [],
            "notCreated": {},
            "notUpdated": {},
            "notDestroyed": {},
        }
        for creation_id, obj in (args.get("create") or {}).items():
            try:
                if create is None:
                    raise _SetError("forbidden", f"{type_} objects cannot be created")
                if not isinstance(obj, dict):
                    raise _SetError("invalidProperties", "object expected")
                new_id, info = create(obj)
                ctx.remember(type_, creation_id, new_id)
                res["created"][creation_id] = info
            except _SetError as err:
                res["notCreated"][creation_id] = err.body
        for oid, patch in (args.get("update") or {}).items():
            real = ctx.resolve(type_, oid)
            try:
                if update is None:
                    raise _SetError("forbidden", f"{type_} objects cannot be updated")
                if not isinstance(patch, dict):
                    raise _SetError("invalidPatch", "patch object expected")
                res["updated"][real] = update(real, patch)
            except _SetError as err:
                res["notUpdated"][oid] = err.body
        for oid in args.get("destroy") or []:
            real = ctx.resolve(type_, oid)
            try:
                if destroy is None:
                    raise _SetError("forbidden", f"{type_} objects cannot be destroyed")
                destroy(real)
                res["destroyed"].append(real)
            except _SetError as err:
                res["notDestroyed"][oid] = err.body
        return res

    def _finish_set(self, acc: _Account, type_: str, res: dict) -> dict:
        res["newState"] = self._state(acc, type_)
        for key in ("created", "updated", "destroyed", "notCreated", "notUpdated", "notDestroyed"):
            res[key] = res[key] or None  # RFC 8620 5.3: null when empty
        return res

    # ------------------------------------------------------------ Mailbox

    def _mailbox_view(self, acc: _Account, mb: dict, read_only: bool) -> dict:
        inside = [e for e in acc.emails.values() if mb["id"] in e["mailboxIds"]]
        unread = [e for e in inside if "$seen" not in e["keywords"]]
        return {
            **mb,
            "totalEmails": len(inside),
            "unreadEmails": len(unread),
            "totalThreads": len({e["threadId"] for e in inside}),
            "unreadThreads": len({e["threadId"] for e in unread}),
            "myRights": {r: not read_only or r == "mayReadItems" for r in MAILBOX_RIGHTS},
            "shareWith": copy.deepcopy(mb.get("shareWith", {})),
        }

    def _mailbox_get(self, ctx: _Ctx, acc: _Account, args: dict) -> dict:
        views = {mid: self._mailbox_view(acc, mb, ctx.access[acc.id]) for mid, mb in acc.mailboxes.items()}
        if acc.id != ctx.user and any(ctx.user in mb.get("shareWith", {}) for mb in acc.mailboxes.values()):
            views = {
                mid: {**v, "myRights": acc.mailboxes[mid]["shareWith"][ctx.user]}
                for mid, v in views.items()
                if ctx.user in acc.mailboxes[mid]["shareWith"]
            }
        return self._get(acc, args, views, "Mailbox")

    def _mailbox_set(self, ctx: _Ctx, acc: _Account, args: dict) -> dict:
        remove_emails = bool(args.get("onDestroyRemoveEmails"))

        def check_parent(value: Any, self_id: str | None = None) -> str | None:
            if value is None:
                return None
            parent = ctx.resolve("Mailbox", value)
            if parent not in acc.mailboxes:
                raise _SetError("invalidProperties", "parentId does not exist", properties=["parentId"])
            cursor = parent
            while cursor is not None:
                if cursor == self_id:
                    raise _SetError("invalidProperties", "parentId would create a cycle", properties=["parentId"])
                cursor = acc.mailboxes[cursor]["parentId"]
            return parent

        def check_name(name: Any, parent: str | None, self_id: str | None = None) -> None:
            if not isinstance(name, str) or not name.strip():
                raise _SetError("invalidProperties", "name is required", properties=["name"])
            if any(m["id"] != self_id and m["parentId"] == parent and m["name"] == name for m in acc.mailboxes.values()):
                raise _SetError("invalidProperties", f"Mailbox '{name}' already exists", properties=["name"])

        def create(obj: dict) -> tuple[str, dict]:
            bad = [k for k in obj if k not in ("name", "parentId", "isSubscribed", "role", "sortOrder")]
            if bad:
                raise _SetError("invalidProperties", properties=bad)
            parent = check_parent(obj.get("parentId"))
            check_name(obj.get("name"), parent)
            role = obj.get("role")
            if role is not None and (not isinstance(role, str) or any(m["role"] == role.lower() for m in acc.mailboxes.values())):
                raise _SetError("invalidProperties", "role is invalid or already in use", properties=["role"])
            mid = self._next("m")
            acc.mailboxes[mid] = {
                "id": mid,
                "name": obj["name"],
                "parentId": parent,
                "role": role.lower() if role else None,
                "sortOrder": int(obj.get("sortOrder") or 0),
                "isSubscribed": bool(obj.get("isSubscribed", False)),
                "shareWith": {},
            }
            self._touch(acc, "Mailbox", mid, "created")
            view = self._mailbox_view(acc, acc.mailboxes[mid], False)
            return mid, {
                k: view[k]
                for k in (
                    "id",
                    "role",
                    "sortOrder",
                    "isSubscribed",
                    "totalEmails",
                    "unreadEmails",
                    "totalThreads",
                    "unreadThreads",
                    "myRights",
                )
            }

        def update(mid: str, patch: dict) -> None:
            mb = acc.mailboxes.get(mid)
            if mb is None:
                raise _SetError("notFound")
            shares = {k: v for k, v in patch.items() if k == "shareWith" or k.startswith("shareWith/")}
            if shares:
                if acc.id != ctx.user:
                    raise _SetError("forbidden", "Only the owner can share this mailbox")
                for key, value in shares.items():
                    if key == "shareWith":
                        mb["shareWith"] = {}
                        items = (value or {}).items()
                    else:
                        items = [(key.split("/", 1)[1], value)]
                    for pid, rights in items:
                        if pid not in self._accounts:
                            raise _SetError("invalidProperties", f"unknown principal {pid}", properties=["shareWith"])
                        if rights is None:
                            mb["shareWith"].pop(pid, None)
                        elif not isinstance(rights, dict) or any(r not in MAILBOX_RIGHTS for r in rights):
                            raise _SetError("invalidProperties", "bad rights", properties=["shareWith"])
                        else:
                            mb["shareWith"][pid] = {r: bool(rights.get(r)) for r in MAILBOX_RIGHTS}
                patch = {k: v for k, v in patch.items() if k not in shares}
                if not patch:
                    self._touch(acc, "Mailbox", mid, "updated")
                    return None
            bad = [k for k in patch if k not in ("name", "parentId", "isSubscribed", "sortOrder")]
            if bad:
                raise _SetError("invalidProperties", properties=bad)
            parent = check_parent(patch["parentId"], mid) if "parentId" in patch else mb["parentId"]
            name = patch.get("name", mb["name"])
            check_name(name, parent, mid)
            mb.update(name=name, parentId=parent)
            if "isSubscribed" in patch:
                mb["isSubscribed"] = bool(patch["isSubscribed"])
            if "sortOrder" in patch:
                mb["sortOrder"] = int(patch["sortOrder"] or 0)
            self._touch(acc, "Mailbox", mid, "updated")
            return None

        def destroy(mid: str) -> None:
            mb = acc.mailboxes.get(mid)
            if mb is None:
                raise _SetError("notFound")
            if mb["role"]:
                raise _SetError("forbidden", f"Mailbox with role '{mb['role']}' cannot be destroyed")
            if any(m["parentId"] == mid for m in acc.mailboxes.values()):
                raise _SetError("mailboxHasChild")
            inside = [e for e in acc.emails.values() if mid in e["mailboxIds"]]
            if inside and not remove_emails:
                raise _SetError("mailboxHasEmail")
            for stored in inside:
                if len(stored["mailboxIds"]) == 1:
                    self._destroy_email(acc, stored["id"])
                else:
                    del stored["mailboxIds"][mid]
                    self._email_changed(acc, stored["id"], "updated")
            del acc.mailboxes[mid]
            self._touch(acc, "Mailbox", mid, "destroyed")

        res = self._run_set(ctx, acc, args, "Mailbox", create, update, destroy)
        return self._finish_set(acc, "Mailbox", res)

    # ------------------------------------------------------------ Email/query

    def _check_filter(self, flt: Any) -> bool:
        """Validate a filter tree; returns True if any condition uses ``header``."""
        if flt is None:
            return False
        if not isinstance(flt, dict):
            raise _MethodError("unsupportedFilter", description="filter must be an object")
        if "operator" in flt:
            if flt["operator"] not in ("AND", "OR", "NOT") or not isinstance(flt.get("conditions"), list):
                raise _MethodError("unsupportedFilter", description="invalid FilterOperator")
            return any([self._check_filter(c) for c in flt["conditions"]])  # list: validate all
        unknown = [k for k in flt if k not in EMAIL_FILTER_KEYS]
        if unknown:
            raise _MethodError("unsupportedFilter", description=f"unsupported condition '{unknown[0]}'")
        return "header" in flt

    def _match(self, acc: _Account, stored: dict, flt: Any) -> bool:
        if flt is None:
            return True
        if "operator" in flt:
            results = [self._match(acc, stored, c) for c in flt["conditions"]]
            if flt["operator"] == "AND":
                return all(results)
            return any(results) if flt["operator"] == "OR" else not any(results)
        return all(self._condition(acc, stored, k, v) for k, v in flt.items())

    def _condition(self, acc: _Account, stored: dict, key: str, value: Any) -> bool:
        def addresses(prop: str) -> str:
            return " ".join(f"{a['name'] or ''} <{a['email']}>" for a in stored[prop] or []).lower()

        needle = value.lower() if isinstance(value, str) else value
        if key == "inMailbox":
            return value in stored["mailboxIds"]
        if key == "inMailboxOtherThan":
            return any(m not in (value or []) for m in stored["mailboxIds"])
        if key in ("before", "after"):
            limit = _parse_utc(value)
            if limit is None:
                raise _MethodError("invalidArguments", description=f"invalid UTCDate for {key}")
            received = _parse_utc(stored["receivedAt"])
            return received < limit if key == "before" else received >= limit
        if key == "minSize":
            return stored["size"] >= value
        if key == "maxSize":
            return stored["size"] < value
        if key == "hasKeyword":
            return needle in stored["keywords"]
        if key == "notKeyword":
            return needle not in stored["keywords"]
        if key.endswith("InThreadHaveKeyword"):
            flags = [needle in acc.emails[i]["keywords"] for i in acc.threads.get(stored["threadId"], [])]
            if key.startswith("all"):
                return all(flags)
            return any(flags) if key.startswith("some") else not any(flags)
        if key == "hasAttachment":
            return stored["hasAttachment"] == value
        if key == "subject":
            return needle in (stored["subject"] or "").lower()
        if key == "body":
            return needle in stored["_body"].lower()
        if key in ("from", "to", "cc", "bcc"):
            return needle in addresses(key)
        if key == "text":
            haystack = " ".join([stored["subject"] or "", stored["_body"], *(addresses(p) for p in ("from", "to", "cc", "bcc"))])
            return needle in haystack.lower()
        return False  # "header" never matches (see QUIRK in _email_query)

    @staticmethod
    def _sort_key(stored: dict, prop: str) -> Any:
        if prop == "receivedAt":
            return _parse_utc(stored["receivedAt"])
        if prop == "sentAt":
            return _parse_utc(stored["sentAt"]) or datetime.min.replace(tzinfo=UTC)
        if prop == "size":
            return stored["size"]
        if prop == "subject":
            return (stored["subject"] or "").casefold()
        addrs = stored[prop] or []
        return ((addrs[0]["name"] or addrs[0]["email"]) if addrs else "").casefold()

    def _email_query(self, ctx: _Ctx, acc: _Account, args: dict) -> dict:
        flt = args.get("filter")
        uses_header = self._check_filter(flt)
        sort = args.get("sort") or [{"property": "receivedAt", "isAscending": False}]
        if not isinstance(sort, list) or any(not isinstance(c, dict) or c.get("property") not in EMAIL_SORT_PROPERTIES for c in sort):
            raise _MethodError("unsupportedSort", description=f"unsupported sort {sort!r}")
        limit = 50 if args.get("limit") is None else args["limit"]
        position = args.get("position") or 0
        if not isinstance(limit, int) or limit < 0 or not isinstance(position, int):
            raise _MethodError("invalidArguments", description="invalid limit/position")
        # QUIRK: Stalwart silently matches nothing when a `header` condition is used.
        matched = [] if uses_header else [e for e in acc.emails.values() if self._match(acc, e, flt)]
        for crit in reversed(sort):
            matched.sort(key=lambda e, p=crit["property"]: self._sort_key(e, p), reverse=not crit.get("isAscending", True))
        if args.get("collapseThreads"):
            seen: set[str] = set()
            matched = [e for e in matched if not (e["threadId"] in seen or seen.add(e["threadId"]))]
        ids = [e["id"] for e in matched]
        if args.get("anchor") is not None:
            if args["anchor"] not in ids:
                raise _MethodError("anchorNotFound")
            position = max(0, ids.index(args["anchor"]) + int(args.get("anchorOffset") or 0))
        elif position < 0:
            position = max(0, len(ids) + position)
        out: dict[str, Any] = {
            "accountId": acc.id,
            "queryState": self._state(acc, "Email"),
            "canCalculateChanges": True,
            "position": position,
            "ids": ids[position : position + min(limit, 1000)],
        }
        if args.get("calculateTotal"):
            out["total"] = len(ids)
        if limit > 1000:
            out["limit"] = 1000
        return out

    # ------------------------------------------------------------ Email/get, Email/parse

    def _email_render_opts(self, args: dict, default_props: list[str]) -> tuple:
        props = list(default_props) if args.get("properties") is None else args["properties"]
        body_props = list(DEFAULT_BODY_PROPS) if args.get("bodyProperties") is None else args["bodyProperties"]
        for given, allowed in ((props, ALL_EMAIL_PROPS), (body_props, ALL_BODY_PROPS)):
            if not isinstance(given, list):
                raise _MethodError("invalidArguments", description="properties must be a list")
            for prop in given:
                if isinstance(prop, str) and prop.startswith("header:"):
                    _parse_header_prop(prop)
                elif prop not in allowed:
                    raise _MethodError("invalidArguments", description=f"unknown property {prop!r}")
        max_bytes = args.get("maxBodyValueBytes") or 0
        if not isinstance(max_bytes, int) or max_bytes < 0:
            raise _MethodError("invalidArguments", description="invalid maxBodyValueBytes")
        fetch = (bool(args.get("fetchTextBodyValues")), bool(args.get("fetchHTMLBodyValues")), bool(args.get("fetchAllBodyValues")))
        return props, body_props, fetch, max_bytes

    @staticmethod
    def _body_values(stored: dict, fetch: tuple[bool, bool, bool], max_bytes: int) -> dict:
        wanted: list[dict] = []
        if fetch[0]:
            wanted += stored["textBody"]
        if fetch[1]:
            wanted += stored["htmlBody"]
        if fetch[2]:
            wanted += [p for p in _leaves(stored["bodyStructure"]) if p["type"].startswith("text/")]
        out = {}
        for part in wanted:
            if part["partId"] in out or part["partId"] not in stored["_values"]:
                continue
            value, problem = stored["_values"][part["partId"]]
            encoded = value.encode("utf-8")
            truncated = bool(max_bytes) and len(encoded) > max_bytes
            if truncated:  # never split a code point
                value = encoded[:max_bytes].decode("utf-8", "ignore")
            out[part["partId"]] = {"value": value, "isEncodingProblem": problem, "isTruncated": truncated}
        return out

    def _render_email(
        self, stored: dict, props: list[str], body_props: list[str], fetch: tuple[bool, bool, bool], max_bytes: int, force_id: bool = True
    ) -> dict:
        out: dict[str, Any] = {"id": stored["id"]} if force_id else {}
        for prop in props:
            if prop == "bodyValues":  # QUIRK A: only present when listed in `properties`
                out[prop] = self._body_values(stored, fetch, max_bytes)
            elif prop in ("textBody", "htmlBody", "attachments"):
                out[prop] = [_render_part(p, body_props, False) for p in stored[prop]]
            elif prop == "bodyStructure":
                out[prop] = _render_part(stored[prop], body_props, True)
            elif prop.startswith("header:"):
                out[prop] = _header_value(stored["headers"], prop)
            else:
                out[prop] = copy.deepcopy(stored.get(prop))
        return out

    def _email_get(self, ctx: _Ctx, acc: _Account, args: dict) -> dict:
        ids = args.get("ids")
        if ids is None:
            ids = list(acc.emails)
        elif not isinstance(ids, list):
            raise _MethodError("invalidArguments", description="ids must be a list or null")
        if len(ids) > MAX_OBJECTS_IN_GET:
            raise _MethodError("requestTooLarge")
        opts = self._email_render_opts(args, DEFAULT_EMAIL_PROPS)
        found, not_found = [], []
        for eid in ids:
            stored = acc.emails.get(eid) if isinstance(eid, str) else None
            if stored is None:
                not_found.append(eid)
            else:
                found.append(self._render_email(stored, *opts))
        return {"accountId": acc.id, "state": self._state(acc, "Email"), "list": found, "notFound": not_found}

    def _email_parse(self, ctx: _Ctx, acc: _Account, args: dict) -> dict:
        blob_ids = args.get("blobIds")
        if not isinstance(blob_ids, list):
            raise _MethodError("invalidArguments", description="blobIds is required")
        opts = self._email_render_opts(args, DEFAULT_PARSE_PROPS)
        parsed, not_parsable, not_found = {}, [], []
        for blob_id in blob_ids:
            real = ctx.resolve("Blob", blob_id)
            blob = acc.blobs.get(real) if isinstance(real, str) else None
            if blob is None:
                not_found.append(blob_id)
            elif not _looks_like_message(blob[0]):
                not_parsable.append(blob_id)
            else:
                info = _parse_message(blob[0], lambda data, type_: self._put_blob(acc, data, type_))
                view = {
                    "id": None,
                    "blobId": real,
                    "threadId": None,
                    "mailboxIds": None,
                    "keywords": None,
                    "size": len(blob[0]),
                    "receivedAt": None,
                    **info,
                }
                parsed[blob_id] = self._render_email(view, *opts, force_id=False)
        return {"accountId": acc.id, "parsed": parsed or None, "notParsable": not_parsable or None, "notFound": not_found or None}

    # ------------------------------------------------------------ Email/set

    def _email_set(self, ctx: _Ctx, acc: _Account, args: dict) -> dict:
        res = self._run_set(
            ctx,
            acc,
            args,
            "Email",
            lambda obj: self._email_create(ctx, acc, obj),
            lambda eid, patch: self._email_update(ctx, acc, eid, patch),
            lambda eid: self._email_destroy(acc, eid),
        )
        return self._finish_set(acc, "Email", res)

    def _mailbox_ids(self, ctx: _Ctx, acc: _Account, value: Any) -> dict[str, bool]:
        if not isinstance(value, dict) or not value:
            raise _SetError("invalidProperties", "mailboxIds must not be empty", properties=["mailboxIds"])
        out = {}
        for key, flag in value.items():
            real = ctx.resolve("Mailbox", key)
            if flag is not True or real not in acc.mailboxes:
                raise _SetError("invalidProperties", f"invalid mailbox {key!r}", properties=["mailboxIds"])
            out[real] = True
        return out

    def _email_create(self, ctx: _Ctx, acc: _Account, obj: dict) -> tuple[str, dict]:
        bad = [k for k in obj if k not in EMAIL_CREATE_KEYS and not k.startswith("header:")]
        if bad:
            raise _SetError("invalidProperties", "unknown or server-set properties", properties=bad)
        # QUIRK C: Stalwart rejects any body part that carries both partId and charset.
        parts = _json_parts([obj.get(k) for k in ("bodyStructure", "textBody", "htmlBody", "attachments")])
        if any("partId" in p and "charset" in p for p in parts):
            raise _SetError("invalidProperties", "charset must not be set together with partId", properties=["bodyStructure"])
        mailbox_ids = self._mailbox_ids(ctx, acc, obj.get("mailboxIds"))
        keywords = _keywords(obj.get("keywords") or {})
        received = _parse_utc(obj["receivedAt"]) if obj.get("receivedAt") else self.now()
        if received is None:
            raise _SetError("invalidProperties", properties=["receivedAt"])
        headers = self._create_headers(obj)
        body = self._create_body(ctx, acc, obj)
        try:
            raw = _render(headers, body, self._boundary)
        except (ValueError, TypeError, email.errors.MessageError) as exc:
            raise _SetError("invalidProperties", str(exc)) from None
        stored = self._store_email(acc, raw, mailbox_ids, keywords, _fmt_utc(received))
        return stored["id"], {k: stored[k] for k in ("id", "blobId", "threadId", "size")}

    def _create_headers(self, obj: dict) -> list[tuple[str, str]]:
        hdrs: list[tuple[str, str]] = []
        for prop, name in (("from", "From"), ("sender", "Sender"), ("to", "To"), ("cc", "Cc"), ("bcc", "Bcc"), ("replyTo", "Reply-To")):
            if obj.get(prop):
                try:
                    if not isinstance(obj[prop], list):
                        raise TypeError
                    hdrs.append((name, _fmt_addrs(obj[prop])))
                except (TypeError, ValueError, AttributeError):
                    raise _SetError("invalidProperties", properties=[prop]) from None
        if obj.get("subject") is not None:
            if not isinstance(obj["subject"], str):
                raise _SetError("invalidProperties", properties=["subject"])
            hdrs.append(("Subject", obj["subject"]))
        sent = _parse_utc(obj["sentAt"]) if obj.get("sentAt") else self.now()
        if sent is None:
            raise _SetError("invalidProperties", properties=["sentAt"])
        hdrs.append(("Date", format_datetime(sent)))
        sender = (obj.get("from") or [{}])[0]
        defaults = {"messageId": [self._message_id(sender if isinstance(sender, dict) else {})]}
        for prop, name in (("messageId", "Message-ID"), ("inReplyTo", "In-Reply-To"), ("references", "References")):
            ids = obj.get(prop) or defaults.get(prop)
            if ids is None:
                continue
            if not isinstance(ids, list) or not all(isinstance(i, str) and i for i in ids):
                raise _SetError("invalidProperties", properties=[prop])
            hdrs.append((name, " ".join(f"<{i}>" for i in ids)))
        try:
            hdrs += [(h["name"], _unfold(h["value"]).strip()) for h in obj.get("headers") or []]
            for key, value in obj.items():
                if key.startswith("header:"):
                    name, form, all_ = _parse_header_prop(key)
                    hdrs += [(name, _render_header_value(v, form)) for v in (value if all_ else [value])]
        except (KeyError, TypeError, ValueError, AttributeError, _MethodError):
            raise _SetError("invalidProperties", "invalid header value", properties=["headers"]) from None
        return hdrs

    def _create_body(self, ctx: _Ctx, acc: _Account, obj: dict) -> tuple:
        values = obj.get("bodyValues") or {}
        if not isinstance(values, dict):
            raise _SetError("invalidProperties", properties=["bodyValues"])
        if obj.get("bodyStructure") is not None:
            if any(obj.get(k) for k in ("textBody", "htmlBody", "attachments")):
                raise _SetError("invalidProperties", "bodyStructure excludes textBody/htmlBody/attachments", properties=["bodyStructure"])
            return self._json_body_part(ctx, acc, obj["bodyStructure"], values, None)
        text, html, attachments = (obj.get(k) or [] for k in ("textBody", "htmlBody", "attachments"))
        for key, given in (("textBody", text), ("htmlBody", html), ("attachments", attachments)):
            if not isinstance(given, list) or (key != "attachments" and len(given) > 1):
                raise _SetError("invalidProperties", f"{key} must be a list (of one part)", properties=[key])
        alternatives = [
            self._json_body_part(ctx, acc, given[0], values, default)
            for given, default in ((text, "text/plain"), (html, "text/html"))
            if given
        ]
        leaves = [self._json_body_part(ctx, acc, a, values, None) for a in attachments]
        return _body_tree(alternatives, leaves)

    def _json_body_part(self, ctx: _Ctx, acc: _Account, spec: Any, values: dict, default_type: str | None) -> tuple:
        if not isinstance(spec, dict):
            raise _SetError("invalidProperties", "body part must be an object", properties=["bodyStructure"])
        ctype = str(spec.get("type") or default_type or ("multipart/mixed" if spec.get("subParts") else "text/plain")).lower()
        if ctype.startswith("multipart/"):
            subs = spec.get("subParts")
            if not isinstance(subs, list) or not subs:
                raise _SetError("invalidProperties", "multipart part needs subParts", properties=["bodyStructure"])
            return ("multipart", ctype.split("/", 1)[1], [self._json_body_part(ctx, acc, s, values, None) for s in subs])
        opts: dict[str, Any] = {k: spec.get(k) for k in ("name", "disposition", "cid", "language", "location")}
        try:
            opts["headers"] = [(h["name"], _unfold(h["value"]).strip()) for h in spec.get("headers") or []]
            for key, value in spec.items():
                if key.startswith("header:"):
                    name, form, all_ = _parse_header_prop(key)
                    opts["headers"] += [(name, _render_header_value(v, form)) for v in (value if all_ else [value])]
        except (KeyError, TypeError, ValueError, AttributeError, _MethodError):
            raise _SetError("invalidProperties", "invalid part header", properties=["bodyStructure"]) from None
        if "partId" in spec:
            value = values.get(spec["partId"]) if isinstance(spec["partId"], str) else None
            if "blobId" in spec or not ctype.startswith("text/"):
                raise _SetError("invalidProperties", "partId needs a text/* part without blobId", properties=["bodyStructure"])
            if (
                not isinstance(value, dict)
                or not isinstance(value.get("value"), str)
                or value.get("isTruncated")
                or value.get("isEncodingProblem")
            ):
                raise _SetError("invalidProperties", f"no usable bodyValues entry for {spec['partId']!r}", properties=["bodyValues"])
            return ("leaf", ctype, value["value"], opts)
        if "blobId" in spec:
            blob_id = ctx.resolve("Blob", spec["blobId"])
            blob = acc.blobs.get(blob_id) if isinstance(blob_id, str) else None
            if blob is None:
                raise _SetError("blobNotFound", notFound=[spec["blobId"]])
            if not spec.get("type") and default_type is None:
                ctype = blob[1].split(";")[0].strip().lower() or "application/octet-stream"
            opts["charset"] = spec.get("charset")
            return ("leaf", ctype, blob[0], opts)
        raise _SetError("invalidProperties", "body part needs partId or blobId", properties=["bodyStructure"])

    def _email_update(self, ctx: _Ctx, acc: _Account, eid: Any, patch: dict) -> None:
        stored = acc.emails.get(eid) if isinstance(eid, str) else None
        if stored is None:
            raise _SetError("notFound")
        mailboxes, keywords = dict(stored["mailboxIds"]), dict(stored["keywords"])
        for key, value in patch.items():
            if key == "mailboxIds":
                mailboxes = self._mailbox_ids(ctx, acc, value)
            elif key == "keywords":
                keywords = _keywords(value)
            elif key.startswith("mailboxIds/"):
                mid = ctx.resolve("Mailbox", _unescape_pointer(key[len("mailboxIds/") :]))
                if value is True and mid in acc.mailboxes:
                    mailboxes[mid] = True
                elif value is None:
                    mailboxes.pop(mid, None)
                else:
                    raise _SetError("invalidProperties", f"invalid patch {key!r}", properties=["mailboxIds"])
            elif key.startswith("keywords/"):
                kw = _unescape_pointer(key[len("keywords/") :])
                if not _valid_keyword(kw) or value not in (True, None):
                    raise _SetError("invalidProperties", f"invalid patch {key!r}", properties=["keywords"])
                if value is True:
                    keywords[kw.lower()] = True
                else:
                    keywords.pop(kw.lower(), None)
            else:
                raise _SetError("invalidProperties", f"'{key}' cannot be updated", properties=[key])
        if not mailboxes:
            raise _SetError("invalidProperties", "An email must belong to at least one mailbox", properties=["mailboxIds"])
        if (mailboxes, keywords) != (stored["mailboxIds"], stored["keywords"]):
            stored["mailboxIds"], stored["keywords"] = mailboxes, keywords
            self._email_changed(acc, eid, "updated")
        return None

    def _email_destroy(self, acc: _Account, eid: Any) -> None:
        if not isinstance(eid, str) or eid not in acc.emails:
            raise _SetError("notFound")
        self._destroy_email(acc, eid)

    # ------------------------------------------------------------ Email/changes, Thread, SearchSnippet

    def _email_changes(self, ctx: _Ctx, acc: _Account, args: dict) -> dict:
        since = args.get("sinceState")
        match = re.fullmatch(r"s(\d+)", since) if isinstance(since, str) else None
        if match is None or int(match.group(1)) > acc.states["Email"]:
            if self.changes_mode == "method_error":
                raise _MethodError("cannotCalculateChanges")
            # QUIRK D: Stalwart fails the WHOLE HTTP request, taking every batched call with it.
            raise _RequestError(400, ERR_PREFIX + "invalidArguments", f"Invalid sinceState {since!r}.")
        max_changes = args.get("maxChanges")
        if max_changes is not None and (not isinstance(max_changes, int) or max_changes <= 0):
            raise _MethodError("invalidArguments", description="maxChanges must be a positive integer")
        since_n, new_n, more = int(match.group(1)), acc.states["Email"], False
        first: dict[str, str] = {}
        last: dict[str, str] = {}
        for n, oid, kind in acc.changes["Email"]:
            if n <= since_n:
                continue
            if oid not in first:
                if max_changes is not None and len(first) >= max_changes:
                    new_n, more = n - 1, True  # intermediate state: everything before n is reported
                    break
                first[oid] = kind
            last[oid] = kind
        return {
            "accountId": acc.id,
            "oldState": since,
            "newState": f"s{new_n}",
            "hasMoreChanges": more,
            "created": [o for o in first if first[o] == "created" and last[o] != "destroyed"],
            "updated": [o for o in first if first[o] != "created" and last[o] != "destroyed"],
            "destroyed": [o for o in first if first[o] != "created" and last[o] == "destroyed"],
        }

    def _thread_get(self, ctx: _Ctx, acc: _Account, args: dict) -> dict:
        threads = {
            tid: {"id": tid, "emailIds": sorted(members, key=lambda i: _parse_utc(acc.emails[i]["receivedAt"]))}
            for tid, members in acc.threads.items()
        }
        return self._get(acc, args, threads, "Thread")

    def _snippet_get(self, ctx: _Ctx, acc: _Account, args: dict) -> dict:
        email_ids = args.get("emailIds")
        if not isinstance(email_ids, list):
            raise _MethodError("invalidArguments", description="emailIds is required")
        if len(email_ids) > MAX_OBJECTS_IN_GET:
            raise _MethodError("requestTooLarge")
        flt = args.get("filter")
        self._check_filter(flt)
        terms: dict[str, list[str]] = defaultdict(list)

        def collect(node: Any) -> None:
            if not isinstance(node, dict):
                return
            if "operator" in node:
                if node["operator"] != "NOT":  # negated terms are never highlighted
                    for cond in node["conditions"]:
                        collect(cond)
                return
            for key in ("text", "subject", "body"):
                if isinstance(node.get(key), str):
                    terms[key].append(node[key])

        collect(flt)
        found, not_found = [], []
        for eid in email_ids:
            stored = acc.emails.get(eid) if isinstance(eid, str) else None
            if stored is None:
                not_found.append(eid)
                continue
            found.append(
                {
                    "emailId": eid,
                    "subject": _mark(stored["subject"], terms["text"] + terms["subject"], False),
                    "preview": _mark(stored["_text"], terms["text"] + terms["body"], True)
                    or _mark(_squash(stored["_body"]), terms["text"] + terms["body"], True),
                }
            )
        return {"accountId": acc.id, "list": found, "notFound": not_found or None}

    # ------------------------------------------------------------ Identity, EmailSubmission

    def _principals(self) -> dict[str, dict]:
        return {a.id: {"id": a.id, "name": a.name, "email": a.username, "type": "individual"} for a in self._accounts.values()}

    def _principal_query(self, ctx: _Ctx, acc: _Account, args: dict) -> dict:
        flt = args.get("filter") or {}
        unknown = [k for k in flt if k not in ("email", "name", "text", "type")]
        if unknown:
            raise _MethodError("unsupportedFilter")
        ids = []
        for pid, p in self._principals().items():
            if "email" in flt and p["email"].lower() != str(flt["email"]).lower():
                continue
            if "name" in flt and str(flt["name"]).lower() not in p["name"].lower():
                continue
            if "type" in flt and p["type"] != flt["type"]:
                continue
            ids.append(pid)
        return {"accountId": acc.id, "queryState": "p", "canCalculateChanges": False, "position": 0, "ids": ids}

    def _principal_get(self, ctx: _Ctx, acc: _Account, args: dict) -> dict:
        principals = self._principals()
        ids = args.get("ids")
        props = args.get("properties")
        found, missing = [], []
        for pid in list(principals) if ids is None else ids:
            p = principals.get(pid)
            if p is None:
                missing.append(pid)
            else:
                found.append({k: v for k, v in p.items() if props is None or k in props or k == "id"})
        return {"accountId": acc.id, "state": "p", "list": found, "notFound": missing}

    def _identity_get(self, ctx: _Ctx, acc: _Account, args: dict) -> dict:
        return self._get(acc, args, acc.identities, "Identity")

    def _submission_get(self, ctx: _Ctx, acc: _Account, args: dict) -> dict:
        return self._get(acc, args, acc.submissions, "EmailSubmission")

    def _submit(self, ctx: _Ctx, acc: _Account, obj: dict) -> dict:
        bad = [k for k in obj if k not in ("identityId", "emailId", "envelope")]
        if bad:
            raise _SetError("invalidProperties", properties=bad)
        identity = acc.identities.get(obj.get("identityId"))
        if identity is None:
            raise _SetError("invalidProperties", "unknown identityId", properties=["identityId"])
        stored = acc.emails.get(ctx.resolve("Email", obj.get("emailId")))
        if stored is None:
            raise _SetError("invalidProperties", "unknown emailId", properties=["emailId"])
        sender = ((stored["from"] or [{}])[0].get("email") or "").lower()
        if sender != identity["email"].lower():
            raise _SetError("forbiddenFrom", f"From {sender!r} does not match identity {identity['email']!r}")
        envelope = obj.get("envelope")
        if envelope is None:
            rcpt: list[str] = []
            for prop in ("to", "cc", "bcc"):
                rcpt += [a["email"] for a in stored[prop] or [] if a["email"] not in rcpt]
            mail_from = identity["email"]
            envelope = {"mailFrom": {"email": mail_from, "parameters": None}, "rcptTo": [{"email": r, "parameters": None} for r in rcpt]}
        else:
            try:
                mail_from = envelope["mailFrom"]["email"]
                rcpt = [r["email"] for r in envelope["rcptTo"]]
            except (KeyError, TypeError):
                raise _SetError("invalidProperties", "invalid envelope", properties=["envelope"]) from None
            if mail_from.lower() != identity["email"].lower():
                raise _SetError("forbiddenMailFrom", f"MAIL FROM {mail_from!r} is not allowed")
        if not rcpt:
            raise _SetError("noRecipients", "The message has no recipients")
        sid = self._next("sub")
        sub = {
            "id": sid,
            "identityId": identity["id"],
            "emailId": stored["id"],
            "threadId": stored["threadId"],
            "envelope": envelope,
            "sendAt": _fmt_utc(self.now()),
            "undoStatus": "final",
            "dsnBlobIds": [],
            "mdnBlobIds": [],
            "deliveryStatus": {r: {"smtpReply": "250 2.1.5 Queued", "delivered": "queued", "displayed": "unknown"} for r in rcpt},
        }
        acc.submissions[sid] = sub
        self._touch(acc, "EmailSubmission", sid, "created")
        # The raw message exactly as stored -- including any Bcc header.
        self.outbox.append(
            {
                "account": acc.id,
                "email_id": stored["id"],
                "identity_id": identity["id"],
                "submission_id": sid,
                "envelope": {"mailFrom": mail_from, "rcptTo": rcpt},
                "raw": stored["raw"],
            }
        )
        return sub

    def _submission_set(self, ctx: _Ctx, acc: _Account, args: dict) -> dict:
        create = args.get("create") if isinstance(args.get("create"), dict) else {}
        # QUIRK: an unresolvable "#creationId" emailId fails the whole method with
        # invalidResultReference instead of a per-object notCreated (a client once
        # reported such a "send" as successful although nothing was sent).
        for obj in create.values():
            ref = obj.get("emailId") if isinstance(obj, dict) else None
            if isinstance(ref, str) and ref.startswith("#") and ctx.resolve("Email", ref) is None:
                raise _MethodError("invalidResultReference")
        succeeded: dict[str, str] = {}  # submission id -> email id

        def create_fn(obj: dict) -> tuple[str, dict]:
            sub = self._submit(ctx, acc, obj)
            succeeded[sub["id"]] = sub["emailId"]
            return sub["id"], {"id": sub["id"], "undoStatus": "final", "sendAt": sub["sendAt"]}

        def update_fn(sid: Any, patch: dict) -> None:
            sub = acc.submissions.get(sid) if isinstance(sid, str) else None
            if sub is None:
                raise _SetError("notFound")
            if patch.get("undoStatus") == "canceled":
                raise _SetError("cannotUnsend", "The message has already been sent")
            if patch:
                raise _SetError("invalidProperties", properties=list(patch))
            succeeded[sid] = sub["emailId"]

        def destroy_fn(sid: Any) -> None:
            sub = acc.submissions.pop(sid, None) if isinstance(sid, str) else None
            if sub is None:
                raise _SetError("notFound")
            succeeded[sid] = sub["emailId"]
            self._touch(acc, "EmailSubmission", sid, "destroyed")

        res = self._run_set(ctx, acc, args, "EmailSubmission", create_fn, update_fn, destroy_fn)
        # RFC 8621 7.5: one implicit Email/set, answered right after this response.
        implicit: dict[str, Any] = {"accountId": acc.id, "update": {}, "destroy": []}
        for key, patch in (args.get("onSuccessUpdateEmail") or {}).items():
            sid = ctx.resolve("EmailSubmission", key)
            if sid in succeeded:
                implicit["update"][succeeded[sid]] = patch
        for key in args.get("onSuccessDestroyEmail") or []:
            sid = ctx.resolve("EmailSubmission", key)
            if sid in succeeded:
                implicit["destroy"].append(succeeded[sid])
        result = self._finish_set(acc, "EmailSubmission", res)
        if implicit["update"] or implicit["destroy"]:
            ctx.implicit.append(("Email/set", self._email_set(ctx, acc, implicit)))
        return result

    # ------------------------------------------------------------ SieveScript (RFC 9661)

    def _sieve_get(self, ctx: _Ctx, acc: _Account, args: dict) -> dict:
        return self._get(acc, args, acc.scripts, "SieveScript")

    def _sieve_query(self, ctx: _Ctx, acc: _Account, args: dict) -> dict:
        flt = args.get("filter") or {}
        if not isinstance(flt, dict) or any(k not in ("name", "isActive") for k in flt):
            raise _MethodError("unsupportedFilter")
        found = [
            s
            for s in acc.scripts.values()
            if ("name" not in flt or str(flt["name"]).lower() in s["name"].lower())
            and ("isActive" not in flt or s["isActive"] == flt["isActive"])
        ]
        for crit in reversed(args.get("sort") or []):
            if not isinstance(crit, dict) or crit.get("property") not in ("name", "isActive"):
                raise _MethodError("unsupportedSort")
            found.sort(key=lambda s, p=crit["property"]: s[p], reverse=not crit.get("isAscending", True))
        ids = [s["id"] for s in found]
        position, limit = args.get("position") or 0, args.get("limit")
        out = {
            "accountId": acc.id,
            "queryState": self._state(acc, "SieveScript"),
            "canCalculateChanges": False,
            "position": position,
            "ids": ids[position:] if limit is None else ids[position : position + limit],
        }
        if args.get("calculateTotal"):
            out["total"] = len(ids)
        return out

    def _sieve_set(self, ctx: _Ctx, acc: _Account, args: dict) -> dict:
        def script_blob(ref: Any) -> str:
            blob_id = ctx.resolve("Blob", ref)
            blob = acc.blobs.get(blob_id) if isinstance(blob_id, str) else None
            if blob is None:
                raise _SetError("blobNotFound", notFound=[ref])
            error = _sieve_error(blob[0].decode("utf-8", "replace"))
            if error:
                raise _SetError("invalidSieve", error)
            return blob_id

        def check_name(name: Any, self_id: str | None = None) -> None:
            if not isinstance(name, str) or not name:
                raise _SetError("invalidProperties", "name is required", properties=["name"])
            for other in acc.scripts.values():
                if other["id"] != self_id and other["name"] == name:
                    raise _SetError("alreadyExists", f"Script {name!r} already exists", existingId=other["id"])

        def create(obj: dict) -> tuple[str, dict]:
            bad = [k for k in obj if k not in ("name", "blobId")]
            if bad or "blobId" not in obj:
                raise _SetError("invalidProperties", properties=bad or ["blobId"])
            name = obj.get("name") or f"script-{len(acc.scripts) + 1}"
            check_name(name)
            blob_id = script_blob(obj["blobId"])
            sid = self._next("sc")
            acc.scripts[sid] = {"id": sid, "name": name, "blobId": blob_id, "isActive": False}
            self._touch(acc, "SieveScript", sid, "created")
            return sid, dict(acc.scripts[sid])

        def update(sid: Any, patch: dict) -> dict | None:
            script = acc.scripts.get(sid) if isinstance(sid, str) else None
            if script is None:
                raise _SetError("notFound")
            bad = [k for k in patch if k not in ("name", "blobId")]
            if bad:
                raise _SetError("invalidProperties", properties=bad)
            if "name" in patch:
                check_name(patch["name"], sid)
            blob_id = script_blob(patch["blobId"]) if "blobId" in patch else script["blobId"]
            script.update(name=patch.get("name", script["name"]), blobId=blob_id)
            self._touch(acc, "SieveScript", sid, "updated")
            return {"blobId": blob_id} if "blobId" in patch else None

        def destroy(sid: Any) -> None:
            script = acc.scripts.get(sid) if isinstance(sid, str) else None
            if script is None:
                raise _SetError("notFound")
            if script["isActive"]:
                raise _SetError("scriptIsActive", "An active script cannot be destroyed")
            del acc.scripts[sid]
            self._touch(acc, "SieveScript", sid, "destroyed")

        res = self._run_set(ctx, acc, args, "SieveScript", create, update, destroy)
        failed = res["notCreated"] or res["notUpdated"] or res["notDestroyed"]
        activate = args.get("onSuccessActivateScript")
        target = ctx.resolve("SieveScript", activate) if activate is not None else None
        if not failed and (args.get("onSuccessDeactivateScript") or target in acc.scripts):
            toggled: dict[str, bool] = {}
            for script in acc.scripts.values():  # at most one active script per account
                if script["isActive"] and script["id"] != target:
                    script["isActive"], toggled[script["id"]] = False, False
            if target in acc.scripts and not acc.scripts[target]["isActive"]:
                acc.scripts[target]["isActive"], toggled[target] = True, True
            created_ids = {v: k for k, v in ctx.created["SieveScript"].items() if k in res["created"]}
            for sid, active in toggled.items():
                self._touch(acc, "SieveScript", sid, "updated")
                if sid in created_ids:
                    res["created"][created_ids[sid]]["isActive"] = active
                else:
                    res["updated"][sid] = {**(res["updated"].get(sid) or {}), "isActive": active}
        return self._finish_set(acc, "SieveScript", res)

    def _sieve_validate(self, ctx: _Ctx, acc: _Account, args: dict) -> dict:
        blob_id = ctx.resolve("Blob", args.get("blobId"))
        blob = acc.blobs.get(blob_id) if isinstance(blob_id, str) else None
        if blob is None:
            return {"accountId": acc.id, "error": {"type": "blobNotFound", "notFound": [args.get("blobId")]}}
        error = _sieve_error(blob[0].decode("utf-8", "replace"))
        return {"accountId": acc.id, "error": {"type": "invalidSieve", "description": error} if error else None}

    # ------------------------------------------------------------ Blob (RFC 9404)

    def _blob_upload(self, ctx: _Ctx, acc: _Account, args: dict) -> dict:
        create = args.get("create")
        if not isinstance(create, dict):
            raise _MethodError("invalidArguments", description="create is required")
        created, not_created = {}, {}
        for creation_id, obj in create.items():
            try:
                chunks = obj.get("data") if isinstance(obj, dict) else None
                if not isinstance(chunks, list) or not chunks:
                    raise _SetError("invalidProperties", properties=["data"])
                data = b""
                for chunk in chunks:
                    if not isinstance(chunk, dict):
                        raise _SetError("invalidProperties", properties=["data"])
                    if "data:asText" in chunk:
                        data += str(chunk["data:asText"]).encode("utf-8")
                    elif "data:asBase64" in chunk:
                        try:
                            data += base64.b64decode(chunk["data:asBase64"], validate=True)
                        except (ValueError, TypeError):
                            raise _SetError("invalidProperties", "invalid base64", properties=["data"]) from None
                    elif "blobId" in chunk:
                        source = acc.blobs.get(ctx.resolve("Blob", chunk["blobId"]))
                        if source is None:
                            raise _SetError("blobNotFound", notFound=[chunk["blobId"]])
                        offset, length = chunk.get("offset") or 0, chunk.get("length")
                        data += source[0][offset : None if length is None else offset + length]
                    else:
                        raise _SetError("invalidProperties", properties=["data"])
                type_ = obj.get("type") or "application/octet-stream"
                blob_id = self._put_blob(acc, data, type_)
                ctx.remember("Blob", creation_id, blob_id)
                created[creation_id] = {"id": blob_id, "type": type_, "size": len(data)}
            except _SetError as err:
                not_created[creation_id] = err.body
        return {"accountId": acc.id, "created": created or None, "notCreated": not_created or None}

    def _blob_get(self, ctx: _Ctx, acc: _Account, args: dict) -> dict:
        ids = args.get("ids")
        props = args.get("properties") or ["data", "size"]
        allowed = {"data", "data:asText", "data:asBase64", "size", "digest:sha", "digest:sha-256"}
        if not isinstance(ids, list) or not isinstance(props, list) or any(p not in allowed for p in props):
            raise _MethodError("invalidArguments", description="invalid ids/properties")
        offset, length = args.get("offset") or 0, args.get("length")
        found, not_found = [], []
        for blob_id in ids:
            blob = acc.blobs.get(ctx.resolve("Blob", blob_id))
            if blob is None:
                not_found.append(blob_id)
                continue
            data = blob[0]
            chunk = data[offset : None if length is None else offset + length]
            item: dict[str, Any] = {"id": blob_id}
            for prop in props:
                if prop == "size":
                    item["size"] = len(data)
                elif prop.startswith("digest:"):
                    algo = hashlib.sha1 if prop == "digest:sha" else hashlib.sha256
                    item[prop] = base64.b64encode(algo(data).digest()).decode()
                else:
                    try:
                        text, problem = chunk.decode("utf-8"), False
                    except UnicodeDecodeError:
                        text, problem = None, True
                    if prop == "data:asBase64" or (prop == "data" and problem):
                        item["data:asBase64"] = base64.b64encode(chunk).decode()
                    else:
                        item["data:asText"] = text
                        if problem:
                            item["isEncodingProblem"] = True
            if length is not None and offset + length > len(data):
                item["isTruncated"] = True
            found.append(item)
        return {"accountId": acc.id, "list": found, "notFound": not_found or None}

    # ------------------------------------------------------------ VacationResponse, Quota

    def _vacation_get(self, ctx: _Ctx, acc: _Account, args: dict) -> dict:
        return self._get(acc, args, {"singleton": acc.vacation}, "VacationResponse")

    def _vacation_set(self, ctx: _Ctx, acc: _Account, args: dict) -> dict:
        def update(oid: Any, patch: dict) -> None:
            if oid != "singleton":
                raise _SetError("notFound")
            bad = [k for k in patch if k not in _PROPS["VacationResponse"] - {"id"}]
            bad += [k for k in ("fromDate", "toDate") if patch.get(k) is not None and _parse_utc(patch[k]) is None]
            if "isEnabled" in patch and not isinstance(patch["isEnabled"], bool):
                bad.append("isEnabled")
            if bad:
                raise _SetError("invalidProperties", properties=bad)
            acc.vacation.update(patch)
            self._touch(acc, "VacationResponse", "singleton", "updated")

        def singleton(*_: Any) -> Any:
            raise _SetError("singleton", "VacationResponse is a singleton")

        res = self._run_set(ctx, acc, args, "VacationResponse", singleton, update, singleton)
        return self._finish_set(acc, "VacationResponse", res)

    def _quota_get(self, ctx: _Ctx, acc: _Account, args: dict) -> dict:
        quota = {
            "id": "storage",
            "resourceType": "octets",
            "used": sum(e["size"] for e in acc.emails.values()),
            "hardLimit": QUOTA_HARD_LIMIT,
            "scope": "account",
            "name": "Storage",
            "types": ["Mail"],
        }
        return self._get(acc, args, {"storage": quota}, "Quota")
