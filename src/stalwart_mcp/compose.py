"""Building drafts: sender identity, recipients, threading headers, MIME structure."""

from __future__ import annotations

import re
from email.utils import parseaddr
from typing import Any

from .errors import InvalidInput, Refused
from .render import addr

_PREFIX_RE = re.compile(r"^\s*((re|aw|wg|fw|fwd|sv|vs|antw)\s*(\[\d+\])?\s*:\s*)+", re.I)


def normalize_address(value: str | dict[str, Any]) -> dict[str, str]:
    """'Name <a@b>' / 'a@b' / {'email':..,'name':..} -> JMAP EmailAddress."""
    if isinstance(value, dict):
        email = (value.get("email") or "").strip()
        name = (value.get("name") or "").strip()
    else:
        name, email = parseaddr(str(value))
        email = email.strip()
    if not email or "@" not in email or any(c.isspace() for c in email):
        raise InvalidInput(f"Not an email address: {value!r}")
    return {"email": email, "name": name} if name else {"email": email}


def normalize_addresses(values: list[str | dict[str, Any]] | None) -> list[dict[str, str]]:
    return [normalize_address(v) for v in (values or [])]


def emails_of(items: list[dict[str, Any]] | None) -> list[str]:
    return [(a.get("email") or "").lower() for a in items or [] if a.get("email")]


def display_name(identity: dict[str, Any], override: str | None) -> str | None:
    """The From display name.

    @gotcha Identity names in Stalwart are often admin labels ("office/jd") rather than
            human names. Names containing '/' or '@' are therefore not used as display
            names unless passed explicitly.
    """
    if override is not None:
        return override.strip() or None
    name = (identity.get("name") or "").strip()
    if not name or "/" in name or "@" in name:
        return None
    return name


def pick_identity(
    identities: list[dict[str, Any]],
    *,
    from_email: str | None = None,
    original: dict[str, Any] | None = None,
    username: str | None = None,
) -> dict[str, Any]:
    """Choose the sending identity.

    Order: explicit `from_email` (must exist) > the identity the original mail was
    addressed to (reply/forward) > the identity matching the login name > the only one.
    """
    if not identities:
        raise Refused("This account has no sending identity.", hint="Create one in Stalwart first.")
    by_email = {(i.get("email") or "").lower(): i for i in identities}
    allowed = ", ".join(sorted(by_email))
    if from_email:
        ident = by_email.get(from_email.strip().lower())
        if not ident:
            raise Refused(f"'{from_email}' is not a sending identity of this account.", hint=f"Allowed: {allowed}")
        return ident
    if original:
        for email in emails_of(original.get("to")) + emails_of(original.get("cc")) + emails_of(original.get("from")):
            if email in by_email:
                return by_email[email]
    if username and username.lower() in by_email:
        return by_email[username.lower()]
    if len(identities) == 1:
        return identities[0]
    raise InvalidInput("Several sending identities are available; pass from_email.", hint=f"Allowed: {allowed}")


def reply_subject(subject: str | None) -> str:
    base = _PREFIX_RE.sub("", subject or "").strip()
    return f"Re: {base}" if base else "Re:"


def forward_subject(subject: str | None) -> str:
    base = _PREFIX_RE.sub("", subject or "").strip()
    return f"Fwd: {base}" if base else "Fwd:"


def reply_recipients(
    original: dict[str, Any], identities: list[dict[str, Any]], *, reply_all: bool
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """(to, cc) for a reply. A reply to one's own mail goes to its recipients."""
    own = {(i.get("email") or "").lower() for i in identities}
    from_ = original.get("from") or []
    own_mail = any((a.get("email") or "").lower() in own for a in from_)
    if own_mail:
        to = list(original.get("to") or [])
    else:
        to = list(original.get("replyTo") or from_)
    cc: list[dict[str, Any]] = []
    if reply_all:
        cc = list(original.get("to") or []) + list(original.get("cc") or []) if not own_mail else list(original.get("cc") or [])

    def clean(items: list[dict[str, Any]], exclude: set[str]) -> list[dict[str, str]]:
        out, seen = [], set(exclude)
        for a in items:
            email = (a.get("email") or "").lower()
            if not email or email in seen:
                continue
            seen.add(email)
            out.append({"email": a["email"], **({"name": a["name"]} if a.get("name") else {})})
        return out

    to_clean = clean(to, set() if own_mail else own)
    cc_clean = clean(cc, own | {(a["email"]).lower() for a in to_clean})
    return to_clean, cc_clean


def threading_headers(original: dict[str, Any]) -> dict[str, list[str]]:
    message_ids = original.get("messageId") or []
    if not message_ids:
        raise Refused("The original mail has no Message-ID; a threaded reply is impossible.")
    parent = message_ids[0]
    refs = [r for r in (original.get("references") or []) if r != parent]
    return {"inReplyTo": [parent], "references": refs + [parent]}


def quote_block(original: dict[str, Any], text: str) -> str:
    who = addr((original.get("from") or [None])[0])
    when = original.get("sentAt") or original.get("receivedAt") or ""
    quoted = "\n".join("> " + line if line else ">" for line in text.splitlines())
    return f"\n\n{when} – {who}:\n{quoted}"


def body_structure(
    text: str,
    html: str | None,
    attachments: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, dict[str, str]]]:
    """MIME structure for Email/set create.

    @gotcha No `charset` next to `partId`. Stalwart answers invalidProperties on the
            Email/set (only there) when a part has both; the text goes out as UTF-8.
    """
    values = {"text": {"value": text}}
    text_part: dict[str, Any] = {"type": "text/plain", "partId": "text"}
    if html:
        values["html"] = {"value": html}
        content: dict[str, Any] = {
            "type": "multipart/alternative",
            "subParts": [text_part, {"type": "text/html", "partId": "html"}],
        }
    else:
        content = text_part
    if not attachments:
        return content, values
    parts = [content]
    for att in attachments:
        parts.append(
            {
                "type": att.get("type") or "application/octet-stream",
                "blobId": att["blobId"],
                "name": att.get("name") or "attachment",
                "disposition": "attachment",
            }
        )
    return {"type": "multipart/mixed", "subParts": parts}, values
