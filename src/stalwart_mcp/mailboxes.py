"""Mailbox lookup: ids, roles, paths, names."""

from __future__ import annotations

from typing import Any

from .errors import InvalidInput, NotFound
from .jmap import MAIL, Jmap

MAILBOX_PROPERTIES = [
    "id",
    "name",
    "parentId",
    "role",
    "sortOrder",
    "totalEmails",
    "unreadEmails",
    "totalThreads",
    "unreadThreads",
    "isSubscribed",
    "myRights",
]
ROLES = {"inbox", "drafts", "sent", "trash", "junk", "archive", "important", "all", "flagged", "scheduled", "memos"}
MAILBOX_CACHE_TTL = 60.0


class MailboxIndex:
    def __init__(self, mailboxes: list[dict[str, Any]]):
        self.list = mailboxes
        self.by_id = {mb["id"]: mb for mb in mailboxes}

    def path(self, mailbox_id: str) -> str:
        parts: list[str] = []
        seen: set[str] = set()
        current = self.by_id.get(mailbox_id)
        while current and current["id"] not in seen:
            seen.add(current["id"])
            parts.append(current.get("name", "?"))
            current = self.by_id.get(current.get("parentId") or "")
        return "/".join(reversed(parts))

    def by_role(self, role: str) -> dict[str, Any] | None:
        role = role.lower()
        return next((mb for mb in self.list if (mb.get("role") or "").lower() == role), None)

    def require_role(self, role: str) -> dict[str, Any]:
        mb = self.by_role(role)
        if not mb:
            raise NotFound(f"This account has no mailbox with role '{role}'.")
        return mb

    def resolve(self, ref: str) -> dict[str, Any]:
        """Find a mailbox by id, path ("Parent/Child"), role ("inbox", "archive", ...) or unique name.

        Matching is case-insensitive. An ambiguous name lists the candidates instead of guessing.
        """
        if not ref or not ref.strip():
            raise InvalidInput("Mailbox reference is empty.")
        ref = ref.strip()
        if ref in self.by_id:
            return self.by_id[ref]
        wanted = ref.strip("/").lower()
        by_path = [mb for mb in self.list if self.path(mb["id"]).lower() == wanted]
        if len(by_path) == 1:
            return by_path[0]
        key = wanted.removeprefix("role:")
        if key in ROLES:
            mb = self.by_role(key)
            if mb:
                return mb
        by_name = [mb for mb in self.list if (mb.get("name") or "").lower() == wanted]
        if len(by_name) == 1:
            return by_name[0]
        if len(by_name) > 1:
            raise InvalidInput(
                f"Mailbox name '{ref}' is ambiguous.",
                hint="Use the full path: " + ", ".join(sorted(self.path(mb["id"]) for mb in by_name)),
            )
        raise NotFound(f"No mailbox '{ref}'.", hint="list_mailboxes shows all paths and roles.")

    def names(self, mailbox_ids: dict[str, bool] | None) -> list[str]:
        return sorted(self.path(mid) for mid, on in (mailbox_ids or {}).items() if on and mid in self.by_id)

    def children(self, mailbox_id: str) -> list[dict[str, Any]]:
        return [mb for mb in self.list if mb.get("parentId") == mailbox_id]


async def mailbox_index(j: Jmap, account_id: str, *, refresh: bool = False) -> MailboxIndex:
    key = (j.cred.fingerprint, account_id, "mailboxes")
    if not refresh:
        hit = j.rt.cache_get(key, MAILBOX_CACHE_TTL)
        if hit is not None:
            return hit
    res = await j.one("Mailbox/get", {"accountId": account_id, "ids": None, "properties": MAILBOX_PROPERTIES}, [MAIL])
    index = MailboxIndex(res.get("list", []))
    j.rt.cache_put(key, index)
    return index


def drop_mailbox_cache(j: Jmap) -> None:
    j.rt.cache_drop(j.cred.fingerprint, "mailboxes")
