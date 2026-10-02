"""Server administration over Stalwart 0.16's JMAP management API (`urn:stalwart:jmap`).

Reference with all sources: docs/stalwart-management-api.md. Rules that bite:

@gotcha Management objects are `x:<Type>` with only /get, /set and /query. There is no
        /changes, and `accountId` is never sent (it defaults to the caller).
@gotcha Wire encoding: a List is an object keyed "0", "1", …; a Set is {"member": true};
        durations are milliseconds, sizes bytes. Secrets read back as "****".
@gotcha /query filters are AND only. OR/NOT answer unsupportedFilter.
@warn   Writes to AllowedIp, Security and most settings only take effect after the
        Action ReloadSettings; BlockedIp writes after ReloadBlockedIps. The tools here
        trigger the reload themselves where they change those objects.
@warn   API keys are valid for the management API only, not for JMAP mail.
"""

from __future__ import annotations

import re
import secrets
from typing import Any

from .errors import InvalidInput, NotFound, Refused, SetError
from .jmap import MANAGEMENT, Jmap, ref
from .render import compact

ANSI = re.compile(r"\x1b\[[0-9;]*m")
SIZE = re.compile(r"^\s*(\d+(?:[.,]\d+)?)\s*(b|kb|mb|gb|tb|kib|mib|gib|tib)?\s*$", re.I)
SIZE_FACTORS = {
    None: 1,
    "b": 1,
    "kb": 1000,
    "mb": 1000**2,
    "gb": 1000**3,
    "tb": 1000**4,
    "kib": 1024,
    "mib": 1024**2,
    "gib": 1024**3,
    "tib": 1024**4,
}
RETRY_NOW = "2000-01-01T00:00:00Z"
SIMPLE_ACTIONS = (
    "ReloadSettings",
    "ReloadTlsCertificates",
    "ReloadBlockedIps",
    "ReloadLookupStores",
    "InvalidateCaches",
    "InvalidateNegativeCaches",
    "PauseMtaQueue",
    "ResumeMtaQueue",
)
CACHE_TTL = 60.0


# ---------------------------------------------------------------------- primitives


def _pointer_key(value: str) -> str:
    """Escape a map key for use in a JSON pointer patch (RFC 6901)."""
    return value.replace("~", "~0").replace("/", "~1")


def _set_failures(result: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in ("notCreated", "notUpdated", "notDestroyed"):
        for oid, err in (result.get(key) or {}).items():
            out[oid] = compact(
                {
                    "type": err.get("type"),
                    "description": err.get("description"),
                    "properties": err.get("properties"),
                    "validationErrors": err.get("validationErrors"),
                    "linkedObjects": err.get("linkedObjects"),
                    "objectId": err.get("objectId"),
                }
            )
    return out


async def mget(j: Jmap, type_: str, ids: list[str] | None = None, properties: list[str] | None = None) -> list[dict]:
    args: dict[str, Any] = {"ids": ids}
    if properties:
        args["properties"] = properties
    res = await j.one(f"x:{type_}/get", args, [MANAGEMENT])
    return res.get("list", [])


async def mquery(
    j: Jmap,
    type_: str,
    *,
    filter: dict[str, Any] | None = None,
    sort: list[dict[str, Any]] | None = None,
    limit: int | None = None,
    position: int | None = None,
    anchor: str | None = None,
    properties: list[str] | None = None,
    total: bool = False,
) -> tuple[list[dict], dict[str, Any]]:
    """Query + get in one request. Returns (objects in query order, query response)."""
    query: dict[str, Any] = {"filter": filter or {}}
    if sort:
        query["sort"] = sort
    if limit:
        query["limit"] = limit
    if position:
        query["position"] = position
    if anchor:
        query["anchor"] = anchor
    if total:
        query["calculateTotal"] = True
    get: dict[str, Any] = {"#ids": ref("q", f"x:{type_}/query", "/ids")}
    if properties:
        get["properties"] = properties
    res = await j.call([(f"x:{type_}/query", query, "q"), (f"x:{type_}/get", get, "g")], [MANAGEMENT])
    q = res.get("q", f"x:{type_}/query")
    found = {o["id"]: o for o in res.get("g", f"x:{type_}/get").get("list", [])}
    return [found[i] for i in q.get("ids", []) if i in found], q


async def mset(
    j: Jmap,
    type_: str,
    *,
    create: dict[str, Any] | None = None,
    update: dict[str, Any] | None = None,
    destroy: list[str] | None = None,
    what: str = "change",
) -> dict[str, Any]:
    args: dict[str, Any] = {}
    if create:
        args["create"] = create
    if update:
        args["update"] = update
    if destroy:
        args["destroy"] = destroy
    res = await j.one(f"x:{type_}/set", args, [MANAGEMENT])
    if failures := _set_failures(res):
        raise SetError(f"Stalwart refused the {what}.", details=failures)
    return res


async def action(j: Jmap, type_: str, **fields: Any) -> dict[str, Any]:
    """Run an x:Action. The result exists only in this create response (never via get)."""
    res = await mset(j, "Action", create={"a": {"@type": type_, **fields}}, what=f"action {type_}")
    return res.get("created", {}).get("a", {})


def parse_size(value: str | int | None) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, int):
        return value
    m = SIZE.match(str(value))
    if not m:
        raise InvalidInput(f"Not a size: {value!r} (e.g. '5 GB', '500 MB' or bytes).")
    number = float(m.group(1).replace(",", "."))
    return int(number * SIZE_FACTORS[(m.group(2) or "").lower() or None])


def human_size(n: int | None) -> str | None:
    if n is None:
        return None
    for unit, factor in (("GB", 1000**3), ("MB", 1000**2), ("KB", 1000)):
        if n >= factor:
            return f"{n / factor:.1f} {unit}"
    return f"{n} B"


def _new_password() -> str:
    return secrets.token_urlsafe(18)


# ---------------------------------------------------------------------- lookups


async def domain_map(j: Jmap, refresh: bool = False) -> dict[str, str]:
    """domain id -> name (cached briefly)."""
    key = (j.cred.fingerprint, "-", "domains")
    if not refresh and (hit := j.rt.cache_get(key, CACHE_TTL)) is not None:
        return hit
    domains = await mget(j, "Domain", None, ["id", "name"])
    value = {d["id"]: d.get("name", "") for d in domains}
    j.rt.cache_put(key, value)
    return value


async def domain_id(j: Jmap, name: str) -> str:
    name = name.strip().lower().lstrip("@")
    for did, dname in (await domain_map(j)).items():
        if dname.lower() == name or did == name:
            return did
    for did, dname in (await domain_map(j, refresh=True)).items():
        if dname.lower() == name:
            return did
    raise NotFound(f"No domain '{name}' on this server.", hint="list_domains shows all domains.")


async def account_by_address(j: Jmap, address: str) -> dict[str, Any]:
    address = address.strip()
    if "@" not in address:
        found = await mget(j, "Account", [address])
        if found:
            return found[0]
        raise InvalidInput(f"'{address}' is neither an address nor an account id.")
    local, _, domain = address.rpartition("@")
    did = await domain_id(j, domain)
    accounts, _ = await mquery(j, "Account", filter={"name": local, "domainId": did})
    if not accounts:
        raise NotFound(f"No account '{address}'.")
    return accounts[0]


def _addr(name: str | None, did: str | None, domains: dict[str, str]) -> str:
    return f"{name}@{domains.get(did or '', did or '?')}"


def _is_disabled(permissions: dict[str, Any] | None) -> bool:
    p = permissions or {}
    return bool((p.get("disabledPermissions") or {}).get("authenticate"))


def summarize_account(acc: dict[str, Any], domains: dict[str, str], groups: dict[str, str] | None = None) -> dict[str, Any]:
    quotas = acc.get("quotas") or {}
    roles = acc.get("roles") or {}
    return compact(
        {
            "id": acc.get("id"),
            "address": acc.get("emailAddress") or _addr(acc.get("name"), acc.get("domainId"), domains),
            "type": acc.get("@type"),
            "name": acc.get("description"),
            "aliases": [
                _addr(a.get("name"), a.get("domainId"), domains) + ("" if a.get("enabled", True) else " (disabled)")
                for _, a in sorted((acc.get("aliases") or {}).items(), key=lambda kv: int(kv[0]) if kv[0].isdigit() else 0)
            ],
            "admin": roles.get("@type") == "Admin" or None,
            "roles": roles.get("@type") if roles.get("@type") not in ("User", "Admin", "Default") else None,
            "disabled": _is_disabled(acc.get("permissions")) or None,
            "quota": human_size(quotas.get("maxDiskQuota")),
            "used": human_size(acc.get("usedDiskQuota")),
            "groups": [(groups or {}).get(g, g) for g, on in (acc.get("memberGroupIds") or {}).items() if on],
            "created": acc.get("createdAt"),
        }
    )


# ---------------------------------------------------------------------- info


async def admin_info(j: Jmap) -> dict[str, Any]:
    session = await j.session()
    out: dict[str, Any] = {"username": session.username}
    resp = await j._send("GET", f"{j.base_url}/api/account")
    try:
        data = resp.json()
    except ValueError:
        data = {}
    permissions = data.get("permissions") or []
    out.update(
        {
            "edition": data.get("edition"),
            "permission_count": len(permissions),
            "is_admin": any("account" in p.lower() and "create" in p.lower() for p in permissions),
            "management_permissions": sorted(p for p in permissions if p.lower().startswith(("sys", "action", "task")))[:200],
        }
    )
    return out


# ---------------------------------------------------------------------- accounts


async def list_accounts(
    j: Jmap, *, text: str | None = None, domain: str | None = None, kind: str | None = None, limit: int = 100, position: int = 0
) -> dict[str, Any]:
    filt: dict[str, Any] = {}
    if text:
        filt["text"] = text
    if domain:
        filt["domainId"] = await domain_id(j, domain)
    if kind:
        if kind not in ("User", "Group"):
            raise InvalidInput("kind must be 'User' or 'Group'.")
        filt["@type"] = kind
    limit = max(1, min(int(limit or 100), 1000))
    accounts, q = await mquery(
        j, "Account", filter=filt, limit=limit, position=position, total=True, sort=[{"property": "name", "isAscending": True}]
    )
    domains = await domain_map(j)
    group_ids = {g for a in accounts for g, on in (a.get("memberGroupIds") or {}).items() if on}
    groups = {}
    if group_ids:
        groups = {
            g["id"]: _addr(g.get("name"), g.get("domainId"), domains)
            for g in await mget(j, "Account", sorted(group_ids), ["id", "name", "domainId"])
        }
    out = {"total": q.get("total"), "count": len(accounts), "accounts": [summarize_account(a, domains, groups) for a in accounts]}
    if q.get("total") and position + len(accounts) < q["total"]:
        out["next_position"] = position + len(accounts)
    return out


async def get_account(j: Jmap, account: str) -> dict[str, Any]:
    acc = await account_by_address(j, account)
    domains = await domain_map(j)
    group_ids = sorted(g for g, on in (acc.get("memberGroupIds") or {}).items() if on)
    groups = (
        {g["id"]: _addr(g.get("name"), g.get("domainId"), domains) for g in await mget(j, "Account", group_ids, ["id", "name", "domainId"])}
        if group_ids
        else {}
    )
    out = summarize_account(acc, domains, groups)
    creds = []
    for key, cred in sorted((acc.get("credentials") or {}).items()):
        creds.append(
            compact(
                {
                    "key": key,
                    "type": cred.get("@type"),
                    "description": cred.get("description"),
                    "expires": cred.get("expiresAt"),
                    "allowedIps": sorted(ip for ip, on in (cred.get("allowedIps") or {}).items() if on) or None,
                    "two_factor": bool(cred.get("otpAuth")) or None,
                    "created": cred.get("createdAt"),
                }
            )
        )
    out["credentials"] = creds
    out["permissions"] = (acc.get("permissions") or {}).get("@type")
    other = {k: v for k, v in (acc.get("quotas") or {}).items() if k != "maxDiskQuota"}
    if other:
        out["limits"] = other
    out["locale"] = acc.get("locale")
    return compact(out)


async def create_account(
    j: Jmap,
    address: str,
    *,
    kind: str = "User",
    display_name: str | None = None,
    password: str | None = None,
    generate_password: bool = False,
    aliases: list[str] | None = None,
    quota: str | int | None = None,
    groups: list[str] | None = None,
    admin: bool = False,
) -> dict[str, Any]:
    if kind not in ("User", "Group"):
        raise InvalidInput("kind must be 'User' or 'Group'.")
    if "@" not in address:
        raise InvalidInput("address must be a full address (name@domain).")
    local, _, domain = address.strip().rpartition("@")
    did = await domain_id(j, domain)
    obj: dict[str, Any] = {"@type": kind, "name": local, "domainId": did}
    if display_name:
        obj["description"] = display_name
    alias_list = {}
    for n, alias in enumerate(aliases or []):
        a_local, _, a_domain = alias.strip().rpartition("@")
        if not a_local:
            raise InvalidInput(f"Alias '{alias}' must be a full address.")
        alias_list[str(n)] = {"name": a_local, "domainId": await domain_id(j, a_domain)}
    if alias_list:
        obj["aliases"] = alias_list
    if (size := parse_size(quota)) is not None:
        obj["quotas"] = {"maxDiskQuota": size}
    generated = None
    if kind == "User":
        if password and generate_password:
            raise InvalidInput("Pass either password or generate_password, not both.")
        if generate_password:
            password = generated = _new_password()
        if password:
            obj["credentials"] = {"0": {"@type": "Password", "secret": password}}
        if groups:
            member = {}
            for g in groups:
                member[(await account_by_address(j, g))["id"]] = True
            obj["memberGroupIds"] = member
        obj["roles"] = {"@type": "Admin" if admin else "User"}
    elif admin or password or generate_password or groups:
        raise InvalidInput("Groups cannot log in: no password, admin role or group membership.")
    res = await mset(j, "Account", create={"n": obj}, what="new account")
    out: dict[str, Any] = {"created": address, "id": res.get("created", {}).get("n", {}).get("id"), "type": kind}
    if generated:
        out["password"] = generated
        out["warning"] = (
            "This password is now in the conversation. Hand it over through a secure channel and have the user "
            "change it at first login (Account › Credentials › Password)."
        )
    if not password and kind == "User":
        out["note"] = "No password set: the account cannot log in until one is set (update_account reset_password)."
    return out


async def update_account(
    j: Jmap,
    account: str,
    *,
    display_name: str | None = None,
    add_aliases: list[str] | None = None,
    remove_aliases: list[str] | None = None,
    quota: str | int | None = None,
    add_groups: list[str] | None = None,
    remove_groups: list[str] | None = None,
    admin: bool | None = None,
    enabled: bool | None = None,
    reset_password: bool = False,
    new_password: str | None = None,
) -> dict[str, Any]:
    acc = await account_by_address(j, account)
    domains = await domain_map(j)
    patch: dict[str, Any] = {}
    changes: list[str] = []
    generated = None
    if display_name is not None:
        patch["description"] = display_name or None
        changes.append("display name")
    aliases = acc.get("aliases") or {}
    if remove_aliases:
        for alias in remove_aliases:
            target = alias.strip().lower()
            key = next((k for k, a in aliases.items() if _addr(a.get("name"), a.get("domainId"), domains).lower() == target), None)
            if key is None:
                raise NotFound(f"'{alias}' is not an alias of {account}.")
            patch[f"aliases/{key}"] = None
        changes.append("aliases removed")
    if add_aliases:
        next_key = max([int(k) for k in aliases if k.isdigit()] + [-1]) + 1
        for alias in add_aliases:
            a_local, _, a_domain = alias.strip().rpartition("@")
            if not a_local:
                raise InvalidInput(f"Alias '{alias}' must be a full address.")
            patch[f"aliases/{next_key}"] = {"name": a_local, "domainId": await domain_id(j, a_domain)}
            next_key += 1
        changes.append("aliases added")
    if quota is not None:
        size = None if str(quota).strip().lower() in ("none", "unlimited", "0") else parse_size(quota)
        patch["quotas/maxDiskQuota"] = size
        changes.append("quota")
    for g in add_groups or []:
        patch[f"memberGroupIds/{(await account_by_address(j, g))['id']}"] = True
    for g in remove_groups or []:
        patch[f"memberGroupIds/{(await account_by_address(j, g))['id']}"] = None
    if add_groups or remove_groups:
        changes.append("groups")
    if admin is not None:
        patch["roles"] = {"@type": "Admin" if admin else "User"}
        changes.append("admin" if admin else "admin removed")
    if enabled is not None:
        perms = dict(acc.get("permissions") or {"@type": "Inherit"})
        disabled = dict(perms.get("disabledPermissions") or {})
        if enabled:
            disabled.pop("authenticate", None)
            if perms.get("@type") == "Merge" and not disabled and not perms.get("enabledPermissions"):
                perms = {"@type": "Inherit"}
            else:
                perms["disabledPermissions"] = disabled
        else:
            if perms.get("@type") == "Inherit":
                perms = {"@type": "Merge", "enabledPermissions": {}, "disabledPermissions": {}}
            perms["disabledPermissions"] = {**(perms.get("disabledPermissions") or {}), "authenticate": True}
        patch["permissions"] = perms
        changes.append("enabled" if enabled else "disabled (login blocked, mail still delivered)")
    if reset_password or new_password:
        if acc.get("@type") != "User":
            raise InvalidInput("Only users have passwords.")
        password = new_password or _new_password()
        generated = None if new_password else password
        creds = acc.get("credentials") or {}
        key = next((k for k, c in creds.items() if c.get("@type") == "Password"), None)
        if key is None:
            key = str(max([int(k) for k in creds if k.isdigit()] + [-1]) + 1)
            patch[f"credentials/{key}"] = {"@type": "Password", "secret": password}
        else:
            # Patch only the secret: replacing the whole credentials object would revoke
            # every app password and API key of the account.
            patch[f"credentials/{key}/secret"] = password
        changes.append("password reset")
    if not patch:
        raise InvalidInput("Nothing to change.")
    await mset(j, "Account", update={acc["id"]: patch}, what=f"update of {account}")
    out: dict[str, Any] = {"updated": acc.get("emailAddress") or account, "changes": changes}
    if generated:
        out["password"] = generated
        out["warning"] = "This password is now in the conversation; hand it over securely and have it changed."
    return out


async def delete_account(j: Jmap, account: str, *, confirm_address: str) -> dict[str, Any]:
    acc = await account_by_address(j, account)
    address = (acc.get("emailAddress") or "").lower()
    if confirm_address.strip().lower() != address:
        raise Refused("confirm_address does not match the account; nothing was deleted.", details={"account": address})
    await mset(j, "Account", destroy=[acc["id"]], what=f"deletion of {address}")
    return {"deleted": address, "note": "Stalwart purges the mailbox data in a background task."}


# ---------------------------------------------------------------------- domains


async def list_domains(j: Jmap, *, text: str | None = None, include_dkim: bool = False) -> dict[str, Any]:
    domains, _ = await mquery(
        j,
        "Domain",
        filter={"text": text} if text else {},
        sort=[{"property": "name", "isAscending": True}],
        properties=[
            "id",
            "name",
            "aliases",
            "isEnabled",
            "description",
            "dkimManagement",
            "dnsManagement",
            "certificateManagement",
            "catchAllAddress",
            "createdAt",
        ],
    )
    keys: dict[str, list] = {}
    if include_dkim and domains:
        for key in await mget(j, "DkimSignature", None, ["id", "domainId", "selector", "stage", "createdAt", "nextTransitionAt"]):
            keys.setdefault(key.get("domainId"), []).append(
                compact(
                    {
                        "selector": key.get("selector"),
                        "algorithm": key.get("@type"),
                        "stage": key.get("stage"),
                        "created": key.get("createdAt"),
                        "next_transition": key.get("nextTransitionAt"),
                    }
                )
            )
    out = []
    for d in domains:
        out.append(
            compact(
                {
                    "id": d["id"],
                    "name": d.get("name"),
                    "aliases": sorted(a for a, on in (d.get("aliases") or {}).items() if on),
                    "enabled": d.get("isEnabled", True),
                    "description": d.get("description"),
                    "dkim": (d.get("dkimManagement") or {}).get("@type"),
                    "dns": (d.get("dnsManagement") or {}).get("@type"),
                    "certificates": (d.get("certificateManagement") or {}).get("@type"),
                    "catch_all": d.get("catchAllAddress"),
                    "dkim_keys": keys.get(d["id"]) if include_dkim else None,
                }
            )
        )
    return {"count": len(out), "domains": out}


async def get_domain_dns(j: Jmap, domain: str) -> dict[str, Any]:
    did = await domain_id(j, domain)
    found = await mget(j, "Domain", [did], ["name", "dnsZoneFile"])
    if not found:
        raise NotFound(f"No domain '{domain}'.")
    return {
        "domain": found[0].get("name"),
        "zone": found[0].get("dnsZoneFile") or "",
        "note": "BIND zone text with every record the domain needs (MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, SRV, "
        "autoconfig). Compare with the live zone before changing DNS.",
    }


async def create_domain(j: Jmap, name: str, *, description: str | None = None, automatic_dkim: bool = True) -> dict[str, Any]:
    obj: dict[str, Any] = {
        "name": name.strip().lower(),
        "dkimManagement": {"@type": "Automatic"} if automatic_dkim else {"@type": "Manual"},
    }
    if description:
        obj["description"] = description
    res = await mset(j, "Domain", create={"d": obj}, what=f"domain {name}")
    j.rt.cache_drop(j.cred.fingerprint, "domains")
    return {
        "created": obj["name"],
        "id": res.get("created", {}).get("d", {}).get("id"),
        "next": "DKIM keys are generated by a background task. Call get_domain_dns in a minute for the full record set.",
    }


async def delete_domain(j: Jmap, name: str, *, confirm_name: str) -> dict[str, Any]:
    if confirm_name.strip().lower() != name.strip().lower():
        raise Refused("confirm_name does not match; nothing was deleted.")
    did = await domain_id(j, name)
    await mset(j, "Domain", destroy=[did], what=f"deletion of {name}")
    j.rt.cache_drop(j.cred.fingerprint, "domains")
    return {"deleted": name}


# ---------------------------------------------------------------------- mailing lists


async def list_mailing_lists(j: Jmap, *, text: str | None = None) -> dict[str, Any]:
    lists, _ = await mquery(j, "MailingList", filter={"text": text} if text else {})
    domains = await domain_map(j)
    return {
        "count": len(lists),
        "lists": [
            compact(
                {
                    "id": m["id"],
                    "address": m.get("emailAddress") or _addr(m.get("name"), m.get("domainId"), domains),
                    "description": m.get("description"),
                    "aliases": [_addr(a.get("name"), a.get("domainId"), domains) for a in (m.get("aliases") or {}).values()],
                    "recipients": sorted(r for r, on in (m.get("recipients") or {}).items() if on),
                }
            )
            for m in lists
        ],
    }


async def manage_mailing_list(
    j: Jmap,
    action_: str,
    address: str,
    *,
    add_recipients: list[str] | None = None,
    remove_recipients: list[str] | None = None,
    description: str | None = None,
    confirm_address: str | None = None,
) -> dict[str, Any]:
    local, _, domain = address.strip().rpartition("@")
    if not local:
        raise InvalidInput("address must be a full address.")
    if action_ == "create":
        obj: dict[str, Any] = {
            "name": local,
            "domainId": await domain_id(j, domain),
            "recipients": {r.strip(): True for r in add_recipients or []},
        }
        if description:
            obj["description"] = description
        res = await mset(j, "MailingList", create={"m": obj}, what=f"mailing list {address}")
        return {"created": address, "id": res.get("created", {}).get("m", {}).get("id"), "recipients": len(obj["recipients"])}
    did = await domain_id(j, domain)
    lists, _ = await mquery(j, "MailingList", filter={"text": local})
    target = next((m for m in lists if m.get("name") == local and m.get("domainId") == did), None)
    if not target:
        raise NotFound(f"No mailing list '{address}'.")
    if action_ == "delete":
        if (confirm_address or "").strip().lower() != address.strip().lower():
            raise Refused("confirm_address does not match; nothing was deleted.")
        await mset(j, "MailingList", destroy=[target["id"]], what=f"deletion of {address}")
        return {"deleted": address}
    if action_ != "update":
        raise InvalidInput("action must be create, update or delete.")
    patch: dict[str, Any] = {}
    for r in add_recipients or []:
        patch[f"recipients/{_pointer_key(r.strip())}"] = True
    for r in remove_recipients or []:
        patch[f"recipients/{_pointer_key(r.strip())}"] = None
    if description is not None:
        patch["description"] = description or None
    if not patch:
        raise InvalidInput("Nothing to change.")
    await mset(j, "MailingList", update={target["id"]: patch}, what=f"update of {address}")
    return compact({"updated": address, "added": add_recipients, "removed": remove_recipients})


# ---------------------------------------------------------------------- queue


def _recipient_status(addr_: str, r: dict[str, Any]) -> dict[str, Any]:
    status = r.get("status") or {}
    return compact(
        {
            "to": addr_,
            "status": status.get("@type"),
            "error": status.get("errorType"),
            "message": status.get("errorMessage") or status.get("responseMessage"),
            "response": " ".join(str(x) for x in (status.get("responseCode"), status.get("responseEnhanced")) if x) or None,
            "host": status.get("responseHostname"),
            "retries": r.get("retryCount") or None,
            "next_retry": r.get("retryDue"),
            "queue": r.get("queueName"),
        }
    )


async def list_queue(
    j: Jmap,
    *,
    recipient: str | None = None,
    sender: str | None = None,
    text: str | None = None,
    due_before: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    from .ops import utc_date

    filt: dict[str, Any] = {}
    if recipient:
        filt["to"] = recipient
    if sender:
        filt["returnPath"] = sender
    if text:
        filt["text"] = text
    if due_before:
        filt["dueIsLessThan"] = utc_date(due_before)
    limit = max(1, min(int(limit or 50), 500))
    messages, q = await mquery(j, "QueuedMessage", filter=filt, sort=[{"property": "due", "isAscending": True}], limit=limit, total=True)
    return {
        "total": q.get("total"),
        "messages": [
            compact(
                {
                    "id": m["id"],
                    "from": m.get("returnPath"),
                    "size": m.get("size"),
                    "queued": m.get("createdAt"),
                    "next_retry": m.get("nextRetry"),
                    "flags": sorted(f for f, on in (m.get("flags") or {}).items() if on),
                    "recipients": [_recipient_status(a, r) for a, r in (m.get("recipients") or {}).items()],
                }
            )
            for m in messages
        ],
    }


async def queue_action(
    j: Jmap, action_: str, *, ids: list[str] | None = None, recipient: str | None = None, at: str | None = None
) -> dict[str, Any]:
    from .ops import utc_date

    if action_ in ("pause", "resume"):
        await action(j, "PauseMtaQueue" if action_ == "pause" else "ResumeMtaQueue")
        return {"queue": "paused" if action_ == "pause" else "resumed"}
    if not ids:
        raise InvalidInput(f"{action_} needs ids (from list_queue).")
    if action_ == "retry_now":
        await mset(j, "QueuedMessage", update={i: {"nextRetry": RETRY_NOW} for i in ids}, what="retry")
        return {"retrying": ids}
    if action_ == "reschedule":
        when = utc_date(at)
        if not when:
            raise InvalidInput("reschedule needs at (date/time).")
        await mset(j, "QueuedMessage", update={i: {"nextRetry": when} for i in ids}, what="reschedule")
        return {"rescheduled": ids, "at": when}
    if action_ == "cancel":
        if recipient:
            if len(ids) != 1:
                raise InvalidInput("Cancelling one recipient works on exactly one message id.")
            await mset(j, "QueuedMessage", update={ids[0]: {f"recipients/{_pointer_key(recipient)}": None}}, what="cancel")
            return {"cancelled_recipient": recipient, "message": ids[0]}
        await mset(j, "QueuedMessage", destroy=ids, what="cancel")
        return {"cancelled": ids}
    raise InvalidInput("action must be retry_now, reschedule, cancel, pause or resume.")


# ---------------------------------------------------------------------- IP lists


async def list_ips(j: Jmap, *, kind: str = "both", address: str | None = None, limit: int = 200) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for type_, key in (("BlockedIp", "blocked"), ("AllowedIp", "allowed")):
        if kind not in ("both", key):
            continue
        items, _ = await mquery(j, type_, filter={"address": address} if address else {}, limit=max(1, min(limit, 1000)))
        out[key] = [
            compact(
                {
                    "id": i["id"],
                    "address": i.get("address"),
                    "reason": i.get("reason"),
                    "created": i.get("createdAt"),
                    "expires": i.get("expiresAt"),
                }
            )
            for i in items
        ]
    return out


async def manage_ip(j: Jmap, action_: str, address: str, *, reason: str | None = None, expires: str | None = None) -> dict[str, Any]:
    from .ops import utc_date

    if action_ not in ("allow", "unallow", "block", "unblock"):
        raise InvalidInput("action must be allow, unallow, block or unblock.")
    type_ = "AllowedIp" if action_ in ("allow", "unallow") else "BlockedIp"
    reload = "ReloadSettings" if type_ == "AllowedIp" else "ReloadBlockedIps"
    if action_ in ("allow", "block"):
        obj: dict[str, Any] = {"address": address.strip()}
        if reason:
            obj["reason"] = reason if type_ == "AllowedIp" else "manual"
        if expires:
            obj["expiresAt"] = utc_date(expires)
        await mset(j, type_, create={"i": obj}, what=f"{action_} {address}")
    else:
        items, _ = await mquery(j, type_, filter={"address": address.strip()})
        if not items:
            raise NotFound(f"{address} is not on the {'allowed' if type_ == 'AllowedIp' else 'blocked'} list.")
        await mset(j, type_, destroy=[i["id"] for i in items], what=f"{action_} {address}")
    # @warn Without the reload the running server keeps its old in-memory list.
    await action(j, reload)
    return {"done": action_, "address": address, "reloaded": reload}


# ---------------------------------------------------------------------- reports


def _dmarc_summary(r: dict[str, Any]) -> dict[str, Any]:
    rep = r.get("report") or {}
    records = list((rep.get("records") or {}).values())
    total = sum(int(x.get("count") or 0) for x in records)
    failing = [x for x in records if x.get("evaluatedDkim") != "pass" and x.get("evaluatedSpf") != "pass"]
    fail_count = sum(int(x.get("count") or 0) for x in failing)
    top = sorted(failing, key=lambda x: -int(x.get("count") or 0))[:5]
    return compact(
        {
            "id": r.get("id"),
            "org": rep.get("orgName"),
            "domain": rep.get("policyDomain"),
            "policy": rep.get("policyDisposition"),
            "from": rep.get("dateRangeBegin"),
            "to": rep.get("dateRangeEnd"),
            "messages": total,
            "dmarc_fail": fail_count,
            "failing_sources": [
                compact(
                    {
                        "ip": x.get("sourceIp"),
                        "count": x.get("count"),
                        "header_from": x.get("headerFrom"),
                        "spf": x.get("evaluatedSpf"),
                        "dkim": x.get("evaluatedDkim"),
                        "disposition": x.get("evaluatedDisposition"),
                    }
                )
                for x in top
            ],
            "received": r.get("receivedAt"),
        }
    )


def _tls_summary(r: dict[str, Any]) -> dict[str, Any]:
    rep = r.get("report") or {}
    policies = list((rep.get("policies") or {}).values())
    return compact(
        {
            "id": r.get("id"),
            "org": rep.get("organizationName"),
            "from": rep.get("dateRangeStart"),
            "to": rep.get("dateRangeEnd"),
            "policies": [
                compact(
                    {
                        "domain": p.get("policyDomain"),
                        "type": p.get("policyType"),
                        "ok": p.get("totalSuccessfulSessions"),
                        "failed": p.get("totalFailedSessions"),
                        "failures": sorted({(f.get("resultType") or "?") for f in (p.get("failureDetails") or {}).values()}),
                    }
                )
                for p in policies
            ],
            "received": r.get("receivedAt"),
        }
    )


async def list_reports(
    j: Jmap, kind: str = "dmarc", *, domain: str | None = None, since: str | None = None, limit: int = 30, full: bool = False
) -> dict[str, Any]:
    from .ops import utc_date

    type_ = {"dmarc": "DmarcExternalReport", "tls": "TlsExternalReport"}.get(kind)
    if not type_:
        raise InvalidInput("kind must be 'dmarc' or 'tls'.")
    # @gotcha The `domain` filter only works for internal reports; `text` covers the
    #         policy and sender domains of external ones.
    filt = {"text": domain} if domain else {}
    reports, _ = await mquery(j, type_, filter=filt, limit=max(1, min(int(limit or 30), 200)))
    cutoff = utc_date(since)
    if cutoff:
        reports = [r for r in reports if (r.get("receivedAt") or "") >= cutoff]
    if full:
        return {"count": len(reports), "reports": reports}
    summary = [_dmarc_summary(r) if kind == "dmarc" else _tls_summary(r) for r in reports]
    return {"count": len(summary), "reports": summary}


# ---------------------------------------------------------------------- logs, tasks, actions


async def search_logs(j: Jmap, text: str | None = None, *, limit: int = 50, anchor: str | None = None) -> dict[str, Any]:
    """Newest first. `text` is a case-sensitive substring of the raw log line, e.g. '(auth.failed)'."""
    entries, _ = await mquery(j, "Log", filter={"text": text} if text else {}, limit=max(1, min(int(limit or 50), 500)), anchor=anchor)
    rows = [
        compact(
            {
                "id": e.get("id"),
                "time": e.get("timestamp"),
                "level": e.get("level"),
                "event": e.get("event"),
                "details": ANSI.sub("", e.get("details") or "")[:2000],
            }
        )
        for e in entries
    ]
    out: dict[str, Any] = {"count": len(rows), "entries": rows}
    if rows:
        out["next_anchor"] = rows[-1]["id"]
    return out


async def list_tasks(j: Jmap, *, failed_only: bool = False, task_type: str | None = None, limit: int = 50) -> dict[str, Any]:
    filt: dict[str, Any] = {}
    if failed_only:
        filt["status"] = "Failed"
    if task_type:
        filt["@type"] = task_type
    tasks, _ = await mquery(j, "Task", filter=filt, sort=[{"property": "due", "isAscending": True}], limit=max(1, min(limit, 500)))
    out = []
    for t in tasks:
        status = t.get("status") or {}
        details = {k: v for k, v in t.items() if k not in ("id", "@type", "status", "due")}
        out.append(
            compact(
                {
                    "id": t["id"],
                    "type": t.get("@type"),
                    "status": status.get("@type"),
                    "due": t.get("due"),
                    "attempt": status.get("attemptNumber") or status.get("failedAttemptNumber"),
                    "failure": status.get("failureReason"),
                    "details": details or None,
                }
            )
        )
    return {"count": len(out), "tasks": out}


async def run_task(
    j: Jmap,
    task_type: str,
    *,
    domain: str | None = None,
    account: str | None = None,
    maintenance: str | None = None,
    records: list[str] | None = None,
) -> dict[str, Any]:
    obj: dict[str, Any] = {"@type": task_type}
    if task_type == "SpamFilterMaintenance":
        obj["maintenanceType"] = maintenance or "train"
    elif task_type in ("DkimManagement", "DnsManagement", "AcmeRenewal"):
        if not domain:
            raise InvalidInput(f"{task_type} needs domain.")
        obj["domainId"] = await domain_id(j, domain)
        if task_type == "DnsManagement":
            obj["updateRecords"] = {r: True for r in records or []}
            obj["onSuccessRenewCertificate"] = False
    elif task_type == "AccountMaintenance":
        if not account:
            raise InvalidInput("AccountMaintenance needs account.")
        obj["accountId"] = (await account_by_address(j, account))["id"]
        obj["maintenanceType"] = maintenance or "recalculateQuota"
    else:
        raise InvalidInput("task_type must be SpamFilterMaintenance, DkimManagement, DnsManagement, AcmeRenewal or AccountMaintenance.")
    res = await mset(j, "Task", create={"t": obj}, what=f"task {task_type}")
    return {
        "scheduled": task_type,
        "id": res.get("created", {}).get("t", {}).get("id"),
        "note": "Runs in the background; list_tasks shows failures.",
    }


async def run_action(j: Jmap, action_type: str) -> dict[str, Any]:
    if action_type not in SIMPLE_ACTIONS:
        raise InvalidInput(f"action_type must be one of {', '.join(SIMPLE_ACTIONS)}.")
    await action(j, action_type)
    return {"done": action_type}


async def diagnose(
    j: Jmap,
    kind: str,
    *,
    message: str | None = None,
    remote_ip: str,
    ehlo_domain: str,
    mail_from: str,
    recipients: list[str] | None = None,
) -> dict[str, Any]:
    if kind == "dmarc":
        mail_domain = mail_from.rpartition("@")[2]
        fields: dict[str, Any] = {
            "remoteIp": remote_ip,
            "ehloDomain": ehlo_domain,
            "mailFrom": mail_from,
            "spfEhloDomain": ehlo_domain,
            "spfMailFromDomain": mail_domain,
        }
        if message:
            fields["message"] = message
        return await action(j, "TroubleshootDmarc", **fields)
    if kind == "spam":
        if not message:
            raise InvalidInput("Spam classification needs the raw message (load_attachment raw=true on the mail side).")
        fields = {"message": message, "remoteIp": remote_ip, "ehloDomain": ehlo_domain, "envFrom": mail_from}
        if recipients:
            fields["envRcptTo"] = {r: True for r in recipients}
        return await action(j, "ClassifySpam", **fields)
    raise InvalidInput("kind must be 'dmarc' or 'spam'.")


# ---------------------------------------------------------------------- generic


_TYPE = re.compile(r"^[A-Z][A-Za-z0-9]+$")


def _type(name: str) -> str:
    name = name.strip().removeprefix("x:")
    if not _TYPE.match(name):
        raise InvalidInput(f"Not a management object type: {name!r} (e.g. 'Domain', 'MtaRoute').")
    return name


async def query_objects(
    j: Jmap,
    type_: str,
    *,
    ids: list[str] | None = None,
    filter: dict[str, Any] | None = None,
    properties: list[str] | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    name = _type(type_)
    if ids or name in (
        "Security",
        "SystemSettings",
        "Authentication",
        "TaskManager",
        "SpamClassifier",
        "MtaOutboundStrategy",
        "Jmap",
        "Email",
    ):
        objects = await mget(j, name, ids or None, properties)
        return {"type": name, "count": len(objects), "objects": objects}
    objects, q = await mquery(j, name, filter=filter, properties=properties, limit=max(1, min(int(limit or 50), 500)), total=True)
    return {"type": name, "total": q.get("total"), "count": len(objects), "objects": objects}


async def set_object(
    j: Jmap,
    type_: str,
    *,
    create: dict[str, Any] | None = None,
    update: dict[str, Any] | None = None,
    destroy: list[str] | None = None,
    reload: bool = False,
) -> dict[str, Any]:
    name = _type(type_)
    if name == "Action":
        raise InvalidInput("Use run_action or diagnose for actions.")
    if not (create or update or destroy):
        raise InvalidInput("Pass create, update or destroy.")
    res = await mset(j, name, create=create, update=update, destroy=destroy, what=f"{name} change")
    out = compact(
        {
            "type": name,
            "created": res.get("created"),
            "updated": list((res.get("updated") or {}).keys()) or None,
            "destroyed": res.get("destroyed"),
        }
    )
    if reload:
        await action(j, "ReloadBlockedIps" if name == "BlockedIp" else "ReloadSettings")
        out["reloaded"] = True
    return out
