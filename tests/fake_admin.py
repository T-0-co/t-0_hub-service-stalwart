"""Management (`urn:stalwart:jmap`) extension of the fake Stalwart.

Implements the generic x:<Type>/get|set|query semantics described in
docs/stalwart-management-api.md with an in-memory object store, plus the few
type-specific behaviours the admin tools depend on.
"""

from __future__ import annotations

import copy
import itertools
import json
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from tests import fake_jmap as fj

MANAGEMENT = "urn:stalwart:jmap"
SECRET_MASK = "****"
REQUIRED = {
    "Account": ("@type", "name", "domainId"),
    "Domain": ("name",),
    "MailingList": ("name", "domainId"),
    "AllowedIp": ("address",),
    "BlockedIp": ("address",),
    "Task": ("@type",),
}
UNIQUE = {
    "Account": ("name", "domainId"),
    "MailingList": ("name", "domainId"),
    "Domain": ("name",),
    "AllowedIp": ("address",),
    "BlockedIp": ("address",),
}
ACTIONS = {
    "ReloadSettings",
    "ReloadTlsCertificates",
    "ReloadBlockedIps",
    "ReloadLookupStores",
    "InvalidateCaches",
    "InvalidateNegativeCaches",
    "PauseMtaQueue",
    "ResumeMtaQueue",
    "TroubleshootDmarc",
    "ClassifySpam",
}
COMPARE = ("IsGreaterThanOrEqual", "IsLessThanOrEqual", "IsGreaterThan", "IsLessThan")


def _unescape(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


def _apply_pointer(obj: dict, path: str, value: Any) -> None:
    tokens = [_unescape(t) for t in path.split("/")]
    cur = obj
    for token in tokens[:-1]:
        if not isinstance(cur.get(token), dict):
            cur[token] = {}
        cur = cur[token]
    if value is None:
        cur.pop(tokens[-1], None)
    else:
        cur[tokens[-1]] = value


class FakeStalwartAdmin(fj.FakeStalwart):
    def __init__(self) -> None:
        super().__init__()
        self.objects: dict[str, dict[str, dict]] = defaultdict(dict)
        self.actions: list[dict] = []
        self.api_permissions = ["authenticate", "sysAccountGet", "sysAccountCreate", "sysDomainGet", "actionReloadSettings"]
        self._oid = itertools.count(1)

    # ------------------------------------------------------------ seeding

    def put(self, type_: str, obj: dict, oid: str | None = None) -> str:
        oid = oid or f"o{next(self._oid)}"
        self.objects[type_][oid] = {**copy.deepcopy(obj), "id": oid}
        return oid

    # ------------------------------------------------------------ routing

    async def _route(self, request: Request, user: str) -> Response:
        if request.url.path == "/api/account":
            return JSONResponse({"permissions": self.api_permissions, "edition": "oss", "locale": "en-US"})
        return await super()._route(request, user)

    def _dispatch(self, ctx: Any, name: str, args: dict, call_id: str) -> None:
        if not name.startswith("x:"):
            return super()._dispatch(ctx, name, args, call_id)
        self.calls.append(name)
        try:
            if MANAGEMENT not in ctx.using:
                raise fj._MethodError("unknownMethod")
            args = self._resolve_refs(ctx, args)
            type_, _, method = name[2:].partition("/")
            if method not in ("get", "set", "query"):
                raise fj._MethodError("unknownMethod")
            result = getattr(self, f"_m_{method}")(type_, args)
        except fj._MethodError as err:
            ctx.responses.append(["error", {"type": err.type, **err.extra}, call_id])
            return
        ctx.responses.append([name, result, call_id])

    # ------------------------------------------------------------ views

    def _view(self, type_: str, obj: dict, properties: list[str] | None) -> dict:
        out = copy.deepcopy(obj)
        if type_ == "Account":
            domain = self.objects["Domain"].get(out.get("domainId"), {})
            out["emailAddress"] = f"{out.get('name')}@{domain.get('name', '?')}"
            out.setdefault("usedDiskQuota", 0)
            for cred in (out.get("credentials") or {}).values():
                if "secret" in cred:
                    cred["secret"] = SECRET_MASK
        if type_ == "Domain":
            name = out.get("name")
            keys = [k for k in self.objects["DkimSignature"].values() if k.get("domainId") == out["id"]]
            zone = [f"{name}. IN MX 10 mail.{name}.", f'{name}. IN TXT "v=spf1 mx -all"', f'_dmarc.{name}. IN TXT "v=DMARC1; p=reject"']
            zone += [f'{k["selector"]}._domainkey.{name}. IN TXT "v=DKIM1; p=KEY"' for k in keys]
            out["dnsZoneFile"] = "\n".join(zone)
        if properties is not None:
            out = {k: v for k, v in out.items() if k in properties or k in ("id", "@type")}
        return out

    def _matches(self, type_: str, obj: dict, filt: dict) -> bool:
        view = self._view(type_, obj, None)
        for key, value in filt.items():
            if key == "text":
                haystack = json.dumps(view, ensure_ascii=False)
                if type_ == "Log":
                    if value not in (view.get("details") or ""):
                        return False
                elif str(value).lower() not in haystack.lower():
                    return False
                continue
            suffix = next((s for s in COMPARE if key.endswith(s)), None)
            if suffix:
                field = key[: -len(suffix)]
                current = view.get(field) or (view.get("nextRetry") if field == "due" else None)
                if current is None:
                    return False
                ok = {
                    "IsGreaterThan": current > value,
                    "IsLessThan": current < value,
                    "IsGreaterThanOrEqual": current >= value,
                    "IsLessThanOrEqual": current <= value,
                }[suffix]
                if not ok:
                    return False
                continue
            if key == "memberGroupIds":
                if not (view.get("memberGroupIds") or {}).get(value):
                    return False
                continue
            if key == "status" and type_ == "Task":
                if (view.get("status") or {}).get("@type") != value:
                    return False
                continue
            if key == "to" and type_ == "QueuedMessage":
                if not any(value in r for r in view.get("recipients") or {}):
                    return False
                continue
            if view.get(key) != value:
                return False
        return True

    # ------------------------------------------------------------ methods

    def _m_get(self, type_: str, args: dict) -> dict:
        store = self.objects[type_]
        ids = args.get("ids")
        if ids is None:
            ids = list(store)
        found = [self._view(type_, store[i], args.get("properties")) for i in ids if i in store]
        return {"list": found, "notFound": [i for i in ids if i not in store] or None, "state": "s1"}

    def _m_query(self, type_: str, args: dict) -> dict:
        if type_ == "Action":
            raise fj._MethodError("invalidArguments", description="Actions cannot be queried")
        filt = args.get("filter") or {}
        if "operator" in filt:
            if filt["operator"] != "AND":
                raise fj._MethodError("unsupportedFilter", description="Only AND is supported in filters")
            merged: dict = {}
            for cond in filt.get("conditions") or []:
                merged.update(cond)
            filt = merged
        if type_ == "Log" and args.get("position"):
            raise fj._MethodError("invalidArguments", description="Pagination is only possible using anchors for logs")
        store = self.objects[type_]
        ids = [i for i, obj in store.items() if self._matches(type_, obj, filt)]
        sort = (args.get("sort") or [{}])[0]
        prop = sort.get("property")
        if prop in ("name", "due", "description"):
            key = (
                (lambda i: store[i].get("nextRetry") or store[i].get("due") or "")
                if prop == "due"
                else (lambda i: store[i].get(prop) or "")
            )
            ids.sort(key=key, reverse=not sort.get("isAscending", False))
        else:
            ids.sort(key=lambda i: int(i.lstrip("o") or 0), reverse=True)
        if args.get("anchor"):
            anchor = args["anchor"]
            if anchor not in ids:
                raise fj._MethodError("anchorNotFound")
            ids = ids[ids.index(anchor) + 1 :]
        position = int(args.get("position") or 0)
        total = len(ids)
        limit = args.get("limit")
        ids = ids[position : position + limit] if limit else ids[position:]
        out = {"ids": ids, "position": position, "queryState": "q1", "canCalculateChanges": False}
        if args.get("calculateTotal"):
            out["total"] = total
        return out

    def _m_set(self, type_: str, args: dict) -> dict:
        created, not_created, updated, not_updated, destroyed, not_destroyed = {}, {}, {}, {}, [], {}
        store = self.objects[type_]
        for cid, obj in (args.get("create") or {}).items():
            if type_ == "Action":
                kind = obj.get("@type")
                if kind not in ACTIONS:
                    not_created[cid] = {"type": "invalidProperties", "properties": ["@type"]}
                    continue
                self.actions.append(copy.deepcopy(obj))
                if kind == "TroubleshootDmarc":
                    created[cid] = {"spfMailFromResult": {"@type": "Pass"}, "dmarcPass": True, "dmarcPolicy": "reject"}
                elif kind == "ClassifySpam":
                    created[cid] = {"score": 1.5, "result": "ham", "tags": {}}
                else:
                    created[cid] = {"id": f"act{len(self.actions)}"}
                continue
            if type_ in ("QueuedMessage", "DmarcExternalReport", "TlsExternalReport", "Log"):
                not_created[cid] = {"type": "forbidden", "description": f"{type_} cannot be created"}
                continue
            missing = [p for p in REQUIRED.get(type_, ()) if not obj.get(p)]
            if missing:
                not_created[cid] = {"type": "validationFailed", "validationErrors": [{"type": "Required", "property": p} for p in missing]}
                continue
            if "domainId" in obj and obj["domainId"] not in self.objects["Domain"]:
                not_created[cid] = {"type": "invalidForeignKey", "objectId": {"object": "Domain", "id": obj["domainId"]}}
                continue
            keys = UNIQUE.get(type_)
            if keys and any(all(o.get(k) == obj.get(k) for k in keys) for o in store.values()):
                not_created[cid] = {"type": "primaryKeyViolation", "properties": list(keys)}
                continue
            oid = self.put(type_, {**obj, "createdAt": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")})
            created[cid] = {"id": oid}
        for oid, patch in (args.get("update") or {}).items():
            if oid not in store:
                not_updated[oid] = {"type": "notFound"}
                continue
            if type_ in ("DmarcExternalReport", "TlsExternalReport"):
                not_updated[oid] = {"type": "forbidden", "description": "External reports cannot be updated"}
                continue
            obj = store[oid]
            for key, value in patch.items():
                if "/" in key:
                    _apply_pointer(obj, key, value)
                elif value is None:
                    obj.pop(key, None)
                else:
                    obj[key] = copy.deepcopy(value)
            updated[oid] = None
        for oid in args.get("destroy") or []:
            if oid not in store:
                not_destroyed[oid] = {"type": "notFound"}
                continue
            if type_ == "Domain":
                linked = [
                    {"object": t, "id": i}
                    for t in ("Account", "MailingList")
                    for i, o in self.objects[t].items()
                    if o.get("domainId") == oid
                ]
                if linked:
                    not_destroyed[oid] = {"type": "objectIsLinked", "linkedObjects": linked}
                    continue
            del store[oid]
            destroyed.append(oid)
        return {
            "created": created or None,
            "notCreated": not_created or None,
            "updated": updated or None,
            "notUpdated": not_updated or None,
            "destroyed": destroyed or None,
            "notDestroyed": not_destroyed or None,
            "oldState": "s1",
            "newState": "s2",
        }
