"""Admin operations against the management extension of the fake (tests/fake_admin.py)."""

from __future__ import annotations

import httpx
import pytest

from stalwart_mcp import admin_ops as ops
from stalwart_mcp import jmap as jmap_module
from stalwart_mcp.config import Config
from stalwart_mcp.credentials import credential_from_headers
from stalwart_mcp.errors import InvalidInput, NotFound, Refused, SetError
from stalwart_mcp.jmap import Jmap, Runtime
from tests import fake_jmap as fj
from tests.fake_admin import MANAGEMENT, FakeStalwartAdmin

ADMIN = "admin@example.com"
TOKEN = "API_admin-token"


@pytest.fixture
def fake(monkeypatch):
    monkeypatch.setitem(fj.CAPABILITIES, MANAGEMENT, {})
    f = FakeStalwartAdmin()
    f.add_account(ADMIN, password="pw", name=ADMIN, tokens=[TOKEN])
    f.domain = f.put("Domain", {"name": "example.com", "dkimManagement": {"@type": "Automatic"}, "dnsManagement": {"@type": "Manual"}})
    f.put("Domain", {"name": "example.org"})
    return f


@pytest.fixture
async def j(fake, monkeypatch):
    monkeypatch.setattr(jmap_module, "RATE_BACKOFF_SECONDS", 0.0)
    http = httpx.AsyncClient(transport=httpx.ASGITransport(app=fake.app), base_url="http://fake", follow_redirects=True)
    rt = Runtime(Config(stalwart_url="http://fake", max_rps=0), http=http)
    yield Jmap(rt, credential_from_headers({"authorization": f"Bearer {TOKEN}"}))
    await rt.aclose()


async def test_admin_info_uses_bearer_and_api_account(j, fake):
    info = await ops.admin_info(j)
    assert info["username"] == ADMIN and info["edition"] == "oss" and info["is_admin"]
    assert "sysAccountGet" in info["management_permissions"]


async def test_account_lifecycle(j, fake):
    group = await ops.create_account(j, "team@example.com", kind="Group", display_name="Team")
    created = await ops.create_account(
        j,
        "jane@example.com",
        display_name="Jane Doe",
        generate_password=True,
        aliases=["j.doe@example.com", "jane@example.org"],
        quota="5 GB",
        groups=["team@example.com"],
        admin=True,
    )
    assert created["password"] and "secure channel" in created["warning"]
    stored = fake.objects["Account"][created["id"]]
    assert stored["roles"] == {"@type": "Admin"} and stored["quotas"] == {"maxDiskQuota": 5_000_000_000}
    assert stored["credentials"]["0"]["secret"] == created["password"]
    assert stored["memberGroupIds"] == {group["id"]: True}

    listed = await ops.list_accounts(j, domain="example.com", kind="User")
    jane = listed["accounts"][0]
    assert jane["address"] == "jane@example.com" and jane["admin"] is True and jane["quota"] == "5.0 GB"
    assert set(jane["aliases"]) == {"j.doe@example.com", "jane@example.org"} and jane["groups"] == ["team@example.com"]

    detail = await ops.get_account(j, "jane@example.com")
    assert detail["credentials"] == [{"key": "0", "type": "Password"}]
    assert created["password"] not in str(detail)

    upd = await ops.update_account(
        j,
        "jane@example.com",
        remove_aliases=["jane@example.org"],
        add_aliases=["info@example.com"],
        quota="none",
        admin=False,
        enabled=False,
        reset_password=True,
    )
    stored = fake.objects["Account"][created["id"]]
    assert {a["name"] for a in stored["aliases"].values()} == {"j.doe", "info"}
    assert "maxDiskQuota" not in stored.get("quotas", {})
    assert stored["roles"] == {"@type": "User"}
    assert stored["permissions"]["disabledPermissions"] == {"authenticate": True}
    assert stored["credentials"]["0"]["secret"] == upd["password"] != created["password"]
    assert (await ops.list_accounts(j, text="jane"))["accounts"][0]["disabled"] is True

    await ops.update_account(j, "jane@example.com", enabled=True)
    assert fake.objects["Account"][created["id"]]["permissions"] == {"@type": "Inherit"}

    with pytest.raises(Refused):
        await ops.delete_account(j, "jane@example.com", confirm_address="john@example.com")
    assert (await ops.delete_account(j, "jane@example.com", confirm_address="JANE@example.com"))["deleted"] == "jane@example.com"
    with pytest.raises(NotFound):
        await ops.get_account(j, "jane@example.com")


async def test_account_input_errors(j, fake):
    with pytest.raises(NotFound):
        await ops.create_account(j, "x@unknown.example")
    with pytest.raises(InvalidInput):
        await ops.create_account(j, "team@example.com", kind="Group", generate_password=True)
    await ops.create_account(j, "dup@example.com")
    with pytest.raises(SetError) as err:
        await ops.create_account(j, "dup@example.com")
    assert next(iter(err.value.details.values()))["type"] == "primaryKeyViolation"


async def test_domains_and_dns(j, fake):
    fake.put(
        "DkimSignature", {"@type": "Dkim1Ed25519Sha256", "domainId": fake.domain, "selector": "v1-ed25519-20261002", "stage": "active"}
    )
    domains = await ops.list_domains(j, include_dkim=True)
    names = [d["name"] for d in domains["domains"]]
    assert names == ["example.com", "example.org"]
    assert domains["domains"][0]["dkim_keys"][0]["selector"] == "v1-ed25519-20261002"
    dns = await ops.get_domain_dns(j, "example.com")
    assert "_domainkey" in dns["zone"] and "MX" in dns["zone"]
    new = await ops.create_domain(j, "example.net")
    assert fake.objects["Domain"][new["id"]]["dkimManagement"] == {"@type": "Automatic"}
    await ops.create_account(j, "x@example.net")
    with pytest.raises(SetError) as err:
        await ops.delete_domain(j, "example.net", confirm_name="example.net")
    assert next(iter(err.value.details.values()))["type"] == "objectIsLinked"
    with pytest.raises(Refused):
        await ops.delete_domain(j, "example.org", confirm_name="example.de")


async def test_mailing_lists(j, fake):
    await ops.manage_mailing_list(j, "create", "crew@example.com", add_recipients=["a@x.org"], description="Crew")
    await ops.manage_mailing_list(j, "update", "crew@example.com", add_recipients=["b/c@x.org"], remove_recipients=["a@x.org"])
    lists = await ops.list_mailing_lists(j)
    assert lists["lists"][0]["recipients"] == ["b/c@x.org"]
    with pytest.raises(Refused):
        await ops.manage_mailing_list(j, "delete", "crew@example.com")
    assert (await ops.manage_mailing_list(j, "delete", "crew@example.com", confirm_address="crew@example.com"))["deleted"]


async def test_queue(j, fake):
    q1 = fake.put(
        "QueuedMessage",
        {
            "returnPath": "jane@example.com",
            "size": 1200,
            "nextRetry": "2026-10-02T12:00:00Z",
            "recipients": {
                "bob@ext.org": {
                    "status": {"@type": "TemporaryFailure", "errorType": "connectionError", "errorMessage": "timed out"},
                    "retryCount": 3,
                },
                "carol@ext.org": {"status": {"@type": "Scheduled"}},
            },
        },
    )
    fake.put("QueuedMessage", {"returnPath": "other@example.com", "nextRetry": "2026-10-02T11:00:00Z", "recipients": {}})
    queue = await ops.list_queue(j)
    assert [m["id"] for m in queue["messages"]][-1] == q1  # next due first
    stuck = (await ops.list_queue(j, recipient="bob@ext.org"))["messages"][0]
    assert stuck["recipients"][0]["error"] == "connectionError" and stuck["recipients"][0]["retries"] == 3
    await ops.queue_action(j, "retry_now", ids=[q1])
    assert fake.objects["QueuedMessage"][q1]["nextRetry"] == ops.RETRY_NOW
    await ops.queue_action(j, "cancel", ids=[q1], recipient="bob@ext.org")
    assert "bob@ext.org" not in fake.objects["QueuedMessage"][q1]["recipients"]
    await ops.queue_action(j, "pause")
    assert fake.actions[-1] == {"@type": "PauseMtaQueue"}
    await ops.queue_action(j, "cancel", ids=[q1])
    assert q1 not in fake.objects["QueuedMessage"]


async def test_ip_lists_reload(j, fake):
    fake.put("BlockedIp", {"address": "198.51.100.7", "reason": "authFailure", "expiresAt": "2026-10-02T13:00:00Z"})
    ips = await ops.list_ips(j)
    assert ips["blocked"][0]["reason"] == "authFailure" and ips["allowed"] == []
    await ops.manage_ip(j, "unblock", "198.51.100.7")
    assert fake.objects["BlockedIp"] == {} and fake.actions[-1] == {"@type": "ReloadBlockedIps"}
    await ops.manage_ip(j, "allow", "203.0.113.10", reason="MCP hub", expires="2027-01-01")
    allowed = next(iter(fake.objects["AllowedIp"].values()))
    assert allowed["reason"] == "MCP hub" and allowed["expiresAt"] == "2027-01-01T00:00:00Z"
    assert fake.actions[-1] == {"@type": "ReloadSettings"}
    with pytest.raises(NotFound):
        await ops.manage_ip(j, "unallow", "1.2.3.4")


async def test_reports_summary(j, fake):
    fake.put(
        "DmarcExternalReport",
        {
            "receivedAt": "2026-10-01T06:00:00Z",
            "report": {
                "orgName": "google.com",
                "policyDomain": "example.com",
                "policyDisposition": "quarantine",
                "dateRangeBegin": "2026-09-30T00:00:00Z",
                "dateRangeEnd": "2026-10-01T00:00:00Z",
                "records": {
                    "0": {"sourceIp": "203.0.113.10", "count": 40, "evaluatedDkim": "pass", "evaluatedSpf": "pass"},
                    "1": {
                        "sourceIp": "203.0.113.9",
                        "count": 3,
                        "evaluatedDkim": "fail",
                        "evaluatedSpf": "fail",
                        "headerFrom": "example.com",
                        "evaluatedDisposition": "quarantine",
                    },
                },
            },
        },
    )
    reports = await ops.list_reports(j, "dmarc", domain="example.com")
    rep = reports["reports"][0]
    assert rep["messages"] == 43 and rep["dmarc_fail"] == 3 and rep["failing_sources"][0]["ip"] == "203.0.113.9"
    assert (await ops.list_reports(j, "dmarc", since="2026-10-02"))["count"] == 0
    with pytest.raises(InvalidInput):
        await ops.list_reports(j, "arf")


async def test_logs_anchor_paging(j, fake):
    for n in range(5):
        fake.put(
            "Log",
            {
                "timestamp": f"2026-10-02T10:0{n}:00Z",
                "level": "warn",
                "event": "auth.failed",
                "details": f"\x1b[31m(auth.failed)\x1b[0m login failed from 198.51.100.{n}",
            },
        )
    first = await ops.search_logs(j, "(auth.failed)", limit=2)
    assert first["count"] == 2 and "\x1b" not in first["entries"][0]["details"]
    rest = await ops.search_logs(j, "(auth.failed)", limit=10, anchor=first["next_anchor"])
    assert rest["count"] == 3


async def test_tasks_actions_diagnose_generic(j, fake):
    fake.put(
        "Task",
        {
            "@type": "DnsManagement",
            "domainId": fake.domain,
            "status": {"@type": "Failed", "failureReason": "DNS provider rejected"},
            "due": "2026-10-01T00:00:00Z",
        },
    )
    failed = await ops.list_tasks(j, failed_only=True)
    assert failed["tasks"][0]["failure"] == "DNS provider rejected"
    await ops.run_task(j, "SpamFilterMaintenance", maintenance="train")
    await ops.run_task(j, "DkimManagement", domain="example.com")
    types = [t["@type"] for t in fake.objects["Task"].values()]
    assert "SpamFilterMaintenance" in types and "DkimManagement" in types
    await ops.run_action(j, "ReloadSettings")
    with pytest.raises(InvalidInput):
        await ops.run_action(j, "UpdateApps")
    dmarc = await ops.diagnose(j, "dmarc", remote_ip="203.0.113.5", ehlo_domain="mx.ext.org", mail_from="news@ext.org")
    assert dmarc["dmarcPass"] is True
    assert fake.actions[-1]["spfMailFromDomain"] == "ext.org"
    route = await ops.set_object(
        j, "MtaRoute", create={"r": {"@type": "Relay", "name": "relay", "address": "smtp.relay.example"}}, reload=True
    )
    assert route["created"]["r"]["id"] and fake.actions[-1] == {"@type": "ReloadSettings"}
    got = await ops.query_objects(j, "MtaRoute", filter={"name": "relay"})
    assert got["objects"][0]["address"] == "smtp.relay.example"
    with pytest.raises(InvalidInput):
        await ops.query_objects(j, "x:../evil")


async def test_or_filters_are_rejected_by_server(j, fake):
    from stalwart_mcp.errors import MethodError

    with pytest.raises(MethodError) as err:
        await ops.mquery(j, "Account", filter={"operator": "OR", "conditions": [{"name": "a"}, {"name": "b"}]})
    assert err.value.type == "unsupportedFilter"
