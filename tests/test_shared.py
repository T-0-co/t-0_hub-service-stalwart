"""Mailboxes shared with the login: ACL grants, account='*', drafts and owner-only refusals."""

from __future__ import annotations

import pytest

from stalwart_mcp import ops
from stalwart_mcp.credentials import credential_from_headers
from stalwart_mcp.errors import InvalidInput, NotFound, Refused
from stalwart_mcp.jmap import Jmap
from tests.conftest import USER

TEAM = "hallo@team.example"
TEAM_PASSWORD = "team-pass"
CUSTOMER = ("Carla Customer", "carla@customer.example")


@pytest.fixture
def team(fake):
    acc = fake.add_account(TEAM, password=TEAM_PASSWORD, name=TEAM)
    fake.add_identity(acc, TEAM, "Team")
    fake.team_id = acc  # type: ignore[attr-defined]
    return acc


@pytest.fixture
def owner(runtime, team) -> Jmap:
    return Jmap(runtime, credential_from_headers({"authorization": f"Bearer {TEAM}:{TEAM_PASSWORD}"}))


def seed(fake, team):
    fake.add_email(fake.acc_id, subject="own old", from_=CUSTOMER, to=[("Me", USER)], text="a", received_at="2026-09-01T08:00:00Z")
    fake.add_email(fake.acc_id, subject="own new", from_=CUSTOMER, to=[("Me", USER)], text="b", received_at="2026-09-03T08:00:00Z")
    return fake.add_email(
        team,
        subject="Order question",
        from_=CUSTOMER,
        to=[("Info", "info@team.example")],
        text="Where is my order?",
        received_at="2026-09-02T08:00:00Z",
        message_id="q1@customer.example",
    )


async def grant(owner: Jmap, level: str = "edit") -> dict:
    return await ops.share_mailbox(owner, "grant", with_user=USER, level=level, confirm=True)


async def test_grant_needs_confirm_and_lists_shares(fake, team, owner, j):
    with pytest.raises(Refused) as exc:
        await ops.share_mailbox(owner, "grant", with_user=USER)
    assert exc.value.details["user"] == USER and "Inbox" in exc.value.details["mailboxes"]
    assert not any(fake.account(team).mailboxes[m]["shareWith"] for m in fake.account(team).mailboxes)

    res = await grant(owner)
    assert res["granted"] == len(fake.account(team).mailboxes)
    listed = await ops.share_mailbox(owner, "list")
    assert set(listed["shared_with"][USER].values()) == {"edit"}

    info = await ops.account_info(j)
    shared = next(a for a in info["accounts"] if a["name"] == TEAM)
    assert shared["shared"] is True and shared["can_send"] is False

    in_shared = await ops.account_info(j, account=TEAM)
    assert "shared_mailbox" in in_shared and "identities" not in in_shared and "notes" not in in_shared


async def test_grant_rejects_unknown_user_and_self(owner):
    with pytest.raises(NotFound):
        await ops.share_mailbox(owner, "grant", with_user="nobody@nowhere.example", confirm=True)
    with pytest.raises(InvalidInput):
        await ops.share_mailbox(owner, "grant", with_user=TEAM, confirm=True)


async def test_read_level_is_read_only(fake, team, owner, j):
    eid = seed(fake, team)
    await grant(owner, level="read")
    assert (await ops.read_email(j, eid, account=TEAM))["emails"][0]["subject"] == "Order question"
    with pytest.raises(Exception):  # noqa: B017 - accountReadOnly surfaces as a method error
        await ops.set_flags(j, [eid], seen=True, account=TEAM)


async def test_revoke_removes_access(fake, team, owner, j):
    await grant(owner)
    res = await ops.share_mailbox(owner, "revoke", with_user=USER)
    assert res["revoked"] == len(fake.account(team).mailboxes)
    assert (await ops.share_mailbox(owner, "list")).get("shared_with") is None
    again = await ops.share_mailbox(owner, "revoke", with_user=USER)
    assert again["revoked"] == 0


async def test_sharing_a_shared_mailbox_is_refused(team, owner, j):
    await grant(owner)
    with pytest.raises(Refused):
        await ops.share_mailbox(j, "list", account=TEAM)


async def test_search_all_accounts_merges_newest_first(fake, team, owner, j):
    seed(fake, team)
    await grant(owner)
    res = await ops.search_emails(j, account="*", detail="subjects", limit=2)
    assert [(r["account"], r["subject"]) for r in res["emails"]] == [(USER, "own new"), (TEAM, "Order question")]
    assert res["accounts"] == {USER: 2, TEAM: 1} and res["total"] == 3 and res["next_position"] == 2
    page2 = await ops.search_emails(j, account="*", detail="subjects", limit=2, position=2)
    assert [r["subject"] for r in page2["emails"]] == ["own old"] and "next_position" not in page2

    only_team = await ops.search_emails(j, account="*", text="order")
    assert [r["account"] for r in only_team["emails"]] == [TEAM]


async def test_search_all_accounts_skips_accounts_without_the_folder(fake, team, owner, j):
    seed(fake, team)
    fake.add_mailbox(team, "Orders")
    await grant(owner)
    res = await ops.search_emails(j, account="*", mailbox="Orders")
    assert res["skipped"] and USER in res["skipped"] and res["accounts"] == {TEAM: 0}
    with pytest.raises(InvalidInput):
        await ops.search_emails(j, account="*", limit=150, position=100)


async def test_changes_all_accounts(fake, team, owner, j):
    start = await ops.list_changes(j, account="*")
    assert start["state"].startswith("*:") and start["accounts"] == [USER]

    await grant(owner)
    eid = seed(fake, team)
    later = await ops.list_changes(j, since_state=start["state"])
    assert any("new in this login" in n for n in later["notes"])
    assert {r["account"] for r in later["created"]} == {USER}  # the team account starts from now

    fake.add_email(team, subject="Second question", from_=CUSTOMER, to=[("Info", "info@team.example")], text="?")
    await ops.delete_emails(j, [eid], permanent=False, account=TEAM)
    third = await ops.list_changes(j, since_state=later["state"])
    assert [(r["account"], r["subject"]) for r in third["created"]] == [(TEAM, "Second question")]
    assert TEAM in {r["account"] for r in third["updated"]}

    with pytest.raises(InvalidInput):
        await ops.list_changes(j, since_state="*:broken")


async def test_reply_draft_in_shared_mailbox(fake, team, owner, j):
    eid = seed(fake, team)
    await grant(owner)
    draft = await ops.write_email(j, mode="reply", email_id=eid, body="On its way.", account=TEAM)
    assert draft["from"] == "info@team.example" and draft["to"] == ["Carla Customer <carla@customer.example>"]
    assert "cannot send" in draft["next"] and draft["account"] == TEAM
    stored = fake.email(team, draft["draft_id"])
    assert fake.mailbox_id(team, "drafts") in stored["mailboxIds"]

    with pytest.raises(Refused) as exc:
        await ops.send_email(j, draft["draft_id"], ["carla@customer.example"], account=TEAM)
    assert "shared mailbox" in exc.value.message
    assert fake.outbox == []


async def test_new_draft_in_shared_mailbox_defaults_to_account_address(team, owner, j):
    await grant(owner)
    draft = await ops.write_email(j, to=["x@y.example"], subject="Hi", body="Hello", account=TEAM)
    assert draft["from"] == TEAM
    explicit = await ops.write_email(j, to=["x@y.example"], body="Hello", from_email="Info <info@team.example>", account=TEAM)
    assert explicit["from"] == "info@team.example"


@pytest.mark.parametrize(
    "call",
    [
        lambda j: ops.list_filters(j, account=TEAM),
        lambda j: ops.save_filter(j, "x", "keep;", account=TEAM),
        lambda j: ops.delete_filter(j, "x", account=TEAM),
        lambda j: ops.set_vacation(j, enabled=True, account=TEAM),
    ],
)
async def test_owner_only_actions_are_refused_in_shared_mailbox(team, owner, j, call):
    await grant(owner)
    with pytest.raises(Refused):
        await call(j)


async def test_newly_shared_account_is_found_despite_cached_session(fake, team, owner, j):
    eid = seed(fake, team)
    await ops.account_info(j)  # caches a session without the team account
    await grant(owner)
    res = await ops.read_email(j, eid, account=TEAM)
    assert res["emails"][0]["id"] == eid
