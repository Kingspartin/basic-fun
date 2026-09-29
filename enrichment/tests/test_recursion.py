"""Recursive expansion: whatever a module finds is itself looked up further."""
from enrichment.dispatcher import Dispatcher, ScanSettings
from enrichment.entities import Entity, EntityType, Finding
from enrichment.modules.base import ModuleConfig
from enrichment.modules.pivots import AccountPivotModule

from conftest import make_module

NAME, EMAIL, USERNAME, ACCOUNT, BREACH = (
    EntityType.FULL_NAME, EntityType.EMAIL, EntityType.USERNAME,
    EntityType.ACCOUNT, EntityType.BREACH,
)


async def test_name_finds_two_emails_and_each_is_looked_up():
    # Module A: a name -> two emails. Module B: any email -> a distinct breach.
    async def name_to_emails(e):
        return [Finding(entity=Entity(EMAIL, "a@x.com"), confidence=0.7),
                Finding(entity=Entity(EMAIL, "b@x.com"), confidence=0.7)]

    looked_up = []

    async def email_lookup(e):
        looked_up.append(e.normalized)
        return [Finding(entity=Entity(BREACH, f"breach-of-{e.normalized}"), confidence=0.9)]

    m_name = make_module("name_src", [NAME], [EMAIL], name_to_emails)
    m_email = make_module("email_src", [EMAIL], [BREACH], email_lookup)
    d = Dispatcher([m_name, m_email])
    res = await d.scan(Entity(NAME, "Jane Doe"), requester_id="r", purpose="t", max_depth=3)

    # Both discovered emails were independently looked up...
    assert sorted(looked_up) == ["a@x.com", "b@x.com"]
    # ...and each produced its own downstream finding.
    breaches = {f.entity.value for f in res.findings if f.entity.type == BREACH}
    assert breaches == {"breach-of-a@x.com", "breach-of-b@x.com"}


async def test_account_pivot_turns_discovered_account_into_username_lookup():
    # gravatar-like module: email -> a linked github account.
    async def email_to_account(e):
        return [Finding(entity=Entity(ACCOUNT, "github:janedoe"), confidence=0.7)]

    seen_usernames = []

    async def username_lookup(e):
        seen_usernames.append(e.normalized)
        return [Finding(entity=Entity(EntityType.FULL_NAME, "Jane Doe"), confidence=0.7)]

    m_email = make_module("grav", [EMAIL], [ACCOUNT], email_to_account)
    acct_pivot = AccountPivotModule(ModuleConfig(requests_per_second=1000), http=None)
    m_user = make_module("gh", [USERNAME], [EntityType.FULL_NAME], username_lookup)
    d = Dispatcher([m_email, acct_pivot, m_user])
    res = await d.scan(Entity(EMAIL, "jane@x.com"), requester_id="r", purpose="t", max_depth=4)

    # The discovered account handle was pivoted to a username and looked up.
    assert "janedoe" in seen_usernames
    assert any(f.entity.value == "Jane Doe" for f in res.findings)


async def test_expansion_respects_depth_but_still_branches():
    # Chain: seed username -> email -> username2 -> email2 ...
    async def u_to_email(e):
        return [Finding(entity=Entity(EMAIL, f"{e.normalized}@x.com"), confidence=0.6)]

    async def email_to_u(e):
        base = e.normalized.split("@")[0]
        return [Finding(entity=Entity(USERNAME, base + "x"), confidence=0.6)]

    m_u = make_module("u", [USERNAME], [EMAIL], u_to_email)
    m_e = make_module("e", [EMAIL], [USERNAME], email_to_u)
    d = Dispatcher([m_u, m_e], settings=ScanSettings(workers=2))
    res = await d.scan(Entity(USERNAME, "a"), requester_id="r", purpose="t", max_depth=2)
    # Processed: a(d0) -> a@x.com(d1) -> ax(d2). The d2 entity's finding (ax@x.com)
    # is still recorded, but it is not expanded (max depth reached).
    emails = {f.entity.value for f in res.findings if f.entity.type == EMAIL}
    users = {f.entity.value for f in res.findings if f.entity.type == USERNAME}
    assert "a@x.com" in emails and "ax" in users
    assert "ax@x.com" in emails               # boundary finding is recorded
    assert "a@x.com" in [c.normalized for c in m_e.calls]  # was looked up
    assert "ax@x.com" not in [c.normalized for c in m_e.calls]  # not expanded further
    assert "axx" not in users                 # so no deeper username appears
