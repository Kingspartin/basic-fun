import asyncio

import pytest

from enrichment.dispatcher import Dispatcher, ScanSettings
from enrichment.entities import Entity, EntityType, Finding
from enrichment.errors import QuotaExceeded
from enrichment.compliance import InMemoryAuditLog, InMemorySuppressionList
from enrichment.storage import InMemoryStorage

from conftest import make_module

EMAIL, USERNAME, FULL_NAME, DOMAIN, BREACH = (
    EntityType.EMAIL, EntityType.USERNAME, EntityType.FULL_NAME,
    EntityType.DOMAIN, EntityType.BREACH,
)


def finding(t, v, conf=0.8):
    return Finding(entity=Entity(t, v), confidence=conf)


async def test_routes_only_to_watching_modules():
    async def email_h(e):
        return [finding(USERNAME, "found_user")]

    async def domain_h(e):
        return [finding(EMAIL, "should_not_run@x.com")]

    email_m = make_module("email_m", [EMAIL], [USERNAME], email_h)
    domain_m = make_module("domain_m", [DOMAIN], [EMAIL], domain_h)
    d = Dispatcher([email_m, domain_m])
    res = await d.scan(Entity(EMAIL, "a@b.com"), requester_id="r", purpose="test", max_depth=1)
    assert len(email_m.calls) == 1
    assert len(domain_m.calls) == 0  # domain module never sees an email
    assert any(f.entity.value == "found_user" for f in res.findings)


async def test_dedup_same_entity_queried_once():
    seen = []

    async def user_h(e):
        seen.append(e.normalized)
        # two parents both produce the same username
        return []

    async def email_h(e):
        return [finding(USERNAME, "dup"), finding(USERNAME, "DUP")]  # same after normalize

    email_m = make_module("email_m", [EMAIL], [USERNAME], email_h)
    user_m = make_module("user_m", [USERNAME], [], user_h)
    d = Dispatcher([email_m, user_m])
    await d.scan(Entity(EMAIL, "a@b.com"), requester_id="r", purpose="t", max_depth=3)
    assert seen == ["dup"]  # queried exactly once despite two findings


async def test_max_depth_limits_expansion():
    async def a(e):
        return [finding(USERNAME, "u1")]

    async def b(e):
        return [finding(EMAIL, "deep@x.com")]

    m_email = make_module("m_email", [EMAIL], [USERNAME], a)
    m_user = make_module("m_user", [USERNAME], [EMAIL], b)
    d = Dispatcher([m_email, m_user])
    # depth 0 seed(email) -> depth1 username -> would-be depth2 email (blocked)
    res = await d.scan(Entity(EMAIL, "s@x.com"), requester_id="r", purpose="t", max_depth=1)
    values = {f.entity.value for f in res.findings}
    assert "u1" in values
    assert "deep@x.com" in values  # produced as a finding
    # but the deep email is never expanded (m_email only ran on the seed)
    assert len(m_email.calls) == 1


async def test_max_requests_budget():
    async def a(e):
        return [finding(USERNAME, f"u{i}") for i in range(5)]

    async def b(e):
        return []

    m_email = make_module("m_email", [EMAIL], [USERNAME], a)
    m_user = make_module("m_user", [USERNAME], [], b)
    d = Dispatcher([m_email, m_user])
    res = await d.scan(Entity(EMAIL, "s@x.com"), requester_id="r", purpose="t",
                       max_depth=3, max_requests=2)
    assert res.stats["requests_made"] <= 2
    assert len(m_email.calls) + len(m_user.calls) <= 2


async def test_seed_suppressed_aborts_before_query():
    ran = []

    async def h(e):
        ran.append(e)
        return []

    m = make_module("m", [EMAIL], [], h)
    supp = InMemorySuppressionList()
    supp.add(EMAIL, "blocked@x.com")
    audit = InMemoryAuditLog()
    d = Dispatcher([m], suppression=supp, audit=audit)
    res = await d.scan(Entity(EMAIL, "blocked@x.com"), requester_id="r", purpose="t")
    assert res.aborted and res.abort_reason == "seed_suppressed"
    assert ran == []  # no query happened
    assert audit.suppressed and audit.suppressed[0]["stage"] == "seed"


async def test_produced_suppressed_not_stored_or_expanded():
    async def email_h(e):
        return [finding(USERNAME, "ok_user"), finding(USERNAME, "blocked_user")]

    async def user_h(e):
        return []

    email_m = make_module("email_m", [EMAIL], [USERNAME], email_h)
    user_m = make_module("user_m", [USERNAME], [], user_h)
    supp = InMemorySuppressionList()
    supp.add(USERNAME, "blocked_user")
    audit = InMemoryAuditLog()
    d = Dispatcher([email_m, user_m], suppression=supp, audit=audit)
    res = await d.scan(Entity(EMAIL, "a@b.com"), requester_id="r", purpose="t", max_depth=2)
    stored = {f.entity.value for f in res.findings}
    assert "ok_user" in stored
    assert "blocked_user" not in stored  # not stored
    assert [c.normalized for c in user_m.calls] == ["ok_user"]  # not expanded
    assert res.stats["suppressed_entities"] == 1


async def test_audit_records_start_and_end():
    async def h(e):
        return []

    m = make_module("m", [EMAIL], [], h)
    audit = InMemoryAuditLog()
    d = Dispatcher([m], audit=audit)
    res = await d.scan(Entity(EMAIL, "a@b.com"), requester_id="analyst-1",
                       purpose="fraud case 9")
    rec = audit.scans[res.scan_id]
    assert rec["requester_id"] == "analyst-1"
    assert rec["purpose"] == "fraud case 9"
    assert rec["summary"]["findings"] == 0


async def test_module_exception_does_not_abort_scan():
    async def boom(e):
        raise RuntimeError("kaboom")

    async def ok(e):
        return [finding(FULL_NAME, "Jane Doe")]

    bad = make_module("bad", [EMAIL], [], boom)
    good = make_module("good", [EMAIL], [FULL_NAME], ok)
    d = Dispatcher([bad, good])
    res = await d.scan(Entity(EMAIL, "a@b.com"), requester_id="r", purpose="t")
    assert any(f.entity.value == "Jane Doe" for f in res.findings)


async def test_quota_disables_module_for_scan():
    async def multi(e):
        return [finding(EMAIL, "one@x.com"), finding(EMAIL, "two@x.com")]

    async def counted(e):
        return []

    producer = make_module("producer", [USERNAME], [EMAIL], multi)
    limited = make_module("limited", [EMAIL], [], counted, daily_quota=1)
    d = Dispatcher([producer, limited])
    res = await d.scan(Entity(USERNAME, "seed"), requester_id="r", purpose="t", max_depth=2)
    assert len(limited.calls) == 1  # second email blocked by quota
    assert "limited" in res.stats["modules_disabled"]


async def test_quota_exceeded_exception_disables_module():
    state = {"n": 0}

    async def producer_h(e):
        return [finding(EMAIL, f"e{i}@x.com") for i in range(3)]

    async def raiser(e):
        state["n"] += 1
        raise QuotaExceeded("upstream says no")

    producer = make_module("producer", [USERNAME], [EMAIL], producer_h)
    raiser_m = make_module("raiser", [EMAIL], [], raiser)
    # workers=1 so "disable for rest of scan" is observed deterministically; with
    # more workers, calls already in flight when the error fires may still run.
    d = Dispatcher([producer, raiser_m], settings=ScanSettings(workers=1))
    res = await d.scan(Entity(USERNAME, "seed"), requester_id="r", purpose="t", max_depth=2)
    assert state["n"] == 1  # first raises + disables; the other two are skipped
    assert "raiser" in res.stats["modules_disabled"]


async def test_slow_module_times_out_without_blocking():
    async def slow(e):
        await asyncio.sleep(1.0)
        return [finding(FULL_NAME, "late")]

    async def fast(e):
        return [finding(FULL_NAME, "Jane")]

    slow_m = make_module("slow", [EMAIL], [FULL_NAME], slow, timeout_seconds=0.05)
    fast_m = make_module("fast", [EMAIL], [FULL_NAME], fast)
    d = Dispatcher([slow_m, fast_m], settings=ScanSettings(workers=4))
    res = await d.scan(Entity(EMAIL, "a@b.com"), requester_id="r", purpose="t")
    values = {f.entity.value for f in res.findings}
    assert "Jane" in values and "late" not in values
