"""Module parsing tests against mocked official-API responses."""
import httpx
import pytest

from enrichment.entities import Entity, EntityType
from enrichment.errors import ConfigurationError, RateLimited
from enrichment.modules.base import ModuleConfig
from enrichment.modules.dns_rdap import DnsRdapModule
from enrichment.modules.gravatar_github import GitHubModule, GravatarModule
from enrichment.modules.hibp import HaveIBeenPwnedModule
from enrichment.modules.hunter import HunterModule

from conftest import http_for


async def test_hibp_parses_breaches_and_sends_key():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["key"] = req.headers.get("hibp-api-key")
        seen["path"] = req.url.path
        return httpx.Response(200, json=[
            {"Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com",
             "BreachDate": "2013-10-04", "PwnCount": 1, "DataClasses": ["Emails"], "IsVerified": True},
        ])

    m = HaveIBeenPwnedModule(ModuleConfig(api_key="secret"), http_for(handler))
    out = await m.handle(Entity(EntityType.EMAIL, "a@b.com"))
    assert seen["key"] == "secret"
    assert "breachedaccount/a@b.com" in seen["path"]
    assert len(out) == 1 and out[0].entity.type == EntityType.BREACH
    assert out[0].entity.value == "Adobe" and out[0].confidence > 0.9


async def test_hibp_404_is_empty_not_error():
    def handler(req):
        return httpx.Response(404)

    m = HaveIBeenPwnedModule(ModuleConfig(api_key="k"), http_for(handler))
    assert await m.handle(Entity(EntityType.EMAIL, "a@b.com")) == []


async def test_hibp_requires_api_key():
    with pytest.raises(ConfigurationError):
        HaveIBeenPwnedModule(ModuleConfig(api_key=None), http_for(lambda r: httpx.Response(200)))


async def test_hunter_parses_emails_names_org():
    def handler(req):
        assert req.url.params.get("domain") == "acme.com"
        return httpx.Response(200, json={"data": {
            "organization": "Acme Inc",
            "emails": [
                {"value": "jane@acme.com", "confidence": 92, "first_name": "Jane",
                 "last_name": "Doe", "position": "CTO", "type": "personal"},
                {"value": "info@acme.com", "confidence": 40, "type": "generic"},
            ],
        }})

    m = HunterModule(ModuleConfig(api_key="k"), http_for(handler))
    out = await m.handle(Entity(EntityType.DOMAIN, "acme.com"))
    types = [(f.entity.type, f.entity.value) for f in out]
    assert (EntityType.ORGANIZATION, "Acme Inc") in types
    assert (EntityType.EMAIL, "jane@acme.com") in types
    assert (EntityType.FULL_NAME, "Jane Doe") in types
    jane = next(f for f in out if f.entity.value == "jane@acme.com")
    assert jane.confidence == pytest.approx(0.92, abs=0.01)


async def test_dns_rdap_parses_mx_and_registrar():
    def handler(req: httpx.Request) -> httpx.Response:
        if "dns.google" in req.url.host:
            return httpx.Response(200, json={"Answer": [
                {"type": 15, "data": "10 mx1.acme.com."},
                {"type": 15, "data": "20 mx2.acme.com."},
            ]})
        # rdap.org
        return httpx.Response(200, json={
            "events": [{"eventAction": "registration", "eventDate": "2001-01-01T00:00:00Z"}],
            "status": ["client transfer prohibited"],
            "entities": [
                {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "NiceRegistrar LLC"]]]},
                {"roles": ["registrant"], "vcardArray": ["vcard", [
                    ["fn", {}, "text", "Acme Holdings"],
                    ["email", {}, "text", "admin@acme.com"]]]},
            ],
        })

    m = DnsRdapModule(ModuleConfig(), http_for(handler))
    out = await m.handle(Entity(EntityType.DOMAIN, "acme.com"))
    vals = {(f.entity.type, f.entity.value) for f in out}
    assert (EntityType.DOMAIN, "mx1.acme.com") in vals
    assert (EntityType.ORGANIZATION, "Acme Holdings") in vals
    assert (EntityType.EMAIL, "admin@acme.com") in vals


async def test_github_username_profile():
    def handler(req):
        return httpx.Response(200, json={
            "name": "Jane Doe", "location": "Seattle, WA", "company": "@acme",
            "blog": "https://jane.dev", "email": "jane@jane.dev",
            "twitter_username": "janedoe", "avatar_url": "https://avatars/x.png",
        })

    m = GitHubModule(ModuleConfig(), http_for(handler))
    out = await m.handle(Entity(EntityType.USERNAME, "janedoe"))
    vals = {(f.entity.type, f.entity.value) for f in out}
    assert (EntityType.FULL_NAME, "Jane Doe") in vals
    assert (EntityType.ORGANIZATION, "acme") in vals  # @ stripped
    assert (EntityType.EMAIL, "jane@jane.dev") in vals
    assert (EntityType.ACCOUNT, "twitter:janedoe") in vals


async def test_github_primary_rate_limit_raises():
    def handler(req):
        return httpx.Response(403, headers={"X-RateLimit-Remaining": "0",
                                            "X-RateLimit-Reset": "0"}, json={"message": "rate limit"})

    m = GitHubModule(ModuleConfig(), http_for(handler))
    with pytest.raises(RateLimited):
        await m.handle(Entity(EntityType.USERNAME, "janedoe"))


async def test_github_email_search_emits_username():
    def handler(req):
        return httpx.Response(200, json={"items": [{"login": "janedoe", "html_url": "https://github.com/janedoe"}]})

    m = GitHubModule(ModuleConfig(), http_for(handler))
    out = await m.handle(Entity(EntityType.EMAIL, "jane@x.com"))
    assert out and out[0].entity.type == EntityType.USERNAME and out[0].entity.value == "janedoe"


async def test_gravatar_parses_profile():
    def handler(req):
        return httpx.Response(200, json={"entry": [{
            "displayName": "Jane", "thumbnailUrl": "https://gravatar/x",
            "urls": [{"value": "https://jane.dev", "title": "Home"}],
            "accounts": [{"shortname": "github", "username": "janedoe", "url": "https://github.com/janedoe"}],
        }]})

    m = GravatarModule(ModuleConfig(), http_for(handler))
    out = await m.handle(Entity(EntityType.EMAIL, "jane@x.com"))
    vals = {(f.entity.type, f.entity.value) for f in out}
    assert (EntityType.FULL_NAME, "Jane") in vals
    assert (EntityType.IMAGE, "https://gravatar/x") in vals
    assert (EntityType.ACCOUNT, "github:janedoe") in vals


async def test_gravatar_404_empty():
    m = GravatarModule(ModuleConfig(), http_for(lambda r: httpx.Response(404)))
    assert await m.handle(Entity(EntityType.EMAIL, "none@x.com")) == []
