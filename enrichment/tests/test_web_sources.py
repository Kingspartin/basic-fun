import httpx

from enrichment.entities import Entity, EntityType
from enrichment.modules.base import ModuleConfig
from enrichment.modules.web_sources import (CrtShModule, GitLabModule, HackerNewsModule,
                                            KeybaseModule, WaybackModule, WikipediaModule)

from conftest import http_for

DOMAIN, URL, FULL_NAME, LOCATION, ACCOUNT, EMAIL, USERNAME = (
    EntityType.DOMAIN, EntityType.URL, EntityType.FULL_NAME, EntityType.LOCATION,
    EntityType.ACCOUNT, EntityType.EMAIL, EntityType.USERNAME,
)


async def test_crtsh_extracts_subdomains():
    def handler(req):
        return httpx.Response(200, json=[
            {"name_value": "mail.example.com\n*.example.com"},
            {"name_value": "api.example.com"},
            {"name_value": "example.com"},          # apex, excluded
            {"name_value": "other.org"},            # different domain, excluded
        ])
    m = CrtShModule(ModuleConfig(), http_for(handler))
    out = await m.handle(Entity(DOMAIN, "example.com"))
    vals = {f.entity.value for f in out}
    assert vals == {"mail.example.com", "api.example.com"}


async def test_wayback_latest_snapshot():
    def handler(req):
        return httpx.Response(200, json={"archived_snapshots": {"closest": {
            "url": "http://web.archive.org/web/20200101/https://example.com/",
            "timestamp": "20200101000000"}}})
    m = WaybackModule(ModuleConfig(), http_for(handler))
    out = await m.handle(Entity(DOMAIN, "example.com"))
    assert out and out[0].entity.type == URL and "web.archive.org" in out[0].entity.value


async def test_keybase_proof_graph():
    def handler(req):
        return httpx.Response(200, json={"them": [{
            "profile": {"full_name": "Jane Doe", "location": "Seattle"},
            "proofs_summary": {"all": [
                {"proof_type": "twitter", "nametag": "janedoe", "service_url": "https://twitter.com/janedoe"},
                {"proof_type": "github", "nametag": "janedoe"},
                {"proof_type": "dns", "nametag": "jane.dev"},
            ]}}]})
    m = KeybaseModule(ModuleConfig(), http_for(handler))
    out = await m.handle(Entity(USERNAME, "janedoe"))
    vals = {(f.entity.type, f.entity.value) for f in out}
    assert (FULL_NAME, "Jane Doe") in vals
    assert (LOCATION, "Seattle") in vals
    assert (ACCOUNT, "twitter:janedoe") in vals
    assert (ACCOUNT, "github:janedoe") in vals
    assert (DOMAIN, "jane.dev") in vals


async def test_gitlab_profile():
    def handler(req):
        return httpx.Response(200, json=[{"name": "Jane Doe", "web_url": "https://gitlab.com/janedoe"}])
    m = GitLabModule(ModuleConfig(), http_for(handler))
    out = await m.handle(Entity(USERNAME, "janedoe"))
    vals = {(f.entity.type, f.entity.value) for f in out}
    assert (FULL_NAME, "Jane Doe") in vals and (URL, "https://gitlab.com/janedoe") in vals


async def test_hackernews_extracts_email_and_url_from_about():
    def handler(req):
        return httpx.Response(200, json={"about": "reach me at jane@x.com or https://jane.dev"})
    m = HackerNewsModule(ModuleConfig(), http_for(handler))
    out = await m.handle(Entity(USERNAME, "janedoe"))
    vals = {(f.entity.type, f.entity.value) for f in out}
    assert (EMAIL, "jane@x.com") in vals and (URL, "https://jane.dev") in vals


async def test_wikipedia_search_titles():
    def handler(req):
        return httpx.Response(200, json={"query": {"search": [
            {"title": "Jane Doe"}, {"title": "John Doe"}]}})
    m = WikipediaModule(ModuleConfig(), http_for(handler))
    out = await m.handle(Entity(FULL_NAME, "Jane Doe"))
    assert any("Jane_Doe" in f.entity.value for f in out)
    assert all(f.entity.type == URL for f in out)
