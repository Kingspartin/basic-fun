"""End-to-end 'gather everything' tests: seed detection, full scan, dossier."""
import httpx

from enrichment.entities import Entity, EntityType
from enrichment.gather import detect_seed, run
from enrichment.http import HttpClient
from enrichment.reporting import build_dossier, dossier_markdown

from conftest import make_module
from enrichment.dispatcher import Dispatcher
from enrichment.entities import Finding


def test_detect_seed_types():
    assert detect_seed("jane@example.com").type == EntityType.EMAIL
    assert detect_seed("8.8.8.8").type == EntityType.IP_ADDRESS
    assert detect_seed("example.com").type == EntityType.DOMAIN
    assert detect_seed("https://example.com/x").type == EntityType.URL
    assert detect_seed("@janedoe").type == EntityType.USERNAME
    assert detect_seed("janedoe88").type == EntityType.USERNAME
    assert detect_seed("Jane Q Doe").type == EntityType.FULL_NAME
    assert detect_seed("anything", "domain").type == EntityType.DOMAIN


def _mock_http() -> HttpClient:
    """A transport that answers every enabled keyless provider for an email seed."""
    def handler(req: httpx.Request) -> httpx.Response:
        h, path = req.url.host, req.url.path
        cors = {"access-control-allow-origin": "*"}
        def j(status, body):
            return httpx.Response(status, json=body, headers=cors)
        if "dns.google" in h:
            typ = req.url.params.get("type")
            if typ == "MX":
                return j(200, {"Answer": [{"type": 15, "data": "10 aspmx.l.google.com."}]})
            if typ == "A":
                return j(200, {"Answer": [{"type": 1, "data": "93.184.216.34"}]})
            return j(200, {"Answer": []})
        if "gravatar.com" in h:
            return j(200, {"entry": [{"displayName": "Jane Doe",
                                      "accounts": [{"shortname": "github", "username": "janedoe"}]}]})
        if "api.github.com" in h and "/search/" in path:
            return j(200, {"items": [{"login": "janedoe"}]})
        if "api.github.com" in h and "/users/" in path:
            return j(200, {"name": "Jane Doe", "company": "@acme", "location": "Seattle, WA",
                           "blog": "https://jane.dev"})
        if "keybase.io" in h:
            return j(200, {"them": [{"profile": {"full_name": "Jane Doe"},
                                     "proofs_summary": {"all": [{"proof_type": "twitter", "nametag": "janedoe"}]}}]})
        if "gitlab.com" in h:
            return j(200, [{"name": "Jane Doe", "web_url": "https://gitlab.com/janedoe"}])
        if "hacker-news" in h:
            return j(200, None)
        if "internetdb.shodan.io" in h:
            return j(200, {"ip": "93.184.216.34", "ports": [443], "hostnames": [],
                           "cpes": [], "vulns": ["CVE-2020-0001"]})
        if "crt.sh" in h:
            return j(200, [{"name_value": "api.jane.dev"}])
        if "archive.org" in h:
            return j(200, {"archived_snapshots": {}})
        if "nominatim" in h:
            return j(200, [{"lat": "47.6", "lon": "-122.3", "display_name": "Seattle", "importance": 0.6}])
        if "en.wikipedia.org" in h:
            return j(200, {"query": {"search": []}})
        if "rdap.org" in h:
            return j(200, {"entities": []})
        return httpx.Response(404, headers=cors)
    return HttpClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)),
                      base_backoff=0.001, max_backoff=0.01)


async def test_gather_email_builds_rich_dossier():
    # Speed: bump every module's rate so the many keyless calls don't pace the test.
    from enrichment import build_modules
    mc = {name: {"requests_per_second": 1000} for name in
          ("email_pivot", "dns_rdap", "gravatar", "github", "keybase", "gitlab", "hackernews",
           "shodan", "crtsh", "wayback", "nominatim", "wikipedia")}
    result, md, geojson = await run(
        "jane.doe@example.com", purpose="unit test", requester="tester",
        max_depth=3, max_requests=0, module_config=mc, http=_mock_http(),
    )
    attrs = result.profile["attributes"]
    # Identity + accounts + web + infrastructure all present from one seed:
    assert attrs["full_name"]["value"] == "Jane Doe"
    assert "janedoe" in {v["value"] for v in attrs.get("usernames", [])}
    assert "93.184.216.34" in {v["value"] for v in attrs.get("ip_addresses", [])}
    assert "443/tcp" in {v["value"] for v in attrs.get("services", [])}
    assert "CVE-2020-0001" in {v["value"] for v in attrs.get("vulnerabilities", [])}
    # Dossier renders with sourced sections
    assert "# Target dossier" in md
    assert "## Infrastructure" in md and "## Identity" in md
    assert "unit test" in md and "tester" in md


async def test_dossier_lists_sources_and_confidence():
    seed = Entity(EntityType.USERNAME, "janedoe")

    async def h(e):
        return [Finding(entity=Entity(EntityType.FULL_NAME, "Jane Doe"), confidence=0.7)]

    async def h2(e):
        return [Finding(entity=Entity(EntityType.FULL_NAME, "Jane Doe"), confidence=0.6)]

    m1 = make_module("src_a", [EntityType.USERNAME], [EntityType.FULL_NAME], h)
    m2 = make_module("src_b", [EntityType.USERNAME], [EntityType.FULL_NAME], h2)
    d = Dispatcher([m1, m2])
    result = await d.scan(seed, requester_id="r", purpose="p")
    dossier = build_dossier(result, requester="r", purpose="p")
    ident = next(s for s in dossier["sections"] if s["heading"] == "Identity")
    row = ident["rows"][0]
    assert row["value"] == "Jane Doe"
    assert set(row["sources"]) == {"src_a", "src_b"}  # both sources credited
