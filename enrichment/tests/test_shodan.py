"""Shodan module: domain->IP resolution and host intel via API / InternetDB."""
import httpx

from enrichment.dispatcher import Dispatcher, ScanSettings
from enrichment.entities import Entity, EntityType
from enrichment.errors import ConfigurationError
from enrichment.modules.base import ModuleConfig
from enrichment.modules.shodan import ShodanModule

from conftest import http_for, make_module

DOMAIN, IP, SERVICE, VULN, ORG, LOC = (
    EntityType.DOMAIN, EntityType.IP_ADDRESS, EntityType.SERVICE,
    EntityType.VULN, EntityType.ORGANIZATION, EntityType.LOCATION,
)


def _doh(a=("93.184.216.34",), aaaa=()):
    def handler(req: httpx.Request) -> httpx.Response:
        typ = req.url.params.get("type")
        if typ == "A":
            return httpx.Response(200, json={"Answer": [{"type": 1, "data": x} for x in a]})
        if typ == "AAAA":
            return httpx.Response(200, json={"Answer": [{"type": 28, "data": x} for x in aaaa]})
        return httpx.Response(200, json={})
    return handler


async def test_domain_resolves_to_ips():
    m = ShodanModule(ModuleConfig(), http_for(_doh(a=("1.2.3.4",), aaaa=("2606:2800::1",))))
    out = await m.handle(Entity(DOMAIN, "example.com"))
    ips = {(f.entity.type, f.entity.value) for f in out}
    assert (IP, "1.2.3.4") in ips
    assert (IP, "2606:2800::1") in ips


async def test_internetdb_keyless_parses_host():
    def handler(req):
        assert "internetdb.shodan.io" in req.url.host
        return httpx.Response(200, json={
            "ip": "1.2.3.4", "ports": [22, 443],
            "hostnames": ["host.example.com"], "cpes": ["cpe:/a:nginx:nginx:1.18.0"],
            "vulns": ["CVE-2021-23017"], "tags": ["cloud"],
        })

    m = ShodanModule(ModuleConfig(), http_for(handler))  # no api_key -> InternetDB
    out = await m.handle(Entity(IP, "1.2.3.4"))
    vals = {(f.entity.type, f.entity.value) for f in out}
    assert (SERVICE, "22/tcp") in vals and (SERVICE, "443/tcp") in vals
    assert (DOMAIN, "host.example.com") in vals
    assert (VULN, "CVE-2021-23017") in vals


async def test_shodan_api_parses_services_org_location_vulns():
    def handler(req: httpx.Request) -> httpx.Response:
        assert "api.shodan.io" in req.url.host
        assert req.url.params.get("key") == "SHODANKEY"
        return httpx.Response(200, json={
            "hostnames": ["mail.example.com"], "org": "Example ISP", "isp": "Example ISP",
            "city": "Ashburn", "country_name": "United States",
            "data": [
                {"port": 443, "transport": "tcp", "product": "nginx", "version": "1.18.0"},
                {"port": 22, "transport": "tcp", "product": "OpenSSH"},
            ],
            "vulns": {"CVE-2021-23017": {"cvss": 9.8}},
        })

    m = ShodanModule(ModuleConfig(api_key="SHODANKEY"), http_for(handler))
    out = await m.handle(Entity(IP, "1.2.3.4"))
    vals = {(f.entity.type, f.entity.value) for f in out}
    assert (ORG, "Example ISP") in vals
    assert (LOC, "Ashburn, United States") in vals
    assert (SERVICE, "443/tcp nginx 1.18.0") in vals
    assert (VULN, "CVE-2021-23017") in vals


async def test_shodan_api_invalid_key_raises():
    m = ShodanModule(ModuleConfig(api_key="bad"), http_for(lambda r: httpx.Response(401)))
    try:
        await m.handle(Entity(IP, "1.2.3.4"))
        assert False, "expected ConfigurationError"
    except ConfigurationError:
        pass


async def test_non_ip_entity_is_ignored():
    m = ShodanModule(ModuleConfig(), http_for(lambda r: httpx.Response(200, json={})))
    assert await m.handle(Entity(IP, "not-an-ip")) == []


async def test_vuln_normalization_uppercases_cve():
    assert Entity(VULN, "cve-2021-23017").normalized == "CVE-2021-23017"


async def test_end_to_end_domain_to_attack_surface():
    # domain -> A record -> host intel, all through the dispatcher graph
    def handler(req: httpx.Request) -> httpx.Response:
        if "dns.google" in req.url.host:
            typ = req.url.params.get("type")
            if typ == "A":
                return httpx.Response(200, json={"Answer": [{"type": 1, "data": "1.2.3.4"}]})
            return httpx.Response(200, json={"Answer": []})
        if "internetdb.shodan.io" in req.url.host:
            return httpx.Response(200, json={"ip": "1.2.3.4", "ports": [443],
                                             "hostnames": [], "cpes": [], "vulns": ["CVE-2020-0001"]})
        return httpx.Response(404)

    shodan = ShodanModule(ModuleConfig(requests_per_second=1000), http_for(handler))
    d = Dispatcher([shodan], settings=ScanSettings(workers=2))
    res = await d.scan(Entity(DOMAIN, "example.com"), requester_id="r",
                       purpose="attack-surface review", max_depth=2)
    attrs = res.profile["attributes"]
    assert "1.2.3.4" in {v["value"] for v in attrs.get("ip_addresses", [])}
    assert "443/tcp" in {v["value"] for v in attrs.get("services", [])}
    assert "CVE-2020-0001" in {v["value"] for v in attrs.get("vulnerabilities", [])}
