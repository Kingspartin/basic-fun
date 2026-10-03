"""Shodan — host / attack-surface intelligence for a domain or IP.

Passive lookup against Shodan's already-collected index, the way Shodan's own web
search works — **not** an active port scanner. Given:

* a **domain**, it resolves A/AAAA records (Google DoH) to ``ip_address`` entities;
* an **ip_address**, it queries Shodan for what that host exposes: open ports and
  services, reverse-DNS hostnames, org/ISP, geolocation, and known CVEs.

Two backends, chosen automatically:

* with ``config.api_key`` → the official Shodan REST API (`/shodan/host/{ip}`),
  which returns per-service product/version banners and vulns;
* without a key → Shodan's free, keyless **InternetDB** (`internetdb.shodan.io`),
  which returns ports, hostnames, CPEs, tags and vulns.

Both are official Shodan endpoints queried within their terms; there is no active
scanning of hosts and no key/IP rotation. Discovered hostnames feed back as domains
and the host's city/country feeds the geo module, so infrastructure and identity
findings land in one profile.
"""
from __future__ import annotations

import ipaddress

from ..entities import Entity, EntityType, Finding
from ..errors import ConfigurationError, UpstreamError
from .base import EnrichmentModule

DOH = "https://dns.google/resolve"
SHODAN_HOST = "https://api.shodan.io/shodan/host/{ip}"
INTERNETDB = "https://internetdb.shodan.io/{ip}"


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


class ShodanModule(EnrichmentModule):
    name = "shodan"
    watched_types = frozenset({EntityType.DOMAIN, EntityType.IP_ADDRESS})
    produced_types = frozenset({
        EntityType.IP_ADDRESS, EntityType.DOMAIN, EntityType.ORGANIZATION,
        EntityType.LOCATION, EntityType.SERVICE, EntityType.VULN,
    })
    requires_api_key = False  # falls back to keyless InternetDB
    terms_note = ("Shodan REST API (key) or InternetDB (keyless); passive query of "
                  "Shodan's index — no active scanning, no key/IP rotation.")

    async def handle(self, entity: Entity) -> list[Finding]:
        if entity.type == EntityType.DOMAIN:
            return await self._resolve(entity)
        return await self._host(entity)

    async def _resolve(self, entity: Entity) -> list[Finding]:
        findings: list[Finding] = []
        for typ, code in (("A", 1), ("AAAA", 28)):
            status, body = await self.http.get_json(
                DOH, params={"name": entity.normalized, "type": typ},
                headers={"accept": "application/dns-json"}, timeout=self.config.timeout_seconds,
            )
            if status != 200 or not isinstance(body, dict):
                continue
            for a in body.get("Answer", []) or []:
                if a.get("type") == code and a.get("data"):
                    findings.append(Finding(
                        entity=Entity(EntityType.IP_ADDRESS, a["data"]),
                        confidence=0.9, label=f"{typ} record",
                        raw={"of": entity.normalized, "record": typ},
                    ))
        return findings

    async def _host(self, entity: Entity) -> list[Finding]:
        ip = entity.normalized
        if not _is_ip(ip):
            return []
        if self.config.api_key:
            return await self._shodan_api(ip)
        return await self._internetdb(ip)

    async def _shodan_api(self, ip: str) -> list[Finding]:
        status, body = await self.http.get_json(
            SHODAN_HOST.format(ip=ip), params={"key": self.config.api_key},
            timeout=self.config.timeout_seconds,
        )
        if status == 401:
            raise ConfigurationError("Shodan: unauthorized (invalid API key)")
        if status == 404:
            return []  # no info for this host
        if status != 200 or not isinstance(body, dict):
            raise UpstreamError(f"Shodan: unexpected status {status}", status)

        findings: list[Finding] = []
        for host in body.get("hostnames", []) or []:
            findings.append(Finding(entity=Entity(EntityType.DOMAIN, host),
                                    confidence=0.7, label="Shodan reverse DNS", raw={"ip": ip}))
        for org in filter(None, {body.get("org"), body.get("isp")}):
            findings.append(Finding(entity=Entity(EntityType.ORGANIZATION, org),
                                    confidence=0.6, label="Shodan org/ISP", raw={"ip": ip}))
        loc = ", ".join(x for x in (body.get("city"), body.get("country_name")) if x)
        if loc:
            findings.append(Finding(entity=Entity(EntityType.LOCATION, loc),
                                    confidence=0.5, label="Shodan geolocation", raw={"ip": ip}))
        for item in body.get("data", []) or []:
            port, transport = item.get("port"), item.get("transport", "tcp")
            product = " ".join(str(x) for x in (item.get("product"), item.get("version")) if x)
            svc = f"{port}/{transport}" + (f" {product}" if product else "")
            findings.append(Finding(
                entity=Entity(EntityType.SERVICE, svc), confidence=0.85,
                label=item.get("product") or f"port {port}",
                raw={"ip": ip, "port": port, "transport": transport,
                     "product": item.get("product"), "version": item.get("version")},
            ))
        for cve in _vulns(body.get("vulns")):
            findings.append(Finding(entity=Entity(EntityType.VULN, cve),
                                    confidence=0.8, label="Shodan-reported CVE", raw={"ip": ip}))
        return findings

    async def _internetdb(self, ip: str) -> list[Finding]:
        status, body = await self.http.get_json(
            INTERNETDB.format(ip=ip), timeout=self.config.timeout_seconds,
        )
        if status == 404:
            return []  # host not in the index
        if status != 200 or not isinstance(body, dict):
            raise UpstreamError(f"InternetDB: unexpected status {status}", status)

        findings: list[Finding] = []
        for host in body.get("hostnames", []) or []:
            findings.append(Finding(entity=Entity(EntityType.DOMAIN, host),
                                    confidence=0.7, label="InternetDB hostname", raw={"ip": ip}))
        for port in body.get("ports", []) or []:
            findings.append(Finding(entity=Entity(EntityType.SERVICE, f"{port}/tcp"),
                                    confidence=0.8, label=f"port {port}", raw={"ip": ip, "port": port}))
        for cpe in body.get("cpes", []) or []:
            findings.append(Finding(entity=Entity(EntityType.SERVICE, cpe),
                                    confidence=0.6, label="CPE", raw={"ip": ip}))
        for cve in _vulns(body.get("vulns")):
            findings.append(Finding(entity=Entity(EntityType.VULN, cve),
                                    confidence=0.75, label="InternetDB CVE", raw={"ip": ip}))
        return findings


def _vulns(vulns) -> list[str]:
    """Shodan returns vulns as a list of CVE ids or a dict keyed by CVE id."""
    if isinstance(vulns, dict):
        return list(vulns.keys())
    if isinstance(vulns, list):
        return [str(v) for v in vulns]
    return []
