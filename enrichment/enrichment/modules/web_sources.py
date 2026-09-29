"""Additional breadth modules, all official/keyless APIs.

* ``CrtShModule``     — domain -> subdomains from certificate-transparency logs (crt.sh)
* ``WaybackModule``   — domain/url -> latest Internet Archive snapshot
* ``KeybaseModule``   — username -> name, location, and the account/web proofs Keybase
                        verifies (a strong cross-platform identity graph)
* ``GitLabModule``    — username -> profile name + URL
* ``HackerNewsModule``— username -> emails/links in the "about" text
* ``WikipediaModule`` — full_name -> matching article URLs (low confidence; a name
                        matches many people)

Each translates one provider response into findings and chains through the
dispatcher like every other module. No scraping of sites that forbid it.
"""
from __future__ import annotations

from ..entities import Entity, EntityType, Finding
from ..extract import text_findings
from .base import EnrichmentModule

_PROOF_PLATFORM = {"twitter": "twitter", "github": "github", "reddit": "reddit",
                   "hackernews": "hackernews", "mastodon": "mastodon", "facebook": "facebook"}


class CrtShModule(EnrichmentModule):
    name = "crtsh"
    watched_types = frozenset({EntityType.DOMAIN})
    produced_types = frozenset({EntityType.DOMAIN})
    requires_api_key = False
    terms_note = "crt.sh certificate transparency logs; keyless public JSON."

    async def handle(self, entity: Entity) -> list[Finding]:
        domain = entity.normalized
        status, body = await self.http.get_json(
            "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
            timeout=self.config.timeout_seconds,
        )
        if status != 200 or not isinstance(body, list):
            return []
        names: set[str] = set()
        for row in body:
            for n in str(row.get("name_value", "")).splitlines():
                n = n.strip().lstrip("*.").lower()
                if n and n != domain and n.endswith("." + domain) and "@" not in n:
                    names.add(n)
        # Cap so a wildcard-heavy domain can't flood the queue.
        return [Finding(entity=Entity(EntityType.DOMAIN, n), confidence=0.7,
                        label="subdomain (crt.sh)") for n in sorted(names)[:200]]


class WaybackModule(EnrichmentModule):
    name = "wayback"
    watched_types = frozenset({EntityType.DOMAIN, EntityType.URL})
    produced_types = frozenset({EntityType.URL})
    requires_api_key = False
    terms_note = "Internet Archive Wayback availability API; keyless public."

    async def handle(self, entity: Entity) -> list[Finding]:
        target = entity.normalized if entity.type == EntityType.DOMAIN else entity.value
        status, body = await self.http.get_json(
            "https://archive.org/wayback/available", params={"url": target},
            timeout=self.config.timeout_seconds,
        )
        if status != 200 or not isinstance(body, dict):
            return []
        snap = (body.get("archived_snapshots") or {}).get("closest") or {}
        if snap.get("url"):
            ts = str(snap.get("timestamp", ""))
            return [Finding(entity=Entity(EntityType.URL, snap["url"]), confidence=0.5,
                            label=f"Wayback snapshot {ts[:8]}", raw={"timestamp": ts})]
        return []


class KeybaseModule(EnrichmentModule):
    name = "keybase"
    watched_types = frozenset({EntityType.USERNAME})
    produced_types = frozenset({EntityType.FULL_NAME, EntityType.LOCATION,
                                EntityType.ACCOUNT, EntityType.DOMAIN})
    requires_api_key = False
    terms_note = "Keybase public user lookup API; keyless."

    async def handle(self, entity: Entity) -> list[Finding]:
        status, body = await self.http.get_json(
            "https://keybase.io/_/api/1.0/user/lookup.json",
            params={"usernames": entity.normalized, "fields": "profile,proofs_summary"},
            timeout=self.config.timeout_seconds,
        )
        if status != 200 or not isinstance(body, dict):
            return []
        them = body.get("them")
        t = them[0] if isinstance(them, list) and them else (them if isinstance(them, dict) else None)
        if not t:
            return []
        out: list[Finding] = []
        prof = t.get("profile") or {}
        if prof.get("full_name"):
            out.append(Finding(entity=Entity(EntityType.FULL_NAME, prof["full_name"]),
                               confidence=0.7, label="Keybase name"))
        if prof.get("location"):
            out.append(Finding(entity=Entity(EntityType.LOCATION, prof["location"]),
                               confidence=0.5, label="Keybase location"))
        for p in ((t.get("proofs_summary") or {}).get("all") or []):
            typ, nametag = p.get("proof_type"), p.get("nametag")
            if not nametag:
                continue
            if typ in ("dns", "generic_web_site", "web"):
                out.append(Finding(entity=Entity(EntityType.DOMAIN, nametag.lower()),
                                   confidence=0.7, label="Keybase web proof"))
            else:
                plat = _PROOF_PLATFORM.get(typ, typ)
                out.append(Finding(entity=Entity(EntityType.ACCOUNT, f"{plat}:{nametag}"),
                                   confidence=0.85, label="Keybase-verified proof",
                                   raw={"url": p.get("service_url")}))
        return out


class GitLabModule(EnrichmentModule):
    name = "gitlab"
    watched_types = frozenset({EntityType.USERNAME})
    produced_types = frozenset({EntityType.FULL_NAME, EntityType.URL})
    requires_api_key = False
    terms_note = "GitLab public users API; keyless (token optional)."

    async def handle(self, entity: Entity) -> list[Finding]:
        headers = {"Authorization": f"Bearer {self.config.api_key}"} if self.config.api_key else {}
        status, body = await self.http.get_json(
            "https://gitlab.com/api/v4/users", params={"username": entity.normalized},
            headers=headers, timeout=self.config.timeout_seconds,
        )
        if status != 200 or not isinstance(body, list) or not body:
            return []
        u = body[0]
        out: list[Finding] = []
        if u.get("name"):
            out.append(Finding(entity=Entity(EntityType.FULL_NAME, u["name"]),
                               confidence=0.6, label="GitLab name"))
        if u.get("web_url"):
            out.append(Finding(entity=Entity(EntityType.URL, u["web_url"]),
                               confidence=0.6, label="GitLab profile"))
        return out


class HackerNewsModule(EnrichmentModule):
    name = "hackernews"
    watched_types = frozenset({EntityType.USERNAME})
    produced_types = frozenset({EntityType.EMAIL, EntityType.URL})
    requires_api_key = False
    terms_note = "Hacker News Firebase API; keyless public."

    async def handle(self, entity: Entity) -> list[Finding]:
        status, body = await self.http.get_json(
            f"https://hacker-news.firebaseio.com/v0/user/{entity.normalized}.json",
            timeout=self.config.timeout_seconds,
        )
        if status != 200 or not isinstance(body, dict):
            return []
        return text_findings(body.get("about"), confidence=0.5, label="Hacker News about")


class WikipediaModule(EnrichmentModule):
    name = "wikipedia"
    watched_types = frozenset({EntityType.FULL_NAME})
    produced_types = frozenset({EntityType.URL})
    requires_api_key = False
    terms_note = "Wikipedia MediaWiki search API; keyless public."

    async def handle(self, entity: Entity) -> list[Finding]:
        status, body = await self.http.get_json(
            "https://en.wikipedia.org/w/api.php",
            params={"action": "query", "list": "search", "srsearch": entity.value,
                    "srlimit": 3, "format": "json", "origin": "*"},
            timeout=self.config.timeout_seconds,
        )
        if status != 200 or not isinstance(body, dict):
            return []
        out: list[Finding] = []
        for h in ((body.get("query") or {}).get("search") or [])[:3]:
            title = h.get("title")
            if title:
                url = "https://en.wikipedia.org/wiki/" + title.replace(" ", "_")
                out.append(Finding(entity=Entity(EntityType.URL, url), confidence=0.4,
                                   label=f"Wikipedia: {title}"))
        return out
