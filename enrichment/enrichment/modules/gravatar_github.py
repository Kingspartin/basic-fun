"""Gravatar and GitHub — email/username -> public profile facts (official APIs).

Gravatar: email -> public profile (display name, linked URLs/accounts, avatar) via
the public ``{md5}.json`` endpoint. GitHub: username -> public profile, and
email -> matching accounts via the official user-search endpoint. A GitHub token in
``config.api_key`` is optional and only raises the rate limit; primary-rate-limit
403s are surfaced as RateLimited so the dispatcher backs off rather than scraping.
"""
from __future__ import annotations

import hashlib

from ..entities import Entity, EntityType, Finding
from ..errors import RateLimited, UpstreamError
from .base import EnrichmentModule


class GravatarModule(EnrichmentModule):
    name = "gravatar"
    watched_types = frozenset({EntityType.EMAIL})
    produced_types = frozenset({EntityType.FULL_NAME, EntityType.URL,
                                EntityType.ACCOUNT, EntityType.IMAGE})
    requires_api_key = False
    terms_note = "Gravatar public profile JSON; keyless."

    async def handle(self, entity: Entity) -> list[Finding]:
        h = hashlib.md5(entity.normalized.encode("utf-8")).hexdigest()
        status, body = await self.http.get_json(
            f"https://en.gravatar.com/{h}.json", timeout=self.config.timeout_seconds,
        )
        if status == 404 or not isinstance(body, dict):
            return []
        if status != 200:
            raise UpstreamError(f"Gravatar: status {status}", status)

        entries = body.get("entry") or []
        if not entries:
            return []
        e = entries[0]
        findings: list[Finding] = []

        name = e.get("displayName") or (e.get("name") or {}).get("formatted")
        if name:
            findings.append(Finding(entity=Entity(EntityType.FULL_NAME, name),
                                    confidence=0.7, label="Gravatar display name"))
        thumb = e.get("thumbnailUrl")
        if thumb:
            findings.append(Finding(entity=Entity(EntityType.IMAGE, thumb),
                                    confidence=0.8, label="Gravatar avatar"))
        for u in e.get("urls", []) or []:
            if u.get("value"):
                findings.append(Finding(entity=Entity(EntityType.URL, u["value"]),
                                        confidence=0.6, label=u.get("title") or "Gravatar link"))
        for acc in e.get("accounts", []) or []:
            svc, handle = acc.get("shortname") or acc.get("domain"), acc.get("username") or acc.get("display")
            if svc and handle:
                findings.append(Finding(
                    entity=Entity(EntityType.ACCOUNT, f"{svc}:{handle}"),
                    confidence=0.7, label="Gravatar linked account",
                    raw={"url": acc.get("url")},
                ))
        return findings


class GitHubModule(EnrichmentModule):
    name = "github"
    watched_types = frozenset({EntityType.USERNAME, EntityType.EMAIL})
    produced_types = frozenset({EntityType.FULL_NAME, EntityType.LOCATION, EntityType.ORGANIZATION,
                                EntityType.URL, EntityType.EMAIL, EntityType.ACCOUNT,
                                EntityType.IMAGE, EntityType.USERNAME})
    requires_api_key = False  # optional token raises rate limits
    terms_note = "GitHub REST API v3; token optional; official rate limits honored."

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/vnd.github+json"}
        if self.config.api_key:
            h["Authorization"] = f"Bearer {self.config.api_key}"
        return h

    async def handle(self, entity: Entity) -> list[Finding]:
        if entity.type == EntityType.EMAIL:
            return await self._by_email(entity)
        return await self._by_username(entity)

    async def _request(self, url: str, params: dict | None = None):
        resp = await self.http.request("GET", url, params=params, headers=self._headers(),
                                       timeout=self.config.timeout_seconds)
        # GitHub signals primary rate limiting with 403/429 + remaining=0.
        if resp.status_code in (403, 429) and resp.headers.get("X-RateLimit-Remaining") == "0":
            reset = resp.headers.get("X-RateLimit-Reset")
            import time as _t
            retry = max(0.0, float(reset) - _t.time()) if reset else None
            raise RateLimited("GitHub rate limit", retry_after=retry)
        return resp

    async def _by_username(self, entity: Entity) -> list[Finding]:
        resp = await self._request(f"https://api.github.com/users/{entity.normalized}")
        if resp.status_code == 404:
            return []
        if resp.status_code != 200:
            raise UpstreamError(f"GitHub users: status {resp.status_code}", resp.status_code)
        u = resp.json()
        findings: list[Finding] = []

        def add(t, v, conf, label, raw=None):
            if v:
                findings.append(Finding(entity=Entity(t, v), confidence=conf, label=label, raw=raw or {}))

        add(EntityType.FULL_NAME, u.get("name"), 0.7, "GitHub name")
        add(EntityType.LOCATION, u.get("location"), 0.55, "GitHub location")
        add(EntityType.ORGANIZATION, (u.get("company") or "").lstrip("@") or None, 0.6, "GitHub company")
        add(EntityType.URL, u.get("blog"), 0.6, "GitHub blog")
        add(EntityType.EMAIL, u.get("email"), 0.85, "GitHub public email")
        add(EntityType.IMAGE, u.get("avatar_url"), 0.7, "GitHub avatar")
        if u.get("twitter_username"):
            add(EntityType.ACCOUNT, f"twitter:{u['twitter_username']}", 0.75, "GitHub-linked Twitter")
        return findings

    async def _by_email(self, entity: Entity) -> list[Finding]:
        resp = await self._request("https://api.github.com/search/users",
                                   params={"q": f"{entity.normalized} in:email"})
        if resp.status_code == 404:
            return []
        if resp.status_code != 200:
            raise UpstreamError(f"GitHub search: status {resp.status_code}", resp.status_code)
        items = (resp.json() or {}).get("items", []) or []
        # Emit the matched login as a username lead; the username handler expands it.
        return [Finding(entity=Entity(EntityType.USERNAME, it["login"]),
                        confidence=0.6, label="GitHub account for email",
                        raw={"html_url": it.get("html_url")})
                for it in items[:3] if it.get("login")]
