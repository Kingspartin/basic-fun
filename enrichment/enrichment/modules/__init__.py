"""Module registry.

``ALL_MODULES`` maps each module's ``name`` to its class. The config layer builds
only the modules that are enabled and correctly configured, so adding a source is:
write the class, add it here.
"""
from __future__ import annotations

from .base import EnrichmentModule, ModuleConfig
from .dns_rdap import DnsRdapModule
from .geo import GeoNominatimModule
from .gravatar_github import GitHubModule, GravatarModule
from .hibp import HaveIBeenPwnedModule
from .hunter import HunterModule
from .pivots import AccountPivotModule, EmailPivotModule
from .shodan import ShodanModule
from .web_sources import (CrtShModule, GitLabModule, HackerNewsModule,
                          KeybaseModule, WaybackModule, WikipediaModule)

ALL_MODULES: dict[str, type[EnrichmentModule]] = {
    m.name: m for m in (
        EmailPivotModule,
        AccountPivotModule,
        HaveIBeenPwnedModule,
        HunterModule,
        DnsRdapModule,
        GravatarModule,
        GitHubModule,
        GeoNominatimModule,
        ShodanModule,
        CrtShModule,
        WaybackModule,
        KeybaseModule,
        GitLabModule,
        HackerNewsModule,
        WikipediaModule,
    )
}

__all__ = ["ALL_MODULES", "EnrichmentModule", "ModuleConfig"]
