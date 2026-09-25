"""Module registry.

``ALL_MODULES`` maps each module's ``name`` to its class. The config layer builds
only the modules that are enabled and correctly configured, so adding a source is:
write the class, add it here.
"""
from __future__ import annotations

from .base import EnrichmentModule, ModuleConfig
from .dns_rdap import DnsRdapModule
from .gravatar_github import GitHubModule, GravatarModule
from .hibp import HaveIBeenPwnedModule
from .hunter import HunterModule

ALL_MODULES: dict[str, type[EnrichmentModule]] = {
    m.name: m for m in (
        HaveIBeenPwnedModule,
        HunterModule,
        DnsRdapModule,
        GravatarModule,
        GitHubModule,
    )
}

__all__ = ["ALL_MODULES", "EnrichmentModule", "ModuleConfig"]
