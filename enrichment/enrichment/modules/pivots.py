"""Local pivot modules — derive new entities from a seed without any network call.

``EmailPivotModule`` turns an email into the two things worth chasing: candidate
usernames from the local part (dotless form first, since dots are invalid on most
platforms) and, for a custom/organizational domain, the domain itself — which then
flows into DNS/RDAP, crt.sh and Shodan. Free webmail, disposable and relay domains
are not emitted as domain pivots (scanning gmail.com's infrastructure is noise).

``AccountPivotModule`` turns a discovered linked account (``platform:handle``, e.g.
Gravatar/Keybase reporting ``github:janedoe``) back into a ``username`` entity, so the
handle gets looked up on the platform modules — this is what keeps the graph
expanding: a found account leads to more lookups. The username inherits modest
confidence because the same handle on another platform may be a different person.
"""
from __future__ import annotations

from ..entities import Entity, EntityType, Finding
from .base import EnrichmentModule

WEBMAIL = frozenset(
    "gmail.com googlemail.com yahoo.com ymail.com outlook.com hotmail.com live.com "
    "msn.com icloud.com me.com mac.com aol.com proton.me protonmail.com pm.me gmx.com "
    "gmx.net mail.com zoho.com yandex.com yandex.ru tuta.io tutanota.com fastmail.com "
    "hey.com qq.com 163.com 126.com comcast.net att.net verizon.net sbcglobal.net "
    "cox.net bellsouth.net charter.net earthlink.net mail.ru".split())
DISPOSABLE = frozenset(
    "mailinator.com guerrillamail.com sharklasers.com 10minutemail.com temp-mail.org "
    "tempmail.com yopmail.com trashmail.com getnada.com maildrop.cc throwawaymail.com "
    "mailinator.net mail.tm moakt.com emailfake.com".split())
RELAY = frozenset(
    "privaterelay.appleid.com duck.com mozmail.com simplelogin.com anonaddy.com "
    "anonaddy.me addy.io passmail.net 33mail.com".split())


class EmailPivotModule(EnrichmentModule):
    name = "email_pivot"
    watched_types = frozenset({EntityType.EMAIL})
    produced_types = frozenset({EntityType.DOMAIN, EntityType.USERNAME})
    requires_api_key = False
    terms_note = "Local only; no network. Derives domain + username pivots from an email."

    async def handle(self, entity: Entity) -> list[Finding]:
        local, _, domain = entity.normalized.partition("@")
        if not local or not domain:
            return []
        base = local.split("+", 1)[0]
        out: list[Finding] = []
        seen: set[str] = set()
        for cand in ([base.replace(".", "")] if "." in base else []) + [base]:
            if cand and cand not in seen:
                seen.add(cand)
                out.append(Finding(entity=Entity(EntityType.USERNAME, cand),
                                   confidence=0.5, label="email local part"))
        if domain not in WEBMAIL and domain not in DISPOSABLE and domain not in RELAY:
            out.append(Finding(entity=Entity(EntityType.DOMAIN, domain),
                               confidence=0.6, label="email domain"))
        return out


class AccountPivotModule(EnrichmentModule):
    name = "account_pivot"
    watched_types = frozenset({EntityType.ACCOUNT})
    produced_types = frozenset({EntityType.USERNAME})
    requires_api_key = False
    terms_note = "Local only; no network. Turns a discovered account handle into a username to look up."

    async def handle(self, entity: Entity) -> list[Finding]:
        # entity.normalized is "platform:handle"
        platform, _, handle = entity.normalized.partition(":")
        handle = handle.strip()
        if not handle:
            return []
        return [Finding(entity=Entity(EntityType.USERNAME, handle),
                        confidence=0.5, label=f"handle from {platform} account")]
