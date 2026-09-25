"""Entity and Finding models.

An **Entity** is a normalized identifier: a node in the investigation graph
(an email, a domain, a username, ...). Two entities are "the same" when their
``(type, normalized_value)`` key matches; that key drives deduplication,
caching and suppression checks.

A **Finding** is an edge with evidence: it records that ``module`` derived
``entity`` from ``parent`` at ``timestamp`` with a ``confidence`` score and
the ``raw`` provider data behind it. Storing findings (rather than bare
entities) is what makes every discovered fact traceable back to its source.

Design note: the requested module signature was ``handle(entity) -> list[Entity]``.
Modules here return ``list[Finding]`` instead, because confidence and the raw
evidence must be attached at the moment of production; the dispatcher fills in
``parent``, ``module`` and ``timestamp``. A Finding still *carries* the produced
Entity as ``finding.entity``, so the spirit of the interface is preserved.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class EntityType(str, Enum):
    EMAIL = "email"
    PHONE = "phone"
    USERNAME = "username"
    FULL_NAME = "full_name"
    DOMAIN = "domain"
    URL = "url"
    IP_ADDRESS = "ip_address"
    ORGANIZATION = "organization"
    LOCATION = "location"
    IMAGE = "image"
    # produced-only fact types
    BREACH = "breach"
    PGP_KEY = "pgp_key"
    ACCOUNT = "account"  # a profile on a named platform, value = "platform:handle"


_WS = re.compile(r"\s+")
_NON_DIGIT = re.compile(r"\D")


def normalize(entity_type: EntityType, value: str) -> str:
    """Return the canonical form of ``value`` for its type.

    Normalization is what makes dedup and suppression reliable, so it must be
    deterministic and idempotent. It only *canonicalizes*; it does not validate.
    """
    v = (value or "").strip()
    if entity_type == EntityType.EMAIL:
        v = v.lower()
        # Gmail ignores dots and +tags in the local part; fold them so the same
        # inbox is not scanned twice. Other providers keep the local part as-is.
        if "@" in v:
            local, _, domain = v.partition("@")
            if domain in ("gmail.com", "googlemail.com"):
                local = local.split("+", 1)[0].replace(".", "")
            else:
                local = local.split("+", 1)[0]
            v = f"{local}@{domain}"
    elif entity_type == EntityType.DOMAIN:
        v = v.lower().rstrip(".")
        v = re.sub(r"^https?://", "", v)
        v = v.split("/", 1)[0]
        if v.startswith("www."):
            v = v[4:]
    elif entity_type == EntityType.USERNAME:
        v = v.lstrip("@").lower()
    elif entity_type == EntityType.PHONE:
        digits = _NON_DIGIT.sub("", v)
        # Treat a 10-digit NANP number and its +1 form as identical.
        if len(digits) == 11 and digits.startswith("1"):
            digits = digits[1:]
        v = digits
    elif entity_type == EntityType.FULL_NAME:
        v = _WS.sub(" ", v).lower()
    elif entity_type == EntityType.ACCOUNT:
        platform, _, handle = v.partition(":")
        v = f"{platform.strip().lower()}:{handle.strip().lstrip('@').lower()}"
    elif entity_type in (EntityType.URL, EntityType.IMAGE):
        v = v.strip()
    else:
        v = v.lower()
    return v


@dataclass(frozen=True)
class Entity:
    type: EntityType
    value: str

    @property
    def normalized(self) -> str:
        return normalize(self.type, self.value)

    @property
    def key(self) -> tuple[str, str]:
        """Identity used for dedup, caching and suppression."""
        return (self.type.value, self.normalized)

    def cache_token(self) -> str:
        return f"{self.type.value}:{self.normalized}"

    def __str__(self) -> str:  # pragma: no cover - display only
        return f"{self.type.value}={self.value}"


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Finding:
    """A produced entity plus the evidence and provenance behind it.

    Modules construct these with ``entity``, ``confidence``, ``raw`` and an
    optional human ``label``. The dispatcher stamps ``module``, ``parent`` and
    ``timestamp`` before the finding is stored, so nothing a module returns can
    forge its own provenance.
    """
    entity: Entity
    confidence: float = 0.5  # 0..1
    label: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    # Filled in by the dispatcher:
    module: str | None = None
    parent: Entity | None = None
    timestamp: datetime = field(default_factory=_now)

    def stamped(self, *, module: str, parent: Entity) -> "Finding":
        conf = max(0.0, min(1.0, float(self.confidence)))
        return replace(self, module=module, parent=parent, confidence=conf,
                       timestamp=self.timestamp or _now())

    def as_record(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "parent_type": self.parent.type.value if self.parent else None,
            "parent_value": self.parent.normalized if self.parent else None,
            "entity_type": self.entity.type.value,
            "entity_value": self.entity.value,
            "entity_normalized": self.entity.normalized,
            "confidence": self.confidence,
            "label": self.label,
            "raw": self.raw,
            "timestamp": self.timestamp.isoformat(),
        }
