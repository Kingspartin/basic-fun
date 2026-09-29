"""Small helpers to pull structured leads out of free text (bios, profile blurbs).

Only full, unambiguous signals are extracted — email addresses and http(s) URLs —
so a profile "about" field yields the same kinds of entities as a structured API
field. Callers decide the confidence.
"""
from __future__ import annotations

import re

from .entities import Entity, EntityType, Finding

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
_URL = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)


def text_findings(text: str | None, *, confidence: float = 0.5, label: str = "from bio/text") -> list[Finding]:
    s = str(text or "")
    out: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for m in _EMAIL.finditer(s):
        e = Entity(EntityType.EMAIL, m.group(0))
        if e.key not in seen:
            seen.add(e.key)
            out.append(Finding(entity=e, confidence=confidence, label=label))
    for m in _URL.finditer(s):
        e = Entity(EntityType.URL, m.group(0).rstrip(".,;:!?"))
        if e.key not in seen:
            seen.add(e.key)
            out.append(Finding(entity=e, confidence=confidence, label=label))
    return out
