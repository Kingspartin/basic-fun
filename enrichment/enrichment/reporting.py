"""Consolidated dossier: fold a scan result into one grouped, sourced report.

``build_dossier`` returns a structured dict (sections of {value, confidence,
sources}); ``dossier_markdown`` renders it. Everything is derived from the scan's
findings, so every line keeps its confidence and the modules that produced it.
"""
from __future__ import annotations

from datetime import datetime, timezone

from .dispatcher import ScanResult
from .entities import EntityType, normalize
from .storage import _MULTI, _SCALAR

# Human-readable field name -> EntityType, for looking values back up.
_FIELD_TO_TYPE = {name: et for et, name in _MULTI.items()}
_FIELD_TO_TYPE.update({et.value: et for et in _SCALAR})

# Ordered report sections: (heading, [attribute field names]).
_SECTIONS = [
    ("Identity", ["full_name", "location", "geo_points"]),
    ("Contact", ["emails", "phones", "pgp_keys"]),
    ("Usernames & accounts", ["usernames", "accounts"]),
    ("Web presence", ["domains", "urls", "images"]),
    ("Affiliations", ["organizations"]),
    ("Exposure", ["breaches", "vulnerabilities"]),
    ("Infrastructure", ["ip_addresses", "services"]),
]


def _sources_index(result: ScanResult) -> dict[tuple[str, str], list[str]]:
    idx: dict[tuple[str, str], set[str]] = {}
    for f in result.findings:
        idx.setdefault((f.entity.type.value, f.entity.normalized), set()).add(f.module or "?")
    return {k: sorted(v) for k, v in idx.items()}


def _rows_for(field: str, attributes: dict, src_idx: dict) -> list[dict]:
    if field not in attributes:
        return []
    et = _FIELD_TO_TYPE.get(field)
    vals = attributes[field]
    items = vals if isinstance(vals, list) else [vals]
    rows = []
    for it in items:
        value, conf = it["value"], it.get("confidence")
        srcs = src_idx.get((et.value, normalize(et, value)), []) if et else []
        rows.append({"value": value, "confidence": conf, "sources": srcs})
    return rows


def build_dossier(result: ScanResult, *, requester: str | None = None,
                  purpose: str | None = None) -> dict:
    attributes = result.profile.get("attributes", {})
    src_idx = _sources_index(result)
    sections = []
    for heading, fields in _SECTIONS:
        rows = [r for field in fields for r in _rows_for(field, attributes, src_idx)]
        if rows:
            sections.append({"heading": heading, "rows": rows})
    return {
        "seed": result.profile.get("seed", {"type": result.seed.type.value, "value": result.seed.value}),
        "requester": requester,
        "purpose": purpose,
        "generated": datetime.now(timezone.utc).isoformat(),
        "scan_id": result.scan_id,
        "aborted": result.aborted,
        "stats": result.stats,
        "sections": sections,
    }


def dossier_markdown(result: ScanResult, *, requester: str | None = None,
                     purpose: str | None = None, title: str | None = None) -> str:
    d = build_dossier(result, requester=requester, purpose=purpose)
    seed = d["seed"]
    L = [f"# {title or 'Target dossier'}: {seed['value']}", "",
         f"- **Seed:** `{seed['type']}` = {seed['value']}"]
    if requester:
        L.append(f"- **Requester:** {requester}")
    if purpose:
        L.append(f"- **Purpose:** {purpose}")
    L.append(f"- **Generated:** {d['generated']}  ·  scan `{d['scan_id'][:8]}`")
    if d["aborted"]:
        L += ["", "> Scan aborted (seed on suppression list). No data gathered.", ""]
        return "\n".join(L) + "\n"
    s = d["stats"]
    L.append(f"- **Coverage:** {s.get('findings', 0)} findings across "
             f"{s.get('entities_seen', 0)} entities; {s.get('requests_made', 0)} requests, "
             f"{s.get('cache_hits', 0)} cache hits"
             + (f"; disabled: {', '.join(s['modules_disabled'])}" if s.get("modules_disabled") else ""))
    if not d["sections"]:
        L += ["", "_No attributes gathered._", ""]
        return "\n".join(L) + "\n"

    def esc(x: str) -> str:
        return str(x).replace("|", "\\|").replace("\n", " ")

    for sec in d["sections"]:
        L += ["", f"## {sec['heading']}", "", "| Value | Confidence | Sources |", "|---|---|---|"]
        for r in sec["rows"]:
            conf = f"{r['confidence']:.2f}" if isinstance(r["confidence"], (int, float)) else "?"
            L.append(f"| {esc(r['value'])} | {conf} | {esc(', '.join(r['sources']) or '—')} |")
    return "\n".join(L) + "\n"
