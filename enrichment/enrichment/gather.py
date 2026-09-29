"""`gather` — one command that pulls as much as possible on a single target.

Detects the seed type, builds a dispatcher with every enabled module (keyless ones
always; keyed ones — HIBP, Hunter, and the Shodan REST backend — only when a key is
provided), runs one scan, and writes a consolidated dossier plus the location map.

Compliance is unchanged: the suppression list still gates the seed and every
discovered entity, the scan is audit-logged with the given requester and purpose,
and only official APIs are called. "As much as possible" means breadth across those
sources — not scraping, not active scanning, not evading limits.

    python -m enrichment.gather jane@example.com \
        --purpose "fraud review, case 42" --requester analyst-7 \
        --md dossier.md --json dossier.json --map footprint.html

Keys via flags (--shodan-key, --hibp-key, --hunter-key, --github-token,
--gitlab-token) or env (ENRICH_<NAME>_API_KEY).
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import re
import sys

from .config import build_dispatcher
from .dispatcher import ScanResult, ScanSettings
from .entities import Entity, EntityType
from .http import HttpClient
from .modules.geo import render_map_html, to_geojson
from .reporting import dossier_markdown

_EMAIL_RE = re.compile(r"^[^\s@]+@[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"^([a-z0-9-]+\.)+[a-z]{2,}$", re.IGNORECASE)
_HANDLE_RE = re.compile(r"^@?[A-Za-z0-9._-]{2,40}$")


def detect_seed(text: str, explicit: str | None = None) -> Entity:
    s = text.strip()
    if explicit and explicit != "auto":
        return Entity(EntityType(explicit), s)
    if _EMAIL_RE.match(s):
        return Entity(EntityType.EMAIL, s)
    try:
        ipaddress.ip_address(s)
        return Entity(EntityType.IP_ADDRESS, s)
    except ValueError:
        pass
    if s.lower().startswith(("http://", "https://")):
        return Entity(EntityType.URL, s)
    if _DOMAIN_RE.match(s) and not s.startswith("@"):
        return Entity(EntityType.DOMAIN, s)
    if " " in s and all(re.match(r"^[\w'.-]+$", w) for w in s.split()):
        return Entity(EntityType.FULL_NAME, s)
    if _HANDLE_RE.match(s):
        return Entity(EntityType.USERNAME, s.lstrip("@"))
    return Entity(EntityType.FULL_NAME, s)


def _module_config(args) -> dict:
    cfg: dict[str, dict] = {}
    for name, val in (("shodan", args.shodan_key), ("hibp", args.hibp_key),
                      ("hunter", args.hunter_key), ("github", args.github_token),
                      ("gitlab", args.gitlab_token)):
        if val:
            cfg[name] = {"api_key": val}
    return cfg


async def run(seed_text: str, *, purpose: str, requester: str = "cli",
              seed_type: str | None = None, max_depth: int = 3, max_requests: int = 0,
              workers: int = 8, module_config: dict | None = None,
              http: HttpClient | None = None):
    """Run a full scan and return (ScanResult, dossier_markdown, geojson)."""
    seed = detect_seed(seed_text, seed_type)
    dispatcher = build_dispatcher(
        module_config=module_config or {},
        settings=ScanSettings(max_depth=max_depth, max_requests=max_requests, workers=workers),
        http=http,
    )
    result: ScanResult = await dispatcher.scan(
        seed, requester_id=requester, purpose=purpose,
        max_depth=max_depth, max_requests=max_requests,
    )
    md = dossier_markdown(result, requester=requester, purpose=purpose)
    geojson = to_geojson(result.findings)
    return result, md, geojson


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="enrichment.gather",
                                description="Gather as much as possible on a single target.")
    p.add_argument("seed", help="email, @username, phone, domain, IP, URL, or full name")
    p.add_argument("--type", dest="seed_type", default="auto",
                   choices=["auto"] + [t.value for t in EntityType])
    p.add_argument("--purpose", required=True, help="stated lawful purpose (audit-logged)")
    p.add_argument("--requester", default="cli", help="requester id (audit-logged)")
    p.add_argument("--depth", type=int, default=3, help="max hops from the seed")
    p.add_argument("--max-requests", type=int, default=0, help="provider-call cap (0 = unlimited)")
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--md", help="write the Markdown dossier here")
    p.add_argument("--json", dest="json_out", help="write the full result JSON here")
    p.add_argument("--map", dest="map_out", help="write the Leaflet footprint map here")
    for flag in ("shodan-key", "hibp-key", "hunter-key", "github-token", "gitlab-token"):
        p.add_argument(f"--{flag}", dest=flag.replace("-", "_"), default=None)
    args = p.parse_args(argv)

    result, md, geojson = asyncio.run(run(
        args.seed, purpose=args.purpose, requester=args.requester,
        seed_type=args.seed_type, max_depth=args.depth, max_requests=args.max_requests,
        workers=args.workers, module_config=_module_config(args),
    ))

    if args.md:
        with open(args.md, "w") as fh:
            fh.write(md)
    if args.json_out:
        with open(args.json_out, "w") as fh:
            json.dump({"scan_id": result.scan_id, "seed": result.profile.get("seed"),
                       "profile": result.profile, "stats": result.stats,
                       "findings": [f.as_record() for f in result.findings]}, fh, indent=2)
    if args.map_out:
        with open(args.map_out, "w") as fh:
            fh.write(render_map_html(geojson, title=f"{args.seed} — footprint"))

    sys.stdout.write(md)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
