"""Geolocation — a modern, compliance-bounded successor to Creepy/geocreepy.

Classic Creepy did two things: (a) aggregate the places a person's public profiles
expose and plot them on a map, and (b) harvest per-post geotags across social
platforms to reconstruct someone's movements over time. This implements **(a)** only.

(b) — scraping a target's post history to rebuild their real-time movements — is a
physical-tracking capability, requires scraping platforms whose terms forbid it, and
violates this layer's official-APIs-only charter, so it is deliberately not built.

What this provides:

* ``GeoNominatimModule`` — turns a LOCATION place-string (e.g. a profile's
  "Seattle, WA") into a GEO_POINT with coordinates, via OpenStreetMap Nominatim
  (keyless). Nominatim's usage policy (max ~1 req/s, descriptive User-Agent) is
  honored by the dispatcher's rate limiter and the shared client's UA. GEO_POINT is
  a terminal type — nothing expands it — so there is no geocode loop.
* ``geo_point_from_coords`` — wrap coordinates the operator already holds (e.g. EXIF
  GPS from an image in evidence) as a GEO_POINT finding, no lookup needed.
* ``to_geojson`` / ``render_map_html`` — the "footprint map" deliverable: a GeoJSON
  FeatureCollection (each point keeps its source module, parent identifier,
  confidence and timestamp) and a self-contained Leaflet map that renders it.

Every point still carries provenance, and everything runs behind the layer's
suppression list and audit log like any other module.
"""
from __future__ import annotations

import json

from ..entities import Entity, EntityType, Finding
from .base import EnrichmentModule

NOMINATIM = "https://nominatim.openstreetmap.org/search"


class GeoNominatimModule(EnrichmentModule):
    name = "nominatim"
    watched_types = frozenset({EntityType.LOCATION})
    produced_types = frozenset({EntityType.GEO_POINT})
    requires_api_key = False
    terms_note = ("OpenStreetMap Nominatim; keyless. Usage policy: <=1 req/s, "
                  "descriptive User-Agent, no heavy/bulk use. Honored via rate limiter.")

    async def handle(self, entity: Entity) -> list[Finding]:
        q = entity.value.strip()
        if not q:
            return []
        status, body = await self.http.get_json(
            NOMINATIM,
            params={"q": q, "format": "jsonv2", "limit": 1, "addressdetails": 0},
            timeout=self.config.timeout_seconds,
        )
        if status != 200 or not isinstance(body, list) or not body:
            return []
        r = body[0]
        lat, lon = r.get("lat"), r.get("lon")
        if lat is None or lon is None:
            return []
        # Self-declared profile locations are coarse; cap confidence accordingly.
        try:
            importance = float(r.get("importance") or 0.3)
        except (TypeError, ValueError):
            importance = 0.3
        return [Finding(
            entity=Entity(EntityType.GEO_POINT, f"{lat},{lon}"),
            confidence=round(min(0.6, max(0.3, importance)), 3),
            label=r.get("display_name") or q,
            raw={"query": q, "display_name": r.get("display_name"),
                 "category": r.get("category") or r.get("type"),
                 "osm_type": r.get("osm_type")},
        )]


def geo_point_from_coords(lat: float, lon: float, *, label: str | None = None,
                          source: str = "operator", confidence: float = 0.9,
                          raw: dict | None = None) -> Finding:
    """Wrap coordinates the operator already has (e.g. EXIF GPS) as a GEO_POINT.

    ``source`` is recorded as the finding's module so provenance stays honest.
    """
    f = Finding(entity=Entity(EntityType.GEO_POINT, f"{lat},{lon}"),
                confidence=confidence, label=label or "supplied coordinates",
                raw=raw or {"source": source})
    f.module = source
    return f


def _points(findings: list[Finding]):
    for f in findings:
        if f.entity.type != EntityType.GEO_POINT:
            continue
        try:
            lat_s, lon_s = f.entity.value.split(",")
            yield float(lat_s), float(lon_s), f
        except (ValueError, TypeError):
            continue


def to_geojson(findings: list[Finding]) -> dict:
    """Build a GeoJSON FeatureCollection from GEO_POINT findings, provenance intact."""
    features = []
    for lat, lon, f in _points(findings):
        features.append({
            "type": "Feature",
            "geometry": {"type": "Point", "coordinates": [lon, lat]},  # GeoJSON is lon,lat
            "properties": {
                "label": f.label,
                "module": f.module,
                "confidence": f.confidence,
                "parent": f.parent.cache_token() if f.parent else None,
                "timestamp": f.timestamp.isoformat() if f.timestamp else None,
                "display_name": (f.raw or {}).get("display_name"),
            },
        })
    return {"type": "FeatureCollection", "features": features}


def render_map_html(feature_collection: dict, *, title: str = "Location footprint") -> str:
    """Self-contained Leaflet map (OSM tiles) rendering the FeatureCollection.

    Coordinates and labels are the only data embedded. ``</`` is escaped so a
    place name can never break out of the data <script> block.
    """
    data = json.dumps(feature_collection).replace("</", "<\\/")
    safe_title = (title or "Location footprint").replace("<", "&lt;").replace(">", "&gt;")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{safe_title}</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.css">
<style>html,body,#map{{height:100%;margin:0}}.lbl{{font:13px sans-serif}}</style>
</head><body><div id="map"></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.js"></script>
<script>
const DATA = {data};
const map = L.map('map');
L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png',
  {{maxZoom: 19, attribution: '&copy; OpenStreetMap contributors'}}).addTo(map);
const layer = L.geoJSON(DATA, {{
  onEachFeature: (feat, lyr) => {{
    const p = feat.properties || {{}};
    lyr.bindPopup('<div class="lbl"><b>' + (p.label || '') + '</b><br>' +
      'source: ' + (p.module || '?') + ' &middot; conf ' + (p.confidence ?? '?') +
      (p.parent ? '<br>from: ' + p.parent : '') +
      (p.timestamp ? '<br>' + p.timestamp : '') + '</div>');
  }}
}}).addTo(map);
const b = layer.getBounds();
if (b.isValid()) map.fitBounds(b.pad(0.2)); else map.setView([20, 0], 2);
</script></body></html>"""
