"""Geolocation module: geocoding, footprint aggregation, GeoJSON/map export."""
import json

import httpx

from enrichment.dispatcher import Dispatcher, ScanSettings
from enrichment.entities import Entity, EntityType, normalize
from enrichment.modules.base import ModuleConfig
from enrichment.modules.geo import (GeoNominatimModule, geo_point_from_coords,
                                    render_map_html, to_geojson)

from conftest import http_for, make_module

LOCATION, GEO_POINT, USERNAME = EntityType.LOCATION, EntityType.GEO_POINT, EntityType.USERNAME


def _nominatim(lat="47.6038", lon="-122.3301", name="Seattle, WA, USA"):
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.params.get("q")
        return httpx.Response(200, json=[{
            "lat": lat, "lon": lon, "display_name": name,
            "importance": 0.7, "category": "place", "osm_type": "relation",
        }])
    return handler


async def test_geocodes_location_to_geo_point():
    m = GeoNominatimModule(ModuleConfig(), http_for(_nominatim()))
    out = await m.handle(Entity(LOCATION, "Seattle, WA"))
    assert len(out) == 1
    p = out[0]
    assert p.entity.type == GEO_POINT and p.entity.value == "47.6038,-122.3301"
    assert p.confidence <= 0.6  # self-declared locations stay coarse
    assert "Seattle" in p.label


async def test_no_result_is_empty():
    m = GeoNominatimModule(ModuleConfig(), http_for(lambda r: httpx.Response(200, json=[])))
    assert await m.handle(Entity(LOCATION, "nowhere-xyzzy")) == []


def test_geo_point_normalization_dedups_nearby():
    a = Entity(GEO_POINT, "47.60380001,-122.33009999")
    b = Entity(GEO_POINT, "47.6038,-122.3301")
    assert a.key == b.key


def test_geo_point_from_coords_helper():
    f = geo_point_from_coords(51.5, -0.12, label="EXIF from photo", source="exif")
    assert f.entity.type == GEO_POINT and f.module == "exif"
    assert f.entity.value == "51.5,-0.12"


def test_to_geojson_shape_and_lonlat_order():
    f = geo_point_from_coords(47.6038, -122.3301, label="Seattle", source="nominatim")
    f.parent = Entity(USERNAME, "janedoe")
    fc = to_geojson([f])
    assert fc["type"] == "FeatureCollection" and len(fc["features"]) == 1
    feat = fc["features"][0]
    assert feat["geometry"]["coordinates"] == [-122.3301, 47.6038]  # lon, lat
    assert feat["properties"]["module"] == "nominatim"
    assert feat["properties"]["parent"] == "username:janedoe"


def test_render_map_html_embeds_points_and_escapes():
    f = geo_point_from_coords(47.6038, -122.3301, label="</script><b>x", source="nominatim")
    html = render_map_html(to_geojson([f]), title="Footprint")
    assert "47.6038" in html and "-122.3301" in html
    assert "leaflet" in html.lower()
    assert "</script><b>" not in html  # label can't break out of the data block


async def test_end_to_end_username_to_map():
    # fake profile module: username -> a self-declared location string
    async def profile_h(e):
        from enrichment.entities import Finding
        return [Finding(entity=Entity(LOCATION, "Seattle, WA"), confidence=0.55)]

    profile = make_module("profile", [USERNAME], [LOCATION], profile_h)
    geo = GeoNominatimModule(ModuleConfig(requests_per_second=1000), http_for(_nominatim()))
    d = Dispatcher([profile, geo], settings=ScanSettings(workers=2))
    res = await d.scan(Entity(USERNAME, "janedoe"), requester_id="r", purpose="t", max_depth=2)
    geo_points = [f for f in res.findings if f.entity.type == GEO_POINT]
    assert geo_points and geo_points[0].parent.type == LOCATION
    assert "geo_points" in res.profile["attributes"]
    fc = to_geojson(res.findings)
    assert fc["features"][0]["geometry"]["coordinates"][0] == -122.3301
