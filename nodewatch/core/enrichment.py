"""
nodewatch.core.enrichment
========================

Best-effort enrichment of source IPs. Never throws — if a lookup fails
we just emit empty values. The aggregator can re-enrich later from a
single richer DB without re-deploying.
"""
from __future__ import annotations

import ipaddress
import socket
from functools import lru_cache
from typing import Optional

try:
    import geoip2.database
except Exception:  # pragma: no cover
    geoip2 = None  # type: ignore

# Common system locations Debian uses for the MaxMind geoip2 DBs.
_GEOIP_PATHS = [
    "/var/lib/GeoIP/GeoLite2-City.mmdb",
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
    "/var/lib/GeoIP/GeoLite2-Country.mmdb",
    "/usr/share/GeoIP/GeoLite2-Country.mmdb",
]
_ASN_PATHS = [
    "/var/lib/GeoIP/GeoLite2-ASN.mmdb",
    "/usr/share/GeoIP/GeoLite2-ASN.mmdb",
]


def _open_first(paths):
    if geoip2 is None:
        return None
    for p in paths:
        try:
            return geoip2.database.Reader(p)
        except Exception:
            continue
    return None


_geo_reader = _open_first(_GEOIP_PATHS)
_asn_reader = _open_first(_ASN_PATHS)


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


@lru_cache(maxsize=10_000)
def enrich(ip: str) -> dict:
    """Returns {country, city, latlon, asn, asn_org, ptr, is_private}.

    Cached because attackers tend to come back.
    """
    out = {
        "country": None,
        "city": None,
        "latlon": None,
        "asn": None,
        "asn_org": None,
        "ptr": None,
        "is_private": is_private(ip),
    }
    if out["is_private"]:
        return out

    if _geo_reader is not None:
        try:
            r = _geo_reader.city(ip)
            out["country"] = r.country.iso_code
            out["city"]    = r.city.name
            if r.location.latitude and r.location.longitude:
                out["latlon"] = [r.location.latitude, r.location.longitude]
        except Exception:
            pass

    if _asn_reader is not None:
        try:
            r = _asn_reader.asn(ip)
            out["asn"]     = r.autonomous_system_number
            out["asn_org"] = r.autonomous_system_organization
        except Exception:
            pass

    try:
        out["ptr"] = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass

    return out
