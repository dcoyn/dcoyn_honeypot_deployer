"""
nodewatch.core.enrichment
========================

Best-effort enrichment of source IPs with PTR + GeoIP (country, city,
ASN). Never throws — if a lookup fails we just emit empty values.

GeoIP data comes from MaxMind GeoLite2 MMDB files. install.sh downloads
them at install time and a weekly systemd timer refreshes them. If the
files are missing entirely (download failed, etc.) every field except
``ptr`` is None and the aggregator still has the chance to fill them
later.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import threading
import time
from typing import Optional

try:
    import geoip2.database
except Exception:  # pragma: no cover
    geoip2 = None  # type: ignore


# Standard Debian paths — install.sh drops MMDBs here so they're trivially
# locatable + survive uninstalls of the sensor (don't need re-downloading).
_CITY_PATHS = [
    "/var/lib/GeoIP/GeoLite2-City.mmdb",
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
]
_ASN_PATHS = [
    "/var/lib/GeoIP/GeoLite2-ASN.mmdb",
    "/usr/share/GeoIP/GeoLite2-ASN.mmdb",
]


# Hold open readers + the file mtime they were opened against. When the
# weekly refresh writes a new MMDB and restarts the sensor, the module
# is re-imported and we open the fresh files. If a refresh happens
# without a sensor restart, the hourly mtime re-check picks up the
# change.
_LOCK = threading.Lock()
_city_reader = None
_city_mtime: float = 0.0
_city_path: Optional[str] = None
_asn_reader = None
_asn_mtime: float = 0.0
_asn_path: Optional[str] = None
_MTIME_RECHECK_SECS = 3600
_last_mtime_check: float = 0.0


def _first_existing(paths):
    for p in paths:
        if os.path.isfile(p):
            return p
    return None


def _ensure_readers() -> None:
    """Open MMDB readers if not open; reopen if the on-disk file changed
    since we opened it. Called once per ``enrich()``."""
    global _city_reader, _city_mtime, _city_path
    global _asn_reader, _asn_mtime, _asn_path, _last_mtime_check

    if geoip2 is None:
        return

    now = time.time()
    with _LOCK:
        need_check = (now - _last_mtime_check) > _MTIME_RECHECK_SECS
        if _city_reader is not None and _asn_reader is not None and not need_check:
            return
        _last_mtime_check = now

        # City DB
        p = _first_existing(_CITY_PATHS)
        if p is not None:
            try:
                mt = os.path.getmtime(p)
                if _city_reader is None or p != _city_path or mt > _city_mtime:
                    if _city_reader is not None:
                        try:
                            _city_reader.close()
                        except Exception:
                            pass
                    _city_reader = geoip2.database.Reader(p)
                    _city_mtime = mt
                    _city_path = p
            except Exception:
                pass

        # ASN DB
        p = _first_existing(_ASN_PATHS)
        if p is not None:
            try:
                mt = os.path.getmtime(p)
                if _asn_reader is None or p != _asn_path or mt > _asn_mtime:
                    if _asn_reader is not None:
                        try:
                            _asn_reader.close()
                        except Exception:
                            pass
                    _asn_reader = geoip2.database.Reader(p)
                    _asn_mtime = mt
                    _asn_path = p
            except Exception:
                pass


# Try to open at import. The lazy re-check inside enrich() retries if
# files were missing then later got downloaded.
_ensure_readers()


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# PTR can be slow (DNS query); cache for the lifetime of the process.
_PTR_CACHE_MAX = 10_000
_ptr_cache: dict[str, Optional[str]] = {}
_ptr_lock = threading.Lock()


def _ptr(ip: str) -> Optional[str]:
    with _ptr_lock:
        if ip in _ptr_cache:
            return _ptr_cache[ip]
    try:
        r = socket.gethostbyaddr(ip)[0]
    except Exception:
        r = None
    with _ptr_lock:
        if len(_ptr_cache) >= _PTR_CACHE_MAX:
            for k in list(_ptr_cache.keys())[: _PTR_CACHE_MAX // 10]:
                _ptr_cache.pop(k, None)
        _ptr_cache[ip] = r
    return r


def enrich(ip: str) -> dict:
    """Returns the canonical geo-enrichment shape used across the fleet:

        {
          "ptr":          str | None,
          "is_private":   bool,
          "country":      str | None,   # ISO-2 code
          "country_name": str | None,
          "city":         str | None,
          "lat":          float | None,
          "lon":          float | None,
          "asn":          int | None,
          "as_org":       str | None,
        }

    Keys match aggregator output so per-event geo flows into fleet
    rollups without remapping.
    """
    out = {
        "ptr":          None,
        "is_private":   is_private(ip),
        "country":      None,
        "country_name": None,
        "city":         None,
        "lat":          None,
        "lon":          None,
        "asn":          None,
        "as_org":       None,
    }
    if out["is_private"]:
        out["ptr"] = _ptr(ip)
        return out

    _ensure_readers()

    if _city_reader is not None:
        try:
            r = _city_reader.city(ip)
            out["country"]      = r.country.iso_code
            out["country_name"] = r.country.name
            out["city"]         = r.city.name
            if r.location.latitude is not None and r.location.longitude is not None:
                out["lat"] = float(r.location.latitude)
                out["lon"] = float(r.location.longitude)
        except Exception:
            pass

    if _asn_reader is not None:
        try:
            r = _asn_reader.asn(ip)
            out["asn"]    = r.autonomous_system_number
            out["as_org"] = r.autonomous_system_organization
        except Exception:
            pass

    out["ptr"] = _ptr(ip)
    return out
