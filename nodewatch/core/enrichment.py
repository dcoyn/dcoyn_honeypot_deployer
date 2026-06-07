"""
nodewatch.core.enrichment
========================

Maximum-depth enrichment of source IPs. Every function is best-effort
and NEVER throws — a failing lookup yields None, not an exception.

Enrichment layers (all additive — each one fills keys the others don't):

  1. **PTR**              – reverse DNS hostname
  2. **GeoIP**            – country, city, lat/lon, ASN, AS org (MaxMind GeoLite2)
  3. **IP metadata**      – RFC classification, bogon detection, IP version
  4. **Network WHOIS**    – abuse contact, registration date, CIDR block (cached)
  5. **Open-source abuse**– AbuseIPDB score + last-report age (optional, needs key)
  6. **TOR exit node**    – checked against cached list from TOR Project
  7. **Known proxy list** – checked against a downloaded open-proxy list
  8. **DNS chain**        – forward-confirms the PTR (FCrDNS) to detect spoofed rDNS
  9. **TCP OS hint**      – TTL/window-size-based OS family inference (when raw socket
                             data is available)
  10. **Timing profile**  – connection-rate, burst detection, first/last seen (per-process)

GeoIP data comes from MaxMind GeoLite2 MMDB files. install.sh downloads
them at install time and a weekly systemd timer refreshes them.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import struct
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
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

    # ---- Forward-confirmed reverse DNS (FCrDNS) ----
    # If PTR resolves to a hostname, verify by resolving that hostname back.
    # Mismatch = the PTR is spoofed or stale (common with bullet-proof hosting).
    if out["ptr"]:
        try:
            fwd = socket.getaddrinfo(out["ptr"], None, socket.AF_INET)
            fwd_ips = {r[4][0] for r in fwd}
            out["fcrdns_verified"] = ip in fwd_ips
            if not out["fcrdns_verified"]:
                out["fcrdns_forward_ips"] = sorted(fwd_ips)[:5]
        except Exception:
            out["fcrdns_verified"] = None

    # ---- IP metadata: version, bogon, RFC classification ----
    try:
        addr = ipaddress.ip_address(ip)
        out["ip_version"] = addr.version
        out["is_loopback"] = addr.is_loopback
        out["is_multicast"] = addr.is_multicast
        out["is_link_local"] = addr.is_link_local
        out["is_reserved"] = addr.is_reserved
        # Bogon detection (RFC 5735 + RFC 6598)
        if addr.version == 4:
            out["is_bogon"] = (addr.is_private or addr.is_reserved
                               or addr.is_loopback or addr.is_link_local
                               or addr in ipaddress.IPv4Network("100.64.0.0/10")  # CGN
                               or addr in ipaddress.IPv4Network("192.0.0.0/24")   # IETF
                               or addr in ipaddress.IPv4Network("198.18.0.0/15")) # benchmarking
        else:
            out["is_bogon"] = addr.is_private or addr.is_reserved or addr.is_loopback
    except Exception:
        pass

    # ---- TOR exit node check ----
    out["is_tor_exit"] = _is_tor_exit(ip)

    # ---- Known open proxy check ----
    out["is_known_proxy"] = _is_known_proxy(ip)

    # ---- Network WHOIS (abuse contact, registration) ----
    whois_data = _whois_lookup(ip)
    if whois_data:
        out["whois"] = whois_data

    # ---- AbuseIPDB check (if API key configured) ----
    abuse_data = _abuseipdb_check(ip)
    if abuse_data:
        out["abuse"] = abuse_data

    # ---- Connection timing profile ----
    timing = _record_connection(ip)
    if timing:
        out["timing"] = timing

    return out


# ===================================================================
# TOR exit node detection
# ===================================================================
_TOR_EXITS: set[str] = set()
_TOR_LOCK = threading.Lock()
_TOR_LAST_LOAD: float = 0.0
_TOR_RELOAD_SECS = 3600  # re-read list hourly
_TOR_LIST_PATHS = [
    "/var/lib/nodewatch/tor_exit_nodes.txt",
    "/var/lib/GeoIP/tor_exit_nodes.txt",
]


def _load_tor_exits() -> None:
    """Load TOR exit node list from disk. install.sh downloads from
    https://check.torproject.org/torbulkexitlist hourly via cron."""
    global _TOR_EXITS, _TOR_LAST_LOAD
    now = time.time()
    if now - _TOR_LAST_LOAD < _TOR_RELOAD_SECS:
        return
    with _TOR_LOCK:
        if now - _TOR_LAST_LOAD < _TOR_RELOAD_SECS:
            return
        _TOR_LAST_LOAD = now
        for p in _TOR_LIST_PATHS:
            try:
                lines = Path(p).read_text().splitlines()
                new = {l.strip() for l in lines if l.strip() and not l.startswith("#")}
                if new:
                    _TOR_EXITS = new
                    return
            except Exception:
                continue


def _is_tor_exit(ip: str) -> bool:
    _load_tor_exits()
    return ip in _TOR_EXITS


# ===================================================================
# Known open proxy detection
# ===================================================================
_PROXY_IPS: set[str] = set()
_PROXY_LOCK = threading.Lock()
_PROXY_LAST_LOAD: float = 0.0
_PROXY_RELOAD_SECS = 3600
_PROXY_LIST_PATHS = [
    "/var/lib/nodewatch/open_proxies.txt",
    "/var/lib/GeoIP/open_proxies.txt",
]


def _load_proxies() -> None:
    global _PROXY_IPS, _PROXY_LAST_LOAD
    now = time.time()
    if now - _PROXY_LAST_LOAD < _PROXY_RELOAD_SECS:
        return
    with _PROXY_LOCK:
        if now - _PROXY_LAST_LOAD < _PROXY_RELOAD_SECS:
            return
        _PROXY_LAST_LOAD = now
        for p in _PROXY_LIST_PATHS:
            try:
                lines = Path(p).read_text().splitlines()
                new = {l.strip() for l in lines if l.strip() and not l.startswith("#")}
                if new:
                    _PROXY_IPS = new
                    return
            except Exception:
                continue


def _is_known_proxy(ip: str) -> bool:
    _load_proxies()
    return ip in _PROXY_IPS


# ===================================================================
# Network WHOIS lookup (cached, rate-limited)
# ===================================================================
_WHOIS_CACHE: dict[str, dict] = {}
_WHOIS_CACHE_MAX = 5000
_WHOIS_LOCK = threading.Lock()


def _whois_lookup(ip: str) -> Optional[dict]:
    """Best-effort WHOIS for abuse contact and registration info.
    Uses the ARIN/RIPE/APNIC RDAP-style whois via the socket protocol.
    Results are cached per /24 (IPv4) or /48 (IPv6)."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            net = str(ipaddress.IPv4Network(f"{ip}/24", strict=False))
        else:
            net = str(ipaddress.IPv6Network(f"{ip}/48", strict=False))
    except Exception:
        return None

    with _WHOIS_LOCK:
        if net in _WHOIS_CACHE:
            return _WHOIS_CACHE[net]

    out: dict = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(("whois.arin.net", 43))
        s.sendall(f"n + {ip}\r\n".encode())
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
            if len(resp) > 16384:
                break
        s.close()
        text = resp.decode("utf-8", "replace")

        # Parse key fields from ARIN response
        for line in text.splitlines():
            line = line.strip()
            if ":" not in line or line.startswith("#") or line.startswith("%"):
                continue
            key, _, val = line.partition(":")
            key = key.strip().lower()
            val = val.strip()
            if not val:
                continue
            if key == "orgname" and "org_name" not in out:
                out["org_name"] = val
            elif key == "orgabuseemail" and "abuse_email" not in out:
                out["abuse_email"] = val
            elif key == "orgabusephone" and "abuse_phone" not in out:
                out["abuse_phone"] = val
            elif key == "cidr" and "cidr" not in out:
                out["cidr"] = val
            elif key == "netname" and "net_name" not in out:
                out["net_name"] = val
            elif key == "regdate" and "reg_date" not in out:
                out["reg_date"] = val
            elif key == "updated" and "updated" not in out:
                out["updated"] = val
            elif key == "country" and "country" not in out:
                out["whois_country"] = val.upper()
            elif key == "ref" and "ref_url" not in out:
                out["ref_url"] = val
    except Exception:
        pass

    if out:
        with _WHOIS_LOCK:
            _WHOIS_CACHE[net] = out
            while len(_WHOIS_CACHE) > _WHOIS_CACHE_MAX:
                oldest = next(iter(_WHOIS_CACHE))
                _WHOIS_CACHE.pop(oldest, None)

    return out or None


# ===================================================================
# AbuseIPDB check (optional — needs HP_ABUSEIPDB_KEY env var)
# ===================================================================
_ABUSEIPDB_KEY = os.environ.get("HP_ABUSEIPDB_KEY", "")
_ABUSE_CACHE: dict[str, dict] = {}
_ABUSE_CACHE_MAX = 5000
_ABUSE_LOCK = threading.Lock()
_ABUSE_TTL = 3600  # cache for 1 hour


def _abuseipdb_check(ip: str) -> Optional[dict]:
    """Query AbuseIPDB for reputation score. Requires HP_ABUSEIPDB_KEY."""
    if not _ABUSEIPDB_KEY:
        return None
    with _ABUSE_LOCK:
        cached = _ABUSE_CACHE.get(ip)
        if cached and (time.time() - cached.get("_ts", 0)) < _ABUSE_TTL:
            return {k: v for k, v in cached.items() if not k.startswith("_")}
    try:
        import urllib.request
        req = urllib.request.Request(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
            headers={"Key": _ABUSEIPDB_KEY, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        d = data.get("data", {})
        out = {
            "abuse_score": d.get("abuseConfidenceScore"),
            "total_reports": d.get("totalReports"),
            "last_reported": d.get("lastReportedAt"),
            "usage_type": d.get("usageType"),
            "isp": d.get("isp"),
            "domain": d.get("domain"),
            "is_whitelisted": d.get("isWhitelisted"),
            "country_code": d.get("countryCode"),
        }
        out = {k: v for k, v in out.items() if v is not None}
        with _ABUSE_LOCK:
            _ABUSE_CACHE[ip] = {**out, "_ts": time.time()}
            while len(_ABUSE_CACHE) > _ABUSE_CACHE_MAX:
                oldest = next(iter(_ABUSE_CACHE))
                _ABUSE_CACHE.pop(oldest, None)
        return out
    except Exception:
        return None


# ===================================================================
# TCP OS fingerprinting (from TTL and window size)
# ===================================================================
# Common default TTLs by OS family — the observed TTL minus hops gives
# the initial TTL which maps to an OS family with high confidence.
_TTL_MAP = [
    (255, "Cisco IOS / Solaris / AIX"),
    (128, "Windows"),
    (64,  "Linux / macOS / FreeBSD"),
    (60,  "HP-UX"),
    (32,  "vintage Windows (3.11/95/98)"),
]


def classify_ttl(ttl: int) -> Optional[dict]:
    """Infer OS family from an observed TTL value.
    Returns {"os_family": ..., "estimated_hops": ...} or None."""
    if ttl <= 0 or ttl > 255:
        return None
    # Find the closest standard initial TTL
    best_init = None
    best_diff = 999
    for init, label in _TTL_MAP:
        diff = init - ttl
        if 0 <= diff < best_diff:
            best_diff = diff
            best_init = (init, label)
    if best_init is None:
        return None
    return {
        "os_family": best_init[1],
        "initial_ttl": best_init[0],
        "estimated_hops": best_init[0] - ttl,
    }


def classify_tcp_fingerprint(ttl: int = 0, window_size: int = 0,
                              mss: int = 0, df: bool = False) -> Optional[dict]:
    """Combine TTL + TCP window size + MSS + DF flag for OS inference."""
    out: dict = {}
    if ttl:
        ttl_data = classify_ttl(ttl)
        if ttl_data:
            out.update(ttl_data)
    if window_size:
        out["tcp_window_size"] = window_size
        # Common window sizes
        if window_size == 65535:
            out.setdefault("os_hints", []).append("Windows (65535 window)")
        elif window_size == 5840:
            out.setdefault("os_hints", []).append("Linux 2.x (5840 window)")
        elif window_size == 29200:
            out.setdefault("os_hints", []).append("Linux 3.x+ (29200 window)")
        elif window_size == 14600:
            out.setdefault("os_hints", []).append("Linux 2.6.x (14600 window)")
        elif window_size == 8192:
            out.setdefault("os_hints", []).append("Windows Vista/7 (8192 window)")
    if mss:
        out["tcp_mss"] = mss
    if df:
        out["tcp_df_flag"] = True
    return out if out else None


# ===================================================================
# Connection timing profiler (per-process, in-memory)
# ===================================================================
_TIMING: dict[str, dict] = {}  # ip -> {first, last, count, burst_count, last_burst_ts}
_TIMING_LOCK = threading.Lock()
_TIMING_MAX = 50_000
_BURST_WINDOW = 5.0  # seconds


def _record_connection(ip: str) -> Optional[dict]:
    """Track connection timing for burst/rate analysis."""
    now = time.time()
    with _TIMING_LOCK:
        rec = _TIMING.get(ip)
        if rec is None:
            rec = {"first_seen": now, "last_seen": now, "count": 1,
                   "burst_count": 1, "last_burst_ts": now,
                   "max_burst": 1, "total_bursts": 0}
            _TIMING[ip] = rec
            while len(_TIMING) > _TIMING_MAX:
                oldest = next(iter(_TIMING))
                _TIMING.pop(oldest, None)
        else:
            rec["count"] += 1
            rec["last_seen"] = now
            # Burst detection
            if now - rec["last_burst_ts"] <= _BURST_WINDOW:
                rec["burst_count"] += 1
                if rec["burst_count"] > rec["max_burst"]:
                    rec["max_burst"] = rec["burst_count"]
            else:
                if rec["burst_count"] > 1:
                    rec["total_bursts"] += 1
                rec["burst_count"] = 1
                rec["last_burst_ts"] = now

        duration = rec["last_seen"] - rec["first_seen"]
        out = {
            "total_connections": rec["count"],
            "first_seen_utc": datetime.fromtimestamp(rec["first_seen"], tz=timezone.utc).isoformat(),
            "last_seen_utc": datetime.fromtimestamp(rec["last_seen"], tz=timezone.utc).isoformat(),
            "duration_seconds": round(duration, 1),
            "connections_per_minute": round(rec["count"] / max(duration / 60, 0.017), 2),
            "max_burst_in_window": rec["max_burst"],
            "total_bursts": rec["total_bursts"],
        }
        # Flag high-rate scanners
        if rec["count"] > 10 and duration > 0:
            rate = rec["count"] / (duration / 60)
            if rate > 30:
                out["rate_class"] = "aggressive_scanner"
            elif rate > 10:
                out["rate_class"] = "moderate_scanner"
            elif rate > 3:
                out["rate_class"] = "slow_scanner"
            else:
                out["rate_class"] = "manual_pace"
        return out
