"""
nodewatch.core.threat_intel
============================

Offline, dependency-free attacker classification. Turns the raw facts we
already collect (source IP, GeoIP/ASN, SSH client banner, HTTP user-agent)
into higher-level *intel tags* without any network calls or paid feeds.

Everything here is best-effort and NEVER throws — a bad input returns an
empty/неutral result, never an exception, so it is safe to call inline on
the hot path of every sensor.

Three independent classifiers:

  * ``classify_source(ip, geo)``  -> hosting/cloud/tor/residential tags from
    the ASN org string and a small bundled keyword table. No DB downloads;
    works off the ``as_org`` string the existing enrichment already gives us.

  * ``classify_ssh_client(banner)`` -> which SSH *tool* connected. The client
    version banner (``SSH-2.0-...``) is one of the strongest cheap signals we
    have: real humans use OpenSSH/PuTTY; mass scanners and botnets use libssh2,
    Go's x/crypto/ssh, paramiko, zgrab, or leave the Mirai/Gafgyt giveaways.

  * ``classify_user_agent(ua)`` -> scanner / library / browser bucket for HTTP.

``tag_event(...)`` glues them together and returns a flat dict that sensors
drop straight into the event ``data`` under the ``intel`` key, so the
aggregator can roll the tags up per-IP with zero remapping.
"""
from __future__ import annotations

import re
from typing import Optional


# ---------------------------------------------------------------------------
# ASN / hosting classification
# ---------------------------------------------------------------------------
# Keyword -> tag. Matched case-insensitively against the AS org string.
# This is deliberately small and high-signal; expand it from your own fleet
# data over time. The goal is to separate "came from a datacenter / VPS /
# cloud" (almost always automated or a rented box) from residential ISPs
# (more likely a real human, a compromised home box, or a proxy exit).
_HOSTING_KEYWORDS = {
    # Hyperscalers
    "amazon":        ("cloud", "aws"),
    "aws":           ("cloud", "aws"),
    "google":        ("cloud", "gcp"),
    "microsoft":     ("cloud", "azure"),
    "azure":         ("cloud", "azure"),
    "oracle":        ("cloud", "oci"),
    "alibaba":       ("cloud", "alibaba"),
    "tencent":       ("cloud", "tencent"),
    "huawei":        ("cloud", "huawei"),
    # Big VPS / hosting where mass scanning is rampant
    "digitalocean":  ("hosting", "digitalocean"),
    "linode":        ("hosting", "linode"),
    "akamai":        ("hosting", "akamai"),
    "ovh":           ("hosting", "ovh"),
    "hetzner":       ("hosting", "hetzner"),
    "contabo":       ("hosting", "contabo"),
    "vultr":         ("hosting", "vultr"),
    "choopa":        ("hosting", "vultr"),
    "leaseweb":      ("hosting", "leaseweb"),
    "scaleway":      ("hosting", "scaleway"),
    "online s.a.s":  ("hosting", "scaleway"),
    "datacamp":      ("hosting", "datacamp"),
    "m247":          ("hosting", "m247"),
    "g-core":        ("hosting", "gcore"),
    "colocrossing":  ("hosting", "colocrossing"),
    "hostwinds":     ("hosting", "hostwinds"),
    " donweb":       ("hosting", "donweb"),
    "tencent":       ("cloud", "tencent"),
    # Generic hosting tells
    "hosting":       ("hosting", None),
    "datacenter":    ("hosting", None),
    "data center":   ("hosting", None),
    "dedicated":     ("hosting", None),
    "server":        ("hosting", None),
    "vps":           ("hosting", None),
    "cloud":         ("hosting", None),
    "colo":          ("hosting", None),
    # VPN / anonymity providers commonly used for abuse
    "mullvad":       ("vpn", "mullvad"),
    "nordvpn":       ("vpn", "nordvpn"),
    "private internet": ("vpn", "pia"),
    "cyberghost":    ("vpn", "cyberghost"),
    "ipvanish":      ("vpn", "ipvanish"),
    # Tor — org strings sometimes literally say this
    "tor exit":      ("tor", None),
    "torservers":    ("tor", None),
}

# Residential / consumer ISP tells. Lower priority than hosting; only used
# when no hosting keyword matched.
_RESIDENTIAL_KEYWORDS = (
    "telecom", "telekom", "comcast", "verizon", "at&t", "spectrum", "cox",
    "vodafone", "orange", "telefonica", "movistar", "bell canada", "rogers",
    "broadband", "cable", "dsl", "fiber", "fibre", "wireless", "mobile",
    "communications", "isp",
)


def classify_source(ip: str, geo: Optional[dict]) -> dict:
    """Return source-infrastructure intel for an IP.

    Output keys (all optional):
        infra        "cloud" | "hosting" | "vpn" | "tor" | "residential" | None
        provider     normalized provider slug when known (e.g. "aws")
        as_org       echoed AS org for convenience
        asn          echoed ASN
    """
    out: dict = {"infra": None, "provider": None}
    geo = geo or {}
    as_org = (geo.get("as_org") or "").strip()
    out["asn"] = geo.get("asn")
    out["as_org"] = as_org or None
    if not as_org:
        return out

    low = as_org.lower()
    for kw, (infra, provider) in _HOSTING_KEYWORDS.items():
        if kw.strip() in low:
            out["infra"] = infra
            if provider:
                out["provider"] = provider
            return out

    for kw in _RESIDENTIAL_KEYWORDS:
        if kw in low:
            out["infra"] = "residential"
            return out

    return out


# ---------------------------------------------------------------------------
# SSH client banner classification
# ---------------------------------------------------------------------------
# Each entry: (compiled regex over the lowercased banner, tool slug, is_bot,
# human-readable note). First match wins; order matters (specific first).
_SSH_CLIENT_RULES: list[tuple[re.Pattern, str, bool, str]] = [
    (re.compile(r"mirai"),                 "mirai",       True,
     "Mirai-family IoT botnet banner"),
    (re.compile(r"gafgyt|bashlite|qbot"),  "gafgyt",      True,
     "Gafgyt/BASHLITE-family IoT botnet"),
    (re.compile(r"zgrab"),                 "zgrab",       True,
     "ZGrab mass-scanner (research or attacker recon)"),
    (re.compile(r"masscan|zmap"),          "masscan",     True,
     "Internet-wide port scanner"),
    (re.compile(r"nmap|npcap"),            "nmap",        True,
     "Nmap NSE ssh probe"),
    (re.compile(r"libssh2"),               "libssh2",     True,
     "libssh2 — common in brute-force tooling (hydra/medusa/ncrack)"),
    (re.compile(r"libssh_?0|libssh-0|libssh/"), "libssh", True,
     "libssh — used by automated tooling and some CVE PoCs"),
    (re.compile(r"paramiko"),              "paramiko",    True,
     "Python paramiko — almost always a script, not a human"),
    (re.compile(r"go\b|golang|crypto/ssh"),"go-ssh",      True,
     "Go x/crypto/ssh — common in modern scanners/worms"),
    (re.compile(r"russh|rust"),            "russh",       True,
     "Rust ssh client — modern tooling"),
    (re.compile(r"jsch"),                  "jsch",        True,
     "Java JSch — often automation"),
    (re.compile(r"phpseclib"),             "phpseclib",   True,
     "phpseclib — web-driven automation"),
    (re.compile(r"putty|kitty|winscp"),    "putty",       False,
     "PuTTY/WinSCP family — interactive Windows client"),
    (re.compile(r"dropbear"),              "dropbear",    False,
     "Dropbear — embedded/legit but also pivot boxes"),
    (re.compile(r"openssh"),               "openssh",     False,
     "OpenSSH — interactive client or a pivot through a real box"),
]


def classify_ssh_client(banner: Optional[str]) -> dict:
    """Classify an SSH client from its version banner.

    Returns:
        tool        slug ("openssh", "paramiko", "mirai", ...) or "unknown"
        automated   bool — True if the tool is overwhelmingly non-interactive
        note        short human description
        product     parsed "comments" portion after the version, if any
    """
    out = {"tool": "unknown", "automated": None, "note": "", "product": None}
    if not banner:
        return out
    b = banner.strip()
    low = b.lower()

    # Try to split SSH-2.0-<softwareversion> <comments>
    m = re.match(r"ssh-\d+\.\d+-(\S+)(?:\s+(.*))?$", low)
    if m:
        out["product"] = m.group(1)

    for rx, slug, is_bot, note in _SSH_CLIENT_RULES:
        if rx.search(low):
            out["tool"] = slug
            out["automated"] = is_bot
            out["note"] = note
            return out
    return out


# ---------------------------------------------------------------------------
# HTTP user-agent classification (lightweight bucket)
# ---------------------------------------------------------------------------
_UA_RULES: list[tuple[re.Pattern, str, bool]] = [
    (re.compile(r"l9explore|nuclei|projectdiscovery"), "nuclei",      True),
    (re.compile(r"sqlmap"),                            "sqlmap",      True),
    (re.compile(r"nikto"),                             "nikto",       True),
    (re.compile(r"wpscan"),                            "wpscan",      True),
    (re.compile(r"acunetix|netsparker|qualys|nessus"), "vuln-scanner",True),
    (re.compile(r"masscan|zgrab|zmap"),                "mass-scanner",True),
    (re.compile(r"censys|shodan|internetmeasurement|stretchoid|paloalto|leakix|onyphe|binaryedge"),
                                                       "recon-service", True),
    (re.compile(r"curl"),                              "curl",        True),
    (re.compile(r"wget"),                              "wget",        True),
    (re.compile(r"python-requests|python-urllib|aiohttp|httpx"), "python", True),
    (re.compile(r"go-http-client"),                    "go-http",     True),
    (re.compile(r"powershell|winhttp"),               "powershell",  True),
    (re.compile(r"\b(bot|spider|crawl)\b"),            "crawler",     True),
    (re.compile(r"chrome/|firefox/|safari/|edg/|edge/"), "browser",   False),
]


def classify_user_agent(ua: Optional[str]) -> dict:
    out = {"ua_class": "unknown", "automated": None}
    if not ua:
        out["ua_class"] = "empty"
        out["automated"] = True   # no UA at all is itself a tell
        return out
    low = ua.lower()
    for rx, slug, is_bot in _UA_RULES:
        if rx.search(low):
            out["ua_class"] = slug
            out["automated"] = is_bot
            return out
    return out


# ---------------------------------------------------------------------------
# Glue
# ---------------------------------------------------------------------------
def tag_event(ip: str,
              geo: Optional[dict] = None,
              *,
              ssh_banner: Optional[str] = None,
              user_agent: Optional[str] = None) -> dict:
    """Produce a flat ``intel`` dict for embedding in an event's ``data``.

    Only includes sub-dicts for the signals actually present, so SSH events
    don't carry empty UA fields and vice-versa. Always safe to call.
    """
    intel: dict = {}
    try:
        src = classify_source(ip, geo)
        if src.get("infra") or src.get("provider"):
            intel["source"] = src
        if ssh_banner is not None:
            c = classify_ssh_client(ssh_banner)
            if c["tool"] != "unknown":
                intel["ssh_client"] = c
        if user_agent is not None:
            u = classify_user_agent(user_agent)
            if u["ua_class"] not in ("unknown",):
                intel["http_client"] = u
        # A single convenience flag: is this almost certainly automated?
        automated_votes = [
            intel.get("ssh_client", {}).get("automated"),
            intel.get("http_client", {}).get("automated"),
        ]
        if any(v is True for v in automated_votes):
            intel["automated"] = True
        elif all(v is False for v in automated_votes if v is not None) and automated_votes != [None, None]:
            intel["automated"] = False
    except Exception:
        return intel
    return intel
