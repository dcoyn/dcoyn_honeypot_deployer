"""
nodewatch.core.canary
======================

Intelligence extraction for canary-beacon callbacks — the moment an attacker
*opens* a bait document we let them exfiltrate. This is the highest-value
signal the fileshare honeypot produces: the beacon fires from the attacker's
real machine, frequently on a different network than the one that downloaded
the file, and it can leak Windows domain credentials.

Everything here is pure parsing of data we already receive. No network calls,
no execution. Every function is total — malformed input returns an empty or
neutral result, never an exception, so it is safe on the request hot path.

Four capabilities:

  * NTLM capture (`build_ntlm_challenge`, `parse_ntlm_authorization`)
      When a Windows WebClient/Office fetches a WebDAV-looking external
      reference and we answer 401 WWW-Authenticate: NTLM, Windows replies with
      NTLMSSP Type 1 then Type 3 messages. These carry, IN CLEARTEXT, the
      victim's domain, username, workstation hostname, and Windows build —
      plus a NetNTLMv2 response that an operator can crack offline. This is the
      "Windows folder / WebDAV" canarytoken technique implemented over plain
      HTTP, no SMB server required.

  * Office build → patch-level inference (`infer_office_channel`)
      Office click-to-run build numbers map to an update channel and roughly
      how recently the box was patched — i.e. how soft a target it is.

  * Proxy-chain unmasking (`extract_proxy_chain`)
      Pulls every forwarded-for-style header to reveal hops in front of the
      opener and the apparent true origin behind a proxy/CDN.

  * Opener classification (`classify_opener`)
      Human-open vs automated detonation (AV / cloud sandbox) heuristic.

References:
  MS-NLMP (NTLM) — https://learn.microsoft.com/openspecs/windows_protocols/ms-nlmp/
  Canarytokens WebDAV token — https://docs.canarytokens.org/
"""
from __future__ import annotations

import base64
import os
import struct
from typing import Optional


# ===========================================================================
# NTLM (MS-NLMP)
# ===========================================================================
_NTLMSSP_SIG = b"NTLMSSP\x00"

# A handful of NEGOTIATE flag bits we care to report.
_FLAGS = {
    0x00000001: "UNICODE",
    0x00000002: "OEM",
    0x00000200: "NTLM",
    0x00008000: "ALWAYS_SIGN",
    0x00080000: "EXTENDED_SESSIONSECURITY",
    0x00200000: "TARGET_INFO",
    0x02000000: "VERSION",
    0x20000000: "SEAL",
    0x40000000: "KEY_EXCH",
    0x80000000: "NEGOTIATE_56",
}

# AV_PAIR ids inside the NTLMv2 target-info blob (cleartext network context).
_AV_IDS = {
    1: "av_nb_computer",      # NetBIOS computer name
    2: "av_nb_domain",        # NetBIOS domain name
    3: "av_dns_computer",     # DNS computer (FQDN)
    4: "av_dns_domain",       # DNS domain
    5: "av_dns_tree",         # DNS forest/tree
}


def build_ntlm_challenge(server_challenge: Optional[bytes] = None,
                         target_name: str = "WORKGROUP") -> str:
    """Build a base64 NTLMSSP Type 2 (CHALLENGE) message to send back in a
    ``WWW-Authenticate: NTLM <b64>`` header. The 8-byte ``server_challenge`` is
    what makes the client's Type 3 NetNTLMv2 response crackable; if not given
    we pick a fixed, well-known value so captured hashes are easy to feed to a
    cracker with a known challenge.
    """
    chal = server_challenge or b"\x11\x22\x33\x44\x55\x66\x77\x88"
    chal = (chal + b"\x00" * 8)[:8]
    tn = target_name.encode("utf-16-le")
    flags = 0x00000001 | 0x00000200 | 0x00080000 | 0x00200000 | 0x02000000  # UNICODE|NTLM|ESS|TARGETINFO|VERSION
    # Minimal target info: just a NetBIOS domain AV pair + terminator
    av = struct.pack("<HH", 2, len(tn)) + tn + struct.pack("<HH", 0, 0)
    # Layout offsets (header is 56 bytes with version)
    base = 56
    target_off = base
    ti_off = base + len(tn)
    msg = bytearray()
    msg += _NTLMSSP_SIG
    msg += struct.pack("<I", 2)                                  # type 2
    msg += struct.pack("<HHI", len(tn), len(tn), target_off)     # TargetName fields
    msg += struct.pack("<I", flags)                              # flags
    msg += chal                                                  # 8-byte challenge
    msg += b"\x00" * 8                                           # reserved
    msg += struct.pack("<HHI", len(av), len(av), ti_off)         # TargetInfo fields
    msg += struct.pack("<BBHBBBB", 10, 0, 19041, 0, 0, 0, 15)    # version: Win10 build 19041
    msg += tn
    msg += av
    return base64.b64encode(bytes(msg)).decode()


def _read_field(buf: bytes, off: int) -> Optional[bytes]:
    """Read a security-buffer (len, maxlen, offset) at ``off`` and return the
    referenced bytes, or None."""
    try:
        ln, _maxln, ptr = struct.unpack_from("<HHI", buf, off)
        if ln == 0 or ptr + ln > len(buf):
            return None
        return buf[ptr:ptr + ln]
    except Exception:
        return None


def _decode_name(raw: Optional[bytes], unicode: bool) -> Optional[str]:
    if not raw:
        return None
    try:
        return raw.decode("utf-16-le" if unicode else "latin-1", "replace") or None
    except Exception:
        return None


def _parse_version(buf: bytes, off: int) -> Optional[str]:
    try:
        if off + 8 > len(buf):
            return None
        major, minor, build = struct.unpack_from("<BBH", buf, off)
        if major == 0 and minor == 0 and build == 0:
            return None
        return f"{major}.{minor}.{build}"
    except Exception:
        return None


def _parse_av_pairs(blob: bytes) -> dict:
    """Walk the NTLMv2 target-info AV_PAIR list (cleartext domain/host names)."""
    out: dict = {}
    i = 0
    try:
        while i + 4 <= len(blob):
            av_id, av_len = struct.unpack_from("<HH", blob, i)
            i += 4
            if av_id == 0:  # MsvAvEOL
                break
            val = blob[i:i + av_len]
            i += av_len
            key = _AV_IDS.get(av_id)
            if key and val:
                out[key] = val.decode("utf-16-le", "replace")
    except Exception:
        pass
    return out


def parse_ntlm_authorization(header_value: Optional[str]) -> dict:
    """Parse an ``Authorization: NTLM/Negotiate <base64>`` header.

    Returns a dict describing whichever NTLMSSP message it is. For a Type 3
    (Authenticate) message the cleartext ``domain``, ``username`` and
    ``workstation`` are the prize. The ``netntlmv2`` field (when present) is a
    Hashcat-mode-5600 string the operator can attempt to crack offline against
    our fixed server challenge.
    """
    out: dict = {}
    if not header_value:
        return out
    try:
        parts = header_value.strip().split(None, 1)
        if len(parts) != 2 or parts[0].lower() not in ("ntlm", "negotiate"):
            return out
        raw = base64.b64decode(parts[1] + "===", validate=False)
    except Exception:
        return out

    if not raw.startswith(_NTLMSSP_SIG):
        # Negotiate/SPNEGO wrapper (GSS) — try to find the embedded NTLMSSP
        idx = raw.find(_NTLMSSP_SIG)
        if idx == -1:
            out["ntlm_scheme"] = parts[0].lower()
            return out
        raw = raw[idx:]

    try:
        mtype = struct.unpack_from("<I", raw, 8)[0]
    except Exception:
        return out
    out["ntlm_message_type"] = mtype

    try:
        if mtype == 1:  # NEGOTIATE
            flags = struct.unpack_from("<I", raw, 12)[0]
            uni = bool(flags & 0x00000001)
            out["ntlm_negotiate_flags"] = [n for b, n in _FLAGS.items() if flags & b]
            out["domain"]      = _decode_name(_read_field(raw, 16), uni)
            out["workstation"] = _decode_name(_read_field(raw, 24), uni)
            ver = _parse_version(raw, 32)
            if ver:
                out["opener_os_build"] = ver
        elif mtype == 3:  # AUTHENTICATE — the credential leak
            flags = struct.unpack_from("<I", raw, 60)[0]
            uni = bool(flags & 0x00000001)
            out["ntlm_negotiate_flags"] = [n for b, n in _FLAGS.items() if flags & b]
            lm_resp  = _read_field(raw, 12)
            nt_resp  = _read_field(raw, 20)
            out["domain"]      = _decode_name(_read_field(raw, 28), uni)
            out["username"]    = _decode_name(_read_field(raw, 36), uni)
            out["workstation"] = _decode_name(_read_field(raw, 44), uni)
            ver = _parse_version(raw, 64)
            if ver:
                out["opener_os_build"] = ver
            # NTLMv2 responses are > 24 bytes and carry an AV_PAIR target-info
            # blob (cleartext domain/host names) starting at offset 44 of the
            # NT response.
            if nt_resp and len(nt_resp) > 24:
                out["ntlm_version"] = "NTLMv2"
                ti = nt_resp[44:]
                av = _parse_av_pairs(ti)
                if av:
                    out["ntlm_target_info"] = av
                # Build a Hashcat -m 5600 NetNTLMv2 line for offline cracking.
                user = out.get("username") or ""
                dom = out.get("domain") or ""
                nt_hex = nt_resp.hex()
                # format: user::domain:serverchallenge:NTproofstr:rest
                server_chal = "1122334455667788"  # matches build_ntlm_challenge default
                nt_proof = nt_hex[:32]
                rest = nt_hex[32:]
                out["netntlmv2"] = f"{user}::{dom}:{server_chal}:{nt_proof}:{rest}"
                out["netntlmv2_hashcat_mode"] = 5600
            elif nt_resp:
                out["ntlm_version"] = "NTLMv1"
                if lm_resp:
                    out["ntlmv1_lm_hex"] = lm_resp.hex()
                out["ntlmv1_nt_hex"] = nt_resp.hex()
    except Exception:
        pass
    # Drop empty keys for clean events
    return {k: v for k, v in out.items() if v not in (None, [], {}, "")}


# ===========================================================================
# Office build → channel / patch recency
# ===========================================================================
# Build major.minor.BUILD; the BUILD number tracks the monthly release train.
# We map a few anchor builds and interpolate "older/newer than" so the operator
# learns roughly how stale the opener's Office install is.
_OFFICE_BUILD_ANCHORS = [
    (16827, "2024-01"), (17029, "2024-05"), (17328, "2024-09"),
    (17531, "2025-01"), (17730, "2025-05"), (17928, "2025-09"),
    (18129, "2026-01"),
]


def infer_office_channel(version: Optional[str]) -> dict:
    """Given an Office version like '16.0.17328.20162', estimate patch recency."""
    out: dict = {}
    if not version:
        return out
    try:
        nums = [int(x) for x in version.split(".") if x.isdigit()]
    except Exception:
        return out
    build = next((n for n in nums if n > 1000), None)
    if build is None:
        return out
    out["office_build"] = build
    # Find the closest anchor
    approx = None
    for b, label in _OFFICE_BUILD_ANCHORS:
        if build >= b:
            approx = label
    if approx:
        out["office_patch_era"] = approx
        # crude staleness flag against the newest anchor
        newest = _OFFICE_BUILD_ANCHORS[-1][0]
        if build < newest - 600:  # ~roughly a year behind
            out["office_likely_unpatched"] = True
    return out


# ===========================================================================
# Proxy chain unmasking
# ===========================================================================
_FWD_HEADERS = [
    "X-Forwarded-For", "Forwarded", "X-Real-IP", "X-Client-IP",
    "CF-Connecting-IP", "True-Client-IP", "X-Originating-IP",
    "Fastly-Client-IP", "X-Cluster-Client-IP", "Via",
]


def extract_proxy_chain(headers: dict, peer_ip: str = "") -> dict:
    """Reveal proxy/CDN hops in front of the opener and the apparent origin."""
    out: dict = {}
    found = {}
    for h in _FWD_HEADERS:
        for k, v in headers.items():
            if k.lower() == h.lower() and v:
                found[h] = v[:512]
    if not found:
        return out
    out["proxy_headers"] = found
    # The left-most IP in X-Forwarded-For is usually the real client.
    xff = found.get("X-Forwarded-For") or found.get("Forwarded")
    if xff:
        first = xff.split(",")[0].strip().replace("for=", "").strip('"[]')
        if first and first != peer_ip:
            out["apparent_origin_ip"] = first
    out["behind_proxy"] = True
    return out


# ===========================================================================
# Opener classification: human vs automated detonation
# ===========================================================================
def classify_opener(*, user_agent: str = "",
                    accept_language: str = "",
                    seconds_since_download: Optional[float] = None,
                    opener_infra: Optional[str] = None,
                    method: str = "GET",
                    range_request: bool = False) -> dict:
    """Heuristic: did a human open the doc, or did an AV / cloud sandbox
    auto-detonate it? Returns ``opener_kind`` and the reasons behind it.

    Strong sandbox tells: fetched from cloud/hosting infra, within seconds of
    download, no Accept-Language, HEAD/Range-only, or a scanning UA.
    """
    reasons: list[str] = []
    score = 0  # positive => automated
    ua = (user_agent or "").lower()

    if opener_infra in ("cloud", "hosting"):
        score += 2; reasons.append("opened from datacenter/cloud infra")
    if seconds_since_download is not None and seconds_since_download <= 20:
        score += 2; reasons.append(f"opened {seconds_since_download:.0f}s after download")
    if not accept_language:
        score += 1; reasons.append("no Accept-Language (uncommon for real Office)")
    if method.upper() == "HEAD" or range_request:
        score += 1; reasons.append("HEAD/Range fetch (scanner-like)")
    for tell in ("forcepoint", "proofpoint", "barracuda", "mimecast", "trend",
                 "symantec", "mcafee", "fireeye", "paloalto", "bitdefender",
                 "virustotal", "wepawet", "cuckoo", "any.run", "joesandbox"):
        if tell in ua:
            score += 3; reasons.append(f"AV/sandbox UA token: {tell}")
            break

    if score >= 3:
        kind = "automated_detonation"
    elif score >= 1:
        kind = "uncertain"
    else:
        kind = "likely_human"
    return {"opener_kind": kind, "opener_signal_score": score,
            "opener_reasons": reasons}
