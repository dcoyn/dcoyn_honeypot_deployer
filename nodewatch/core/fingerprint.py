"""
nodewatch.core.fingerprint
=========================

Compute JA3 and JA4 fingerprints from a raw TLS ClientHello.

This is a self-contained implementation — no external `python-ja3`
needed — so install is one less moving part. We parse only what we
need; malformed records return ``None`` rather than crashing.

References:
  JA3 - https://github.com/salesforce/ja3 (deprecated, still widely used)
  JA4 - https://github.com/FoxIO-LLC/ja4

Important:
  GREASE values (RFC 8701) must be skipped in BOTH JA3 and JA4.
"""
from __future__ import annotations

import hashlib
import struct
from typing import Optional, Tuple, List

# RFC 8701 reserved/GREASE values to ignore.
_GREASE = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}


def _u8(b: bytes, i: int)  -> Tuple[int, int]: return b[i], i + 1
def _u16(b: bytes, i: int) -> Tuple[int, int]: return struct.unpack_from(">H", b, i)[0], i + 2
def _u24(b: bytes, i: int) -> Tuple[int, int]:
    return (b[i] << 16) | (b[i+1] << 8) | b[i+2], i + 3


def parse_client_hello(record: bytes) -> Optional[dict]:
    """Parse a TLS record containing a ClientHello.

    Returns a dict with: tls_version, ciphers, extensions, sni, alpn,
    sig_algs, supported_versions, curves. ``None`` if the record isn't
    a parseable ClientHello.
    """
    try:
        if len(record) < 6 or record[0] != 0x16:  # handshake
            return None
        rec_ver, i = _u16(record, 1)
        rec_len, i = _u16(record, i)
        payload = record[i:i + rec_len]

        if not payload or payload[0] != 0x01:  # ClientHello
            return None

        i = 1
        body_len, i = _u24(payload, i)
        client_ver,  i = _u16(payload, i)
        # 32-byte random
        i += 32
        sid_len, i = _u8(payload, i)
        i += sid_len

        ciphers_len, i = _u16(payload, i)
        ciphers: List[int] = []
        for j in range(0, ciphers_len, 2):
            c = struct.unpack_from(">H", payload, i + j)[0]
            if c not in _GREASE:
                ciphers.append(c)
        i += ciphers_len

        comp_len, i = _u8(payload, i)
        i += comp_len

        if i >= len(payload):
            return {"tls_version": client_ver, "ciphers": ciphers,
                    "extensions": [], "sni": None, "alpn": [],
                    "sig_algs": [], "supported_versions": [], "curves": []}

        ext_total_len, i = _u16(payload, i)
        ext_end = i + ext_total_len

        extensions: List[int] = []
        sni: Optional[str] = None
        alpn: List[str] = []
        sig_algs: List[int] = []
        supported_versions: List[int] = []
        curves: List[int] = []

        while i < ext_end:
            etype, i = _u16(payload, i)
            elen, i  = _u16(payload, i)
            edata = payload[i:i + elen]
            i += elen
            if etype in _GREASE:
                continue
            extensions.append(etype)

            if etype == 0x0000 and len(edata) > 5:  # SNI
                # server_name list
                try:
                    list_len = struct.unpack_from(">H", edata, 0)[0]
                    name_type = edata[2]
                    name_len  = struct.unpack_from(">H", edata, 3)[0]
                    sni = edata[5:5 + name_len].decode("ascii", "replace")
                except Exception:
                    sni = None
            elif etype == 0x0010:  # ALPN
                try:
                    j = 2
                    while j < len(edata):
                        ln = edata[j]; j += 1
                        alpn.append(edata[j:j+ln].decode("ascii", "replace"))
                        j += ln
                except Exception:
                    pass
            elif etype == 0x000D:  # signature_algorithms
                try:
                    ln = struct.unpack_from(">H", edata, 0)[0]
                    for k in range(0, ln, 2):
                        sig_algs.append(struct.unpack_from(">H", edata, 2 + k)[0])
                except Exception:
                    pass
            elif etype == 0x002B:  # supported_versions
                try:
                    ln = edata[0]
                    for k in range(0, ln, 2):
                        v = struct.unpack_from(">H", edata, 1 + k)[0]
                        if v not in _GREASE:
                            supported_versions.append(v)
                except Exception:
                    pass
            elif etype == 0x000A:  # supported_groups (curves)
                try:
                    ln = struct.unpack_from(">H", edata, 0)[0]
                    for k in range(0, ln, 2):
                        v = struct.unpack_from(">H", edata, 2 + k)[0]
                        if v not in _GREASE:
                            curves.append(v)
                except Exception:
                    pass

        return {
            "tls_version": client_ver,
            "ciphers": ciphers,
            "extensions": extensions,
            "sni": sni,
            "alpn": alpn,
            "sig_algs": sig_algs,
            "supported_versions": supported_versions,
            "curves": curves,
        }
    except Exception:
        return None


def compute_ja3(parsed: dict) -> Tuple[str, str]:
    """Returns (ja3_string, md5)."""
    parts = [
        str(parsed["tls_version"]),
        "-".join(str(c) for c in parsed["ciphers"]),
        "-".join(str(e) for e in parsed["extensions"]),
        "-".join(str(c) for c in parsed["curves"]),
        "",  # ec_point_formats: not parsed -> empty (still valid JA3)
    ]
    s = ",".join(parts)
    return s, hashlib.md5(s.encode()).hexdigest()


def compute_ja4(parsed: dict, is_quic: bool = False) -> str:
    """Compute a JA4 client fingerprint.

    Format:  ``q|t`` + tls_version(2) + sni(d|i) + ccount(2)
            + ecount(2) + alpn_first2 + "_" + cipher_hash12 + "_" + ext_hash12

    Where:
      tls_version  highest of supported_versions (TLS 1.3 prefers ext over record)
      sni          'd' if SNI present, 'i' otherwise
      ccount       len(ciphers) capped 99
      ecount       len(extensions) capped 99
      alpn_first2  first two chars of first ALPN, or "00"
      cipher_hash  sha256(sorted ciphers hex csv) first 12 chars
      ext_hash     sha256(sorted exts excluding 0,16 hex csv + "_" + sig_algs hex csv) first 12 chars
    """
    versions = parsed["supported_versions"] or [parsed["tls_version"]]
    top = max(versions)
    ja4_vers = {
        0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3",
    }.get(top, "00")

    proto = "q" if is_quic else "t"
    sni_flag = "d" if parsed["sni"] else "i"
    ccount = min(len(parsed["ciphers"]), 99)
    # exclude SNI(0) and ALPN(16) from extension count per JA4 spec
    filtered_exts = [e for e in parsed["extensions"] if e not in (0x0000, 0x0010)]
    ecount = min(len(parsed["extensions"]), 99)  # but count uses all non-grease
    first_alpn = (parsed["alpn"][0] if parsed["alpn"] else "00")
    if len(first_alpn) >= 2:
        alpn2 = first_alpn[0] + first_alpn[-1]
    else:
        alpn2 = "00"

    cipher_csv = ",".join(f"{c:04x}" for c in sorted(parsed["ciphers"]))
    cipher_hash = hashlib.sha256(cipher_csv.encode()).hexdigest()[:12] if cipher_csv else "0" * 12

    ext_csv = ",".join(f"{e:04x}" for e in sorted(filtered_exts))
    sig_csv = ",".join(f"{s:04x}" for s in parsed["sig_algs"])
    ext_input = ext_csv + ("_" + sig_csv if sig_csv else "")
    ext_hash = hashlib.sha256(ext_input.encode()).hexdigest()[:12] if ext_input else "0" * 12

    a = f"{proto}{ja4_vers}{sni_flag}{ccount:02d}{ecount:02d}{alpn2}"
    return f"{a}_{cipher_hash}_{ext_hash}"


def fingerprint(record: bytes) -> Optional[dict]:
    parsed = parse_client_hello(record)
    if not parsed:
        return None
    ja3_str, ja3_md5 = compute_ja3(parsed)
    ja4 = compute_ja4(parsed)
    return {
        "ja3":       ja3_str,
        "ja3_hash":  ja3_md5,
        "ja4":       ja4,
        "sni":       parsed["sni"],
        "alpn":      parsed["alpn"],
        "tls_versions": parsed["supported_versions"] or [parsed["tls_version"]],
    }


# ============================================================================
# HASSH — the SSH equivalent of JA3
# ============================================================================
# HASSH fingerprints an SSH *client* (HASSHServer fingerprints a server) from
# the algorithm lists it offers in its SSH_MSG_KEXINIT packet. Two clients that
# offer the same kex / encryption / MAC / compression algorithms in the same
# order hash to the same HASSH — so the same brute-force tool, worm, or library
# is recognizable across IPs even when the version banner is spoofed.
#
#   hassh        = md5( kex ; ciphers ; macs ; compression )   [client->server]
#   hasshServer  = md5( kex ; ciphers ; macs ; compression )   [server->client]
#
# Reference: https://github.com/salesforce/hassh
#
# We parse the binary SSH KEXINIT ourselves so there is no extra dependency and
# it works from the passive sniffer's reassembled TCP stream.

_SSH_MSG_KEXINIT = 20


def parse_ssh_kexinit(stream: bytes) -> Optional[dict]:
    """Locate and parse an SSH_MSG_KEXINIT inside a reassembled TCP stream.

    The stream may begin with the ASCII version banner ("SSH-2.0-...\\r\\n")
    followed by one or more binary packets. We skip the banner, then walk
    binary packets looking for message type 20 (KEXINIT). Returns the offered
    name-lists, or ``None`` if no parseable KEXINIT is present yet.
    """
    try:
        if not stream:
            return None

        i = 0
        # Skip an optional identification string line(s) ("SSH-2.0-..." CRLF).
        # Pre-banner comment lines are allowed by RFC 4253 but rare; handle the
        # common single-banner case and any leading lines that aren't binary.
        while stream[i:i+4] == b"SSH-" or (i < len(stream) and stream[i] in (0x0d, 0x0a)):
            nl = stream.find(b"\n", i)
            if nl == -1:
                return None
            i = nl + 1
            if i >= len(stream):
                return None

        # Walk binary packets: uint32 packet_length, byte padding_length, payload
        while i + 5 <= len(stream):
            pkt_len = struct.unpack_from(">I", stream, i)[0]
            if pkt_len < 2 or pkt_len > 35000:
                return None  # not a sane SSH packet boundary
            if i + 4 + pkt_len > len(stream):
                return None  # need more bytes (handshake not fully reassembled)
            pad_len = stream[i + 4]
            payload = stream[i + 5 : i + 4 + pkt_len - pad_len]
            i = i + 4 + pkt_len

            if not payload:
                continue
            if payload[0] != _SSH_MSG_KEXINIT:
                continue  # some other packet; keep scanning

            # KEXINIT body: msg(1) + cookie(16) + 10 name-lists + first_kex(1) + reserved(4)
            j = 1 + 16
            names: List[List[str]] = []
            for _ in range(10):
                if j + 4 > len(payload):
                    return None
                ln = struct.unpack_from(">I", payload, j)[0]
                j += 4
                raw = payload[j:j + ln]
                j += ln
                names.append(raw.decode("ascii", "replace").split(",") if raw else [])

            return {
                "kex":              names[0],
                "server_host_key":  names[1],
                "enc_c2s":          names[2],
                "enc_s2c":          names[3],
                "mac_c2s":          names[4],
                "mac_s2c":          names[5],
                "cmp_c2s":          names[6],
                "cmp_s2c":          names[7],
                "lang_c2s":         names[8],
                "lang_s2c":         names[9],
            }
        return None
    except Exception:
        return None


def compute_hassh(parsed: dict, server: bool = False) -> Tuple[str, str]:
    """Compute (hassh_algorithms_string, md5) from a parsed KEXINIT.

    ``server=False`` -> client HASSH (uses c2s lists);
    ``server=True``  -> server HASSH (uses s2c lists).
    """
    if server:
        enc, mac, cmp = parsed["enc_s2c"], parsed["mac_s2c"], parsed["cmp_s2c"]
    else:
        enc, mac, cmp = parsed["enc_c2s"], parsed["mac_c2s"], parsed["cmp_c2s"]
    algos = ";".join([
        ",".join(parsed["kex"]),
        ",".join(enc),
        ",".join(mac),
        ",".join(cmp),
    ])
    return algos, hashlib.md5(algos.encode()).hexdigest()


def ssh_fingerprint(stream: bytes) -> Optional[dict]:
    """Parse a reassembled SSH stream and return a HASSH client fingerprint."""
    parsed = parse_ssh_kexinit(stream)
    if not parsed:
        return None
    algos, md5 = compute_hassh(parsed, server=False)
    return {
        "hassh":            md5,
        "hassh_algorithms": algos,
        "kex":              parsed["kex"],
        "ciphers":          parsed["enc_c2s"],
        "macs":             parsed["mac_c2s"],
        "compression":      parsed["cmp_c2s"],
        "server_host_key_algos": parsed["server_host_key"],
    }
