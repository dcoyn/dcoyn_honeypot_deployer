"""
sensors.rdp_sensor
==================

A medium-interaction **RDP / Windows Terminal Services** honeypot on port 3389.

RDP is the single most brute-forced service on the internet — every exposed
3389 gets a relentless stream of credential-stuffing and CVE scanning. Even
before any login, the RDP connection handshake leaks valuable attribution data
that we capture here:

  * the **mstshash cookie** in the X.224 Connection Request — this is the
    username (often ``DOMAIN\\user``) the attacker's client is configured to
    log in as, sent in the clear before any auth;
  * the **requested security** (standard RDP / TLS / CredSSP-NLA / RDSTLS),
    which tells us whether it's a modern client or an old scanner;
  * the **client hostname, build number and keyboard layout** from the MCS
    Connect-Initial GCC client-core block (TS_UD_CS_CORE), also pre-auth.

We implement just the negotiation: parse the X.224 Connection Request, answer
with a Connection Confirm offering standard RDP security (so the client sends
its MCS/GCC client data, which we parse), and then record and disconnect. No
RDP crypto, no session — it's the pre-auth recon data that's the prize, and
it's captured without ever completing a connection.

References:
  MS-RDPBCGR (RDP Basic Connectivity & Graphics Remoting)
"""
from __future__ import annotations

import socket
import socketserver
import struct
import time

from ..config import Config
from ..core import logger as L
from ..core.logger import EventType
from ..core.session import TRACKER
from ..core.enrichment import enrich
from ..core import threat_intel as TI

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 3389
READ_TIMEOUT = 15.0
MAX_PDU = 8192

# requestedProtocols bit flags (MS-RDPBCGR 2.2.1.1.1)
_PROTO_FLAGS = {
    0x00000000: "RDP",            # standard RDP security
    0x00000001: "TLS",           # TLS 1.x
    0x00000002: "CredSSP/NLA",   # Network Level Authentication
    0x00000004: "RDSTLS_EARLY",
    0x00000008: "RDSTLS",
    0x00000010: "CredSSP_RDP",
}


def _decode_protocols(val: int) -> list[str]:
    if val == 0:
        return ["RDP"]
    out = [name for bit, name in _PROTO_FLAGS.items() if bit and (val & bit)]
    return out or [f"unknown(0x{val:08x})"]


# --------------------------------------------------------------- TPKT / X.224
def _recv_tpkt(sock_file) -> bytes | None:
    """Read one TPKT-framed PDU. TPKT header = ver(1)=3, rsvd(1), len(2 BE)."""
    hdr = sock_file.read(4)
    if len(hdr) < 4 or hdr[0] != 0x03:
        return None
    total = struct.unpack(">H", hdr[2:4])[0]
    body = sock_file.read(max(0, total - 4))
    return hdr + body


def _parse_connection_request(pdu: bytes) -> dict:
    """Parse a TPKT+X.224 Connection Request. Extract the mstshash cookie and
    the optional RDP Negotiation Request (requested protocols)."""
    out: dict = {}
    try:
        x224 = pdu[4:]                       # strip TPKT header
        # X.224 CR: len(1), type(1)=0xE0, dst(2), src(2), class(1), then data
        if len(x224) < 7 or x224[1] != 0xE0:
            return out
        data = x224[7:]
        # routing/cookie token is ASCII terminated by \r\n
        if data[:8] == b"Cookie: ":
            end = data.find(b"\r\n")
            cookie = data[8:end if end != -1 else len(data)].decode("latin-1", "replace")
            out["rdp_cookie"] = cookie[:256]
            if cookie.lower().startswith("mstshash="):
                out["mstshash_user"] = cookie[len("mstshash="):][:256]
            data = data[(end + 2):] if end != -1 else b""
        elif data[:3] == b"\x03\x00\x00":
            pass
        # RDP Negotiation Request: type(1)=0x01, flags(1), length(2 LE)=8, proto(4 LE)
        idx = data.find(b"\x01")
        # be defensive: look for an 8-byte negReq starting with 0x01
        for off in range(0, max(0, len(data) - 7)):
            if data[off] == 0x01:
                try:
                    _t, _flags, _len, proto = struct.unpack_from("<BBHI", data, off)
                    if _len == 8:
                        out["requested_protocols_raw"] = proto
                        out["requested_protocols"] = _decode_protocols(proto)
                        out["nla_required"] = bool(proto & 0x00000002)
                        break
                except Exception:
                    continue
    except Exception:
        pass
    return out


def _build_connection_confirm(selected_proto: int = 0) -> bytes:
    """TPKT + X.224 Connection Confirm + RDP Negotiation Response selecting a
    protocol (0 = standard RDP, so the client proceeds to send MCS/GCC data)."""
    # RDP Negotiation Response: type(1)=0x02, flags(1), length(2 LE)=8, selectedProto(4 LE)
    neg = struct.pack("<BBHI", 0x02, 0x00, 8, selected_proto)
    # X.224 CC: len, 0xD0, dst(2), src(2), class(1)
    x224 = struct.pack(">BBHHB", 6 + len(neg), 0xD0, 0x0000, 0x1234, 0x00) + neg
    tpkt = struct.pack(">BBH", 0x03, 0x00, 4 + len(x224)) + x224
    return tpkt


def _parse_client_core(pdu: bytes) -> dict:
    """Best-effort parse of the GCC client-core data (TS_UD_CS_CORE) embedded in
    the MCS Connect-Initial. Pulls clientName (Unicode), build and keyboard
    layout. We locate the CS_CORE block by its type marker 0xC001."""
    out: dict = {}
    try:
        i = pdu.find(b"\x01\xc0")            # CS_CORE header type (LE 0xC001)
        if i == -1:
            return out
        body = pdu[i + 4:]                   # skip type(2)+length(2)
        if len(body) < 20:
            return out
        version = struct.unpack_from("<I", body, 0)[0]
        # desktopWidth(2) height(2) colorDepth(2) sasSequence(2) keyboardLayout(4)
        keyboard_layout = struct.unpack_from("<I", body, 12)[0]
        client_build = struct.unpack_from("<I", body, 16)[0]
        # clientName: 32 bytes UTF-16LE, null-padded
        name_raw = body[20:52]
        client_name = name_raw.decode("utf-16-le", "replace").split("\x00")[0]
        out["client_build"] = client_build
        out["client_name"] = client_name[:128]
        out["keyboard_layout"] = f"0x{keyboard_layout:08x}"
        out["rdp_version_raw"] = f"0x{version:08x}"
    except Exception:
        pass
    return {k: v for k, v in out.items() if v not in (None, "", 0)}


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        src_ip, src_port = self.client_address[0], self.client_address[1]
        sid = TRACKER.get(src_ip)
        start = time.monotonic()
        geo = enrich(src_ip)

        L.get().emit(
            EventType.CONNECTION,
            src_ip=src_ip, src_port=src_port, dst_port=LISTEN_PORT,
            session_id=sid,
            data={"service": "rdp", "geo": geo, "intel": TI.tag_event(src_ip, geo)},
        )

        sock.settimeout(READ_TIMEOUT)
        f = sock.makefile("rwb")
        try:
            cr = _recv_tpkt(f)
            if not cr:
                return
            parsed = _parse_connection_request(cr)
            L.get().emit(
                EventType.RDP_CONNECT,
                src_ip=src_ip, src_port=src_port, dst_port=LISTEN_PORT,
                session_id=sid,
                data={"service": "rdp", "geo": geo,
                      "intel": TI.tag_event(src_ip, geo),
                      "techniques": ["T1021.001"],  # Remote Services: RDP
                      **parsed},
            )

            # Offer standard RDP security so the client sends its MCS/GCC data.
            try:
                f.write(_build_connection_confirm(0))
                f.flush()
            except Exception:
                return

            # The next PDU is the MCS Connect-Initial carrying client core data.
            mcs = _recv_tpkt(f)
            if mcs:
                core = _parse_client_core(mcs)
                if core:
                    L.get().emit(
                        EventType.RDP_CLIENT_INFO,
                        src_ip=src_ip, src_port=src_port, dst_port=LISTEN_PORT,
                        session_id=sid,
                        data={"service": "rdp", "geo": geo, **core},
                    )
        except Exception:
            pass
        finally:
            L.get().emit(
                EventType.RDP_CONNECT,
                src_ip=src_ip, src_port=src_port, dst_port=LISTEN_PORT,
                session_id=sid,
                data={"service": "rdp", "event": "session_end",
                      "duration_s": round(time.monotonic() - start, 3)},
            )
            try:
                f.close(); sock.close()
            except Exception:
                pass


class _ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(host: str = LISTEN_HOST, port: int = LISTEN_PORT) -> None:
    cfg = Config.load()
    if L._default is None:
        L.configure(cfg.log_dir, cfg.node_name, "rdp")
    L.get().emit(EventType.NODE_START, src_ip="0.0.0.0",
                 data={"role": "rdp_sensor", "listen_port": port})
    srv = _ThreadedTCPServer((host, port), _Handler)
    srv.serve_forever()


if __name__ == "__main__":
    serve()
