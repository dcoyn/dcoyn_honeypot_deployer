"""
sensors.win_sensor
=====================================

Looks like a Windows Server in production: lots of ports open, each
with a plausible banner that nudges scanners into showing their hand.

We don't actually implement these protocols (that's a project-sized
endeavour). We:
  * Accept the TCP connection.
  * Emit the banner real Windows services emit on connect, when there
    is one.
  * Read up to N bytes from the attacker, log them base64-encoded.
  * Optionally emit a second canned response so SMB / RDP scanners get
    enough to fingerprint us as Windows.

Ports we open (tunable):

  135   RPC / DCE             — small "ncacn_ip_tcp ready" greeting
  139   NetBIOS Session       — silent, just absorb bytes
  445   SMB                   — return a fake SMB Negotiate response
  1433  MSSQL                 — TDS pre-login response
  3389  RDP                   — return X.224 connection confirm
  5985  WinRM HTTP            — IIS 10 banner
  5986  WinRM HTTPS           — TLS-then-banner
  47001 WinRM legacy
  49152 dynamic RPC

If our packet capture sidecar is running, it captures the raw flow at
layer 4 too, so we have both protocol-level interpretation here and
ground-truth pcap data alongside.
"""
from __future__ import annotations

import base64
import socket
import socketserver
import struct
import threading
import time

from ..config import Config
from ..core import logger as L
from ..core.logger import EventType
from ..core.session import TRACKER
from ..core.enrichment import enrich
from ..core import threat_intel as TI

READ_BUDGET = 8192   # bytes we will accept per connection
READ_TIMEOUT = 5.0


# ---------------------------------------------------------------- responses
def _smb2_negotiate_response() -> bytes:
    """Minimal-ish SMB2 NegotiateProtocol response.

    Not a real handshake — just enough binary that nmap / metasploit
    fingerprint us as a Windows SMB server worth probing.
    """
    # SMB2 header (64 bytes) + tiny body
    proto   = b"\xfeSMB"
    header  = struct.pack("<HHIHHIIQI4sQ16s",
                          64, 0, 0, 0, 0, 0, 0, 0, 0, b"\x00"*4, 0, b"\x00"*16)
    # Body: StructureSize(65) + SecurityMode + Dialect(0x0311 -> 3.1.1) + ...
    body    = struct.pack("<HHHH16sIIIIIQQHHI",
                          65,           # struct size
                          0x0001,       # security mode = signing enabled
                          0x0311,       # dialect 3.1.1
                          0,            # ctx count
                          b"\x00"*16,   # server GUID
                          0x00000007,   # capabilities
                          65536,        # max transact
                          65536,        # max read
                          65536,        # max write
                          0,            # system time hi
                          0,            # boot time
                          0, 0, 0, 0)   # offsets + ctx
    payload = proto + header + body
    # NetBIOS framing: 4-byte length prefix (type=0, length high+low)
    return struct.pack(">I", len(payload)) + payload


def _rdp_connection_confirm() -> bytes:
    """X.224 Connection Confirm — RDP scanners trip on this.

    TPKT header (4) + COTP CC (7) + RDP Negotiation Response (8).
    """
    rdp_neg_resp = struct.pack("<BBHI", 0x02, 0x00, 0x0008, 0x00000002)  # type, flags, len, RDP+TLS
    cotp = struct.pack(">BBBHHB", 0x0E, 0xD0, 0x00, 0x00, 0x12, 0x34) + rdp_neg_resp
    tpkt = struct.pack(">BBH", 0x03, 0x00, len(cotp) + 4) + cotp
    return tpkt


def _mssql_prelogin_response() -> bytes:
    """TDS pre-login response advertising SQL Server 2019."""
    # TDS header (8) + tokens
    tokens = (
        b"\x00\x00\x1f\x00\x06"            # VERSION token offset/len
        b"\x01\x00\x21\x00\x01"            # ENCRYPTION token
        b"\x02\x00\x22\x00\x01"            # INSTOPT
        b"\x03\x00\x23\x00\x04"            # THREADID
        b"\xff"                            # terminator
        b"\x0f\x00\x07\xd0\x00\x00"        # version 15.0.2000
        b"\x02"                            # not supported encryption
        b"\x00"                            # no instance
        b"\x00\x00\x00\x00"                # thread id
    )
    header = struct.pack(">BBHHBB",
                         0x04, 0x01,        # type=tabular result, status=end
                         8 + len(tokens),   # length
                         0x0000, 0x01, 0x00)
    return header + tokens


def _winrm_banner() -> bytes:
    return (
        b"HTTP/1.1 404 Not Found\r\n"
        b"Content-Type: text/html; charset=us-ascii\r\n"
        b"Server: Microsoft-HTTPAPI/2.0\r\n"
        b"Date: " + time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()).encode() + b"\r\n"
        b"Connection: close\r\n"
        b"Content-Length: 315\r\n"
        b"\r\n"
        b"<!DOCTYPE HTML><html><head><title>Not Found</title></head>"
        b"<body><h2>Not Found</h2></body></html>"
    )


# Map of dst_port -> (greeting bytes, label)
PORT_PROFILES = {
    135:   (b"",                          "MSRPC"),
    139:   (b"",                          "NetBIOS-SSN"),
    445:   (_smb2_negotiate_response(),   "SMB"),
    1433:  (_mssql_prelogin_response(),   "MSSQL"),
    3389:  (_rdp_connection_confirm(),    "RDP"),
    5985:  (_winrm_banner(),              "WinRM-HTTP"),
    47001: (_winrm_banner(),              "WinRM-Compat"),
    49152: (b"",                          "RPC-Dynamic"),
}


# ----------------------------------------------------------------- handler
class _PortHandler(socketserver.BaseRequestHandler):
    # Each instance is created with a 'dst_port' attribute by the factory below
    dst_port: int = 0
    label: str = ""

    def handle(self):
        sock = self.request
        src_ip, src_port = self.client_address[0], self.client_address[1]
        sid = TRACKER.get(src_ip)

        geo = enrich(src_ip)
        L.get().emit(
            EventType.WIN_PROBE,
            src_ip=src_ip, src_port=src_port, dst_port=self.dst_port,
            session_id=sid,
            data={"service": self.label, "geo": geo,
                  "intel": TI.tag_event(src_ip, geo)},
        )

        sock.settimeout(READ_TIMEOUT)
        greeting = PORT_PROFILES.get(self.dst_port, (b"", "unknown"))[0]
        try:
            if greeting:
                sock.sendall(greeting)
        except Exception:
            return

        # Read up to READ_BUDGET bytes, in chunks, logging each
        remaining = READ_BUDGET
        chunks = []
        try:
            while remaining > 0:
                data = sock.recv(min(4096, remaining))
                if not data:
                    break
                chunks.append(data)
                remaining -= len(data)
                if remaining <= 0:
                    break
        except (socket.timeout, ConnectionResetError, OSError):
            pass

        if chunks:
            payload = b"".join(chunks)
            L.get().emit(
                EventType.WIN_PAYLOAD,
                src_ip=src_ip, src_port=src_port, dst_port=self.dst_port,
                session_id=sid,
                data={
                    "service":   self.label,
                    "byte_len":  len(payload),
                    "payload_b64": base64.b64encode(payload).decode(),
                    "preview":   payload[:64].hex(),
                },
            )

        try: sock.close()
        except Exception: pass


def _make_handler(port: int, label: str):
    return type(
        f"H_{port}",
        (_PortHandler,),
        {"dst_port": port, "label": label},
    )


class _ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(host: str = "0.0.0.0") -> None:
    cfg = Config.load()
    L.configure(cfg.log_dir, cfg.node_name, "winserver")
    L.get().emit(EventType.NODE_START, src_ip="0.0.0.0",
                 data={"role": "winserver_sensor",
                       "ports": sorted(PORT_PROFILES.keys())})

    servers = []
    for port, (_, label) in PORT_PROFILES.items():
        try:
            srv = _ThreadedTCPServer((host, port), _make_handler(port, label))
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            servers.append((port, srv, t))
        except OSError as e:
            L.get().emit(EventType.NODE_START, src_ip="0.0.0.0",
                         data={"warning": f"could not bind {port}: {e}"})

    # Park
    try:
        while True:
            time.sleep(60)
            L.get().heartbeat()
    except KeyboardInterrupt:
        for _, srv, _ in servers:
            srv.shutdown()


if __name__ == "__main__":
    serve()
