"""
sensors.ssh_shell_base
=======================

A reusable medium-interaction **SSH fake-shell harness**. The original
``ssh_sensor`` projects a Linux box; this harness factors out the paramiko
transport, auth capture, channel handling and the interactive read/execute loop
so other profiles can project a *different* operating environment over SSH
simply by supplying a "personality":

  * ESXi   — ``esxi_shell`` (esxcli / vim-cmd / esxtop, fake VMs + datastores)
  * Windows— ``win_shell``  (cmd.exe / PowerShell, fake C:\\ + tasklist + domain)

ESXi's management shell is literally SSH (dropbear/OpenSSH), and modern Windows
Server ships OpenSSH Server (default shell cmd.exe) that attackers brute-force,
so SSH is the realistic transport for capturing the commands they run on both.

The harness logs the same event types as the Linux SSH sensor — ``ssh_auth``,
``ssh_command`` (with MITRE classification), ``ssh_session_end`` — tagged with
the personality's ``service`` so the aggregator can tell them apart. Nothing is
ever executed; every command is dispatched to the personality's pure-Python
simulator.
"""
from __future__ import annotations

import os
import socketserver
import threading
import time
from pathlib import Path
from typing import Optional, Protocol

import paramiko

from ..config import Config
from ..core import logger as L
from ..core.logger import EventType
from ..core.enrichment import enrich
from ..core import threat_intel as TI
from ..core import classify as CLS


class ShellSession(Protocol):
    def prompt(self) -> str: ...
    def motd(self) -> str: ...
    def execute(self, cmd: str) -> str: ...        # return "__EXIT__" to close


class Personality:
    """Subclass and set the attributes / implement the factory."""
    ssh_banner: str = "SSH-2.0-OpenSSH_8.9"
    service: str = "ssh"
    listen_port: int = 22
    host_key_name: str = "ssh_host_rsa_key"

    def accept_auth(self, username: str, password: str) -> bool:
        # Accept common weak creds so the attacker gets a shell and we capture
        # what they do. Everything is logged regardless of acceptance.
        return True

    def make_session(self, username: str, src_ip: str, src_port: int,
                     session_id: str) -> ShellSession:
        raise NotImplementedError

    def classify(self, cmd: str) -> dict:
        """Optional per-personality classification; defaults to the shared
        ATT&CK command classifier (which still catches curl/wget/powershell/
        base64/certutil regardless of OS)."""
        return CLS.classify_command(cmd)


# ----------------------------------------------------------------------------
class _Server(paramiko.ServerInterface):
    def __init__(self, p: Personality, session_id, src_ip, src_port):
        self.p = p
        self.event = threading.Event()
        self.session_id = session_id
        self.src_ip = src_ip
        self.src_port = src_port
        self.username: Optional[str] = None
        self.start = time.monotonic()
        self._exec_for_chan: dict[int, str] = {}
        self._lock = threading.Lock()

    def get_allowed_auths(self, username): return "password,publickey"

    def check_auth_password(self, username, password):
        accepted = self.p.accept_auth(username, password)
        L.get().emit(EventType.SSH_AUTH,
                     src_ip=self.src_ip, src_port=self.src_port, dst_port=self.p.listen_port,
                     session_id=self.session_id,
                     data={"service": self.p.service, "username": username,
                           "password": password, "method": "password",
                           "accepted": accepted,
                           "latency_s": round(time.monotonic() - self.start, 4)})
        if accepted:
            self.username = username
            L.get().emit(EventType.SSH_LOGIN_OK,
                         src_ip=self.src_ip, src_port=self.src_port, dst_port=self.p.listen_port,
                         session_id=self.session_id,
                         data={"service": self.p.service, "username": username,
                               "password": password})
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        L.get().emit(EventType.SSH_AUTH,
                     src_ip=self.src_ip, src_port=self.src_port, dst_port=self.p.listen_port,
                     session_id=self.session_id,
                     data={"service": self.p.service, "username": username,
                           "method": "publickey", "accepted": False,
                           "key_type": key.get_name(),
                           "key_base64": key.get_base64()[:300]})
        return paramiko.AUTH_FAILED  # force a password so we capture it

    def check_channel_request(self, kind, chanid):
        return (paramiko.OPEN_SUCCEEDED if kind == "session"
                else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)

    def check_channel_pty_request(self, *a, **k): return True
    def check_channel_shell_request(self, channel):
        self.event.set(); return True

    def check_channel_exec_request(self, channel, command):
        cmd = command.decode("utf-8", "replace")
        L.get().emit(EventType.SSH_COMMAND,
                     src_ip=self.src_ip, src_port=self.src_port, dst_port=self.p.listen_port,
                     session_id=self.session_id,
                     data={"service": self.p.service, "command": cmd, "mode": "exec",
                           "classification": self.p.classify(cmd)})
        with self._lock:
            self._exec_for_chan[channel.get_id()] = cmd
        self.event.set(); return True

    def take_exec(self, channel) -> Optional[str]:
        with self._lock:
            return self._exec_for_chan.pop(channel.get_id(), None)


class _Handler(socketserver.BaseRequestHandler):
    personality: Personality = None  # set per-server subclass

    def handle(self):
        p = self.personality
        sock = self.request
        src_ip, src_port = self.client_address[0], self.client_address[1]
        session_id = L.get().new_session()
        ge = enrich(src_ip)
        L.get().emit(EventType.CONNECTION,
                     src_ip=src_ip, src_port=src_port, dst_port=p.listen_port,
                     session_id=session_id,
                     data={"service": p.service, "geo": ge,
                           "intel": TI.tag_event(src_ip, ge)})

        transport = paramiko.Transport(sock)
        transport.local_version = p.ssh_banner
        try:
            hk_path = os.environ.get("HP_SSH_HOST_KEY",
                                     str(Path(Config.load().data_dir) / p.host_key_name))
            host_key = paramiko.RSAKey(filename=hk_path)
        except Exception:
            host_key = paramiko.RSAKey.generate(2048)
        transport.add_server_key(host_key)
        server = _Server(p, session_id, src_ip, src_port)
        try:
            transport.start_server(server=server)
        except Exception as e:
            L.get().emit(EventType.SSH_BANNER,
                         src_ip=src_ip, src_port=src_port, dst_port=p.listen_port,
                         session_id=session_id,
                         data={"service": p.service, "error": str(e),
                               "remote_version": getattr(transport, "remote_version", "")})
            transport.close(); return

        L.get().emit(EventType.SSH_BANNER,
                     src_ip=src_ip, src_port=src_port, dst_port=p.listen_port,
                     session_id=session_id,
                     data={"service": p.service, "remote_version": transport.remote_version,
                           "intel": {"ssh_client": TI.classify_ssh_client(transport.remote_version)}})

        chan_threads = []
        try:
            while transport.is_active():
                server.event.clear()
                chan = transport.accept(30)
                if chan is None:
                    break
                if not server.event.wait(30):
                    try: chan.close()
                    except Exception: pass
                    continue
                th = threading.Thread(target=self._serve_channel,
                                      args=(chan, server), daemon=True)
                th.start(); chan_threads.append(th)
        finally:
            for th in chan_threads:
                th.join(timeout=5)
            try: transport.close()
            except Exception: pass
            L.get().emit(EventType.SSH_SESSION_END,
                         src_ip=src_ip, src_port=src_port, dst_port=p.listen_port,
                         session_id=session_id,
                         data={"service": p.service,
                               "duration_s": round(time.monotonic() - server.start, 3),
                               "channels": len(chan_threads)})

    def _serve_channel(self, chan, server):
        try:
            self._serve_shell(chan, server)
        except Exception:
            pass
        finally:
            try: chan.close()
            except Exception: pass

    def _serve_shell(self, chan, server):
        p = self.personality
        username = server.username or "root"
        sess = p.make_session(username, server.src_ip, server.src_port, server.session_id)

        exec_cmd = server.take_exec(chan)
        if exec_cmd is not None:
            out = sess.execute(exec_cmd)
            if out == "__EXIT__":
                out = ""
            try:
                chan.send(out.replace("\n", "\r\n"))
                chan.send_exit_status(0)
            except Exception:
                pass
            return

        try:
            chan.send(sess.motd().replace("\n", "\r\n"))
            chan.send(sess.prompt())
        except Exception:
            return

        buf = bytearray()
        n = 0
        last_cr = False
        while True:
            try:
                data = chan.recv(1024)
            except Exception:
                break
            if not data:
                break
            for b in data:
                ch = bytes([b])
                if ch in (b"\r", b"\n"):
                    if ch == b"\n" and last_cr:
                        last_cr = False
                        continue
                    last_cr = (ch == b"\r")
                    chan.send(b"\r\n")
                    cmd = buf.decode("utf-8", "replace")
                    buf.clear()
                    n += 1
                    L.get().emit(EventType.SSH_COMMAND,
                                 src_ip=server.src_ip, src_port=server.src_port,
                                 dst_port=p.listen_port, session_id=server.session_id,
                                 data={"service": p.service, "command": cmd,
                                       "mode": "shell", "seq": n,
                                       "classification": p.classify(cmd)})
                    out = sess.execute(cmd)
                    if out == "__EXIT__":
                        try: chan.send("logout\r\n")
                        except Exception: pass
                        return
                    if out:
                        chan.send(out.replace("\n", "\r\n"))
                    chan.send(sess.prompt())
                    continue
                last_cr = False
                if ch in (b"\x7f", b"\x08"):
                    if buf:
                        buf.pop()
                        try: chan.send(b"\b \b")
                        except Exception: pass
                    continue
                if ch == b"\x03":           # Ctrl-C
                    buf.clear()
                    chan.send(b"^C\r\n")
                    chan.send(sess.prompt())
                    continue
                buf += ch
                try: chan.send(ch)           # echo
                except Exception: break


class _ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def run(personality: Personality, host: str = "0.0.0.0",
        port: Optional[int] = None) -> None:
    cfg = Config.load()
    if L._default is None:
        L.configure(cfg.log_dir, cfg.node_name, personality.service)
    port = port or personality.listen_port
    L.get().emit(EventType.NODE_START, src_ip="0.0.0.0",
                 data={"role": f"{personality.service}_ssh_shell", "listen_port": port})

    handler = type("_BoundHandler", (_Handler,), {"personality": personality})
    srv = _ThreadedTCPServer((host, port), handler)
    srv.serve_forever()
