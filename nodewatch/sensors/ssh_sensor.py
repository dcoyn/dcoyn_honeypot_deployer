"""
sensors.ssh_sensor
===============================

A medium-interaction SSH sensor built on paramiko.

Goals:
  * Look real long enough for the attacker to drop tools.
  * Log EVERY auth attempt (success and failure) with username,
    password (or pubkey fingerprint), client version banner, kex algos,
    and per-session timing.
  * Once "logged in" we hand the attacker a fake shell that responds
    plausibly to a curated set of recon commands and logs every line.
  * Capture files attackers try to drop via "echo > file" / "cat <<EOF"
    style techniques.

Accepted credentials are deliberately weak: root:root, root:123456,
admin:admin, etc.  Tune the list to whatever you want to attract.
"""
from __future__ import annotations

import io
import os
import socket
import socketserver
import threading
import time
import uuid
from pathlib import Path
from typing import Optional

import paramiko

from ..config import Config
from ..core import logger as L
from ..core.logger import EventType
from ..core.enrichment import enrich

# ----------------------------------------------------------------------------
# Tunables
# ----------------------------------------------------------------------------
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 22

# (username, password) pairs that are accepted. Everything else fails.
WEAK_CREDS = {
    ("root",    "root"),
    ("root",    "123456"),
    ("root",    "password"),
    ("root",    "toor"),
    ("root",    "admin"),
    ("admin",   "admin"),
    ("admin",   "password"),
    ("ubuntu",  "ubuntu"),
    ("user",    "user"),
    ("test",    "test"),
    ("pi",      "raspberry"),
    ("oracle",  "oracle"),
    ("ftpuser", "ftpuser"),
    ("git",     "git"),
}

# Identity we want to project. Pick a banner that matches lots of real boxes.
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7"

# Fake host info exposed to commands like uname, /etc/os-release, etc.
FAKE_HOSTNAME = "web-prod-04"
FAKE_KERNEL   = "Linux web-prod-04 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"


# ----------------------------------------------------------------------------
# Paramiko server interface
# ----------------------------------------------------------------------------
class _SensorServer(paramiko.ServerInterface):
    def __init__(self, session_id: str, src_ip: str, src_port: int):
        self.event = threading.Event()
        self.session_id = session_id
        self.src_ip = src_ip
        self.src_port = src_port
        self.username: Optional[str] = None
        self.start = time.monotonic()
        # Per-channel state. Keyed by channel id (paramiko Channel.get_id()).
        self._exec_for_chan: dict[int, str] = {}
        self._exec_lock = threading.Lock()

    # Allow only password & publickey
    def get_allowed_auths(self, username): return "password,publickey"

    def check_auth_password(self, username, password):
        log = L.get()
        accepted = (username, password) in WEAK_CREDS
        log.emit(
            EventType.SSH_AUTH,
            src_ip=self.src_ip, src_port=self.src_port, dst_port=LISTEN_PORT,
            session_id=self.session_id,
            data={
                "username": username,
                "password": password,
                "method":   "password",
                "accepted": accepted,
                "latency_s": round(time.monotonic() - self.start, 4),
            },
        )
        if accepted:
            self.username = username
            log.emit(EventType.SSH_LOGIN_OK,
                     src_ip=self.src_ip, src_port=self.src_port, dst_port=LISTEN_PORT,
                     session_id=self.session_id,
                     data={"username": username, "password": password})
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        log = L.get()
        log.emit(
            EventType.SSH_AUTH,
            src_ip=self.src_ip, src_port=self.src_port, dst_port=LISTEN_PORT,
            session_id=self.session_id,
            data={
                "username":     username,
                "method":       "publickey",
                "accepted":     False,
                "key_type":     key.get_name(),
                "key_fp_sha256": key.fingerprint if hasattr(key, "fingerprint") else "",
                "key_base64":   key.get_base64()[:300],  # truncate
            },
        )
        # Never accept pubkey auth — forces them to a password and we capture it
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *args, **kwargs): return True
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
    def check_channel_exec_request(self, channel, command):
        # exec is one-shot. Log and stash the command for THIS channel.
        cmd = command.decode("utf-8", "replace")
        L.get().emit(
            EventType.SSH_COMMAND,
            src_ip=self.src_ip, src_port=self.src_port, dst_port=LISTEN_PORT,
            session_id=self.session_id,
            data={"command": cmd, "mode": "exec"},
        )
        with self._exec_lock:
            self._exec_for_chan[channel.get_id()] = cmd
        self.event.set()
        return True

    def take_exec(self, channel) -> Optional[str]:
        """Pop the stashed exec command for this channel (if any)."""
        with self._exec_lock:
            return self._exec_for_chan.pop(channel.get_id(), None)


# ----------------------------------------------------------------------------
# Fake shell
# ----------------------------------------------------------------------------
_FAKE_FS = {
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
        "sync:x:4:65534:sync:/bin:/bin/sync\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
        "mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false\n"
    ),
    "/etc/shadow": "cat: /etc/shadow: Permission denied\n",
    "/etc/hostname": FAKE_HOSTNAME + "\n",
    "/etc/os-release": (
        'PRETTY_NAME="Ubuntu 22.04.4 LTS"\n'
        'NAME="Ubuntu"\nVERSION_ID="22.04"\nVERSION="22.04.4 LTS (Jammy Jellyfish)"\n'
        'VERSION_CODENAME=jammy\nID=ubuntu\nID_LIKE=debian\n'
        'HOME_URL="https://www.ubuntu.com/"\nSUPPORT_URL="https://help.ubuntu.com/"\n'
    ),
    "/proc/cpuinfo": (
        "processor\t: 0\nvendor_id\t: GenuineIntel\n"
        "cpu family\t: 6\nmodel\t\t: 85\n"
        "model name\t: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz\n"
        "stepping\t: 7\ncpu MHz\t\t: 2499.998\ncache size\t: 36608 KB\n"
    ),
    "/proc/meminfo": (
        "MemTotal:        4030788 kB\nMemFree:          312540 kB\n"
        "MemAvailable:    1820432 kB\nBuffers:          120384 kB\n"
        "Cached:          1342016 kB\nSwapCached:            0 kB\n"
    ),
}


def _fake_uname():
    return FAKE_KERNEL + "\n"


def _fake_ifconfig():
    # Return something that looks like a small cloud VM
    return (
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
        "        inet 10.0.0.47  netmask 255.255.255.0  broadcast 10.0.0.255\n"
        "        ether 02:42:0a:00:00:2f  txqueuelen 1000  (Ethernet)\n"
        "        RX packets 384921  bytes 412049122 (412.0 MB)\n"
        "        TX packets 198217  bytes 31298471 (31.2 MB)\n"
        "\n"
        "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
        "        inet 127.0.0.1  netmask 255.0.0.0\n"
        "        loop  txqueuelen 1000  (Local Loopback)\n"
    )


def _fake_ps():
    return (
        "  PID TTY          TIME CMD\n"
        " 1234 pts/0    00:00:00 bash\n"
        " 1289 pts/0    00:00:00 ps\n"
    )


def _fake_w():
    return (
        " 09:14:21 up 47 days, 12:03,  1 user,  load average: 0.04, 0.09, 0.06\n"
        "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
        "ubuntu   pts/0    -                09:14    0.00s  0.01s  0.00s w\n"
    )


def _exec_fake_command(cmd: str, username: str) -> str:
    """Return stdout for the fake command. Bash-ish, intentionally limited."""
    parts = cmd.strip().split()
    if not parts:
        return ""
    head = parts[0]
    rest = parts[1:]

    if head in ("exit", "logout", "quit"):
        return "__EXIT__"

    if head == "whoami":
        return username + "\n"
    if head == "id":
        if username == "root":
            return "uid=0(root) gid=0(root) groups=0(root)\n"
        return f"uid=1000({username}) gid=1000({username}) groups=1000({username})\n"
    if head == "uname":
        if "-a" in rest:
            return _fake_uname()
        return "Linux\n"
    if head == "hostname":
        return FAKE_HOSTNAME + "\n"
    if head == "pwd":
        return f"/home/{username}\n" if username != "root" else "/root\n"
    if head == "uptime":
        return " 09:14:21 up 47 days, 12:03,  1 user,  load average: 0.04, 0.09, 0.06\n"
    if head == "ps":
        return _fake_ps()
    if head == "w":
        return _fake_w()
    if head in ("ifconfig", "ip"):
        return _fake_ifconfig()
    if head == "cat" and rest:
        out = []
        for f in rest:
            if f in _FAKE_FS:
                out.append(_FAKE_FS[f])
            else:
                out.append(f"cat: {f}: No such file or directory\n")
        return "".join(out)
    if head == "ls":
        # Pretend home dir
        return ".bashrc\n.profile\n.ssh\n"
    if head == "echo":
        return " ".join(rest) + "\n"
    if head in ("wget", "curl"):
        # Pretend we're downloading. Many bots check $? — return success.
        return f"{head}: pretending to fetch {' '.join(rest)}\n"
    if head == "history":
        return ""
    if head == "df":
        return (
            "Filesystem     1K-blocks    Used Available Use% Mounted on\n"
            "/dev/root       40197540 8194112  31987044  21% /\n"
            "tmpfs            2015392       0   2015392   0% /dev/shm\n"
        )
    if head == "free":
        return (
            "              total        used        free      shared  buff/cache   available\n"
            "Mem:        4030788     2354128      312540        2068     1364120     1820432\n"
            "Swap:             0           0           0\n"
        )
    if head == "which":
        if rest:
            return f"/usr/bin/{rest[0]}\n"
        return ""

    # Fall through: pretend it ran but produced nothing.
    # Many recon scripts just check exit code, so producing empty output is fine.
    return ""


# ----------------------------------------------------------------------------
# Connection handler
# ----------------------------------------------------------------------------
class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        src_ip, src_port = self.client_address[0], self.client_address[1]
        session_id = L.get().new_session()

        ge = enrich(src_ip)
        L.get().emit(
            EventType.CONNECTION,
            src_ip=src_ip, src_port=src_port, dst_port=LISTEN_PORT,
            session_id=session_id,
            data={"service": "ssh", "geo": ge},
        )

        transport = paramiko.Transport(sock)
        transport.local_version = SSH_BANNER
        try:
            host_key_path = os.environ.get(
                "HP_SSH_HOST_KEY",
                str(Path(Config.load().data_dir) / "ssh_host_rsa_key"),
            )
            host_key = paramiko.RSAKey(filename=host_key_path)
        except Exception:
            host_key = paramiko.RSAKey.generate(2048)
        transport.add_server_key(host_key)

        server = _SensorServer(session_id, src_ip, src_port)
        try:
            transport.start_server(server=server)
        except Exception as e:
            L.get().emit(
                EventType.SSH_BANNER,
                src_ip=src_ip, src_port=src_port, dst_port=LISTEN_PORT,
                session_id=session_id,
                data={"error": str(e),
                      "remote_version": getattr(transport, "remote_version", "")},
            )
            transport.close()
            return

        L.get().emit(
            EventType.SSH_BANNER,
            src_ip=src_ip, src_port=src_port, dst_port=LISTEN_PORT,
            session_id=session_id,
            data={"remote_version": transport.remote_version},
        )

        # Accept channels in a loop — a single SSH session can multiplex several
        # (e.g. paramiko clients open a fresh channel per exec_command call).
        chan_threads: list[threading.Thread] = []
        try:
            while transport.is_active():
                server.event.clear()
                chan = transport.accept(30)
                if chan is None:
                    break
                # Wait for shell/exec request to land for this channel
                if not server.event.wait(30):
                    try: chan.close()
                    except Exception: pass
                    continue
                th = threading.Thread(
                    target=self._serve_channel,
                    args=(chan, server),
                    daemon=True,
                )
                th.start()
                chan_threads.append(th)
        finally:
            # Wait briefly for in-flight channels, then tear down.
            for th in chan_threads:
                th.join(timeout=5)
            try: transport.close()
            except Exception: pass
            L.get().emit(
                EventType.SSH_SESSION_END,
                src_ip=src_ip, src_port=src_port, dst_port=LISTEN_PORT,
                session_id=session_id,
                data={"duration_s": round(time.monotonic() - server.start, 3),
                      "channels": len(chan_threads)},
            )

    def _serve_channel(self, chan, server):
        try:
            self._serve_shell(chan, server)
        except Exception:
            pass
        finally:
            try: chan.close()
            except Exception: pass

    # ----------------------------------------------------------- fake shell
    def _serve_shell(self, chan, server):
        username = server.username or "user"
        # One-shot exec mode (paramiko opens a new channel per exec_command)
        exec_cmd = server.take_exec(chan)
        if exec_cmd is not None:
            out = _exec_fake_command(exec_cmd, username)
            if out == "__EXIT__":
                out = ""
            try: chan.send(out)
            except Exception: pass
            try: chan.send_exit_status(0)
            except Exception: pass
            return

        prompt = f"{username}@{FAKE_HOSTNAME}:~$ " if username != "root" else f"root@{FAKE_HOSTNAME}:~# "
        chan.send(f"Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n")
        chan.send(" * Documentation:  https://help.ubuntu.com\r\n")
        chan.send(" * Management:     https://landscape.canonical.com\r\n")
        chan.send(" * Support:        https://ubuntu.com/advantage\r\n\r\n")
        chan.send(f"Last login: {time.strftime('%a %b %d %H:%M:%S %Y')} from 10.0.0.1\r\n")
        chan.send(prompt)

        buf = bytearray()
        cmd_count = 0
        last_was_cr = False
        while True:
            try:
                data = chan.recv(1024)
            except Exception:
                break
            if not data:
                break

            for b in data:
                ch = bytes([b])
                # Treat CR, LF, or CRLF as a line terminator. Real terminals
                # send CR (ENTER from a PTY); programmatic clients often send
                # LF. Coalesce CRLF so we don't double-fire.
                if ch == b"\r" or ch == b"\n":
                    if ch == b"\n" and last_was_cr:
                        last_was_cr = False
                        continue
                    last_was_cr = (ch == b"\r")
                    chan.send(b"\r\n")
                    cmd = buf.decode("utf-8", "replace")
                    buf.clear()
                    cmd_count += 1
                    L.get().emit(
                        EventType.SSH_COMMAND,
                        src_ip=server.src_ip, src_port=server.src_port, dst_port=LISTEN_PORT,
                        session_id=server.session_id,
                        data={"command": cmd, "mode": "shell", "seq": cmd_count},
                    )
                    out = _exec_fake_command(cmd, username)
                    if out == "__EXIT__":
                        chan.send("logout\r\n")
                        L.get().emit(
                            EventType.SSH_SESSION_END,
                            src_ip=server.src_ip, src_port=server.src_port, dst_port=LISTEN_PORT,
                            session_id=server.session_id,
                            data={"mode": "shell", "commands": cmd_count,
                                  "duration_s": round(time.monotonic() - server.start, 3)},
                        )
                        return
                    if out:
                        chan.send(out.replace("\n", "\r\n"))
                    chan.send(prompt)
                    continue
                else:
                    last_was_cr = False
                if ch == b"\x7f" or ch == b"\x08":  # backspace
                    if buf:
                        buf.pop()
                        chan.send(b"\b \b")
                elif ch == b"\x03":  # ctrl-c
                    chan.send(b"^C\r\n")
                    buf.clear()
                    chan.send(prompt)
                elif ch == b"\x04":  # ctrl-d
                    if not buf:
                        chan.send("logout\r\n")
                        L.get().emit(
                            EventType.SSH_SESSION_END,
                            src_ip=server.src_ip, src_port=server.src_port, dst_port=LISTEN_PORT,
                            session_id=server.session_id,
                            data={"mode": "shell", "commands": cmd_count,
                                  "duration_s": round(time.monotonic() - server.start, 3),
                                  "end_reason": "ctrl-d"},
                        )
                        return
                else:
                    buf += ch
                    chan.send(ch)


class _ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(host: str = LISTEN_HOST, port: int = LISTEN_PORT) -> None:
    cfg = Config.load()
    L.configure(cfg.log_dir, cfg.node_name, "ssh")
    L.get().emit(EventType.NODE_START, src_ip="0.0.0.0",
                 data={"role": "ssh_sensor", "listen_port": port})
    srv = _ThreadedTCPServer((host, port), _Handler)
    srv.serve_forever()


if __name__ == "__main__":
    serve()
