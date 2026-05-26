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

import base64 as _b64
import io
import os
import re
import shlex
import socket
import socketserver
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import paramiko

from ..config import Config
from ..core import logger as L
from ..core.logger import EventType
from ..core.enrichment import enrich
from .fake_fs import FakeFS, DEFAULT_CANARY_BASE
from .fake_world import FakeWorld
from .fake_system import FakeSystem, render_proc_path

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
# ----------------------------------------------------------------------------
# Per-VM fake filesystem singleton — same instance shared by all sessions
# so attackers see a consistent universe.
# ----------------------------------------------------------------------------
_FS: Optional[FakeFS] = None
_SYS: Optional[FakeSystem] = None
_FS_LOCK = threading.Lock()


def _get_fs() -> FakeFS:
    global _FS, _SYS
    if _FS is None:
        with _FS_LOCK:
            if _FS is None:
                cfg = Config.load()
                agent = cfg.node_name or "kworker"
                world_path = Path(cfg.data_dir) / "fake_world.json"
                world = FakeWorld.load_or_create(agent, world_path)
                _FS = FakeFS(
                    world=world,
                    hostname=FAKE_HOSTNAME,
                    canary_base=os.environ.get("HP_CANARY_URL", DEFAULT_CANARY_BASE),
                )
                _SYS = FakeSystem(world=world, hostname=FAKE_HOSTNAME)
    return _FS


def _get_sys() -> FakeSystem:
    if _SYS is None:
        _get_fs()  # forces init of both
    return _SYS  # type: ignore[return-value]


class _ShellState:
    """Per-SSH-session shell state. Tracks cwd, env, command history."""
    def __init__(self, username: str, session_id: str, src_ip: str, src_port: int):
        self.username = username
        self.session_id = session_id
        self.src_ip = src_ip
        self.src_port = src_port
        # default cwd
        self.cwd = f"/home/{username}" if username != "root" else "/root"
        if not _get_fs().exists(self.cwd):
            self.cwd = "/"
        self.env = {
            "HOME": self.cwd,
            "USER": username,
            "SHELL": "/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TERM": "xterm-256color",
            "PWD":  self.cwd,
        }


def _resolve(state: _ShellState, arg: str) -> str:
    """Resolve a shell path argument against state.cwd."""
    if not arg:
        return state.cwd
    if arg == "~":
        return state.env["HOME"]
    if arg.startswith("~/"):
        arg = state.env["HOME"] + arg[1:]
    if not arg.startswith("/"):
        arg = state.cwd.rstrip("/") + "/" + arg
    # Normalize ./.. via the FS helper
    return _get_fs()._norm(arg)


def _format_ls_la_line(name: str, m) -> str:
    """Render one `ls -l` line like real ls does."""
    mtime = m.mtime.strftime("%b %d %H:%M")
    size = f"{m.size:>8d}"
    if m.is_link:
        return f"{m.mode} {m.nlink} {m.owner:<8s} {m.group:<8s} {size} {mtime} {name} -> {m.link_target}"
    return f"{m.mode} {m.nlink} {m.owner:<8s} {m.group:<8s} {size} {mtime} {name}"


def _fake_uname():
    return FAKE_KERNEL + "\n"


def _fake_ifconfig():
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


# These now delegate to FakeSystem for live, drifted output. Each call
# returns slightly different CPU% / free memory / load avg so the
# attacker sees a machine that's actually doing work.
def _fake_ps():       return _get_sys().render_ps_aux()
def _fake_ps_ef():    return _get_sys().render_ps_ef()
def _fake_top():      return _get_sys().render_top()
def _fake_w():        return _get_sys().render_w()
def _fake_uptime():   return _get_sys().render_uptime()
def _fake_free(**k):  return _get_sys().render_free(**k)
def _fake_df(**k):    return _get_sys().render_df(**k)
def _fake_vmstat():   return _get_sys().render_vmstat()
def _fake_mpstat():   return _get_sys().render_mpstat()
def _fake_nproc():    return _get_sys().render_nproc()
def _fake_lscpu():    return _get_sys().render_lscpu()


def _detect_filetype(data: bytes) -> str:
    """Mimic the `file` command."""
    if data.startswith(b"PK\x03\x04"):
        # Check for ZIP-based office docs
        if b"word/document.xml" in data[:4096]:
            return "Microsoft Word 2007+ document"
        if b"xl/workbook.xml" in data[:4096]:
            return "Microsoft Excel 2007+ spreadsheet"
        if b"ppt/presentation.xml" in data[:4096]:
            return "Microsoft PowerPoint 2007+ presentation"
        return "Zip archive data, at least v2.0 to extract"
    if data.startswith(b"\x1f\x8b"):
        return "gzip compressed data"
    if data.startswith(b"\x7fELF"):
        return "ELF 64-bit LSB executable, x86-64, dynamically linked"
    if data.startswith(b"#!/"):
        first_line = data.split(b"\n", 1)[0].decode("utf-8", "replace")
        return f"a {first_line[2:]} script, ASCII text executable"
    if data.startswith(b"%PDF"):
        return "PDF document"
    try:
        data.decode("utf-8")
        return "ASCII text" if all(b < 128 for b in data[:1024]) else "UTF-8 Unicode text"
    except UnicodeDecodeError:
        return "data"


# ----------------------------------------------------------------------------
# Main command dispatcher
# ----------------------------------------------------------------------------
_CANARY_URL_RE = re.compile(r"https?://[^\s'\"]+")


def _emit_canary_event(state: _ShellState, kind: str, **extra) -> None:
    """Log when an attacker interacts with a canary URL or file."""
    L.get().emit(
        EventType.SSH_COMMAND,
        src_ip=state.src_ip, src_port=state.src_port, dst_port=LISTEN_PORT,
        session_id=state.session_id,
        data={"canary_event": kind, **extra},
    )


def _exec(state: _ShellState, cmd: str) -> str:
    """Run a fake command, return stdout (or '__EXIT__')."""
    cmd = cmd.strip()
    if not cmd:
        return ""

    # Sniff for compound commands (we don't actually parse pipes; just
    # handle some common patterns)
    if "|" in cmd or ">" in cmd:
        # Handle common single-pipe exfil patterns:
        #   cat file | base64
        #   base64 file | head -c N
        m = re.match(r"^cat\s+(\S+)\s*\|\s*base64\s*$", cmd)
        if m:
            return _do_base64(state, m.group(1))
        m = re.match(r"^base64\s+(\S+)\s*\|\s*head", cmd)
        if m:
            return _do_base64(state, m.group(1))[:1024] + "\n"
        # Anything else with pipes/redirects: pretend it ran
        return ""

    try:
        parts = shlex.split(cmd, posix=True)
    except ValueError:
        parts = cmd.split()
    if not parts:
        return ""
    head, rest = parts[0], parts[1:]

    fs = _get_fs()

    # --- session control ---
    if head in ("exit", "logout", "quit"):
        return "__EXIT__"
    if head == "clear":
        return "\033[H\033[2J"

    # --- env / identity ---
    if head == "whoami":
        return state.username + "\n"
    if head == "id":
        if state.username == "root":
            return "uid=0(root) gid=0(root) groups=0(root)\n"
        uid = 1000 if state.username == "ubuntu" else 1001
        return f"uid={uid}({state.username}) gid={uid}({state.username}) groups={uid}({state.username}),27(sudo),998(docker)\n"
    if head == "uname":
        if "-a" in rest:
            return _fake_uname()
        if "-r" in rest:
            return "5.15.0-91-generic\n"
        return "Linux\n"
    if head == "hostname":
        return FAKE_HOSTNAME + "\n"
    if head == "uptime":
        return _fake_uptime()
    if head == "env" or head == "printenv":
        return "".join(f"{k}={v}\n" for k, v in state.env.items())
    if head == "echo":
        return " ".join(rest) + "\n"
    if head == "history":
        return ""
    if head == "date":
        return time.strftime("%a %b %d %H:%M:%S UTC %Y", time.gmtime()) + "\n"
    if head == "which":
        if rest:
            return f"/usr/bin/{rest[0]}\n"
        return ""
    if head == "groups":
        if state.username == "root":
            return "root\n"
        return f"{state.username} sudo docker\n"

    # --- navigation ---
    if head == "pwd":
        return state.cwd + "\n"
    if head == "cd":
        target = _resolve(state, rest[0] if rest else "~")
        if not fs.exists(target):
            return f"-bash: cd: {rest[0] if rest else target}: No such file or directory\n"
        if not fs.is_dir(target):
            return f"-bash: cd: {rest[0] if rest else target}: Not a directory\n"
        state.cwd = target
        state.env["PWD"] = target
        return ""

    # --- ls ---
    if head == "ls":
        return _do_ls(state, rest)

    # --- cat / head / tail ---
    if head == "cat":
        return _do_cat(state, rest)
    if head == "head":
        return _do_head_tail(state, rest, head=True)
    if head == "tail":
        return _do_head_tail(state, rest, head=False)
    if head == "less" or head == "more":
        # No paginator — just dump
        return _do_cat(state, rest)

    # --- file inspection ---
    if head == "file":
        return _do_file(state, rest)
    if head == "stat":
        return _do_stat(state, rest)

    # --- search ---
    if head == "find":
        return _do_find(state, rest)
    if head == "grep":
        return _do_grep(state, rest)

    # --- exfil-friendly ---
    if head == "base64":
        if not rest:
            return ""
        # Handle "base64 -d" decode mode — pretend not implemented
        if rest[0] in ("-d", "--decode"):
            return "base64: invalid input\n"
        return _do_base64(state, rest[0])

    if head in ("md5sum", "sha256sum", "sha1sum"):
        # Compute a real hash of the fake file's content
        if not rest:
            return ""
        target = _resolve(state, rest[0])
        try:
            data = fs.read(target, session_id=state.session_id)
        except FileNotFoundError:
            return f"{head}: {rest[0]}: No such file or directory\n"
        import hashlib as _h
        algo = {"md5sum": "md5", "sha1sum": "sha1", "sha256sum": "sha256"}[head]
        digest = getattr(_h, algo)(data).hexdigest()
        return f"{digest}  {target}\n"

    # --- network commands — log if attacker is hitting a canary URL ---
    if head in ("wget", "curl"):
        # Find the URL among rest
        url = next((a for a in rest if a.startswith("http://") or a.startswith("https://")), None)
        if url:
            # Check if it's one of our canary URLs (they read it from a file
            # and are now fetching it from the honeypot — strong signal)
            if fs.canary_base and url.startswith(fs.canary_base):
                _emit_canary_event(state, "canary_url_fetched_in_shell",
                                   tool=head, url=url)
            else:
                # Any wget/curl is worth surfacing for IOC purposes
                _emit_canary_event(state, "outbound_http_attempt",
                                   tool=head, url=url)
        if head == "wget":
            fname = url.rsplit("/", 1)[-1] if url else "index.html"
            return (f"--{time.strftime('%Y-%m-%d %H:%M:%S')}--  {url or ''}\n"
                    f"Resolving... done.\n"
                    f"Connecting... connected.\n"
                    f"HTTP request sent, awaiting response... 200 OK\n"
                    f"Length: 14392 (14K) [application/octet-stream]\n"
                    f"Saving to: '{fname}'\n\n"
                    f"     0K .......... ....                  100%  4.21M=0.003s\n\n"
                    f"'{fname}' saved [14392/14392]\n")
        else:
            return ""  # curl silent on success by default

    if head == "scp":
        _emit_canary_event(state, "scp_invoked", args=rest)
        return ""
    if head == "ssh":
        # Attacker pivoting — log the target
        target = next((a for a in rest if "@" in a or "." in a), None)
        _emit_canary_event(state, "ssh_pivot_attempt", target=target, args=rest)
        return f"ssh: connect to host {target or 'unknown'} port 22: Connection timed out\n"

    # --- process / sys info ---
    if head == "ps":
        # Recognize common ps flags. We render a big roster regardless;
        # `ps` alone shows just this terminal's procs, `ps aux`/`ps -ef` show all.
        joined = " ".join(rest) if rest else ""
        if "-ef" in joined or joined == "-eaf":
            return _fake_ps_ef()
        if "aux" in joined or "-A" in joined or "-e" in joined or "ax" in joined:
            return _fake_ps()
        # Plain `ps` — only THIS shell's procs
        return ("    PID TTY          TIME CMD\n"
                f"{_get_sys()._procs[-2].pid:>7d} pts/0    00:00:00 bash\n"
                f"{_get_sys()._procs[-2].pid + 4:>7d} pts/0    00:00:00 ps\n")
    if head == "top":
        return _fake_top()
    if head == "htop":
        # htop is curses — we can't render an interactive UI. Most attackers
        # who try htop on a remote shell quickly switch to `top -bn1` anyway.
        return ("Error opening terminal: unknown.\n"
                "Trying to fall back to 'top'…\n"
                + _fake_top())
    if head == "vmstat":
        return _fake_vmstat()
    if head == "mpstat":
        return _fake_mpstat()
    if head == "iostat":
        # Compact iostat-ish output
        sys = _get_sys()
        return (f"Linux 5.15.0-91-generic ({FAKE_HOSTNAME}) \t"
                + datetime_now_str() + " \t_x86_64_\t"
                + f"({sys.NUM_CPUS} CPU)\n\n"
                "avg-cpu:  %user   %nice %system %iowait  %steal   %idle\n"
                "          18.42    0.00    4.21    0.30    0.00   77.07\n\n"
                "Device             tps    kB_read/s    kB_wrtn/s    kB_read    kB_wrtn\n"
                "nvme0n1          12.34       142.21       287.43    1234567    9876543\n"
                "nvme1n1          43.21       324.18       912.05    8765432   12345678\n"
                "nvme2n1          78.43       512.34      1843.21   18765432   45678901\n")
    if head == "nproc":
        return _fake_nproc()
    if head == "w":
        return _fake_w()
    if head == "uptime":
        return _fake_uptime()
    if head == "who":
        return f"{state.username}  pts/0        " + time.strftime("%Y-%m-%d %H:%M") + " (10.0.0.1)\n"
    if head == "last":
        return ("ops      pts/1        10.10.5.42       Tue May 25 14:22   still logged in\n"
                "deploy   pts/0        10.10.5.42       Tue May 25 09:14 - 11:48  (02:34)\n"
                "admin    pts/0        10.10.5.42       Mon May 24 16:08 - 18:12  (02:04)\n"
                "\nwtmp begins Sat Jan  1 00:00:01 2024\n")
    if head == "ifconfig" or (head == "ip" and "a" in (rest[0] if rest else "")):
        return _fake_ifconfig()
    if head == "df":
        return _fake_df(human=("h" in " ".join(rest)))
    if head == "free":
        joined = " ".join(rest)
        if "-h" in joined:    return _fake_free(human=True)
        if "-m" in joined:    return _fake_free(mb=True)
        if "-g" in joined:    return _fake_free(gb=True)
        return _fake_free()
    if head == "lscpu":
        return _fake_lscpu()
    if head == "mount":
        return ("/dev/nvme0n1p2 on / type ext4 (rw,relatime)\n"
                "tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev,inode64)\n"
                "tmpfs on /run type tmpfs (rw,nosuid,nodev,size=27307356k,nr_inodes=819200,mode=755,inode64)\n"
                "/dev/nvme0n1p1 on /boot/efi type vfat (rw,relatime,fmask=0077,dmask=0077,codepage=437,iocharset=ascii)\n"
                "/dev/nvme1n1 on /var/lib/docker type ext4 (rw,relatime)\n"
                "/dev/nvme2n1 on /var/lib/postgresql type ext4 (rw,relatime)\n"
                "/dev/sdb1 on /var/backups type ext4 (rw,relatime)\n"
                "/dev/sdc1 on /data type xfs (rw,relatime,attr2,inode64)\n")

    if head == "sudo":
        # Pretend we don't ask for password since "you're admin"
        if rest:
            return _exec(state, " ".join(rest))
        return "sudo: a command is required\n"

    if head == "su":
        return ""  # silently do nothing

    # Fall through: behave like the command ran but produced nothing.
    return ""


def datetime_now_str() -> str:
    return datetime.now(timezone.utc).strftime("%m/%d/%Y")


def _do_ls(state, args) -> str:
    fs = _get_fs()
    long = False
    show_hidden = False
    targets = []
    for a in args:
        if a.startswith("-"):
            if "l" in a: long = True
            if "a" in a: show_hidden = True
            if "h" in a: pass
        else:
            targets.append(a)
    if not targets:
        targets = [state.cwd]

    out_lines = []
    for t in targets:
        p = _resolve(state, t)
        if not fs.exists(p):
            out_lines.append(f"ls: cannot access '{t}': No such file or directory")
            continue
        if fs.is_file(p):
            if long:
                m = fs.meta(p)
                out_lines.append(_format_ls_la_line(p.split("/")[-1], m))
            else:
                out_lines.append(p.split("/")[-1])
            continue
        # directory
        if len(targets) > 1:
            out_lines.append(f"{p}:")
        try:
            entries = fs.list_dir(p)
        except NotADirectoryError:
            continue
        if not show_hidden:
            entries = [e for e in entries if not e[0].startswith(".")]
        if long:
            total = sum(e[1].size for e in entries) // 1024 + 4
            out_lines.append(f"total {total}")
            for name, m in entries:
                out_lines.append(_format_ls_la_line(name, m))
        else:
            # Plain listing: just names, one per line is simplest and matches
            # ls behavior on a non-tty.
            for name, m in entries:
                suffix = "/" if m.is_dir else ""
                out_lines.append(name + suffix)
    return "\n".join(out_lines) + ("\n" if out_lines else "")


def _do_cat(state, args) -> str:
    fs = _get_fs()
    if not args:
        return ""
    out = []
    for a in args:
        p = _resolve(state, a)

        # Dynamic /proc/* paths (meminfo/loadavg/uptime/cpuinfo) are rendered
        # fresh on every read so consecutive cats show different memory free,
        # different load average, etc. — what attackers see on a live box.
        proc_dyn = render_proc_path(_get_sys(), p)
        if proc_dyn is not None:
            out.append(proc_dyn.decode("utf-8"))
            continue

        if not fs.exists(p):
            out.append(f"cat: {a}: No such file or directory\n")
            continue
        if fs.is_dir(p):
            out.append(f"cat: {a}: Is a directory\n")
            continue
        m = fs.meta(p)
        # Permission check
        if "rw-------" in m.mode and m.owner != state.username and state.username != "root":
            out.append(f"cat: {a}: Permission denied\n")
            continue
        if a.endswith("shadow") or p == "/etc/shadow":
            if state.username != "root":
                out.append(f"cat: {a}: Permission denied\n")
                continue
        if fs.is_canary(p):
            # Log the canary read — attacker has the doc in front of them now
            _emit_canary_event(state, "canary_file_read_via_cat",
                               file=p, viewer="cat")
            data = fs.read(p, session_id=state.session_id)
            # Don't dump binary to terminal (it would break it), warn instead
            out.append(f"cat: {a}: binary data, use `base64 {a}` to extract or scp\n")
            continue
        try:
            data = fs.read(p, session_id=state.session_id)
        except FileNotFoundError:
            out.append(f"cat: {a}: No such file or directory\n")
            continue
        try:
            out.append(data.decode("utf-8"))
        except UnicodeDecodeError:
            # Binary file
            out.append(f"cat: {a}: binary data, use `base64 {a}` to extract\n")
    return "".join(out)


def _do_head_tail(state, args, head=True) -> str:
    fs = _get_fs()
    n = 10
    files = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-n" and i + 1 < len(args):
            try: n = int(args[i + 1])
            except ValueError: pass
            i += 2; continue
        if a.startswith("-") and a[1:].isdigit():
            n = int(a[1:]); i += 1; continue
        files.append(a); i += 1
    if not files:
        return ""
    out = []
    for f in files:
        p = _resolve(state, f)
        try:
            data = fs.read(p, session_id=state.session_id).decode("utf-8", "replace")
        except FileNotFoundError:
            out.append(f"{'head' if head else 'tail'}: cannot open '{f}' for reading: No such file or directory\n")
            continue
        lines = data.splitlines(keepends=True)
        sel = lines[:n] if head else lines[-n:]
        out.append("".join(sel))
    return "".join(out)


def _do_file(state, args) -> str:
    fs = _get_fs()
    out = []
    for a in args:
        p = _resolve(state, a)
        if not fs.exists(p):
            out.append(f"{a}: cannot open `{a}' (No such file or directory)\n")
            continue
        if fs.is_dir(p):
            out.append(f"{a}: directory\n")
            continue
        try:
            data = fs.read(p, session_id=state.session_id, max_bytes=4096)
            out.append(f"{a}: {_detect_filetype(data)}\n")
        except FileNotFoundError:
            out.append(f"{a}: cannot open\n")
    return "".join(out)


def _do_stat(state, args) -> str:
    fs = _get_fs()
    if not args:
        return ""
    p = _resolve(state, args[0])
    if not fs.exists(p):
        return f"stat: cannot stat '{args[0]}': No such file or directory\n"
    m = fs.meta(p)
    kind = "directory" if m.is_dir else "regular file"
    mtime = m.mtime.strftime("%Y-%m-%d %H:%M:%S.000000000 +0000")
    return (f"  File: {p}\n"
            f"  Size: {m.size:<10d} Blocks: {(m.size + 511) // 512:<10d} IO Block: 4096   {kind}\n"
            f"Device: 801h/2049d Inode: {abs(hash(p)) % 9999999:<10d} Links: {m.nlink}\n"
            f"Access: ({m.mode[1:].replace('-', '').count('r') * 4:0>3d}/{m.mode}) Uid: ({m.owner})  Gid: ({m.group})\n"
            f"Access: {mtime}\nModify: {mtime}\nChange: {mtime}\n")


def _do_find(state, args) -> str:
    """Very basic find. Supports: find [path] [-name PATTERN] [-type f|d]"""
    fs = _get_fs()
    root = state.cwd
    name_pat = None
    type_filter = None
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-name" and i + 1 < len(args):
            name_pat = args[i + 1]; i += 2; continue
        if a == "-type" and i + 1 < len(args):
            type_filter = args[i + 1]; i += 2; continue
        if not a.startswith("-"):
            root = _resolve(state, a); i += 1; continue
        i += 1

    if not fs.exists(root):
        return f"find: '{root}': No such file or directory\n"

    out = []
    import fnmatch
    for path in fs.all_paths():
        if not (path == root or path.startswith(root.rstrip("/") + "/")):
            continue
        m = fs.meta(path)
        if type_filter == "f" and m.is_dir: continue
        if type_filter == "d" and not m.is_dir: continue
        if name_pat:
            base = path.rsplit("/", 1)[-1]
            if not fnmatch.fnmatch(base, name_pat):
                continue
        out.append(path)
    return "\n".join(out) + ("\n" if out else "")


def _do_grep(state, args) -> str:
    """Basic grep. Supports: grep [-r] [-i] [-l] [-n] PATTERN PATH..."""
    fs = _get_fs()
    recursive = False
    ignore_case = False
    list_files = False
    show_lineno = False
    positional = []
    for a in args:
        if a.startswith("-"):
            if "r" in a or "R" in a: recursive = True
            if "i" in a: ignore_case = True
            if "l" in a: list_files = True
            if "n" in a: show_lineno = True
        else:
            positional.append(a)
    if len(positional) < 2:
        return "Usage: grep [-r] [-i] [-l] [-n] PATTERN PATH\n"
    pattern, *paths = positional
    flags = re.IGNORECASE if ignore_case else 0
    try:
        pat = re.compile(pattern, flags)
    except re.error:
        pat = re.compile(re.escape(pattern), flags)

    targets: list[str] = []
    for p in paths:
        rp = _resolve(state, p)
        if not fs.exists(rp):
            continue
        if fs.is_file(rp):
            targets.append(rp)
        elif recursive:
            for ap in fs.all_paths():
                if ap.startswith(rp.rstrip("/") + "/") and fs.is_file(ap):
                    targets.append(ap)

    out = []
    for t in targets:
        try:
            data = fs.read(t, session_id=state.session_id).decode("utf-8", "replace")
        except FileNotFoundError:
            continue
        for ln, line in enumerate(data.splitlines(), 1):
            if pat.search(line):
                if list_files:
                    out.append(t)
                    break
                if show_lineno:
                    if len(targets) > 1:
                        out.append(f"{t}:{ln}:{line}")
                    else:
                        out.append(f"{ln}:{line}")
                else:
                    if len(targets) > 1:
                        out.append(f"{t}:{line}")
                    else:
                        out.append(line)
    return "\n".join(out) + ("\n" if out else "")


def _do_base64(state, arg) -> str:
    fs = _get_fs()
    p = _resolve(state, arg)
    if not fs.exists(p):
        return f"base64: {arg}: No such file or directory\n"
    if fs.is_dir(p):
        return f"base64: {arg}: Is a directory\n"
    try:
        data = fs.read(p, session_id=state.session_id)
    except FileNotFoundError:
        return f"base64: {arg}: No such file or directory\n"
    if fs.is_canary(p):
        # Attacker just exfil'd a canary doc
        _emit_canary_event(state, "canary_file_exfiltrated_via_base64",
                            file=p, bytes=len(data))
    # Wrap at 76 cols like real base64
    encoded = _b64.b64encode(data).decode("ascii")
    return "\n".join(encoded[i:i + 76] for i in range(0, len(encoded), 76)) + "\n"


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
        state = _ShellState(username, server.session_id, server.src_ip, server.src_port)

        # One-shot exec mode (paramiko opens a new channel per exec_command)
        exec_cmd = server.take_exec(chan)
        if exec_cmd is not None:
            out = _exec(state, exec_cmd)
            if out == "__EXIT__":
                out = ""
            try: chan.send(out)
            except Exception: pass
            try: chan.send_exit_status(0)
            except Exception: pass
            return

        def _prompt():
            short_cwd = state.cwd
            home = state.env["HOME"]
            if short_cwd == home:
                short_cwd = "~"
            elif short_cwd.startswith(home + "/"):
                short_cwd = "~" + short_cwd[len(home):]
            sym = "#" if username == "root" else "$"
            return f"{username}@{FAKE_HOSTNAME}:{short_cwd}{sym} "

        chan.send(f"Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n")
        chan.send(" * Documentation:  https://help.ubuntu.com\r\n")
        chan.send(" * Management:     https://landscape.canonical.com\r\n")
        chan.send(" * Support:        https://ubuntu.com/advantage\r\n\r\n")
        chan.send(f"Last login: {time.strftime('%a %b %d %H:%M:%S %Y')} from 10.10.5.42\r\n")
        chan.send(_prompt())

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
                        data={"command": cmd, "mode": "shell", "seq": cmd_count,
                              "cwd": state.cwd},
                    )
                    out = _exec(state, cmd)
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
                    chan.send(_prompt())
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
                    chan.send(_prompt())
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
