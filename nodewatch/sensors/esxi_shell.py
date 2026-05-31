"""
sensors.esxi_shell
==================

ESXi personality for the SSH fake-shell harness (``ssh_shell_base``). ESXi's
management shell is reached over SSH, so a compromised-ESXi attacker gets a
busybox-ish ``-ash`` prompt with the ESXi tooling (``esxcli``, ``vim-cmd``,
``esxtop``, ``vmware -v``) over a realistic fake host: real-looking VMs, VMFS
datastores, CPU, RAM, uptime.

High-value capture is **ransomware tradecraft** — the ESXiArgs / Akira / Royal
playbook stops the running VMs (``esxcli vm process kill`` / ``vim-cmd
vmsvc/power.off``) and enumerates ``.vmdk`` files before encrypting the
datastores. We render believable output and flag those steps (Service Stop /
Inhibit System Recovery) so the scorecard shows a VMFS ransomware hit lining up.
Nothing is executed; no VM is touched.
"""
from __future__ import annotations

import random
import re
import time

from .ssh_shell_base import Personality
from ..core import classify as CLS

ESXI_VERSION = "7.0.3"
ESXI_BUILD = "19898904"
HOSTNAME = "esxi-prod-01"
CPU_MODEL = "Intel(R) Xeon(R) Gold 6230 CPU @ 2.10GHz"
CPU_CORES = 40
CPU_SOCKETS = 2
RAM_GB = 256
_BOOT = time.time() - random.randint(40, 220) * 86400

_GOOD = {("root", "VMware1!"), ("root", "vmware"), ("root", "password"), ("root", "")}

# vmid, name, guest, power, datastore, cpus, ram_mb
_VMS = [
    (1, "DC01",         "windows2019srvNext_64", "on",  "datastore1",    4, 16384),
    (2, "SQL-PROD-01",  "windows2019srvNext_64", "on",  "datastore1",    8, 65536),
    (3, "FILE-01",      "windows2019srvNext_64", "on",  "datastore2",    4, 16384),
    (4, "APP-PROD-02",  "ubuntu64Guest",         "on",  "datastore2",    4, 8192),
    (5, "BACKUP-VEEAM", "windows2019srvNext_64", "on",  "vsanDatastore", 6, 32768),
    (6, "WEB-DMZ-01",   "ubuntu64Guest",         "off", "datastore1",    2, 4096),
]
# name, uuid, fstype, total_gb, free_gb
_DS = [
    ("datastore1",    "5f9c2a1b-3e4d5c6a-7b8c-0011223344aa",    "VMFS-6", 4096, 1180),
    ("datastore2",    "60ad3b2c-4f5e6d7b-8c9d-1122334455bb",    "VMFS-6", 8192, 5320),
    ("vsanDatastore", "vsan:52aabbccddeeff0011-2233445566778899", "vsan", 20480, 12030),
]


def _wid(vmid): return 2097152 + vmid * 17


def esxi_accept(username, password):
    return (username, password) in _GOOD or username == "root"


class EsxiPersonality(Personality):
    ssh_banner = "SSH-2.0-OpenSSH_7.9 VMware_ESXi"
    service = "esxi_shell"
    listen_port = 22
    host_key_name = "ssh_host_rsa_key"

    def accept_auth(self, username, password):
        return esxi_accept(username, password)

    def make_session(self, username, src_ip, src_port, session_id):
        return _EsxiSession(username, src_ip)

    def classify(self, cmd):
        base = CLS.classify_command(cmd)
        low = cmd.lower()
        techs = set(base.get("techniques", []))
        cat = base.get("category")
        if re.search(r"vm process kill|power\.off|power\.shutdown|vmsvc/power\.suspend", low):
            techs.add("T1489"); cat = cat or "service_stop"           # Service Stop
        if re.search(r"find\b.*\.vmdk|ls\b.*\.vmdk|\*\.vmdk|\.vmx\b", low):
            techs.add("T1083"); cat = cat or "encryption_target_recon"  # File Discovery
        if re.search(r"encrypt|\.args\b|never_open|openssl enc|elf|encryptor", low):
            techs.add("T1486"); cat = cat or "data_encrypted_for_impact"
        if re.search(r"vmdumper|esxcli system snmp|vsish", low):
            techs.add("T1082")
        base["techniques"] = sorted(techs)
        if cat:
            base["category"] = cat
        return base


class _EsxiSession:
    def __init__(self, username, src_ip):
        self.user = username or "root"
        self.cwd = "/"
        self.src_ip = src_ip

    def motd(self):
        return ("The time and date of this login have been sent to the system logs.\n\n"
                "WARNING:\n"
                "   All commands run on the ESXi shell are logged and may be included in\n"
                "   support bundles. Do not provide passwords directly on the command line.\n\n")

    def prompt(self):
        return f"[{self.user}@{HOSTNAME}:{self.cwd}] "

    # ---- command sets -------------------------------------------------
    def _esxcli(self, a):
        j = " ".join(a)
        if j.startswith("system version"):
            return (f"   Product: VMware ESXi\n   Version: {ESXI_VERSION}\n"
                    f"   Build: Releasebuild-{ESXI_BUILD}\n   Update: 3\n   Patch: 17\n")
        if j.startswith("system hostname"):
            return (f"   Domain Name: corp.local\n"
                    f"   Fully Qualified Domain Name: {HOSTNAME}.corp.local\n"
                    f"   Host Name: {HOSTNAME}\n")
        if j.startswith("hardware cpu global") or j.startswith("hardware cpu list"):
            return (f"   CPU Packages: {CPU_SOCKETS}\n   CPU Cores: {CPU_CORES}\n"
                    f"   CPU Threads: {CPU_CORES*2}\n   Brand: {CPU_MODEL}\n"
                    f"   Hyperthreading Active: true\n")
        if j.startswith("hardware memory"):
            return (f"   Physical Memory: {RAM_GB*1024*1024*1024} Bytes\n"
                    f"   Reliable Memory: 0 Bytes\n")
        if j.startswith("hardware platform"):
            return ("   Product Name: PowerEdge R740\n   Vendor Name: Dell Inc.\n"
                    "   Serial Number: 7Q2KX13\n")
        if j.startswith("network ip interface"):
            return ("Name  IPv4 Address  IPv4 Netmask   IPv4 Broadcast  Type    Gateway\n"
                    "----  ------------  -------------  --------------  ------  ----------\n"
                    "vmk0  10.20.30.41   255.255.255.0  10.20.30.255    STATIC  10.20.30.1\n"
                    "vmk1  10.20.40.41   255.255.255.0  10.20.40.255    STATIC  0.0.0.0\n")
        if j.startswith("storage filesystem list"):
            out = ("Mount Point                                          Volume Name     Type    Size            Free\n"
                   "---------------------------------------------------  --------------  ------  --------------  --------------\n")
            for name, uuid, fs, tot, free in _DS:
                out += (f"/vmfs/volumes/{uuid:<37}  {name:<14}  {fs:<6}  "
                        f"{tot*1073741824:<14}  {free*1073741824}\n")
            return out
        if j.startswith("vm process list"):
            out = ""
            for vmid, name, guest, power, ds, cpu, ram in _VMS:
                if power != "on":
                    continue
                out += (f"{name}\n   World ID: {_wid(vmid)}\n   Process ID: 0\n"
                        f"   VMX Cartel ID: {_wid(vmid)-1}\n   Display Name: {name}\n"
                        f"   Config File: /vmfs/volumes/{ds}/{name}/{name}.vmx\n\n")
            return out
        if j.startswith("vm process kill"):
            return ""   # silent success — flagged in classify()
        if j.startswith("system account list"):
            return ("User ID  Description\n-------  -------------\nroot     Administrator\n")
        if j.startswith("system maintenancemode get"):
            return "   Enabled: false\n"
        return "Usage: esxcli [options] {namespace}+ {cmd} [cmd options]\n"

    def _vimcmd(self, a):
        j = " ".join(a)
        if j.startswith("vmsvc/getallvms"):
            out = "Vmid   Name           File                                  Guest OS                 Version\n"
            for vmid, name, guest, power, ds, cpu, ram in _VMS:
                out += f"{vmid:<6} {name:<14} [{ds}] {name}/{name}.vmx     {guest:<23} vmx-19\n"
            return out
        m = re.match(r"vmsvc/power\.getstate\s+(\d+)", j)
        if m:
            vm = next((v for v in _VMS if v[0] == int(m.group(1))), None)
            st = "Powered on" if (vm and vm[3] == "on") else "Powered off"
            return f"Retrieved runtime info\n{st}\n"
        if re.match(r"vmsvc/power\.(off|shutdown|suspend)\s+\d+", j):
            return ""   # silent — flagged in classify()
        if j.startswith("hostsvc/hostsummary"):
            return (f"Listsummary:\n   name = \"{HOSTNAME}.corp.local\",\n"
                    f"   version = \"{ESXI_VERSION}\", build = \"{ESXI_BUILD}\",\n"
                    f"   memorySize = {RAM_GB*1073741824},\n   numCpuCores = {CPU_CORES},\n")
        return "vim-cmd: command not found\n"

    def _df(self):
        out = "Filesystem   Size   Used  Avail  Use%  Mounted on\n"
        for name, uuid, fs, tot, free in _DS:
            used = tot - free
            pct = int(used * 100 / tot)
            out += f"VMFS-6     {tot}G  {used}G  {free}G  {pct}%  /vmfs/volumes/{name}\n"
        return out

    def _ps(self):
        return ("    WID    CID   WorldName                 GID\n"
                " 2097152      1   vmkernel                    1\n"
                " 2099003   2099003 hostd                   3201\n"
                " 2099410   2099410 vpxa                    3380\n"
                " 2100119   2100119 vmsyslogd               2118\n"
                + "".join(f" {_wid(v[0]):>7} {_wid(v[0]):>7} vmx-{v[1]:<18} {1000+v[0]}\n"
                          for v in _VMS if v[3] == "on"))

    def _esxtop(self):
        return (f"{time.strftime('%H:%M:%S')}up {int((time.time()-_BOOT)/86400)} days, "
                f"{len([v for v in _VMS if v[3]=='on'])} worlds, "
                f"CPU load average: 0.34, 0.41, 0.39\n"
                "PCPU USED(%): 22 18 25 19 AVG: 21\n"
                "   ID   GID NAME             %USED  %RUN  %SYS  %WAIT\n"
                "    1     1 system            4.10   3.9   0.2  395.0\n"
                + "".join(f" {_wid(v[0])} {1000+v[0]} {v[1]:<14} {random.randint(2,40):>5}.0  "
                          f"{random.randint(2,30)}.0   0.1  {random.randint(80,180)}.0\n"
                          for v in _VMS if v[3] == "on")
                + "(esxtop is interactive; press 'q' to quit)\n")

    def _ls(self, a):
        target = a[-1] if a and not a[-1].startswith("-") else self.cwd
        if target in ("/vmfs/volumes", "/vmfs/volumes/"):
            return "  ".join([d[0] for d in _DS] + [d[1] for d in _DS]) + "\n"
        if target.rstrip("/").endswith("/vmfs"):
            return "volumes  devices\n"
        if target in ("/", ""):
            return ("altbootbank  bin  bootbank  dev  etc  lib  lib64  mbr  opt  "
                    "proc  productLocker  sbin  scratch  store  tardisks  tmp  "
                    "usr  var  vmfs  vmimages\n")
        for name, uuid, fs, tot, free in _DS:
            if name in target or uuid in target:
                return "  ".join(f"{v[1]}" for v in _VMS if v[4] == name) + "\n"
        return ""

    def execute(self, cmd: str) -> str:
        raw = cmd.strip()
        if not raw:
            return ""
        parts = raw.split()
        c = parts[0]
        a = parts[1:]
        if c in ("exit", "logout", "quit"):
            return "__EXIT__"
        if c == "vmware":
            return (f"VMware ESXi {ESXI_VERSION} build-{ESXI_BUILD}\n"
                    f"VMware ESXi {ESXI_VERSION} GA\n")
        if c == "esxcli":
            return self._esxcli(a)
        if c == "vim-cmd":
            return self._vimcmd(a)
        if c == "esxtop":
            return self._esxtop()
        if c in ("df",):
            return self._df()
        if c in ("ps",):
            return self._ps()
        if c == "uname":
            return (f"VMkernel {HOSTNAME} {ESXI_VERSION}.0 #1 SMP Release build-{ESXI_BUILD} "
                    f"Jan 1 2023 x86_64 x86_64 x86_64 ESXi\n")
        if c == "whoami":
            return "root\n"
        if c == "id":
            return "uid=0(root) gid=0(root)\n"
        if c == "hostname":
            return HOSTNAME + ".corp.local\n"
        if c in ("uptime",):
            d = int((time.time() - _BOOT) / 86400)
            return f" {time.strftime('%H:%M:%S')} up {d} days,  load average: 0.34, 0.41, 0.39\n"
        if c == "date":
            return time.strftime("%a %b %e %H:%M:%S UTC %Y") + "\n"
        if c == "pwd":
            return self.cwd + "\n"
        if c == "cd":
            self.cwd = a[0] if a else "/"
            return ""
        if c == "ls":
            return self._ls(a)
        if c == "find":
            # often used to hunt encryption targets
            if any(".vmdk" in x for x in a) or "*.vmdk" in raw:
                return "".join(f"/vmfs/volumes/{v[4]}/{v[1]}/{v[1]}.vmdk\n"
                               f"/vmfs/volumes/{v[4]}/{v[1]}/{v[1]}-flat.vmdk\n"
                               for v in _VMS)
            return ""
        if c == "cat":
            if a and "machine.id" in a[0]:
                return "Welcome to VMware ESXi.\n"
            return f"cat: {a[0] if a else ''}: No such file or directory\n"
        if c in ("help", "?"):
            return ("Commands: esxcli, vim-cmd, esxtop, vmware, df, ps, ls, cat, "
                    "find, uname, whoami, id, hostname, uptime, date, exit\n")
        if c == "echo":
            return " ".join(a) + "\n"
        return f"-ash: {c}: not found\n"
