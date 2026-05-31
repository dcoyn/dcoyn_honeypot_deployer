"""
sensors.win_shell
=================

Windows personality for the SSH fake-shell harness (``ssh_shell_base``).

Capturing keystroke-level commands over RDP isn't feasible at medium
interaction (RDP is a graphical protocol — there's no text shell to read).
Modern Windows Server (2019/2022) ships OpenSSH Server whose default shell is
``cmd.exe``, and attackers brute-force it constantly, so SSH is the realistic
text transport for learning *which Windows commands an intruder runs*.

This projects a believable domain-joined Windows Server: a fake ``C:\\`` tree,
a ``tasklist`` process table, ``systeminfo`` (RAM / CPU / domain / uptime /
hotfixes), local + domain users, networking, the registry, and both ``cmd`` and
``PowerShell`` command handling — including decoding ``powershell -enc`` base64
payloads. Post-exploitation tradecraft is flagged: shadow-copy / backup deletion
(ransomware), account creation, and remote payload download. Nothing executes.
"""
from __future__ import annotations

import base64
import re
import time

from .ssh_shell_base import Personality
from ..core import classify as CLS

HOSTNAME = "WINSRV-DC01"
DOMAIN = "CORP"
FQDN_DOMAIN = "corp.local"
OS_CAPTION = "Microsoft Windows Server 2019 Standard"
OS_VERSION = "10.0.17763"
OS_BUILD = "17763.5458"
CPU_MODEL = "Intel(R) Xeon(R) Silver 4214 CPU @ 2.20GHz"
CPU_CORES = 8
RAM_MB = 32768
_BOOT = time.time() - 11 * 86400 - 7200

_GOOD = {("administrator", "P@ssw0rd!"), ("administrator", "Passw0rd123"),
         ("administrator", "Welcome1"), ("admin", "admin"),
         ("administrator", "Summer2024!")}

_USERS = ["Administrator", "Guest", "krbtgt", "jsmith", "svc_sql", "svc_backup"]
_DOMAIN_ADMINS = ["Administrator", "jsmith"]

# tasklist: (image, pid, mem_kb, svc)
_PROCS = [
    ("System Idle Process", 0, 8, ""), ("System", 4, 144, ""),
    ("smss.exe", 332, 1080, ""), ("csrss.exe", 444, 4972, ""),
    ("wininit.exe", 528, 6320, ""), ("services.exe", 612, 9220, ""),
    ("lsass.exe", 620, 18540, "KeyIso, Netlogon, SamSs"),
    ("svchost.exe", 728, 22140, "DcomLaunch"), ("svchost.exe", 812, 31280, "RPCSS"),
    ("svchost.exe", 980, 44120, "Schedule"), ("MsMpEng.exe", 2208, 198540, "WinDefend"),
    ("sqlservr.exe", 3120, 1485220, "MSSQLSERVER"),
    ("w3wp.exe", 4480, 122300, ""), ("explorer.exe", 5012, 96340, ""),
    ("dns.exe", 1840, 38420, "DNS"), ("ntds.dit-holder lsass", 620, 0, ""),
    ("powershell.exe", 6320, 88200, ""), ("cmd.exe", 6440, 4120, ""),
    ("sshd.exe", 2880, 9220, "sshd"),
]


def win_accept(username, password):
    return (username.lower(), password) in {(u.lower(), p) for u, p in _GOOD} \
        or username.lower() == "administrator"


def _decode_enc(cmd: str) -> str | None:
    m = re.search(r"-e(?:nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{16,})", cmd, re.I)
    if not m:
        return None
    try:
        raw = base64.b64decode(m.group(1) + "===")
        # PowerShell -enc is UTF-16LE
        return raw.decode("utf-16-le", "replace")
    except Exception:
        return None


class WinPersonality(Personality):
    ssh_banner = "SSH-2.0-OpenSSH_for_Windows_8.1"
    service = "winserver_shell"
    listen_port = 22
    host_key_name = "ssh_host_rsa_key"

    def accept_auth(self, username, password):
        return win_accept(username, password)

    def make_session(self, username, src_ip, src_port, session_id):
        return _WinSession(username, src_ip)

    def classify(self, cmd):
        base = CLS.classify_command(cmd)
        low = cmd.lower()
        techs = set(base.get("techniques", []))
        cat = base.get("category")
        notes = list(base.get("notes", []))
        iocs = base.get("iocs") or {}

        dec = _decode_enc(cmd)
        if dec:
            base["decoded_powershell"] = dec[:2000]
            techs.update({"T1059.001", "T1027"})        # PowerShell + obfuscation
            cat = cat or "obfuscated_powershell"
            sub = CLS.classify_command(dec)              # classify the decoded inner cmd
            techs.update(sub.get("techniques", []))
            for u in (sub.get("iocs") or {}).get("urls", []):
                iocs.setdefault("urls", []).append(u)
        if re.search(r"vssadmin\s+delete\s+shadows|win32_shadowcopy.*delete|"
                     r"wbadmin\s+delete|bcdedit.*recoveryenabled\s+no|"
                     r"bcdedit.*bootstatuspolicy\s+ignoreallfailures", low):
            techs.add("T1490"); cat = cat or "inhibit_system_recovery"   # ransomware prep
            notes.append("Deletes backups/shadow copies (ransomware prep)")
        if re.search(r"net\s+user\s+\S+\s+\S+\s+/add|net\s+localgroup\s+administrators\s+\S+\s+/add", low):
            techs.add("T1136.001"); cat = cat or "create_account"
            notes.append("Creates/escalates a local account")
        if re.search(r"reg\s+(save|export).*sam|reg\s+(save|export).*system|"
                     r"\bntds(util)?\b|lsass.*dmp|procdump.*lsass|sekurlsa|mimikatz", low):
            techs.add("T1003"); cat = cat or "credential_dumping"        # OS Cred Dumping
            notes.append("Credential dumping (SAM/LSASS/NTDS)")
        if re.search(r"certutil.*-urlcache|bitsadmin\s+/transfer|"
                     r"invoke-webrequest|\biwr\b|\bcurl\b|\bwget\b|downloadstring|downloadfile", low):
            techs.add("T1105"); cat = cat or "payload_download"
        if re.search(r"net\s+(view|group|user)|nltest|dsquery|whoami\s+/|"
                     r"get-aduser|get-adcomputer|arp\s+-a|net\s+share", low):
            techs.add("T1087"); cat = cat or (cat or "discovery")        # Account/Domain Discovery

        if techs:
            base["techniques"] = sorted(techs)
        if cat:
            base["category"] = cat
        if notes:
            base["notes"] = notes
        if iocs:
            base["iocs"] = iocs
        return base


class _WinSession:
    def __init__(self, username, src_ip):
        self.user = username or "Administrator"
        self.cwd = "C:\\Users\\" + (self.user if self.user.lower() != "administrator"
                                    else "Administrator")
        self.src_ip = src_ip

    def motd(self):
        return (f"Microsoft Windows [Version {OS_VERSION}.{OS_BUILD.split('.')[1]}]\n"
                "(c) Microsoft Corporation. All rights reserved.\n\n")

    def prompt(self):
        return f"{self.cwd}>"

    def _uptime(self):
        secs = int(time.time() - _BOOT)
        d, r = divmod(secs, 86400); h, r = divmod(r, 3600); m, _ = divmod(r, 60)
        return d, h, m

    def _systeminfo(self):
        d, h, m = self._uptime()
        boot = time.strftime("%m/%d/%Y, %I:%M:%S %p", time.localtime(_BOOT))
        return (f"\nHost Name:                 {HOSTNAME}\n"
                f"OS Name:                   {OS_CAPTION}\n"
                f"OS Version:                {OS_VERSION} N/A Build {OS_BUILD.split('.')[0]}\n"
                f"OS Manufacturer:           Microsoft Corporation\n"
                f"OS Configuration:          Primary Domain Controller\n"
                f"Registered Owner:          {DOMAIN}\n"
                f"Original Install Date:     03/14/2023, 09:21:44\n"
                f"System Boot Time:          {boot}\n"
                f"System Manufacturer:       Dell Inc.\n"
                f"System Model:              PowerEdge R640\n"
                f"System Type:               x64-based PC\n"
                f"Processor(s):              1 Processor(s) Installed.\n"
                f"                           [01]: Intel64 Family 6 - {CPU_MODEL}\n"
                f"BIOS Version:              Dell Inc. 2.15.1, 6/21/2023\n"
                f"Windows Directory:         C:\\Windows\n"
                f"System Locale:             en-us;English (United States)\n"
                f"Total Physical Memory:     {RAM_MB:,} MB\n"
                f"Available Physical Memory: {int(RAM_MB*0.36):,} MB\n"
                f"Virtual Memory: Max Size:  {RAM_MB*2:,} MB\n"
                f"Domain:                    {FQDN_DOMAIN}\n"
                f"Logon Server:              \\\\{HOSTNAME}\n"
                f"Hotfix(s):                 6 Hotfix(s) Installed.\n"
                f"                           [01]: KB5034768\n"
                f"                           [02]: KB5034619\n"
                f"Network Card(s):           1 NIC(s) Installed.\n"
                f"                           [01]: Intel(R) I350 Gigabit\n"
                f"                                 IP address(es): [01]: 10.20.30.10\n"
                f"System Up Time:            {d} Days, {h} Hours, {m} Minutes\n")

    def _ipconfig(self, full=False):
        base = ("\nWindows IP Configuration\n\n"
                "Ethernet adapter Ethernet0:\n\n"
                "   Connection-specific DNS Suffix  . : corp.local\n"
                "   IPv4 Address. . . . . . . . . . . : 10.20.30.10\n"
                "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n"
                "   Default Gateway . . . . . . . . . : 10.20.30.1\n")
        if not full:
            return base + "\n"
        return ("\nWindows IP Configuration\n\n"
                f"   Host Name . . . . . . . . . . . . : {HOSTNAME}\n"
                f"   Primary Dns Suffix  . . . . . . . : {FQDN_DOMAIN}\n"
                "   Node Type . . . . . . . . . . . . : Hybrid\n"
                "   IP Routing Enabled. . . . . . . . : No\n\n"
                "Ethernet adapter Ethernet0:\n\n"
                "   Connection-specific DNS Suffix  . : corp.local\n"
                "   Description . . . . . . . . . . . : Intel(R) I350 Gigabit Network Connection\n"
                "   Physical Address. . . . . . . . . : 00-50-56-A1-3C-7E\n"
                "   DHCP Enabled. . . . . . . . . . . : No\n"
                "   IPv4 Address. . . . . . . . . . . : 10.20.30.10(Preferred)\n"
                "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n"
                "   Default Gateway . . . . . . . . . : 10.20.30.1\n"
                "   DNS Servers . . . . . . . . . . . : 10.20.30.10\n"
                "                                       127.0.0.1\n")

    def _tasklist(self, svc=False):
        if svc:
            out = ("\nImage Name                     PID Services\n"
                   "========================= ======== ============================================\n")
            for img, pid, mem, s in _PROCS:
                out += f"{img:<25} {pid:>8} {s or 'N/A'}\n"
            return out
        out = ("\nImage Name                     PID Session Name        Session#    Mem Usage\n"
               "========================= ======== ================ =========== ============\n")
        for img, pid, mem, s in _PROCS:
            out += f"{img:<25} {pid:>8} Services{'':>16}0 {mem:>9,} K\n"
        return out

    def _dir(self, path):
        p = (path or self.cwd).rstrip("\\")
        head = (f" Volume in drive C has no label.\n Volume Serial Number is 7A3C-9F12\n\n"
                f" Directory of {p or 'C:'}\\\n\n")
        def line(date, kind, name):
            return f"{date}    {kind:<14} {name}\n"
        if p.lower() in ("c:", ""):
            body = (line("03/14/2023  09:21 AM", "<DIR>", "inetpub")
                    + line("06/02/2024  02:10 PM", "<DIR>", "Backups")
                    + line("09/15/2018  12:19 AM", "<DIR>", "PerfLogs")
                    + line("05/01/2024  11:44 AM", "<DIR>", "Program Files")
                    + line("05/01/2024  11:40 AM", "<DIR>", "Program Files (x86)")
                    + line("06/10/2024  08:30 AM", "<DIR>", "Users")
                    + line("06/11/2024  03:14 AM", "<DIR>", "Windows"))
            return head + body + "               0 File(s)              0 bytes\n"
        if "users\\administrator" in p.lower():
            body = (line("06/10/2024  08:30 AM", "<DIR>", "Desktop")
                    + line("06/10/2024  08:30 AM", "<DIR>", "Documents")
                    + line("06/10/2024  08:30 AM", "<DIR>", "Downloads")
                    + line("06/02/2024  02:11 PM", "    1,204", "vCenter-creds.txt")
                    + line("06/02/2024  02:09 PM", "   18,944", "passwords.xlsx"))
            return head + body + "               2 File(s)         20,148 bytes\n"
        if p.lower().endswith("users"):
            body = "".join(line("06/10/2024  08:30 AM", "<DIR>", u) for u in
                           ["Administrator", "Public", "jsmith", "svc_sql"])
            return head + body
        return head + "File Not Found\n"

    def _type(self, name):
        n = (name or "").lower()
        if "vcenter-creds" in n:
            return ("vCenter:  https://vcenter.corp.local\n"
                    "user:     administrator@vsphere.local\n"
                    "pass:     vSph3re-Adm!n-2024\n"
                    "esxi root: VMware1!\n")
        if "passwords" in n:
            return "PK\x03\x04... (binary .xlsx file)\n"
        return f"The system cannot find the file specified.\n"

    def _net(self, a):
        j = " ".join(a).lower()
        if j.startswith("user") and len(a) == 1:
            return ("\nUser accounts for \\\\" + HOSTNAME + "\n\n"
                    "-------------------------------------------------------------------------------\n"
                    + "".join(f"{u:<25}" for u in _USERS) + "\n"
                    "The command completed successfully.\n")
        if j.startswith("user "):
            u = a[1]
            return (f"User name                    {u}\n"
                    f"Full Name                    {u}\n"
                    f"Account active               Yes\n"
                    f"Local Group Memberships      *Administrators\n"
                    f"Global Group memberships     *Domain Admins        *Domain Users\n"
                    "The command completed successfully.\n")
        if "localgroup administrators" in j or 'group "domain admins"' in j:
            return ("Members\n-------------------------------------------------------------------------------\n"
                    + "".join(f"{u}\n" for u in _DOMAIN_ADMINS)
                    + "The command completed successfully.\n")
        if j.startswith("share"):
            return ("Share name   Resource                        Remark\n"
                    "-------------------------------------------------------------------------------\n"
                    "ADMIN$       C:\\Windows                      Remote Admin\n"
                    "C$           C:\\                              Default share\n"
                    "NETLOGON     C:\\Windows\\SYSVOL\\sysvol\\...   Logon server share\n"
                    "SYSVOL       C:\\Windows\\SYSVOL\\sysvol        Logon server share\n"
                    "The command completed successfully.\n")
        if j.startswith("accounts"):
            return ("Minimum password length                               7\n"
                    "Maximum password age (days)                           42\n"
                    "Lockout threshold                                     Never\n"
                    "The command completed successfully.\n")
        return "The command completed successfully.\n"

    def execute(self, cmd: str) -> str:
        raw = cmd.strip()
        if not raw:
            return ""
        low = raw.lower()
        parts = raw.split()
        c = parts[0].lower().strip('"')
        a = parts[1:]

        if c in ("exit", "logoff"):
            return "__EXIT__"
        if c == "cls":
            return "\x1b[2J\x1b[H"
        if c in ("ver",):
            return f"\nMicrosoft Windows [Version {OS_VERSION}.{OS_BUILD.split('.')[1]}]\n"
        if c == "whoami":
            if "/priv" in low:
                return ("\nPRIVILEGES INFORMATION\n----------------------\n"
                        "SeDebugPrivilege              Debug programs            Enabled\n"
                        "SeBackupPrivilege             Back up files             Enabled\n"
                        "SeTakeOwnershipPrivilege      Take ownership            Enabled\n")
            if "/groups" in low:
                return "\nBUILTIN\\Administrators   Enabled\nCORP\\Domain Admins       Enabled\n"
            return f"{DOMAIN.lower()}\\{self.user.lower()}\n"
        if c == "hostname":
            return HOSTNAME + "\n"
        if c == "systeminfo":
            return self._systeminfo()
        if c == "ipconfig":
            return self._ipconfig(full=("/all" in low))
        if c == "tasklist":
            return self._tasklist(svc=("/svc" in low))
        if c == "dir":
            return self._dir(a[-1] if a and not a[-1].startswith("/") else self.cwd)
        if c == "type":
            return self._type(a[0] if a else "")
        if c == "cd" or c == "chdir":
            if a:
                t = a[0]
                self.cwd = t if re.match(r"^[A-Za-z]:", t) else (self.cwd + "\\" + t)
            return ("" if a else self.cwd + "\n")
        if c == "net":
            return self._net(a)
        if c in ("quser", "query") and ("user" in low or c == "quser"):
            return (" USERNAME    SESSIONNAME   ID  STATE   IDLE TIME  LOGON TIME\n"
                    f" administrator rdp-tcp#2    2  Active        .   06/12/2024 9:02 AM\n")
        if c == "arp":
            return ("\nInterface: 10.20.30.10 --- 0x4\n"
                    "  Internet Address      Physical Address      Type\n"
                    "  10.20.30.1            00-50-56-a1-00-01     dynamic\n"
                    "  10.20.30.10           00-50-56-a1-3c-7e     dynamic\n")
        if c == "netstat":
            return ("\n  Proto  Local Address          Foreign Address        State\n"
                    "  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING\n"
                    "  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING\n"
                    "  TCP    10.20.30.10:389        0.0.0.0:0              LISTENING\n")
        if c == "nltest":
            return ("    DC01.corp.local\nThe command completed successfully\n")
        if c == "wmic":
            if "computersystem" in low:
                return f"Domain={FQDN_DOMAIN}\nManufacturer=Dell Inc.\nModel=PowerEdge R640\nTotalPhysicalMemory={RAM_MB*1024*1024}\n"
            if "os get" in low:
                return f"Caption={OS_CAPTION}\nVersion={OS_VERSION}\n"
            if "useraccount" in low:
                return "Name\n" + "".join(u + "\n" for u in _USERS)
            return "\n"
        if c == "reg":
            return "\nHKEY_LOCAL_MACHINE\\... \n    (Default)    REG_SZ    (value not set)\n"
        if c == "echo":
            return " ".join(a).replace("%username%", self.user).replace("%userdomain%", DOMAIN) + "\n"
        if c == "set":
            return (f"COMPUTERNAME={HOSTNAME}\nUSERDOMAIN={DOMAIN}\nUSERNAME={self.user}\n"
                    f"USERPROFILE=C:\\Users\\{self.user}\nNUMBER_OF_PROCESSORS={CPU_CORES}\n")
        if c in ("powershell", "powershell.exe", "pwsh"):
            dec = _decode_enc(raw)
            if dec:
                return ""   # decoded command captured via classify(); emulate silent run
            if "get-process" in low:
                return self._tasklist()
            if "get-aduser" in low or "get-adcomputer" in low:
                return "\nDistinguishedName : CN=Administrator,CN=Users,DC=corp,DC=local\nEnabled : True\n"
            if "get-localuser" in low:
                return "\nName           Enabled\n----           -------\n" + "".join(f"{u:<14} True\n" for u in _USERS)
            return ""
        if c in ("vssadmin", "wbadmin", "bcdedit", "cipher"):
            # ransomware prep — produce believable output; flagged in classify()
            if c == "vssadmin" and "delete" in low:
                return "vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool\n(C) Copyright 2001-2013 Microsoft Corp.\n\nSuccessfully deleted 2 shadow copies.\n"
            return "The operation completed successfully.\n"
        if c == "certutil":
            return "****  Online  ****\nCertUtil: -URLCache command completed successfully.\n"
        if c in ("md", "mkdir", "del", "copy", "move", "ren", "attrib"):
            return ""
        return (f"'{parts[0]}' is not recognized as an internal or external command,\n"
                "operable program or batch file.\n")
