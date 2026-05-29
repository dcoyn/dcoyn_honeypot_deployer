"""
nodewatch.core.classify
========================

Turns a captured shell command or an HTTP request path into structured
intel: an attack *category*, the MITRE ATT&CK technique IDs it maps to,
and any IOCs (URLs, IPs, dropped filenames) extracted from it.

This is pure pattern-matching over strings we already log. No execution,
no network. Every function is total: bad input yields an empty result.

Why this matters: an analyst reading a per-IP profile wants "this actor ran
recon, then dropped a cryptominer from 1.2.3.4, then tried to wipe logs",
not 200 raw command lines. Tagging each command at capture time means the
aggregator can roll ATT&CK techniques up per IP and per session for free.

References:
  MITRE ATT&CK Enterprise — https://attack.mitre.org/
"""
from __future__ import annotations

import re
from typing import Optional


# ---------------------------------------------------------------------------
# IOC extraction
# ---------------------------------------------------------------------------
_URL_RE  = re.compile(r"\bhttps?://[^\s'\"|;>)]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
# wget/curl http://x/y -O name  /  ">name"  /  "mv x name"
_OUTFILE_RE = re.compile(r"(?:-O|-o|>>?)\s*([\w./\-]+)")


def extract_iocs(text: str) -> dict:
    """Pull URLs, IPv4 addresses, and likely dropped-file names from a string."""
    out: dict = {}
    if not text:
        return out
    urls = _URL_RE.findall(text)
    if urls:
        out["urls"] = sorted(set(urls))[:20]
    # IPs not already inside a captured URL
    ip_in_url = " ".join(urls)
    ips = [ip for ip in _IPV4_RE.findall(text) if ip not in ip_in_url]
    if ips:
        out["ips"] = sorted(set(ips))[:20]
    files = [f for f in _OUTFILE_RE.findall(text) if "/" in f or "." in f]
    if files:
        out["dropped_files"] = sorted(set(files))[:20]
    return out


# ---------------------------------------------------------------------------
# Command classification
# ---------------------------------------------------------------------------
# (regex, category, [attack technique ids], note)
# Ordered most-specific first; ALL matching rules contribute their techniques,
# but the FIRST match sets the primary category.
_CMD_RULES: list[tuple[re.Pattern, str, list[str], str]] = [
    # --- Malware download / staging (T1105 Ingress Tool Transfer) ---
    (re.compile(r"\b(wget|curl)\b.*\bhttps?://"),               "payload_download",
     ["T1105"], "Downloads a remote payload"),
    (re.compile(r"\b(tftp|ftpget|scp|rsync)\b"),                "payload_download",
     ["T1105"], "Alt-protocol file transfer"),
    (re.compile(r"\b(chmod|chattr)\b.*(\+x|777|755)"),          "make_executable",
     ["T1222"], "Marks a dropped file executable"),
    (re.compile(r"\bbase64\b\s+-d|\|\s*base64\s+-d|\bbase64\b\s+--decode"), "decode_payload",
     ["T1140"], "Decodes an obfuscated/base64 payload"),
    (re.compile(r"\b(echo|printf)\b.*\|\s*(sh|bash)\b|curl[^|]*\|\s*(sh|bash)|wget[^|]*\|\s*(sh|bash)"),
                                                                "pipe_to_shell",
     ["T1059.004", "T1105"], "Pipes a download straight into a shell"),

    # --- Cryptomining (T1496 Resource Hijacking) ---
    (re.compile(r"\b(xmrig|minerd|cpuminer|cgminer|stratum\+tcp|nicehash|nanopool|supportxmr|minexmr)\b"),
                                                                "cryptominer",
     ["T1496"], "Cryptocurrency miner indicators"),

    # --- Persistence ---
    (re.compile(r"\b(crontab|/etc/cron|/var/spool/cron)\b"),    "persistence_cron",
     ["T1053.003"], "Cron-based persistence"),
    (re.compile(r"authorized_keys|\.ssh/.*key|ssh-keygen"),     "persistence_sshkey",
     ["T1098.004"], "SSH authorized_keys persistence"),
    (re.compile(r"\b(systemctl|service)\b.*\b(enable|start)\b|/etc/systemd/system|/etc/rc\.local|/etc/init\.d"),
                                                                "persistence_service",
     ["T1543.002"], "systemd/init service persistence"),
    (re.compile(r"\.bashrc|\.bash_profile|\.profile|/etc/profile"), "persistence_shellrc",
     ["T1546.004"], "Shell-init persistence"),

    # --- Defense evasion / anti-forensics ---
    (re.compile(r"\bhistory\b.*-c|unset\s+HISTFILE|HISTFILE=|/dev/null.*history|rm\s+.*\.bash_history"),
                                                                "clear_history",
     ["T1070.003"], "Clears shell history"),
    (re.compile(r"\brm\b\s+(-rf?\s+)?(/var/log|/var/run/utmp|/var/log/wtmp|/var/log/secure|/var/log/auth)"),
                                                                "clear_logs",
     ["T1070.002"], "Deletes system logs"),
    (re.compile(r"\b(iptables|ufw|firewalld)\b.*\b(flush|-F|disable|stop)\b"), "disable_firewall",
     ["T1562.004"], "Tampers with the host firewall"),
    (re.compile(r"\b(setenforce\s+0|selinux=0|systemctl\s+(stop|disable)\s+(auditd|rsyslog))\b"),
                                                                "disable_security",
     ["T1562.001"], "Disables a security/logging service"),

    # --- Discovery / recon ---
    (re.compile(r"\b(uname|lscpu|nproc|cat\s+/proc/cpuinfo|lsb_release)\b"), "recon_system",
     ["T1082"], "System information discovery"),
    (re.compile(r"\b(whoami|id|groups|sudo\s+-l)\b"),           "recon_user",
     ["T1033"], "User/permission discovery"),
    (re.compile(r"\b(ifconfig|ip\s+a|ip\s+addr|netstat|ss\s+-|arp|route)\b"), "recon_network",
     ["T1016"], "Network configuration discovery"),
    (re.compile(r"\b(ps\s|top\b|htop\b)"),                      "recon_process",
     ["T1057"], "Process discovery"),
    (re.compile(r"/etc/passwd|/etc/shadow|getent\s+passwd"),    "recon_accounts",
     ["T1087.001"], "Local account enumeration"),
    (re.compile(r"\bcat\b.*/proc/.*(scsi|version)|\bdmidecode\b|virt-what|systemd-detect-virt"),
                                                                "recon_vm_detect",
     ["T1497.001"], "Virtualization/sandbox detection"),
    (re.compile(r"nproc|/proc/stat|\bfree\b|\bnvidia-smi\b"),   "recon_resources",
     ["T1082"], "Resource discovery (often pre-mining)"),

    # --- Credential access ---
    (re.compile(r"\.aws/credentials|\.docker/config|\.kube/config|\.git-credentials|id_rsa\b|\.pgpass"),
                                                                "credential_theft",
     ["T1552.001"], "Reads credential files"),
    (re.compile(r"\benv\b\s*$|printenv|cat\s+\.env\b"),         "credential_env",
     ["T1552.001"], "Harvests environment/.env secrets"),

    # --- Lateral movement / pivot ---
    (re.compile(r"\bssh\b\s+\S+@|\bsshpass\b"),                 "lateral_ssh",
     ["T1021.004"], "SSH pivot to another host"),

    # --- Impact ---
    (re.compile(r"\brm\b\s+(-[a-z]*r[a-z]*\s+)?(/\s*$|/\s|/\*|~|/home|/root|/etc|/var|/usr|/boot)"),
                                                                "destruction",
     ["T1485"], "Destructive file removal"),

    # --- Benign-ish navigation (lowest priority, still logged) ---
    (re.compile(r"^\s*(ls|cd|pwd|cat|echo|clear|exit|logout)\b"), "navigation",
     [], "Routine navigation/inspection"),
]


def classify_command(cmd: Optional[str]) -> dict:
    """Classify a single shell command line.

    Returns:
        category     primary attack category (first matching rule) or "other"
        techniques   sorted unique list of MITRE ATT&CK IDs across all matches
        notes        list of human notes for the matched rules
        iocs         dict from extract_iocs (urls/ips/dropped_files), if any
        automated_hint  True if the command looks machine-generated
    """
    out = {"category": "other", "techniques": [], "notes": [], "iocs": {}}
    if not cmd or not cmd.strip():
        out["category"] = "empty"
        return out

    techniques: set[str] = set()
    notes: list[str] = []
    primary: Optional[str] = None
    for rx, cat, techs, note in _CMD_RULES:
        if rx.search(cmd):
            if primary is None:
                primary = cat
            techniques.update(techs)
            notes.append(note)

    if primary is not None:
        out["category"] = primary
    out["techniques"] = sorted(techniques)
    out["notes"] = notes
    iocs = extract_iocs(cmd)
    if iocs:
        out["iocs"] = iocs

    # crude automation hint: very long one-liners, ';'-chains, or no spaces
    if len(cmd) > 200 or cmd.count(";") >= 3 or cmd.count("&&") >= 3:
        out["automated_hint"] = True
    return out


# ---------------------------------------------------------------------------
# HTTP path classification — known scanner / exploit probes
# ---------------------------------------------------------------------------
# (regex over path+query, category, [techniques], note)
_HTTP_RULES: list[tuple[re.Pattern, str, list[str], str]] = [
    (re.compile(r"\$\{jndi:", re.I),                            "exploit_log4shell",
     ["T1190"], "Log4Shell (CVE-2021-44228) JNDI probe"),
    (re.compile(r"\(\)\s*\{.*;\s*\}|/bin/bash.*-c", re.I),      "exploit_shellshock",
     ["T1190"], "Shellshock (CVE-2014-6271) probe"),
    (re.compile(r"\.\./|\.\.%2f|%2e%2e%2f|/etc/passwd", re.I),  "path_traversal",
     ["T1190"], "Directory-traversal / LFI attempt"),
    (re.compile(r"/\.env\b|/\.git/|/\.aws/|/\.ssh/|wp-config\.php|/config\.json", re.I),
                                                                "secret_probe",
     ["T1592", "T1552"], "Probing for exposed secrets/config"),
    (re.compile(r"/phpunit|/vendor/phpunit|eval-stdin\.php", re.I), "exploit_phpunit",
     ["T1190"], "PHPUnit RCE (CVE-2017-9841) probe"),
    (re.compile(r"/cgi-bin/|/boaform/|/GponForm/|/setup\.cgi|/HNAP1", re.I), "exploit_router",
     ["T1190"], "Router/IoT RCE probe"),
    (re.compile(r"/solr/|/struts|/actuator/|/_search|\.action\b", re.I), "exploit_appserver",
     ["T1190"], "App-server CVE probe (Struts/Solr/Spring)"),
    (re.compile(r"/manager/html|/jenkins|/phpmyadmin|/pma/|/adminer", re.I), "admin_probe",
     ["T1190"], "Admin-console discovery"),
    (re.compile(r"\.(php|asp|aspx|jsp)\??.*(cmd|exec|shell|passthru|system)=", re.I),
                                                                "webshell",
     ["T1505.003"], "Web-shell interaction"),
    (re.compile(r"/owa/|/autodiscover|/ecp/|/mapi/", re.I),     "exchange_probe",
     ["T1190"], "Exchange/OWA enumeration"),
    (re.compile(r"sqlmap|union\s+select|' or '1'='1|information_schema", re.I), "sqli",
     ["T1190"], "SQL-injection probe"),
]


def classify_http(path: str, query: str = "", user_agent: str = "") -> dict:
    """Classify an HTTP request by path/query (and optionally UA)."""
    out = {"category": "other", "techniques": [], "notes": []}
    blob = f"{path}?{query}" if query else (path or "")
    if not blob:
        out["category"] = "empty"
        return out

    techniques: set[str] = set()
    notes: list[str] = []
    primary: Optional[str] = None
    for rx, cat, techs, note in _HTTP_RULES:
        if rx.search(blob):
            if primary is None:
                primary = cat
            techniques.update(techs)
            notes.append(note)

    if primary is not None:
        out["category"] = primary
    out["techniques"] = sorted(techniques)
    out["notes"] = notes
    return out
