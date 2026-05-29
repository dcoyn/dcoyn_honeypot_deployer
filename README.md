# dcoyn_honeypot_deployer

Debian honeypot agent. One VM runs one of four sensor profiles
(`ssh`, `owa`, `winserver`, `fileshare`), captures events to JSONL, and pushes them
every five minutes to a per-VM private GitHub repo via systemd timer.
A separate central aggregator (in another repo) consolidates per-node
repos and produces fleet-wide IOC feeds.

## Requirements

- Debian 12+, kernel ≥ 4.x
- 384 MB RAM, 1 GB disk
- Outbound HTTPS to `github.com`
- Root during install (drops to unprivileged users at runtime)

## Profiles

| `HP_TYPE`   | Ports                                       | Captures |
|-------------|---------------------------------------------|----------|
| `ssh`       | 22 (real sshd moves to 62222)               | SSH auth attempts, kex, exec/shell commands, file drops, canary file exfil |
| `owa`       | 80, 443 (self-signed TLS)                   | HTTP method/path/headers/body, login POSTs, scanner paths |
| `winserver` | 135, 139, 445, 1433, 3389, 5985, 47001, 49152 | TCP payloads + plausible service banners (SMB2, MSSQL TDS, RDP X.224, WinRM) |
| `telnet`    | 23                                          | IoT/Mirai magnet: fake BusyBox login + shell. Logs every credential and command, flags the BusyBox/`MIRAI` arch-probe as a botnet IOC |
| `redis`     | 6379                                        | Speaks the RESP wire protocol. Logs every command and recognizes the classic unauth-Redis RCE chains (SSH-key write, cron write, `MODULE LOAD`, `SLAVEOF` replication) |
| `docker`    | 2375                                        | Fake **Docker Engine API**. Speaks enough REST to keep cryptojacking bots (Kinsing/TeamTNT-style) talking, and captures the `/containers/create` payload: the image pulled, the command run, host bind-mounts / privileged / host-namespace **escape attempts** (T1611), miner images, mining pools, and IOC URLs — all classified to MITRE ATT&CK |
| `fileshare` | 22 + 80 + 443 (real sshd moves to 62222)    | Linux box honeypot: Apache-style open share on 80/443 **and** the SSH sensor on 22. Bait docs (`.env`, `.git/`, SQL dumps, credentials.txt, DOCX/XLSX/HTML canaries) plus the full fake shell. Both sensors share the same per-VM FakeWorld, so the universe (org name, secrets, customer roster) is identical across all ports. |
| `random`    | one of the above, picked at install         | — |

On every profile: nftables connection log, JA3+JA4 fingerprinting **plus passive HASSH (SSH client) fingerprinting** via the sniff sidecar, PTR + GeoIP/ASN lookup, offline threat-intel tagging (hosting/cloud/Tor + SSH-tool/UA classification), MITRE ATT&CK classification of every command and HTTP path, and 300 s session tracking.

## Install

Run on a fresh VM as root. The installer prompts for the per-node repo URL
and its PAT (fine-grained, `Contents: Read+write`, scoped to that one repo).
Keep a second SSH session open as a safety net — the installer moves the
real sshd to port 62222 for `ssh`/`random` profiles.

### Random profile

```bash
 unset HISTFILE; set +o history; \
 read -rp "Node repo URL: " REPO; \
 read -rsp "Token for that repo: " GH; echo; \
 [ -n "$GH" ] && [ -n "$REPO" ] && \
 export HP_GIT_TOKEN="$GH" \
        HP_REPO="$REPO" \
        HP_TYPE=random \
        HP_NODE_NAME="$(hostname)" \
        HP_NONINTERACTIVE=1 && \
 curl -fsSL \
      https://raw.githubusercontent.com/dcoyn/dcoyn_honeypot_deployer/main/install.sh \
   | sudo -E bash; \
 unset GH REPO HP_GIT_TOKEN HP_REPO HP_TYPE HP_NODE_NAME HP_NONINTERACTIVE
```

### SSH

```bash
 unset HISTFILE; set +o history; \
 read -rp "Node repo URL: " REPO; \
 read -rsp "Token for that repo: " GH; echo; \
 [ -n "$GH" ] && [ -n "$REPO" ] && \
 export HP_GIT_TOKEN="$GH" \
        HP_REPO="$REPO" \
        HP_TYPE=ssh \
        HP_NODE_NAME="$(hostname)" \
        HP_NONINTERACTIVE=1 && \
 curl -fsSL \
      https://raw.githubusercontent.com/dcoyn/dcoyn_honeypot_deployer/main/install.sh \
   | sudo -E bash; \
 unset GH REPO HP_GIT_TOKEN HP_REPO HP_TYPE HP_NODE_NAME HP_NONINTERACTIVE
```

### OWA

```bash
 unset HISTFILE; set +o history; \
 read -rp "Node repo URL: " REPO; \
 read -rsp "Token for that repo: " GH; echo; \
 [ -n "$GH" ] && [ -n "$REPO" ] && \
 export HP_GIT_TOKEN="$GH" \
        HP_REPO="$REPO" \
        HP_TYPE=owa \
        HP_NODE_NAME="$(hostname)" \
        HP_NONINTERACTIVE=1 && \
 curl -fsSL \
      https://raw.githubusercontent.com/dcoyn/dcoyn_honeypot_deployer/main/install.sh \
   | sudo -E bash; \
 unset GH REPO HP_GIT_TOKEN HP_REPO HP_TYPE HP_NODE_NAME HP_NONINTERACTIVE
```

### Winserver

```bash
 unset HISTFILE; set +o history; \
 read -rp "Node repo URL: " REPO; \
 read -rsp "Token for that repo: " GH; echo; \
 [ -n "$GH" ] && [ -n "$REPO" ] && \
 export HP_GIT_TOKEN="$GH" \
        HP_REPO="$REPO" \
        HP_TYPE=winserver \
        HP_NODE_NAME="$(hostname)" \
        HP_NONINTERACTIVE=1 && \
 curl -fsSL \
      https://raw.githubusercontent.com/dcoyn/dcoyn_honeypot_deployer/main/install.sh \
   | sudo -E bash; \
 unset GH REPO HP_GIT_TOKEN HP_REPO HP_TYPE HP_NODE_NAME HP_NONINTERACTIVE
```

### Fileshare

```bash
 unset HISTFILE; set +o history; \
 read -rp "Node repo URL: " REPO; \
 read -rsp "Token for that repo: " GH; echo; \
 [ -n "$GH" ] && [ -n "$REPO" ] && \
 export HP_GIT_TOKEN="$GH" \
        HP_REPO="$REPO" \
        HP_TYPE=fileshare \
        HP_NODE_NAME="$(hostname)" \
        HP_NONINTERACTIVE=1 && \
 curl -fsSL \
      https://raw.githubusercontent.com/dcoyn/dcoyn_honeypot_deployer/main/install.sh \
   | sudo -E bash; \
 unset GH REPO HP_GIT_TOKEN HP_REPO HP_TYPE HP_NODE_NAME HP_NONINTERACTIVE
```

## Environment variables

| Variable             | Default                          | Description |
|----------------------|----------------------------------|-------------|
| `HP_TYPE`            | (required)                       | `ssh` \| `owa` \| `winserver` \| `fileshare` \| `telnet` \| `redis` \| `docker` \| `random` |
| `HP_CANARY_URL`      | (empty)                          | Base URL embedded in canary docs (DOCX/XLSX/HTML). Beacon hits land here when an attacker opens an exfiltrated file. Operator-controlled; e.g. another OWA honeypot's URL, or a canarytokens.org token URL, or a dedicated webhook receiver. |
| `HP_REPO`            | (required)                       | Per-VM logs repo URL (`https://github.com/<owner>/<repo>.git`) |
| `HP_GIT_TOKEN`       | (required)                       | PAT for `HP_REPO`, `Contents: Read+write` |
| `HP_AGENT_NAME`      | randomly generated               | Force a specific agent name. Must match `^kworker-[a-z0-9]{1,4}$` |
| `HP_NODE_NAME`       | `hostname-<random>`              | Free-form label written into every event |
| `HP_SSH_PORT`        | `62222`                          | Port the real sshd moves to |
| `HP_PCAP_IFACE`      | autodetected (`eth0` / `ens3`)   | Interface for the passive JA3/JA4 capture |
| `HP_INSTALL_REPO`    | `https://github.com/dcoyn/dcoyn_honeypot_deployer.git` | Where install.sh fetches its source |
| `HP_INSTALL_TOKEN`   | falls back to `HP_GIT_TOKEN`     | PAT for the deployer repo if it's private |
| `HP_NONINTERACTIVE`  | `0`                              | `1` disables all prompts |

## Agent naming

Each VM gets an agent name matching `^kworker-[a-z0-9]{1,4}$` — generated
fresh on every install unless `HP_AGENT_NAME` is set. The name is used for:

- `/opt/kworker-XXXX/` — install root
- `/var/log/kworker-XXXX/` — event logs
- `/var/lib/kworker-XXXX/` — state, repo clone, token
- `/etc/kworker-XXXX/env` — systemd environment file
- Systemd units (`kworker-XXXX.service`, `-capture`, `-connlog`, `-sync.timer`)
- Python package directory (`kworker_XXXX`, dashes → underscores)
- nftables log prefix (`KWORKER_XXXX_TCP `, etc.)
- rsyslog filter (`/etc/rsyslog.d/30-kworker-XXXX.conf`)

The string `honeypot` does not appear anywhere in the deployed artifact.

## Privilege separation

Four services, each as a separate unprivileged account:

| User              | Service               | Capabilities | Notes |
|-------------------|-----------------------|--------------|-------|
| `kworker-XXXX-s`  | sensor + packet capture | `CAP_NET_BIND_SERVICE`, `CAP_NET_RAW`, `CAP_NET_ADMIN` | reads sensor key/cert |
| `kworker-XXXX-c`  | nftables log tailer   | none, `PrivateNetwork=true` | reads kernel log |
| `kworker-XXXX-y`  | git push (every 5 min) | none | only reader of the GitHub token |
| `kworker-XXXX-rw` | shared group          | — | setgid on log dir |

Every unit sets `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`,
`PrivateTmp`, `PrivateDevices`, `ProtectKernel{Tunables,Modules,Logs}`,
`ProtectControlGroups`, `RestrictNamespaces`, `RestrictRealtime`,
`RestrictSUIDSGID`, `LockPersonality`, plus explicit
`ReadOnlyPaths`/`ReadWritePaths`.

Token at `/var/lib/kworker-XXXX/.token` is mode `0400` owned by the sync
user. Sensor and connlog processes cannot read it.

## Operator commands

```bash
NAME=$(sudo awk -F= '/^agent_name/{print $2}' /root/.agent-info)

# unit health
sudo systemctl is-active ${NAME} ${NAME}-capture ${NAME}-connlog ${NAME}-sync.timer

# live events
sudo tail -F /var/log/${NAME}/events.jsonl

# journal
sudo journalctl -u ${NAME} -f

# port bindings
sudo ss -tlnp | grep -E ':(22|62222)\s'

# force a sync now
sudo systemctl start ${NAME}-sync.service
sudo -u ${NAME}-y git -C /var/lib/${NAME}/store log --oneline -5

# install log
sudo less /var/log/agent-install-*.log
```

## Uninstall

Rolls back sshd_config, flushes nftables, removes users/groups and all
`/opt`, `/var/log`, `/var/lib`, `/etc` artifacts for the agent.

```bash
# remove the install named in /root/.agent-info
sudo bash uninstall.sh

# remove every kworker-* install on this host
sudo bash uninstall.sh --all
```

## Per-node repo layout (what the sync pushes)

```
events/YYYY/MM/DD/<node>-HH.jsonl   # raw event stream, one event per line
ips/<ip>.json                        # this node's view of one source IP
sessions/<sid>.json                  # one file per session
node.json                            # heartbeat + counters
```

`.git/hp-state.json` exists locally as the sync cursor but is never tracked
by git (anything under `.git/` is ignored by definition).

## Event schema

```json
{
  "ts":             "2026-05-26T14:23:01.123456+00:00",
  "event_id":       "60f30229-…",
  "session_id":     "9f24a1b8-…",
  "node_name":      "lon1-vm",
  "sensor_profile": "ssh",
  "event_type":     "ssh_auth",
  "src_ip":         "45.93.20.122",
  "src_port":       54123,
  "dst_port":       22,
  "proto":          "tcp",
  "data": {
    "username": "root",
    "password": "P@ssw0rd123",
    "method":   "password",
    "accepted": false,
    "geo": { "ptr": "host.example.com" }
  }
}
```

Event types: `node_start`, `connection`, `tcp_payload`, `tls_fingerprint`,
`ssh_fingerprint` (HASSH), `ssh_session_start`, `ssh_banner`, `ssh_auth`,
`ssh_login_ok`, `ssh_command`, `ssh_session_end`, `http_request`, `http_login`,
`win_probe`, `win_payload`, `telnet_auth`, `telnet_command`,
`telnet_session_end`, `redis_command`, `docker_api`,
`docker_container_create`, `heartbeat`.

### Attacker intelligence (added to `data` on most events)

Every event now carries machine-derived intel so the central feed is
analyst-ready without post-processing:

- **`data.intel.source`** — `infra` (`cloud`/`hosting`/`vpn`/`tor`/`residential`)
  and a normalized `provider` slug, derived offline from the ASN org string
  (no extra feeds/downloads).
- **`data.intel.ssh_client`** — which SSH *tool* connected, parsed from the
  client banner (`openssh`/`putty` = likely human; `paramiko`/`libssh2`/`go-ssh`/
  `zgrab`/`mirai` = automated), with an `automated` flag.
- **`data.intel.http_client`** — UA bucket (`sqlmap`/`nuclei`/`curl`/`browser`…).
- **`data.classification`** — for every shell command and HTTP path: an attack
  `category`, the **MITRE ATT&CK** technique IDs it maps to, and extracted IOCs
  (`urls`, `ips`, `dropped_files`).
- **`ssh_fingerprint` events** carry **HASSH** (`hassh` md5 + offered
  `kex`/`ciphers`/`macs`) — the SSH equivalent of JA3, so the same tool is
  recognizable across IPs even when the version banner is spoofed.

The aggregator rolls these up per IP into an attacker scorecard:
`infra`, `provider`, `automated`, `ssh_tools`, `http_tools`, `hassh`,
`attack_techniques` (ATT&CK), `attack_categories` (counts), `ioc_ips`,
`ioc_urls`, `redis_attack_chains`, and `botnet_probe`.

## Repository layout

```
install.sh                          # installer entrypoint
uninstall.sh                        # rollback
requirements.txt
nodewatch/                          # renamed to kworker_XXXX at install
  config.py
  runner.py
  core/
    logger.py                       # jsonl event sink
    session.py                      # sliding-window per-IP session tracker
    enrichment.py                   # PTR + GeoIP/ASN lookup
    fingerprint.py                  # JA3 + JA4 (TLS) + HASSH (SSH KEXINIT)
    threat_intel.py                 # offline infra/SSH-tool/UA classification
    classify.py                     # MITRE ATT&CK command + HTTP-path classifier
  sensors/
    ssh_sensor.py
    owa_sensor.py
    win_sensor.py
    telnet_sensor.py                # port 23 — IoT/Mirai BusyBox honeypot
    redis_sensor.py                 # port 6379 — RESP protocol, RCE-chain detection
    docker_sensor.py                # port 2375 — fake Docker API, container-escape capture
    beacon.py                       # universal canary beacon receiver (non-HTTP profiles)
  network/
    packet_capture.py               # scapy sniffer → JA3/JA4 + HASSH
    connection_logger.py            # nftables log tailer
  sync/
    aggregator.py                   # builds per-node repo layout + scorecards
    github_sync.py                  # pull --rebase + push
templates/
  owa_login.html
  owa_error.html
```
