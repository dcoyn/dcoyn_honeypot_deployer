# dcoyn_honeypot_deployer

Debian honeypot agent. One VM runs one of nine sensor profiles
(`ssh`, `owa`, `winserver`, `fileshare`, `telnet`, `redis`, `docker`, `rdp`,
`esxi`), captures events to JSONL, and pushes them every five minutes to a
per-VM private GitHub repo via a systemd timer. A separate central aggregator
(in another repo) consolidates per-node repos and produces fleet-wide IOC feeds.

The deployed agent never contains the string `honeypot`: it installs under a
randomly generated `kworker-XXXX` name so it blends into a busy box's process
and log noise.

## Requirements

- Debian 12+, kernel ≥ 4.x
- 384 MB RAM, 1 GB disk (local logs are size-bounded — see [Log retention](#log-retention--disk-usage))
- Outbound HTTPS to `github.com`
- Root during install (drops to unprivileged users at runtime)
- A private per-node GitHub repo + a fine-grained PAT scoped to it
  (`Contents: Read+write`, that one repo only)

## Profiles

| `HP_TYPE`   | Ports                                       | Captures |
|-------------|---------------------------------------------|----------|
| `ssh`       | 22 (real sshd moves to 62222)               | SSH auth attempts, kex, exec/shell commands, file drops, canary file exfil |
| `owa`       | 80, 443 (self-signed TLS)                   | HTTP method/path/headers/body, login POSTs, scanner paths |
| `winserver` | 135, 139, 445, 1433, 3389, 5985, 47001, 49152 + 22 | TCP payloads + plausible service banners (SMB2, MSSQL TDS, RDP X.224, WinRM), **plus a cmd.exe/PowerShell fake shell over OpenSSH (22)** that captures every Windows command an intruder runs against a realistic domain-joined server (fake `C:\`, tasklist, systeminfo, users, registry). Decodes `powershell -enc` payloads and flags shadow-copy deletion, account creation, and credential dumping. Real admin sshd moves to 62222. |
| `telnet`    | 23                                          | IoT/Mirai magnet: fake BusyBox login + shell. Logs every credential and command, flags the BusyBox/`MIRAI` arch-probe as a botnet IOC |
| `redis`     | 6379                                        | Speaks the RESP wire protocol. Logs every command and recognizes the classic unauth-Redis RCE chains (SSH-key write, cron write, `MODULE LOAD`, `SLAVEOF` replication) |
| `docker`    | 2375                                        | Fake **Docker Engine API**. Speaks enough REST to keep cryptojacking bots (Kinsing/TeamTNT-style) talking, and captures the `/containers/create` payload: the image pulled, the command run, host bind-mounts / privileged / host-namespace **escape attempts** (T1611), miner images, mining pools, and IOC URLs — all classified to MITRE ATT&CK |
| `rdp`       | 3389                                        | **RDP / Windows Terminal Services**. Does the X.224 negotiation and captures pre-auth recon: the `mstshash` cookie **username** (often `DOMAIN\user`), the requested security (RDP/TLS/CredSSP-NLA), and the client **hostname + build** from the MCS/GCC client-core block |
| `esxi`      | 443 + 22                                    | **VMware ESXi** host (a top ransomware target). Serves a believable ESXi 7.x Welcome page + Host Client, answers the `/sdk` SOAP API (`RetrieveServiceContent` fingerprint), and **captures the credentials** from every SOAP `Login`. **Also exposes the ESXi shell over SSH (22)** — `esxcli`/`vim-cmd`/`esxtop` over a realistic host (fake VMs, VMFS datastores, CPU/RAM) — capturing the commands attackers run and flagging the VMFS-ransomware playbook (stopping VMs, hunting `.vmdk`). Real admin sshd moves to 62222. |
| `fileshare` | 22 + 80 + 443 (real sshd moves to 62222)    | Linux box honeypot: Apache-style open share on 80/443 **and** the SSH sensor on 22. Bait docs (`.env`, `.git/`, SQL dumps, credentials.txt, DOCX/XLSX/HTML canaries) plus the full fake shell. Both sensors share the same per-VM FakeWorld, so the universe (org name, secrets, customer roster) is identical across all ports. |
| `random`    | one of the above, picked at install         | — |

On every profile: nftables connection log, JA3+JA4 fingerprinting **plus passive HASSH (SSH client) fingerprinting** via the sniff sidecar, PTR + GeoIP/ASN lookup, offline threat-intel tagging (hosting/cloud/Tor + SSH-tool/UA classification), MITRE ATT&CK classification of every command and HTTP path, and 300 s session tracking.

> **Profiles that move the real sshd to port 62222:** `ssh`, `fileshare`,
> `esxi`, `winserver` (and `random` when it lands on one of them). **Keep a
> second SSH session open on the new port as a safety net during install.**

---

## Deploy a honeypot

The installer prompts for the per-node repo URL and its PAT, picks a random
`kworker-XXXX` agent name, lays down the systemd units, and kicks an initial
sync to prove the path to GitHub works.

### Option A — interactive (simplest)

Clone the repo (or copy `install.sh`) onto a fresh VM and run it as root. It
asks for the profile (menu), the repo URL, and the token:

```bash
sudo bash install.sh
# or pass the profile directly and only get asked for repo + token:
sudo bash install.sh ssh
```

### Option B — non-interactive one-liner (any profile)

This is the canonical remote install. **Change the one `HP_TYPE=` line** to any
value from the [Profiles](#profiles) table — everything else is identical:

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

(`unset HISTFILE; set +o history` keeps the token out of your shell history;
the trailing `unset` scrubs it from the environment.)

<details>
<summary><b>Ready-to-paste, one block per profile</b> (click to expand)</summary>

Each block is identical except for `HP_TYPE=`.

#### ssh
```bash
 unset HISTFILE; set +o history; \
 read -rp "Node repo URL: " REPO; read -rsp "Token for that repo: " GH; echo; \
 [ -n "$GH" ] && [ -n "$REPO" ] && \
 export HP_GIT_TOKEN="$GH" HP_REPO="$REPO" HP_TYPE=ssh \
        HP_NODE_NAME="$(hostname)" HP_NONINTERACTIVE=1 && \
 curl -fsSL https://raw.githubusercontent.com/dcoyn/dcoyn_honeypot_deployer/main/install.sh | sudo -E bash; \
 unset GH REPO HP_GIT_TOKEN HP_REPO HP_TYPE HP_NODE_NAME HP_NONINTERACTIVE
```

#### owa
```bash
 unset HISTFILE; set +o history; \
 read -rp "Node repo URL: " REPO; read -rsp "Token for that repo: " GH; echo; \
 [ -n "$GH" ] && [ -n "$REPO" ] && \
 export HP_GIT_TOKEN="$GH" HP_REPO="$REPO" HP_TYPE=owa \
        HP_NODE_NAME="$(hostname)" HP_NONINTERACTIVE=1 && \
 curl -fsSL https://raw.githubusercontent.com/dcoyn/dcoyn_honeypot_deployer/main/install.sh | sudo -E bash; \
 unset GH REPO HP_GIT_TOKEN HP_REPO HP_TYPE HP_NODE_NAME HP_NONINTERACTIVE
```

#### winserver
```bash
 unset HISTFILE; set +o history; \
 read -rp "Node repo URL: " REPO; read -rsp "Token for that repo: " GH; echo; \
 [ -n "$GH" ] && [ -n "$REPO" ] && \
 export HP_GIT_TOKEN="$GH" HP_REPO="$REPO" HP_TYPE=winserver \
        HP_NODE_NAME="$(hostname)" HP_NONINTERACTIVE=1 && \
 curl -fsSL https://raw.githubusercontent.com/dcoyn/dcoyn_honeypot_deployer/main/install.sh | sudo -E bash; \
 unset GH REPO HP_GIT_TOKEN HP_REPO HP_TYPE HP_NODE_NAME HP_NONINTERACTIVE
```

#### fileshare
```bash
 unset HISTFILE; set +o history; \
 read -rp "Node repo URL: " REPO; read -rsp "Token for that repo: " GH; echo; \
 [ -n "$GH" ] && [ -n "$REPO" ] && \
 export HP_GIT_TOKEN="$GH" HP_REPO="$REPO" HP_TYPE=fileshare \
        HP_NODE_NAME="$(hostname)" HP_NONINTERACTIVE=1 && \
 curl -fsSL https://raw.githubusercontent.com/dcoyn/dcoyn_honeypot_deployer/main/install.sh | sudo -E bash; \
 unset GH REPO HP_GIT_TOKEN HP_REPO HP_TYPE HP_NODE_NAME HP_NONINTERACTIVE
```

#### telnet
```bash
 unset HISTFILE; set +o history; \
 read -rp "Node repo URL: " REPO; read -rsp "Token for that repo: " GH; echo; \
 [ -n "$GH" ] && [ -n "$REPO" ] && \
 export HP_GIT_TOKEN="$GH" HP_REPO="$REPO" HP_TYPE=telnet \
        HP_NODE_NAME="$(hostname)" HP_NONINTERACTIVE=1 && \
 curl -fsSL https://raw.githubusercontent.com/dcoyn/dcoyn_honeypot_deployer/main/install.sh | sudo -E bash; \
 unset GH REPO HP_GIT_TOKEN HP_REPO HP_TYPE HP_NODE_NAME HP_NONINTERACTIVE
```

#### redis
```bash
 unset HISTFILE; set +o history; \
 read -rp "Node repo URL: " REPO; read -rsp "Token for that repo: " GH; echo; \
 [ -n "$GH" ] && [ -n "$REPO" ] && \
 export HP_GIT_TOKEN="$GH" HP_REPO="$REPO" HP_TYPE=redis \
        HP_NODE_NAME="$(hostname)" HP_NONINTERACTIVE=1 && \
 curl -fsSL https://raw.githubusercontent.com/dcoyn/dcoyn_honeypot_deployer/main/install.sh | sudo -E bash; \
 unset GH REPO HP_GIT_TOKEN HP_REPO HP_TYPE HP_NODE_NAME HP_NONINTERACTIVE
```

#### docker
```bash
 unset HISTFILE; set +o history; \
 read -rp "Node repo URL: " REPO; read -rsp "Token for that repo: " GH; echo; \
 [ -n "$GH" ] && [ -n "$REPO" ] && \
 export HP_GIT_TOKEN="$GH" HP_REPO="$REPO" HP_TYPE=docker \
        HP_NODE_NAME="$(hostname)" HP_NONINTERACTIVE=1 && \
 curl -fsSL https://raw.githubusercontent.com/dcoyn/dcoyn_honeypot_deployer/main/install.sh | sudo -E bash; \
 unset GH REPO HP_GIT_TOKEN HP_REPO HP_TYPE HP_NODE_NAME HP_NONINTERACTIVE
```

#### rdp
```bash
 unset HISTFILE; set +o history; \
 read -rp "Node repo URL: " REPO; read -rsp "Token for that repo: " GH; echo; \
 [ -n "$GH" ] && [ -n "$REPO" ] && \
 export HP_GIT_TOKEN="$GH" HP_REPO="$REPO" HP_TYPE=rdp \
        HP_NODE_NAME="$(hostname)" HP_NONINTERACTIVE=1 && \
 curl -fsSL https://raw.githubusercontent.com/dcoyn/dcoyn_honeypot_deployer/main/install.sh | sudo -E bash; \
 unset GH REPO HP_GIT_TOKEN HP_REPO HP_TYPE HP_NODE_NAME HP_NONINTERACTIVE
```

#### esxi
```bash
 unset HISTFILE; set +o history; \
 read -rp "Node repo URL: " REPO; read -rsp "Token for that repo: " GH; echo; \
 [ -n "$GH" ] && [ -n "$REPO" ] && \
 export HP_GIT_TOKEN="$GH" HP_REPO="$REPO" HP_TYPE=esxi \
        HP_NODE_NAME="$(hostname)" HP_NONINTERACTIVE=1 && \
 curl -fsSL https://raw.githubusercontent.com/dcoyn/dcoyn_honeypot_deployer/main/install.sh | sudo -E bash; \
 unset GH REPO HP_GIT_TOKEN HP_REPO HP_TYPE HP_NODE_NAME HP_NONINTERACTIVE
```

#### random
```bash
 unset HISTFILE; set +o history; \
 read -rp "Node repo URL: " REPO; read -rsp "Token for that repo: " GH; echo; \
 [ -n "$GH" ] && [ -n "$REPO" ] && \
 export HP_GIT_TOKEN="$GH" HP_REPO="$REPO" HP_TYPE=random \
        HP_NODE_NAME="$(hostname)" HP_NONINTERACTIVE=1 && \
 curl -fsSL https://raw.githubusercontent.com/dcoyn/dcoyn_honeypot_deployer/main/install.sh | sudo -E bash; \
 unset GH REPO HP_GIT_TOKEN HP_REPO HP_TYPE HP_NODE_NAME HP_NONINTERACTIVE
```

</details>

### Useful deploy-time extras

```bash
# Pin a specific agent name instead of a random one (must match
# ^kworker-[a-z0-9]{1,4}$). Useful to re-claim a node's identity + logs repo.
export HP_AGENT_NAME=kworker-a1

# Point canary beacons (DOCX/XLSX/HTML bait) at a receiver you control.
# Defaults to this host's own public IP if unset.
export HP_CANARY_URL="http://203.0.113.10"

# Tune local-log retention at install time (see Log retention below).
export HP_LOG_RETENTION_DAYS=3      # session/IP jsonl age cap (days)
export HP_EVENTS_MAX_MB=200         # events.jsonl size cap (MB)
export HP_DISK_BUDGET_GB=8          # hard ceiling for /var/lib + /var/log
export HP_MIN_EVENT_DAYS=14         # never trim raw-event days newer than this
```

After install, the operator summary and `/root/.agent-info` record the chosen
agent name, profile, and node label.

---

## Update an existing honeypot

`upgrade.sh` performs an in-place upgrade to the latest installer **without
re-entering the repo URL or token** — it reads them from the node's existing
per-node repo git config.

**Preserves:** agent name (so the same `kworker-XXXX` → same logs repo), profile
type, logs repo URL + token, and the node label.
**Replaces:** all code under `/opt/<name>`, the systemd units, the rsyslog
filter, and the privsep users (recreated identically). A **new**
`fake_world.json` is generated (the per-VM universe changes) unless you pass
`--keep-universe`.

```bash
# Interactive confirmation, regenerate the fake universe
sudo bash upgrade.sh

# No prompts
sudo bash upgrade.sh --yes

# No prompts, and keep the existing fake universe (org name, secrets, roster)
sudo bash upgrade.sh --yes --keep-universe

# Pull the upgrade straight from GitHub (oneshot)
curl -fsSL https://raw.githubusercontent.com/dcoyn/dcoyn_honeypot_deployer/main/upgrade.sh \
  | sudo bash -s -- --yes --keep-universe

# Upgrade from a non-default source (e.g. a fork or a pinned ref)
sudo bash upgrade.sh --yes --installer-url=https://example.com/path/to/install.sh
```

**Alternative — clean reinstall keeping the same identity:** if you'd rather
start fresh but keep the node pointed at the same logs repo, uninstall and
reinstall with the same agent name and node label:

```bash
OLD=$(sudo awk -F= '/^agent_name/{print $2}' /root/.agent-info)
NODE=$(sudo awk -F= '/^node_name/{print $2}' /root/.agent-info)
sudo bash uninstall.sh "$OLD"
export HP_AGENT_NAME="$OLD" HP_NODE_NAME="$NODE"   # reuse identity + repo
sudo bash install.sh <profile>                      # re-enter repo URL + token
```

---

## Log retention & disk usage

The per-node git repo (pushed to GitHub every few minutes) is the **system of
record**. The files under `/var/log/<agent>/` are a **local convenience cache**,
so they're aged out automatically by a daily root-run timer
(`<agent>-log-prune.timer`):

- **`sessions/*.jsonl` and `by_ip/*.jsonl`** — independent per-session / per-IP
  files. Deleted once older than `HP_LOG_RETENTION_DAYS` (default **3**). On a
  busy node these are the bulk of the disk and inode usage.
- **`events.jsonl`** — a single append-only file the aggregator reads by byte
  offset. It is only truncated when it exceeds `HP_EVENTS_MAX_MB` (default
  **200**) **and** the aggregator has already consumed it to EOF, with the sync
  cursor reset in the same step. This guarantees no un-synced event is ever
  dropped; if the aggregator is behind, the prune skips that file and tries
  again next run.

### Change the retention policy

Edit the per-agent env file and the next daily run (or a manual run) picks it up:

```bash
NAME=$(sudo awk -F= '/^agent_name/{print $2}' /root/.agent-info)

sudo sed -i 's/^HP_LOG_RETENTION_DAYS=.*/HP_LOG_RETENTION_DAYS=2/' /etc/${NAME}/env
sudo sed -i 's/^HP_EVENTS_MAX_MB=.*/HP_EVENTS_MAX_MB=100/'        /etc/${NAME}/env

# Apply now instead of waiting for the daily timer
sudo systemctl start ${NAME}-log-prune.service
sudo journalctl -u ${NAME}-log-prune.service -n 20 --no-pager

# Current footprint
sudo du -sh /var/log/${NAME} /var/log/${NAME}/sessions /var/log/${NAME}/by_ip
```

### The git store (`/var/lib/<agent>/store`) and the disk budget

The per-node git repo is the other big disk consumer. Each 5-minute sync
commits and pushes; the aggregator rewrites whole profile files (`ips/*.json`,
`sessions/*.json`, `node.json`) and appends raw events, so without maintenance
`.git/objects` accumulates every version forever — even though GitHub already
has the full history.

The sync user keeps the agent's `/var/lib` + `/var/log` footprint under
`HP_DISK_BUDGET_GB` (default **8**, with the `HP_MIN_EVENT_DAYS` floor, default
**14**) automatically, right after each successful push, in three tiers,
cheapest first:

1. **`git gc`** (daily) — packs and delta-compresses loose objects. On a repo
   that has never been gc'd this is the dominant win: thousands of
   near-identical rewritten JSON blobs compress dramatically.
2. **Shallow truncation** (weekly, or immediately when over budget) —
   `git fetch --depth=1` + reset to `origin/main`, so the *local* clone forgets
   old history. The remote keeps full history, so this never force-pushes and
   the central aggregator is unaffected.
3. **Raw-event trim** (only if still over budget) — deletes the oldest
   `events/YYYY/MM/DD` directories from the tree and pushes the deletion, never
   touching days newer than `HP_MIN_EVENT_DAYS`. The remote's git history still
   retains them.

The aggregator cursor (`.git/hp-state.json`) is untracked, so gc / shallow /
reset all leave it intact — no events are reprocessed.

To change the ceiling:

```bash
NAME=$(sudo awk -F= '/^agent_name/{print $2}' /root/.agent-info)
sudo sed -i 's/^HP_DISK_BUDGET_GB=.*/HP_DISK_BUDGET_GB=6/' /etc/${NAME}/env
sudo sed -i 's/^HP_MIN_EVENT_DAYS=.*/HP_MIN_EVENT_DAYS=7/' /etc/${NAME}/env
# enforced on the next sync; force one now:
sudo systemctl start ${NAME}-sync.service
```

**Reclaim a store that has already ballooned** (one-time, before the automated
maintenance has run — e.g. on an older install). Run as the sync user; the repo
is owned by `<agent>-y` and running git as root would create root-owned objects
that break the next push:

```bash
NAME=$(sudo awk -F= '/^agent_name/{print $2}' /root/.agent-info)
REPO=/var/lib/$NAME/store

sudo systemctl start ${NAME}-sync.service          # flush a sync first

# simple — keeps full local history, memory-capped for small boxes
sudo -u ${NAME}-y git -C "$REPO" \
  -c pack.threads=1 -c pack.windowMemory=64m -c pack.deltaCacheSize=32m \
  gc --prune=now

# maximum reclaim / lowest memory — drops LOCAL history (remote keeps it)
sudo -u ${NAME}-y git -C "$REPO" fetch --depth=1 origin main
sudo -u ${NAME}-y git -C "$REPO" reset --hard origin/main
sudo -u ${NAME}-y git -C "$REPO" reflog expire --expire=now --all
sudo -u ${NAME}-y git -C "$REPO" gc --prune=now

sudo du -sh "$REPO/.git"
```

---

## Environment variables

| Variable                | Default                          | Description |
|-------------------------|----------------------------------|-------------|
| `HP_TYPE`               | (required)                       | `ssh` \| `owa` \| `winserver` \| `fileshare` \| `telnet` \| `redis` \| `docker` \| `rdp` \| `esxi` \| `random` (may also be passed as the first positional arg) |
| `HP_REPO`               | (required)                       | Per-VM logs repo URL (`https://github.com/<owner>/<repo>.git`) |
| `HP_GIT_TOKEN`          | (required)                       | PAT for `HP_REPO`, `Contents: Read+write` |
| `HP_CANARY_URL`         | this host's public IP            | Base URL embedded in canary docs (DOCX/XLSX/HTML). Beacon hits land here when an attacker opens an exfiltrated file. Operator-controlled; e.g. another OWA honeypot's URL, a canarytokens.org token URL, or a dedicated webhook receiver. |
| `HP_AGENT_NAME`         | randomly generated               | Force a specific agent name. Must match `^kworker-[a-z0-9]{1,4}$` |
| `HP_NODE_NAME`          | `hostname-<random>`              | Free-form label written into every event |
| `HP_SSH_PORT`           | `62222`                          | Port the real sshd moves to (ssh/fileshare/esxi/winserver) |
| `HP_PCAP_IFACE`         | autodetected (`eth0` / `ens3`)   | Interface for the passive JA3/JA4 capture |
| `HP_LOG_RETENTION_DAYS` | `3`                              | Age cap (days) for `sessions/` and `by_ip/` jsonl files in the local cache |
| `HP_EVENTS_MAX_MB`      | `200`                            | Size cap (MB) for `events.jsonl` before a cursor-safe truncate |
| `HP_DISK_BUDGET_GB`     | `8`                              | Ceiling for the agent's `/var/lib` + `/var/log` footprint. The sync user keeps under it (git gc → shallow → raw-event trim). Set below your disk size with headroom for the OS. |
| `HP_MIN_EVENT_DAYS`     | `14`                             | Floor for budget enforcement: never trim raw-event day directories newer than this |
| `HP_INSTALL_REPO`       | `https://github.com/dcoyn/dcoyn_honeypot_deployer.git` | Where install.sh fetches its source |
| `HP_INSTALL_TOKEN`      | falls back to `HP_GIT_TOKEN`     | PAT for the deployer repo if it's private |
| `HP_NONINTERACTIVE`     | `0`                              | `1` disables all prompts |

## Agent naming

Each VM gets an agent name matching `^kworker-[a-z0-9]{1,4}$` — generated
fresh on every install unless `HP_AGENT_NAME` is set. The name is used for:

- `/opt/kworker-XXXX/` — install root
- `/var/log/kworker-XXXX/` — event logs (local cache)
- `/var/lib/kworker-XXXX/` — state, repo clone, token
- `/etc/kworker-XXXX/env` — systemd environment file
- Systemd units (`kworker-XXXX.service`, `-capture`, `-connlog`,
  `-sync.timer`, `-geoip-refresh.timer`, `-log-prune.timer`)
- Python package directory (`kworker_XXXX`, dashes → underscores)
- nftables log prefix (`KWORKER_XXXX_TCP `, etc.)
- rsyslog filter (`/etc/rsyslog.d/30-kworker-XXXX.conf`)

The string `honeypot` does not appear anywhere in the deployed artifact.

## Privilege separation

Three runtime services, each as a separate unprivileged account:

| User              | Service               | Capabilities | Notes |
|-------------------|-----------------------|--------------|-------|
| `kworker-XXXX-s`  | sensor + packet capture | `CAP_NET_BIND_SERVICE`, `CAP_NET_RAW`, `CAP_NET_ADMIN` | reads sensor key/cert |
| `kworker-XXXX-c`  | nftables log tailer   | none, `PrivateNetwork=true` | reads kernel log |
| `kworker-XXXX-y`  | git push (every 5 min) | none | only reader of the GitHub token |
| `kworker-XXXX-rw` | shared group          | — | setgid on log dir |

Two maintenance timers run as **root** oneshots, kept minimal and sandboxed
(`ProtectSystem=strict`, `NoNewPrivileges`, explicit `ReadWritePaths`):

| Unit                          | Schedule           | Job |
|-------------------------------|--------------------|-----|
| `kworker-XXXX-geoip-refresh`  | weekly (+≤4 h jitter) | re-download GeoLite2 City/ASN MMDBs |
| `kworker-XXXX-log-prune`      | daily (+≤1 h jitter)  | age out the local `/var/log` cache (see [Log retention](#log-retention--disk-usage)) |

Every runtime unit sets `NoNewPrivileges`, `ProtectSystem=strict`,
`ProtectHome`, `PrivateTmp`, `PrivateDevices`,
`ProtectKernel{Tunables,Modules,Logs}`, `ProtectControlGroups`,
`RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`,
`LockPersonality`, plus explicit `ReadOnlyPaths`/`ReadWritePaths`.

Token at `/var/lib/kworker-XXXX/.token` is mode `0400` owned by the sync
user. Sensor and connlog processes cannot read it.

## Operator commands

```bash
NAME=$(sudo awk -F= '/^agent_name/{print $2}' /root/.agent-info)

# unit health (runtime services + all timers)
sudo systemctl is-active ${NAME} ${NAME}-capture ${NAME}-connlog \
     ${NAME}-sync.timer ${NAME}-geoip-refresh.timer ${NAME}-log-prune.timer

# all timers and when they next fire
sudo systemctl list-timers "${NAME}-*" --all

# live events
sudo tail -F /var/log/${NAME}/events.jsonl

# journal (main sensor)
sudo journalctl -u ${NAME} -f

# what's actually listening (swap the ports for your profile)
sudo ss -tlnp | grep -E ':(22|23|80|443|445|2375|3389|6379|62222)\s'

# force a sync now, then check the last commits in the local repo clone
sudo systemctl start ${NAME}-sync.service
sudo -u ${NAME}-y git -C /var/lib/${NAME}/store log --oneline -5

# run / inspect the log-prune now
sudo systemctl start ${NAME}-log-prune.service
sudo journalctl -u ${NAME}-log-prune.service -n 20 --no-pager

# disk footprint of the local cache
sudo du -sh /var/log/${NAME} /var/log/${NAME}/{sessions,by_ip} 2>/dev/null

# install log
sudo less /var/log/agent-install-*.log
```

## Troubleshooting

- **Locked out over SSH after install.** On `ssh`/`fileshare`/`esxi`/`winserver`
  (and `random` when it picked one of those), the real admin sshd is on
  **62222**: `ssh -p 62222 you@host`.
- **Sync keeps failing.** `sudo journalctl -u ${NAME}-sync` — the token needs
  `Contents: Read+write` on *that* repo, and the very first push may need to
  create the branch. Confirm the remote: `sudo -u ${NAME}-y git -C
  /var/lib/${NAME}/store remote -v`.
- **No events showing up.** Check the sensor is active
  (`systemctl is-active ${NAME}`), that it's listening on the expected ports
  (`ss -tlnp`), and that the cloud firewall/security group actually allows
  inbound to those ports.
- **`-capture` or `-connlog` inactive.** These degrade gracefully (you lose TLS
  fingerprinting / the nftables connection log, respectively); the main sensor
  still runs. The journal for each unit explains why.
- **Disk filling up.** Lower `HP_LOG_RETENTION_DAYS` / `HP_EVENTS_MAX_MB` in
  `/etc/${NAME}/env` and run `sudo systemctl start ${NAME}-log-prune.service`.
  See [Log retention](#log-retention--disk-usage).

## Uninstall

Rolls back sshd_config, flushes nftables, removes users/groups and all
`/opt`, `/var/log`, `/var/lib`, `/etc` artifacts (and the geoip/log-prune
scripts and units) for the agent. The install log is left in place for
forensics.

```bash
# remove the install named in /root/.agent-info
sudo bash uninstall.sh

# remove a specific agent
sudo bash uninstall.sh kworker-x4z

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

`.git/hp-state.json` exists locally as the sync cursor (the last-processed byte
offset into `events.jsonl`) but is never tracked by git — anything under
`.git/` is ignored by definition.

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
`docker_container_create`, `rdp_connect`, `rdp_client_info`, `esxi_request`, `esxi_login`, `heartbeat`.

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

### Attacker profile (derived verdict)

On top of the raw signals, each IP profile carries a derived verdict so an
analyst can sort and triage at a glance:

- **`actor_type`** — one of `research_scanner`, `ransomware_operator`,
  `cryptojacker`, `credential_harvester`, `container_escape_operator`,
  `iot_botnet`, `interactive_operator`, `credential_bruteforcer`,
  `automated_scanner`, `prober`.
- **`threat_score`** — 0-100, weighting destructive TTPs (ransomware, credential
  dumping, container escape), credential success, hands-on-keyboard activity and
  infra type. Benign internet-wide scanners are capped low.
- **`profile_tags`** — e.g. `ransomware-ttp`, `credential-dumping`,
  `cryptojacking`, `persistence`, `captured-domain-creds`, `multi-service`.
- **`is_known_scanner` / `scanner_name`** — flags benign research scanners
  (Censys, Shodan, Shadowserver, BinaryEdge, Rapid7, …) so they don't pollute
  the real-attacker view.

Plus the supporting evidence behind the verdict:

- **Credential corpus** — `usernames_tried`, `passwords_tried` (the actual
  wordlist they used, across SSH/RDP/ESXi/OWA/telnet), with `cred_attempts` /
  `cred_successes`.
- **Behavioural / temporal** — `active_hours_utc`, `active_window_utc` (operator
  timezone hint), `active_days`, `first_seen` / `last_seen`, `sessions`.
- **Captured artifacts** — `captured_ssh_keys` (a key the attacker installed —
  a reusable cross-victim IOC), `captured_credentials` / `captured_netntlmv2`
  (from canaries), `decoded_powershell`, `crypto_wallets`, `mining_pools`,
  `docker_images`.
- **Network attribution** — `asn`, `as_org`, `rdns`, `country`, `ports_hit`,
  `sensors` (which honeypot types this IP touched — multi-service = coordinated).
- **Per-OS command corpus** — `esxi_commands`, `windows_commands` (exactly what
  was typed in the fake shells).

## Repository layout

```
install.sh                          # installer entrypoint
upgrade.sh                          # in-place upgrade (keeps name/profile/repo/token)
uninstall.sh                        # rollback
requirements.txt
nodewatch/                          # renamed to kworker_XXXX at install
  config.py
  runner.py
  core/
    logger.py                       # jsonl event sink (events.jsonl + sessions/ + by_ip/)
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
    rdp_sensor.py                   # port 3389 — RDP/Terminal Services, pre-auth recon
    esxi_sensor.py                  # port 443 — VMware ESXi, SOAP credential capture
    ssh_shell_base.py               # reusable paramiko SSH fake-shell harness
    esxi_shell.py                   # ESXi shell personality (esxcli/vim-cmd, SSH 22)
    win_shell.py                    # Windows cmd/PowerShell shell personality (SSH 22)
    beacon.py                       # universal canary beacon receiver (non-HTTP profiles)
    fake_fs.py / fake_system.py / fake_world.py  # the per-VM fake universe
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