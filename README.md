# Tidemark — sensor fleet

A multi-sensor honeypot framework for building a first-party threat-intel feed
out of hundreds of cheap VMs.  Each node runs one of three sensor profiles
(`ssh`, `owa`, `winserver`), captures everything the attacker does, and syncs
structured logs to a private GitHub repo every five minutes. A central
aggregator builds IP-pivoted profiles, JA3/JA4 indices, credential dictionaries,
and command corpora directly inside the repo.

> **Intent.** Research and defensive tooling. The OWA login page uses a
> fictitious company (`Northbridge Logistics`) — never impersonate a real
> organization, that crosses the line into phishing infrastructure.

## Naming

- **Tidemark** — the org / product brand (the threat-intel side; what the
  fleet feeds into).
- **dcoyn_honeypot_deployer** — this repo (`github.com/dcoyn/dcoyn_honeypot_deployer`).
  This is the operator's view; only your dev team sees it.
- **kworker-XXXX** — the on-disk name the agent installs as on each VM. The
  format is enforced by the installer: literal `kworker-` followed by 1-4
  random `[a-z0-9]` characters, mimicking the visual style of real Linux
  kernel worker thread names (`kworker/0:1-events`). **Every VM in the fleet
  gets a fresh random suffix**, so:

  - `systemctl list-units` shows e.g. `kworker-x4z.service` rather than
    something uniform across the fleet.
  - `ps aux` shows `python -m kworker_x4z.runner` (dashes → underscores for
    the Python module).
  - Compromising one node doesn't burn a "look for service X" pivot on the
    rest of the fleet, since each node's name is different.

Nothing in the deployed artifact contains the literal string `honeypot` — not
the systemd units, not `ps aux`, not the event JSON, not the kernel log lines,
not the file paths. (Verified by the test suite.) The word `honeypot` only
appears in the operator-facing repo name (`dcoyn/dcoyn_honeypot_deployer`) and in
backward-compat code that reads old config files.

---

## What you get

| Profile     | Listens on                                       | What it captures                                                                                                              |
|-------------|--------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------|
| `ssh`       | 22                                               | Every auth attempt (username + password + pubkey fingerprint), SSH banner, kex algos, exec & shell commands, files dropped   |
| `owa`       | 80, 443 (self-signed TLS)                        | HTTP method/path/headers/body, every OWA login POST, full UA, scanner paths via catch-all                                     |
| `winserver` | 135, 139, 445, 1433, 3389, 5985, 47001, 49152    | TCP payloads (base64 + hex preview) on Windows-ish ports, plausible service banners (SMB2 negotiate, MSSQL TDS, RDP X.224, WinRM) |

Plus on **every** node:

- **TLS fingerprinting** (JA3 + JA4) via passive packet capture on the wire
- **Connection log** from `nftables` (rejected scans too, not just established)
- **Per-IP enrichment**: GeoIP city, ASN, reverse-DNS PTR
- **Session tracking** with a 300s sliding window
- **Heartbeats** every minute (so dead nodes are obvious)

---

## Quick start

Once both repos are populated in your `dcoyn` org, **on a fresh Debian 12 VM
as root**, pick ONE of the three flows below.

### Flow A — private repos, one-liner

This is what you'll use for cloud-init / mass deploy. Assumes a single
fine-grained PAT (`$GH`) with **read** access to `dcoyn/dcoyn_honeypot_deployer`
and **read-write** access to `dcoyn/dcoyn_honeypot_logs`.

```bash
GH='ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx'   # your PAT (do NOT commit!)
LOGS='https://github.com/dcoyn/dcoyn_honeypot_logs.git'

curl -fsSL -H "Authorization: token $GH" \
  https://raw.githubusercontent.com/dcoyn/dcoyn_honeypot_deployer/main/install.sh \
  | sudo HP_TYPE=random \
         HP_REPO="$LOGS" \
         HP_GIT_TOKEN="$GH" \
         HP_INSTALL_TOKEN="$GH" \
         HP_NODE_NAME="$(hostname)" \
         HP_NONINTERACTIVE=1 \
         bash
```

`HP_TYPE=random` picks one of `ssh|owa|winserver` per VM (fleet diversity).
Pin to a specific profile by setting `HP_TYPE=ssh`, etc.

### Flow B — clone then install (best for first-time testing)

If you want to inspect the code before running it:

```bash
GH='ghp_xxx...'

# 1. clone the deployer
sudo apt-get update -qq && sudo apt-get install -y git
git clone "https://x-access-token:${GH}@github.com/dcoyn/dcoyn_honeypot_deployer.git" \
  /opt/_deployer

# 2. install
sudo HP_TYPE=ssh \
     HP_REPO=https://github.com/dcoyn/dcoyn_honeypot_logs.git \
     HP_GIT_TOKEN="$GH" \
     HP_NODE_NAME="$(hostname)" \
     HP_NONINTERACTIVE=1 \
     bash /opt/_deployer/install.sh

# 3. (optional) remove the clone, install.sh already copied everything it needs
sudo rm -rf /opt/_deployer
```

### Flow C — public repos

If you decide to keep `dcoyn_honeypot_deployer` public (the logs repo should stay
private regardless), drop the `Authorization` header and `HP_INSTALL_TOKEN`:

```bash
curl -fsSL https://raw.githubusercontent.com/dcoyn/dcoyn_honeypot_deployer/main/install.sh \
  | sudo HP_TYPE=random \
         HP_REPO=https://github.com/dcoyn/dcoyn_honeypot_logs.git \
         HP_GIT_TOKEN=ghp_xxx \
         HP_NONINTERACTIVE=1 \
         bash
```

---

### After install — operator commands

The installer prints the random agent name at the end and also writes it to
`/root/.agent-info`. To check status on a node:

```bash
cat /root/.agent-info        # e.g. agent_name=kworker-x4z
NAME=$(awk -F= '/^agent_name/{print $2}' /root/.agent-info)

systemctl status $NAME $NAME-capture $NAME-connlog $NAME-sync.timer
tail -F /var/log/$NAME/events.jsonl
journalctl -u $NAME -f
```

To remove (rolls back sshd_config and nftables):

```bash
sudo bash /path/to/uninstall.sh           # uses /root/.agent-info
sudo bash /path/to/uninstall.sh --all     # nuke every kworker-* install
```

If the install fails, the full install log is at
`/var/log/agent-install-<timestamp>.log` — `tail -F` it for diagnostics.

### Profiles

```bash
HP_TYPE=ssh           # SSH only — most signal per VM
HP_TYPE=owa           # OWA / IIS impersonation
HP_TYPE=winserver     # Windows-flavored multiport
HP_TYPE=random        # installer picks one at random (good for fleet diversity)
```

### Agent-name format (the stealth knob)

The deployer **always** assigns each VM an agent name matching
`^kworker-[a-z0-9]{1,4}$`. By default this is generated freshly per VM:

```bash
# Default behavior: random per VM
sudo HP_TYPE=ssh HP_REPO=… HP_GIT_TOKEN=… HP_NONINTERACTIVE=1 bash /tmp/i.sh
#   → /opt/kworker-x4z/, kworker-x4z.service, python -m kworker_x4z.runner, …
```

You can pin a specific name if you need to (e.g. for a test box you'll log
into a lot), but the format is enforced:

```bash
HP_AGENT_NAME=kworker-test bash /tmp/i.sh     # OK
HP_AGENT_NAME=kworker-a1   bash /tmp/i.sh     # OK
HP_AGENT_NAME=nodewatch    bash /tmp/i.sh     # REJECTED — wrong format
HP_AGENT_NAME=kworker-abcde bash /tmp/i.sh    # REJECTED — too long (max 4)
```

What gets renamed per VM:

- `/opt/kworker-XXXX/` (install root)
- `/var/log/kworker-XXXX/` (event logs)
- `/var/lib/kworker-XXXX/` (state, repo clone, token)
- `/etc/kworker-XXXX/` (env file)
- The system user `kworker-XXXX`
- All systemd units: `kworker-XXXX.service`, `kworker-XXXX-capture.service`,
  `kworker-XXXX-connlog.service`, `kworker-XXXX-sync.timer`
- The Python package directory (with `-` → `_`), so `ps aux` shows
  `python -m kworker_XXXX.runner`
- The nftables log prefix (`KWORKER_XXXX_TCP `, `KWORKER_XXXX_UDP `, etc.)
- The rsyslog filter file (`/etc/rsyslog.d/30-kworker-XXXX.conf`)

> **One important note.** No service-name trick survives a determined attacker
> with root who reads the install path and pokes around. The point is to defeat
> **casual** inspection (`ps`, `systemctl list-units`, `ls /opt`, `find / -name
> '*honeypot*'`) and to **break the pivot from one compromised VM to the
> others**. The `kworker-` prefix specifically blends in next to the real
> kernel worker threads in `ps`. If you want stronger stealth, also disable
> bash history (`HISTSIZE=0`), point `~root/.bash_logout` at `/dev/null`, and
> bake the install into a custom AMI so there's no install log on disk.

---

## Mass deployment

The installer is fully non-interactive when `HP_NONINTERACTIVE=1` is set with the env vars above. From your fleet orchestrator (Terraform `user_data`, Ansible, plain bash loop, cloud-init), pass them in. GitHub tokens go through `HP_GIT_TOKEN` and land in `/var/lib/$AGENT_NAME/.token` (root-only, mode 0600).

### Cloud-init user-data example

```yaml
#cloud-config
runcmd:
  - |
    HP_TYPE=random \
    HP_REPO=https://github.com/dcoyn/dcoyn_honeypot_logs.git \
    HP_GIT_TOKEN=ghp_xxx \
    HP_NODE_NAME=$(hostname) \
    HP_NONINTERACTIVE=1 \
    bash -c "$(curl -fsSL https://raw.githubusercontent.com/dcoyn/dcoyn_honeypot_deployer/main/install.sh)"
```

> The deployer repo (`dcoyn/dcoyn_honeypot_deployer`) is likely private. For
> curl-installable bootstrap on private repos, either embed install.sh
> directly into cloud-init user-data, host it on a separate domain with
> presigned/temporary URLs, or include a deploy-key in the cloud-init
> payload. Avoid baking long-lived tokens into AMIs.

### GitHub PAT setup

1. Create a **fine-grained PAT** scoped to your private logs repo only (e.g.
   `dcoyn/dcoyn_honeypot_logs`, separate from the `dcoyn_honeypot_deployer` code repo).
2. Permissions: **Contents: Read and write**. Nothing else.
3. Set an expiry. Rotate by re-running the installer with a new `HP_GIT_TOKEN`.

> Don't use a classic PAT with `repo` scope unless you accept the blast radius of a leaked token across every repo it can reach.

### Push strategy

Every node does `git pull --rebase --autostash && git push` against the same private repo. Each node writes to a **disjoint set of files** (its own hourly events file, its own node heartbeat) plus a shared set of IP/session/index files. The aggregator merges atomically (tmp + rename) before commit, and the rebase resolves the common case of two nodes pushing simultaneously. For very large fleets (>200 nodes) consider sharding the repo by node-name prefix.

---

## Repo layout produced by the sync

```
events/2026/05/24/<node>-14.jsonl   # raw event firehose, one line per event
ips/<ip>.json                       # everything we've seen FROM that IP, cumulatively
sessions/<sid>.json                 # one file per attacker session
nodes/<node>.json                   # heartbeats + counters per sensor node
index/
  by-asn.json                       # asn -> [ips...]
  by-country.json                   # cc  -> [ips...]
  by-ja4.json                       # ja4 -> [ips...]
  credentials.jsonl                 # every cred attempt across all nodes
  commands.jsonl                    # every SSH command attempted, with seq
```

### Event schema

Every event is one line of JSON in `events.jsonl`:

```json
{
  "ts":             "2026-05-24T14:23:01.123456+00:00",
  "node_name":      "hp-eu-west-04",
  "sensor_profile": "ssh",
  "event_type":     "ssh_auth",
  "session_id":     "9f24a1b8-...",
  "src_ip":         "45.93.20.122",
  "src_port":       54123,
  "dst_port":       22,
  "data": {
    "username": "root",
    "password": "P@ssw0rd123",
    "method":   "password",
    "accepted": false,
    "latency_s": 0.083
  }
}
```

Event types: `connection`, `tcp_payload`, `tls_fingerprint`, `ssh_banner`, `ssh_auth`, `ssh_login_ok`, `ssh_command`, `ssh_session_end`, `http_request`, `http_login`, `win_probe`, `win_payload`, `heartbeat`, `node_start`.

### IP profile (the money artifact)

```json
{
  "ip": "45.93.20.122",
  "first_seen": "2026-05-24T14:23:01Z",
  "last_seen":  "2026-05-24T19:11:48Z",
  "event_count": 184,
  "event_types": { "ssh_auth": 42, "ssh_command": 31, "connection": 12, "tls_fingerprint": 8 },
  "ports_hit":   [22, 445, 3389, 8080],
  "sensors":     ["ssh", "winserver"],
  "nodes":       ["hp-eu-west-04", "hp-us-east-01", "hp-ap-south-02"],
  "sessions":    ["...", "..."],
  "ja3":         ["cb45d9c6fc4364bc10eb8b087be9a7a6"],
  "ja4":         ["t13d0305h2_92548b2f350b_fbabbea27ee8"],
  "user_agents": ["AiTM-Toolkit/2.1", "Mozilla/5.0 ..."],
  "geo":         {"country":"NL","city":"Amsterdam","asn":"AS49981","asn_org":"M247 Europe SRL"},
  "cred_attempts":  42,
  "cred_successes": 3,
  "commands_run":   31
}
```

This is the structure to query when answering *"tell me everything about 45.93.20.122"* — one file, fully self-contained, mergeable across the fleet.

---

## Building a product on top of this

The framework is the easy part. The product is what you do with the data. A few angles that are differentiated vs. existing players (GreyNoise, Censys, Shodan, etc.):

### 1. **JA4 + ASN + command-sequence fingerprints**

Most providers stop at the IP. Combine `JA4` (which survives IP rotation) with the *sequence* of SSH commands run within the first 60s of a session, and you have a behavioral fingerprint that follows the actor across NAT'd egress, mobile carriers, and bulletproof hosters. Call it a "tool-chain ID." Sell it as: *"this scanner is the same actor as that brute-forcer, from a different IP."*

### 2. **First-seen feeds**

You operate hundreds of fresh IPs. Any IP that hits *you* within 24 hours of starting probing is, by definition, doing internet-wide scanning today. That's a vastly higher-quality "scanner" feed than scraping abuse blocklists. Sell it as a **real-time scanner list, refreshed every 5 minutes**, with confidence scored by `(num_nodes_hit / fleet_size)`. The customer drops it into their WAF.

### 3. **Coordinated-campaign detection**

When the same JA4 + UA + URI path appears across ≥N nodes in different ASNs within a 10-minute window, that's not noise, it's a campaign. Surface those as **named campaigns** (`CAMPAIGN-2026-05-24-OWA-AITM-01`) and notify customers when their tenant's TLS fingerprint matches. This is the high-margin part.

### 4. **Credential intel**

The `credentials.jsonl` index is a stream of every password attempted against the fleet, with timing. Three sub-products fall out:
- **Compromised-password feed** — passwords being actively tried right now.
- **Targeted-credentials alerts** — credentials matching the customer's domain (`@customer.com:*`) get a high-priority webhook.
- **Canary tokens** — bury fake-but-plausible creds in your OWA login page hints (`Tip: contact helpdesk@northbridge-logistics.com — last password was 'Spring2024!'`); any subsequent use of `Spring2024!` against any tenant is a confirmed credential-list-trader.

### 5. **The unique-data moat**

Most threat-intel feeds are aggregations of OSINT. Yours is **first-party**: nobody else sees what your sensors see, and you control where they sit. Two cheap multipliers:
- **IPv6 sensors.** Most TI feeds are IPv4-only because their data sources don't see v6 scanning. Stand up half your fleet on v6 prefixes and you instantly have a feed nobody else has.
- **ASN-targeted placement.** Buy small VMs inside specific cloud ASNs (AWS, Azure, DO, Linode, OVH, Hetzner). Scanners often filter on cloud ranges. Each cloud presence is a separate vantage point.

### 6. **Pricing model that actually works for this**

Don't sell per-API-call. Sell **named feeds** (`scanners`, `bruteforcers`, `aitm-toolkits`, `bulk-cred-stuffers`) as a flat-rate subscription, delivered as STIX 2.1 or as a `git pull` from a per-customer mirror repo. Customers love `git`-based delivery: auditable, diffable, free retention. Charge for **velocity** (how fresh) and **breadth** (how many feeds), not volume.

---

## Operational notes

- **Don't run on a VM you care about.** Treat each node as compromised by design.
- The installer **doesn't** disable real services. If you pick `ssh` profile, real sshd is moved to 62222 — make sure your firewall opens it before you push the change.
- Capture is on `eth0` by default. Override with `HP_PCAP_IFACE=ens3` in the systemd env file at `/etc/$AGENT_NAME/env`.
- GeoIP works without a DB but returns `unknown`. Drop a MaxMind `GeoLite2-City.mmdb` + `GeoLite2-ASN.mmdb` at `/var/lib/$AGENT_NAME/geoip/` for proper enrichment.
- For mass deployment, the installer is idempotent — running it again upgrades in place. **But** if you change `HP_AGENT_NAME` between runs, you'll get two parallel installs; don't do that without cleaning up the old one.

---

## Repository layout (what you ship to your private dev repo)

```
install.sh                          # the installer (curl|bash entrypoint)
requirements.txt
nodewatch/                          # python package — renamed at install time
  config.py
  runner.py
  core/
    logger.py                       # jsonl event sink
    session.py                      # sliding-window per-IP session tracker
    enrichment.py                   # GeoIP/ASN/PTR with safe fallbacks
    fingerprint.py                  # self-contained JA3 + JA4 from raw TLS
  sensors/
    ssh_sensor.py                   # paramiko-based, fake shell + fs
    owa_sensor.py                   # Flask app + Northbridge Logistics branding
    win_sensor.py                   # multi-port Windows mimicry
  network/
    packet_capture.py               # scapy sniffer → JA3/JA4 events
    connection_logger.py            # tails nftables log → structured events
  sync/
    aggregator.py                   # builds repo layout from events.jsonl
    github_sync.py                  # pull --rebase --autostash + push
templates/
  owa_login.html
  owa_error.html
```
