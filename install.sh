#!/usr/bin/env bash
# =============================================================================
#  dcoyn_honeypot_deployer — sensor installer (dcoyn/dcoyn_honeypot_deployer)
# -----------------------------------------------------------------------------
#  Installs one sensor profile on a Debian/Ubuntu VM. Every artifact on disk
#  uses a random "kworker-XXXX" name so the fleet doesn't share a "look for
#  service X" pivot.
#
#  Usage (local checkout):
#      sudo ./install.sh
#
#  Usage (remote, public repo):
#      curl -fsSL https://raw.githubusercontent.com/dcoyn/dcoyn_honeypot_deployer/main/install.sh \
#        | sudo bash
#
#  Usage (remote, private repo — pass token):
#      sudo HP_INSTALL_TOKEN=ghp_xxx HP_GIT_TOKEN=ghp_xxx HP_REPO=... HP_TYPE=ssh \
#           HP_NONINTERACTIVE=1 bash -c "$(curl -fsSL \
#           -H 'Authorization: token ghp_xxx' \
#           https://raw.githubusercontent.com/dcoyn/dcoyn_honeypot_deployer/main/install.sh)"
#
#  Environment variables (all optional, defaults listed in -h output):
#      HP_TYPE            ssh|owa|winserver|random       (sensor profile)
#      HP_AGENT_NAME      kworker-[a-z0-9]{1,4}          (force a specific name)
#      HP_REPO            git URL of THIS node's repo
#                          (e.g. https://github.com/dcoyn/dcoyn_honeypot_logs.git
#                          — you create one private repo per VM in the GitHub UI)
#      HP_GIT_TOKEN       ghp_…                          (PAT scoped to ONLY
#                                                          that one node repo,
#                                                          Contents: r/w)
#      HP_INSTALL_TOKEN   ghp_…                          (PAT for the deployer
#                                                          repo, if private;
#                                                          falls back to
#                                                          HP_GIT_TOKEN)
#      HP_INSTALL_REPO    git URL of this deployer repo
#                          (default https://github.com/dcoyn/dcoyn_honeypot_deployer.git)
#      HP_NODE_NAME       free-form node label           (default: hostname-random)
#      HP_SSH_PORT        port the real admin sshd moves to (default 62222)
#      HP_NONINTERACTIVE  1 to disable prompts
# =============================================================================

set -Eeuo pipefail

# -----------------------------------------------------------------------------
# Handle -h/--help BEFORE setting up any logging redirect
# -----------------------------------------------------------------------------
case "${1:-}" in
  -h|--help)
    sed -n '/^# =====.*=====$/,/^# =====.*=====$/p' "$0" | sed 's/^# \?//'
    exit 0
    ;;
esac

# -----------------------------------------------------------------------------
# 0. Logging and error handling — set up FIRST so everything is captured
# -----------------------------------------------------------------------------
INSTALL_TS=$(date -u +%Y%m%d-%H%M%S)
INSTALL_LOG="/var/log/agent-install-${INSTALL_TS}.log"
# Failsafe: if /var/log isn't writable yet, fall back to /tmp
if ! mkdir -p /var/log 2>/dev/null || ! touch "$INSTALL_LOG" 2>/dev/null; then
  INSTALL_LOG="/tmp/agent-install-${INSTALL_TS}.log"
  touch "$INSTALL_LOG"
fi
chmod 0600 "$INSTALL_LOG" 2>/dev/null || true

# Mirror everything we say (stdout + stderr) into the log file
exec > >(tee -a "$INSTALL_LOG") 2>&1

C_R='\033[0;31m'; C_G='\033[0;32m'; C_Y='\033[0;33m'; C_B='\033[0;34m'; C_N='\033[0m'
_ts() { date -u +'%Y-%m-%dT%H:%M:%SZ'; }
log()  { echo -e "$(_ts) ${C_B}[*]${C_N} $*"; }
ok()   { echo -e "$(_ts) ${C_G}[+]${C_N} $*"; }
warn() { echo -e "$(_ts) ${C_Y}[!]${C_N} $*"; }
err()  { echo -e "$(_ts) ${C_R}[x]${C_N} $*" >&2; }
die()  { err "$*"; exit 1; }

# Track installed state for rollback
declare -a INSTALLED_UNITS=()
declare -a CREATED_DIRS=()
declare -a INSTALLED_FILES=()
INSTALL_FAILED=0

on_error() {
  local lineno="$1" rc="$2" cmd="$3"
  INSTALL_FAILED=1
  err "--------------------------------------------------------------------"
  err "Install failed at line ${lineno}: '${cmd}' (exit ${rc})"
  err "Log file: ${INSTALL_LOG}"
  err "Last 20 lines of output:"
  tail -n 20 "$INSTALL_LOG" 2>/dev/null | sed 's/^/    /' >&2 || true
  err "--------------------------------------------------------------------"
  err "Re-run with set -x for verbose tracing, or inspect ${INSTALL_LOG}."
  if (( ${#INSTALLED_UNITS[@]} > 0 )); then
    err "Partial install was performed. To clean up, run:"
    err "  sudo bash ${INSTALL_LOG%/install*}/uninstall.sh $AGENT_NAME"
    err "  (or manually stop: ${INSTALLED_UNITS[*]})"
  fi
}
trap 'on_error "${LINENO}" "$?" "${BASH_COMMAND}"' ERR

# -----------------------------------------------------------------------------
# 1. Argv parsing (--help was already handled before logging set up)
# -----------------------------------------------------------------------------

log "dcoyn_honeypot_deployer install starting"
log "Log file: $INSTALL_LOG"

# -----------------------------------------------------------------------------
# 2. Pre-flight: kernel, OS, root, RAM, disk, tools
# -----------------------------------------------------------------------------
log "Pre-flight checks…"

[[ $EUID -eq 0 ]] || die "Run as root (use sudo)."
[[ -f /etc/debian_version ]] || die "Debian/Ubuntu required. Found: $(uname -a)"

# Kernel ≥ 4.0 for nftables to work well
KERNEL_VER=$(uname -r | cut -d. -f1)
(( KERNEL_VER >= 4 )) || die "Kernel >= 4.0 required (found $(uname -r))"

# Min 384MB RAM
RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
(( RAM_MB >= 384 )) || die "Need >= 384MB RAM (found ${RAM_MB}MB)"

# Min 1GB free disk on /
DISK_MB=$(df -Pm / | awk 'NR==2{print $4}')
(( DISK_MB >= 1024 )) || die "Need >= 1GB free disk on / (found ${DISK_MB}MB)"

# Required tools (ones we need *before* apt-get install can run)
for t in curl tr shuf head awk sed grep; do
  command -v "$t" >/dev/null 2>&1 || die "missing required tool: $t"
done

ok "Pre-flight passed (kernel $(uname -r), ${RAM_MB}MB RAM, ${DISK_MB}MB disk)"

# -----------------------------------------------------------------------------
# 3. Argv / env parsing
# -----------------------------------------------------------------------------
ARG_TYPE="${1:-${HP_TYPE:-}}"
case "$ARG_TYPE" in
  ssh|owa|winserver) ;;
  random)
    ARG_TYPE=$(shuf -n1 -e ssh owa winserver)
    log "Random profile selected: $ARG_TYPE"
    ;;
  "")
    if [[ "${HP_NONINTERACTIVE:-0}" == "1" ]]; then
      die "Sensor profile not given. Pass as arg, or set HP_TYPE."
    fi
    echo "Sensor profile? [1] ssh  [2] owa  [3] winserver  [4] random"
    read -rp "> " choice
    case "$choice" in
      1) ARG_TYPE=ssh ;;
      2) ARG_TYPE=owa ;;
      3) ARG_TYPE=winserver ;;
      4) ARG_TYPE=$(shuf -n1 -e ssh owa winserver) ;;
      *) die "Invalid choice." ;;
    esac
    ;;
  *) die "Unknown profile: '$ARG_TYPE' (use ssh|owa|winserver|random)" ;;
esac

# -----------------------------------------------------------------------------
# 4. Pick agent name: kworker-XXXX (1-4 lowercase alphanumeric chars)
# -----------------------------------------------------------------------------
# Pure-bash random string generator. We don't use `tr -dc … </dev/urandom |
# head -c N` because under `set -o pipefail` the early-closing pipe sends
# SIGPIPE to `tr`, which surfaces as exit code 141 and kills the script.
# $RANDOM is plenty of entropy for picking an opaque agent name.
_rand_alnum() {
  local len="$1" chars='abcdefghijklmnopqrstuvwxyz0123456789' i out=''
  for (( i = 0; i < len; i++ )); do
    out+="${chars:RANDOM%36:1}"
  done
  printf '%s' "$out"
}

_gen_agent_name() {
  local len=$(( (RANDOM % 4) + 1 ))
  printf 'kworker-%s' "$(_rand_alnum "$len")"
}

AGENT_NAME="${HP_AGENT_NAME:-}"
if [[ -z "$AGENT_NAME" || "$AGENT_NAME" == "random" ]]; then
  AGENT_NAME=$(_gen_agent_name)
fi
if ! [[ "$AGENT_NAME" =~ ^kworker-[a-z0-9]{1,4}$ ]]; then
  die "HP_AGENT_NAME must match 'kworker-[a-z0-9]{1,4}' — got '$AGENT_NAME'"
fi
PKG_NAME="${AGENT_NAME//-/_}"

# Re-pick if name collides with an existing install on this VM
if id "$AGENT_NAME" &>/dev/null && [[ -d "/opt/$AGENT_NAME" ]] && [[ "${HP_NONINTERACTIVE:-0}" == "1" ]]; then
  # Random suffix re-roll to avoid stomping a previous install in non-interactive mode
  for _ in 1 2 3 4 5; do
    NEW=$(_gen_agent_name)
    if [[ ! -d "/opt/$NEW" ]]; then
      warn "$AGENT_NAME already installed; using $NEW"
      AGENT_NAME=$NEW
      PKG_NAME="${AGENT_NAME//-/_}"
      break
    fi
  done
fi

# -----------------------------------------------------------------------------
# 5. Collect per-node repo URL + its dedicated token
# -----------------------------------------------------------------------------
# Each VM pushes to its OWN private GitHub repo (e.g. dcoyn/dcoyn_honeypot_logs,
# dcoyn/dcoyn_honeypot_logs2, …). Create the repo yourself in the GitHub UI
# (private, with "Initialize with a README" checked), generate a fine-grained
# PAT scoped to ONLY that repo with Contents: Read+write, and paste the URL
# and token here. This way a compromise of one honeypot leaks at most ONE
# repo's worth of data.
REPO="${HP_REPO:-}"
TOKEN="${HP_GIT_TOKEN:-}"
NODE_NAME="${HP_NODE_NAME:-$(hostname)-$(_rand_alnum 6)}"

if [[ -z "$REPO" ]]; then
  [[ "${HP_NONINTERACTIVE:-0}" == "1" ]] && die "HP_REPO is required (the per-node GitHub repo URL)."
  read -rp "Per-node GitHub repo URL (https://github.com/dcoyn/dcoyn_honeypot_logsN.git): " REPO
fi
if [[ -z "$TOKEN" ]]; then
  [[ "${HP_NONINTERACTIVE:-0}" == "1" ]] && die "HP_GIT_TOKEN is required."
  read -rsp "Fine-grained PAT for THAT repo (Contents r/w): " TOKEN; echo
fi

[[ "$REPO" =~ ^https://github\.com/.+\.git$ ]] || warn "Repo URL doesn't look like an https git URL: $REPO"
[[ -n "$TOKEN" ]] || die "GitHub token is empty."

ADMIN_SSH_PORT="${HP_SSH_PORT:-62222}"

# Deployer-repo URL and its token (for fetching source code if no local checkout)
INSTALL_REPO="${HP_INSTALL_REPO:-https://github.com/dcoyn/dcoyn_honeypot_deployer.git}"
INSTALL_TOKEN="${HP_INSTALL_TOKEN:-$TOKEN}"

# -----------------------------------------------------------------------------
# 6. Derive on-disk paths and unit names from AGENT_NAME
# -----------------------------------------------------------------------------
AGENT_HOME=/opt/$AGENT_NAME
AGENT_LOGS=/var/log/$AGENT_NAME
AGENT_DATA=/var/lib/$AGENT_NAME
AGENT_ETC=/etc/$AGENT_NAME
AGENT_REPO_DIR="$AGENT_DATA/store"

SVC_MAIN="$AGENT_NAME"
SVC_CAPTURE="$AGENT_NAME-capture"
SVC_CONNLOG="$AGENT_NAME-connlog"
SVC_SYNC="$AGENT_NAME-sync"

DESC_MAIN="Kernel work queue helper"
DESC_CAPTURE="Workqueue packet inspector"
DESC_CONNLOG="Connection state worker"
DESC_SYNC="Worker state synchronization"

# Detect local checkout (script run from its own repo) — preferred over remote fetch.
# When the script is piped from curl, BASH_SOURCE[0] may be unset; use :- to
# avoid tripping `set -u`.
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]:-}" 2>/dev/null || true)"
SCRIPT_DIR="${SCRIPT_PATH%/*}"
LOCAL_SRC=""
if [[ -n "${SCRIPT_PATH:-}" && -f "$SCRIPT_DIR/nodewatch/sensors/ssh_sensor.py" ]]; then
  LOCAL_SRC="$SCRIPT_DIR"
fi

# -----------------------------------------------------------------------------
# 7. Connectivity check — fail early if GitHub is unreachable
# -----------------------------------------------------------------------------
log "Checking connectivity to GitHub…"
_curl_auth() {
  # curl wrapper with retries, sane timeouts, auth header optional
  local url="$1" out="${2:--}"
  local auth=()
  [[ -n "${INSTALL_TOKEN:-}" ]] && auth=(-H "Authorization: token ${INSTALL_TOKEN}")
  curl -fsSL \
       --connect-timeout 10 \
       --max-time 60 \
       --retry 3 --retry-delay 2 --retry-connrefused \
       "${auth[@]}" \
       "$url" -o "$out"
}

if ! curl -fsS --connect-timeout 10 --max-time 15 \
      -o /dev/null https://github.com 2>/dev/null; then
  die "Cannot reach https://github.com (network/DNS/firewall?)"
fi
ok "GitHub reachable"

# Check the logs repo URL resolves with the given token
LOGS_API_URL=$(echo "$REPO" | sed -E 's|^https://github\.com/([^/]+)/([^/]+)\.git$|https://api.github.com/repos/\1/\2|')
if ! curl -fsS --connect-timeout 10 --max-time 30 \
      -H "Authorization: token ${TOKEN}" \
      -o /dev/null "$LOGS_API_URL" 2>/dev/null; then
  warn "Could not validate logs repo $REPO via API — push may fail later."
else
  ok "Logs repo reachable with provided token"
fi

# -----------------------------------------------------------------------------
# 8. Summary banner (the operator wants to know the chosen name)
# -----------------------------------------------------------------------------
cat <<EOF | tee -a "$INSTALL_LOG"

------------------------------------------------------------------------
  Sensor profile  : $ARG_TYPE
  Agent name      : $AGENT_NAME           (Python pkg: $PKG_NAME)
  Node label      : $NODE_NAME
  Logs repo       : $REPO
  Install source  : ${LOCAL_SRC:-$INSTALL_REPO (remote)}
  Admin SSH port  : $ADMIN_SSH_PORT
  Install root    : $AGENT_HOME
  Install log     : $INSTALL_LOG
------------------------------------------------------------------------

EOF

# -----------------------------------------------------------------------------
# 9. Move real sshd to admin port BEFORE installing SSH sensor
# -----------------------------------------------------------------------------
if [[ "$ARG_TYPE" == "ssh" ]]; then
  log "Moving real sshd to port $ADMIN_SSH_PORT…"
  if ! grep -qE "^Port\s+$ADMIN_SSH_PORT" /etc/ssh/sshd_config; then
    cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak.$INSTALL_TS"
    # Replace or insert Port line
    if grep -qE "^#?Port\s+" /etc/ssh/sshd_config; then
      sed -i -E "s/^#?Port\s+.*/Port $ADMIN_SSH_PORT/" /etc/ssh/sshd_config
    else
      echo "Port $ADMIN_SSH_PORT" >> /etc/ssh/sshd_config
    fi
    # Validate before reloading — sshd -t exits non-zero on bad config
    if ! sshd -t 2>/dev/null; then
      warn "sshd config invalid; reverting"
      mv "/etc/ssh/sshd_config.bak.$INSTALL_TS" /etc/ssh/sshd_config
      die "Could not move sshd port; check /etc/ssh/sshd_config manually."
    fi
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
    ok "Real sshd now listening on $ADMIN_SSH_PORT. KEEP YOUR CURRENT SESSION OPEN."
  else
    ok "sshd already on port $ADMIN_SSH_PORT"
  fi
fi

# -----------------------------------------------------------------------------
# 10. APT install (with retries — apt sometimes flakes on slow networks)
# -----------------------------------------------------------------------------
log "Installing system packages (apt)…"
export DEBIAN_FRONTEND=noninteractive

_apt_retry() {
  local n=0 max=3
  while (( n < max )); do
    if apt-get "$@"; then return 0; fi
    n=$(( n + 1 ))
    warn "apt-get $1 failed (attempt $n/$max); retrying in 5s…"
    sleep 5
  done
  return 1
}

_apt_retry update -qq
_apt_retry install -yqq \
  python3 python3-venv python3-pip python3-dev \
  build-essential libssl-dev libffi-dev \
  git curl jq tcpdump openssh-server \
  nftables iptables rsyslog \
  ca-certificates openssl

ok "System packages installed"

# -----------------------------------------------------------------------------
# 11. Stage source code (local copy or remote clone)
# -----------------------------------------------------------------------------
log "Staging source code…"
STAGING=$(mktemp -d -t agent-stage.XXXXXX)
trap 'rm -rf "$STAGING"' EXIT
CREATED_DIRS+=("$STAGING")

if [[ -n "$LOCAL_SRC" ]]; then
  log "  using local checkout: $LOCAL_SRC"
  cp -r "$LOCAL_SRC/nodewatch"     "$STAGING/"
  cp -r "$LOCAL_SRC/templates"     "$STAGING/"
  cp    "$LOCAL_SRC/requirements.txt" "$STAGING/"
else
  log "  cloning $INSTALL_REPO into staging…"
  AUTH_INSTALL_REPO=$(echo "$INSTALL_REPO" | sed "s|https://|https://x-access-token:${INSTALL_TOKEN}@|")
  # Retry git clone up to 3 times
  for attempt in 1 2 3; do
    if git clone --depth 1 --quiet "$AUTH_INSTALL_REPO" "$STAGING/_repo" 2>/tmp/git-err; then
      break
    fi
    warn "git clone failed (attempt $attempt/3): $(head -1 /tmp/git-err 2>/dev/null || true)"
    sleep 3
    rm -rf "$STAGING/_repo"
    (( attempt == 3 )) && die "Cannot clone deployer repo $INSTALL_REPO (check HP_INSTALL_TOKEN/HP_GIT_TOKEN access)."
  done
  cp -r "$STAGING/_repo/nodewatch"        "$STAGING/"
  cp -r "$STAGING/_repo/templates"        "$STAGING/"
  cp    "$STAGING/_repo/requirements.txt" "$STAGING/"
  rm -rf "$STAGING/_repo"
fi

# Sanity: required files present?
for f in nodewatch/runner.py nodewatch/sensors/ssh_sensor.py \
         nodewatch/sensors/owa_sensor.py nodewatch/sensors/win_sensor.py \
         templates/owa_login.html requirements.txt; do
  [[ -f "$STAGING/$f" ]] || die "Staged source missing $f"
done

# Rename python package to match $PKG_NAME (so ps shows kworker_xxx.runner)
if [[ "$PKG_NAME" != "nodewatch" ]]; then
  mv "$STAGING/nodewatch" "$STAGING/$PKG_NAME"
fi
ok "Source staged at $STAGING (pkg dir: $PKG_NAME)"

# -----------------------------------------------------------------------------
# 12. Create privsep users, group, and directories
# -----------------------------------------------------------------------------
# Privilege model: each service runs as the least-privileged identity that
# can do its job. A shared group ($AGENT_NAME-rw) owns the log dir with the
# setgid bit so any service can append to the shared events.jsonl without
# anyone needing root just for file ownership.
#
#   sensor-user        runs the main sensor + packet capture
#                      gets CAP_NET_BIND_SERVICE + CAP_NET_RAW via systemd
#                      (NOT a root process — has fewer privileges than root)
#
#   connlog-user       runs the connection-log tailer
#                      member of the shared rw group + 'adm' (rsyslog group)
#                      NO capabilities, just reads a text file and writes events
#
#   sync-user          runs the every-5-minute git push
#                      has the ONLY filesystem access to the GitHub token
#                      NO capabilities, NO read of the live log files except
#                      via the aggregator
#
# A successful RCE in any one service is contained — the attacker would have
# to chain a local privilege escalation to reach the others.

SENSOR_USER="$AGENT_NAME-s"
CONNLOG_USER="$AGENT_NAME-c"
SYNC_USER="$AGENT_NAME-y"
SHARED_GROUP="$AGENT_NAME-rw"

log "Creating privsep accounts and directories…"

getent group  "$SHARED_GROUP"   >/dev/null || groupadd --system "$SHARED_GROUP"
id            "$SENSOR_USER"    &>/dev/null || useradd --system --no-create-home \
    --home "$AGENT_DATA" --shell /usr/sbin/nologin -g "$SHARED_GROUP" "$SENSOR_USER"
id            "$CONNLOG_USER"   &>/dev/null || useradd --system --no-create-home \
    --home "$AGENT_DATA" --shell /usr/sbin/nologin -g "$SHARED_GROUP" "$CONNLOG_USER"
id            "$SYNC_USER"      &>/dev/null || useradd --system --no-create-home \
    --home "$AGENT_DATA" --shell /usr/sbin/nologin -g "$SHARED_GROUP" "$SYNC_USER"

# Add connlog user to 'adm' so it can read the rsyslog-written kernel log
usermod -a -G adm "$CONNLOG_USER" 2>/dev/null || true

for d in "$AGENT_HOME" "$AGENT_LOGS" "$AGENT_DATA" "$AGENT_ETC" "$AGENT_REPO_DIR"; do
  mkdir -p "$d"
  CREATED_DIRS+=("$d")
done

# Log directory: setgid so new files inherit the shared group
chown -R root:"$SHARED_GROUP" "$AGENT_LOGS"
chmod 2770 "$AGENT_LOGS"
# Existing per-session/event files (re-runs) need group write
find "$AGENT_LOGS" -type f -exec chmod g+w {} \; 2>/dev/null || true

# Data dir: root-owned, only sync-user can read it (where the token lives)
chown -R root:"$SYNC_USER" "$AGENT_DATA"
chmod 0750 "$AGENT_DATA"

# Repo dir inside data: writable by sync user
chown -R "$SYNC_USER":"$SYNC_USER" "$AGENT_REPO_DIR"
chmod 0700 "$AGENT_REPO_DIR"

# Install root: readable by everyone, writable by no one
chmod 0755 "$AGENT_HOME"

# Copy source into install root, replacing any prior install
rm -rf "$AGENT_HOME/$PKG_NAME" "$AGENT_HOME/templates"
cp -r "$STAGING/$PKG_NAME"  "$AGENT_HOME/"
cp -r "$STAGING/templates"  "$AGENT_HOME/"
cp    "$STAGING/requirements.txt" "$AGENT_HOME/"
chown -R root:root "$AGENT_HOME/$PKG_NAME" "$AGENT_HOME/templates" "$AGENT_HOME/requirements.txt"
ok "Source installed at $AGENT_HOME/$PKG_NAME"

# -----------------------------------------------------------------------------
# 13. Python venv + deps (retry pip on flakiness)
# -----------------------------------------------------------------------------
log "Creating Python venv and installing deps…"
python3 -m venv "$AGENT_HOME/venv"
"$AGENT_HOME/venv/bin/pip" install --quiet --upgrade pip wheel >>"$INSTALL_LOG" 2>&1

_pip_retry() {
  local n=0 max=3
  while (( n < max )); do
    if "$AGENT_HOME/venv/bin/pip" install --quiet "$@" >>"$INSTALL_LOG" 2>&1; then
      return 0
    fi
    n=$(( n + 1 ))
    warn "pip install failed (attempt $n/$max); retrying in 3s…"
    sleep 3
  done
  return 1
}
_pip_retry -r "$AGENT_HOME/requirements.txt" || die "pip install failed; see $INSTALL_LOG"
ok "Python deps installed"

# -----------------------------------------------------------------------------
# 14. Sensor-specific assets: cert for OWA, host key for SSH
# -----------------------------------------------------------------------------
# These are read by the sensor process. Owned by root, readable by the sensor
# user (via group). The private keys stay 0640 — the sensor needs to read
# them, nothing else should.
if [[ "$ARG_TYPE" == "owa" ]]; then
  if [[ ! -f "$AGENT_DATA/owa.crt" ]]; then
    log "Generating self-signed cert for OWA…"
    openssl req -x509 -nodes -newkey rsa:2048 \
      -keyout "$AGENT_DATA/owa.key" -out "$AGENT_DATA/owa.crt" \
      -days 730 -subj "/CN=mail.northbridge-logistics.com" 2>/dev/null
    chown root:"$SENSOR_USER" "$AGENT_DATA/owa.key" "$AGENT_DATA/owa.crt"
    chmod 0640 "$AGENT_DATA/owa.key"
    chmod 0644 "$AGENT_DATA/owa.crt"
    ok "OWA cert at $AGENT_DATA/owa.crt"
  fi
fi
if [[ "$ARG_TYPE" == "ssh" ]]; then
  if [[ ! -f "$AGENT_DATA/ssh_host_rsa_key" ]]; then
    log "Generating sensor SSH host key…"
    ssh-keygen -q -t rsa -b 2048 -f "$AGENT_DATA/ssh_host_rsa_key" -N "" -C "ubuntu-prod-01"
    chown root:"$SENSOR_USER" "$AGENT_DATA/ssh_host_rsa_key"*
    chmod 0640 "$AGENT_DATA/ssh_host_rsa_key"
    chmod 0644 "$AGENT_DATA/ssh_host_rsa_key.pub" 2>/dev/null || true
    ok "SSH host key generated"
  fi
fi

# -----------------------------------------------------------------------------
# 15. Initialize logs repo (owned by sync-user — the only one who needs it)
# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------
log "Cloning per-node repo $REPO…"
AUTH_REPO=$(echo "$REPO" | sed "s|https://|https://x-access-token:${TOKEN}@|")
if [[ ! -d "$AGENT_REPO_DIR/.git" ]]; then
  rm -rf "$AGENT_REPO_DIR"
  for attempt in 1 2 3; do
    if sudo -u "$SYNC_USER" git -C "$AGENT_DATA" clone --quiet "$AUTH_REPO" store 2>/tmp/git-err; then
      break
    fi
    warn "logs-repo clone failed (attempt $attempt/3): $(cat /tmp/git-err | head -1)"
    rm -rf "$AGENT_REPO_DIR"
    sleep 3
    if (( attempt == 3 )); then
      warn "Could not clone logs repo — initializing empty + adding remote (push will create branch on first sync)"
      sudo -u "$AGENT_USER" mkdir -p "$AGENT_REPO_DIR"
      sudo -u "$AGENT_USER" git -C "$AGENT_REPO_DIR" init --quiet
      sudo -u "$AGENT_USER" git -C "$AGENT_REPO_DIR" remote add origin "$AUTH_REPO"
      sudo -u "$AGENT_USER" git -C "$AGENT_REPO_DIR" checkout -b main 2>/dev/null || true
    fi
  done
fi
sudo -u "$AGENT_USER" git -C "$AGENT_REPO_DIR" config user.email "agent@local"
sudo -u "$AGENT_USER" git -C "$AGENT_REPO_DIR" config user.name  "agent-bot"
sudo -u "$AGENT_USER" git -C "$AGENT_REPO_DIR" config pull.rebase true
ok "Logs repo at $AGENT_REPO_DIR"

# -----------------------------------------------------------------------------
# 16. Write config and env file
# -----------------------------------------------------------------------------
log "Writing config…"
cat > "$AGENT_HOME/config.json" <<EOF
{
  "node_name": "$NODE_NAME",
  "sensor_profile": "$ARG_TYPE",
  "log_dir": "$AGENT_LOGS",
  "data_dir": "$AGENT_DATA",
  "repo_dir": "$AGENT_REPO_DIR",
  "repo_url": "$REPO",
  "admin_ssh_port": $ADMIN_SSH_PORT
}
EOF
chmod 0644 "$AGENT_HOME/config.json"

# Token: root-only
install -m 0400 /dev/null "$AGENT_DATA/.token"
echo "$TOKEN" > "$AGENT_DATA/.token"
chown "$SYNC_USER":"$SYNC_USER" "$AGENT_DATA/.token"
chmod 0400 "$AGENT_DATA/.token"

# -----------------------------------------------------------------------------
# 17. nftables: log every new connection attempt (incl. closed ports)
# -----------------------------------------------------------------------------
log "Configuring nftables connection logging…"
NFT_TABLE="netmon"
NFT_PREFIX_UP=$(echo "${AGENT_NAME}_" | tr '[:lower:]-' '[:upper:]_')

cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
flush ruleset

table inet $NFT_TABLE {
  chain input {
    type filter hook input priority -100; policy accept;
    ct state established,related accept
    iif lo accept
    tcp dport $ADMIN_SSH_PORT accept
    ct state new tcp flags & (fin|syn|rst|ack) == syn \\
      log prefix "${NFT_PREFIX_UP}TCP " level info
    meta l4proto udp log prefix "${NFT_PREFIX_UP}UDP " level info
    meta l4proto icmp log prefix "${NFT_PREFIX_UP}ICMP " level info
  }
}
EOF
# Validate nftables config before reloading
if ! nft -c -f /etc/nftables.conf 2>/dev/null; then
  warn "nftables config failed validation; skipping. Connection log won't work."
else
  systemctl enable --now nftables >/dev/null 2>&1 || true
  nft -f /etc/nftables.conf
  ok "nftables loaded (prefix=$NFT_PREFIX_UP)"
fi

# rsyslog filter — pipe kernel log lines matching prefix into our log file
cat > "/etc/rsyslog.d/30-$AGENT_NAME.conf" <<EOF
:msg, contains, "${NFT_PREFIX_UP}" -$AGENT_LOGS/kernel-connections.log
& stop
EOF
INSTALLED_FILES+=("/etc/rsyslog.d/30-$AGENT_NAME.conf")
systemctl restart rsyslog 2>/dev/null || warn "rsyslog restart failed"
touch "$AGENT_LOGS/kernel-connections.log"
chown root:adm "$AGENT_LOGS/kernel-connections.log" 2>/dev/null \
  || chown root:root "$AGENT_LOGS/kernel-connections.log"

# Per-agent env file (read by systemd)
cat > "$AGENT_ETC/env" <<EOF
HP_CONFIG=$AGENT_HOME/config.json
HP_NFT_PREFIX=$NFT_PREFIX_UP
HP_CONNLOG_PATH=$AGENT_LOGS/kernel-connections.log
EOF
chmod 0644 "$AGENT_ETC/env"
INSTALLED_FILES+=("$AGENT_ETC/env")

# -----------------------------------------------------------------------------
# 18. systemd units
# -----------------------------------------------------------------------------
log "Installing systemd units…"

_write_unit() {
  local path="$1"; shift
  cat > "$path"
  INSTALLED_FILES+=("$path")
}

_write_unit /etc/systemd/system/${SVC_MAIN}.service <<EOF
[Unit]
Description=$DESC_MAIN
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SENSOR_USER
Group=$SHARED_GROUP
UMask=0002
WorkingDirectory=$AGENT_HOME
EnvironmentFile=$AGENT_ETC/env
Environment=PYTHONUNBUFFERED=1
ExecStart=$AGENT_HOME/venv/bin/python -m ${PKG_NAME}.runner
Restart=always
RestartSec=3

# Capabilities: bind to ports below 1024, nothing else
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Sandboxing
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
PrivateTmp=true
PrivateDevices=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true

# Filesystem: read its source, append to logs, read its cert/key
ReadOnlyPaths=$AGENT_HOME
ReadWritePaths=$AGENT_LOGS
ReadOnlyPaths=$AGENT_DATA

[Install]
WantedBy=multi-user.target
EOF

_write_unit /etc/systemd/system/${SVC_CAPTURE}.service <<EOF
[Unit]
Description=$DESC_CAPTURE
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SENSOR_USER
Group=$SHARED_GROUP
UMask=0002
WorkingDirectory=$AGENT_HOME
EnvironmentFile=$AGENT_ETC/env
Environment=PYTHONUNBUFFERED=1
ExecStart=$AGENT_HOME/venv/bin/python -m ${PKG_NAME}.network.packet_capture
Restart=always
RestartSec=5

# Capabilities: open raw sockets for sniffing
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

# Sandboxing
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
PrivateTmp=true
PrivateDevices=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true

ReadOnlyPaths=$AGENT_HOME
ReadWritePaths=$AGENT_LOGS

[Install]
WantedBy=multi-user.target
EOF

_write_unit /etc/systemd/system/${SVC_CONNLOG}.service <<EOF
[Unit]
Description=$DESC_CONNLOG
After=rsyslog.service

[Service]
Type=simple
User=$CONNLOG_USER
Group=$SHARED_GROUP
UMask=0002
SupplementaryGroups=adm
WorkingDirectory=$AGENT_HOME
EnvironmentFile=$AGENT_ETC/env
ExecStart=$AGENT_HOME/venv/bin/python -m ${PKG_NAME}.network.connection_logger
Restart=always
RestartSec=3

# No capabilities — this just reads a text file
CapabilityBoundingSet=

# Sandboxing — most restrictive of all the services
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
PrivateTmp=true
PrivateDevices=true
PrivateNetwork=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true

ReadOnlyPaths=$AGENT_HOME
ReadWritePaths=$AGENT_LOGS

[Install]
WantedBy=multi-user.target
EOF

_write_unit /etc/systemd/system/${SVC_SYNC}.service <<EOF
[Unit]
Description=$DESC_SYNC

[Service]
Type=oneshot
User=$SYNC_USER
Group=$SYNC_USER
UMask=0002
SupplementaryGroups=$SHARED_GROUP
WorkingDirectory=$AGENT_HOME
EnvironmentFile=$AGENT_ETC/env
ExecStart=$AGENT_HOME/venv/bin/python -m ${PKG_NAME}.sync.github_sync

# No capabilities — only does network egress and filesystem reads
CapabilityBoundingSet=

# Sandboxing
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
PrivateTmp=true
PrivateDevices=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true

# Sync needs: read events.jsonl, read the token, read+write the repo dir
ReadOnlyPaths=$AGENT_HOME $AGENT_LOGS
ReadWritePaths=$AGENT_REPO_DIR
EOF

_write_unit /etc/systemd/system/${SVC_SYNC}.timer <<EOF
[Unit]
Description=Periodic $DESC_SYNC

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload

# -----------------------------------------------------------------------------
# 19. Start services and VERIFY they're running
# -----------------------------------------------------------------------------
log "Starting and verifying services…"
_start_and_verify() {
  local svc="$1"
  systemctl enable --now "$svc" 2>>"$INSTALL_LOG"
  INSTALLED_UNITS+=("$svc")
  # Wait up to 10s for it to come up
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    sleep 1
    if systemctl is-active --quiet "$svc"; then
      ok "  $svc is active"
      return 0
    fi
  done
  err "  $svc did NOT start. Last journal lines:"
  journalctl -u "$svc" -n 15 --no-pager 2>&1 | sed 's/^/      /' >&2 || true
  return 1
}

# Capture and connlog can degrade gracefully — main service is the critical one
_start_and_verify "${SVC_CAPTURE}.service"  || warn "${SVC_CAPTURE} not running (TLS fingerprinting will be missing)"
_start_and_verify "${SVC_CONNLOG}.service"  || warn "${SVC_CONNLOG} not running (connection log will be missing)"
_start_and_verify "${SVC_MAIN}.service"     || die  "${SVC_MAIN} failed to start — install aborted"

# Sync timer
systemctl enable --now "${SVC_SYNC}.timer" 2>>"$INSTALL_LOG"
INSTALLED_UNITS+=("${SVC_SYNC}.timer")
ok "  ${SVC_SYNC}.timer enabled"

# Kick a sync immediately to verify the path works (don't fail the install if it errs)
log "Kicking initial sync (this may take 30s)…"
if systemctl start "${SVC_SYNC}.service" 2>>"$INSTALL_LOG"; then
  # Wait for the oneshot to finish (max 60s)
  for _ in $(seq 1 60); do
    sleep 1
    state=$(systemctl is-active "${SVC_SYNC}.service" 2>/dev/null || true)
    [[ "$state" == "inactive" || "$state" == "failed" ]] && break
  done
  if systemctl is-failed --quiet "${SVC_SYNC}.service"; then
    warn "Initial sync failed. Repo may need its first commit, or the token may lack write perms."
    journalctl -u "${SVC_SYNC}.service" -n 10 --no-pager | sed 's/^/      /' || true
  else
    ok "Initial sync completed (or quickly idle)"
  fi
else
  warn "Could not start sync service for initial run"
fi

# -----------------------------------------------------------------------------
# 20. Stash agent info for operator + write uninstall hint
# -----------------------------------------------------------------------------
cat > /root/.agent-info <<EOF
agent_name=$AGENT_NAME
pkg_name=$PKG_NAME
profile=$ARG_TYPE
node_name=$NODE_NAME
installed_at=$(date -u +%FT%TZ)
install_log=$INSTALL_LOG
EOF
chmod 0600 /root/.agent-info

# -----------------------------------------------------------------------------
# 21. Final summary
# -----------------------------------------------------------------------------
cat <<EOF

========================================================================
  Install complete.

  Profile      : $ARG_TYPE
  Agent name   : $AGENT_NAME
  Node label   : $NODE_NAME
  Logs repo    : $REPO

  Units installed:
    ${SVC_MAIN}.service
    ${SVC_CAPTURE}.service
    ${SVC_CONNLOG}.service
    ${SVC_SYNC}.timer

  Operator commands:
    status   :  systemctl status ${SVC_MAIN} ${SVC_CAPTURE} ${SVC_CONNLOG} ${SVC_SYNC}.timer
    events   :  tail -F $AGENT_LOGS/events.jsonl
    journal  :  journalctl -u ${SVC_MAIN} -f
    info     :  cat /root/.agent-info
    install log: $INSTALL_LOG

EOF

if [[ "$ARG_TYPE" == "ssh" ]]; then
  warn "Real sshd is on port $ADMIN_SSH_PORT — verify a NEW admin session works BEFORE closing this one."
fi

ok "Done."
exit 0
