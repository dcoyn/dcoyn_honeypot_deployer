#!/usr/bin/env bash
# =============================================================================
#  dcoyn_honeypot_deployer — uninstaller
# -----------------------------------------------------------------------------
#  Usage:
#      sudo ./uninstall.sh                # auto-detects from /root/.agent-info
#      sudo ./uninstall.sh kworker-x4z    # explicit agent name
#      sudo ./uninstall.sh --all          # remove EVERY kworker-* install
#
#  What it does:
#      - Stops and disables systemd units
#      - Removes /opt/<name>, /var/log/<name>, /var/lib/<name>, /etc/<name>
#      - Removes rsyslog filter
#      - Restores /etc/ssh/sshd_config from the most recent .bak file (if SSH
#        sensor was installed)
#      - Restores nftables to a permissive default (or empties it)
#      - Leaves the install log in place at /var/log/agent-install-*.log
# =============================================================================

set -Eeuo pipefail

C_R='\033[0;31m'; C_G='\033[0;32m'; C_Y='\033[0;33m'; C_N='\033[0m'
log()  { echo -e "${C_G}[*]${C_N} $*"; }
warn() { echo -e "${C_Y}[!]${C_N} $*"; }
err()  { echo -e "${C_R}[x]${C_N} $*" >&2; }
die()  { err "$*"; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root."

trap 'err "Uninstall failed at line $LINENO (exit $?)"; exit 1' ERR

# -----------------------------------------------------------------------------
# Discover what to remove
# -----------------------------------------------------------------------------
TARGETS=()

if [[ "${1:-}" == "--all" ]]; then
  # Find every kworker-* install (by /opt/kworker-XXXX/config.json existence)
  while IFS= read -r d; do
    name=$(basename "$d")
    [[ "$name" =~ ^kworker-[a-z0-9]{1,4}$ ]] && TARGETS+=("$name")
  done < <(find /opt -maxdepth 1 -type d -name 'kworker-*' 2>/dev/null)
elif [[ -n "${1:-}" ]]; then
  TARGETS=("$1")
elif [[ -f /root/.agent-info ]]; then
  TARGETS=( "$(grep ^agent_name /root/.agent-info | cut -d= -f2)" )
else
  die "No agent name given and /root/.agent-info missing. Try: sudo $0 --all"
fi

(( ${#TARGETS[@]} > 0 )) || die "Nothing to uninstall."

for AGENT_NAME in "${TARGETS[@]}"; do
  [[ "$AGENT_NAME" =~ ^kworker-[a-z0-9]{1,4}$ ]] || { warn "Skipping malformed name: $AGENT_NAME"; continue; }
  log "Uninstalling $AGENT_NAME…"

  # Stop and disable everything
  for unit in "$AGENT_NAME-sync.timer" \
              "$AGENT_NAME-sync.service" \
              "$AGENT_NAME-connlog.service" \
              "$AGENT_NAME-capture.service" \
              "$AGENT_NAME-geoip-refresh.timer" \
              "$AGENT_NAME-geoip-refresh.service" \
              "$AGENT_NAME.service"; do
    systemctl stop    "$unit" 2>/dev/null || true
    systemctl disable "$unit" 2>/dev/null || true
    rm -f "/etc/systemd/system/$unit"
  done
  systemctl daemon-reload

  # Remove the geoip refresh script (per-agent)
  rm -f "/usr/local/sbin/$AGENT_NAME-geoip-refresh.sh"

  # Remove rsyslog filter
  rm -f "/etc/rsyslog.d/30-$AGENT_NAME.conf"
  systemctl restart rsyslog 2>/dev/null || true

  # Remove privsep accounts (current install creates -s/-c/-y users and a -rw group;
  # older installs may have just $AGENT_NAME — clean both)
  for u in "$AGENT_NAME-s" "$AGENT_NAME-c" "$AGENT_NAME-y" "$AGENT_NAME"; do
    if id "$u" &>/dev/null; then
      userdel "$u" 2>/dev/null || true
    fi
  done
  getent group "$AGENT_NAME-rw" >/dev/null && groupdel "$AGENT_NAME-rw" 2>/dev/null || true

  # Remove on-disk artifacts (NOT the install log — keep that for forensics)
  rm -rf "/opt/$AGENT_NAME" \
         "/var/log/$AGENT_NAME" \
         "/var/lib/$AGENT_NAME" \
         "/etc/$AGENT_NAME"

  log "  $AGENT_NAME removed."
done

# -----------------------------------------------------------------------------
# Restore sshd_config from the most recent backup (best-effort)
# -----------------------------------------------------------------------------
BAK=$(ls -t /etc/ssh/sshd_config.bak.* 2>/dev/null | head -1 || true)
if [[ -n "$BAK" ]]; then
  warn "Restoring sshd_config from $BAK"
  cp "$BAK" /etc/ssh/sshd_config
  if sshd -t 2>/dev/null; then
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
    log "sshd restarted with restored config"
  else
    err "Restored sshd_config failed validation; keeping current as-is"
  fi
fi

# -----------------------------------------------------------------------------
# Flush nftables back to empty (we created /etc/nftables.conf)
# -----------------------------------------------------------------------------
if [[ -f /etc/nftables.conf ]] && grep -q "table inet netmon" /etc/nftables.conf 2>/dev/null; then
  warn "Flushing our nftables ruleset"
  cat > /etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
flush ruleset
EOF
  nft -f /etc/nftables.conf 2>/dev/null || true
fi

# Clean up agent-info if we removed everything pointed at by it
if [[ -f /root/.agent-info ]]; then
  for AGENT_NAME in "${TARGETS[@]}"; do
    if grep -q "^agent_name=$AGENT_NAME$" /root/.agent-info 2>/dev/null; then
      rm -f /root/.agent-info
      break
    fi
  done
fi

log "Uninstall complete. Install logs preserved at /var/log/agent-install-*.log"
