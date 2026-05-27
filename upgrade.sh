#!/usr/bin/env bash
# =============================================================================
# upgrade.sh — in-place upgrade of a deployed honeypot to the latest installer.
#
# Preserves:
#   - agent name              (same kworker-XXXX → same per-node logs repo)
#   - profile type            (ssh / owa / winserver / fileshare)
#   - logs repo URL + token   (read from the per-node repo's git config)
#   - node label              (the friendly hostname-y string)
#
# Replaces:
#   - all installed code under /opt/<name>
#   - systemd units
#   - rsyslog filter
#   - privsep users (recreated identically)
#   - fake_world.json — NEW one is generated; per-VM universe will change.
#     Use --keep-universe to preserve the existing one (copies it into the
#     new install).
#
# Usage:
#   sudo bash upgrade.sh                 # interactive confirmation
#   sudo bash upgrade.sh --yes           # no prompts
#   sudo bash upgrade.sh --keep-universe # preserve the existing fake_world.json
#
# Or oneshot:
#   curl -fsSL https://raw.githubusercontent.com/dcoyn/dcoyn_honeypot_deployer/main/upgrade.sh \
#     | sudo bash -s -- --yes --keep-universe
# =============================================================================
set -euo pipefail

# --------- output helpers ---------
log()  { echo "$(date -u +%FT%TZ) [*] $*"; }
ok()   { echo "$(date -u +%FT%TZ) [+] $*"; }
warn() { echo "$(date -u +%FT%TZ) [!] $*" >&2; }
die()  { echo "$(date -u +%FT%TZ) [X] $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Must run as root."

ASSUME_YES=0
KEEP_UNIVERSE=0
INSTALLER_URL="https://raw.githubusercontent.com/dcoyn/dcoyn_honeypot_deployer/main/install.sh"
for a in "$@"; do
  case "$a" in
    -y|--yes)         ASSUME_YES=1 ;;
    --keep-universe)  KEEP_UNIVERSE=1 ;;
    --installer-url=*) INSTALLER_URL="${a#--installer-url=}" ;;
    -h|--help)
      sed -n '3,28p' "$0"; exit 0 ;;
    *) die "Unknown arg: $a" ;;
  esac
done

# --------- discover current install ---------
INFO=/root/.agent-info
[[ -f $INFO ]] || die "No /root/.agent-info — is a honeypot installed on this box?"

AGENT_NAME=$(awk -F= '/^agent_name=/{print $2}' "$INFO")
PROFILE=$(awk -F= '/^profile=/{print $2}'    "$INFO")
NODE_NAME=$(awk -F= '/^node_name=/{print $2}' "$INFO")
[[ -n $AGENT_NAME ]] || die "Cannot read agent_name from $INFO"
[[ -n $PROFILE ]]    || die "Cannot read profile from $INFO"

# Fall back to config.json for the profile if .agent-info is from a really old
# version that didn't write it
if [[ -z $PROFILE ]]; then
  PROFILE=$(grep -oE '"sensor_profile":[[:space:]]*"[^"]+"' \
    "/etc/$AGENT_NAME/config.json" 2>/dev/null \
    | head -1 | sed -E 's/.*"sensor_profile":[[:space:]]*"([^"]+)".*/\1/')
fi
[[ -n $PROFILE ]] || die "Cannot determine current profile; aborting."

# Extract repo URL + token from the per-node logs repo's git config
GIT_CONFIG="/var/lib/$AGENT_NAME/store/.git/config"
[[ -f $GIT_CONFIG ]] || die "Logs repo not at $GIT_CONFIG — can't extract token."

AUTH_URL=$(sed -nE 's|^[[:space:]]*url[[:space:]]*=[[:space:]]*(https://[^[:space:]]+)$|\1|p' \
           "$GIT_CONFIG" | head -1)
[[ -n $AUTH_URL ]] || die "Cannot parse remote URL from $GIT_CONFIG"

if [[ $AUTH_URL =~ ^https://x-access-token:([^@]+)@(.+)$ ]]; then
  HP_GIT_TOKEN="${BASH_REMATCH[1]}"
  HP_REPO="https://${BASH_REMATCH[2]}"
elif [[ $AUTH_URL =~ ^https://[^:]+:([^@]+)@(.+)$ ]]; then
  # Less common form (PAT in classic Basic-auth user-style)
  HP_GIT_TOKEN="${BASH_REMATCH[1]}"
  HP_REPO="https://${BASH_REMATCH[2]}"
else
  die "Unrecognized remote URL format in $GIT_CONFIG"
fi

# Save the fake_world snapshot before we wipe /var/lib/$AGENT_NAME
SAVED_UNIVERSE=""
if [[ $KEEP_UNIVERSE -eq 1 && -f "/var/lib/$AGENT_NAME/fake_world.json" ]]; then
  SAVED_UNIVERSE=$(mktemp -t fake_world.XXXXXX.json)
  cp "/var/lib/$AGENT_NAME/fake_world.json" "$SAVED_UNIVERSE"
  log "Saved existing fake_world.json → $SAVED_UNIVERSE"
fi

# --------- show what's about to happen ---------
cat <<SUMMARY

────────────────────────────────────────────────────────────────────
  HONEYPOT IN-PLACE UPGRADE
────────────────────────────────────────────────────────────────────
  Agent name      : $AGENT_NAME
  Profile         : $PROFILE
  Node label      : ${NODE_NAME:-<unset>}
  Logs repo       : $HP_REPO
  Token preview   : ${HP_GIT_TOKEN:0:8}…${HP_GIT_TOKEN: -4}
  Keep universe   : $([ $KEEP_UNIVERSE -eq 1 ] && echo yes || echo no)
  Installer URL   : $INSTALLER_URL

  What happens next:
    1. Stop all $AGENT_NAME services.
    2. Run /opt/$AGENT_NAME/uninstall.sh (clears code, units, privsep accounts).
       The logs repo's contents on GitHub are untouched.
    3. Re-run the latest install.sh with the same agent name, profile, repo, token.
    4. New version starts fresh; first sync pushes new events to the same logs repo.

  TIP: keep your CURRENT SSH session open while this runs.  If your profile is
       'ssh' or 'fileshare' the sensor will rebind port 22 — your live session
       on port 62222 (the admin port) will be unaffected.
SUMMARY

if [[ $ASSUME_YES -eq 0 ]]; then
  read -rp "Proceed with upgrade? [y/N] " ans
  [[ ${ans,,} == y || ${ans,,} == yes ]] || die "Aborted by user."
fi

# --------- run uninstall ---------
log "Running uninstall.sh in non-interactive mode…"
if [[ -x "/opt/$AGENT_NAME/uninstall.sh" ]]; then
  AGENT_NAME="$AGENT_NAME" yes | bash "/opt/$AGENT_NAME/uninstall.sh" || \
    warn "uninstall.sh returned non-zero; continuing anyway"
else
  warn "uninstall.sh missing — doing manual teardown"
  for unit in "$AGENT_NAME-sync.timer" "$AGENT_NAME-sync.service" \
              "$AGENT_NAME-connlog.service" "$AGENT_NAME-capture.service" \
              "$AGENT_NAME-geoip-refresh.timer" "$AGENT_NAME-geoip-refresh.service" \
              "$AGENT_NAME.service"; do
    systemctl stop    "$unit" 2>/dev/null || true
    systemctl disable "$unit" 2>/dev/null || true
    rm -f "/etc/systemd/system/$unit"
  done
  systemctl daemon-reload
  rm -f "/etc/rsyslog.d/30-$AGENT_NAME.conf"
  systemctl restart rsyslog 2>/dev/null || true
  rm -f "/usr/local/sbin/$AGENT_NAME-geoip-refresh.sh"
  for u in "$AGENT_NAME-s" "$AGENT_NAME-c" "$AGENT_NAME-y" "$AGENT_NAME"; do
    id "$u" &>/dev/null && userdel "$u" 2>/dev/null || true
  done
  getent group "$AGENT_NAME-rw" >/dev/null && groupdel "$AGENT_NAME-rw" 2>/dev/null || true
  rm -rf "/opt/$AGENT_NAME" "/var/log/$AGENT_NAME" "/var/lib/$AGENT_NAME" "/etc/$AGENT_NAME"
fi
ok "Uninstall complete."

# --------- re-run installer with preserved identity ---------
log "Re-running installer with profile=$PROFILE name=$AGENT_NAME…"

# Pre-seed the new fake_world.json BEFORE install.sh runs, so we don't lose
# the universe. install.sh's pre-creation step is idempotent (load_or_create
# reads existing file when present).
if [[ -n $SAVED_UNIVERSE ]]; then
  install -d -m 0750 -o root -g root "/var/lib/$AGENT_NAME"
  cp "$SAVED_UNIVERSE" "/var/lib/$AGENT_NAME/fake_world.json"
  rm -f "$SAVED_UNIVERSE"
  log "Restored fake_world.json → /var/lib/$AGENT_NAME/fake_world.json"
fi

export HP_GIT_TOKEN \
       HP_REPO \
       HP_TYPE="$PROFILE" \
       HP_AGENT_NAME="$AGENT_NAME" \
       HP_NODE_NAME="$NODE_NAME" \
       HP_CANARY_URL="${HP_CANARY_URL:-}" \
       HP_NONINTERACTIVE=1

# Pull and run the latest installer
TMPI=$(mktemp -t install.XXXXXX.sh)
curl -fsSL "$INSTALLER_URL" -o "$TMPI"
bash "$TMPI"
rm -f "$TMPI"

unset HP_GIT_TOKEN HP_REPO HP_TYPE HP_AGENT_NAME HP_NODE_NAME HP_CANARY_URL HP_NONINTERACTIVE

# --------- verify ---------
echo
ok "Upgrade complete. Verification:"
systemctl is-active "$AGENT_NAME.service"         | sed "s|^|  $AGENT_NAME:          |"
systemctl is-active "$AGENT_NAME-capture.service" | sed "s|^|  $AGENT_NAME-capture:  |"
systemctl is-active "$AGENT_NAME-connlog.service" | sed "s|^|  $AGENT_NAME-connlog:  |"
systemctl is-enabled "$AGENT_NAME-sync.timer"     | sed "s|^|  $AGENT_NAME-sync:     |"
echo
echo "  Sockets:"
ss -tlnp 2>/dev/null | awk '/python|paramiko/{print "    " $0}' | head -8
echo
echo "  Events written so far:"
[ -f "/var/log/$AGENT_NAME/events.jsonl" ] && wc -l "/var/log/$AGENT_NAME/events.jsonl" \
  | awk '{print "    " $1 " lines in events.jsonl"}'
echo
echo "  Watch live:"
echo "    sudo tail -F /var/log/$AGENT_NAME/events.jsonl"
echo "    sudo journalctl -u $AGENT_NAME -f"
