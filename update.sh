#!/usr/bin/env bash
#
# Update the running bot: pull latest code, preserve local config, restart.
# Usage:  sudo bash update.sh [branch]   (branch defaults to main)
#
# Safe to re-run. Local edits to tracked files (e.g. scope.yaml) are stashed
# across the pull and re-applied, so your ROE is not overwritten.
#
set -euo pipefail

SERVICE_NAME="pentest-bot"
SERVICE_USER="pentestbot"
BRANCH="${1:-main}"
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log()  { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[✓]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
else
  command -v sudo >/dev/null 2>&1 || die "sudo not found and not running as root."
  SUDO="sudo"
fi

git_in() { $SUDO git -C "$APP_DIR" "$@"; }

[ -d "$APP_DIR/.git" ] || die "$APP_DIR is not a git checkout."

# The repo is owned by $SERVICE_USER; let root operate on it without complaint.
git_in config --global --add safe.directory "$APP_DIR" >/dev/null 2>&1 || true

# --------------------------------------------------------------- preserve local edits
STASHED=0
if ! git_in diff --quiet || ! git_in diff --cached --quiet; then
  log "Stashing local changes (e.g. scope.yaml) before pull"
  git_in stash push -u -m "update.sh autostash" >/dev/null
  STASHED=1
fi

# --------------------------------------------------------------- pull
BEFORE="$(git_in rev-parse HEAD)"
log "Pulling origin/$BRANCH"
if ! git_in pull --ff-only origin "$BRANCH"; then
  warn "Fast-forward pull failed."
  if [ "$STASHED" -eq 1 ]; then
    warn "Restoring your stashed changes."
    git_in stash pop || warn "stash pop conflicted — resolve manually (git stash list)."
  fi
  die "Resolve the above and re-run. Nothing was restarted."
fi
AFTER="$(git_in rev-parse HEAD)"

# --------------------------------------------------------------- restore local edits
if [ "$STASHED" -eq 1 ]; then
  log "Re-applying your local changes"
  git_in stash pop || warn "stash pop conflicted — check 'git status' / 'git stash list'."
fi

# --------------------------------------------------------------- react to what changed
if [ "$BEFORE" = "$AFTER" ]; then
  ok "Already up to date ($AFTER)."
else
  ok "Updated ${BEFORE:0:7} -> ${AFTER:0:7}"
  CHANGED="$(git_in diff --name-only "$BEFORE" "$AFTER")"
  if echo "$CHANGED" | grep -qx "requirements.txt"; then
    log "requirements.txt changed — reinstalling Python deps"
    $SUDO "$APP_DIR/.venv/bin/pip" install -r "$APP_DIR/requirements.txt"
  fi
  if echo "$CHANGED" | grep -qxE "pentest-bot.service|install.sh"; then
    warn "systemd unit or installer changed — consider: sudo bash install.sh"
  fi
fi

# --------------------------------------------------------------- ownership + restart
if id "$SERVICE_USER" >/dev/null 2>&1; then
  $SUDO chown -R "$SERVICE_USER":"$SERVICE_USER" "$APP_DIR"
fi

log "Restarting $SERVICE_NAME"
$SUDO systemctl restart "$SERVICE_NAME"

# Give it a moment, then show a short status.
( sleep 1 ) || true
echo
$SUDO systemctl --no-pager --lines=0 status "$SERVICE_NAME" || true
echo
ok "Done. Follow logs with: $SUDO journalctl -u ${SERVICE_NAME} -f"
