#!/usr/bin/env bash
#
# Idempotent installer for the Router Pentest Orchestrator on Ubuntu 22.04.
# Safe to re-run: it never overwrites .env / scope.yaml and skips work already done.
#
set -euo pipefail

# --------------------------------------------------------------------------- config
NUCLEI_VERSION="3.3.0"
SERVICE_USER="pentestbot"
SERVICE_NAME="pentest-bot"
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --------------------------------------------------------------------------- helpers
log()  { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[✓]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# sudo wrapper that is a no-op when already root.
if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
else
  command -v sudo >/dev/null 2>&1 || die "sudo not found and not running as root."
  SUDO="sudo"
fi

# --------------------------------------------------------------------------- 1. OS check
log "Checking OS"
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  if [ "${ID:-}" != "ubuntu" ] || [ "${VERSION_ID:-}" != "22.04" ]; then
    warn "Target OS is Ubuntu 22.04; detected ${ID:-?} ${VERSION_ID:-?}. Continuing anyway."
  else
    ok "Ubuntu 22.04 detected"
  fi
else
  warn "/etc/os-release missing; cannot verify OS."
fi

# --------------------------------------------------------------------------- 2. apt deps
log "Installing apt packages"
export DEBIAN_FRONTEND=noninteractive
$SUDO apt-get update -y
$SUDO apt-get install -y \
  python3 python3-venv python3-pip nmap git curl unzip ca-certificates build-essential \
  snmp masscan hydra

# --------------------------------------------------------------------------- 3. venv + python deps
log "Creating virtualenv and installing Python dependencies"
if [ ! -d "$APP_DIR/.venv" ]; then
  python3 -m venv "$APP_DIR/.venv"
fi
"$APP_DIR/.venv/bin/pip" install --upgrade pip
"$APP_DIR/.venv/bin/pip" install -r "$APP_DIR/requirements.txt"

# --------------------------------------------------------------------------- 4. nuclei
log "Ensuring nuclei $NUCLEI_VERSION"
if command -v nuclei >/dev/null 2>&1 && nuclei -version 2>&1 | grep -q "$NUCLEI_VERSION"; then
  ok "nuclei $NUCLEI_VERSION already installed"
else
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  url="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
  log "Downloading $url"
  curl -fsSL -o "$tmp/nuclei.zip" "$url" || die "Failed to download nuclei."
  unzip -o "$tmp/nuclei.zip" -d "$tmp" >/dev/null
  $SUDO install -m 0755 "$tmp/nuclei" /usr/local/bin/nuclei
  rm -rf "$tmp"
  trap - EXIT
  ok "nuclei installed to /usr/local/bin/nuclei"
fi
# Templates are updated later (step 8) AS the service user, so they land in that
# user's $HOME where the bot will read them — not in root's home.

# --------------------------------------------------------------------------- 5. routersploit
log "Installing routersploit into venv"
if "$APP_DIR/.venv/bin/python" -c "import routersploit" >/dev/null 2>&1; then
  ok "routersploit already importable"
else
  "$APP_DIR/.venv/bin/pip" install routersploit \
    || die "Failed to install routersploit. See README for the git-clone fallback."
  "$APP_DIR/.venv/bin/python" -c "import routersploit" \
    || die "routersploit installed but not importable."
  ok "routersploit installed"
fi

# --------------------------------------------------------------------------- 6. config files
log "Ensuring config files"
if [ ! -f "$APP_DIR/.env" ]; then
  cp "$APP_DIR/.env.example" "$APP_DIR/.env"
  ok "Created .env from .env.example"
else
  ok ".env already exists (left untouched)"
fi
if [ ! -f "$APP_DIR/scope.yaml" ]; then
  cp "$APP_DIR/scope.example.yaml" "$APP_DIR/scope.yaml"
  ok "Created scope.yaml from scope.example.yaml"
else
  ok "scope.yaml already exists (left untouched)"
fi

# --------------------------------------------------------------------------- 7. token check
TOKEN_IS_PLACEHOLDER=0
if grep -q "PUT_YOUR_TOKEN_HERE" "$APP_DIR/.env"; then
  TOKEN_IS_PLACEHOLDER=1
  warn "BOT_TOKEN is still a placeholder."
  warn "Edit $APP_DIR/.env — set BOT_TOKEN and ADMIN_IDS — then:"
  warn "    $SUDO systemctl restart ${SERVICE_NAME}"
fi

# --------------------------------------------------------------------------- 8. service user
SERVICE_HOME="/home/${SERVICE_USER}"
log "Ensuring service user '$SERVICE_USER'"
if id "$SERVICE_USER" >/dev/null 2>&1; then
  ok "User $SERVICE_USER already exists"
else
  # Give the user a home dir: nuclei needs a writable $HOME for its config dir
  # and templates ($HOME/.config/nuclei). Without it nuclei fails at runtime.
  $SUDO useradd --system --create-home --home-dir "$SERVICE_HOME" \
    --shell /usr/sbin/nologin "$SERVICE_USER"
  ok "Created system user $SERVICE_USER"
fi
# Ensure the home exists and is writable even on re-runs / pre-existing users.
$SUDO mkdir -p "$SERVICE_HOME"
$SUDO chown -R "$SERVICE_USER":"$SERVICE_USER" "$SERVICE_HOME"
log "Setting ownership of $APP_DIR"
$SUDO chown -R "$SERVICE_USER":"$SERVICE_USER" "$APP_DIR"

# Update nuclei templates AS the service user so they land in its $HOME (the
# bot runs as $SERVICE_USER and reads templates from there, not from root's home).
log "Updating nuclei templates for $SERVICE_USER (non-fatal)"
$SUDO -u "$SERVICE_USER" env HOME="$SERVICE_HOME" nuclei -update-templates >/dev/null 2>&1 \
  || warn "nuclei -update-templates failed; continuing (run it later as $SERVICE_USER)."

# --------------------------------------------------------------------------- 9. systemd unit
log "Installing systemd unit"
UNIT_TARGET="/etc/systemd/system/${SERVICE_NAME}.service"
tmp_unit="$(mktemp)"
sed -e "s|__APP_DIR__|${APP_DIR}|g" \
    -e "s|__SERVICE_USER__|${SERVICE_USER}|g" \
    "$APP_DIR/pentest-bot.service" > "$tmp_unit"
$SUDO install -m 0644 "$tmp_unit" "$UNIT_TARGET"
rm -f "$tmp_unit"
$SUDO systemctl daemon-reload
$SUDO systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
ok "Unit installed and enabled at $UNIT_TARGET"

if [ "$TOKEN_IS_PLACEHOLDER" -eq 0 ]; then
  log "Starting service"
  $SUDO systemctl restart "$SERVICE_NAME"
  ok "Service started"
else
  warn "Service NOT started because BOT_TOKEN is a placeholder."
fi

# --------------------------------------------------------------------------- 10. summary
echo
ok "Installation complete."
echo "----------------------------------------------------------------------"
echo " Installed:"
echo "   nmap:        $(nmap --version 2>/dev/null | head -n1 || echo '?')"
echo "   nuclei:      $(nuclei -version 2>&1 | head -n1 || echo '?')"
echo "   routersploit: $("$APP_DIR/.venv/bin/python" -c 'import routersploit; print("ok")' 2>/dev/null || echo 'missing')"
echo
echo " Config:"
echo "   .env:        $APP_DIR/.env"
echo "   scope.yaml:  $APP_DIR/scope.yaml"
echo
echo " Service management:"
echo "   $SUDO systemctl start   ${SERVICE_NAME}"
echo "   $SUDO systemctl status  ${SERVICE_NAME}"
echo "   $SUDO journalctl -u ${SERVICE_NAME} -f"
echo "----------------------------------------------------------------------"
if [ "$TOKEN_IS_PLACEHOLDER" -eq 1 ]; then
  echo
  warn "NEXT STEP: fill BOT_TOKEN and ADMIN_IDS in $APP_DIR/.env, then:"
  echo "    $SUDO systemctl restart ${SERVICE_NAME} && $SUDO journalctl -u ${SERVICE_NAME} -f"
fi
