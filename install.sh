#!/usr/bin/env bash
# Serial Server — Raspberry Pi install script
# Usage: sudo bash install.sh
# Installs everything to /opt/serial-server and sets up systemd + nginx.

set -euo pipefail

INSTALL_DIR="/opt/serial-server"
SERVICE_USER="serial-server"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/serial_server"

# -- Colour helpers -------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# -- Root check -----------------------------------------------------------------
[[ $EUID -eq 0 ]] || error "This script must be run as root (sudo bash install.sh)"

# -- Detect source directory ----------------------------------------------------
[[ -f "$SRC_DIR/server.py" ]] || \
    error "Cannot find $SRC_DIR/server.py — run this script from the stand_alone_serial directory."

# -- Python version check -------------------------------------------------------
PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "0.0")
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
if [[ "$PY_MAJOR" -lt 3 || ( "$PY_MAJOR" -eq 3 && "$PY_MINOR" -lt 10 ) ]]; then
    error "Python 3.10 or newer is required (found $PY_VERSION)."
fi
info "Python $PY_VERSION found — OK."

# -- System packages ------------------------------------------------------------
info "Updating package lists…"
apt-get update -qq

info "Installing system dependencies…"
apt-get install -y -qq \
    python3 python3-venv python3-pip \
    nginx \
    ser2net \
    openssl \
    libffi-dev libssl-dev \
    sqlite3 \
    rsync \
    git

# -- Service user ---------------------------------------------------------------
if ! id "$SERVICE_USER" &>/dev/null; then
    info "Creating system user '$SERVICE_USER'…"
    useradd --system --no-create-home --shell /usr/sbin/nologin \
            --groups dialout "$SERVICE_USER"
else
    info "User '$SERVICE_USER' already exists."
    # Ensure dialout group membership (needed for serial ports)
    usermod -aG dialout "$SERVICE_USER" 2>/dev/null || true
fi

# -- Emergency disable script ---------------------------------------------------
EMERGENCY_SCRIPT="/usr/local/sbin/serial-server-emergency-disable"
info "Installing emergency disable script to $EMERGENCY_SCRIPT…"
cp "$SCRIPT_DIR/serial_server/emergency-disable.sh" "$EMERGENCY_SCRIPT"
chmod 700 "$EMERGENCY_SCRIPT"
info "Emergency disable script installed."

# -- sudoers (allow service user to run privileged helpers) ---------------------
info "Installing sudoers rules for '$SERVICE_USER'…"
SUDOERS_FILE="/etc/sudoers.d/serial-server"
TEE_BIN=$(command -v tee)
UDEVADM_BIN=$(command -v udevadm)
NGINX_BIN=$(command -v nginx)
SYSTEMCTL_BIN=$(command -v systemctl)
CP_BIN=$(command -v cp)
SQLITE3_BIN=$(command -v sqlite3 || echo "/usr/bin/sqlite3")
cat > "$SUDOERS_FILE" <<SUDOEOF
# Managed by serial-server install.sh -- do not edit manually
$SERVICE_USER ALL=(root) NOPASSWD: \\
    $TEE_BIN /etc/udev/rules.d/99-usb-serial.rules, \\
    $UDEVADM_BIN control --reload-rules, \\
    $UDEVADM_BIN trigger --subsystem-match=tty, \\
    $NGINX_BIN -t, \\
    $SYSTEMCTL_BIN reload nginx, \\
    $CP_BIN $INSTALL_DIR/nginx/serial-server.conf /etc/nginx/sites-available/serial-server

# Allow the admin user to run the emergency disable script
%sudo ALL=(root) NOPASSWD: $EMERGENCY_SCRIPT
SUDOEOF
chmod 440 "$SUDOERS_FILE"
visudo -cf "$SUDOERS_FILE" || error "Generated sudoers file is invalid — check $SUDOERS_FILE"
info "sudoers OK."

# -- sqlite3 (needed by emergency-disable script) -------------------------------
if ! command -v sqlite3 &>/dev/null; then
    info "Installing sqlite3 (required by emergency-disable script)…"
    apt-get install -y -qq sqlite3
fi

# -- Install application files --------------------------------------------------
info "Installing application to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

# Copy source files (exclude venv, __pycache__, .git)
rsync -a --delete \
    --exclude='.venv' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='.git' \
    --exclude='users.db' \
    --exclude='session.key' \
    --exclude='labels.json' \
    --exclude='tls/' \
    "$SRC_DIR/" "$INSTALL_DIR/"

# Create subdirectories that must exist
mkdir -p "$INSTALL_DIR/static"
mkdir -p "$INSTALL_DIR/nginx"
mkdir -p "$INSTALL_DIR/tls"

# -- Python virtual environment -------------------------------------------------
if [[ ! -d "$INSTALL_DIR/.venv" ]]; then
    info "Creating Python virtual environment…"
    python3 -m venv "$INSTALL_DIR/.venv"
fi

info "Installing Python packages…"
"$INSTALL_DIR/.venv/bin/pip" install --upgrade pip -q
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q

# -- Ownership & permissions ----------------------------------------------------
info "Setting file ownership…"
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
chmod 750 "$INSTALL_DIR"
chmod 755 "$INSTALL_DIR/static"

# -- Self-signed TLS certificate (if no cert present) --------------------------
if [[ ! -f "$INSTALL_DIR/tls/server.crt" ]]; then
    info "Generating self-signed TLS certificate…"
    HOSTNAME=$(hostname -f 2>/dev/null || hostname)
    openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout "$INSTALL_DIR/tls/server.key" \
        -out    "$INSTALL_DIR/tls/server.crt" \
        -days   3650 \
        -subj   "/CN=$HOSTNAME" \
        -addext "subjectAltName=DNS:$HOSTNAME,IP:$(hostname -I | awk '{print $1}')" \
        2>/dev/null
    chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/tls/server.key" \
                                        "$INSTALL_DIR/tls/server.crt"
    chmod 640 "$INSTALL_DIR/tls/server.key"
    chmod 644 "$INSTALL_DIR/tls/server.crt"
    info "Self-signed cert written to $INSTALL_DIR/tls/"
fi

# -- nginx configuration --------------------------------------------------------
info "Installing nginx configuration…"

NGINX_CONF_DEST="/etc/nginx/sites-available/serial-server"
cat > "$NGINX_CONF_DEST" <<'NGINXEOF'
# Serial Console — nginx reverse proxy (HTTPS)
# Authentication is handled by the Python app (session cookies).

upstream serial_backend {
    server 127.0.0.1:8080;
    keepalive 8;
}

# Redirect HTTP → HTTPS
server {
    listen 80;
    server_name _;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name _;

    ssl_certificate     /opt/serial-server/tls/server.crt;
    ssl_certificate_key /opt/serial-server/tls/server.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 10m;

    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;

    location /ws/ {
        proxy_pass         http://serial_backend;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade    $http_upgrade;
        proxy_set_header   Connection "upgrade";
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    location / {
        proxy_pass         http://serial_backend;
        proxy_http_version 1.1;
    }
}
NGINXEOF

# Enable site (remove default if it would conflict on port 80/443)
ln -sf "$NGINX_CONF_DEST" /etc/nginx/sites-enabled/serial-server

# Disable default nginx site quietly
if [[ -L /etc/nginx/sites-enabled/default ]]; then
    warn "Disabling nginx default site to avoid port conflict."
    rm -f /etc/nginx/sites-enabled/default
fi

nginx -t 2>/dev/null && info "nginx config OK." || warn "nginx config test failed — check $NGINX_CONF_DEST"

# Allow nginx to read the TLS cert (nginx runs as www-data)
chown "$SERVICE_USER:www-data" "$INSTALL_DIR/tls/server.key" \
                               "$INSTALL_DIR/tls/server.crt" 2>/dev/null || true
chmod 640 "$INSTALL_DIR/tls/server.key"
chmod 644 "$INSTALL_DIR/tls/server.crt"

# -- systemd service ------------------------------------------------------------
info "Installing systemd service…"

cat > /etc/systemd/system/serial-server.service <<SVCEOF
[Unit]
Description=Serial WebSocket Bridge Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/.venv/bin/python3 $INSTALL_DIR/server.py
Restart=on-failure
RestartSec=5
TimeoutStopSec=15
StandardOutput=journal
StandardError=journal
SyslogIdentifier=serial-server

# Give the process access to serial devices
SupplementaryGroups=dialout

# Hardening (loosen where needed)
ProtectSystem=full
ProtectHome=yes
ReadWritePaths=$INSTALL_DIR /etc/udev/rules.d /etc/nginx/sites-available

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable serial-server.service

# -- ser2net --------------------------------------------------------------------
# ser2net is managed by server.py as subprocesses — just ensure it is installed.
# Leave any existing /etc/ser2net.conf untouched.
if command -v ser2net &>/dev/null; then
    info "ser2net is available (managed by serial-server at runtime)."
    # Make sure the system ser2net service doesn't fight with our subprocesses
    systemctl disable --now ser2net.service 2>/dev/null || true
fi

# -- Start services -------------------------------------------------------------
info "Starting serial-server…"
systemctl restart serial-server.service

info "Reloading nginx…"
systemctl reload nginx 2>/dev/null || systemctl restart nginx

# -- Done -----------------------------------------------------------------------
IP=$(hostname -I | awk '{print $1}')
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN} Serial Server installed successfully!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  Web UI : https://$IP"
echo "  SSH    : ssh <user>@$IP -p 2222  (if SSH bridge is enabled)"
echo ""
echo "  Default login: admin / admin"
echo "  Change your password in Settings after first login."
echo ""
echo "  Logs   : journalctl -u serial-server -f"
echo ""
warn "The TLS certificate is self-signed. Your browser will show a security"
warn "warning — accept the exception, or upload a real certificate in Settings."
echo ""
