#!/usr/bin/env bash
# serial-server-emergency-disable
# Run via SSH as: sudo serial-server-emergency-disable
#
# Disables mTLS and IP whitelist in the serial-server database,
# regenerates the nginx config, and restarts the service so you
# can reach the web UI again without a client certificate.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -eq 0 ]] || error "Must be run as root: sudo serial-server-emergency-disable"

# Locate the installation directory
if [[ -f "/opt/serial-server/users.db" ]]; then
    INSTALL_DIR="/opt/serial-server"
elif [[ -f "$(dirname "${BASH_SOURCE[0]}")/users.db" ]]; then
    INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    error "Cannot find users.db -- tried /opt/serial-server and script directory."
fi

DB="$INSTALL_DIR/users.db"
NGINX_CONF="$INSTALL_DIR/nginx/serial-server.conf"
NGINX_DEST="/etc/nginx/sites-available/serial-server"

info "Using installation directory: $INSTALL_DIR"

info "Disabling mTLS and IP whitelist in database..."
if command -v sqlite3 &>/dev/null; then
    sqlite3 "$DB" <<SQL
INSERT OR REPLACE INTO settings (key, value) VALUES ('mtls_enabled',         '0');
INSERT OR REPLACE INTO settings (key, value) VALUES ('ip_whitelist_enabled', '0');
SQL
elif command -v python3 &>/dev/null; then
    python3 - "$DB" <<'PYEOF'
import sys, sqlite3 as _sql
db = _sql.connect(sys.argv[1])
db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('mtls_enabled', '0')")
db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ip_whitelist_enabled', '0')")
db.commit(); db.close()
PYEOF
else
    error "Neither sqlite3 nor python3 found -- cannot update database."
fi

info "Writing plain HTTPS nginx config..."
PORT=$(sqlite3 "$DB" "SELECT value FROM settings WHERE key='port'" 2>/dev/null || echo "8080")
SERVER_CERT="/opt/serial-server/tls/server.crt"
SERVER_KEY="/opt/serial-server/tls/server.key"

if [[ -f "$SERVER_CERT" && -f "$SERVER_KEY" ]]; then
    cat > "$NGINX_CONF" <<NGINXEOF
# Serial Console -- nginx reverse proxy (HTTPS)
# Written by emergency-disable script -- mTLS and IP whitelist disabled.

upstream serial_backend {
    server 127.0.0.1:8080;
    keepalive 8;
}

server {
    listen 80;
    server_name _;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name _;

    ssl_certificate     $SERVER_CERT;
    ssl_certificate_key $SERVER_KEY;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 10m;

    proxy_set_header Host              \$host;
    proxy_set_header X-Real-IP         \$remote_addr;
    proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;

    location /ws/ {
        proxy_pass         http://serial_backend;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade    \$http_upgrade;
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
    cp "$NGINX_CONF" "$NGINX_DEST"
    nginx -t 2>/dev/null && systemctl reload nginx || warn "nginx reload failed -- check config manually"
    info "nginx config updated."
else
    warn "No TLS certificate found -- nginx config not changed."
fi

info "Restarting serial-server..."
systemctl restart serial-server.service

IP=$(hostname -I | awk '{print $1}')
echo ""
echo -e "${GREEN}Emergency disable complete.${NC}"
echo ""
echo "  Access the web UI at: https://$IP"
echo "  Login with your username and password."
echo "  Re-enable security controls in Settings -> Access Control."
echo ""
