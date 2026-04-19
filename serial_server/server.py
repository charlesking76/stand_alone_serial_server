#!/usr/bin/env python3
"""
Serial WebSocket bridge server with session-based authentication.

Endpoints:
  GET  /                        -> web UI (requires auth)
  GET  /login                   -> login page
  POST /login                   -> authenticate
  GET  /logout                  -> log out
  GET  /api/me                  -> current logged-in username
  GET  /ports                   -> JSON list of port names
  GET  /api/config              -> JSON full config (baud, tcp_port) per port
  POST /api/config/{port}       -> update port config  body: {"baud": 115200}
  GET  /api/baud_rates          -> valid baud rates
  GET  /api/labels              -> port labels
  POST /api/labels/{port}       -> set port label
  GET  /api/users               -> list users (requires auth)
  POST /api/users               -> add/update user  body: {"username": "...", "password": "..."}
  DELETE /api/users/{username}  -> remove user (requires auth)
  GET  /ws/{port}               -> WebSocket terminal (requires auth)
"""

import asyncio
import base64
import datetime
import glob
import hashlib
import json
import logging
import os
import pathlib
import re
import time
import uuid

import aiosqlite
import asyncssh
import bcrypt
from aiohttp import web, WSMsgType
from aiohttp_session import get_session, setup as session_setup
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from cryptography.fernet import Fernet

_log_handler = logging.StreamHandler()
_log_handler.terminator = "\r\n"
_log_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logging.basicConfig(level=logging.INFO, handlers=[_log_handler])
log = logging.getLogger(__name__)

__version__ = "1.0.0"

VALID_BAUDS   = [300, 1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200]
TCP_PORT_BASE = 7000

# Populated at startup by _discover_ports(); baud can be changed at runtime.
PORT_CONFIG: dict[str, dict] = {}

CONF_DIR         = pathlib.Path(__file__).parent
STATIC_DIR       = pathlib.Path(__file__).parent / "static"
LABELS_FILE      = CONF_DIR / "labels.json"
DB_PATH          = CONF_DIR / "users.db"
SESSION_KEY_FILE = CONF_DIR / "session.key"
TLS_DIR          = CONF_DIR / "tls"
CA_DIR           = TLS_DIR / "ca"
CLIENTS_DIR      = TLS_DIR / "clients"
NGINX_CONF_SRC   = CONF_DIR / "nginx" / "serial-server.conf"
NGINX_CONF_DEST  = pathlib.Path(
    os.environ.get("NGINX_CONF_DEST", "/etc/nginx/sites-available/serial-server")
)
SERVER_NAME      = os.environ.get("SERVER_NAME", "_")
CHUNK            = 4096

LABELS: dict[str, str] = {}


# -- Session key ----------------------------------------------------------------

def _get_or_create_session_key() -> bytes:
    """Load or generate a persistent Fernet key for cookie encryption."""
    if SESSION_KEY_FILE.exists():
        return base64.urlsafe_b64decode(SESSION_KEY_FILE.read_bytes().strip())
    key = Fernet.generate_key()
    SESSION_KEY_FILE.write_bytes(key)
    SESSION_KEY_FILE.chmod(0o600)
    log.info("Generated new session key: %s", SESSION_KEY_FILE)
    return base64.urlsafe_b64decode(key)


# -- Database -------------------------------------------------------------------

async def init_db() -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS login_log (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                username     TEXT NOT NULL,
                ip           TEXT,
                success      INTEGER NOT NULL DEFAULT 1,
                logged_in_at TEXT NOT NULL
            )
        """)
        # Migrate: add success column if upgrading from an older schema
        try:
            await db.execute("ALTER TABLE login_log ADD COLUMN success INTEGER NOT NULL DEFAULT 1")
        except Exception:
            pass  # column already exists

        await db.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        await db.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES ('session_timeout_minutes', '60')"
        )
        await db.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES ('ssh_enabled', '0')"
        )
        await db.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES ('ssh_port', '2222')"
        )
        await db.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES ('ssh_serial_port', '')"
        )
        await db.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES ('udev_auto_register', '0')"
        )
        await db.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES ('udev_id_method', 'usb_path')"
        )
        await db.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES ('mtls_enabled', '0')"
        )
        await db.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES ('ip_whitelist_enabled', '0')"
        )
        await db.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES ('ip_whitelist', '[]')"
        )
        await db.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES ('break_glass_ips', '[]')"
        )
        # Generate a unique system ID on first run
        async with db.execute("SELECT value FROM settings WHERE key = 'system_id'") as cur:
            if not await cur.fetchone():
                import secrets as _secrets
                raw = _secrets.token_hex(4).upper()
                sid = f"{raw[:4]}-{raw[4:]}"
                await db.execute(
                    "INSERT INTO settings (key, value) VALUES ('system_id', ?)", (sid,)
                )
        await db.execute("""
            CREATE TABLE IF NOT EXISTS client_certs (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                serial_num  TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                issued_at   TEXT NOT NULL,
                revoked     INTEGER NOT NULL DEFAULT 0
            )
        """)
        await db.commit()

        async with db.execute("SELECT COUNT(*) FROM users") as cur:
            (count,) = await cur.fetchone()

        if count == 0:
            hashed = bcrypt.hashpw(b"admin", bcrypt.gensalt()).decode()
            await db.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                ("admin", hashed),
            )
            await db.commit()
            log.info("Created default admin/admin user")


# In-memory cache — updated at startup and whenever the setting changes
_session_timeout_seconds: int = 3600  # default 60 min
_mtls_enabled:            bool       = False
_ip_whitelist_enabled:    bool       = False
_ip_whitelist:            list[str]  = []
_break_glass_ips:         list[str]  = []


_system_id: str = ''

async def _load_settings() -> None:
    global _session_timeout_seconds, _udev_auto_register, _udev_id_method, _system_id
    global _mtls_enabled, _ip_whitelist_enabled, _ip_whitelist, _break_glass_ips
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT key, value FROM settings") as cur:
            rows = await cur.fetchall()
    for key, value in rows:
        if key == 'session_timeout_minutes':
            minutes = int(value)
            _session_timeout_seconds = minutes * 60 if minutes > 0 else 0
        elif key == 'udev_auto_register':
            _udev_auto_register = value == '1'
        elif key == 'udev_id_method':
            _udev_id_method = value if value in ('usb_path', 'serial') else 'usb_path'
        elif key == 'system_id':
            _system_id = value
        elif key == 'mtls_enabled':
            _mtls_enabled = value == '1'
        elif key == 'ip_whitelist_enabled':
            _ip_whitelist_enabled = value == '1'
        elif key == 'ip_whitelist':
            _ip_whitelist = json.loads(value)
        elif key == 'break_glass_ips':
            _break_glass_ips = json.loads(value)


async def _check_credentials(username: str, password: str) -> bool:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT password FROM users WHERE username = ?", (username,)
        ) as cur:
            row = await cur.fetchone()
    if not row:
        return False
    # Run bcrypt in a thread — it's deliberately slow and would block the event loop
    return await asyncio.get_running_loop().run_in_executor(
        None, bcrypt.checkpw, password.encode(), row[0].encode()
    )


# -- Auth middleware ------------------------------------------------------------

_PUBLIC_PATHS = {"/login", "/logout"}


def _get_client_ip(request: web.Request) -> str:
    """Return the real client IP, preferring X-Real-IP set by nginx."""
    return (
        request.headers.get("X-Real-IP", "").strip()
        or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or (request.remote or "")
    )


def _ip_in_list(ip: str, entries: list[str]) -> bool:
    """Return True if *ip* matches any entry (exact IP or CIDR) in *entries*."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in entries:
        try:
            if addr in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            if ip == entry:
                return True
    return False


@web.middleware
async def auth_middleware(request: web.Request, handler) -> web.StreamResponse:
    path = request.path
    if path in _PUBLIC_PATHS or path.startswith("/static/"):
        return await handler(request)

    client_ip = _get_client_ip(request)

    # -- IP whitelist (enforced before session check) --------------------------
    if _ip_whitelist_enabled and _ip_whitelist:
        if not _ip_in_list(client_ip, _ip_whitelist):
            return web.Response(status=403, text="IP not permitted")

    # -- mTLS enforcement ------------------------------------------------------
    if _mtls_enabled:
        is_break_glass = bool(_break_glass_ips) and _ip_in_list(client_ip, _break_glass_ips)
        if not is_break_glass:
            verify = request.headers.get("X-SSL-Client-Verify", "NONE")
            if verify != "SUCCESS":
                return web.Response(
                    status=403,
                    content_type="text/html",
                    text=(
                        "<html><body><h2>Client certificate required</h2>"
                        "<p>This server requires a valid client TLS certificate.<br>"
                        "Download your certificate from the Access Control settings.</p>"
                        "</body></html>"
                    ),
                )

    # -- Session / login check -------------------------------------------------
    session = await get_session(request)
    if not session.get("username"):
        raise web.HTTPFound("/login")

    if _session_timeout_seconds > 0:
        last_active = session.get("last_active", 0)
        if time.time() - last_active > _session_timeout_seconds:
            session.invalidate()
            raise web.HTTPFound("/login?timeout=1")
        session["last_active"] = time.time()

    return await handler(request)


# -- Auth handlers --------------------------------------------------------------

async def login_get_handler(request: web.Request) -> web.FileResponse:
    session = await get_session(request)
    if session.get("username"):
        raise web.HTTPFound("/")
    return web.FileResponse(STATIC_DIR / "login.html")


async def login_post_handler(request: web.Request) -> web.Response:
    data = await request.post()
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    ip = (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.remote
    )

    ok = bool(username and password and await _check_credentials(username, password))

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO login_log (username, ip, success, logged_in_at)"
            " VALUES (?, ?, ?, datetime('now'))",
            (username or "(blank)", ip, int(ok)),
        )
        await db.commit()

    if not ok:
        log.warning("Failed login attempt for '%s' from %s", username or "(blank)", ip)
        raise web.HTTPFound("/login?error=1")

    session = await get_session(request)
    session["username"] = username
    session["last_active"] = time.time()
    log.info("User logged in: %s from %s", username, ip)
    raise web.HTTPFound("/")


async def logout_handler(request: web.Request) -> web.Response:
    session = await get_session(request)
    username = session.get("username", "?")
    session.invalidate()
    log.info("User logged out: %s", username)
    raise web.HTTPFound("/login")


# -- User management API --------------------------------------------------------

async def me_handler(request: web.Request) -> web.Response:
    session = await get_session(request)
    return web.json_response({"username": session.get("username")})


async def users_list_handler(request: web.Request) -> web.Response:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT username FROM users ORDER BY username") as cur:
            rows = await cur.fetchall()
    return web.json_response([row[0] for row in rows])


async def users_add_handler(request: web.Request) -> web.Response:
    body = await request.json()
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))

    if not username or not password:
        raise web.HTTPBadRequest(reason="username and password are required")
    if len(username) > 64:
        raise web.HTTPBadRequest(reason="username too long")

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    async with aiosqlite.connect(DB_PATH) as db:
        # INSERT OR REPLACE so this doubles as an update
        await db.execute(
            "INSERT OR REPLACE INTO users (username, password) VALUES (?, ?)",
            (username, hashed),
        )
        await db.commit()

    log.info("User '%s' added/updated", username)
    return web.json_response({"ok": True, "username": username})


async def ping_handler(request: web.Request) -> web.Response:
    """Lightweight endpoint the client hits to reset the server-side idle timer."""
    return web.json_response({"ok": True})


async def version_handler(request: web.Request) -> web.Response:
    return web.json_response({"version": __version__})


async def system_info_handler(request: web.Request) -> web.Response:
    import sys, platform, subprocess

    def _run(cmd):
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=3).decode().strip()
            return out
        except Exception:
            return None

    # Python
    py_ver = sys.version.split()[0]

    # ser2net
    ser2net_ver = None
    raw = _run(["ser2net", "-v"])
    if raw:
        m = re.search(r'[\d]+\.[\d]+[\w.]*', raw)
        ser2net_ver = m.group(0) if m else raw.split('\n')[0]

    # nginx
    nginx_ver = None
    raw = _run(["nginx", "-v"])
    if raw:
        m = re.search(r'nginx/([\d.]+)', raw)
        nginx_ver = m.group(1) if m else None

    # OS
    os_name = platform.freedesktop_os_release().get('PRETTY_NAME', platform.platform()) \
        if hasattr(platform, 'freedesktop_os_release') else platform.platform()

    # aiohttp
    try:
        import aiohttp as _aiohttp
        aiohttp_ver = _aiohttp.__version__
    except Exception:
        aiohttp_ver = None

    # xterm versions derived from versioned filenames e.g. xterm-5.3.0.js
    import glob as _glob

    def _xterm_version(pattern, prefix):
        matches = _glob.glob(str(STATIC_DIR / pattern))
        if matches:
            stem = pathlib.Path(matches[0]).stem
            return stem[len(prefix):]
        return None

    xterm_ver     = _xterm_version("xterm-[0-9]*.js",          "xterm-")
    xterm_fit_ver = _xterm_version("xterm-addon-fit-[0-9]*.js", "xterm-addon-fit-")

    return web.json_response({
        "serial_server":    __version__,
        "python":           py_ver,
        "aiohttp":          aiohttp_ver,
        "ser2net":          ser2net_ver,
        "nginx":            nginx_ver,
        "os":               os_name,
        "xterm":            xterm_ver,
        "xterm_addon_fit":  xterm_fit_ver,
    })


async def get_settings_handler(request: web.Request) -> web.Response:
    timeout_minutes = _session_timeout_seconds // 60 if _session_timeout_seconds > 0 else 0
    return web.json_response({"session_timeout_minutes": timeout_minutes})


async def post_settings_handler(request: web.Request) -> web.Response:
    global _session_timeout_seconds
    body = await request.json()
    try:
        minutes = int(body["session_timeout_minutes"])
    except (KeyError, ValueError):
        raise web.HTTPBadRequest(reason="session_timeout_minutes must be an integer")
    if minutes < 0:
        raise web.HTTPBadRequest(reason="Timeout must be 0 (disabled) or a positive number of minutes")

    _session_timeout_seconds = minutes * 60 if minutes > 0 else 0
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES ('session_timeout_minutes', ?)",
            (str(minutes),),
        )
        await db.commit()
    log.info("Session timeout set to %d minutes", minutes)
    return web.json_response({"ok": True, "session_timeout_minutes": minutes})


async def logs_handler(request: web.Request) -> web.Response:
    limit  = min(int(request.rel_url.query.get("limit", 25)), 200)
    page   = max(int(request.rel_url.query.get("page", 1)), 1)
    offset = (page - 1) * limit
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT COUNT(*) FROM login_log") as cur:
            (total,) = await cur.fetchone()
        async with db.execute(
            "SELECT username, ip, success, logged_in_at FROM login_log"
            " ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ) as cur:
            rows = await cur.fetchall()
    return web.json_response({
        "total": total,
        "page": page,
        "limit": limit,
        "rows": [dict(r) for r in rows],
    })


async def users_delete_handler(request: web.Request) -> web.Response:
    target = request.match_info["username"]
    session = await get_session(request)

    if target == session.get("username"):
        raise web.HTTPBadRequest(reason="Cannot delete your own account")

    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT COUNT(*) FROM users") as cur:
            (count,) = await cur.fetchone()
        if count <= 1:
            raise web.HTTPBadRequest(reason="Cannot delete the last user")
        result = await db.execute("DELETE FROM users WHERE username = ?", (target,))
        await db.commit()
        if result.rowcount == 0:
            raise web.HTTPNotFound(reason=f"User '{target}' not found")

    log.info("User '%s' removed", target)
    return web.json_response({"ok": True, "username": target})


# -- TLS / NGINX config management ---------------------------------------------

def _nginx_conf_http() -> str:
    port = int(os.environ.get("PORT", "8080"))
    return f"""\
# Serial Console — nginx reverse proxy
# Authentication is handled by the Python app (session cookies).

upstream serial_backend {{
    server 127.0.0.1:{port};
    keepalive 8;
}}

server {{
    listen 80;
    server_name {SERVER_NAME};

    location /ws/ {{
        proxy_pass         http://serial_backend;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_set_header   Upgrade           $http_upgrade;
        proxy_set_header   Connection        "upgrade";
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }}

    location / {{
        proxy_pass         http://serial_backend;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }}
}}
"""


def _nginx_conf_https(
    mtls_enabled:         bool      = False,
    ip_whitelist_enabled: bool      = False,
    ip_whitelist:         list[str] | None = None,
    break_glass_ips:      list[str] | None = None,
) -> str:
    port      = int(os.environ.get("PORT", "8080"))
    cert_path = TLS_DIR / "server.crt"
    key_path  = TLS_DIR / "server.key"
    ca_crt    = CA_DIR / "ca.crt"
    ca_crl    = CA_DIR / "ca.crl"

    ip_whitelist    = ip_whitelist    or []
    break_glass_ips = break_glass_ips or []

    # -- ssl_verify_client / ssl_client_certificate lines ---------------------
    # Access control (mTLS cert check, IP whitelist) is enforced in Python
    # auth_middleware via the X-SSL-Client-Verify / X-Real-IP headers.
    # We deliberately avoid nginx `if` blocks inside `location` blocks that
    # also have `proxy_pass` — that combination can produce ERR_INVALID_RESPONSE
    # in some nginx versions ("if is evil").
    mtls_ssl_lines = ""
    if mtls_enabled and ca_crt.exists():
        mtls_ssl_lines = f"    ssl_verify_client optional;\n    ssl_client_certificate {ca_crt};"
        if ca_crl.exists():
            mtls_ssl_lines += f"\n    ssl_crl {ca_crl};"

    return f"""\
# Serial Console -- nginx reverse proxy (HTTPS)
# Authentication is handled by the Python app (session cookies).
# Auto-generated by serial-server -- do not edit manually.

upstream serial_backend {{
    server 127.0.0.1:{port};
    keepalive 8;
}}

# Redirect HTTP to HTTPS
server {{
    listen 80;
    server_name {SERVER_NAME};
    return 301 https://$host$request_uri;
}}

server {{
    listen 443 ssl;
    server_name {SERVER_NAME};

    ssl_certificate     {cert_path};
    ssl_certificate_key {key_path};
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 10m;
{mtls_ssl_lines}

    location /ws/ {{
        proxy_pass         http://serial_backend;
        proxy_http_version 1.1;
        proxy_set_header   Host                $host;
        proxy_set_header   X-Real-IP           $remote_addr;
        proxy_set_header   X-Forwarded-For     $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto   https;
        proxy_set_header   X-SSL-Client-Verify $ssl_client_verify;
        proxy_set_header   Upgrade             $http_upgrade;
        proxy_set_header   Connection          "upgrade";
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }}

    location / {{
        proxy_pass         http://serial_backend;
        proxy_http_version 1.1;
        proxy_set_header   Host                $host;
        proxy_set_header   X-Real-IP           $remote_addr;
        proxy_set_header   X-Forwarded-For     $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto   https;
        proxy_set_header   X-SSL-Client-Verify $ssl_client_verify;
    }}
}}
"""


def _get_cert_info() -> dict | None:
    cert_path = TLS_DIR / "server.crt"
    if not cert_path.exists():
        return None
    try:
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        try:
            cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        except (IndexError, Exception):
            cn = "(no CN)"
        return {
            "subject": cn,
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after":  cert.not_valid_after_utc.isoformat(),
        }
    except Exception as exc:
        log.warning("Failed to parse cert: %s", exc)
        return {"subject": "Unknown", "not_before": None, "not_after": None}


async def _apply_nginx_config(https: bool) -> tuple[bool, str]:
    """Write the nginx config locally, copy to sites-available, test, and reload."""
    conf = (
        _nginx_conf_https(
            mtls_enabled=_mtls_enabled,
            ip_whitelist_enabled=_ip_whitelist_enabled,
            ip_whitelist=_ip_whitelist,
            break_glass_ips=_break_glass_ips,
        )
        if https else _nginx_conf_http()
    )
    NGINX_CONF_SRC.write_text(conf)

    for cmd in [
        ["sudo", "cp", str(NGINX_CONF_SRC), str(NGINX_CONF_DEST)],
        ["sudo", "nginx", "-t"],
        ["sudo", "systemctl", "reload", "nginx"],
    ]:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            return False, f"{' '.join(cmd[1])} failed: {stderr.decode().strip()}"

    return True, ""


# -- CA and client certificate management --------------------------------------

def _ensure_ca():
    """Return (ca_key, ca_cert), generating a 4096-bit RSA CA if not present."""
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    CA_DIR.mkdir(parents=True, exist_ok=True)
    key_path = CA_DIR / "ca.key"
    crt_path = CA_DIR / "ca.crt"

    if key_path.exists() and crt_path.exists():
        ca_key  = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        ca_cert = _x509.load_pem_x509_certificate(crt_path.read_bytes())
        return ca_key, ca_cert

    log.info("Generating CA key and certificate…")
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    cn = f"Serial Server CA [{_system_id}]" if _system_id else "Serial Server CA"
    subject = _x509.Name([_x509.NameAttribute(_x509.NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_cert = (
        _x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(_x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(_x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            _x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                           content_commitment=False, key_encipherment=False,
                           data_encipherment=False, key_agreement=False,
                           encipher_only=False, decipher_only=False),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    key_path.write_bytes(
        ca_key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    )
    key_path.chmod(0o600)
    crt_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    log.info("CA generated: %s", crt_path)
    return ca_key, ca_cert


def _regenerate_crl() -> None:
    """Build a CRL from all revoked certs and write it to ca/ca.crl (sync)."""
    import aiosqlite as _aio  # noqa — sync sqlite3 used here for simplicity
    import sqlite3
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import hashes, serialization

    ca_key, ca_cert = _ensure_ca()
    now = datetime.datetime.now(datetime.timezone.utc)

    builder = (
        _x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=1))
    )

    with sqlite3.connect(DB_PATH) as con:
        rows = con.execute(
            "SELECT serial_num FROM client_certs WHERE revoked = 1"
        ).fetchall()

    for (serial_str,) in rows:
        revoked = (
            _x509.RevokedCertificateBuilder()
            .serial_number(int(serial_str))
            .revocation_date(now)
            .build()
        )
        builder = builder.add_revoked_certificate(revoked)

    crl = builder.sign(ca_key, hashes.SHA256())
    crl_path = CA_DIR / "ca.crl"
    crl_path.write_bytes(crl.public_bytes(serialization.Encoding.PEM))


async def _generate_client_cert(name: str) -> tuple[str, bytes, str]:
    """Generate a 2048-bit RSA client cert signed by the CA.

    Returns (cert_id, p12_bytes, p12_password).
    The p12 is encrypted with a random password (required by macOS for import).
    """
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12

    loop = asyncio.get_running_loop()
    ca_key, ca_cert = await loop.run_in_executor(None, _ensure_ca)

    def _build():
        client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert_id    = str(uuid.uuid4())
        now        = datetime.datetime.now(datetime.timezone.utc)
        subject    = _x509.Name([_x509.NameAttribute(_x509.NameOID.COMMON_NAME, name)])

        client_cert = (
            _x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(client_key.public_key())
            .serial_number(_x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(_x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                _x509.ExtendedKeyUsage([_x509.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        CLIENTS_DIR.mkdir(parents=True, exist_ok=True)
        (CLIENTS_DIR / f"{cert_id}.crt").write_bytes(
            client_cert.public_bytes(serialization.Encoding.PEM)
        )

        fingerprint = client_cert.fingerprint(hashes.SHA256()).hex()
        serial_num  = str(client_cert.serial_number)
        issued_at   = now.isoformat()

        # Do not bundle the CA in the p12 — macOS tries to install it into
        # System Roots (protected) and shows an error. The CA is installed
        # separately via the "Download CA Certificate" button.
        #
        # Use BestAvailableEncryption with a random password.
        # NoEncryption omits the MAC that macOS requires, so it always reports
        # "wrong password".  BestAvailableEncryption requires a non-empty
        # password.  We generate a random one and return it to the browser.
        import secrets as _secrets
        import string as _string
        alphabet  = _string.ascii_letters + _string.digits
        p12_password = "".join(_secrets.choice(alphabet) for _ in range(16))
        p12_bytes = pkcs12.serialize_key_and_certificates(
            name=name.encode(),
            key=client_key,
            cert=client_cert,
            cas=None,
            encryption_algorithm=serialization.BestAvailableEncryption(
                p12_password.encode()
            ),
        )
        return cert_id, fingerprint, serial_num, issued_at, p12_bytes, p12_password

    cert_id, fingerprint, serial_num, issued_at, p12_bytes, p12_password = \
        await loop.run_in_executor(None, _build)

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO client_certs (id, name, serial_num, fingerprint, issued_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (cert_id, name, serial_num, fingerprint, issued_at),
        )
        await db.commit()

    # Regenerate CRL to include any fresh state
    await asyncio.get_running_loop().run_in_executor(None, _regenerate_crl)
    log.info("Client cert issued: name=%s id=%s", name, cert_id)
    return cert_id, p12_bytes, p12_password


async def _revoke_client_cert(cert_id: str) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE client_certs SET revoked = 1 WHERE id = ?", (cert_id,)
        )
        await db.commit()
    await asyncio.get_running_loop().run_in_executor(None, _regenerate_crl)
    log.info("Client cert revoked: id=%s", cert_id)


async def tls_get_handler(request: web.Request) -> web.Response:
    enabled = (TLS_DIR / "server.crt").exists() and (TLS_DIR / "server.key").exists()
    return web.json_response({"enabled": enabled, "cert": _get_cert_info()})


async def tls_post_handler(request: web.Request) -> web.Response:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, NoEncryption, pkcs12,
    )

    reader = await request.multipart()
    cert_data = key_data = p12_data = p12_password = None

    async for part in reader:
        if part.name == "cert":
            cert_data = await part.read()
        elif part.name == "key":
            key_data = await part.read()
        elif part.name == "p12":
            p12_data = await part.read()
        elif part.name == "p12_password":
            p12_password = (await part.read()).decode().strip()

    if p12_data:
        # -- PKCS#12 path ------------------------------------------------------
        try:
            password_bytes = p12_password.encode() if p12_password else b""
            private_key, certificate, _ = pkcs12.load_key_and_certificates(
                p12_data, password_bytes
            )
        except Exception as exc:
            raise web.HTTPBadRequest(reason=f"Invalid PKCS#12 file or wrong password: {exc}")

        if certificate is None or private_key is None:
            raise web.HTTPBadRequest(reason="PKCS#12 must contain both a certificate and a private key")

        cert_data = certificate.public_bytes(Encoding.PEM)
        key_data  = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

    elif cert_data and key_data:
        # -- PEM path ----------------------------------------------------------
        try:
            x509.load_pem_x509_certificate(cert_data)
        except Exception as exc:
            raise web.HTTPBadRequest(reason=f"Invalid certificate: {exc}")

        if b"PRIVATE KEY" not in key_data:
            raise web.HTTPBadRequest(reason="Key does not look like a PEM private key")

    else:
        raise web.HTTPBadRequest(
            reason="Provide either a PKCS#12 file or both a certificate and key file"
        )

    TLS_DIR.mkdir(exist_ok=True)
    (TLS_DIR / "server.crt").write_bytes(cert_data)
    key_path = TLS_DIR / "server.key"
    key_path.write_bytes(key_data)
    key_path.chmod(0o600)

    ok, err = await _apply_nginx_config(https=True)
    if not ok:
        raise web.HTTPInternalServerError(reason=err)

    log.info("TLS enabled")
    return web.json_response({"ok": True, "cert": _get_cert_info()})


async def tls_delete_handler(request: web.Request) -> web.Response:
    for name in ("server.crt", "server.key"):
        p = TLS_DIR / name
        if p.exists():
            p.unlink()

    ok, err = await _apply_nginx_config(https=False)
    if not ok:
        raise web.HTTPInternalServerError(reason=err)

    log.info("TLS disabled")
    return web.json_response({"ok": True})


# -- Telnet framing (used by all ser2net connections) ---------------------------
#
# ser2net is configured with "accepter: telnet,...".  The telnet protocol lets
# us send IAC BREAK which ser2net translates to a hardware serial BREAK — no
# direct device access or elevated permissions required.

_IAC       = 0xFF
_IAC_BREAK = b"\xff\xf3"   # IAC BREAK  — triggers serial BREAK in ser2net
_IAC_IAC   = b"\xff\xff"   # escaped literal 0xFF in data stream
_WILL      = 0xFB
_WONT      = 0xFC
_DO        = 0xFD
_DONT      = 0xFE


def _telnet_escape(data: bytes) -> bytes:
    """Escape 0xFF (IAC) bytes before sending over a telnet connection."""
    return data.replace(b"\xff", _IAC_IAC)


def _telnet_strip(raw: bytes, state: list) -> tuple[bytes, bytes]:
    """Remove telnet IAC sequences from received bytes.

    `state` is a mutable two-element list [parse_state, pending_cmd] that
    must persist across calls for the same connection.

    Returns (clean_data, negotiation_responses_to_send).
    """
    out  = bytearray()
    resp = bytearray()
    s, pending = state[0], state[1]

    for b in raw:
        if s == 0:          # normal data
            if b == _IAC:
                s = 1
            else:
                out.append(b)
        elif s == 1:        # just saw IAC
            if b == _IAC:
                out.append(_IAC)   # 0xFF 0xFF → literal 0xFF
                s = 0
            elif b in (_WILL, _WONT, _DO, _DONT):
                pending = b
                s = 2
            else:
                s = 0              # ignore bare IAC commands (BREAK, etc.)
        elif s == 2:        # option byte after WILL/WONT/DO/DONT
            if pending == _WILL:
                resp += bytes([_IAC, _DONT, b])
            elif pending == _DO:
                resp += bytes([_IAC, _WONT, b])
            # WONT / DONT need no reply
            s = 0

    state[0] = s
    state[1] = pending
    return bytes(out), bytes(resp)


async def _send_serial_break(port_name: str) -> None:
    """Send IAC BREAK through ser2net's telnet port for /dev/{port_name}.

    ser2net converts IAC BREAK to a hardware serial BREAK (~2.5 s on Cisco).
    """
    if port_name not in PORT_CONFIG:
        log.warning("BREAK: unknown port %s", port_name)
        return
    tcp_port = PORT_CONFIG[port_name]["tcp_port"]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", tcp_port)
        writer.write(_IAC_BREAK)
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        log.info("BREAK sent on %s via telnet IAC", port_name)
    except Exception as exc:
        log.warning("BREAK failed on %s: %s", port_name, exc)


# -- SSH serial bridge ----------------------------------------------------------

SSH_DIR      = CONF_DIR / "ssh"
SSH_KEY_FILE = SSH_DIR / "host_key"

_ssh_server = None
_ssh_config: dict = {"enabled": False, "port": 2222, "serial_port": ""}
_active_ssh_writers: dict = {}   # process -> StreamWriter (TCP → ser2net)


async def _load_ssh_settings() -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT key, value FROM settings WHERE key LIKE 'ssh_%'"
        ) as cur:
            rows = await cur.fetchall()
    for key, value in rows:
        if key == "ssh_enabled":
            _ssh_config["enabled"] = value == "1"
        elif key == "ssh_port":
            _ssh_config["port"] = int(value)
        elif key == "ssh_serial_port":
            _ssh_config["serial_port"] = value


def _get_or_create_host_key():
    SSH_DIR.mkdir(exist_ok=True)
    if SSH_KEY_FILE.exists():
        return asyncssh.read_private_key(str(SSH_KEY_FILE))
    key = asyncssh.generate_private_key("ssh-ed25519")
    key.write_private_key(str(SSH_KEY_FILE))
    SSH_KEY_FILE.chmod(0o600)
    log.info("Generated SSH host key: %s", SSH_KEY_FILE)
    return key


def _host_key_fingerprint() -> str | None:
    if not SSH_KEY_FILE.exists():
        return None
    try:
        key = asyncssh.read_private_key(str(SSH_KEY_FILE))
        return key.convert_to_public().get_fingerprint()
    except Exception:
        return None


class _SerialSSHServer(asyncssh.SSHServer):
    def connection_made(self, conn):
        self._conn = conn

    def connection_lost(self, exc):
        pass

    def password_auth_supported(self):
        return True

    async def validate_password(self, username, password):
        return await _check_credentials(username, password)


async def _handle_ssh_client(process) -> None:
    port_name = _ssh_config.get("serial_port", "")
    if not port_name or port_name not in PORT_CONFIG:
        port_name = next(iter(PORT_CONFIG), None)

    if not port_name:
        process.stdout.write(b"\r\nNo serial ports available.\r\n")
        process.exit(1)
        return

    tcp_port = PORT_CONFIG[port_name]["tcp_port"]
    process.stdout.write(f"\r\nConnected to /dev/{port_name}\r\n".encode())

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", tcp_port)
    except (ConnectionRefusedError, OSError) as exc:
        process.stdout.write(f"\r\nError: {exc}\r\n".encode())
        process.exit(1)
        return

    log.info("SSH client bridged to %s", port_name)
    _active_ssh_writers[process] = writer

    telnet_state = [0, 0]   # [parse_state, pending_cmd] for _telnet_strip

    async def serial_to_ssh() -> None:
        try:
            while True:
                raw = await reader.read(4096)
                if not raw:
                    break
                data, resp = _telnet_strip(raw, telnet_state)
                if resp:
                    writer.write(resp)
                    await writer.drain()
                if data:
                    process.stdout.write(data)
        except Exception as exc:
            log.debug("serial_to_ssh ended: %s", exc)
        finally:
            process.exit(0)

    async def ssh_to_serial() -> None:
        # ~B at the start of a line → IAC BREAK (same convention as OpenSSH)
        # ~~ at the start of a line → literal ~
        at_line_start = True
        pending_tilde = False
        try:
            while True:
                data = await process.stdin.read(4096)
                if not data:
                    break
                out = bytearray()
                for byte in data:
                    b = bytes([byte])
                    if pending_tilde:
                        pending_tilde = False
                        if b == b"B":
                            writer.write(_IAC_BREAK)
                            await writer.drain()
                            process.stdout.write(b"\r\n[BREAK sent]\r\n")
                            at_line_start = True
                            continue
                        elif b == b"~":
                            out += b"~"    # ~~ → literal ~
                            at_line_start = False
                            continue
                        else:
                            out += b"~"   # plain ~ not an escape; forward it
                    if at_line_start and b == b"~":
                        pending_tilde = True
                        continue
                    at_line_start = b in (b"\r", b"\n")
                    out.append(byte)
                if out:
                    writer.write(_telnet_escape(bytes(out)))
                    await writer.drain()
        except Exception as exc:
            log.debug("ssh_to_serial ended: %s", exc)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    try:
        await asyncio.gather(serial_to_ssh(), ssh_to_serial())
    finally:
        _active_ssh_writers.pop(process, None)


async def _disconnect_all_ssh_sessions(reason: str = "Serial port changed") -> None:
    """Close every active SSH bridge so clients are cleanly disconnected."""
    for process, writer in list(_active_ssh_writers.items()):
        try:
            process.stdout.write(f"\r\n[{reason}. Disconnecting...]\r\n".encode())
        except Exception:
            pass
        try:
            writer.close()
        except Exception:
            pass
    if _active_ssh_writers:
        await asyncio.sleep(0.2)


async def _start_ssh_server() -> None:
    global _ssh_server
    if _ssh_server is not None:
        return
    host_key = _get_or_create_host_key()
    port = _ssh_config["port"]
    try:
        _ssh_server = await asyncssh.create_server(
            _SerialSSHServer,
            host="0.0.0.0",
            port=port,
            server_host_keys=[host_key],
            process_factory=_handle_ssh_client,
            encoding=None,          # binary — essential for XMODEM/ZMODEM
            reuse_address=True,
        )
        log.info("SSH server listening on port %d", port)
    except Exception as exc:
        log.error("Failed to start SSH server on port %d: %s", port, exc)
        _ssh_server = None


async def _stop_ssh_server() -> None:
    global _ssh_server
    if _ssh_server is None:
        return
    _ssh_server.close()
    try:
        await asyncio.wait_for(_ssh_server.wait_closed(), timeout=5.0)
    except asyncio.TimeoutError:
        log.warning("SSH server did not close cleanly within 5s — forcing shutdown")
    _ssh_server = None
    log.info("SSH server stopped")


async def ssh_settings_get_handler(request: web.Request) -> web.Response:
    return web.json_response({
        "enabled":      _ssh_config["enabled"],
        "port":         _ssh_config["port"],
        "serial_port":  _ssh_config["serial_port"],
        "fingerprint":  _host_key_fingerprint(),
    })


async def ssh_settings_post_handler(request: web.Request) -> web.Response:
    body = await request.json()
    enabled     = bool(body.get("enabled", False))
    port        = int(body.get("port", 2222))
    serial_port = str(body.get("serial_port", ""))

    if not (1024 <= port <= 65535):
        raise web.HTTPBadRequest(reason="Port must be between 1024 and 65535")

    _ssh_config["enabled"]     = enabled
    _ssh_config["port"]        = port
    _ssh_config["serial_port"] = serial_port

    async with aiosqlite.connect(DB_PATH) as db:
        for key, value in [
            ("ssh_enabled",     "1" if enabled else "0"),
            ("ssh_port",        str(port)),
            ("ssh_serial_port", serial_port),
        ]:
            await db.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value)
            )
        await db.commit()

    await _disconnect_all_ssh_sessions()
    await _stop_ssh_server()
    if enabled:
        await _start_ssh_server()

    log.info("SSH server %s on port %d → /dev/%s",
             "enabled" if enabled else "disabled", port, serial_port or "(auto)")
    return web.json_response({"ok": True, "fingerprint": _host_key_fingerprint()})


# -- USB / udev management ------------------------------------------------------
#
# Manages /etc/udev/rules.d/99-usb-serial.rules so that USB serial adapters
# always get the same /dev/ttyUSBPortN symlink regardless of insertion order.
# Rules are keyed on the device's USB serial number (ATTRS{serial}).
#
# Requires the following entries in /etc/sudoers.d/serial-server:
#   <user> ALL=(ALL) NOPASSWD: /usr/bin/tee /etc/udev/rules.d/99-usb-serial.rules
#   <user> ALL=(ALL) NOPASSWD: /usr/bin/udevadm control --reload-rules
#   <user> ALL=(ALL) NOPASSWD: /usr/bin/udevadm trigger --subsystem-match=tty

UDEV_RULES_FILE = pathlib.Path("/etc/udev/rules.d/99-usb-serial.rules")

_udev_auto_register: bool = False
_udev_id_method: str = 'usb_path'
_udev_monitor_task_handle: asyncio.Task | None = None
_udev_sse_queues: set[asyncio.Queue] = set()


async def _broadcast_udev_change() -> None:
    for q in list(_udev_sse_queues):
        try:
            q.put_nowait('udev_change')
        except asyncio.QueueFull:
            pass


def _parse_udev_rules() -> list[dict]:
    """Read the rules file and return every rule that assigns a ttyUSBPortN symlink.

    The serial field is empty for rules that match on something other than
    ATTRS{serial} (e.g. USB port path or vendor/product only).  Those rules
    are shown in the UI as read-only — they cannot be auto-detected by serial
    but they are still displayed so the user has a complete picture.
    """
    rules: list[dict] = []
    if not UDEV_RULES_FILE.exists():
        return rules
    comment = ""
    for line in UDEV_RULES_FILE.read_text().splitlines():
        line = line.strip()
        if not line:
            comment = ""
            continue
        if line.startswith('#'):
            comment = line[1:].strip()
            continue
        m_symlink = re.search(r'SYMLINK\+="(ttyUSBPort\d+)"', line)
        if m_symlink:
            m_serial = re.search(r'ATTRS\{serial\}=="([^"]+)"', line)
            if not m_serial:
                m_serial = re.search(r'ENV\{ID_SERIAL_SHORT\}=="([^"]+)"', line)
            m_usb_path = re.search(r'KERNELS=="([^"]+)"', line)
            rules.append({
                'serial':    m_serial.group(1) if m_serial else '',
                'usb_path':  m_usb_path.group(1) if m_usb_path else '',
                'port_name': m_symlink.group(1),
                'comment':   comment,
                'raw':       line,
            })
        comment = ""
    return rules


def _format_udev_rules(rules: list[dict]) -> str:
    """Generate the udev rules file content from a list of rule dicts.

    Rules with a serial number are regenerated in canonical form.
    Rules without a serial (manually written, matched by other attrs) are
    preserved verbatim via their 'raw' field so we don't lose information.
    """
    lines = [
        "# USB serial port mapping — managed by serial-server",
        "# Do not edit manually; use the web interface.",
        "",
    ]
    for r in sorted(rules, key=lambda x: x['port_name']):
        comment = r.get('comment', '').strip()
        if comment:
            lines.append(f"# {comment}")
        if r.get('usb_path'):
            lines.append(
                f'SUBSYSTEM=="tty", KERNELS=="{r["usb_path"]}", SYMLINK+="{r["port_name"]}"'
            )
        elif r.get('serial'):
            lines.append(
                f'SUBSYSTEM=="tty", ATTRS{{serial}}=="{r["serial"]}", SYMLINK+="{r["port_name"]}"'
            )
        else:
            # Preserve the original line for rules we don't fully manage
            lines.append(r.get('raw', f'# (unparseable rule for {r["port_name"]})'))
        lines.append("")
    return "\n".join(lines)


def _next_udev_port_number(rules: list[dict]) -> int:
    """Return the lowest available ttyUSBPortN number (starting from 1)."""
    used = set()
    for r in rules:
        m = re.match(r'ttyUSBPort(\d+)$', r['port_name'])
        if m:
            used.add(int(m.group(1)))
    n = 1
    while n in used:
        n += 1
    return n


def _usb_attrs_from_sysfs(tty_name: str) -> dict:
    """Read USB device attributes directly from sysfs — no pyudev required.

    Walks up the sysfs hierarchy from /sys/class/tty/<tty_name> until it finds
    a node that contains idVendor (the USB device node), then reads serial,
    manufacturer, product, and physical port path from the same directory.
    """
    attrs = {
        'serial': '', 'vendor': '', 'model': '',
        'vendor_id': '', 'model_id': '',
        'usb_path': '',   # sysfs USB device name, e.g. "1-1.2" — used for KERNELS matching
    }
    try:
        candidate = pathlib.Path(f'/sys/class/tty/{tty_name}').resolve()
        for _ in range(8):
            candidate = candidate.parent
            if str(candidate) in ('/', '/sys', '/sys/devices'):
                break
            if (candidate / 'idVendor').exists():
                for key, fname in [
                    ('vendor_id', 'idVendor'),
                    ('model_id',  'idProduct'),
                    ('serial',    'serial'),
                    ('vendor',    'manufacturer'),
                    ('model',     'product'),
                ]:
                    f = candidate / fname
                    if f.exists():
                        attrs[key] = f.read_text().strip()
                # candidate.name is the USB device node, e.g. "1-1.2" or "3-1.4.2"
                attrs['usb_path'] = candidate.name
                break
    except Exception:
        pass
    return attrs


def _list_usb_serial_devices() -> list[dict]:
    """Enumerate currently connected USB serial devices.

    Tries pyudev first; falls back to a pure sysfs walk if pyudev is not
    installed or fails.
    """
    try:
        import pyudev  # noqa: PLC0415
        context = pyudev.Context()
        result = []
        for dev in context.list_devices(subsystem='tty'):
            if dev.properties.get('ID_BUS') != 'usb':
                continue
            serial    = dev.properties.get('ID_SERIAL_SHORT', '').strip()
            vendor    = dev.properties.get('ID_VENDOR',  '').replace('_', ' ').strip()
            model     = dev.properties.get('ID_MODEL',   '').replace('_', ' ').strip()
            vendor_id = dev.properties.get('ID_VENDOR_ID', '')
            model_id  = dev.properties.get('ID_MODEL_ID',  '')
            devlinks  = dev.properties.get('DEVLINKS', '').split()
            symlinks  = sorted(
                pathlib.Path(lnk).name for lnk in devlinks if 'ttyUSBPort' in lnk
            )
            # Physical USB port path: walk up to the usb_device parent
            usb_path = ''
            try:
                usb_dev = dev.find_parent('usb', 'usb_device')
                if usb_dev:
                    usb_path = usb_dev.sys_name  # e.g. "1-1.2"
            except Exception:
                pass
            result.append({
                'sys_name':  dev.sys_name,
                'serial':    serial,
                'vendor':    vendor,
                'model':     model,
                'vendor_id': vendor_id,
                'model_id':  model_id,
                'symlinks':  symlinks,
                'usb_path':  usb_path,
            })
        return result
    except ImportError:
        log.info("pyudev not installed — falling back to sysfs device enumeration")
    except Exception as exc:
        log.warning("pyudev enumeration failed (%s) — falling back to sysfs", exc)

    # -- sysfs fallback ---------------------------------------------------------
    result = []
    try:
        for tty_path in sorted(pathlib.Path('/sys/class/tty').iterdir()):
            if not (tty_path / 'device').exists():
                continue
            attrs = _usb_attrs_from_sysfs(tty_path.name)
            if not attrs['vendor_id']:
                continue   # not a USB device
            if not pathlib.Path(f'/dev/{tty_path.name}').exists():
                continue
            result.append({
                'sys_name':  tty_path.name,
                'serial':    attrs['serial'],
                'vendor':    attrs['vendor'],
                'model':     attrs['model'],
                'vendor_id': attrs['vendor_id'],
                'model_id':  attrs['model_id'],
                'symlinks':  [],
                'usb_path':  attrs.get('usb_path', ''),
            })
    except Exception as exc:
        log.warning("sysfs device enumeration failed: %s", exc)
    return result


async def _write_and_apply_udev_rules(rules: list[dict]) -> tuple[bool, str]:
    """Write rules to the system udev file via sudo tee, then reload udev."""
    content = _format_udev_rules(rules)

    proc = await asyncio.create_subprocess_exec(
        "sudo", "tee", str(UDEV_RULES_FILE),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate(input=content.encode())
    if proc.returncode != 0:
        return False, f"tee failed: {stderr.decode().strip()}"

    for cmd in [
        ["sudo", "udevadm", "control", "--reload-rules"],
        ["sudo", "udevadm", "trigger", "--subsystem-match=tty"],
    ]:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            return False, f"'{' '.join(cmd)}' failed: {stderr.decode().strip()}"

    return True, ""


async def _discover_and_start_new_ports() -> None:
    """Check for new /dev/ttyUSBPort* symlinks that appeared after a rule change."""
    await asyncio.sleep(1.0)   # allow udev time to create symlinks
    new_config = _discover_ports()

    # If symlinks now exist, retire any raw ttyUSB*/ttyACM* fallback entries
    has_symlinks = any(re.match(r'ttyUSBPort\d+$', p) for p in new_config)
    if has_symlinks:
        raw = [p for p in list(PORT_CONFIG) if re.match(r'ttyUSB\d+$|ttyACM\d+$', p)]
        for port_name in raw:
            log.info("Retiring raw port %s — superseded by udev symlink", port_name)
            proc = _ser2net_procs.pop(port_name, None)
            if proc and proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=4.0)
                except asyncio.TimeoutError:
                    proc.kill()
            PORT_CONFIG.pop(port_name, None)

    for port_name, cfg in new_config.items():
        if port_name not in PORT_CONFIG:
            PORT_CONFIG[port_name] = cfg
            async with aiosqlite.connect(DB_PATH) as db:
                async with db.execute(
                    "SELECT value FROM settings WHERE key = ?",
                    (f"baud_{port_name}",),
                ) as cur:
                    row = await cur.fetchone()
            if row:
                PORT_CONFIG[port_name]["baud"] = int(row[0])
            log.info("Hot-plug: starting ser2net for new port %s", port_name)
            await _restart_port(port_name)


async def _handle_udev_add(device) -> None:
    """Handle a udev 'add' event for a tty device."""
    if device.properties.get('ID_BUS') != 'usb':
        return

    serial   = device.properties.get('ID_SERIAL_SHORT', '').strip()
    usb_path = ''
    try:
        usb_dev = device.find_parent('usb', 'usb_device')
        if usb_dev:
            usb_path = usb_dev.sys_name
    except Exception:
        pass

    rules = _parse_udev_rules()

    # Check if this device already has a rule (by usb_path or serial)
    already_mapped = (
        (usb_path and any(r.get('usb_path') == usb_path for r in rules)) or
        (serial   and any(r.get('serial')   == serial   for r in rules))
    )
    if already_mapped:
        log.info("USB-serial device usb_path=%s serial=%s already has a rule — checking for new ports", usb_path, serial)
        await _discover_and_start_new_ports()
        await _broadcast_udev_change()
        return

    if not _udev_auto_register:
        log.info("New USB-serial device usb_path=%s serial=%s — no rule (auto-register disabled)", usb_path, serial)
        return

    if not usb_path and not serial:
        log.info("New USB-serial device has neither a USB path nor a serial — skipping auto-register")
        return

    port_num  = _next_udev_port_number(rules)
    port_name = f"ttyUSBPort{port_num}"
    vendor    = device.properties.get('ID_VENDOR',  '').replace('_', ' ').strip()
    model     = device.properties.get('ID_MODEL',   '').replace('_', ' ').strip()
    comment   = port_name
    if vendor or model:
        comment += f" | {(vendor + ' ' + model).strip()}"

    # Use configured id_method; fall back to whichever identifier is available
    if _udev_id_method == 'serial' and serial:
        rule_usb_path, rule_serial = '', serial
    elif _udev_id_method == 'serial' and usb_path:
        rule_usb_path, rule_serial = usb_path, ''
    elif usb_path:
        rule_usb_path, rule_serial = usb_path, ''
    else:
        rule_usb_path, rule_serial = '', serial
    rules.append({
        'usb_path':  rule_usb_path,
        'serial':    rule_serial,
        'port_name': port_name,
        'comment':   comment,
    })
    ok, err = await _write_and_apply_udev_rules(rules)
    if ok:
        log.info("Auto-registered USB-serial device usb_path=%s serial=%s → %s", usb_path, serial, port_name)
        await _discover_and_start_new_ports()
        await _broadcast_udev_change()
    else:
        log.error("Failed to auto-register udev rule: %s", err)


async def _udev_monitor_task() -> None:
    """Asyncio task that watches for USB serial device insertions via pyudev."""
    try:
        import pyudev  # noqa: PLC0415
    except ImportError:
        log.info("pyudev not installed — USB hot-plug monitoring unavailable")
        return

    try:
        context = pyudev.Context()
        monitor = pyudev.Monitor.from_netlink(context)
        monitor.filter_by('tty')
        monitor.start()
    except Exception as exc:
        log.warning("Could not start udev monitor: %s", exc)
        return

    loop  = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()

    def _readable() -> None:
        device = monitor.poll(timeout=0)
        if device is not None:
            queue.put_nowait(device)

    loop.add_reader(monitor.fileno(), _readable)
    log.info("USB hot-plug monitor started")

    try:
        while True:
            device = await queue.get()
            if device.action in ('add', 'bind'):
                asyncio.ensure_future(_handle_udev_add(device))
    except asyncio.CancelledError:
        pass
    finally:
        try:
            loop.remove_reader(monitor.fileno())
        except Exception:
            pass
        log.info("USB hot-plug monitor stopped")


# -- Security API handlers (mTLS, IP whitelist, client certs) ------------------

async def security_get_handler(request: web.Request) -> web.Response:
    """Return current security settings and list of issued client certs."""
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT id, name, fingerprint, issued_at, revoked FROM client_certs ORDER BY issued_at"
        ) as cur:
            rows = await cur.fetchall()

    certs = [
        {"id": r[0], "name": r[1], "fingerprint": r[2], "issued_at": r[3], "revoked": bool(r[4])}
        for r in rows
    ]
    ca_ready = (CA_DIR / "ca.crt").exists()

    return web.json_response({
        "mtls_enabled":         _mtls_enabled,
        "ip_whitelist_enabled": _ip_whitelist_enabled,
        "ip_whitelist":         _ip_whitelist,
        "break_glass_ips":      _break_glass_ips,
        "ca_ready":             ca_ready,
        "system_id":            _system_id,
        "certs":                certs,
    })


async def security_post_handler(request: web.Request) -> web.Response:
    """Update security settings and regenerate nginx config."""
    global _mtls_enabled, _ip_whitelist_enabled, _ip_whitelist, _break_glass_ips

    body = await request.json()

    _mtls_enabled         = bool(body.get("mtls_enabled",         _mtls_enabled))
    _ip_whitelist_enabled = bool(body.get("ip_whitelist_enabled", _ip_whitelist_enabled))
    _ip_whitelist         = list(body.get("ip_whitelist",         _ip_whitelist))
    _break_glass_ips      = list(body.get("break_glass_ips",      _break_glass_ips))

    # If mTLS is being enabled, ensure the CA exists
    if _mtls_enabled:
        await asyncio.get_running_loop().run_in_executor(None, _ensure_ca)
        await asyncio.get_running_loop().run_in_executor(None, _regenerate_crl)

    async with aiosqlite.connect(DB_PATH) as db:
        for key, value in [
            ("mtls_enabled",         "1" if _mtls_enabled else "0"),
            ("ip_whitelist_enabled", "1" if _ip_whitelist_enabled else "0"),
            ("ip_whitelist",         json.dumps(_ip_whitelist)),
            ("break_glass_ips",      json.dumps(_break_glass_ips)),
        ]:
            await db.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value)
            )
        await db.commit()

    # Regenerate nginx config if HTTPS is active
    https_active = (TLS_DIR / "server.crt").exists() and (TLS_DIR / "server.key").exists()
    if https_active:
        ok, err = await _apply_nginx_config(https=True)
        if not ok:
            log.error("nginx reload failed after security change: %s", err)
            raise web.HTTPInternalServerError(
                reason=err.replace('\r', ' ').replace('\n', ' ')
            )

    log.info(
        "Security settings updated: mtls=%s ip_whitelist=%s",
        _mtls_enabled, _ip_whitelist_enabled,
    )
    return web.json_response({"ok": True})


async def security_cert_generate_handler(request: web.Request) -> web.Response:
    """Generate a new client certificate.

    Returns JSON with base64-encoded p12 and the import password so the
    browser can trigger the download and show the password to the user.
    """
    import base64 as _base64
    body = await request.json()
    name = str(body.get("name", "")).strip()
    if not name:
        raise web.HTTPBadRequest(reason="name is required")

    cert_id, p12_bytes, p12_password = await _generate_client_cert(name)

    return web.json_response({
        "p12_b64":  _base64.b64encode(p12_bytes).decode(),
        "password": p12_password,
        "filename": f"{name}.p12",
    })


async def security_cert_delete_handler(request: web.Request) -> web.Response:
    """Revoke a client certificate."""
    cert_id = request.match_info["cert_id"]
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT id FROM client_certs WHERE id = ? AND revoked = 0", (cert_id,)
        ) as cur:
            row = await cur.fetchone()
    if not row:
        raise web.HTTPNotFound(reason="Certificate not found or already revoked")

    await _revoke_client_cert(cert_id)

    # Reload nginx to pick up updated CRL
    https_active = (TLS_DIR / "server.crt").exists() and (TLS_DIR / "server.key").exists()
    if https_active:
        await _apply_nginx_config(https=True)

    return web.json_response({"ok": True})


async def security_ca_download_handler(request: web.Request) -> web.Response:
    """Download the CA certificate (for import into browser/OS trust store)."""
    await asyncio.get_running_loop().run_in_executor(None, _ensure_ca)
    ca_crt = CA_DIR / "ca.crt"
    return web.Response(
        body=ca_crt.read_bytes(),
        content_type="application/x-pem-file",
        headers={"Content-Disposition": 'attachment; filename="serial-server-ca.crt"'},
    )


# -- udev API handlers ----------------------------------------------------------

async def udev_events_handler(request: web.Request) -> web.StreamResponse:
    """SSE stream that pushes a 'udev_change' event when device mapping changes."""
    resp = web.StreamResponse(headers={
        'Content-Type':  'text/event-stream',
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no',
    })
    await resp.prepare(request)
    q: asyncio.Queue = asyncio.Queue(maxsize=8)
    _udev_sse_queues.add(q)
    try:
        while True:
            try:
                event = await asyncio.wait_for(q.get(), timeout=25)
                await resp.write(f"event: {event}\ndata: \n\n".encode())
            except asyncio.TimeoutError:
                await resp.write(b": keepalive\n\n")
    except (asyncio.CancelledError, ConnectionResetError):
        pass
    finally:
        _udev_sse_queues.discard(q)
    return resp


async def udev_get_handler(request: web.Request) -> web.Response:
    rules   = _parse_udev_rules()
    devices = _list_usb_serial_devices()

    dev_by_serial:   dict[str, dict] = {d['serial']:   d for d in devices if d['serial']}
    dev_by_usb_path: dict[str, dict] = {d['usb_path']: d for d in devices if d.get('usb_path')}
    dev_by_sysname:  dict[str, dict] = {d['sys_name']: d for d in devices}

    enriched: list[dict] = []
    matched_sys_names: set[str] = set()
    registered_serials: set[str] = set()
    registered_usb_paths: set[str] = set()

    for r in rules:
        dev = None
        connected = False

        if r.get('usb_path'):
            dev = dev_by_usb_path.get(r['usb_path'])
            connected = dev is not None
        elif r['serial']:
            dev = dev_by_serial.get(r['serial'])
            connected = dev is not None
        else:
            # For manually-written rules (no ATTRS{serial}), check whether
            # the /dev/ttyUSBPortN symlink actually exists right now.
            # Resolve it to the underlying kernel device (e.g. ttyUSB0) and
            # look that up in our device list; fall back to a direct sysfs
            # read if the device list is empty (pyudev not installed).
            sym_path = pathlib.Path(f'/dev/{r["port_name"]}')
            connected = sym_path.is_symlink()
            if connected:
                try:
                    target_name = sym_path.resolve().name
                    dev = dev_by_sysname.get(target_name)
                    if dev is None:
                        # pyudev list was empty or missed this device —
                        # read attrs straight from sysfs
                        attrs = _usb_attrs_from_sysfs(target_name)
                        if attrs.get('vendor_id') or attrs.get('serial'):
                            dev = {
                                'sys_name':  target_name,
                                'serial':    attrs['serial'],
                                'vendor':    attrs['vendor'],
                                'model':     attrs['model'],
                                'vendor_id': attrs['vendor_id'],
                                'model_id':  attrs['model_id'],
                                'symlinks':  [],
                                'usb_path':  attrs.get('usb_path', ''),
                            }
                except Exception:
                    pass

        if dev:
            matched_sys_names.add(dev['sys_name'])

        live_serial   = dev['serial']               if dev else ''
        live_usb_path = dev.get('usb_path', '')     if dev else ''

        enriched.append({
            'port_name':      r['port_name'],
            'serial':         r['serial'],
            'usb_path':       r.get('usb_path', ''),
            'live_serial':    live_serial,
            'live_usb_path':  live_usb_path,
            'serial_managed': bool(r['serial']),
            'usb_path_managed': bool(r.get('usb_path')),
            'vendor':         dev['vendor']    if dev else '',
            'model':          dev['model']     if dev else '',
            'vendor_id':      dev['vendor_id'] if dev else '',
            'model_id':       dev['model_id']  if dev else '',
            'connected':      connected,
            'sys_name':       dev['sys_name']  if dev else None,
        })
        if r['serial']:
            registered_serials.add(r['serial'])
        if r.get('usb_path'):
            registered_usb_paths.add(r['usb_path'])

    unregistered = [
        d for d in devices
        if d['serial'] not in registered_serials
        and d.get('usb_path', '') not in registered_usb_paths
        and d['sys_name'] not in matched_sys_names
    ]

    return web.json_response({
        'rules':         enriched,
        'unregistered':  unregistered,
        'auto_register': _udev_auto_register,
        'id_method':     _udev_id_method,
    })


async def udev_post_handler(request: web.Request) -> web.Response:
    body      = await request.json()
    serial    = str(body.get('serial',   '')).strip()
    usb_path  = str(body.get('usb_path', '')).strip()
    port_name = str(body.get('port_name', '')).strip()

    if not serial and not usb_path:
        raise web.HTTPBadRequest(reason="serial or usb_path is required")

    rules = _parse_udev_rules()

    if not port_name:
        n         = _next_udev_port_number(rules)
        port_name = f"ttyUSBPort{n}"
    elif not re.match(r'^ttyUSBPort\d+$', port_name):
        raise web.HTTPBadRequest(reason="port_name must be ttyUSBPortN (e.g. ttyUSBPort3)")

    # Prevent two different devices from claiming the same symlink
    for r in rules:
        if r['port_name'] == port_name:
            if usb_path and r.get('usb_path') and r['usb_path'] != usb_path:
                raise web.HTTPConflict(
                    reason=f"{port_name} is already assigned to USB port {r['usb_path']}"
                )
            if serial and r.get('serial') and r['serial'] != serial:
                raise web.HTTPConflict(
                    reason=f"{port_name} is already assigned to serial {r['serial']}"
                )

    devices = _list_usb_serial_devices()
    if usb_path:
        dev = next((d for d in devices if d.get('usb_path') == usb_path), None)
    else:
        dev = next((d for d in devices if d['serial'] == serial), None)

    comment = port_name
    if dev and (dev['vendor'] or dev['model']):
        comment += f" | {(dev['vendor'] + ' ' + dev['model']).strip()}"

    updated = False
    for r in rules:
        match = (usb_path and r.get('usb_path') == usb_path) or \
                (serial  and r.get('serial')   == serial)
        if match:
            r['port_name'] = port_name
            r['comment']   = comment
            if usb_path:
                r['usb_path'] = usb_path
                r['serial']   = ''
            else:
                r['serial']   = serial
                r['usb_path'] = ''
            updated = True
            break
    if not updated:
        rules.append({
            'usb_path': usb_path,
            'serial':   serial,
            'port_name': port_name,
            'comment':   comment,
        })

    ok, err = await _write_and_apply_udev_rules(rules)
    if not ok:
        log.error("udev rule write failed: %s", err)
        raise web.HTTPInternalServerError(reason=err.replace('\r', ' ').replace('\n', ' '))

    log.info("udev rule set: usb_path=%s serial=%s → %s", usb_path, serial, port_name)
    await _discover_and_start_new_ports()
    return web.json_response({'ok': True, 'usb_path': usb_path, 'serial': serial, 'port_name': port_name})


async def udev_delete_handler(request: web.Request) -> web.Response:
    port_name = request.match_info['port_name']
    rules     = _parse_udev_rules()
    new_rules = [r for r in rules if r['port_name'] != port_name]
    if len(new_rules) == len(rules):
        raise web.HTTPNotFound(reason=f"No rule found for {port_name}")

    ok, err = await _write_and_apply_udev_rules(new_rules)
    if not ok:
        log.error("udev rule delete failed: %s", err)
        raise web.HTTPInternalServerError(reason=err.replace('\r', ' ').replace('\n', ' '))

    # Stop ser2net process and clean up config
    proc = _ser2net_procs.pop(port_name, None)
    if proc and proc.returncode is None:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=4.0)
        except asyncio.TimeoutError:
            proc.kill()
    PORT_CONFIG.pop(port_name, None)
    conf = _conf_path(port_name)
    if conf.exists():
        conf.unlink()
        log.info("Deleted ser2net config %s", conf)

    log.info("udev rule removed for %s", port_name)
    return web.json_response({'ok': True, 'port_name': port_name})


async def udev_auto_register_handler(request: web.Request) -> web.Response:
    global _udev_auto_register
    body    = await request.json()
    enabled = bool(body.get('enabled', False))
    _udev_auto_register = enabled
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES ('udev_auto_register', ?)",
            ("1" if enabled else "0",),
        )
        await db.commit()
    log.info("udev auto-register %s", "enabled" if enabled else "disabled")
    return web.json_response({'ok': True, 'enabled': enabled})


async def udev_id_method_handler(request: web.Request) -> web.Response:
    global _udev_id_method
    body   = await request.json()
    method = str(body.get('method', 'usb_path'))
    if method not in ('usb_path', 'serial'):
        return web.Response(status=400, text="method must be 'usb_path' or 'serial'")
    _udev_id_method = method
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES ('udev_id_method', ?)",
            (method,),
        )
        await db.commit()
    log.info("udev id_method set to %s", method)
    return web.json_response({'ok': True, 'method': method})


# -- Port discovery -------------------------------------------------------------

def _discover_ports() -> dict[str, dict]:
    """Scan /dev for stable ttyUSBPort* symlinks (or fall back to ttyUSB*/ttyACM*)."""
    symlinks = sorted(glob.glob("/dev/ttyUSBPort*"),
                      key=lambda p: int(m.group(1)) if (m := re.search(r'(\d+)$', p)) else 0)
    if symlinks:
        devices = symlinks
    else:
        patterns = ["/dev/ttyUSB*", "/dev/ttyACM*"]
        devices = sorted(p for pat in patterns for p in glob.glob(pat))
    config = {}
    for i, dev in enumerate(devices):
        name = pathlib.Path(dev).name
        m = re.match(r'ttyUSBPort(\d+)$', name)
        tcp_port = TCP_PORT_BASE + (int(m.group(1)) - 1) if m else TCP_PORT_BASE + i
        config[name] = {"baud": 9600, "tcp_port": tcp_port}
    log.info("Discovered serial ports: %s", list(config.keys()) or "none")
    return config


def _load_labels() -> None:
    if LABELS_FILE.exists():
        LABELS.update(json.loads(LABELS_FILE.read_text()))


def _save_labels() -> None:
    LABELS_FILE.write_text(json.dumps(LABELS, indent=2))


# One ser2net process per port — keyed by port name (e.g. "ttyUSB0")
_ser2net_procs: dict[str, asyncio.subprocess.Process] = {}


# -- ser2net lifecycle ----------------------------------------------------------

def _conf_path(port_name: str) -> pathlib.Path:
    return CONF_DIR / f"ser2net-{port_name}.yaml"


def _write_port_config(port_name: str) -> None:
    cfg = PORT_CONFIG[port_name]
    lines = [
        "%YAML 1.1",
        "---",
        f"connection: &con-{port_name}",
        f"  accepter: telnet,tcp,127.0.0.1,{cfg['tcp_port']}",
        f"  connector: serialdev,/dev/{port_name},{cfg['baud']}n81,local",
        f"  options:",
        f"    kickolduser: true",
        f'    banner: ""',
        f"    telnet-brk-on-sync: false",
        "",
    ]
    path = _conf_path(port_name)
    path.write_text("\n".join(lines))
    log.info("Wrote %s", path)


async def _restart_port(port_name: str) -> None:
    proc = _ser2net_procs.get(port_name)
    if proc and proc.returncode is None:
        log.info("Stopping ser2net for %s (pid %d)…", port_name, proc.pid)
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=4.0)
        except asyncio.TimeoutError:
            proc.kill()

    _write_port_config(port_name)
    new_proc = await asyncio.create_subprocess_exec(
        "ser2net", "-n", "-c", str(_conf_path(port_name)),
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )
    _ser2net_procs[port_name] = new_proc
    log.info("ser2net started for %s (pid %d)", port_name, new_proc.pid)

    async def _drain_stderr() -> None:
        assert new_proc.stderr
        async for line in new_proc.stderr:
            log.warning("ser2net[%s]: %s", port_name, line.decode().rstrip())
    asyncio.ensure_future(_drain_stderr())


# -- WebSocket handler ----------------------------------------------------------

async def ws_handler(request: web.Request) -> web.WebSocketResponse:
    port_name = request.match_info["port"]
    if port_name not in PORT_CONFIG:
        raise web.HTTPNotFound(reason=f"Unknown port: {port_name}")

    tcp_port = PORT_CONFIG[port_name]["tcp_port"]
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    log.info("WS connected for %s", port_name)

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", tcp_port)
        log.info("TCP bridge open for %s (port %d)", port_name, tcp_port)
    except (ConnectionRefusedError, OSError) as exc:
        await ws.send_str(f"\r\n\033[31m[error] Cannot connect to {port_name}: {exc}\033[0m\r\n")
        await ws.close()
        return ws

    telnet_state = [0, 0]   # [parse_state, pending_cmd] for _telnet_strip

    async def tcp_to_ws() -> None:
        try:
            while True:
                raw = await reader.read(CHUNK)
                if not raw:
                    break
                data, resp = _telnet_strip(raw, telnet_state)
                if resp:
                    writer.write(resp)
                    await writer.drain()
                if data and not ws.closed:
                    await ws.send_bytes(data)
        except Exception as exc:
            log.debug("tcp_to_ws ended: %s", exc)
        finally:
            if not ws.closed:
                await ws.close()

    async def ws_to_tcp() -> None:
        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        obj = json.loads(msg.data)
                        if obj.get("type") == "break":
                            writer.write(_IAC_BREAK)
                            await writer.drain()
                            log.info("BREAK sent on %s via WebSocket", port_name)
                            await ws.send_bytes(b"\r\n\x1b[33m[BREAK sent]\x1b[0m\r\n")
                            continue
                    except (json.JSONDecodeError, AttributeError):
                        pass
                    writer.write(_telnet_escape(msg.data.encode()))
                    await writer.drain()
                elif msg.type == WSMsgType.BINARY:
                    writer.write(_telnet_escape(msg.data))
                    await writer.drain()
                elif msg.type in (WSMsgType.ERROR, WSMsgType.CLOSE):
                    break
        except Exception as exc:
            log.debug("ws_to_tcp ended: %s", exc)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    await asyncio.gather(tcp_to_ws(), ws_to_tcp())
    log.info("WS closed for %s", port_name)
    return ws


# -- REST handlers --------------------------------------------------------------

async def ports_handler(request: web.Request) -> web.Response:
    return web.json_response(list(PORT_CONFIG.keys()))


async def get_config_handler(request: web.Request) -> web.Response:
    return web.json_response({
        name: {"baud": cfg["baud"], "tcp_port": cfg["tcp_port"]}
        for name, cfg in PORT_CONFIG.items()
    })


async def post_config_handler(request: web.Request) -> web.Response:
    port_name = request.match_info["port"]
    if port_name not in PORT_CONFIG:
        raise web.HTTPNotFound(reason=f"Unknown port: {port_name}")

    body = await request.json()
    baud = int(body.get("baud", PORT_CONFIG[port_name]["baud"]))
    if baud not in VALID_BAUDS:
        raise web.HTTPBadRequest(reason=f"Invalid baud rate {baud}. Valid: {VALID_BAUDS}")

    PORT_CONFIG[port_name]["baud"] = baud
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            (f"baud_{port_name}", str(baud)),
        )
        await db.commit()
    log.info("Baud rate for %s changed to %d — restarting its ser2net", port_name, baud)
    await _restart_port(port_name)
    return web.json_response({"ok": True, "port": port_name, "baud": baud})


async def baud_rates_handler(request: web.Request) -> web.Response:
    return web.json_response(VALID_BAUDS)


async def break_handler(request: web.Request) -> web.Response:
    port_name = request.match_info["port"]
    if port_name not in PORT_CONFIG:
        raise web.HTTPNotFound(reason=f"Unknown port: {port_name}")
    asyncio.ensure_future(_send_serial_break(port_name))
    return web.json_response({"ok": True, "port": port_name})


async def get_labels_handler(request: web.Request) -> web.Response:
    return web.json_response(LABELS)


async def post_label_handler(request: web.Request) -> web.Response:
    port_name = request.match_info["port"]
    if port_name not in PORT_CONFIG:
        raise web.HTTPNotFound(reason=f"Unknown port: {port_name}")
    body = await request.json()
    label = str(body.get("label", "")).strip()
    if label:
        LABELS[port_name] = label
    else:
        LABELS.pop(port_name, None)
    _save_labels()
    return web.json_response({"ok": True, "port": port_name, "label": label})


async def index_handler(request: web.Request) -> web.FileResponse:
    return web.FileResponse(STATIC_DIR / "index.html")


# -- App lifecycle --------------------------------------------------------------

async def _load_baud_rates() -> None:
    """Overlay saved baud rates from DB onto PORT_CONFIG after port discovery."""
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT key, value FROM settings WHERE key LIKE 'baud_%'"
        ) as cur:
            rows = await cur.fetchall()
    for key, value in rows:
        port_name = key[len("baud_"):]
        if port_name in PORT_CONFIG:
            PORT_CONFIG[port_name]["baud"] = int(value)
            log.info("Restored baud rate for %s: %s", port_name, value)


async def on_startup(app: web.Application) -> None:
    global _udev_monitor_task_handle
    await init_db()
    await _load_settings()
    await _load_ssh_settings()
    if _ssh_config["enabled"]:
        await _start_ssh_server()
    _load_labels()
    PORT_CONFIG.update(_discover_ports())
    await _load_baud_rates()
    for port_name in PORT_CONFIG:
        await _restart_port(port_name)
    _udev_monitor_task_handle = asyncio.ensure_future(_udev_monitor_task())
    # Regenerate nginx config on every startup so it always reflects DB settings
    https_active = (TLS_DIR / "server.crt").exists() and (TLS_DIR / "server.key").exists()
    if https_active:
        ok, err = await _apply_nginx_config(https=True)
        if not ok:
            log.warning("nginx config sync at startup failed: %s", err)


async def on_cleanup(app: web.Application) -> None:
    global _udev_monitor_task_handle
    if _udev_monitor_task_handle is not None:
        _udev_monitor_task_handle.cancel()
        try:
            await asyncio.wait_for(_udev_monitor_task_handle, timeout=2.0)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass
        _udev_monitor_task_handle = None
    await _stop_ssh_server()
    for port_name, proc in _ser2net_procs.items():
        if proc.returncode is None:
            log.info("Shutting down ser2net for %s…", port_name)
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=4.0)
            except asyncio.TimeoutError:
                proc.kill()


def build_app() -> web.Application:
    secret_key = _get_or_create_session_key()
    app = web.Application()
    session_setup(app, EncryptedCookieStorage(secret_key))  # must be before auth_middleware
    app.middlewares.append(auth_middleware)

    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)

    # Auth
    app.router.add_get("/login",                    login_get_handler)
    app.router.add_post("/login",                   login_post_handler)
    app.router.add_get("/logout",                   logout_handler)

    # Pages
    app.router.add_get("/",                         index_handler)

    # User management
    app.router.add_get("/api/me",                       me_handler)
    app.router.add_get("/api/users",                    users_list_handler)
    app.router.add_post("/api/users",                   users_add_handler)
    app.router.add_delete("/api/users/{username}",      users_delete_handler)
    app.router.add_get("/api/logs",                     logs_handler)
    app.router.add_get("/api/ping",                     ping_handler)
    app.router.add_get("/api/version",                  version_handler)
    app.router.add_get("/api/system_info",              system_info_handler)
    app.router.add_get("/api/settings",                 get_settings_handler)
    app.router.add_post("/api/settings",                post_settings_handler)
    app.router.add_get("/api/ssh",                      ssh_settings_get_handler)
    app.router.add_post("/api/ssh",                     ssh_settings_post_handler)

    # TLS management
    app.router.add_get("/api/tls",                      tls_get_handler)
    app.router.add_post("/api/tls",                     tls_post_handler)
    app.router.add_delete("/api/tls",                   tls_delete_handler)

    # Security: mTLS, IP whitelist, client certificates
    app.router.add_get("/api/security",                          security_get_handler)
    app.router.add_post("/api/security",                         security_post_handler)
    app.router.add_post("/api/security/certs",                   security_cert_generate_handler)
    app.router.add_delete("/api/security/certs/{cert_id}",       security_cert_delete_handler)
    app.router.add_get("/api/security/ca",                       security_ca_download_handler)

    # USB / udev device mapping
    app.router.add_get("/api/udev",                          udev_get_handler)
    app.router.add_get("/api/udev/events",                   udev_events_handler)
    app.router.add_post("/api/udev",                         udev_post_handler)
    app.router.add_post("/api/udev/auto_register",           udev_auto_register_handler)
    app.router.add_post("/api/udev/id_method",               udev_id_method_handler)
    app.router.add_delete("/api/udev/{port_name}",           udev_delete_handler)

    # Serial port API
    app.router.add_get("/ports",                    ports_handler)
    app.router.add_get("/api/config",               get_config_handler)
    app.router.add_post("/api/config/{port}",       post_config_handler)
    app.router.add_get("/api/baud_rates",           baud_rates_handler)
    app.router.add_post("/api/break/{port}",        break_handler)
    app.router.add_get("/api/labels",               get_labels_handler)
    app.router.add_post("/api/labels/{port}",       post_label_handler)

    # WebSocket
    app.router.add_get("/ws/{port}",                ws_handler)

    app.router.add_static("/static",                STATIC_DIR)
    return app


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8080"))
    log.info("Starting serial web server on http://%s:%d", host, port)
    web.run_app(build_app(), host=host, port=port, access_log=log, shutdown_timeout=8)
