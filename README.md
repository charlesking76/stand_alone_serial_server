# Serial Server

A self-contained web-based serial console server. Connects to USB serial devices and exposes them as browser terminals over HTTPS, with optional SSH bridge access.

Designed for **Debian-based Linux** (Debian 11+, Ubuntu 22.04+, Raspberry Pi OS).

---

## Features

- Browser terminal (xterm.js) per serial port over HTTPS
- Multi-user authentication with session management
- Optional SSH bridge to serial console (port 2222)
- Automatic TLS certificate generation (self-signed, replaceable)
- Persistent serial device naming via udev rules
- IP whitelisting and mTLS client certificate support
- Hot-plug detection — new devices appear automatically
- Air-gapped friendly — xterm.js bundled locally, no CDN required

---

## Requirements

- Debian-based Linux (Debian 11+, Ubuntu 22.04+, Raspberry Pi OS)
- Python 3.10+
- Internet access during installation (apt packages and pip)
- One or more USB serial devices

---

## Installation

```bash
git clone git@github.com:charlesking76/stand_alone_serial_server.git
cd stand_alone_serial_server
sudo bash install.sh
```

The installer will:
- Install system dependencies (nginx, ser2net, python3, openssl, sqlite3)
- Create a dedicated `serial-server` system user
- Install the application to `/opt/serial-server`
- Generate a self-signed TLS certificate
- Configure and start nginx and the systemd service

**Default login: `admin` / `admin` — change this after first login via Settings.**

---

## Accessing the UI

| Interface | Address |
|-----------|---------|
| Web UI | `https://<device-ip>` |
| SSH bridge (if enabled) | `ssh <user>@<device-ip> -p 2222` |

The TLS certificate is self-signed — your browser will show a security warning. Accept the exception, or upload a real certificate in Settings.

---

## Service Management

```bash
sudo systemctl start serial-server
sudo systemctl stop serial-server
sudo systemctl restart serial-server
journalctl -u serial-server -f
```

---

## Ports

| Port | Purpose |
|------|---------|
| 80 | HTTP — redirects to HTTPS |
| 443 | HTTPS web UI (nginx reverse proxy) |
| 8080 | Python backend (localhost only) |
| 7000+ | ser2net telnet bridges (one per serial port) |
| 2222 | SSH serial bridge (optional, enable in Settings) |
