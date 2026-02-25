# Install Guide: Ubuntu 24.04 Minimal → FreeRADIUS + Web Dashboard

This guide takes a fresh Ubuntu 24.04 minimal server to a working FreeRADIUS install plus this web dashboard.

## 0) Assumptions

- OS: Ubuntu Server 24.04 (minimal)
- You have shell access as a sudo user
- Repository/files are available on the server (copy this `freeradius-webgui` folder there)
- This dashboard is for internal admin use only

---

## 1) Base OS setup

```bash
sudo apt update && sudo apt -y upgrade
sudo apt -y install openssh-server curl wget git vim ufw ca-certificates gnupg lsb-release
sudo timedatectl set-timezone Europe/London
sudo hostnamectl set-hostname radius01
```

Optional but recommended reboot after patching:

```bash
sudo reboot
```

---

## 2) Basic firewall and SSH hardening

Allow only what you need (adjust source ranges):

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH
sudo ufw allow 1812/udp
sudo ufw allow 1813/udp
sudo ufw allow 443/tcp
sudo ufw enable
sudo ufw status verbose
```

If this is an internal-only admin UI, restrict 443 to admin subnets:

```bash
sudo ufw delete allow 443/tcp
sudo ufw allow from 10.0.0.0/8 to any port 443 proto tcp
```

---

## 3) Install FreeRADIUS

```bash
sudo apt -y install freeradius freeradius-utils
sudo systemctl enable freeradius
sudo systemctl start freeradius
sudo systemctl status freeradius --no-pager
```

Validate config parser:

```bash
sudo freeradius -XC
```

FreeRADIUS paths on Ubuntu are typically under `/etc/freeradius/3.0/`.

---

## 4) (Optional) Quick smoke test FreeRADIUS locally

Create a temporary local test client/user only if needed:

```bash
sudo cp /etc/freeradius/3.0/clients.conf /etc/freeradius/3.0/clients.conf.bak.$(date +%Y%m%d%H%M%S)
sudo cp /etc/freeradius/3.0/users /etc/freeradius/3.0/users.bak.$(date +%Y%m%d%H%M%S)
```

Then test with `radtest` once configured:

```bash
radtest testuser testpass 127.0.0.1 0 testing123
```

---

## 5) Install Python runtime for dashboard

```bash
sudo apt -y install python3 python3-venv python3-pip
```

Create app directory:

```bash
sudo mkdir -p /opt/freeradius-webgui
sudo chown $USER:$USER /opt/freeradius-webgui
```

Copy project files to `/opt/freeradius-webgui` (scp/git/copy as appropriate).

Create virtualenv and install dependencies:

```bash
cd /opt/freeradius-webgui
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 6) Configure the dashboard

Create env file:

```bash
cp .env.example .env
```

Edit `.env`:

```dotenv
FLASK_SECRET_KEY=<long-random-value>
DASHBOARD_USER=admin
DASHBOARD_PASSKEY=<strong-passkey>
# Recommended alternative to plain passkey:
# DASHBOARD_PASSKEY_HASH=pbkdf2:sha256:...

FREERADIUS_SERVICE=freeradius
VALIDATE_COMMAND=freeradius -XC
TRUSTED_ROOT_UPDATE_COMMAND=update-ca-certificates
SERVER_CERT_PATH=/etc/freeradius/3.0/certs/server.pem
TRUSTED_ROOT_DIR=/usr/local/share/ca-certificates
EDITABLE_CONFIGS=default:/etc/freeradius/3.0/sites-enabled/default,eap:/etc/freeradius/3.0/mods-enabled/eap
```

Generate a hashed passkey (recommended):

```bash
source .venv/bin/activate
python3 - << 'PY'
from werkzeug.security import generate_password_hash
print(generate_password_hash("REPLACE_WITH_STRONG_PASSKEY"))
PY
```

Put the output into `DASHBOARD_PASSKEY_HASH` and remove plain `DASHBOARD_PASSKEY`.

---

## 7) Permissions model (important)

This MVP app performs system operations (service control, validation, config/cert updates).

### Simplest path for first deployment
Run the dashboard service as `root` on localhost behind `nginx`.

- Pros: works immediately with current code
- Cons: larger blast radius if the app is compromised

Use network restrictions and strong credentials.

---

## 8) Create systemd service for dashboard

Create service file:

```bash
sudo tee /etc/systemd/system/freeradius-webgui.service > /dev/null << 'EOF'
[Unit]
Description=FreeRADIUS Web GUI
After=network.target freeradius.service
Wants=freeradius.service

[Service]
Type=simple
WorkingDirectory=/opt/freeradius-webgui
EnvironmentFile=/opt/freeradius-webgui/.env
ExecStart=/opt/freeradius-webgui/.venv/bin/python /opt/freeradius-webgui/app.py
Restart=on-failure
RestartSec=5
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF
```

Enable/start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable freeradius-webgui
sudo systemctl start freeradius-webgui
sudo systemctl status freeradius-webgui --no-pager
```

App listens on `127.0.0.1:8080` by default from Flask config. (Current code binds `0.0.0.0`; `nginx` will still proxy. Restrict exposure with firewall.)

---

## 9) Install and configure nginx reverse proxy

```bash
sudo apt -y install nginx
```

Create site config:

```bash
sudo tee /etc/nginx/sites-available/freeradius-webgui > /dev/null << 'EOF'
server {
    listen 80;
    server_name _;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name _;

    ssl_certificate     /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;

    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header Referrer-Policy no-referrer;
    add_header Content-Security-Policy "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'";

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF
```

Enable and reload:

```bash
sudo ln -sf /etc/nginx/sites-available/freeradius-webgui /etc/nginx/sites-enabled/freeradius-webgui
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl enable nginx
sudo systemctl restart nginx
```

> Replace snakeoil cert with your real server cert for production.

---

## 10) Verify end-to-end

1. Open `https://<server-ip-or-name>/`
2. Log in with dashboard credentials
3. Check service state loads
4. Open logs panel
5. Load/save a test config (non-production first)
6. Confirm validation/rollback behavior by intentionally introducing bad syntax

CLI checks:

```bash
sudo systemctl status freeradius --no-pager
sudo systemctl status freeradius-webgui --no-pager
sudo journalctl -u freeradius-webgui -n 100 --no-pager
sudo journalctl -u freeradius -n 100 --no-pager
```

---

## 11) Production hardening checklist

- Put dashboard behind internal network/VPN only
- Use real TLS certificate in nginx
- Use strong, rotated admin passkey hash
- Add fail2ban/rate-limit for login path
- Back up `/etc/freeradius/3.0` and cert material securely
- Centralize audit/event logs
- Restrict who can reach 443
- Test rollback path regularly

---

## 12) Optional next improvements

- Entra ID (OIDC) login integration
- Move from Flask dev server to `gunicorn`
- Replace root-run model with least-privilege command broker
- Add persistent audit log (who changed what/when/result)
- Add time-series metrics store for richer auth graphs

---

## 13) Rollback / uninstall

Disable web GUI service:

```bash
sudo systemctl disable --now freeradius-webgui
sudo rm -f /etc/systemd/system/freeradius-webgui.service
sudo systemctl daemon-reload
```

Remove nginx site:

```bash
sudo rm -f /etc/nginx/sites-enabled/freeradius-webgui
sudo rm -f /etc/nginx/sites-available/freeradius-webgui
sudo nginx -t && sudo systemctl reload nginx
```

Remove app files:

```bash
sudo rm -rf /opt/freeradius-webgui
```
