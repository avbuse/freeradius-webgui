# FreeRADIUS Web GUI (MVP)
## This is a work in progress  it's been vibe-coded in an afternoon so far

A minimal Flask dashboard for operating a FreeRADIUS service with:
- service start/stop/restart
- config file edit + validation + backup + rollback
- recent logs view
- auth success/failure summary from journal logs
- server cert update
- trusted root cert update

See full host deployment steps in `INSTALL-UBUNTU-24.04.md`.

## 1) Setup

```bash
cd freeradius-webgui
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Set `.env` values for your environment.

## 2) Run

```bash
python app.py
```

Default URL: `http://<server>:8080`

## 3) Required host permissions

The process user must be able to:
- run `systemctl` on FreeRADIUS
- run `journalctl -u <service>`
- run validation command (`freeradius -XC` by default)
- read/write configured FreeRADIUS config files
- read/write server certificate file
- write trusted roots and run root update command

In production, run behind HTTPS reverse proxy and restrict source network.

## 4) Config mapping

Set editable files via `EDITABLE_CONFIGS` in `.env`:

```dotenv
EDITABLE_CONFIGS=default:/etc/freeradius/3.0/sites-enabled/default,eap:/etc/freeradius/3.0/mods-enabled/eap
```

Additional config options are auto-discovered by default from `FREERADIUS_CONFIG_ROOT`
(`/etc/freeradius/3.0`) and shown in the GUI dropdown, including:
- `sites-enabled/*`
- `mods-enabled/*`
- `policy.d/*`
- `radiusd.conf`, `clients.conf`, `proxy.conf`, `hints`, `huntgroups`

Optional controls:

```dotenv
FREERADIUS_CONFIG_ROOT=/etc/freeradius/3.0
AUTO_DISCOVER_CONFIGS=true
```

## 5) Security notes

- Use `DASHBOARD_PASSKEY_HASH` instead of plain passkey when possible.
- Keep `FLASK_SECRET_KEY` strong and unique.
- Restrict dashboard access to internal admin subnet.
- Prefer reverse proxy auth / SSO integration for production.
- Keep backups protected; they contain prior config and certificate material.

## 6) Optional Entra ID + RBAC

Web GUI authentication supports local login, Entra ID, or hybrid mode:

```dotenv
AUTH_MODE=local                # local | entra | hybrid
LOCAL_AUTH_FALLBACK=true
RBAC_DB_PATH=/opt/freeradius-webgui/data/rbac.db
ENTRA_TENANT_ID=
ENTRA_CLIENT_ID=
ENTRA_CLIENT_SECRET=
ENTRA_REDIRECT_URI=
ENTRA_SCOPES=openid profile email
ENTRA_GROUP_CLAIM=groups
```

The `.env` admin user (`DASHBOARD_USER`) is always treated as `Super Admin`
and cannot be downgraded by RBAC assignments.

## 7) Current scope limitations

- Metrics are summary counts, not full time-series charting.
- No per-action audit log persistence yet.

