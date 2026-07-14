# AGENTS.md

## Cursor Cloud specific instructions

This repo is a single Flask app (`app.py`) — the **FreeRADIUS Web GUI**, an admin
dashboard that manages a host FreeRADIUS server (service control, transactional
config edit/validate/backup/rollback, log/metrics views, cert management, and
local/Entra-ID auth + RBAC). Standard setup/run steps live in `README.md`;
notes below are only the non-obvious, environment-specific gotchas.

### Running the app
- Run in development with the venv Python: `sudo .venv/bin/python app.py`
  (serves on `0.0.0.0:8080`). **Root (sudo) is required** because the app reads
  and writes FreeRADIUS config files under `/etc/freeradius/3.0` (owned `root`
  / mode `0640`) and shells out to `freeradius -XC`, `systemctl`, `journalctl`.
  Running as an unprivileged user makes the config/cert/log panels error with
  permission-denied.
- Copy `cp .env.example .env` once. Default local login is `admin` / `change-me`
  (`AUTH_MODE=local`). Set a strong `FLASK_SECRET_KEY`. `.env` is git-ignored.
- `RBAC_DB_PATH` in `.env.example` points at `/opt/...`; use a local path such as
  `data/rbac.db` when running from the repo (auto-created on first run).

### Key gotcha: no systemd in the Cloud VM
- The Cloud VM does **not** run systemd as PID 1 (PID 1 is `tini`), so every
  `systemctl` call (`is-active`/`start`/`stop`/`restart`) fails with
  "System has not been booted with systemd as init system", and `journalctl`
  has no FreeRADIUS journal. Therefore the **Service** panel, service
  start/stop/restart, and the **Logs** view cannot function here.
- The **transactional config feature still works** because validation uses
  `freeradius -XC` (not systemd): edit → atomic write → validate → backup →
  rollback-on-failure. But the GUI "Save + Validate + Restart" button always
  sends `restart_after: true`, so saving a *valid* config still fails at the
  final restart step and rolls back. To exercise a successful save without a
  restart, `POST /api/config/<key>` (or `/api/simple-config/apply`) with
  `restart_after: false`. Saving an *invalid* config cleanly demonstrates the
  validate + rollback path (it never reaches the restart step).

### System dependencies (baked into the VM, not the update script)
- `freeradius` + `freeradius-utils` provide `/etc/freeradius/3.0/*` and the
  `freeradius -XC` validator that the app's config validation depends on.
- `python3.12-venv` is required to (re)create `.venv`.

### Lint / test / build
- No formal linter config, no automated test suite, and no build step (plain
  Flask, server-rendered Jinja templates + vanilla JS/CSS).
- Syntax check: `.venv/bin/python -m py_compile app.py`.

### Notes
- `.venv/` is git-ignored; it is recreated by the startup update script. A
  virtualenv was previously committed to the repo by accident — do not re-add it.
- The app writes `*.bak.<timestamp>` backups next to the edited file; for
  `sites-enabled/` and `mods-enabled/` those dirs are auto-included by
  FreeRADIUS, so stray backups there can affect a subsequent `freeradius -XC`.
