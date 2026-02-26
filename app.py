from __future__ import annotations

import base64
import binascii
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from secrets import compare_digest
from typing import Any

from dotenv import load_dotenv
from flask import Flask, current_app, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

try:
    from authlib.integrations.flask_client import OAuth
except ImportError:  # pragma: no cover - optional dependency path
    OAuth = None  # type: ignore[assignment]

load_dotenv()


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-only-change-me")

    settings = AppSettings.from_env()
    app.config["APP_SETTINGS"] = settings
    initialize_rbac_store(settings)

    oauth = None
    if settings.entra_enabled and OAuth is not None:
        oauth = OAuth(app)
        oauth.register(
            name="entra",
            client_id=settings.entra_client_id,
            client_secret=settings.entra_client_secret,
            server_metadata_url=f"https://login.microsoftonline.com/{settings.entra_tenant_id}/v2.0/.well-known/openid-configuration",
            client_kwargs={"scope": settings.entra_scopes},
        )

    @app.get("/")
    def index() -> str:
        if not session.get("authenticated"):
            return redirect(url_for("login_page"))
        refresh_session_access_if_needed()
        if not session_has_permission("view_dashboard"):
            session.clear()
            return redirect(url_for("login_page"))
        return render_template("index.html", editable_configs=list(settings.editable_configs.keys()))

    @app.get("/login")
    def login_page() -> str:
        if session.get("authenticated"):
            return redirect(url_for("index"))
        return render_template(
            "login.html",
            local_login_enabled=is_local_login_enabled(settings),
            entra_login_enabled=is_entra_login_enabled(settings),
            auth_mode=settings.auth_mode,
        )

    @app.post("/api/login")
    def login() -> Any:
        if not is_local_login_enabled(settings):
            return jsonify({"ok": False, "error": "Local login is disabled."}), 403

        payload = request.get_json(silent=True) or {}
        username = str(payload.get("username", "")).strip()
        passkey = str(payload.get("passkey", ""))

        if authenticate_user(settings, username, passkey):
            sign_in_user(settings, principal=username, display_name=username, provider="local", groups=[])
            return jsonify({"ok": True})
        return jsonify({"ok": False, "error": "Invalid username or passkey."}), 401

    @app.get("/auth/entra/login")
    def entra_login() -> Any:
        if not is_entra_login_enabled(settings) or oauth is None:
            return redirect(url_for("login_page"))

        redirect_uri = settings.entra_redirect_uri or url_for("entra_callback", _external=True)
        return oauth.entra.authorize_redirect(redirect_uri)

    @app.get("/auth/entra/callback")
    def entra_callback() -> Any:
        if not is_entra_login_enabled(settings) or oauth is None:
            return redirect(url_for("login_page"))

        try:
            token = oauth.entra.authorize_access_token()
            userinfo = token.get("userinfo")
            if not userinfo:
                userinfo = oauth.entra.parse_id_token(token)
        except Exception:
            return redirect(url_for("login_page"))

        principal = str(
            userinfo.get("preferred_username")
            or userinfo.get("email")
            or userinfo.get("upn")
            or userinfo.get("sub")
            or ""
        ).strip()
        if not principal:
            return redirect(url_for("login_page"))

        display_name = str(userinfo.get("name") or principal)
        groups = userinfo.get(settings.entra_group_claim, [])
        if not isinstance(groups, list):
            groups = []

        sign_in_user(settings, principal=principal, display_name=display_name, provider="entra", groups=[str(item) for item in groups])
        return redirect(url_for("index"))

    @app.get("/api/auth/me")
    @require_auth
    def whoami() -> Any:
        permissions = session.get("permissions", [])
        if not isinstance(permissions, list):
            permissions = []
        roles = session.get("roles", [])
        if not isinstance(roles, list):
            roles = []

        if bool(session.get("is_env_admin", False)) or SYSTEM_SUPER_ADMIN_ROLE in roles:
            effective_permissions = sorted(ALL_PERMISSION_NAMES)
        else:
            effective_permissions = permissions

        return jsonify(
            {
                "ok": True,
                "principal": session.get("principal"),
                "display_name": session.get("display_name"),
                "provider": session.get("provider"),
                "roles": roles,
                "permissions": effective_permissions,
                "is_env_admin": bool(session.get("is_env_admin", False)),
            }
        )

    @app.get("/api/auth/settings")
    @require_auth
    @require_permission("access_control_manage")
    def auth_settings() -> Any:
        return jsonify(
            {
                "ok": True,
                "auth_mode": settings.auth_mode,
                "local_auth_fallback": settings.local_auth_fallback,
                "entra_tenant_id": settings.entra_tenant_id,
                "entra_client_id": settings.entra_client_id,
                "entra_client_secret": settings.entra_client_secret,
                "entra_redirect_uri": settings.entra_redirect_uri,
                "entra_scopes": settings.entra_scopes,
                "entra_group_claim": settings.entra_group_claim,
                "entra_enabled": settings.entra_enabled,
            }
        )

    @app.post("/api/auth/settings")
    @require_auth
    @require_permission("access_control_manage")
    def update_auth_settings() -> Any:
        payload = request.get_json(silent=True) or {}

        auth_mode = str(payload.get("auth_mode", settings.auth_mode)).strip().lower()
        if auth_mode not in {"local", "entra", "hybrid"}:
            return jsonify({"ok": False, "error": "auth_mode must be local, entra, or hybrid."}), 400

        updates = {
            "AUTH_MODE": auth_mode,
            "LOCAL_AUTH_FALLBACK": "true" if bool(payload.get("local_auth_fallback", settings.local_auth_fallback)) else "false",
            "ENTRA_TENANT_ID": str(payload.get("entra_tenant_id", settings.entra_tenant_id)).strip(),
            "ENTRA_CLIENT_ID": str(payload.get("entra_client_id", settings.entra_client_id)).strip(),
            "ENTRA_CLIENT_SECRET": str(payload.get("entra_client_secret", settings.entra_client_secret)).strip(),
            "ENTRA_REDIRECT_URI": str(payload.get("entra_redirect_uri", settings.entra_redirect_uri)).strip(),
            "ENTRA_SCOPES": str(payload.get("entra_scopes", settings.entra_scopes)).strip() or "openid profile email",
            "ENTRA_GROUP_CLAIM": str(payload.get("entra_group_claim", settings.entra_group_claim)).strip() or "groups",
        }

        try:
            upsert_env_values(settings.env_file_path, updates)
        except OSError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500

        settings.auth_mode = updates["AUTH_MODE"]
        settings.local_auth_fallback = updates["LOCAL_AUTH_FALLBACK"] == "true"
        settings.entra_tenant_id = updates["ENTRA_TENANT_ID"]
        settings.entra_client_id = updates["ENTRA_CLIENT_ID"]
        settings.entra_client_secret = updates["ENTRA_CLIENT_SECRET"]
        settings.entra_redirect_uri = updates["ENTRA_REDIRECT_URI"]
        settings.entra_scopes = updates["ENTRA_SCOPES"]
        settings.entra_group_claim = updates["ENTRA_GROUP_CLAIM"]

        return jsonify(
            {
                "ok": True,
                "message": "Auth settings saved to .env.",
                "restart_required": True,
            }
        )

    @app.get("/api/rbac/permissions")
    @require_auth
    @require_permission("access_control_manage")
    def list_permissions_api() -> Any:
        return jsonify({"ok": True, "permissions": list_permissions_catalog()})

    @app.get("/api/rbac/roles")
    @require_auth
    @require_permission("access_control_manage")
    def list_roles_api() -> Any:
        return jsonify({"ok": True, "roles": list_roles_with_permissions(settings)})

    @app.post("/api/rbac/roles")
    @require_auth
    @require_permission("access_control_manage")
    def create_role_api() -> Any:
        payload = request.get_json(silent=True) or {}
        role_name = str(payload.get("name", "")).strip()
        permissions = payload.get("permissions")
        if not role_name:
            return jsonify({"ok": False, "error": "Role name is required."}), 400
        if not isinstance(permissions, list):
            return jsonify({"ok": False, "error": "Permissions must be a list."}), 400

        try:
            create_or_update_role(settings, role_name, [str(item) for item in permissions], create_only=True)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify({"ok": True, "role": role_name})

    @app.put("/api/rbac/roles/<role_name>")
    @require_auth
    @require_permission("access_control_manage")
    def update_role_api(role_name: str) -> Any:
        payload = request.get_json(silent=True) or {}
        permissions = payload.get("permissions")
        if not isinstance(permissions, list):
            return jsonify({"ok": False, "error": "Permissions must be a list."}), 400

        try:
            create_or_update_role(settings, role_name, [str(item) for item in permissions], create_only=False)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify({"ok": True, "role": role_name})

    @app.delete("/api/rbac/roles/<role_name>")
    @require_auth
    @require_permission("access_control_manage")
    def delete_role_api(role_name: str) -> Any:
        try:
            delete_role(settings, role_name)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify({"ok": True, "role": role_name})

    @app.get("/api/rbac/users")
    @require_auth
    @require_permission("access_control_manage")
    def list_user_role_assignments_api() -> Any:
        return jsonify({"ok": True, "assignments": list_user_role_assignments(settings)})

    @app.post("/api/rbac/users/assign")
    @require_auth
    @require_permission("access_control_manage")
    def assign_user_role_api() -> Any:
        payload = request.get_json(silent=True) or {}
        principal = str(payload.get("principal", "")).strip()
        role_name = str(payload.get("role", "")).strip()
        if not principal or not role_name:
            return jsonify({"ok": False, "error": "Principal and role are required."}), 400

        try:
            assign_role_to_principal(settings, principal, role_name)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify({"ok": True})

    @app.post("/api/rbac/users/unassign")
    @require_auth
    @require_permission("access_control_manage")
    def unassign_user_role_api() -> Any:
        payload = request.get_json(silent=True) or {}
        principal = str(payload.get("principal", "")).strip()
        if not principal:
            return jsonify({"ok": False, "error": "Principal is required."}), 400
        remove_role_from_principal(settings, principal)
        return jsonify({"ok": True})

    @app.get("/api/rbac/groups")
    @require_auth
    @require_permission("access_control_manage")
    def list_group_role_assignments_api() -> Any:
        return jsonify({"ok": True, "assignments": list_group_role_assignments(settings)})

    @app.post("/api/rbac/groups/assign")
    @require_auth
    @require_permission("access_control_manage")
    def assign_group_role_api() -> Any:
        payload = request.get_json(silent=True) or {}
        group_id = str(payload.get("group_id", "")).strip()
        role_name = str(payload.get("role", "")).strip()
        if not group_id or not role_name:
            return jsonify({"ok": False, "error": "Group ID and role are required."}), 400

        try:
            assign_role_to_group(settings, group_id, role_name)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify({"ok": True})

    @app.post("/api/rbac/groups/unassign")
    @require_auth
    @require_permission("access_control_manage")
    def unassign_group_role_api() -> Any:
        payload = request.get_json(silent=True) or {}
        group_id = str(payload.get("group_id", "")).strip()
        if not group_id:
            return jsonify({"ok": False, "error": "Group ID is required."}), 400
        remove_role_from_group(settings, group_id)
        return jsonify({"ok": True})

    @app.post("/api/logout")
    @require_auth
    def logout() -> Any:
        session.clear()
        return jsonify({"ok": True})

    @app.get("/api/status")
    @require_auth
    @require_permission("view_dashboard")
    def service_status() -> Any:
        result = run_command(["systemctl", "is-active", settings.freeradius_service], check=False)
        is_active = result.returncode == 0 and result.stdout.strip() == "active"
        return jsonify(
            {
                "ok": True,
                "service": settings.freeradius_service,
                "state": result.stdout.strip(),
                "active": is_active,
            }
        )

    @app.post("/api/service")
    @require_auth
    @require_permission("service_control")
    def service_control() -> Any:
        payload = request.get_json(silent=True) or {}
        action = str(payload.get("action", "")).strip().lower()
        if action not in {"start", "stop", "restart"}:
            return jsonify({"ok": False, "error": "Invalid action."}), 400

        result = run_command(["systemctl", action, settings.freeradius_service], check=False)
        if result.returncode != 0:
            return jsonify({"ok": False, "error": result.stderr or result.stdout}), 500
        return jsonify({"ok": True, "action": action})

    @app.get("/api/logs")
    @require_auth
    @require_permission("view_logs")
    def logs() -> Any:
        lines = max(10, min(int(request.args.get("lines", 200)), 1000))
        result = run_command(
            [
                "journalctl",
                "-u",
                settings.freeradius_service,
                "-n",
                str(lines),
                "--no-pager",
                "-o",
                "short-iso",
            ],
            check=False,
        )
        if result.returncode != 0:
            return jsonify({"ok": False, "error": result.stderr or result.stdout}), 500
        return jsonify({"ok": True, "logs": result.stdout})

    @app.get("/api/metrics")
    @require_auth
    @require_permission("view_metrics")
    def metrics() -> Any:
        minutes = max(15, min(int(request.args.get("minutes", 120)), 1440))
        since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")

        result = run_command(
            [
                "journalctl",
                "-u",
                settings.freeradius_service,
                "--since",
                since,
                "--no-pager",
                "-o",
                "short-iso",
            ],
            check=False,
        )
        if result.returncode != 0:
            return jsonify({"ok": False, "error": result.stderr or result.stdout}), 500

        success_count = 0
        failure_count = 0
        for line in result.stdout.splitlines():
            if SUCCESS_REGEX.search(line):
                success_count += 1
            elif FAILURE_REGEX.search(line):
                failure_count += 1

        return jsonify(
            {
                "ok": True,
                "window_minutes": minutes,
                "success": success_count,
                "failure": failure_count,
            }
        )

    @app.get("/api/simple-config")
    @require_auth
    @require_permission("simple_config_read")
    def simple_config_snapshot() -> Any:
        try:
            snapshot = build_simple_config_snapshot(settings)
        except OSError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500
        return jsonify({"ok": True, **snapshot})

    @app.post("/api/simple-config/apply")
    @require_auth
    @require_permission("simple_config_apply")
    def simple_config_apply() -> Any:
        payload = request.get_json(silent=True) or {}
        mods = payload.get("mods") if isinstance(payload.get("mods"), dict) else {}
        sites = payload.get("sites") if isinstance(payload.get("sites"), dict) else {}
        restart_after = bool(payload.get("restart_after", True))

        state_snapshots: list[dict[str, Any]] = []
        changes: list[str] = []
        try:
            apply_toggle_selections(
                selections=mods,
                available_dir=settings.freeradius_config_root / "mods-available",
                enabled_dir=settings.freeradius_config_root / "mods-enabled",
                group_label="mod",
                state_snapshots=state_snapshots,
                changes=changes,
            )
            apply_toggle_selections(
                selections=sites,
                available_dir=settings.freeradius_config_root / "sites-available",
                enabled_dir=settings.freeradius_config_root / "sites-enabled",
                group_label="site",
                state_snapshots=state_snapshots,
                changes=changes,
            )

            validation = run_command(settings.validate_command, check=False)
            if validation.returncode != 0:
                rollback_toggle_changes(state_snapshots)
                return (
                    jsonify(
                        {
                            "ok": False,
                            "error": "Validation failed. Rolled back.",
                            "details": validation.stderr or validation.stdout,
                        }
                    ),
                    400,
                )

            if restart_after:
                restart = run_command(["systemctl", "restart", settings.freeradius_service], check=False)
                if restart.returncode != 0:
                    rollback_toggle_changes(state_snapshots)
                    run_command(["systemctl", "restart", settings.freeradius_service], check=False)
                    return (
                        jsonify(
                            {
                                "ok": False,
                                "error": "Service restart failed. Rolled back.",
                                "details": restart.stderr or restart.stdout,
                            }
                        ),
                        500,
                    )
        except ValueError as exc:
            rollback_toggle_changes(state_snapshots)
            return jsonify({"ok": False, "error": str(exc)}), 400
        except OSError as exc:
            rollback_toggle_changes(state_snapshots)
            return jsonify({"ok": False, "error": str(exc)}), 500

        return jsonify({"ok": True, "changes": changes})

    @app.get("/api/simple-config/sections")
    @require_auth
    @require_permission("simple_config_read")
    def simple_config_sections() -> Any:
        root = settings.freeradius_config_root
        radiusd_path = root / "radiusd.conf"
        clients_path = root / "clients.conf"
        policy_dir = root / "policy.d"

        try:
            radiusd_content = radiusd_path.read_text(encoding="utf-8") if radiusd_path.exists() else ""
            radiusd_options = build_simple_radiusd_options(radiusd_content)
            radiusd_directive_items = [item for item in radiusd_options if item.get("editable", True)]
            radiusd_structure_items = [item for item in radiusd_options if item.get("editable") is False]
            clients_content = clients_path.read_text(encoding="utf-8") if clients_path.exists() else ""
            clients_index = build_simple_clients_index(
                settings,
                include_secrets=session_has_permission("client_secret_view"),
            )
            clients_sources = sorted({item["source_path"] for item in clients_index})
            policy_files = []
            if policy_dir.exists() and policy_dir.is_dir():
                for item in sorted(policy_dir.iterdir()):
                    if item.name.startswith(".") or not item.is_file():
                        continue
                    policy_files.append({"name": item.name, "path": str(item)})
        except OSError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500

        return jsonify(
            {
                "ok": True,
                "radiusd": {
                    "path": str(radiusd_path),
                    "content": radiusd_content,
                    "items": radiusd_options,
                    "directive_items": radiusd_directive_items,
                    "structure_items": radiusd_structure_items,
                },
                "clients": {
                    "path": str(clients_path),
                    "content": clients_content,
                    "items": clients_index,
                    "sources": clients_sources,
                },
                "policy": {"directory": str(policy_dir), "files": policy_files},
            }
        )

    @app.get("/api/simple-config/policy/<policy_name>")
    @require_auth
    @require_permission("simple_config_read")
    def simple_config_policy_file(policy_name: str) -> Any:
        filename = secure_filename(policy_name)
        if not filename:
            return jsonify({"ok": False, "error": "Invalid policy filename."}), 400

        policy_dir = settings.freeradius_config_root / "policy.d"
        policy_path = (policy_dir / filename).resolve()
        if not is_under_directory(policy_path, policy_dir):
            return jsonify({"ok": False, "error": "Invalid policy path."}), 400
        if not policy_path.exists() or not policy_path.is_file():
            return jsonify({"ok": False, "error": "Policy file not found."}), 404

        try:
            content = policy_path.read_text(encoding="utf-8")
        except OSError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500

        return jsonify({"ok": True, "name": filename, "path": str(policy_path), "content": content})

    @app.post("/api/simple-config/radiusd/option")
    @require_auth
    @require_permission("simple_config_apply")
    def simple_config_update_radiusd_option() -> Any:
        payload = request.get_json(silent=True) or {}
        option_key = str(payload.get("key", "")).strip()
        value = str(payload.get("value", "")).strip()

        radiusd_path = settings.freeradius_config_root / "radiusd.conf"
        try:
            current_text = radiusd_path.read_text(encoding="utf-8") if radiusd_path.exists() else ""
            option_index = build_simple_radiusd_option_index(current_text)
            option_spec = option_index.get(option_key)
            if not option_spec:
                return jsonify({"ok": False, "error": "Unknown radiusd option."}), 400
            if option_spec.get("editable") is False:
                return jsonify({"ok": False, "error": "This entry is code-only and not editable from this control."}), 400

            if option_spec["type"] == "number" and value and not re.fullmatch(r"\d+", value):
                return jsonify({"ok": False, "error": "Value must be a whole number."}), 400
            if option_spec["type"] == "boolean":
                normalized = value.lower()
                if normalized not in {"yes", "no", "true", "false", "1", "0"}:
                    return jsonify({"ok": False, "error": "Boolean options must be yes/no."}), 400
                value = "yes" if normalized in {"yes", "true", "1"} else "no"
            if option_spec["type"] == "select":
                allowed = option_spec.get("choices", [])
                if value not in allowed:
                    return jsonify({"ok": False, "error": f"Value must be one of: {', '.join(allowed)}"}), 400

            section = str(option_spec.get("section", "global"))
            if section == "global":
                updated_text, _ = set_assignment_value(current_text, option_spec["directive"], value)
            else:
                updated_text = set_block_assignment_value(
                    current_text,
                    section_name=section,
                    key=option_spec["directive"],
                    value=value,
                )

            result, status_code = apply_text_to_path_with_validation(
                settings=settings,
                path=radiusd_path,
                content=updated_text,
                restart_after=True,
            )
            if not result.get("ok"):
                return jsonify(result), status_code
        except OSError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500

        return jsonify({"ok": True, "key": option_key, "value": value})

    @app.post("/api/simple-config/radiusd/option/state")
    @require_auth
    @require_permission("simple_config_apply")
    def simple_config_set_radiusd_option_state() -> Any:
        payload = request.get_json(silent=True) or {}
        option_key = str(payload.get("key", "")).strip()
        should_be_active = bool(payload.get("active", True))
        value = str(payload.get("value", "")).strip()

        radiusd_path = settings.freeradius_config_root / "radiusd.conf"
        try:
            current_text = radiusd_path.read_text(encoding="utf-8") if radiusd_path.exists() else ""
            option_index = build_simple_radiusd_option_index(current_text)
            option_spec = option_index.get(option_key)
            if not option_spec:
                return jsonify({"ok": False, "error": "Unknown radiusd option."}), 400
            if option_spec.get("editable") is False:
                return jsonify({"ok": False, "error": "This entry is code-only and cannot be toggled."}), 400

            if not value:
                value = str(option_spec.get("value", "")).strip()
            if not value:
                option_type = str(option_spec.get("type", "text"))
                if option_type == "boolean":
                    value = "no"
                elif option_type == "number":
                    value = "0"
                elif option_type == "select":
                    choices = option_spec.get("choices", [])
                    value = str(choices[0]) if isinstance(choices, list) and choices else ""

            section = str(option_spec.get("section", "global"))
            directive = str(option_spec.get("directive", "")).strip()
            if not directive:
                return jsonify({"ok": False, "error": "Invalid option directive."}), 400

            if section == "global":
                updated_text = set_directive_active_in_body(
                    content=current_text,
                    key=directive,
                    active=should_be_active,
                    value=value,
                    default_indent="",
                )
            else:
                updated_text = set_block_directive_active(
                    content=current_text,
                    section_name=section,
                    key=directive,
                    active=should_be_active,
                    value=value,
                )

            result, status_code = apply_text_to_path_with_validation(
                settings=settings,
                path=radiusd_path,
                content=updated_text,
                restart_after=True,
            )
            if not result.get("ok"):
                return jsonify(result), status_code
        except OSError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500

        return jsonify({"ok": True, "key": option_key, "active": should_be_active})

    @app.get("/api/simple-config/clients/<client_id>")
    @require_auth
    @require_permission("simple_config_read")
    def simple_config_get_client(client_id: str) -> Any:
        try:
            client = find_simple_client_by_id(
                settings,
                client_id,
                include_secrets=session_has_permission("client_secret_view"),
            )
        except (OSError, ValueError) as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

        if not client:
            return jsonify({"ok": False, "error": "Client not found."}), 404

        return jsonify({"ok": True, "client": client})

    @app.post("/api/simple-config/clients/add")
    @require_auth
    @require_permission("simple_config_apply")
    def simple_config_add_client() -> Any:
        payload = request.get_json(silent=True) or {}
        name = secure_filename(str(payload.get("name", "")).strip())
        target_path_raw = str(payload.get("target_path", "")).strip()
        target_path = settings.freeradius_config_root / "clients.conf"
        if target_path_raw:
            candidate = Path(target_path_raw).resolve()
            if not is_under_directory(candidate, settings.freeradius_config_root):
                return jsonify({"ok": False, "error": "Invalid target clients file path."}), 400
            target_path = candidate

        client_data, error_message = normalize_simple_client_payload(payload, require_secret=True)

        if not name:
            return jsonify({"ok": False, "error": "Client name is required."}), 400
        if error_message:
            return jsonify({"ok": False, "error": error_message}), 400

        try:
            current_text = target_path.read_text(encoding="utf-8") if target_path.exists() else ""
            if any(block["name"] == name for block in parse_client_blocks(current_text)):
                return jsonify({"ok": False, "error": f"Client '{name}' already exists."}), 400

            block = render_simple_client_block(name, client_data)
            separator = "" if not current_text.strip() or current_text.endswith("\n") else "\n"
            updated_text = f"{current_text}{separator}\n{block}\n"
            result, status_code = apply_text_to_path_with_validation(
                settings=settings,
                path=target_path,
                content=updated_text,
                restart_after=True,
            )
            if not result.get("ok"):
                return jsonify(result), status_code
        except OSError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500

        return jsonify({"ok": True, "client": name})

    @app.post("/api/simple-config/clients/update")
    @require_auth
    @require_permission("simple_config_apply")
    def simple_config_update_client() -> Any:
        payload = request.get_json(silent=True) or {}
        client_id = str(payload.get("id", "")).strip()
        if not client_id:
            return jsonify({"ok": False, "error": "Client id is required."}), 400

        try:
            decoded = decode_simple_client_id(client_id)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

        source_path = decoded["path"]
        if not is_allowed_simple_clients_path(settings, source_path):
            return jsonify({"ok": False, "error": "Client source path is not allowed."}), 400

        client_data, error_message = normalize_simple_client_payload(payload, require_secret=False)
        if error_message:
            return jsonify({"ok": False, "error": error_message}), 400

        try:
            content = source_path.read_text(encoding="utf-8") if source_path.exists() else ""
            blocks = parse_client_blocks(content)
        except OSError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500

        block = locate_client_block(blocks, decoded)
        if not block:
            return jsonify({"ok": False, "error": "Client block not found."}), 404

        existing_data = parse_simple_client_fields(block["body"])
        if not client_data.get("secret"):
            client_data["secret"] = existing_data.get("secret", "")

        replacement = render_simple_client_block(decoded["name"], client_data)
        updated_text = f"{content[:block['start']]}{replacement}{content[block['end']:] }"

        result, status_code = apply_text_to_path_with_validation(
            settings=settings,
            path=source_path,
            content=updated_text,
            restart_after=True,
        )
        if not result.get("ok"):
            return jsonify(result), status_code

        return jsonify({"ok": True, "client": decoded["name"], "path": str(source_path)})

    @app.post("/api/simple-config/clients/delete")
    @require_auth
    @require_permission("simple_config_apply")
    def simple_config_delete_client() -> Any:
        payload = request.get_json(silent=True) or {}
        client_id = str(payload.get("id", "")).strip()
        confirmed = bool(payload.get("confirmed", False))

        if not client_id:
            return jsonify({"ok": False, "error": "Client id is required."}), 400
        if not confirmed:
            return jsonify({"ok": False, "error": "Deletion not confirmed."}), 400

        try:
            decoded = decode_simple_client_id(client_id)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

        source_path = decoded["path"]
        if not is_allowed_simple_clients_path(settings, source_path):
            return jsonify({"ok": False, "error": "Client source path is not allowed."}), 400

        try:
            content = source_path.read_text(encoding="utf-8") if source_path.exists() else ""
            blocks = parse_client_blocks(content)
        except OSError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500

        block = locate_client_block(blocks, decoded)
        if not block:
            return jsonify({"ok": False, "error": "Client block not found."}), 404

        updated_text = f"{content[:block['start']].rstrip()}\n\n{content[block['end']:].lstrip()}"
        result, status_code = apply_text_to_path_with_validation(
            settings=settings,
            path=source_path,
            content=updated_text,
            restart_after=True,
        )
        if not result.get("ok"):
            return jsonify(result), status_code

        return jsonify({"ok": True, "client": decoded["name"], "path": str(source_path)})

    @app.post("/api/simple-config/policy/add")
    @require_auth
    @require_permission("simple_config_apply")
    def simple_config_add_policy() -> Any:
        payload = request.get_json(silent=True) or {}
        filename = secure_filename(str(payload.get("filename", "")).strip())
        content = payload.get("content")

        if not filename:
            return jsonify({"ok": False, "error": "Policy filename is required."}), 400
        if not isinstance(content, str) or not content.strip():
            return jsonify({"ok": False, "error": "Policy content is required."}), 400

        if "." not in filename:
            filename = f"{filename}.conf"

        policy_dir = settings.freeradius_config_root / "policy.d"
        policy_dir.mkdir(parents=True, exist_ok=True)
        policy_path = (policy_dir / filename).resolve()
        if not is_under_directory(policy_path, policy_dir):
            return jsonify({"ok": False, "error": "Invalid policy path."}), 400
        if policy_path.exists():
            return jsonify({"ok": False, "error": "Policy file already exists."}), 400

        result, status_code = apply_text_to_path_with_validation(
            settings=settings,
            path=policy_path,
            content=content,
            restart_after=True,
        )
        if not result.get("ok"):
            return jsonify(result), status_code

        return jsonify({"ok": True, "policy": filename})

    @app.get("/api/config/<config_key>")
    @require_auth
    @require_permission("advanced_config_read")
    def get_config(config_key: str) -> Any:
        file_path = settings.editable_configs.get(config_key)
        if not file_path:
            return jsonify({"ok": False, "error": "Unknown config key."}), 404

        try:
            content = file_path.read_text(encoding="utf-8")
            backups = list_backups(file_path)
        except OSError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500

        return jsonify(
            {
                "ok": True,
                "config_key": config_key,
                "path": str(file_path),
                "content": content,
                "backups": backups,
            }
        )

    @app.post("/api/config/<config_key>")
    @require_auth
    @require_permission("advanced_config_write")
    def update_config(config_key: str) -> Any:
        file_path = settings.editable_configs.get(config_key)
        if not file_path:
            return jsonify({"ok": False, "error": "Unknown config key."}), 404

        payload = request.get_json(silent=True) or {}
        content = payload.get("content")
        restart_after = bool(payload.get("restart_after", True))

        if not isinstance(content, str):
            return jsonify({"ok": False, "error": "Missing config content."}), 400

        backup_path = backup_file(file_path)
        try:
            apply_text_atomic(file_path, content)
            validation = run_command(settings.validate_command, check=False)
            if validation.returncode != 0:
                restore_file(backup_path, file_path)
                return (
                    jsonify(
                        {
                            "ok": False,
                            "error": "Validation failed. Rolled back.",
                            "details": validation.stderr or validation.stdout,
                        }
                    ),
                    400,
                )

            if restart_after:
                restart = run_command(["systemctl", "restart", settings.freeradius_service], check=False)
                if restart.returncode != 0:
                    restore_file(backup_path, file_path)
                    run_command(["systemctl", "restart", settings.freeradius_service], check=False)
                    return (
                        jsonify(
                            {
                                "ok": False,
                                "error": "Service restart failed. Rolled back.",
                                "details": restart.stderr or restart.stdout,
                            }
                        ),
                        500,
                    )
        except OSError as exc:
            restore_file(backup_path, file_path)
            return jsonify({"ok": False, "error": f"Write failed and rollback attempted: {exc}"}), 500

        return jsonify({"ok": True, "backup": str(backup_path)})

    @app.post("/api/config/<config_key>/rollback")
    @require_auth
    @require_permission("advanced_config_rollback")
    def rollback_config(config_key: str) -> Any:
        file_path = settings.editable_configs.get(config_key)
        if not file_path:
            return jsonify({"ok": False, "error": "Unknown config key."}), 404

        payload = request.get_json(silent=True) or {}
        backup = payload.get("backup")
        backup_path = Path(backup) if isinstance(backup, str) and backup else latest_backup(file_path)
        if not backup_path or not backup_path.exists():
            return jsonify({"ok": False, "error": "No backup found."}), 404

        restore_file(backup_path, file_path)
        restart = run_command(["systemctl", "restart", settings.freeradius_service], check=False)
        if restart.returncode != 0:
            return jsonify({"ok": False, "error": restart.stderr or restart.stdout}), 500

        return jsonify({"ok": True, "restored_from": str(backup_path)})

    @app.post("/api/certs/server")
    @require_auth
    @require_permission("cert_server_manage")
    def update_server_cert() -> Any:
        payload = request.get_json(silent=True) or {}
        content = payload.get("content")
        restart_after = bool(payload.get("restart_after", True))
        if not isinstance(content, str) or not content.strip():
            return jsonify({"ok": False, "error": "Missing certificate content."}), 400

        result, status_code = apply_server_certificate_content(settings, content, restart_after)
        return jsonify(result), status_code

    @app.get("/api/certs/server/details")
    @require_auth
    @require_permission("cert_server_manage")
    def server_cert_details() -> Any:
        cert_path = settings.server_cert_path
        key_path = settings.server_key_path
        csr_path = settings.server_csr_path

        if not cert_path.exists():
            return jsonify(
                {
                    "ok": True,
                    "exists": False,
                    "path": str(cert_path),
                    "key_exists": key_path.exists(),
                    "key_path": str(key_path),
                    "csr_exists": csr_path.exists(),
                    "csr_path": str(csr_path),
                }
            )

        details = read_certificate_details(cert_path)
        if details.get("error"):
            return jsonify({"ok": False, "error": details["error"]}), 400

        return jsonify(
            {
                "ok": True,
                "exists": True,
                "path": str(cert_path),
                "key_exists": key_path.exists(),
                "key_path": str(key_path),
                "csr_exists": csr_path.exists(),
                "csr_path": str(csr_path),
                "details": details,
            }
        )

    @app.post("/api/certs/server/csr")
    @require_auth
    @require_permission("cert_server_manage")
    def generate_server_csr() -> Any:
        payload = request.get_json(silent=True) or {}
        common_name = str(payload.get("common_name", "")).strip()
        if not common_name:
            return jsonify({"ok": False, "error": "Common Name is required."}), 400

        subject = build_certificate_subject(payload)
        san_entries = parse_san_entries(payload.get("san"))

        key_path = settings.server_key_path
        csr_path = settings.server_csr_path
        key_path.parent.mkdir(parents=True, exist_ok=True)
        csr_path.parent.mkdir(parents=True, exist_ok=True)

        base_command = [
            "openssl",
            "req",
            "-new",
            "-out",
            str(csr_path),
            "-subj",
            subject,
        ]

        if key_path.exists():
            command = [*base_command, "-key", str(key_path)]
        else:
            command = [*base_command, "-newkey", "rsa:2048", "-nodes", "-keyout", str(key_path)]

        if san_entries:
            command.extend(["-addext", f"subjectAltName={','.join(san_entries)}"])

        result = run_command(command, check=False)
        if result.returncode != 0:
            return jsonify({"ok": False, "error": result.stderr or result.stdout}), 500

        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass

        try:
            csr_content = csr_path.read_text(encoding="utf-8")
        except OSError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500

        return jsonify(
            {
                "ok": True,
                "csr_path": str(csr_path),
                "key_path": str(key_path),
                "csr": csr_content,
                "san": san_entries,
            }
        )

    @app.post("/api/certs/server/upload")
    @require_auth
    @require_permission("cert_server_manage")
    def upload_server_cert() -> Any:
        payload = request.get_json(silent=True) or {}
        filename = secure_filename(str(payload.get("filename", "")).strip())
        content_base64 = payload.get("content_base64")
        restart_after = bool(payload.get("restart_after", True))

        if not filename:
            return jsonify({"ok": False, "error": "Missing upload filename."}), 400
        if not isinstance(content_base64, str) or not content_base64.strip():
            return jsonify({"ok": False, "error": "Missing upload content."}), 400

        try:
            raw_bytes = base64.b64decode(content_base64, validate=True)
        except (binascii.Error, ValueError):
            return jsonify({"ok": False, "error": "Invalid base64 file content."}), 400

        pem_content, conversion = convert_uploaded_server_certificate(filename, raw_bytes)
        if not pem_content:
            return jsonify({"ok": False, "error": "Unable to convert upload to PEM certificate format."}), 400

        result, status_code = apply_server_certificate_content(settings, pem_content, restart_after)
        if not result.get("ok"):
            return jsonify(result), status_code

        result["conversion"] = conversion
        return jsonify(result), status_code

    @app.post("/api/certs/root")
    @require_auth
    @require_permission("cert_trusted_roots_manage")
    def add_trusted_root() -> Any:
        payload = request.get_json(silent=True) or {}
        filename = secure_filename(str(payload.get("filename", "")).strip())
        content = payload.get("content")

        if not filename:
            return jsonify({"ok": False, "error": "Missing filename."}), 400
        if not isinstance(content, str) or not content.strip():
            return jsonify({"ok": False, "error": "Missing certificate content."}), 400

        target = settings.trusted_root_dir / filename
        if target.suffix.lower() not in {".crt", ".pem"}:
            return jsonify({"ok": False, "error": "File must be .crt or .pem."}), 400

        backup_path = backup_file(target) if target.exists() else None
        try:
            apply_text_atomic(target, content)
            update_cmd = run_command(settings.trusted_root_update_command, check=False)
            if update_cmd.returncode != 0:
                if backup_path and backup_path.exists():
                    restore_file(backup_path, target)
                return jsonify({"ok": False, "error": update_cmd.stderr or update_cmd.stdout}), 500
        except OSError as exc:
            if backup_path and backup_path.exists():
                restore_file(backup_path, target)
            return jsonify({"ok": False, "error": str(exc)}), 500

        return jsonify({"ok": True, "path": str(target), "backup": str(backup_path) if backup_path else None})

    @app.get("/api/certs/roots")
    @require_auth
    @require_permission("cert_trusted_roots_manage")
    def list_trusted_roots() -> Any:
        try:
            settings.trusted_root_dir.mkdir(parents=True, exist_ok=True)
            certs: list[dict[str, Any]] = []
            seen_paths: set[str] = set()

            source_dirs: list[tuple[str, Path]] = [
                ("Custom", settings.trusted_root_dir),
                ("System", Path("/etc/ssl/certs")),
            ]

            hash_link_pattern = re.compile(r"^[0-9a-f]{8}\.\d+$")
            for source_name, directory in source_dirs:
                if not directory.exists() or not directory.is_dir():
                    continue

                for item in sorted(directory.iterdir()):
                    if item.name.startswith("."):
                        continue
                    if hash_link_pattern.match(item.name):
                        continue

                    resolved = item.resolve()
                    if not resolved.exists() or not resolved.is_file():
                        continue
                    if resolved.suffix.lower() not in {".crt", ".pem"}:
                        continue

                    normalized_path = str(resolved)
                    if normalized_path in seen_paths:
                        continue
                    seen_paths.add(normalized_path)

                    stat = resolved.stat()
                    cert_details = read_certificate_details(item)
                    certs.append(
                        {
                            "name": resolved.name,
                            "path": str(item),
                            "size": stat.st_size,
                            "modified": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                            "source": source_name,
                            "subject": cert_details.get("subject"),
                            "not_after": cert_details.get("not_after"),
                            "days_remaining": cert_details.get("days_remaining"),
                            "expired": cert_details.get("expired"),
                            "expiring_soon": cert_details.get("expiring_soon"),
                            "deletable": source_name == "Custom",
                        }
                    )
        except OSError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 500

        certs.sort(key=lambda item: (item.get("source", ""), item["name"].lower()))
        return jsonify(
            {
                "ok": True,
                "directory": str(settings.trusted_root_dir),
                "sources": [str(path) for _, path in source_dirs],
                "certs": certs,
            }
        )

    @app.post("/api/certs/root/details")
    @require_auth
    @require_permission("cert_trusted_roots_manage")
    def trusted_root_details() -> Any:
        payload = request.get_json(silent=True) or {}
        cert_path = payload.get("path")
        target = resolve_allowed_trusted_root_path(settings, cert_path, allow_system=True)
        if not target or not target.exists() or not target.is_file():
            return jsonify({"ok": False, "error": "Certificate not found."}), 404

        details = read_certificate_details(target)
        if details.get("error"):
            return jsonify({"ok": False, "error": details["error"]}), 400

        return jsonify(
            {
                "ok": True,
                "path": str(target),
                "name": target.name,
                "details": details,
                "deletable": is_under_directory(target, settings.trusted_root_dir),
            }
        )

    @app.post("/api/certs/root/delete")
    @require_auth
    @require_permission("cert_trusted_roots_manage")
    def delete_trusted_root() -> Any:
        payload = request.get_json(silent=True) or {}
        cert_path = payload.get("path")
        confirmed = bool(payload.get("confirmed", False))
        if not confirmed:
            return jsonify({"ok": False, "error": "Deletion not confirmed."}), 400

        target = resolve_allowed_trusted_root_path(settings, cert_path, allow_system=False)
        if not target or not target.exists() or not target.is_file():
            return jsonify({"ok": False, "error": "Certificate not found in custom trusted roots."}), 404

        backup_path = backup_file(target)
        try:
            target.unlink()
            update_cmd = run_command(settings.trusted_root_update_command, check=False)
            if update_cmd.returncode != 0:
                restore_file(backup_path, target)
                return jsonify({"ok": False, "error": update_cmd.stderr or update_cmd.stdout}), 500
        except OSError as exc:
            if backup_path.exists() and not target.exists():
                restore_file(backup_path, target)
            return jsonify({"ok": False, "error": str(exc)}), 500

        return jsonify({"ok": True, "deleted": str(target), "backup": str(backup_path)})

    return app


SUCCESS_REGEX = re.compile(r"(Login OK|Access-Accept|Login correct)", re.IGNORECASE)
FAILURE_REGEX = re.compile(r"(Login incorrect|Access-Reject|Invalid user|Auth: Failed)", re.IGNORECASE)

SYSTEM_SUPER_ADMIN_ROLE = "Super Admin"
SYSTEM_SERVER_OPERATOR_ROLE = "Server Operator"
SYSTEM_CONFIG_ADMIN_ROLE = "Config Admin"
SYSTEM_READ_ONLY_ROLE = "Read Only"

PERMISSION_DEFINITIONS = [
    ("view_dashboard", "View dashboard and service status."),
    ("view_logs", "View FreeRADIUS logs."),
    ("view_metrics", "View auth metrics."),
    ("service_control", "Start/stop/restart FreeRADIUS service."),
    ("simple_config_read", "View simple configuration sections."),
    ("simple_config_apply", "Apply simple configuration changes."),
    ("client_secret_view", "View client shared secrets in Simple Config."),
    ("advanced_config_read", "Read advanced configuration files."),
    ("advanced_config_write", "Write advanced configuration files."),
    ("advanced_config_rollback", "Rollback advanced configuration files."),
    ("cert_server_manage", "Manage server certificate operations."),
    ("cert_trusted_roots_manage", "Manage trusted root certificate operations."),
    ("access_control_manage", "Manage users, roles, and permissions."),
]

ALL_PERMISSION_NAMES = {item[0] for item in PERMISSION_DEFINITIONS}

SYSTEM_ROLE_PERMISSIONS = {
    SYSTEM_SUPER_ADMIN_ROLE: sorted(ALL_PERMISSION_NAMES),
    SYSTEM_SERVER_OPERATOR_ROLE: [
        "view_dashboard",
        "view_logs",
        "view_metrics",
        "service_control",
        "simple_config_read",
        "simple_config_apply",
        "cert_server_manage",
        "cert_trusted_roots_manage",
    ],
    SYSTEM_CONFIG_ADMIN_ROLE: [
        "view_dashboard",
        "view_logs",
        "view_metrics",
        "simple_config_read",
        "simple_config_apply",
        "advanced_config_read",
        "advanced_config_write",
        "advanced_config_rollback",
        "cert_server_manage",
        "cert_trusted_roots_manage",
    ],
    SYSTEM_READ_ONLY_ROLE: [
        "view_dashboard",
        "view_logs",
        "view_metrics",
        "simple_config_read",
        "advanced_config_read",
    ],
}


def initialize_rbac_store(settings: "AppSettings") -> None:
    settings.rbac_db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(settings.rbac_db_path) as connection:
        cursor = connection.cursor()
        cursor.executescript(
            """
            CREATE TABLE IF NOT EXISTS roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                is_system INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS permissions (
                name TEXT PRIMARY KEY,
                description TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS role_permissions (
                role_id INTEGER NOT NULL,
                permission_name TEXT NOT NULL,
                PRIMARY KEY (role_id, permission_name),
                FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE,
                FOREIGN KEY(permission_name) REFERENCES permissions(name) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS user_roles (
                principal TEXT PRIMARY KEY,
                role_id INTEGER NOT NULL,
                FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS group_roles (
                group_id TEXT PRIMARY KEY,
                role_id INTEGER NOT NULL,
                FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE
            );
            """
        )

        for name, description in PERMISSION_DEFINITIONS:
            cursor.execute(
                "INSERT INTO permissions(name, description) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET description=excluded.description",
                (name, description),
            )

        for role_name, permissions in SYSTEM_ROLE_PERMISSIONS.items():
            cursor.execute(
                "INSERT INTO roles(name, is_system) VALUES (?, 1) ON CONFLICT(name) DO UPDATE SET is_system=1",
                (role_name,),
            )
            role_id = cursor.execute("SELECT id FROM roles WHERE name=?", (role_name,)).fetchone()[0]
            cursor.execute("DELETE FROM role_permissions WHERE role_id=?", (role_id,))
            cursor.executemany(
                "INSERT OR IGNORE INTO role_permissions(role_id, permission_name) VALUES (?, ?)",
                [(role_id, permission) for permission in permissions if permission in ALL_PERMISSION_NAMES],
            )

        connection.commit()


def list_permissions_catalog() -> list[dict[str, Any]]:
    return [{"name": name, "description": description} for name, description in PERMISSION_DEFINITIONS]


def rbac_connection(settings: "AppSettings") -> sqlite3.Connection:
    connection = sqlite3.connect(settings.rbac_db_path)
    connection.row_factory = sqlite3.Row
    return connection


def is_local_login_enabled(settings: "AppSettings") -> bool:
    return settings.auth_mode in {"local", "hybrid"} or settings.local_auth_fallback


def is_entra_login_enabled(settings: "AppSettings") -> bool:
    return settings.auth_mode in {"entra", "hybrid"} and settings.entra_enabled


def session_has_permission(permission_name: str) -> bool:
    if bool(session.get("is_env_admin", False)):
        return True
    roles = session.get("roles", [])
    if isinstance(roles, list) and SYSTEM_SUPER_ADMIN_ROLE in roles:
        return True
    permissions = session.get("permissions", [])
    return isinstance(permissions, list) and permission_name in permissions


def normalized_principal(value: str) -> str:
    return value.strip().lower()


def sign_in_user(settings: "AppSettings", principal: str, display_name: str, provider: str, groups: list[str]) -> None:
    principal_normalized = normalized_principal(principal)
    roles, permissions, is_env_admin = resolve_effective_access(settings, principal_normalized, groups)
    session.clear()
    session["authenticated"] = True
    session["user"] = principal
    session["principal"] = principal_normalized
    session["display_name"] = display_name
    session["provider"] = provider
    session["groups"] = groups
    session["roles"] = roles
    session["permissions"] = permissions
    session["is_env_admin"] = is_env_admin


def resolve_effective_access(settings: "AppSettings", principal: str, groups: list[str]) -> tuple[list[str], list[str], bool]:
    env_admin = normalized_principal(settings.dashboard_user)
    if principal == env_admin:
        return [SYSTEM_SUPER_ADMIN_ROLE], sorted(ALL_PERMISSION_NAMES), True

    role_names: set[str] = set()
    permission_names: set[str] = set()

    with rbac_connection(settings) as connection:
        cursor = connection.cursor()

        row = cursor.execute(
            """
            SELECT roles.name
            FROM user_roles
            JOIN roles ON roles.id = user_roles.role_id
            WHERE lower(user_roles.principal) = ?
            """,
            (principal,),
        ).fetchone()
        if row:
            role_names.add(str(row["name"]))

        for group_id in groups:
            group_row = cursor.execute(
                """
                SELECT roles.name
                FROM group_roles
                JOIN roles ON roles.id = group_roles.role_id
                WHERE group_roles.group_id = ?
                """,
                (str(group_id),),
            ).fetchone()
            if group_row:
                role_names.add(str(group_row["name"]))

        for role_name in role_names:
            role_permissions = cursor.execute(
                """
                SELECT rp.permission_name
                FROM role_permissions rp
                JOIN roles ON roles.id = rp.role_id
                WHERE roles.name = ?
                """,
                (role_name,),
            ).fetchall()
            for permission_row in role_permissions:
                permission_names.add(str(permission_row["permission_name"]))

    return sorted(role_names), sorted(permission_names), False


def role_exists(connection: sqlite3.Connection, role_name: str) -> bool:
    row = connection.execute("SELECT 1 FROM roles WHERE name=?", (role_name,)).fetchone()
    return bool(row)


def create_or_update_role(settings: "AppSettings", role_name: str, permissions: list[str], create_only: bool) -> None:
    if role_name in SYSTEM_ROLE_PERMISSIONS:
        raise ValueError("System role cannot be modified.")

    invalid = sorted({permission for permission in permissions if permission not in ALL_PERMISSION_NAMES})
    if invalid:
        raise ValueError(f"Unknown permissions: {', '.join(invalid)}")

    with rbac_connection(settings) as connection:
        cursor = connection.cursor()
        exists = role_exists(connection, role_name)
        if create_only and exists:
            raise ValueError("Role already exists.")
        if not create_only and not exists:
            raise ValueError("Role does not exist.")

        if not exists:
            cursor.execute("INSERT INTO roles(name, is_system) VALUES (?, 0)", (role_name,))

        role_id = cursor.execute("SELECT id FROM roles WHERE name=?", (role_name,)).fetchone()[0]
        cursor.execute("DELETE FROM role_permissions WHERE role_id=?", (role_id,))
        cursor.executemany(
            "INSERT INTO role_permissions(role_id, permission_name) VALUES (?, ?)",
            [(role_id, permission) for permission in permissions],
        )
        connection.commit()


def delete_role(settings: "AppSettings", role_name: str) -> None:
    if role_name in SYSTEM_ROLE_PERMISSIONS:
        raise ValueError("System role cannot be deleted.")

    with rbac_connection(settings) as connection:
        cursor = connection.cursor()
        row = cursor.execute("SELECT id FROM roles WHERE name=?", (role_name,)).fetchone()
        if not row:
            raise ValueError("Role does not exist.")
        role_id = row[0]
        cursor.execute("DELETE FROM user_roles WHERE role_id=?", (role_id,))
        cursor.execute("DELETE FROM group_roles WHERE role_id=?", (role_id,))
        cursor.execute("DELETE FROM role_permissions WHERE role_id=?", (role_id,))
        cursor.execute("DELETE FROM roles WHERE id=?", (role_id,))
        connection.commit()


def get_role_id(connection: sqlite3.Connection, role_name: str) -> int:
    row = connection.execute("SELECT id FROM roles WHERE name=?", (role_name,)).fetchone()
    if not row:
        raise ValueError("Role does not exist.")
    return int(row[0])


def assign_role_to_principal(settings: "AppSettings", principal: str, role_name: str) -> None:
    if normalized_principal(principal) == normalized_principal(settings.dashboard_user):
        raise ValueError("Configured env admin is always Super Admin and cannot be reassigned.")

    with rbac_connection(settings) as connection:
        role_id = get_role_id(connection, role_name)
        connection.execute(
            "INSERT INTO user_roles(principal, role_id) VALUES (?, ?) ON CONFLICT(principal) DO UPDATE SET role_id=excluded.role_id",
            (normalized_principal(principal), role_id),
        )
        connection.commit()


def remove_role_from_principal(settings: "AppSettings", principal: str) -> None:
    if normalized_principal(principal) == normalized_principal(settings.dashboard_user):
        return
    with rbac_connection(settings) as connection:
        connection.execute("DELETE FROM user_roles WHERE lower(principal)=?", (normalized_principal(principal),))
        connection.commit()


def assign_role_to_group(settings: "AppSettings", group_id: str, role_name: str) -> None:
    with rbac_connection(settings) as connection:
        role_id = get_role_id(connection, role_name)
        connection.execute(
            "INSERT INTO group_roles(group_id, role_id) VALUES (?, ?) ON CONFLICT(group_id) DO UPDATE SET role_id=excluded.role_id",
            (group_id, role_id),
        )
        connection.commit()


def remove_role_from_group(settings: "AppSettings", group_id: str) -> None:
    with rbac_connection(settings) as connection:
        connection.execute("DELETE FROM group_roles WHERE group_id=?", (group_id,))
        connection.commit()


def list_roles_with_permissions(settings: "AppSettings") -> list[dict[str, Any]]:
    with rbac_connection(settings) as connection:
        cursor = connection.cursor()
        roles = cursor.execute("SELECT id, name, is_system FROM roles ORDER BY name").fetchall()
        result: list[dict[str, Any]] = []
        for role in roles:
            permissions = cursor.execute(
                "SELECT permission_name FROM role_permissions WHERE role_id=? ORDER BY permission_name",
                (role["id"],),
            ).fetchall()
            result.append(
                {
                    "name": str(role["name"]),
                    "is_system": bool(role["is_system"]),
                    "permissions": [str(item[0]) for item in permissions],
                }
            )
        return result


def list_user_role_assignments(settings: "AppSettings") -> list[dict[str, Any]]:
    with rbac_connection(settings) as connection:
        rows = connection.execute(
            """
            SELECT user_roles.principal, roles.name
            FROM user_roles
            JOIN roles ON roles.id = user_roles.role_id
            ORDER BY user_roles.principal
            """
        ).fetchall()
        env_admin = normalized_principal(settings.dashboard_user)
        assignments = [{"principal": env_admin, "role": SYSTEM_SUPER_ADMIN_ROLE, "is_system": True}]
        assignments.extend(
            {
                "principal": str(row["principal"]),
                "role": str(row["name"]),
                "is_system": False,
            }
            for row in rows
            if str(row["principal"]) != env_admin
        )
        return assignments


def list_group_role_assignments(settings: "AppSettings") -> list[dict[str, Any]]:
    with rbac_connection(settings) as connection:
        rows = connection.execute(
            """
            SELECT group_roles.group_id, roles.name
            FROM group_roles
            JOIN roles ON roles.id = group_roles.role_id
            ORDER BY group_roles.group_id
            """
        ).fetchall()
        return [{"group_id": str(row["group_id"]), "role": str(row["name"])} for row in rows]


@dataclass
class AppSettings:
    env_file_path: Path
    auth_mode: str
    local_auth_fallback: bool
    dashboard_user: str
    dashboard_passkey: str
    dashboard_passkey_hash: str
    rbac_db_path: Path
    entra_tenant_id: str
    entra_client_id: str
    entra_client_secret: str
    entra_redirect_uri: str
    entra_scopes: str
    entra_group_claim: str
    freeradius_service: str
    validate_command: list[str]
    trusted_root_update_command: list[str]
    freeradius_config_root: Path
    server_cert_path: Path
    server_key_path: Path
    server_csr_path: Path
    trusted_root_dir: Path
    editable_configs: dict[str, Path]

    @classmethod
    def from_env(cls) -> "AppSettings":
        config_root = Path(os.getenv("FREERADIUS_CONFIG_ROOT", "/etc/freeradius/3.0"))
        auto_discover_configs = os.getenv("AUTO_DISCOVER_CONFIGS", "true").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

        editable_configs_raw = os.getenv("EDITABLE_CONFIGS", "")
        editable_configs: dict[str, Path] = {}
        for entry in editable_configs_raw.split(","):
            entry = entry.strip()
            if not entry or ":" not in entry:
                continue
            key, value = entry.split(":", 1)
            editable_configs[key.strip()] = Path(value.strip())

        if auto_discover_configs:
            discovered = discover_editable_configs(config_root)
            for key, value in discovered.items():
                editable_configs.setdefault(key, value)

        return cls(
            env_file_path=Path(os.getenv("APP_ENV_FILE_PATH", "/opt/freeradius-webgui/.env")),
            auth_mode=os.getenv("AUTH_MODE", "local").strip().lower(),
            local_auth_fallback=os.getenv("LOCAL_AUTH_FALLBACK", "true").strip().lower() in {"1", "true", "yes", "on"},
            dashboard_user=os.getenv("DASHBOARD_USER", "admin"),
            dashboard_passkey=os.getenv("DASHBOARD_PASSKEY", ""),
            dashboard_passkey_hash=os.getenv("DASHBOARD_PASSKEY_HASH", ""),
            rbac_db_path=Path(os.getenv("RBAC_DB_PATH", "/opt/freeradius-webgui/data/rbac.db")),
            entra_tenant_id=os.getenv("ENTRA_TENANT_ID", ""),
            entra_client_id=os.getenv("ENTRA_CLIENT_ID", ""),
            entra_client_secret=os.getenv("ENTRA_CLIENT_SECRET", ""),
            entra_redirect_uri=os.getenv("ENTRA_REDIRECT_URI", ""),
            entra_scopes=os.getenv("ENTRA_SCOPES", "openid profile email"),
            entra_group_claim=os.getenv("ENTRA_GROUP_CLAIM", "groups"),
            freeradius_service=os.getenv("FREERADIUS_SERVICE", "freeradius"),
            validate_command=os.getenv("VALIDATE_COMMAND", "freeradius -XC").split(),
            trusted_root_update_command=os.getenv("TRUSTED_ROOT_UPDATE_COMMAND", "update-ca-certificates").split(),
            freeradius_config_root=config_root,
            server_cert_path=Path(os.getenv("SERVER_CERT_PATH", "/etc/freeradius/3.0/certs/server.pem")),
            server_key_path=Path(os.getenv("SERVER_KEY_PATH", "/etc/freeradius/3.0/certs/server.key")),
            server_csr_path=Path(os.getenv("SERVER_CSR_PATH", "/etc/freeradius/3.0/certs/server.csr")),
            trusted_root_dir=Path(os.getenv("TRUSTED_ROOT_DIR", "/usr/local/share/ca-certificates")),
            editable_configs=editable_configs,
        )

    @property
    def entra_enabled(self) -> bool:
        return bool(self.entra_tenant_id and self.entra_client_id and self.entra_client_secret)


def discover_editable_configs(config_root: Path) -> dict[str, Path]:
    discovered: dict[str, Path] = {}

    named_files = {
        "radiusd": config_root / "radiusd.conf",
        "clients": config_root / "clients.conf",
        "proxy": config_root / "proxy.conf",
        "hints": config_root / "hints",
        "huntgroups": config_root / "huntgroups",
    }
    for key, path in named_files.items():
        if path.exists() and path.is_file():
            discovered[key] = path

    discovery_dirs = {
        "sites": config_root / "sites-enabled",
        "mods": config_root / "mods-enabled",
        "policy": config_root / "policy.d",
    }
    for prefix, directory in discovery_dirs.items():
        if not directory.exists() or not directory.is_dir():
            continue

        for path in sorted(directory.iterdir()):
            if path.name.startswith(".") or not path.is_file():
                continue
            discovered[f"{prefix}:{path.name}"] = path

    return discovered


def authenticate_user(settings: AppSettings, username: str, passkey: str) -> bool:
    if not compare_digest(username, settings.dashboard_user):
        return False
    if settings.dashboard_passkey_hash:
        return check_password_hash(settings.dashboard_passkey_hash, passkey)
    return compare_digest(passkey, settings.dashboard_passkey)


def require_auth(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("authenticated"):
            return jsonify({"ok": False, "error": "Unauthorized"}), 401
        refresh_session_access_if_needed()
        return func(*args, **kwargs)

    return wrapper


def require_permission(permission_name: str):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not session.get("authenticated"):
                return jsonify({"ok": False, "error": "Unauthorized"}), 401
            refresh_session_access_if_needed()
            if not session_has_permission(permission_name):
                return jsonify({"ok": False, "error": "Forbidden"}), 403
            return func(*args, **kwargs)

        return wrapper

    return decorator


def refresh_session_access_if_needed() -> None:
    permissions = session.get("permissions")
    roles = session.get("roles", [])
    if isinstance(permissions, list):
        if bool(session.get("is_env_admin", False)) and len(permissions) < len(ALL_PERMISSION_NAMES):
            pass
        elif isinstance(roles, list) and SYSTEM_SUPER_ADMIN_ROLE in roles and len(permissions) < len(ALL_PERMISSION_NAMES):
            pass
        else:
            return

    settings = current_app.config.get("APP_SETTINGS")
    if not isinstance(settings, AppSettings):
        return

    principal = str(session.get("principal") or session.get("user") or "").strip()
    if not principal:
        return

    sign_in_user(
        settings,
        principal=principal,
        display_name=str(session.get("display_name") or principal),
        provider=str(session.get("provider") or "local"),
        groups=[str(item) for item in session.get("groups", []) if isinstance(item, str)],
    )


def run_command(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, check=check)


def backup_file(path: Path) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    backup_path = path.with_name(f"{path.name}.bak.{timestamp}")
    if path.exists():
        shutil.copy2(path, backup_path)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        backup_path.touch()
    return backup_path


def latest_backup(path: Path) -> Path | None:
    backups = sorted(path.parent.glob(f"{path.name}.bak.*"), reverse=True)
    return backups[0] if backups else None


def list_backups(path: Path) -> list[str]:
    backups = sorted(path.parent.glob(f"{path.name}.bak.*"), reverse=True)
    return [str(item) for item in backups[:20]]


def apply_text_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=path.parent) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)
    shutil.move(str(tmp_path), str(path))


def restore_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def apply_server_certificate_content(settings: AppSettings, content: str, restart_after: bool) -> tuple[dict[str, Any], int]:
    cert_path = settings.server_cert_path
    backup_path = backup_file(cert_path)
    try:
        apply_text_atomic(cert_path, content)
        validation = run_command(settings.validate_command, check=False)
        if validation.returncode != 0:
            restore_file(backup_path, cert_path)
            return (
                {
                    "ok": False,
                    "error": "Validation failed. Rolled back.",
                    "details": validation.stderr or validation.stdout,
                },
                400,
            )
        if restart_after:
            restart = run_command(["systemctl", "restart", settings.freeradius_service], check=False)
            if restart.returncode != 0:
                restore_file(backup_path, cert_path)
                run_command(["systemctl", "restart", settings.freeradius_service], check=False)
                return (
                    {
                        "ok": False,
                        "error": "Service restart failed. Rolled back.",
                        "details": restart.stderr or restart.stdout,
                    },
                    500,
                )
    except OSError as exc:
        restore_file(backup_path, cert_path)
        return ({"ok": False, "error": f"Write failed and rollback attempted: {exc}"}, 500)

    return ({"ok": True, "backup": str(backup_path), "path": str(cert_path)}, 200)


def apply_text_to_path_with_validation(settings: AppSettings, path: Path, content: str, restart_after: bool) -> tuple[dict[str, Any], int]:
    existed_before = path.exists()
    backup_path = backup_file(path)
    try:
        apply_text_atomic(path, content)
        validation = run_command(settings.validate_command, check=False)
        if validation.returncode != 0:
            if existed_before:
                restore_file(backup_path, path)
            elif path.exists():
                path.unlink()
            return (
                {
                    "ok": False,
                    "error": "Validation failed. Rolled back.",
                    "details": validation.stderr or validation.stdout,
                },
                400,
            )

        if restart_after:
            restart = run_command(["systemctl", "restart", settings.freeradius_service], check=False)
            if restart.returncode != 0:
                if existed_before:
                    restore_file(backup_path, path)
                elif path.exists():
                    path.unlink()
                run_command(["systemctl", "restart", settings.freeradius_service], check=False)
                return (
                    {
                        "ok": False,
                        "error": "Service restart failed. Rolled back.",
                        "details": restart.stderr or restart.stdout,
                    },
                    500,
                )
    except OSError as exc:
        if existed_before and backup_path.exists():
            restore_file(backup_path, path)
        elif path.exists():
            path.unlink()
        return ({"ok": False, "error": str(exc)}, 500)

    return ({"ok": True, "backup": str(backup_path), "path": str(path)}, 200)


def build_certificate_subject(payload: dict[str, Any]) -> str:
    fields = [
        ("C", payload.get("country")),
        ("ST", payload.get("state")),
        ("L", payload.get("locality")),
        ("O", payload.get("organization")),
        ("OU", payload.get("organizational_unit")),
        ("CN", payload.get("common_name")),
        ("emailAddress", payload.get("email")),
    ]
    parts: list[str] = []
    for key, value in fields:
        text = str(value or "").strip()
        if not text:
            continue
        safe = text.replace("/", "\\/")
        parts.append(f"/{key}={safe}")
    return "".join(parts) or "/CN=freeradius"


def parse_san_entries(raw_value: Any) -> list[str]:
    if raw_value is None:
        return []

    if isinstance(raw_value, str):
        values = [item.strip() for item in raw_value.split(",") if item.strip()]
    elif isinstance(raw_value, list):
        values = [str(item).strip() for item in raw_value if str(item).strip()]
    else:
        return []

    entries: list[str] = []
    for value in values:
        if ":" in value:
            entries.append(value)
        else:
            entries.append(f"DNS:{value}")
    return entries


def convert_uploaded_server_certificate(filename: str, raw_bytes: bytes) -> tuple[str | None, str]:
    suffix = Path(filename).suffix.lower()

    with tempfile.NamedTemporaryFile("wb", delete=False) as tmp:
        tmp.write(raw_bytes)
        tmp_path = Path(tmp.name)

    try:
        if suffix in {".p7b", ".p7c"}:
            pem = extract_pkcs7_to_pem(tmp_path)
            return pem, "pkcs7-to-pem"

        if suffix in {".der", ".cer"}:
            result = run_command(["openssl", "x509", "-inform", "DER", "-in", str(tmp_path), "-outform", "PEM"], check=False)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout, "der-to-pem"

        decoded = raw_bytes.decode("utf-8", errors="ignore")
        if "-----BEGIN CERTIFICATE-----" in decoded:
            return decoded, "pem"

        result = run_command(["openssl", "x509", "-inform", "DER", "-in", str(tmp_path), "-outform", "PEM"], check=False)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout, "der-to-pem"
        return None, "unknown"
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass


def extract_pkcs7_to_pem(path: Path) -> str | None:
    pem_result = run_command(["openssl", "pkcs7", "-print_certs", "-in", str(path)], check=False)
    output = pem_result.stdout if pem_result.returncode == 0 else ""

    if not output:
        der_result = run_command(["openssl", "pkcs7", "-inform", "DER", "-print_certs", "-in", str(path)], check=False)
        if der_result.returncode != 0:
            return None
        output = der_result.stdout

    blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", output, flags=re.DOTALL)
    if not blocks:
        return None
    return "\n".join(blocks) + "\n"


def is_under_directory(path: Path, directory: Path) -> bool:
    try:
        path.resolve().relative_to(directory.resolve())
        return True
    except ValueError:
        return False


def resolve_allowed_trusted_root_path(settings: AppSettings, raw_path: Any, allow_system: bool) -> Path | None:
    if not isinstance(raw_path, str) or not raw_path.strip():
        return None

    path = Path(raw_path.strip()).expanduser()
    if not path.is_absolute():
        path = path.resolve()
    if path.suffix.lower() not in {".crt", ".pem"}:
        return None

    custom_root = settings.trusted_root_dir.resolve()
    if is_under_directory(path, custom_root):
        return path.resolve()

    if allow_system:
        system_root = Path("/etc/ssl/certs").resolve()
        try:
            path.relative_to(system_root)
            return path
        except ValueError:
            pass

    return None


def read_certificate_details(path: Path) -> dict[str, Any]:
    command = [
        "openssl",
        "x509",
        "-in",
        str(path),
        "-noout",
        "-subject",
        "-issuer",
        "-serial",
        "-startdate",
        "-enddate",
        "-fingerprint",
        "-sha256",
    ]
    result = run_command(command, check=False)
    if result.returncode != 0:
        return {"error": result.stderr or result.stdout or "Unable to parse certificate."}

    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip().lower()] = value.strip()

    not_before = values.get("notbefore")
    not_after = values.get("notafter")
    not_after_dt = parse_openssl_datetime(not_after)

    days_remaining: int | None = None
    expired = False
    expiring_soon = False
    if not_after_dt:
        delta = not_after_dt - datetime.now(timezone.utc)
        days_remaining = int(delta.total_seconds() // 86400)
        expired = days_remaining < 0
        expiring_soon = 0 <= days_remaining <= 30

    return {
        "subject": values.get("subject"),
        "issuer": values.get("issuer"),
        "serial": values.get("serial"),
        "fingerprint": values.get("sha256 fingerprint"),
        "not_before": not_before,
        "not_after": not_after,
        "days_remaining": days_remaining,
        "expired": expired,
        "expiring_soon": expiring_soon,
        "raw": result.stdout,
    }


def parse_openssl_datetime(raw_value: str | None) -> datetime | None:
    if not raw_value:
        return None

    try:
        dt = datetime.strptime(raw_value.strip(), "%b %d %H:%M:%S %Y %Z")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def upsert_env_values(env_path: Path, values: dict[str, str]) -> None:
    env_path.parent.mkdir(parents=True, exist_ok=True)
    if env_path.exists():
        lines = env_path.read_text(encoding="utf-8").splitlines()
    else:
        lines = []

    keys = set(values.keys())
    seen: set[str] = set()
    updated_lines: list[str] = []

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            updated_lines.append(line)
            continue

        key, _ = line.split("=", 1)
        normalized_key = key.strip()
        if normalized_key in keys:
            updated_lines.append(f"{normalized_key}={values[normalized_key]}")
            seen.add(normalized_key)
        else:
            updated_lines.append(line)

    for key, value in values.items():
        if key not in seen:
            updated_lines.append(f"{key}={value}")

    env_path.write_text("\n".join(updated_lines) + "\n", encoding="utf-8")


SIMPLE_MOD_DESCRIPTIONS = {
    "eap": "802.1X / EAP authentication (PEAP, EAP-TLS, etc.).",
    "mschap": "MSCHAPv2 support for PEAP and NTLM-style auth.",
    "pap": "PAP authentication method.",
    "chap": "CHAP authentication method.",
    "files": "Read users and policy data from flat files.",
    "ldap": "LDAP directory integration for auth and lookups.",
    "sql": "SQL database integration for auth/accounting.",
    "linelog": "Write accounting/auth events to line-based logs.",
    "detail": "Detailed accounting and debugging output files.",
}

SIMPLE_SITE_DESCRIPTIONS = {
    "default": "Main RADIUS authentication and accounting virtual server.",
    "inner-tunnel": "Inner virtual server used by tunneled EAP methods.",
    "status": "Status virtual server for health/status checks.",
}

SIMPLE_CORE_RADIUSD_KEYS = {
    "max_request_time": "max_request_time",
    "cleanup_delay": "cleanup_delay",
    "max_requests": "max_requests",
    "hostname_lookups": "hostname_lookups",
}

SIMPLE_CORE_CLIENT_KEYS = {
    "ipaddr": "ipaddr",
    "secret": "secret",
    "nastype": "nastype",
    "require_message_authenticator": "require_message_authenticator",
}

SIMPLE_RADIUSD_OPTIONS: list[dict[str, Any]] = [
    {
        "key": "name",
        "directive": "name",
        "section": "global",
        "type": "text",
        "label": "Server name",
        "description": "Name of the running server instance.",
        "category": "Global",
    },
    {
        "key": "pidfile",
        "directive": "pidfile",
        "section": "global",
        "type": "text",
        "label": "PID file",
        "description": "Path where FreeRADIUS writes the PID in daemon mode.",
        "category": "Global",
    },
    {
        "key": "max_request_time",
        "directive": "max_request_time",
        "section": "global",
        "type": "number",
        "label": "max_request_time",
        "description": "Maximum seconds to process a request.",
        "category": "Global",
    },
    {
        "key": "max_requests",
        "directive": "max_requests",
        "section": "global",
        "type": "number",
        "label": "max_requests",
        "description": "Maximum in-flight requests tracked by server.",
        "category": "Global",
    },
    {
        "key": "reverse_lookups",
        "directive": "reverse_lookups",
        "section": "global",
        "type": "boolean",
        "label": "reverse_lookups",
        "description": "Resolve client IP addresses to names in logs.",
        "category": "Global",
    },
    {
        "key": "hostname_lookups",
        "directive": "hostname_lookups",
        "section": "global",
        "type": "boolean",
        "label": "hostname_lookups",
        "description": "Allow hostname resolution in configuration processing.",
        "category": "Global",
    },
    {
        "key": "log.destination",
        "directive": "destination",
        "section": "log",
        "type": "select",
        "choices": ["files", "syslog", "stdout", "stderr"],
        "label": "log.destination",
        "description": "Log output destination.",
        "category": "Logging",
    },
    {
        "key": "log.colourise",
        "directive": "colourise",
        "section": "log",
        "type": "boolean",
        "label": "log.colourise",
        "description": "Enable colourized logs on terminal outputs.",
        "category": "Logging",
    },
    {
        "key": "log.timestamp",
        "directive": "timestamp",
        "section": "log",
        "type": "boolean",
        "label": "log.timestamp",
        "description": "Force timestamps on/off for logs.",
        "category": "Logging",
    },
    {
        "key": "log.file",
        "directive": "file",
        "section": "log",
        "type": "text",
        "label": "log.file",
        "description": "Log file path when destination is files.",
        "category": "Logging",
    },
    {
        "key": "log.syslog_facility",
        "directive": "syslog_facility",
        "section": "log",
        "type": "text",
        "label": "log.syslog_facility",
        "description": "Syslog facility when destination is syslog.",
        "category": "Logging",
    },
    {
        "key": "security.allow_core_dumps",
        "directive": "allow_core_dumps",
        "section": "security",
        "type": "boolean",
        "label": "security.allow_core_dumps",
        "description": "Allow core dumps for debugging.",
        "category": "Security",
    },
    {
        "key": "security.max_attributes",
        "directive": "max_attributes",
        "section": "security",
        "type": "number",
        "label": "security.max_attributes",
        "description": "Max packet attributes before request drop.",
        "category": "Security",
    },
    {
        "key": "security.allow_vulnerable_openssl",
        "directive": "allow_vulnerable_openssl",
        "section": "security",
        "type": "boolean",
        "label": "security.allow_vulnerable_openssl",
        "description": "Allow startup with vulnerable OpenSSL versions.",
        "category": "Security",
    },
    {
        "key": "security.openssl_fips_mode",
        "directive": "openssl_fips_mode",
        "section": "security",
        "type": "boolean",
        "label": "security.openssl_fips_mode",
        "description": "Enable OpenSSL FIPS mode.",
        "category": "Security",
    },
    {
        "key": "thread_pool.num_workers",
        "directive": "num_workers",
        "section": "thread pool",
        "type": "number",
        "label": "thread_pool.num_workers",
        "description": "Number of worker threads.",
        "category": "Thread Pool",
    },
    {
        "key": "thread_pool.openssl_async_pool_init",
        "directive": "openssl_async_pool_init",
        "section": "thread pool",
        "type": "number",
        "label": "thread_pool.openssl_async_pool_init",
        "description": "Initial OpenSSL async contexts per worker.",
        "category": "Thread Pool",
    },
    {
        "key": "thread_pool.openssl_async_pool_max",
        "directive": "openssl_async_pool_max",
        "section": "thread pool",
        "type": "number",
        "label": "thread_pool.openssl_async_pool_max",
        "description": "Max OpenSSL async contexts per worker.",
        "category": "Thread Pool",
    },
]

SIMPLE_RADIUSD_OPTION_INDEX = {item["key"]: item for item in SIMPLE_RADIUSD_OPTIONS}


def make_simple_radiusd_option_key(section: str, directive: str) -> str:
    if section == "global":
        return directive
    return f"{section.replace(' ', '_')}.{directive}"


def infer_radiusd_option_type(value: str) -> str:
    text = value.strip().lower()
    if text in {"yes", "no", "true", "false", "1", "0", "on", "off"}:
        return "boolean"
    if re.fullmatch(r"\d+", text):
        return "number"
    return "text"


def parse_simple_radiusd_assignments(radiusd_content: str) -> dict[str, dict[str, str]]:
    assignments: dict[str, dict[str, str]] = {"global": {}}
    section_stack: list[str] = []

    for raw_line in radiusd_content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        open_match = re.match(r"^([A-Za-z0-9_.\- ]+)\s*\{\s*$", line)
        if open_match:
            section_name = open_match.group(1).strip()
            section_stack.append(section_name)
            continue

        if line == "}":
            if section_stack:
                section_stack.pop()
            continue

        assign_match = re.match(r"^([A-Za-z0-9_.\-]+)\s*=\s*(.*?)\s*(?:#.*)?$", line)
        if not assign_match:
            continue

        directive = assign_match.group(1).strip()
        value = assign_match.group(2).strip()

        section = section_stack[0] if section_stack else "global"
        if section not in assignments:
            assignments[section] = {}
        assignments[section][directive] = value

    return assignments


def parse_simple_radiusd_commented_assignments(radiusd_content: str) -> dict[str, dict[str, str]]:
    assignments: dict[str, dict[str, str]] = {"global": {}}
    section_stack: list[str] = []

    for raw_line in radiusd_content.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        open_match = re.match(r"^([A-Za-z0-9_.\- ]+)\s*\{\s*$", line)
        if open_match:
            section_name = open_match.group(1).strip()
            section_stack.append(section_name)
            continue

        if line == "}":
            if section_stack:
                section_stack.pop()
            continue

        commented_match = re.match(r"^#\s*([A-Za-z0-9_.\-]+)\s*=\s*(.*?)\s*(?:#.*)?$", line)
        if not commented_match:
            continue

        directive = commented_match.group(1).strip()
        value = commented_match.group(2).strip()
        section = section_stack[0] if section_stack else "global"

        if section not in assignments:
            assignments[section] = {}
        assignments[section].setdefault(directive, value)

    return assignments


def parse_simple_radiusd_structural_entries(radiusd_content: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []

    section_stack: list[str] = []
    include_index = 0
    for raw_line in radiusd_content.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        open_match = re.match(r"^([A-Za-z0-9_.\- ]+)\s*\{\s*$", line)
        if open_match and not line.startswith("#"):
            section_stack.append(open_match.group(1).strip())

        section = section_stack[0] if section_stack else "global"

        include_active = re.match(r"^\$INCLUDE\s+(.+)$", line)
        include_commented = re.match(r"^#\s*\$INCLUDE\s+(.+)$", line)
        if include_active or include_commented:
            include_index += 1
            target = (include_active or include_commented).group(1).strip()
            is_active = include_active is not None
            entries.append(
                {
                    "key": f"code.include.{section.replace(' ', '_').lower()}.{include_index}",
                    "directive": "$INCLUDE",
                    "section": section,
                    "type": "code",
                    "label": f"$INCLUDE {target}",
                    "description": "Include directive entry from radiusd.conf.",
                    "category": "Code",
                    "choices": [],
                    "value": line,
                    "active": is_active,
                    "source": "active" if is_active else "commented",
                    "editable": False,
                }
            )

        if line == "}" and section_stack:
            section_stack.pop()

    lines = radiusd_content.splitlines(keepends=True)
    depth = 0
    block_start_offset: int | None = None
    block_name = ""
    block_index = 0
    offset = 0

    for line in lines:
        stripped = line.strip()

        if block_start_offset is None and depth == 0 and stripped and not stripped.startswith("#"):
            block_match = re.match(r"^([A-Za-z0-9_.\- ]+)\s*\{\s*$", stripped)
            if block_match:
                block_start_offset = offset
                block_name = block_match.group(1).strip()

        if not stripped.startswith("#"):
            depth += line.count("{")
            depth -= line.count("}")

        if block_start_offset is not None and depth == 0:
            block_index += 1
            block_text = radiusd_content[block_start_offset : offset + len(line)].strip()
            entries.append(
                {
                    "key": f"code.block.{block_name.replace(' ', '_').lower()}.{block_index}",
                    "directive": block_name,
                    "section": "global",
                    "type": "code",
                    "label": f"{block_name} {{...}}",
                    "description": "Top-level code block entry from radiusd.conf.",
                    "category": "Code",
                    "choices": [],
                    "value": block_text,
                    "active": True,
                    "source": "active",
                    "editable": False,
                }
            )
            block_start_offset = None
            block_name = ""

        offset += len(line)

    return entries


def build_simple_config_snapshot(settings: AppSettings) -> dict[str, Any]:
    root = settings.freeradius_config_root
    core = read_simple_core_options(settings)
    mods = list_toggle_items(
        available_dir=root / "mods-available",
        enabled_dir=root / "mods-enabled",
        descriptions=SIMPLE_MOD_DESCRIPTIONS,
    )
    sites = list_toggle_items(
        available_dir=root / "sites-available",
        enabled_dir=root / "sites-enabled",
        descriptions=SIMPLE_SITE_DESCRIPTIONS,
    )
    return {
        "core": core,
        "mods": mods,
        "sites": sites,
    }


def read_simple_core_options(settings: AppSettings) -> dict[str, Any]:
    radiusd_path = settings.freeradius_config_root / "radiusd.conf"
    clients_path = settings.freeradius_config_root / "clients.conf"

    radiusd_text = radiusd_path.read_text(encoding="utf-8") if radiusd_path.exists() else ""
    clients_text = clients_path.read_text(encoding="utf-8") if clients_path.exists() else ""

    radiusd_values: dict[str, Any] = {}
    for key, source_key in SIMPLE_CORE_RADIUSD_KEYS.items():
        raw_value = extract_assignment_value(radiusd_text, source_key)
        if key == "hostname_lookups":
            radiusd_values[key] = (raw_value or "no").strip().lower() in {"yes", "true", "1"}
        else:
            radiusd_values[key] = (raw_value or "").strip()

    client_values: dict[str, Any] = {}
    localhost_block = extract_client_block(clients_text, "localhost")
    for key, source_key in SIMPLE_CORE_CLIENT_KEYS.items():
        raw_value = extract_assignment_value(localhost_block or "", source_key)
        if key == "require_message_authenticator":
            client_values[key] = (raw_value or "no").strip().lower() in {"yes", "true", "1"}
        else:
            client_values[key] = (raw_value or "").strip()

    if not client_values.get("ipaddr"):
        client_values["ipaddr"] = "127.0.0.1"
    if not client_values.get("nastype"):
        client_values["nastype"] = "other"

    return {
        "radiusd": radiusd_values,
        "clients": {
            "localhost": client_values,
        },
    }


def extract_assignment_value(content: str, key: str) -> str | None:
    pattern = re.compile(rf"(?m)^\s*{re.escape(key)}\s*=\s*([^#\n]+)")
    match = pattern.search(content)
    return match.group(1).strip() if match else None


def set_assignment_value(content: str, key: str, value: str) -> tuple[str, bool]:
    pattern = re.compile(rf"(?m)^(\s*{re.escape(key)}\s*=\s*)([^#\n]+)(.*)$")

    def replace(match: re.Match[str]) -> str:
        return f"{match.group(1)}{value}{match.group(3)}"

    updated, count = pattern.subn(replace, content, count=1)
    if count > 0:
        return updated, True

    suffix = "" if content.endswith("\n") or not content else "\n"
    return f"{content}{suffix}{key} = {value}\n", True


def set_assignment_value_with_indent(content: str, key: str, value: str, indent: str) -> tuple[str, bool]:
    pattern = re.compile(rf"(?m)^(\s*{re.escape(key)}\s*=\s*)([^#\n]+)(.*)$")

    def replace(match: re.Match[str]) -> str:
        return f"{match.group(1)}{value}{match.group(3)}"

    updated, count = pattern.subn(replace, content, count=1)
    if count > 0:
        return updated, True

    suffix = "" if content.endswith("\n") or not content else "\n"
    return f"{content}{suffix}{indent}{key} = {value}\n", True


def extract_named_block(content: str, section_name: str) -> dict[str, Any] | None:
    pattern = re.compile(rf"(?m)^\s*{re.escape(section_name)}\s*\{{")
    match = pattern.search(content)
    if not match:
        return None

    open_brace_index = content.find("{", match.start())
    if open_brace_index == -1:
        return None

    depth = 0
    end_index = None
    for index in range(open_brace_index, len(content)):
        char = content[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                end_index = index + 1
                break

    if end_index is None:
        return None

    return {
        "start": match.start(),
        "body_start": open_brace_index + 1,
        "body_end": end_index - 1,
        "end": end_index,
        "body": content[open_brace_index + 1 : end_index - 1],
    }


def set_block_assignment_value(content: str, section_name: str, key: str, value: str) -> str:
    block = extract_named_block(content, section_name)
    if not block:
        suffix = "" if not content.strip() or content.endswith("\n") else "\n"
        return f"{content}{suffix}\n{section_name} {{\n\t{key} = {value}\n}}\n"

    updated_body, _ = set_assignment_value(block["body"], key, value)
    return f"{content[:block['body_start']]}{updated_body}{content[block['body_end']:] }"


def set_directive_active_in_body(content: str, key: str, active: bool, value: str, default_indent: str) -> str:
    active_pattern = re.compile(rf"(?m)^(\s*){re.escape(key)}\s*=\s*(.*)$")
    commented_pattern = re.compile(rf"(?m)^(\s*)#\s*{re.escape(key)}\s*=\s*(.*)$")

    if active:
        if active_pattern.search(content):
            return content
        commented_match = commented_pattern.search(content)
        if commented_match:
            def uncomment(match: re.Match[str]) -> str:
                return f"{match.group(1)}{key} = {match.group(2)}"

            return commented_pattern.sub(uncomment, content, count=1)

        updated, _ = set_assignment_value_with_indent(content, key, value, default_indent)
        return updated

    if commented_pattern.search(content):
        return content

    def comment(match: re.Match[str]) -> str:
        return f"{match.group(1)}# {key} = {match.group(2)}"

    updated, _ = active_pattern.subn(comment, content, count=1)
    return updated


def set_block_directive_active(content: str, section_name: str, key: str, active: bool, value: str) -> str:
    block = extract_named_block(content, section_name)
    if not block:
        if not active:
            return content
        suffix = "" if not content.strip() or content.endswith("\n") else "\n"
        return f"{content}{suffix}\n{section_name} {{\n\t{key} = {value}\n}}\n"

    updated_body = set_directive_active_in_body(
        content=block["body"],
        key=key,
        active=active,
        value=value,
        default_indent="\t",
    )
    return f"{content[:block['body_start']]}{updated_body}{content[block['body_end']:] }"


def build_simple_radiusd_options(radiusd_content: str) -> list[dict[str, Any]]:
    parsed_assignments = parse_simple_radiusd_assignments(radiusd_content)
    parsed_commented_assignments = parse_simple_radiusd_commented_assignments(radiusd_content)
    structural_entries = parse_simple_radiusd_structural_entries(radiusd_content)

    result: list[dict[str, Any]] = []
    for option in SIMPLE_RADIUSD_OPTIONS:
        section = option["section"]
        directive = option["directive"]

        raw_value = parsed_assignments.get(section, {}).get(directive)
        is_active = raw_value is not None
        if raw_value is None:
            raw_value = parsed_commented_assignments.get(section, {}).get(directive)

        value = (raw_value or "").strip()
        if option["type"] == "boolean" and value:
            value = "yes" if value.lower() in {"yes", "true", "1", "on"} else "no"

        result.append(
            {
                "key": option["key"],
                "directive": directive,
                "section": section,
                "type": option["type"],
                "label": option["label"],
                "description": option["description"],
                "category": option["category"],
                "choices": option.get("choices", []),
                "value": value,
                "active": is_active,
                "source": "active" if is_active else ("commented" if value else "missing"),
                "editable": True,
            }
        )

    known_keys = {item["key"] for item in result}
    for section_name, directives in parsed_assignments.items():
        for directive, raw_value in directives.items():
            key = make_simple_radiusd_option_key(section_name, directive)
            if key in known_keys:
                continue

            inferred_type = infer_radiusd_option_type(raw_value)
            normalized_value = raw_value.strip()
            if inferred_type == "boolean" and normalized_value:
                normalized_value = "yes" if normalized_value.lower() in {"yes", "true", "1", "on"} else "no"

            result.append(
                {
                    "key": key,
                    "directive": directive,
                    "section": section_name,
                    "type": inferred_type,
                    "label": key,
                    "description": "Discovered from current radiusd.conf.",
                    "category": "Global" if section_name == "global" else section_name.title(),
                    "choices": [],
                    "value": normalized_value,
                    "active": True,
                    "source": "active",
                    "editable": True,
                }
            )
            known_keys.add(key)

    for section_name, directives in parsed_commented_assignments.items():
        for directive, raw_value in directives.items():
            key = make_simple_radiusd_option_key(section_name, directive)
            if key in known_keys:
                continue

            inferred_type = infer_radiusd_option_type(raw_value)
            normalized_value = raw_value.strip()
            if inferred_type == "boolean" and normalized_value:
                normalized_value = "yes" if normalized_value.lower() in {"yes", "true", "1", "on"} else "no"

            result.append(
                {
                    "key": key,
                    "directive": directive,
                    "section": section_name,
                    "type": inferred_type,
                    "label": key,
                    "description": "Discovered from commented/default radiusd.conf entry.",
                    "category": "Global" if section_name == "global" else section_name.title(),
                    "choices": [],
                    "value": normalized_value,
                    "active": False,
                    "source": "commented",
                    "editable": True,
                }
            )
            known_keys.add(key)

    for entry in structural_entries:
        entry_key = str(entry.get("key", "")).strip()
        if not entry_key or entry_key in known_keys:
            continue
        result.append(entry)
        known_keys.add(entry_key)

    result.sort(key=lambda item: (item["category"], item["source"] != "active", item["label"]))
    return result


def build_simple_radiusd_option_index(radiusd_content: str) -> dict[str, dict[str, Any]]:
    options = build_simple_radiusd_options(radiusd_content)
    return {item["key"]: item for item in options}


def extract_client_block(content: str, client_name: str) -> str | None:
    pattern = re.compile(rf"client\s+{re.escape(client_name)}\s*\{{(.*?)\}}", flags=re.DOTALL)
    match = pattern.search(content)
    return match.group(1) if match else None


def set_client_block_values(content: str, client_name: str, updates: dict[str, str]) -> tuple[str, dict[str, str]]:
    pattern = re.compile(rf"(client\s+{re.escape(client_name)}\s*\{{)(.*?)(\}})", flags=re.DOTALL)
    match = pattern.search(content)
    applied = dict(updates)

    if not match:
        lines = [f"\t{key} = {value}" for key, value in updates.items()]
        block = f"\nclient {client_name} {{\n" + "\n".join(lines) + "\n}\n"
        return content + block, applied

    block_body = match.group(2)
    for key, value in updates.items():
        block_body, _ = set_assignment_value(block_body, key, value)

    updated_content = content[: match.start()] + match.group(1) + block_body + match.group(3) + content[match.end() :]
    return updated_content, applied


def resolve_simple_clients_config_files(config_root: Path, clients_path: Path) -> list[Path]:
    to_visit: list[Path] = [clients_path.resolve()]
    visited: set[str] = set()
    result: list[Path] = []

    include_pattern = re.compile(r"(?m)^\s*\$INCLUDE\s+([^\n#]+)")
    while to_visit:
        path = to_visit.pop(0)
        path_key = str(path)
        if path_key in visited:
            continue
        visited.add(path_key)
        result.append(path)

        if not path.exists() or not path.is_file():
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            continue

        for include_match in include_pattern.finditer(content):
            include_raw = include_match.group(1).strip().strip('"').strip("'")
            if not include_raw:
                continue

            include_path = Path(include_raw)
            if not include_path.is_absolute():
                include_path = (config_root / include_path).resolve()

            include_values: list[Path] = []
            if any(char in include_raw for char in ["*", "?", "["]):
                include_values = sorted(path for path in config_root.glob(include_raw) if path.is_file())
            elif include_path.is_dir():
                include_values = sorted(path for path in include_path.iterdir() if path.is_file())
            else:
                include_values = [include_path]

            for include_item in include_values:
                resolved = include_item.resolve()
                if is_under_directory(resolved, config_root) and str(resolved) not in visited:
                    to_visit.append(resolved)

    return [item for item in result if is_under_directory(item, config_root)]


def parse_client_blocks(content: str) -> list[dict[str, Any]]:
    start_pattern = re.compile(r"(?m)^\s*client\s+([^\s\{]+)\s*\{")
    blocks: list[dict[str, Any]] = []

    for block_index, match in enumerate(start_pattern.finditer(content)):
        open_brace_index = content.find("{", match.start())
        if open_brace_index == -1:
            continue

        depth = 0
        end_index = None
        for index in range(open_brace_index, len(content)):
            char = content[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    end_index = index + 1
                    break

        if end_index is None:
            continue

        body = content[open_brace_index + 1 : end_index - 1]
        blocks.append(
            {
                "name": match.group(1).strip(),
                "start": match.start(),
                "end": end_index,
                "body": body,
                "index": block_index,
            }
        )

    return blocks


def parse_simple_client_fields(body: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    keys = [
        "ipaddr",
        "ipv4addr",
        "ipv6addr",
        "secret",
        "nastype",
        "shortname",
        "proto",
        "virtual_server",
    ]
    for key in keys:
        result[key] = (extract_assignment_value(body, key) or "").strip()

    require_ma_raw = extract_assignment_value(body, "require_message_authenticator") or ""
    result["require_message_authenticator"] = require_ma_raw.strip().lower() in {"yes", "true", "1"}

    limit_block_match = re.search(r"limit\s*\{(.*?)\}", body, flags=re.DOTALL)
    limit_data: dict[str, str] = {}
    if limit_block_match:
        limit_body = limit_block_match.group(1)
        for key in ["max_connections", "lifetime", "idle_timeout"]:
            value = extract_assignment_value(limit_body, key)
            if value:
                limit_data[key] = value.strip()
    result["limit"] = limit_data
    return result


def sanitize_simple_client_entry(client: dict[str, Any], include_secrets: bool) -> dict[str, Any]:
    sanitized = dict(client)
    secret_value = str(sanitized.get("secret", ""))
    sanitized["has_secret"] = bool(secret_value)
    sanitized["secret"] = secret_value if include_secrets else ""
    return sanitized


def normalize_simple_client_payload(payload: dict[str, Any], require_secret: bool) -> tuple[dict[str, Any], str | None]:
    client_data: dict[str, Any] = {
        "ipaddr": str(payload.get("ipaddr", "")).strip(),
        "ipv4addr": str(payload.get("ipv4addr", "")).strip(),
        "ipv6addr": str(payload.get("ipv6addr", "")).strip(),
        "secret": str(payload.get("secret", "")).strip(),
        "nastype": str(payload.get("nastype", "")).strip() or "other",
        "shortname": str(payload.get("shortname", "")).strip(),
        "proto": str(payload.get("proto", "")).strip(),
        "virtual_server": str(payload.get("virtual_server", "")).strip(),
        "require_message_authenticator": bool(payload.get("require_message_authenticator", False)),
        "limit": {
            "max_connections": str(payload.get("limit_max_connections", "")).strip(),
            "lifetime": str(payload.get("limit_lifetime", "")).strip(),
            "idle_timeout": str(payload.get("limit_idle_timeout", "")).strip(),
        },
    }

    if not any([client_data["ipaddr"], client_data["ipv4addr"], client_data["ipv6addr"]]):
        return client_data, "At least one of ipaddr, ipv4addr, or ipv6addr is required."
    if require_secret and not client_data["secret"]:
        return client_data, "Client secret is required."
    return client_data, None


def render_simple_client_block(client_name: str, client_data: dict[str, Any]) -> str:
    lines = [f"client {client_name} {{"]

    for key in ["ipaddr", "ipv4addr", "ipv6addr", "secret", "nastype", "shortname", "proto", "virtual_server"]:
        value = str(client_data.get(key, "")).strip()
        if value:
            lines.append(f"\t{key} = {value}")

    lines.append(
        f"\trequire_message_authenticator = {'yes' if bool(client_data.get('require_message_authenticator')) else 'no'}"
    )

    limit = client_data.get("limit", {}) if isinstance(client_data.get("limit"), dict) else {}
    limit_lines = []
    for key in ["max_connections", "lifetime", "idle_timeout"]:
        value = str(limit.get(key, "")).strip()
        if value:
            limit_lines.append(f"\t\t{key} = {value}")
    if limit_lines:
        lines.append("\tlimit {")
        lines.extend(limit_lines)
        lines.append("\t}")

    lines.append("}")
    return "\n".join(lines)


def encode_simple_client_id(path: Path, name: str, block_index: int) -> str:
    raw = f"{path.resolve()}|{name}|{block_index}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_simple_client_id(client_id: str) -> dict[str, Any]:
    padded = client_id + "=" * (-len(client_id) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        raise ValueError("Invalid client id.")

    parts = decoded.split("|", 2)
    if len(parts) != 3:
        raise ValueError("Invalid client id.")

    path_raw, name, block_index_raw = parts
    try:
        block_index = int(block_index_raw)
    except ValueError:
        raise ValueError("Invalid client id.")

    return {
        "path": Path(path_raw).resolve(),
        "name": name,
        "block_index": block_index,
    }


def locate_client_block(blocks: list[dict[str, Any]], decoded_id: dict[str, Any]) -> dict[str, Any] | None:
    block_index = decoded_id["block_index"]
    if 0 <= block_index < len(blocks):
        block = blocks[block_index]
        if block["name"] == decoded_id["name"]:
            return block

    for block in blocks:
        if block["name"] == decoded_id["name"]:
            return block
    return None


def is_allowed_simple_clients_path(settings: AppSettings, path: Path) -> bool:
    root = settings.freeradius_config_root.resolve()
    if not is_under_directory(path.resolve(), root):
        return False
    allowed_sources = resolve_simple_clients_config_files(root, root / "clients.conf")
    return str(path.resolve()) in {str(item.resolve()) for item in allowed_sources}


def build_simple_clients_index(settings: AppSettings, include_secrets: bool = False) -> list[dict[str, Any]]:
    root = settings.freeradius_config_root.resolve()
    clients_path = (root / "clients.conf").resolve()
    files = resolve_simple_clients_config_files(root, clients_path)

    entries: list[dict[str, Any]] = []
    for source_file in files:
        try:
            content = source_file.read_text(encoding="utf-8") if source_file.exists() else ""
        except OSError:
            continue

        blocks = parse_client_blocks(content)
        for block in blocks:
            fields = parse_simple_client_fields(block["body"])
            entries.append(
                {
                    "id": encode_simple_client_id(source_file, block["name"], block["index"]),
                    "name": block["name"],
                    "source_path": str(source_file),
                    "source_file": source_file.name,
                    "ipaddr": fields.get("ipaddr", ""),
                    "ipv4addr": fields.get("ipv4addr", ""),
                    "ipv6addr": fields.get("ipv6addr", ""),
                    "secret": fields.get("secret", ""),
                    "nastype": fields.get("nastype", ""),
                    "shortname": fields.get("shortname", ""),
                    "proto": fields.get("proto", ""),
                    "virtual_server": fields.get("virtual_server", ""),
                    "require_message_authenticator": fields.get("require_message_authenticator", False),
                    "limit": fields.get("limit", {}),
                }
            )

    entries.sort(key=lambda item: (item["name"].lower(), item["source_file"].lower()))
    return [sanitize_simple_client_entry(item, include_secrets) for item in entries]


def find_simple_client_by_id(settings: AppSettings, client_id: str, include_secrets: bool = False) -> dict[str, Any] | None:
    target_id = client_id.strip()
    if not target_id:
        raise ValueError("Client id is required.")
    clients = build_simple_clients_index(settings, include_secrets=include_secrets)
    for client in clients:
        if client["id"] == target_id:
            return client
    return None


def list_toggle_items(available_dir: Path, enabled_dir: Path, descriptions: dict[str, str]) -> list[dict[str, Any]]:
    if not available_dir.exists() or not available_dir.is_dir():
        return []

    items: list[dict[str, Any]] = []
    for path in sorted(available_dir.iterdir()):
        if path.name.startswith("."):
            continue
        if not path.is_file() and not path.is_symlink():
            continue

        enabled_path = enabled_dir / path.name
        enabled = enabled_path.exists() or enabled_path.is_symlink()
        items.append(
            {
                "name": path.name,
                "enabled": enabled,
                "description": descriptions.get(path.name, ""),
                "featured": path.name in descriptions,
            }
        )

    items.sort(key=lambda item: (not item["featured"], item["name"].lower()))
    return items


def capture_toggle_state(path: Path) -> dict[str, Any]:
    state: dict[str, Any] = {"path": path}
    if path.is_symlink():
        state["kind"] = "symlink"
        state["target"] = os.readlink(path)
        return state

    if path.exists():
        if path.is_dir():
            raise ValueError(f"Cannot manage directory entry: {path}")
        state["kind"] = "file"
        state["backup"] = str(backup_file(path))
        return state

    state["kind"] = "missing"
    return state


def apply_toggle_selections(
    selections: dict[str, Any],
    available_dir: Path,
    enabled_dir: Path,
    group_label: str,
    state_snapshots: list[dict[str, Any]],
    changes: list[str],
) -> None:
    enabled_dir.mkdir(parents=True, exist_ok=True)

    for name, value in selections.items():
        if not isinstance(name, str):
            continue
        should_enable = bool(value)

        available_path = available_dir / name
        enabled_path = enabled_dir / name
        state_snapshots.append(capture_toggle_state(enabled_path))

        currently_enabled = enabled_path.exists() or enabled_path.is_symlink()
        if should_enable and currently_enabled:
            continue
        if not should_enable and not currently_enabled:
            continue

        if should_enable:
            if not available_path.exists():
                raise ValueError(f"Cannot enable {group_label} '{name}': not found in available directory.")
            if enabled_path.exists() and not enabled_path.is_symlink():
                raise ValueError(f"Cannot enable {group_label} '{name}': enabled entry is a regular file.")
            if enabled_path.is_symlink():
                enabled_path.unlink()
            enabled_path.symlink_to(available_path)
            changes.append(f"Enabled {group_label}: {name}")
            continue

        if enabled_path.is_symlink() or enabled_path.exists():
            enabled_path.unlink()
            changes.append(f"Disabled {group_label}: {name}")


def rollback_toggle_changes(state_snapshots: list[dict[str, Any]]) -> None:
    for state in reversed(state_snapshots):
        path = state["path"]
        try:
            if path.is_symlink() or path.exists():
                if path.is_file() or path.is_symlink():
                    path.unlink()

            kind = state.get("kind")
            if kind == "symlink":
                path.parent.mkdir(parents=True, exist_ok=True)
                path.symlink_to(state["target"])
            elif kind == "file":
                backup = Path(state["backup"])
                if backup.exists():
                    restore_file(backup, path)
        except OSError:
            continue


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")), debug=False)
