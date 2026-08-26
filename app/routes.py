from functools import wraps

from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for

from .config import Config
from .db import (
    acknowledge_alert, add_target, dashboard_data, delete_target, get_user,
    login_failures, recent_checks, record_event, record_login_attempt,
    set_target_enabled,
)
from .security import client_key, now, verify_password

bp = Blueprint("main", __name__)


def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"error": "authentication required"}), 401
            return redirect(url_for("main.login"))
        return fn(*args, **kwargs)
    return wrapped


def json_or_form(name, default=None):
    data = request.get_json(silent=True) or request.form
    return data.get(name, default)


@bp.get("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("main.login"))
    targets, events, alerts, total, up = dashboard_data(Config.DB_PATH)
    return render_template("dashboard.html", targets=targets, events=events, alerts=alerts, total=total, up=up)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    ip = request.remote_addr or "unknown"
    key = client_key(ip)
    current = now()

    if login_failures(Config.DB_PATH, key, current - Config.LOCKOUT_SECONDS) >= Config.MAX_LOGIN_ATTEMPTS:
        record_event(Config.DB_PATH, "login_blocked", "warning", ip, "Login temporarily blocked after repeated failures")
        return render_template("login.html", error="Too many failed attempts. Try again later."), 429

    user = get_user(Config.DB_PATH, username)
    success = bool(user and verify_password(password, user["password_hash"]))
    record_login_attempt(Config.DB_PATH, key, success, current)

    if not success:
        record_event(Config.DB_PATH, "login_failure", "warning", ip, "Invalid username or password")
        return render_template("login.html", error="Invalid username or password."), 401

    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    record_event(Config.DB_PATH, "login_success", "info", ip, "User authenticated")
    return redirect(url_for("main.index"))


@bp.post("/logout")
@login_required
def logout():
    record_event(Config.DB_PATH, "logout", "info", request.remote_addr, "User logged out")
    session.clear()
    return redirect(url_for("main.login"))


@bp.post("/targets")
@login_required
def create_target():
    name = (json_or_form("name") or "").strip()
    host = (json_or_form("host") or "").strip()
    try:
        port = int(json_or_form("port"))
    except (TypeError, ValueError):
        return jsonify({"error": "port must be an integer"}), 400
    if not name or not host or not (1 <= port <= 65535) or len(name) > 100 or len(host) > 255:
        return jsonify({"error": "invalid target"}), 400
    target_id = add_target(Config.DB_PATH, name, host, port)
    record_event(Config.DB_PATH, "target_added", "info", request.remote_addr, f"Monitoring target {name}")
    return jsonify({"id": target_id, "message": "target created"}), 201


@bp.post("/targets/<int:target_id>/toggle")
@login_required
def toggle_target(target_id):
    enabled = str(json_or_form("enabled", "1")).lower() in {"1", "true", "on"}
    set_target_enabled(Config.DB_PATH, target_id, enabled)
    return jsonify({"message": "updated", "enabled": enabled})


@bp.delete("/targets/<int:target_id>")
@login_required
def remove_target(target_id):
    delete_target(Config.DB_PATH, target_id)
    record_event(Config.DB_PATH, "target_removed", "info", request.remote_addr, f"Monitoring target {target_id} removed")
    return jsonify({"message": "deleted"})


@bp.post("/alerts/<int:alert_id>/ack")
@login_required
def ack_alert(alert_id):
    acknowledge_alert(Config.DB_PATH, alert_id)
    return jsonify({"message": "acknowledged"})


@bp.get("/api/overview")
@login_required
def overview_api():
    targets, events, alerts, total, up = dashboard_data(Config.DB_PATH)
    return jsonify({
        "summary": {"total": total, "up": up, "down": max(total - up, 0)},
        "targets": [dict(row) for row in targets],
        "alerts": [dict(row) for row in alerts],
        "events": [dict(row) for row in events],
    })


@bp.get("/api/targets/<int:target_id>/history")
@login_required
def history_api(target_id):
    return jsonify([dict(row) for row in recent_checks(Config.DB_PATH, target_id)])
