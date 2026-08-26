import secrets
from functools import wraps

from flask import Blueprint, current_app, jsonify, redirect, render_template, request, session, url_for

from .db import (
    acknowledge_alert, add_target, dashboard_data, delete_target, get_user,
    login_failures, recent_checks, record_event, record_login_attempt,
    set_target_enabled,
)
from .security import client_key, now, verify_password

bp = Blueprint("main", __name__)


def db_path():
    return current_app.config["DB_PATH"]


def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            if request.path.startswith("/api/") or request.is_json:
                return jsonify({"error": "authentication required"}), 401
            return redirect(url_for("main.login"))
        return fn(*args, **kwargs)
    return wrapped


def json_or_form(name, default=None):
    data = request.get_json(silent=True) or request.form
    return data.get(name, default)


def ensure_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)


@bp.before_request
def csrf_guard():
    ensure_csrf_token()
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.endpoint != "main.login":
        if "user_id" not in session:
            return None
        provided = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
        if not provided or not secrets.compare_digest(provided, session["csrf_token"]):
            return jsonify({"error": "invalid CSRF token"}), 400
    return None


@bp.app_context_processor
def inject_security_context():
    ensure_csrf_token()
    return {"csrf_token": session.get("csrf_token")}


@bp.get("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("main.login"))
    targets, events, alerts, total, up = dashboard_data(db_path())
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
    database = db_path()
    config = current_app.config

    if login_failures(database, key, current - config["LOCKOUT_SECONDS"]) >= config["MAX_LOGIN_ATTEMPTS"]:
        record_event(database, "login_blocked", "warning", ip, "Login temporarily blocked after repeated failures")
        return render_template("login.html", error="Too many failed attempts. Try again later."), 429

    user = get_user(database, username)
    success = bool(user and verify_password(password, user["password_hash"]))
    record_login_attempt(database, key, success, current)

    if not success:
        record_event(database, "login_failure", "warning", ip, "Invalid username or password")
        return render_template("login.html", error="Invalid username or password."), 401

    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["csrf_token"] = secrets.token_urlsafe(32)
    record_event(database, "login_success", "info", ip, "User authenticated")
    return redirect(url_for("main.index"))


@bp.post("/logout")
@login_required
def logout():
    record_event(db_path(), "logout", "info", request.remote_addr, "User logged out")
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
    database = db_path()
    target_id = add_target(database, name, host, port)
    record_event(database, "target_added", "info", request.remote_addr, f"Monitoring target {name}")
    return jsonify({"id": target_id, "message": "target created"}), 201


@bp.post("/targets/<int:target_id>/toggle")
@login_required
def toggle_target(target_id):
    enabled = str(json_or_form("enabled", "1")).lower() in {"1", "true", "on"}
    set_target_enabled(db_path(), target_id, enabled)
    return jsonify({"message": "updated", "enabled": enabled})


@bp.delete("/targets/<int:target_id>")
@login_required
def remove_target(target_id):
    database = db_path()
    delete_target(database, target_id)
    record_event(database, "target_removed", "info", request.remote_addr, f"Monitoring target {target_id} removed")
    return jsonify({"message": "deleted"})


@bp.post("/alerts/<int:alert_id>/ack")
@login_required
def ack_alert(alert_id):
    acknowledge_alert(db_path(), alert_id)
    return jsonify({"message": "acknowledged"})


@bp.get("/api/overview")
@login_required
def overview_api():
    targets, events, alerts, total, up = dashboard_data(db_path())
    return jsonify({
        "summary": {"total": total, "up": up, "down": max(total - up, 0)},
        "targets": [dict(row) for row in targets],
        "alerts": [dict(row) for row in alerts],
        "events": [dict(row) for row in events],
    })


@bp.get("/api/targets/<int:target_id>/history")
@login_required
def history_api(target_id):
    return jsonify([dict(row) for row in recent_checks(db_path(), target_id)])
