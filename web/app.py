import datetime
import json
import logging
import os
import sys
import threading

# Добавляем корень проекта в путь
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, jsonify, request, Response, redirect, url_for, session
from config import get_config
from database import get_db, Database
from auth import (
    init_auth, authenticate, get_current_user, logout,
    login_required, admin_required, change_password,
    add_user, delete_user, toggle_user, list_users
)

logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.urandom(32)


def row_to_dict(obj):
    """Конвертация SQLAlchemy объекта в словарь."""
    if obj is None:
        return None
    d = {}
    for c in obj.__table__.columns:
        val = getattr(obj, c.name)
        if isinstance(val, datetime.datetime):
            val = val.strftime("%Y-%m-%d %H:%M:%S")
        d[c.name] = val
    return d


# ======== Аутентификация ========

@app.route("/login", methods=["GET"])
def login_page():
    user = get_current_user()
    if user:
        return redirect("/")
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login_action():
    data = request.form if request.form else request.json or {}
    username = data.get("username", "")
    password = data.get("password", "")
    token = authenticate(username, password)
    if token:
        session["auth_token"] = token
        session.permanent = True
        if request.is_json:
            return jsonify({"status": "ok", "token": token})
        return redirect("/")
    if request.is_json:
        return jsonify({"status": "error", "message": "Неверное имя пользователя или пароль"}), 401
    return render_template("login.html", error="Неверное имя пользователя или пароль")


@app.route("/logout")
def logout_action():
    logout()
    session.pop("auth_token", None)
    return redirect("/login")


@app.before_request
def check_auth():
    """Проверка аутентификации для всех маршрутов, кроме login и static."""
    open_paths = {"/login", "/static/"}
    path = request.path
    if path == "/login" or path.startswith("/static/"):
        return
    # API-запросы могут использовать заголовок Authorization
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        from auth import _session_tokens
        token = auth_header[7:]
        if token in _session_tokens:
            return
    if "auth_token" not in session:
        return redirect("/login")


# ======== Страницы ========

@app.route("/")
@login_required
def index():
    return render_template("dashboard.html")


@app.route("/access-denied")
@login_required
def access_denied_page():
    return render_template("access_denied.html")


@app.route("/clipboard")
@login_required
def clipboard_page():
    return render_template("clipboard.html")


@app.route("/file-operations")
@login_required
def file_ops_page():
    return render_template("file_operations.html")


@app.route("/login-events")
@login_required
def login_events_page():
    return render_template("login_events.html")


@app.route("/alerts")
@login_required
def alerts_page():
    return render_template("alerts.html")


@app.route("/sessions")
@login_required
def sessions_page():
    return render_template("sessions.html")


@app.route("/settings")
@admin_required
def settings_page():
    return render_template("settings.html")


@app.route("/risk-assessment")
@login_required
def risk_page():
    return render_template("risk.html")


@app.route("/reports")
@login_required
def reports_page():
    return render_template("reports.html")


@app.route("/users")
@admin_required
def users_page():
    return render_template("users.html")


# ======== API ========

@app.route("/api/stats")
@login_required
def api_stats():
    db = get_db()
    hours = request.args.get("hours", 24, type=int)
    stats = db.get_stats(hours=hours)
    return jsonify(stats)


@app.route("/api/user-stats")
@login_required
def api_user_stats():
    db = get_db()
    hours = request.args.get("hours", 24, type=int)
    stats = db.get_user_stats(hours=hours)
    return jsonify(stats)


@app.route("/api/timeline")
@login_required
def api_timeline():
    db = get_db()
    hours = request.args.get("hours", 24, type=int)
    timeline = db.get_timeline(hours=hours)
    return jsonify(timeline)


@app.route("/api/access-denied")
@login_required
def api_access_denied():
    db = get_db()
    limit = request.args.get("limit", 200, type=int)
    offset = request.args.get("offset", 0, type=int)
    username = request.args.get("username")
    events = db.get_access_denied(limit=limit, offset=offset, username=username)
    return jsonify([row_to_dict(e) for e in events])


@app.route("/api/clipboard")
@login_required
def api_clipboard():
    db = get_db()
    limit = request.args.get("limit", 200, type=int)
    offset = request.args.get("offset", 0, type=int)
    username = request.args.get("username")
    suspicious = request.args.get("suspicious", "").lower() == "true"
    events = db.get_clipboard_events(limit=limit, offset=offset, username=username, suspicious_only=suspicious)
    return jsonify([row_to_dict(e) for e in events])


@app.route("/api/file-operations")
@login_required
def api_file_operations():
    db = get_db()
    limit = request.args.get("limit", 200, type=int)
    offset = request.args.get("offset", 0, type=int)
    username = request.args.get("username")
    operation = request.args.get("operation")
    events = db.get_file_operations(limit=limit, offset=offset, username=username, operation=operation)
    return jsonify([row_to_dict(e) for e in events])


@app.route("/api/login-events")
@login_required
def api_login_events():
    db = get_db()
    limit = request.args.get("limit", 200, type=int)
    offset = request.args.get("offset", 0, type=int)
    username = request.args.get("username")
    event_type = request.args.get("event_type")
    events = db.get_login_events(limit=limit, offset=offset, username=username, event_type=event_type)
    return jsonify([row_to_dict(e) for e in events])


@app.route("/api/alerts")
@login_required
def api_alerts():
    db = get_db()
    limit = request.args.get("limit", 100, type=int)
    unread = request.args.get("unread", "").lower() == "true"
    alerts = db.get_alerts(limit=limit, unread_only=unread)
    return jsonify([row_to_dict(a) for a in alerts])


@app.route("/api/alerts/<int:alert_id>/acknowledge", methods=["POST"])
@login_required
def api_acknowledge_alert(alert_id):
    db = get_db()
    db.acknowledge_alert(alert_id)
    return jsonify({"status": "ok"})


@app.route("/api/alerts/acknowledge-all", methods=["POST"])
@login_required
def api_acknowledge_all_alerts():
    db = get_db()
    alerts = db.get_alerts(limit=10000, unread_only=True)
    for a in alerts:
        db.acknowledge_alert(a.id)
    return jsonify({"status": "ok", "count": len(alerts)})


@app.route("/api/sessions")
@login_required
def api_sessions():
    db = get_db()
    sessions = db.get_active_sessions()
    return jsonify([row_to_dict(s) for s in sessions])


@app.route("/api/config", methods=["GET"])
@admin_required
def api_get_config():
    cfg = get_config()
    return jsonify(cfg.all)


@app.route("/api/config", methods=["POST"])
@admin_required
def api_set_config():
    cfg = get_config()
    data = request.json
    if data:
        for key, value in data.items():
            cfg.set(key, value)
    return jsonify({"status": "ok"})


# ======== Risk API ========

@app.route("/api/risk/summary")
@login_required
def api_risk_summary():
    from risk_engine import get_risk_summary
    hours = request.args.get("hours", 24, type=int)
    return jsonify(get_risk_summary(hours))


@app.route("/api/risk/user/<username>")
@login_required
def api_risk_user(username):
    from risk_engine import calculate_user_risk
    hours = request.args.get("hours", 24, type=int)
    return jsonify(calculate_user_risk(username, hours))


@app.route("/api/risk/all")
@login_required
def api_risk_all():
    from risk_engine import calculate_all_users_risk
    hours = request.args.get("hours", 24, type=int)
    return jsonify(calculate_all_users_risk(hours))


# ======== Reports API ========

@app.route("/api/reports/generate", methods=["POST"])
@login_required
def api_generate_report():
    from reports import generate_html_report
    hours = request.json.get("hours", 24) if request.json else 24
    path = generate_html_report(hours=hours)
    return jsonify({"status": "ok", "path": path})


@app.route("/api/reports/download/<path:filename>")
@login_required
def api_download_report(filename):
    reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
    filepath = os.path.join(reports_dir, filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "Файл не найден"}), 404
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    return Response(
        content,
        mimetype="text/html",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ======== Users API ========

@app.route("/api/users")
@admin_required
def api_users():
    return jsonify(list_users())


@app.route("/api/users", methods=["POST"])
@admin_required
def api_add_user():
    data = request.json or {}
    ok, msg = add_user(
        username=data.get("username", ""),
        password=data.get("password", ""),
        role=data.get("role", "viewer"),
        full_name=data.get("full_name", ""),
    )
    return jsonify({"status": "ok" if ok else "error", "message": msg})


@app.route("/api/users/<username>", methods=["DELETE"])
@admin_required
def api_delete_user(username):
    ok, msg = delete_user(username)
    return jsonify({"status": "ok" if ok else "error", "message": msg})


@app.route("/api/users/<username>/toggle", methods=["POST"])
@admin_required
def api_toggle_user(username):
    ok, msg = toggle_user(username)
    return jsonify({"status": "ok" if ok else "error", "message": msg})


@app.route("/api/users/change-password", methods=["POST"])
@login_required
def api_change_password():
    data = request.json or {}
    user = get_current_user()
    ok, msg = change_password(
        username=user["username"],
        old_password=data.get("old_password", ""),
        new_password=data.get("new_password", ""),
    )
    return jsonify({"status": "ok" if ok else "error", "message": msg})


# ======== Export ========

@app.route("/api/export/csv/<table_name>")
@login_required
def api_export_csv(table_name):
    """Экспорт данных в CSV."""
    import csv
    import io

    db = get_db()
    s = db.get_session()
    try:
        from database import AccessDeniedEvent, ClipboardEvent, FileOperationEvent, LoginEvent, Alert

        models = {
            "access-denied": AccessDeniedEvent,
            "clipboard": ClipboardEvent,
            "file-operations": FileOperationEvent,
            "login-events": LoginEvent,
            "alerts": Alert,
        }

        model = models.get(table_name)
        if not model:
            return jsonify({"error": "Unknown table"}), 404

        rows = s.query(model).order_by(model.timestamp.desc()).limit(10000).all()

        output = io.StringIO()
        writer = csv.writer(output)
        columns = [c.name for c in model.__table__.columns]
        writer.writerow(columns)

        for row in rows:
            writer.writerow([getattr(row, c) for c in columns])

        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={table_name}_export.csv"},
        )
    finally:
        s.close()


# ======== Инициализация ========

def create_app():
    init_auth()
    return app


def run_web_server(host="0.0.0.0", port=8080):
    """Запуск веб-сервера в отдельном потоке."""
    init_auth()
    app.secret_key = os.urandom(32)
    app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)