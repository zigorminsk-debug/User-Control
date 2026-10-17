"""
User Control — Генератор отчётов.

Создаёт HTML-отчёты по безопасности за указанный период.
"""

import datetime
import os
import logging
from database import get_db
from risk_engine import calculate_all_users_risk, get_risk_summary, get_risk_level

logger = logging.getLogger(__name__)


def generate_html_report(hours=24, output_path=None):
    """Сгенерировать HTML-отчёт."""
    db = get_db()
    stats = db.get_stats(hours=hours)
    user_stats = db.get_user_stats(hours=hours)
    timeline = db.get_timeline(hours=hours)
    risk_summary = get_risk_summary(hours)
    top_risks = risk_summary.get("top_risky_users", [])

    # Последние события
    recent_denied = db.get_access_denied(limit=20)
    recent_clipboard = db.get_clipboard_events(limit=10, suspicious_only=True)
    recent_alerts = db.get_alerts(limit=20)

    now = datetime.datetime.utcnow()
    period_start = now - datetime.timedelta(hours=hours)

    def severity_badge(sev):
        colors = {
            "critical": "#ef4444",
            "warning": "#eab308",
            "info": "#3b82f6",
            "success": "#22c55e",
        }
        c = colors.get(sev, "#888")
        return f'<span style="background:{c}22;color:{c};padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600">{sev}</span>'

    def risk_badge(score):
        _, label = get_risk_level(score)
        return f'<span style="font-size:13px;font-weight:700">{label} ({score})</span>'

    def fmt_dt(dt):
        if not dt:
            return "—"
        if isinstance(dt, str):
            return dt
        return dt.strftime("%Y-%m-%d %H:%M:%S")

    denied_rows = ""
    for e in recent_denied:
        denied_rows += f"""<tr>
            <td>{fmt_dt(e.timestamp)}</td>
            <td><b>{e.username}</b></td>
            <td style="font-family:monospace;font-size:12px;color:#06b6d4">{e.file_path}</td>
            <td>{e.process_name or '—'}</td>
            <td>{severity_badge(e.severity)}</td>
        </tr>"""

    clipboard_rows = ""
    for e in recent_clipboard:
        clipboard_rows += f"""<tr>
            <td>{fmt_dt(e.timestamp)}</td>
            <td><b>{e.username}</b></td>
            <td style="font-family:monospace;font-size:12px">{e.content_preview[:80]}</td>
            <td>{e.reason[:60] if e.reason else '—'}</td>
        </tr>"""

    risk_rows = ""
    for r in top_risks:
        factors_html = "<ul style='margin:4px 0;font-size:12px'>"
        for f in r.get("factors", [])[:3]:
            factors_html += f"<li>{f['description']}</li>"
        factors_html += "</ul>"
        risk_rows += f"""<tr>
            <td><b>{r['username']}</b></td>
            <td>{risk_badge(r['score'])}</td>
            <td>{factors_html}</td>
        </tr>"""

    alert_rows = ""
    for a in recent_alerts[:10]:
        alert_rows += f"""<tr>
            <td>{fmt_dt(a.timestamp)}</td>
            <td>{severity_badge(a.severity)}</td>
            <td>{a.username or '—'}</td>
            <td><b>{a.title}</b><br><span style="color:#888;font-size:12px">{a.description[:100]}</span></td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>User Control — Отчёт по безопасности</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #0f1923; color: #e8edf2; margin: 0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ font-size: 24px; border-bottom: 2px solid #3b82f6; padding-bottom: 12px; margin-bottom: 24px; }}
        h2 {{ font-size: 18px; color: #8899aa; margin-top: 32px; margin-bottom: 12px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 24px; }}
        .stat-card {{ background: #1e2d3d; border: 1px solid #2a3f52; border-radius: 12px; padding: 16px; text-align: center; }}
        .stat-value {{ font-size: 32px; font-weight: 700; }}
        .stat-label {{ font-size: 12px; color: #8899aa; text-transform: uppercase; margin-top: 4px; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 24px; }}
        th {{ background: #1a2733; padding: 10px 14px; text-align: left; font-size: 11px; text-transform: uppercase; color: #8899aa; border-bottom: 1px solid #2a3f52; }}
        td {{ padding: 8px 14px; border-bottom: 1px solid #2a3f52; }}
        tr:hover td {{ background: #243447; }}
        .meta {{ color: #5c7080; font-size: 12px; margin-top: 32px; border-top: 1px solid #2a3f52; padding-top: 12px; }}
        @media print {{
            body {{ background: white; color: black; }}
            .stat-card {{ border-color: #ddd; }}
            th {{ background: #f0f0f0; color: #333; }}
            td {{ border-color: #ddd; }}
        }}
    </style>
</head>
<body>
<div class="container">
    <h1>🛡️ User Control — Отчёт по безопасности</h1>
    <p style="color:#8899aa">Период: {period_start.strftime('%d.%m.%Y %H:%M')} — {now.strftime('%d.%m.%Y %H:%M')} ({hours} ч.)</p>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-value" style="color:#ef4444">{stats.get('access_denied', 0)}</div>
            <div class="stat-label">Отказы в доступе</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color:#3b82f6">{stats.get('clipboard_total', 0)}</div>
            <div class="stat-label">Операции буфера</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color:#eab308">{stats.get('clipboard_suspicious', 0)}</div>
            <div class="stat-label">Подозрительные</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color:#a855f7">{stats.get('file_operations', 0)}</div>
            <div class="stat-label">Файловые операции</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color:#22c55e">{stats.get('login_success', 0)}</div>
            <div class="stat-label">Успешные входы</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color:#f97316">{stats.get('login_failure', 0)}</div>
            <div class="stat-label">Неудачные входы</div>
        </div>
    </div>

    <h2>⚠️ Оценка рисков пользователей</h2>
    <p style="color:#8899aa;font-size:13px">Топ пользователей с наивысшим уровнем риска</p>
    <table>
        <thead><tr><th>Пользователь</th><th>Оценка риска</th><th>Факторы</th></tr></thead>
        <tbody>{risk_rows if risk_rows else '<tr><td colspan="3" style="text-align:center;color:#5c7080;padding:20px">Нет данных</td></tr>'}</tbody>
    </table>

    <h2>🚫 Последние отказы в доступе</h2>
    <table>
        <thead><tr><th>Время</th><th>Пользователь</th><th>Файл</th><th>Процесс</th><th>Уровень</th></tr></thead>
        <tbody>{denied_rows if denied_rows else '<tr><td colspan="5" style="text-align:center;color:#5c7080;padding:20px">Нет событий</td></tr>'}</tbody>
    </table>

    <h2>📋 Подозрительные копирования</h2>
    <table>
        <thead><tr><th>Время</th><th>Пользователь</th><th>Содержимое</th><th>Причина</th></tr></thead>
        <tbody>{clipboard_rows if clipboard_rows else '<tr><td colspan="4" style="text-align:center;color:#5c7080;padding:20px">Нет событий</td></tr>'}</tbody>
    </table>

    <h2>🔔 Оповещения</h2>
    <table>
        <thead><tr><th>Время</th><th>Уровень</th><th>Пользователь</th><th>Описание</th></tr></thead>
        <tbody>{alert_rows if alert_rows else '<tr><td colspan="4" style="text-align:center;color:#5c7080;padding:20px">Нет оповещений</td></tr>'}</tbody>
    </table>

    <div class="meta">
        <p>Отчёт сгенерирован: {now.strftime('%d.%m.%Y %H:%M:%S')} UTC</p>
        <p>User Control — Система мониторинга действий пользователей</p>
    </div>
</div>
</body>
</html>"""

    if not output_path:
        os.makedirs("reports", exist_ok=True)
        output_path = f"reports/report_{now.strftime('%Y%m%d_%H%M%S')}.html"

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    logger.info(f"Отчёт сохранён: {output_path}")
    return output_path