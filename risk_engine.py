"""
User Control — Движок оценки рисков пользователей.

Анализирует поведение пользователей и присваивает оценку риска
на основе:
- Частоты отказов в доступе
- Подозрительных копирований
- Файловых операций с конфиденциальными данными
- Попыток входа в нерабочее время
- Подключений внешних носителей
- Сетевых ресурсов

Оценка риска: 0-100 (0 = безопасно, 100 = критический риск)
"""

import datetime
import logging
from database import get_db

logger = logging.getLogger(__name__)

# Веса факторов риска
WEIGHTS = {
    "access_denied_count": 2.0,        # каждый отказ = 2 балла
    "clipboard_suspicious": 3.0,        # каждое подозрительное копирование = 3 балла
    "file_suspicious_ops": 2.5,         # подозрительная файловая операция = 2.5 балла
    "failed_logins": 4.0,               # неудачный вход = 4 балла
    "off_hours_activity": 1.5,          # активность в нерабочее время = 1.5 балла
    "sensitive_file_access": 3.5,       # доступ к конфиденциальным файлам = 3.5 балла
    "mass_copying": 5.0,                # массовое копирование = 5 баллов
    "external_drive_usage": 4.0,        # использование внешнего носителя = 4 балла
    "repeated_denied_same_file": 3.0,   # повторные отказы к одному файлу = 3 балла
}

# Уровни риска
RISK_LEVELS = {
    (0, 15): ("low", "🟢 Низкий"),
    (15, 35): ("medium", "🟡 Средний"),
    (35, 60): ("high", "🟠 Высокий"),
    (60, 80): ("critical", "🔴 Критический"),
    (80, 101): ("extreme", "⛔ Экстремальный"),
}

SENSITIVE_EXTENSIONS = {
    ".key", ".pem", ".crt", ".pfx", ".p12",
    ".db", ".sql", ".mdb", ".bak",
    ".pst", ".ost",
}


def get_risk_level(score):
    """Получить текстовое описание уровня риска."""
    for (low, high), (key, label) in RISK_LEVELS.items():
        if low <= score < high:
            return key, label
    return "unknown", "❓ Неизвестно"


def calculate_user_risk(username, hours=24):
    """Рассчитать оценку риска для конкретного пользователя."""
    db = get_db()
    s = db.get_session()

    try:
        from database import AccessDeniedEvent, ClipboardEvent, FileOperationEvent, LoginEvent

        cutoff = datetime.datetime.utcnow() - datetime.timedelta(hours=hours)
        score = 0.0
        factors = []

        # 1. Отказы в доступе
        ad_count = (
            s.query(AccessDeniedEvent)
            .filter(AccessDeniedEvent.username == username, AccessDeniedEvent.timestamp >= cutoff)
            .count()
        )
        if ad_count > 0:
            points = min(ad_count * WEIGHTS["access_denied_count"], 30)
            score += points
            factors.append({
                "factor": "Отказы в доступе",
                "count": ad_count,
                "points": round(points, 1),
                "description": f"{ad_count} попыток доступа к запрещённым ресурсам",
            })

        # 2. Подозрительные копирования буфера
        cb_suspicious = (
            s.query(ClipboardEvent)
            .filter(
                ClipboardEvent.username == username,
                ClipboardEvent.timestamp >= cutoff,
                ClipboardEvent.is_suspicious == True,
            )
            .count()
        )
        if cb_suspicious > 0:
            points = min(cb_suspicious * WEIGHTS["clipboard_suspicious"], 25)
            score += points
            factors.append({
                "factor": "Подозрительные копирования",
                "count": cb_suspicious,
                "points": round(points, 1),
                "description": f"{cb_suspicious} подозрительных операций с буфером обмена",
            })

        # 3. Подозрительные файловые операции
        fo_suspicious = (
            s.query(FileOperationEvent)
            .filter(
                FileOperationEvent.username == username,
                FileOperationEvent.timestamp >= cutoff,
                FileOperationEvent.is_suspicious == True,
            )
            .count()
        )
        if fo_suspicious > 0:
            points = min(fo_suspicious * WEIGHTS["file_suspicious_ops"], 20)
            score += points
            factors.append({
                "factor": "Подозрительные файловые операции",
                "count": fo_suspicious,
                "points": round(points, 1),
                "description": f"{fo_suspicious} подозрительных файловых операций",
            })

        # 4. Неудачные попытки входа
        failed = (
            s.query(LoginEvent)
            .filter(
                LoginEvent.username == username,
                LoginEvent.timestamp >= cutoff,
                LoginEvent.event_type == "failure",
            )
            .count()
        )
        if failed > 0:
            points = min(failed * WEIGHTS["failed_logins"], 20)
            score += points
            factors.append({
                "factor": "Неудачные входы",
                "count": failed,
                "points": round(points, 1),
                "description": f"{failed} неудачных попыток входа",
            })

        # 5. Доступ к конфиденциальным файлам
        sensitive_ad = (
            s.query(AccessDeniedEvent)
            .filter(
                AccessDeniedEvent.username == username,
                AccessDeniedEvent.timestamp >= cutoff,
                AccessDeniedEvent.severity == "critical",
            )
            .count()
        )
        if sensitive_ad > 0:
            points = min(sensitive_ad * WEIGHTS["sensitive_file_access"], 20)
            score += points
            factors.append({
                "factor": "Доступ к конфиденциальным данным",
                "count": sensitive_ad,
                "points": round(points, 1),
                "description": f"{sensitive_ad} попыток доступа к критически важным файлам",
            })

        # 6. Повторные отказы к одному файлу
        from sqlalchemy import func
        repeated = (
            s.query(AccessDeniedEvent.file_path, func.count(AccessDeniedEvent.id))
            .filter(
                AccessDeniedEvent.username == username,
                AccessDeniedEvent.timestamp >= cutoff,
            )
            .group_by(AccessDeniedEvent.file_path)
            .having(func.count(AccessDeniedEvent.id) > 2)
            .all()
        )
        if repeated:
            total_repeated = sum(c for _, c in repeated)
            points = min(total_repeated * WEIGHTS["repeated_denied_same_file"], 15)
            score += points
            factors.append({
                "factor": "Повторные попытки",
                "count": len(repeated),
                "points": round(points, 1),
                "description": f"Повторные попытки доступа к {len(repeated)} файлам",
            })

        # Ограничение до 100
        score = min(score, 100)
        level_key, level_label = get_risk_level(score)

        return {
            "username": username,
            "score": round(score, 1),
            "level": level_key,
            "level_label": level_label,
            "factors": factors,
            "period_hours": hours,
            "calculated_at": datetime.datetime.utcnow().isoformat(),
        }

    finally:
        s.close()


def calculate_all_users_risk(hours=24):
    """Рассчитать риски для всех пользователей."""
    db = get_db()
    s = db.get_session()

    try:
        from database import AccessDeniedEvent
        from sqlalchemy import func

        users = (
            s.query(AccessDeniedEvent.username)
            .distinct()
            .all()
        )

        results = []
        for (username,) in users:
            risk = calculate_user_risk(username, hours)
            results.append(risk)

        # Сортировка по убыванию риска
        results.sort(key=lambda x: x["score"], reverse=True)
        return results

    finally:
        s.close()


def get_risk_summary(hours=24):
    """Получить сводку по рискам."""
    all_risks = calculate_all_users_risk(hours)

    summary = {
        "total_users": len(all_risks),
        "extreme": sum(1 for r in all_risks if r["level"] == "extreme"),
        "critical": sum(1 for r in all_risks if r["level"] == "critical"),
        "high": sum(1 for r in all_risks if r["level"] == "high"),
        "medium": sum(1 for r in all_risks if r["level"] == "medium"),
        "low": sum(1 for r in all_risks if r["level"] == "low"),
        "top_risky_users": all_risks[:10],
        "period_hours": hours,
        "calculated_at": datetime.datetime.utcnow().isoformat(),
    }

    return summary