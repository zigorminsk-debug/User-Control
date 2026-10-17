import logging
import datetime
import threading
import time
import hashlib
from config import get_config
from database import get_db

logger = logging.getLogger(__name__)


class ClipboardMonitor:
    """Мониторинг буфера обмена на терминальном сервере.

    Отслеживает операции копирования пользователей в RDP-сессиях,
    выявляет массовое копирование и попытки экспорта конфиденциальных данных.
    """

    def __init__(self):
        self._running = False
        self._thread = None
        self.cfg = get_config()
        self.db = get_db()
        self._last_hashes = {}  # user -> last content hash
        self._copy_counts = {}  # user -> [timestamps]
        self._win32 = None
        self._init_win32()

    def _init_win32(self):
        try:
            import win32clipboard
            import win32con
            import win32ts
            import win32api
            import win32security
            import ctypes
            self._win32 = {
                "clipboard": win32clipboard,
                "con": win32con,
                "ts": win32ts,
                "api": win32api,
                "security": win32security,
                "ctypes": ctypes,
            }
        except ImportError:
            logger.warning("win32clipboard не доступен — мониторинг буфера обмена в демо-режиме")

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run if self._win32 else self._demo_run, daemon=True)
        self._thread.start()
        logger.info("ClipboardMonitor запущен")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("ClipboardMonitor остановлен")

    def _get_rdp_sessions(self):
        """Получить список активных RDP-сессий."""
        if not self._win32:
            return []

        try:
            ts = self._win32["ts"]
            sessions = ts.WTSEnumerateSessions(None, 0)
            active = []
            for s in sessions:
                if s["State"] == 0:  # WTSActive
                    active.append({
                        "session_id": s["SessionId"],
                        "name": s["pWinStationName"],
                        "state": s["State"],
                    })
            return active
        except Exception as e:
            logger.error(f"Ошибка получения RDP-сессий: {e}")
            return []

    def _get_session_user(self, session_id):
        """Получить имя пользователя RDP-сессии."""
        if not self._win32:
            return "unknown"
        try:
            ts = self._win32["ts"]
            return ts.WTSQuerySessionInformation(None, session_id, ts.WTSUserName) or "unknown"
        except Exception:
            return "unknown"

    def _get_clipboard_content(self):
        """Прочитать содержимое буфера обмена."""
        if not self._win32:
            return None, None

        try:
            cb = self._win32["clipboard"]
            con = self._win32["con"]

            cb.OpenClipboard()
            try:
                content_type = "text"
                content = None

                if cb.IsClipboardFormatAvailable(con.CF_UNICODETEXT):
                    data = cb.GetClipboardData(con.CF_UNICODETEXT)
                    if data:
                        content = str(data)[:10000]
                        content_type = "text"
                elif cb.IsClipboardFormatAvailable(con.CF_HDROP):
                    data = cb.GetClipboardData(con.CF_HDROP)
                    if data:
                        content = str(data)
                        content_type = "files"
                elif cb.IsClipboardFormatAvailable(con.CF_BITMAP):
                    content = "[IMAGE]"
                    content_type = "image"

                return content_type, content
            finally:
                cb.CloseClipboard()
        except Exception as e:
            logger.debug(f"Ошибка чтения буфера: {e}")
            return None, None

    def _check_suspicious(self, username, content_type, content, timestamp):
        """Проверка на подозрительную активность."""
        reasons = []

        if not content:
            return False, ""

        # Проверка на массовое копирование
        if username not in self._copy_counts:
            self._copy_counts[username] = []

        self._copy_counts[username].append(timestamp)
        cutoff_min = timestamp - datetime.timedelta(minutes=1)
        cutoff_hr = timestamp - datetime.timedelta(hours=1)
        self._copy_counts[username] = [
            t for t in self._copy_counts[username] if t >= cutoff_hr
        ]

        copies_per_min = sum(1 for t in self._copy_counts[username] if t >= cutoff_min)
        copies_per_hr = len(self._copy_counts[username])

        max_per_min = self.cfg.get("alerts.clipboard_max_copies_per_minute", 50)
        max_per_hr = self.cfg.get("alerts.clipboard_max_copies_per_hour", 200)

        if copies_per_min > max_per_min:
            reasons.append(f"Массовое копирование: {copies_per_min} операций/мин (лимит: {max_per_min})")
        if copies_per_hr > max_per_hr:
            reasons.append(f"Слишком много копирований: {copies_per_hr} операций/час (лимит: {max_per_hr})")

        # Проверка на дублирование
        content_hash = hashlib.md5((content or "").encode("utf-8", errors="replace")).hexdigest()
        if username in self._last_hashes:
            if self._last_hashes[username] == content_hash:
                reasons.append("Повторное копирование того же содержимого")
        self._last_hashes[username] = content_hash

        # Проверка на конфиденциальные данные
        sensitive_patterns = [
            r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",  # кредитные карты
            r"\b\d{3}-\d{2}-\d{4}\b",  # SSN-like
            r"password\s*[:=]",
            r"пароль\s*[:=]",
            r"secret\s*[:=]",
            r"api[_-]?key\s*[:=]",
            r"BEGIN\s+(RSA\s+)?PRIVATE\s+KEY",
        ]
        import re
        for pattern in sensitive_patterns:
            if re.search(pattern, content or "", re.IGNORECASE):
                reasons.append(f"Обнаружены конфиденциальные данные: {pattern}")
                break

        # Проверка расширений файлов в копируемых путях
        if content_type == "files":
            risky = self.cfg.get("risky_extensions", [])
            for ext in risky:
                if ext.lower() in (content or "").lower():
                    reasons.append(f"Копирование файлов с расширением {ext}")
                    break

        is_suspicious = len(reasons) > 0
        return is_suspicious, "; ".join(reasons)

    def _demo_run(self):
        """Демо-режим для тестирования без win32."""
        import random

        demo_users = ["ivanov", "petrov", "sidorov", "admin", "testuser"]
        demo_apps = [
            "WINWORD.EXE", "EXCEL.EXE", "notepad.exe",
            "explorer.exe", "chrome.exe", "putty.exe",
        ]
        demo_texts = [
            "Обычный текст для заметок",
            "password=SuperSecret123",
            "SELECT * FROM users WHERE role='admin'",
            "C:\\Confidential\\salary_data.xlsx",
            "-----BEGIN RSA PRIVATE KEY-----",
            "Client card: 4111-1111-1111-1111",
            "Meeting notes for Q4 planning",
            "Адрес сервера: 10.0.0.50, api_key=abc123def456",
            "Список сотрудников и зарплат",
            "Backup of database passwords",
        ]

        while self._running:
            try:
                for _ in range(random.randint(0, 5)):
                    user = random.choice(demo_users)
                    now = datetime.datetime.utcnow()
                    content = random.choice(demo_texts)
                    content_type = "text"
                    app = random.choice(demo_apps)
                    content_length = len(content)

                    is_suspicious, reason = self._check_suspicious(
                        user, content_type, content, now
                    )

                    self.db.add_clipboard_event(
                        timestamp=now,
                        username=user,
                        session_id=random.randint(1, 50),
                        session_name=f"RDP-Tcp#{random.randint(1, 20)}",
                        content_type=content_type,
                        content_preview=content[:200],
                        content_length=content_length,
                        source_app=app,
                        is_suspicious=is_suspicious,
                        reason=reason,
                    )

                    if is_suspicious:
                        self.db.add_alert(
                            alert_type="clipboard_suspicious",
                            severity="warning",
                            username=user,
                            title=f"Подозрительная активность буфера: {user}",
                            description=f"Пользователь {user}. Причина: {reason}. Приложение: {app}. Содержимое: {content[:100]}",
                        )

            except Exception as e:
                logger.error(f"ClipboardMonitor demo error: {e}")

            time.sleep(self.cfg.get("monitoring.clipboard_poll_interval", 2))

    def _run(self):
        """Основной цикл мониторинга буфера обмена."""
        poll_interval = self.cfg.get("monitoring.clipboard_poll_interval", 2)

        while self._running:
            try:
                sessions = self._get_rdp_sessions()
                for session in sessions:
                    sid = session["session_id"]
                    username = self._get_session_user(sid)
                    if not username or username == "unknown":
                        continue

                    content_type, content = self._get_clipboard_content()
                    if content is None:
                        continue

                    content_hash = hashlib.md5(
                        (content or "").encode("utf-8", errors="replace")
                    ).hexdigest()

                    if username in self._last_hashes and self._last_hashes[username] == content_hash:
                        continue

                    now = datetime.datetime.utcnow()
                    is_suspicious, reason = self._check_suspicious(
                        username, content_type, content, now
                    )

                    self.db.add_clipboard_event(
                        timestamp=now,
                        username=username,
                        session_id=sid,
                        session_name=session["name"],
                        content_type=content_type or "unknown",
                        content_preview=(content or "")[:200],
                        content_length=len(content or ""),
                        source_app="",
                        is_suspicious=is_suspicious,
                        reason=reason,
                    )

                    if is_suspicious:
                        self.db.add_alert(
                            alert_type="clipboard_suspicious",
                            severity="warning",
                            username=username,
                            title=f"Подозрительная активность буфера: {username}",
                            description=f"Причина: {reason}. Сессия: {session['name']}. Содержимое: {(content or '')[:100]}",
                        )

            except Exception as e:
                logger.error(f"ClipboardMonitor error: {e}")

            time.sleep(poll_interval)