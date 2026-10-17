import logging
import datetime
import threading
import time
import os
import hashlib
from config import get_config
from database import get_db

logger = logging.getLogger(__name__)


class FileAccessMonitor:
    """Мониторинг файловых операций на сервере.

    Отслеживает копирование, перемещение и удаление файлов,
    выявляет массовые операции и работу с конфиденциальными расширениями.
    """

    def __init__(self):
        self._running = False
        self._thread = None
        self.cfg = get_config()
        self.db = get_db()
        self._file_snapshots = {}  # path -> (mtime, size, hash)
        self._op_counts = {}  # user -> [timestamps]

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info("FileAccessMonitor запущен")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("FileAccessMonitor остановлен")

    def _get_user_for_path(self, path):
        """Определить владельца файла."""
        try:
            if os.name == "nt":
                import win32security
                sd = win32security.GetFileSecurity(
                    path, win32security.OWNER_SECURITY_INFORMATION
                )
                owner_sid = sd.GetSecurityDescriptorOwner()
                name, domain, _ = win32security.LookupAccountSid(None, owner_sid)
                return f"{domain}\\{name}"
        except Exception:
            pass
        return os.environ.get("USERNAME", "SYSTEM")

    def _check_suspicious_file_op(self, username, operation, source, dest="", file_size=0, ext=""):
        """Проверка на подозрительные файловые операции."""
        reasons = []
        now = datetime.datetime.utcnow()

        # Массовые операции
        if username not in self._op_counts:
            self._op_counts[username] = []

        self._op_counts[username].append(now)
        cutoff = now - datetime.timedelta(hours=1)
        self._op_counts[username] = [t for t in self._op_counts[username] if t >= cutoff]
        ops_count = len(self._op_counts[username])

        if ops_count > 50:
            reasons.append(f"Массовые файловые операции: {ops_count} за час")

        # Копирование на внешние пути
        external_indicators = [
            "D:\\", "E:\\", "F:\\", "G:\\",
            "\\\\tsclient\\",
            "/media/", "/mnt/",
        ]
        for indicator in external_indicators:
            if dest and indicator.lower() in dest.lower():
                reasons.append(f"Копирование на внешний носитель: {dest}")
                break

        # Конфиденциальные расширения
        risky = self.cfg.get("risky_extensions", [])
        if ext.lower() in risky:
            reasons.append(f"Операция с конфиденциальным файлом: {ext}")

        # Большие файлы
        if file_size > 100 * 1024 * 1024:  # > 100MB
            reasons.append(f"Большой файл: {file_size / (1024*1024):.1f} MB")

        # Операции в нерабочее время
        if now.hour < 6 or now.hour > 22:
            reasons.append(f"Операция в нерабочее время: {now.strftime('%H:%M')}")

        is_suspicious = len(reasons) > 0
        return is_suspicious, "; ".join(reasons)

    def _demo_run(self):
        """Демо-режим."""
        import random

        demo_users = ["ivanov", "petrov", "sidorov", "admin", "testuser"]
        demo_ops = ["copy", "move", "delete", "rename"]
        demo_files = [
            ("C:\\Users\\ivanov\\Documents\\report.docx", ".docx"),
            ("C:\\Confidential\\salary.xlsx", ".xlsx"),
            ("C:\\Finance\\budget_2024.pdf", ".pdf"),
            ("C:\\IT\\backup.sql", ".sql"),
            ("C:\\HR\\employees.db", ".db"),
            ("D:\\USB\\copy.docx", ".docx"),
            ("\\\\tsclient\\C\\export\\data.zip", ".zip"),
            ("C:\\Management\\strategy.pptx", ".pptx"),
            ("C:\\Users\\petrov\\Desktop\\notes.txt", ".txt"),
            ("C:\\Archive\\contracts\\deal.pdf", ".pdf"),
        ]

        while self._running:
            try:
                for _ in range(random.randint(0, 4)):
                    user = random.choice(demo_users)
                    op = random.choice(demo_ops)
                    source, ext = random.choice(demo_files)
                    dest = ""
                    if op in ("copy", "move"):
                        dest = random.choice(demo_files)[0]
                    file_size = random.randint(1024, 500 * 1024 * 1024)

                    is_suspicious, reason = self._check_suspicious_file_op(
                        user, op, source, dest, file_size, ext
                    )

                    self.db.add_file_operation(
                        timestamp=datetime.datetime.utcnow(),
                        username=user,
                        operation=op,
                        source_path=source,
                        dest_path=dest,
                        file_size=file_size,
                        file_extension=ext,
                        is_suspicious=is_suspicious,
                        reason=reason,
                    )

                    if is_suspicious:
                        self.db.add_alert(
                            alert_type="file_suspicious",
                            severity="warning" if op != "delete" else "critical",
                            username=user,
                            title=f"Подозрительная файловая операция: {user}",
                            description=f"Операция: {op}. Файл: {source}. {('Назначение: ' + dest + '. ') if dest else ''}Причина: {reason}",
                        )

            except Exception as e:
                logger.error(f"FileAccessMonitor demo error: {e}")

            time.sleep(self.cfg.get("monitoring.file_access_scan_interval", 300) // 10)

    def _run(self):
        """Основной цикл мониторинга."""
        scan_interval = self.cfg.get("monitoring.file_access_scan_interval", 300)
        monitored = self.cfg.get("monitored_paths", ["C:\\Users"])

        while self._running:
            try:
                self._scan_paths(monitored)
            except Exception as e:
                logger.error(f"FileAccessMonitor error: {e}")

            time.sleep(scan_interval)

    def _scan_paths(self, paths):
        """Сканирование указанных путей на изменения."""
        for base_path in paths:
            if not os.path.exists(base_path):
                continue

            for root, dirs, files in os.walk(base_path):
                if not self._running:
                    return

                dirs[:] = [d for d in dirs if not d.startswith(".") and d not in (
                    "AppData", "node_modules", "__pycache__", ".git", "Thumbs.db"
                )]

                for fname in files:
                    if not self._running:
                        return

                    fpath = os.path.join(root, fname)
                    try:
                        stat = os.stat(fpath)
                        mtime = stat.st_mtime
                        size = stat.st_size
                        ext = os.path.splitext(fname)[1].lower()

                        if fpath in self._file_snapshots:
                            old_mtime, old_size, _ = self._file_snapshots[fpath]
                            if mtime != old_mtime or size != old_size:
                                user = self._get_user_for_path(fpath)
                                is_suspicious, reason = self._check_suspicious_file_op(
                                    user, "modify", fpath, file_size=size, ext=ext
                                )
                                self.db.add_file_operation(
                                    timestamp=datetime.datetime.utcnow(),
                                    username=user,
                                    operation="modify",
                                    source_path=fpath,
                                    file_size=size,
                                    file_extension=ext,
                                    is_suspicious=is_suspicious,
                                    reason=reason,
                                )

                        self._file_snapshots[fpath] = (mtime, size, None)

                    except (PermissionError, OSError):
                        continue
                    except Exception as e:
                        logger.debug(f"Ошибка сканирования {fpath}: {e}")