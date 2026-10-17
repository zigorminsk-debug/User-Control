import logging
import datetime
import threading
import re
from config import get_config
from database import get_db

logger = logging.getLogger(__name__)


class EventLogMonitor:
    """Мониторинг событий безопасности Windows Event Log.

    Считывает события из журнала Security, фильтрует события отказа в доступе
    и записывает их в базу данных.
    """

    def __init__(self):
        self._running = False
        self._thread = None
        self._last_record = 0
        self.cfg = get_config()
        self.db = get_db()
        self._win32evtlog = None
        self._init_win32()

    def _init_win32(self):
        try:
            import win32evtlog
            import win32evtlogutil
            import win32security
            self._win32evtlog = win32evtlog
            self._win32evtlogutil = win32evtlogutil
            self._win32security = win32security
        except ImportError:
            logger.warning("win32evtlog не доступен — мониторинг Event Log отключён")

    def start(self):
        if not self._win32evtlog:
            logger.info("EventLogMonitor: win32evtlog недоступен, запуск демо-режима")
            self._running = True
            self._thread = threading.Thread(target=self._demo_loop, daemon=True)
            self._thread.start()
            return
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info("EventLogMonitor запущен")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("EventLogMonitor остановлен")

    def _demo_loop(self):
        """Демо-цикл для тестирования без win32evtlog."""
        import random
        import time

        demo_users = ["ivanov", "petrov", "sidorov", "admin", "testuser"]
        demo_paths = [
            "C:\\Confidential\\salary.xlsx",
            "C:\\Finance\\report_2024.docx",
            "C:\\HR\\employees.db",
            "C:\\IT\\passwords.txt",
            "C:\\Management\\strategy.pptx",
            "\\\\server\\share\\secret.doc",
        ]
        demo_processes = [
            "C:\\Windows\\explorer.exe",
            "C:\\Windows\\notepad.exe",
            "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
            "C:\\Windows\\System32\\cmd.exe",
        ]

        while self._running:
            try:
                for _ in range(random.randint(0, 3)):
                    user = random.choice(demo_users)
                    path = random.choice(demo_paths)
                    proc = random.choice(demo_processes)
                    event_id = random.choice(self.cfg.get("event_ids", [4663]))
                    severity = random.choice(["warning", "warning", "critical"])

                    self.db.add_access_denied(
                        timestamp=datetime.datetime.utcnow(),
                        username=user,
                        domain="CORP",
                        source_ip=f"192.168.1.{random.randint(10, 250)}",
                        file_path=path,
                        access_mask="0x120089",
                        access_reason="ACCESS_DENIED",
                        process_name=proc,
                        event_id=event_id,
                        raw_message=f"Отказ в доступе: {user} -> {path}",
                        severity=severity,
                    )

                    self.db.add_alert(
                        alert_type="access_denied",
                        severity=severity,
                        username=user,
                        title=f"Отказ в доступе: {user}",
                        description=f"Пользователь {user} попытался получить доступ к {path}. Процесс: {proc}. EventID: {event_id}",
                    )

                # Демо-события входа
                for _ in range(random.randint(0, 2)):
                    user = random.choice(demo_users)
                    event_type = random.choice(["success", "success", "failure"])
                    self.db.add_login_event(
                        timestamp=datetime.datetime.utcnow(),
                        username=user,
                        domain="CORP",
                        source_ip=f"192.168.1.{random.randint(10, 250)}",
                        event_type=event_type,
                        logon_type=random.choice(["RemoteInteractive", "Interactive", "Network"]),
                        failure_reason="Unknown user name or bad password" if event_type == "failure" else "",
                        event_id=4625 if event_type == "failure" else 4624,
                    )

                self.db.upsert_user_session(
                    username=random.choice(demo_users),
                    session_id=random.randint(1, 50),
                    session_name=f"RDP-Tcp#{random.randint(1, 20)}",
                    client_name=f"PC-{random.randint(100, 999)}",
                    client_ip=f"192.168.1.{random.randint(10, 250)}",
                )

            except Exception as e:
                logger.error(f"EventLogMonitor demo error: {e}")

            time.sleep(self.cfg.get("monitoring.event_log_poll_interval", 10))

    def _run(self):
        win32evtlog = self._win32evtlog
        hand = win32evtlog.OpenEventLog(None, "Security")
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        denied_ids = set(self.cfg.get("denied_event_ids", [4656, 4663, 4674]))
        login_ids = {4624, 4625, 4634, 4647}
        excluded = set(self.cfg.get("excluded_users", ["SYSTEM"]))

        while self._running:
            try:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    import time
                    time.sleep(self.cfg.get("monitoring.event_log_poll_interval", 10))
                    continue

                for ev_obj in events:
                    if ev_obj.RecordNumber <= self._last_record:
                        continue
                    self._last_record = max(self._last_record, ev_obj.RecordNumber)

                    eid = ev_obj.EventID & 0xFFFF
                    ts = ev_obj.TimeGenerated.Format()

                    try:
                        timestamp = datetime.datetime.strptime(ts, "%m/%d/%Y %H:%M:%S %p")
                    except Exception:
                        timestamp = datetime.datetime.utcnow()

                    strings = ev_obj.StringInserts or []
                    username = ""
                    domain = ""
                    source_ip = ""
                    file_path = ""
                    access_mask = ""
                    process_name = ""

                    if eid in denied_ids and len(strings) >= 6:
                        domain = strings[5] if len(strings) > 5 else ""
                        username = strings[1] if len(strings) > 1 else ""
                        file_path = strings[6] if len(strings) > 6 else ""
                        access_mask = strings[8] if len(strings) > 8 else ""
                        process_name = strings[11] if len(strings) > 11 else ""

                    elif eid == 4624 or eid == 4625:
                        domain = strings[6] if len(strings) > 6 else ""
                        username = strings[5] if len(strings) > 5 else ""
                        source_ip = strings[18] if len(strings) > 18 else ""
                        logon_type = strings[8] if len(strings) > 8 else ""

                    if username in excluded:
                        continue

                    if eid in denied_ids:
                        severity = "critical" if any(
                            ext in file_path.lower()
                            for ext in [".key", ".pem", ".pfx", ".db", ".sql"]
                        ) else "warning"

                        self.db.add_access_denied(
                            timestamp=timestamp,
                            username=username,
                            domain=domain,
                            source_ip=source_ip,
                            file_path=file_path,
                            access_mask=access_mask,
                            access_reason="ACCESS_DENIED",
                            process_name=process_name,
                            event_id=eid,
                            raw_message=" | ".join(str(s) for s in strings[:20]),
                            severity=severity,
                        )
                        self.db.add_alert(
                            alert_type="access_denied",
                            severity=severity,
                            username=username,
                            title=f"Отказ в доступе: {domain}\\{username}",
                            description=f"Файл: {file_path}. Процесс: {process_name}. EventID: {eid}",
                        )

                    elif eid in login_ids:
                        event_type = "success" if eid == 4624 else ("failure" if eid == 4625 else "logout")
                        self.db.add_login_event(
                            timestamp=timestamp,
                            username=username,
                            domain=domain,
                            source_ip=source_ip,
                            event_type=event_type,
                            logon_type=logon_type if eid == 4624 or eid == 4625 else "",
                            failure_reason=strings[7] if eid == 4625 and len(strings) > 7 else "",
                            event_id=eid,
                        )

            except Exception as e:
                logger.error(f"EventLogMonitor error: {e}")
                import time
                time.sleep(5)

        win32evtlog.CloseEventLog(hand)