"""
User Control — Мониторинг подключения USB-устройств и внешних носителей.

Отслеживает:
- Подключение USB-флешек и внешних дисков
- Подключение к сетевым дискам
- Монтирование ISO-образов
- Изменение съёмных носителей
"""

import logging
import datetime
import threading
import time
import os
import string
from config import get_config
from database import get_db

logger = logging.getLogger(__name__)


class USBDeviceEvent:
    """Таблица событий USB — используется через database."""

    @staticmethod
    def add_event(db, **kwargs):
        """Добавить событие USB в таблицу alerts (переиспользуем)."""
        db.add_alert(
            alert_type="usb_device",
            severity=kwargs.get("severity", "info"),
            username=kwargs.get("username", "SYSTEM"),
            title=kwargs.get("title", "USB-событие"),
            description=kwargs.get("description", ""),
        )


class USBMonitor:
    """Мониторинг подключения USB-устройств и внешних носителей."""

    def __init__(self):
        self._running = False
        self._thread = None
        self.cfg = get_config()
        self.db = get_db()
        self._known_drives = set()
        self._ctypes = None
        self._init_win32()

    def _init_win32(self):
        try:
            import ctypes
            self._ctypes = ctypes
        except ImportError:
            logger.warning("ctypes недоступен")

    def start(self):
        if self._running:
            return
        self._running = True

        # Определить текущие диски
        self._known_drives = self._get_removable_drives()
        logger.info(f"Известные съёмные диски: {self._known_drives}")

        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info("USBMonitor запущен")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("USBMonitor остановлен")

    def _get_removable_drives(self):
        """Получить список съёмных дисков (USB-флешки, внешние HDD)."""
        drives = set()

        if self._ctypes and os.name == "nt":
            try:
                ctypes = self._ctypes
                bitmask = ctypes.windll.kernel32.GetLogicalDrives()
                for letter in string.ascii_uppercase:
                    if bitmask & 1:
                        drive = f"{letter}:\\"
                        drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive)
                        # DRIVE_REMOVABLE=2, DRIVE_REMOTE=4
                        if drive_type in (2, 4):
                            drives.add(drive)
                    bitmask >>= 1
            except Exception as e:
                logger.debug(f"Ошибка определения дисков: {e}")
        else:
            # Демо-режим
            import random
            if random.random() < 0.1:
                drives.add(f"{random.choice(['E', 'F', 'G'])}:\\")

        return drives

    def _get_drive_info(self, drive):
        """Получить информацию о диске."""
        info = {"path": drive, "label": "", "size": 0, "free": 0, "fs": ""}

        try:
            if os.name == "nt" and os.path.exists(drive):
                import ctypes
                kernel32 = ctypes.windll.kernel32
                volume_name = ctypes.create_unicode_buffer(256)
                fs_type = ctypes.create_unicode_buffer(256)
                serial = ctypes.c_ulong()
                max_comp = ctypes.c_ulong()
                flags = ctypes.c_ulong()

                if kernel32.GetVolumeInformationW(
                    drive, volume_name, 256,
                    ctypes.byref(serial), ctypes.byref(max_comp),
                    ctypes.byref(flags), fs_type, 256
                ):
                    info["label"] = volume_name.value
                    info["fs"] = fs_type.value

                free_bytes = ctypes.c_ulonglong(0)
                total_bytes = ctypes.c_ulonglong(0)
                if kernel32.GetDiskFreeSpaceExW(drive, None, ctypes.byref(total_bytes), ctypes.byref(free_bytes)):
                    info["size"] = total_bytes.value
                    info["free"] = free_bytes.value
        except Exception as e:
            logger.debug(f"Ошибка получения информации о диске {drive}: {e}")

        return info

    def _get_current_user(self):
        """Получить текущего пользователя."""
        if os.name == "nt":
            return os.environ.get("USERNAME", "SYSTEM")
        return os.environ.get("USER", "SYSTEM")

    def _run(self):
        """Основной цикл мониторинга."""
        poll_interval = 5  # секунд

        while self._running:
            try:
                current_drives = self._get_removable_drives()

                # Новые диски
                new_drives = current_drives - self._known_drives
                for drive in new_drives:
                    info = self._get_drive_info(drive)
                    user = self._get_current_user()
                    label = info.get("label", "")
                    size_gb = info.get("size", 0) / (1024 ** 3)

                    title = f"🔌 Подключён внешний носитель: {drive}"
                    if label:
                        title += f" ({label})"

                    description = (
                        f"Пользователь: {user}. "
                        f"Диск: {drive}. "
                        f"Метка: {label or 'нет'}. "
                        f"Файловая система: {info.get('fs', 'неизвестно')}. "
                        f"Объём: {size_gb:.1f} ГБ."
                    )

                    USBDeviceEvent.add_event(
                        self.db,
                        severity="warning",
                        username=user,
                        title=title,
                        description=description,
                    )

                    logger.warning(f"Подключён внешний носитель: {drive} ({label}) пользователем {user}")

                # Отключённые диски
                removed_drives = self._known_drives - current_drives
                for drive in removed_drives:
                    user = self._get_current_user()
                    title = f"🔌 Отключён внешний носитель: {drive}"
                    description = f"Пользователь: {user}. Диск: {drive}."

                    USBDeviceEvent.add_event(
                        self.db,
                        severity="info",
                        username=user,
                        title=title,
                        description=description,
                    )

                    logger.info(f"Отключён внешний носитель: {drive}")

                self._known_drives = current_drives

            except Exception as e:
                logger.error(f"USBMonitor error: {e}")

            time.sleep(poll_interval)


class NetworkShareMonitor:
    """Мониторинг подключения к сетевым ресурсам."""

    def __init__(self):
        self._running = False
        self._thread = None
        self.cfg = get_config()
        self.db = get_db()
        self._known_shares = set()

    def start(self):
        if self._running:
            return
        self._running = True
        self._known_shares = self._get_mapped_drives()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info("NetworkShareMonitor запущен")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("NetworkShareMonitor остановлен")

    def _get_mapped_drives(self):
        """Получить список подключённых сетевых дисков."""
        shares = set()

        if os.name == "nt":
            try:
                import subprocess
                result = subprocess.run(
                    ["net", "use"], capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.split("\n"):
                    line = line.strip()
                    if line and "\\\\" in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            shares.add(parts[-1])
            except Exception as e:
                logger.debug(f"Ошибка получения сетевых дисков: {e}")
        else:
            # Демо
            import random
            if random.random() < 0.02:
                shares.add(f"\\\\server{random.randint(1,5)}\\share{random.randint(1,10)}")

        return shares

    def _get_current_user(self):
        if os.name == "nt":
            return os.environ.get("USERNAME", "SYSTEM")
        return os.environ.get("USER", "SYSTEM")

    def _run(self):
        while self._running:
            try:
                current = self._get_mapped_drives()
                new_shares = current - self._known_shares

                for share in new_shares:
                    user = self._get_current_user()
                    self.db.add_alert(
                        alert_type="network_share",
                        severity="info",
                        username=user,
                        title=f"🌐 Подключён сетевой ресурс: {share}",
                        description=f"Пользователь: {user}. Ресурс: {share}.",
                    )
                    logger.info(f"Подключён сетевой ресурс: {share} пользователем {user}")

                removed = self._known_shares - current
                for share in removed:
                    user = self._get_current_user()
                    self.db.add_alert(
                        alert_type="network_share",
                        severity="info",
                        username=user,
                        title=f"🌐 Отключён сетевой ресурс: {share}",
                        description=f"Пользователь: {user}. Ресурс: {share}.",
                    )

                self._known_shares = current

            except Exception as e:
                logger.error(f"NetworkShareMonitor error: {e}")

            time.sleep(10)