"""
User Control — Система мониторинга действий пользователя на Windows Server.

Главный файл приложения. Запускает:
  - Веб-сервер с HTML-интерфейсом
  - Мониторинг событий безопасности Windows
  - Мониторинг буфера обмена терминального сервера
  - Мониторинг файловых операций
  - GUI-панель управления (опционально)

Использование:
  python main.py                  # Запуск с GUI и веб-интерфейсом
  python main.py --no-gui         # Только веб-интерфейс (для службы)
  python main.py --port 9090      # Указание порта
  python main.py --install        # Установка как служба Windows
  python main.py --uninstall      # Удаление службы Windows
"""

import sys
import os
import argparse
import logging
import threading
import datetime

# Настройка логирования
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(
            f"logs/monitor_{datetime.date.today().isoformat()}.log",
            encoding="utf-8",
        ),
    ],
)
logger = logging.getLogger("UserControl")


def check_single_instance():
    """Проверка единственного экземпляра приложения."""
    if os.name == "nt":
        try:
            import ctypes
            mutex = ctypes.windll.kernel32.CreateMutexW(None, False, "Global\\UserControlMonitor")
            if ctypes.windll.kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
                logger.error("Приложение уже запущено!")
                sys.exit(1)
        except Exception:
            pass


def start_monitors():
    """Запуск всех мониторов."""
    from config import get_config
    from monitors import EventLogMonitor, ClipboardMonitor, FileAccessMonitor
    from monitors.usb_monitor import USBMonitor, NetworkShareMonitor

    cfg = get_config()
    monitors = []

    if cfg.get("monitoring.event_log_enabled", True):
        em = EventLogMonitor()
        em.start()
        monitors.append(em)
        logger.info("EventLogMonitor запущен")

    if cfg.get("monitoring.clipboard_enabled", True):
        cm = ClipboardMonitor()
        cm.start()
        monitors.append(cm)
        logger.info("ClipboardMonitor запущен")

    if cfg.get("monitoring.file_access_enabled", True):
        fm = FileAccessMonitor()
        fm.start()
        monitors.append(fm)
        logger.info("FileAccessMonitor запущен")

    # USB-мониторинг
    um = USBMonitor()
    um.start()
    monitors.append(um)
    logger.info("USBMonitor запущен")

    # Сетевые ресурсы
    nm = NetworkShareMonitor()
    nm.start()
    monitors.append(nm)
    logger.info("NetworkShareMonitor запущен")

    return monitors


def start_web_server(host, port):
    """Запуск веб-сервера в отдельном потоке."""
    from web.app import run_web_server

    thread = threading.Thread(target=run_web_server, args=(host, port), daemon=True)
    thread.start()
    logger.info(f"Веб-сервер запущен: http://{host}:{port}")
    return thread


def start_gui(monitors):
    """Запуск GUI-интерфейса."""
    try:
        import tkinter as tk
        from tkinter import ttk, messagebox
        import webbrowser
    except ImportError:
        logger.warning("tkinter недоступен, GUI отключён")
        return None

    from config import get_config
    from database import get_db

    cfg = get_config()
    db = get_db()

    root = tk.Tk()
    root.title("🛡️ User Control — Мониторинг пользователей")
    root.geometry("800x600")
    root.configure(bg="#1a1a2e")
    root.resizable(True, True)

    # Стили
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"), foreground="#e8edf2", background="#1a1a2e")
    style.configure("Info.TLabel", font=("Segoe UI", 10), foreground="#8899aa", background="#1a1a2e")
    style.configure("Value.TLabel", font=("Segoe UI", 24, "bold"), foreground="#3b82f6", background="#1a1a2e")
    style.configure("Status.TLabel", font=("Segoe UI", 9), foreground="#22c55e", background="#1a1a2e")
    style.configure("Dark.TFrame", background="#1a1a2e")
    style.configure("Card.TFrame", background="#1e2d3d")
    style.configure("CardTitle.TLabel", font=("Segoe UI", 11, "bold"), foreground="#e8edf2", background="#1e2d3d")
    style.configure("CardValue.TLabel", font=("Segoe UI", 20, "bold"), foreground="#e8edf2", background="#1e2d3d")
    style.configure("CardDesc.TLabel", font=("Segoe UI", 9), foreground="#8899aa", background="#1e2d3d")

    # Главный фрейм
    main_frame = ttk.Frame(root, style="Dark.TFrame")
    main_frame.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)

    # Заголовок
    header = ttk.Frame(main_frame, style="Dark.TFrame")
    header.pack(fill=tk.X, pady=(0, 16))
    ttk.Label(header, text="🛡️ User Control", style="Title.TLabel").pack(side=tk.LEFT)
    ttk.Label(header, text="Система мониторинга действий пользователей", style="Info.TLabel").pack(side=tk.LEFT, padx=(12, 0))

    # Статус
    status_frame = ttk.Frame(header, style="Dark.TFrame")
    status_frame.pack(side=tk.RIGHT)
    status_label = ttk.Label(status_frame, text="● Сервер активен", style="Status.TLabel")
    status_label.pack()

    # Карточки статистики
    stats_frame = ttk.Frame(main_frame, style="Dark.TFrame")
    stats_frame.pack(fill=tk.X, pady=(0, 16))

    stat_labels = {}
    stat_configs = [
        ("🚫", "Отказы в доступе", "access_denied"),
        ("📋", "Буфер обмена", "clipboard_total"),
        ("⚠️", "Подозрительные", "clipboard_suspicious"),
        ("📁", "Файловые оп.", "file_operations"),
        ("✅", "Успешные входы", "login_success"),
        ("❌", "Неудачные входы", "login_failure"),
        ("🔔", "Оповещения", "unread_alerts"),
    ]

    for i, (icon, desc, key) in enumerate(stat_configs):
        card = ttk.Frame(stats_frame, style="Card.TFrame")
        card.grid(row=i // 4, column=i % 4, padx=6, pady=6, sticky="nsew")
        stats_frame.columnconfigure(i % 4, weight=1)

        ttk.Label(card, text=icon, font=("Segoe UI", 18), background="#1e2d3d").pack(pady=(10, 2))
        lbl = ttk.Label(card, text="0", style="CardValue.TLabel")
        lbl.pack()
        stat_labels[key] = lbl
        ttk.Label(card, text=desc, style="CardDesc.TLabel").pack(pady=(0, 10))

    # Кнопки
    btn_frame = ttk.Frame(main_frame, style="Dark.TFrame")
    btn_frame.pack(fill=tk.X, pady=(0, 16))

    def open_browser():
        port = cfg.get("web_port", 8080)
        webbrowser.open(f"http://localhost:{port}")

    def show_alerts():
        port = cfg.get("web_port", 8080)
        webbrowser.open(f"http://localhost:{port}/alerts")

    tk.Button(
        btn_frame, text="🌐 Открыть веб-интерфейс", command=open_browser,
        bg="#3b82f6", fg="white", font=("Segoe UI", 10, "bold"),
        relief=tk.FLAT, padx=16, pady=8, cursor="hand2"
    ).pack(side=tk.LEFT, padx=(0, 8))

    tk.Button(
        btn_frame, text="🔔 Оповещения", command=show_alerts,
        bg="#f97316", fg="white", font=("Segoe UI", 10, "bold"),
        relief=tk.FLAT, padx=16, pady=8, cursor="hand2"
    ).pack(side=tk.LEFT, padx=(0, 8))

    # Лог
    log_frame = ttk.Frame(main_frame, style="Dark.TFrame")
    log_frame.pack(fill=tk.BOTH, expand=True)

    ttk.Label(log_frame, text="📜 Последние события:", style="Info.TLabel").pack(anchor=tk.W, pady=(0, 4))

    log_text = tk.Text(
        log_frame, bg="#0f1923", fg="#e8edf2", font=("Consolas", 10),
        relief=tk.FLAT, wrap=tk.WORD, state=tk.DISABLED,
        insertbackground="#3b82f6", selectbackground="#3b82f6",
        borderwidth=0, highlightthickness=1, highlightcolor="#2a3f52",
        highlightbackground="#2a3f52"
    )
    log_text.pack(fill=tk.BOTH, expand=True)

    log_scroll = ttk.Scrollbar(log_text, command=log_text.yview)
    log_text.configure(yscrollcommand=log_scroll.set)

    # Функция обновления GUI
    def update_stats():
        try:
            stats = db.get_stats(hours=24)
            for key, label in stat_labels.items():
                val = stats.get(key, 0)
                label.configure(text=str(val))

            # Последние события в лог
            recent = db.get_access_denied(limit=5)
            recent_cb = db.get_clipboard_events(limit=3, suspicious_only=True)

            log_text.configure(state=tk.NORMAL)
            log_text.delete("1.0", tk.END)
            for ev in recent:
                line = f"[{ev.timestamp.strftime('%H:%M:%S')}] 🚫 {ev.username} → {ev.file_path[:60]}\n"
                log_text.insert(tk.END, line)
            for ev in recent_cb:
                line = f"[{ev.timestamp.strftime('%H:%M:%S')}] ⚠️ {ev.username}: {ev.reason[:70]}\n"
                log_text.insert(tk.END, line)
            log_text.configure(state=tk.DISABLED)

        except Exception as e:
            logger.error(f"GUI update error: {e}")

        root.after(5000, update_stats)

    update_stats()

    # Обработка закрытия
    def on_close():
        if messagebox.askyesno("Выход", "Остановить мониторинг и закрыть приложение?"):
            for m in monitors:
                m.stop()
            root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)

    return root


def install_service():
    """Установка приложения как службы Windows."""
    try:
        import win32serviceutil
        import win32service
        import win32event
        import servicemanager

        class UserControlService(win32serviceutil.ServiceFramework):
            _svc_name_ = "UserControlMonitor"
            _svc_display_name_ = "User Control — Мониторинг пользователей"
            _svc_description_ = "Мониторинг действий пользователей: отказы в доступе, буфер обмена, файловые операции"

            def __init__(self, args):
                win32serviceutil.ServiceFramework.__init__(self, args)
                self.stop_event = win32event.CreateEvent(None, 0, 0, None)
                self.monitors = []

            def SvcStop(self):
                self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
                win32event.SetEvent(self.stop_event)
                for m in self.monitors:
                    m.stop()

            def SvcDoRun(self):
                servicemanager.LogMsg(
                    servicemanager.EVENTLOG_INFORMATION_TYPE,
                    servicemanager.PYS_SERVICE_STARTED,
                    (self._svc_name_, ""),
                )
                self.monitors = start_monitors()
                from config import get_config as _cfg
                host = _cfg().get("web_host", "0.0.0.0")
                port = _cfg().get("web_port", 8080)
                start_web_server(host, port)
                win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)

        if len(sys.argv) == 1:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(UserControlService)
            servicemanager.StartServiceCtrlDispatcher()
        else:
            win32serviceutil.HandleCommandLine(UserControlService)

    except ImportError:
        logger.error("pywin32 не установлен. Установите: pip install pywin32")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="User Control — Система мониторинга действий пользователей"
    )
    parser.add_argument("--no-gui", action="store_true", help="Запуск без GUI")
    parser.add_argument("--port", type=int, default=None, help="Порт веб-сервера")
    parser.add_argument("--host", type=str, default=None, help="Хост веб-сервера")
    parser.add_argument("--install", action="store_true", help="Установить как службу Windows")
    parser.add_argument("--uninstall", action="store_true", help="Удалить службу Windows")
    args = parser.parse_args()

    if args.install:
        sys.argv = [sys.argv[0], "--startup", "auto", "install"]
        install_service()
        return

    if args.uninstall:
        sys.argv = [sys.argv[0], "remove"]
        install_service()
        return

    check_single_instance()

    from config import get_config
    cfg = get_config()

    host = args.host or cfg.get("web_host", "0.0.0.0")
    port = args.port or cfg.get("web_port", 8080)

    logger.info("=" * 60)
    logger.info("  User Control — Запуск системы мониторинга")
    logger.info("=" * 60)
    logger.info(f"  Веб-интерфейс: http://{host}:{port}")
    logger.info(f"  База данных:   {cfg.get('db_path')}")
    logger.info(f"  Логи:          logs/")
    logger.info("=" * 60)

    # Инициализация базы данных
    from database import get_db
    db = get_db()
    logger.info("База данных инициализирована")

    # Запуск мониторов
    monitors = start_monitors()

    # Запуск веб-сервера
    web_thread = start_web_server(host, port)

    if not args.no_gui:
        root = start_gui(monitors)
        if root:
            logger.info("GUI запущен")
            try:
                root.mainloop()
            except KeyboardInterrupt:
                pass
        else:
            logger.info("GUI недоступен, работа в режиме без GUI")
            _wait_for_exit()
    else:
        logger.info("Режим без GUI. Нажмите Ctrl+C для остановки.")
        _wait_for_exit()

    # Остановка
    logger.info("Остановка мониторов...")
    for m in monitors:
        m.stop()
    logger.info("Приложение остановлено.")


def _wait_for_exit():
    """Ожидание сигнала остановки."""
    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()