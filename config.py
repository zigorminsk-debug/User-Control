import os
import json

CONFIG_FILE = "config.json"

DEFAULT_CONFIG = {
    "web_host": "0.0.0.0",
    "web_port": 8080,
    "db_path": "monitor.db",
    "log_path": "logs",
    "monitoring": {
        "event_log_enabled": True,
        "clipboard_enabled": True,
        "file_access_enabled": True,
        "event_log_poll_interval": 10,
        "clipboard_poll_interval": 2,
        "file_access_scan_interval": 300,
    },
    "alerts": {
        "clipboard_max_copies_per_minute": 50,
        "clipboard_max_copies_per_hour": 200,
        "file_access_max_denied_per_hour": 20,
        "enable_popup_alerts": True,
        "enable_email_alerts": False,
        "smtp_server": "",
        "smtp_port": 587,
        "smtp_user": "",
        "smtp_password": "",
        "alert_recipients": [],
    },
    "monitored_paths": [
        "C:\\Users",
        "C:\\ProgramData",
    ],
    "excluded_users": [
        "SYSTEM",
        "LOCAL SERVICE",
        "NETWORK SERVICE",
    ],
    "event_ids": [
        4656,  # A handle to an object was requested
        4663,  # An attempt was made to access an object
        4658,  # The handle to an object was closed
        4703,  # A user right was adjusted
        4670,  # Permissions on an object were changed
        4674,  # An operation was attempted on a privileged object
        5140,  # A network share object was accessed
        5145,  # A network share check was performed
        4776,  # The computer attempted to validate the credentials
        4625,  # An account failed to log on
    ],
    "denied_event_ids": [
        4656,
        4663,
        4674,
    ],
    "risky_extensions": [
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".pdf", ".txt", ".csv", ".zip", ".rar", ".7z",
        ".db", ".sql", ".mdb", ".pst", ".ost",
        ".key", ".pem", ".crt", ".pfx", ".p12",
    ],
}


class Config:
    _instance = None
    _config = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self._config = DEFAULT_CONFIG.copy()
        self.load()

    def load(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                self._deep_merge(self._config, saved)
            except Exception:
                pass

    def save(self):
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(self._config, f, indent=4, ensure_ascii=False)
        except Exception:
            pass

    def _deep_merge(self, base, override):
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    def get(self, key, default=None):
        keys = key.split(".")
        val = self._config
        for k in keys:
            if isinstance(val, dict) and k in val:
                val = val[k]
            else:
                return default
        return val

    def set(self, key, value):
        keys = key.split(".")
        d = self._config
        for k in keys[:-1]:
            if k not in d:
                d[k] = {}
            d = d[k]
        d[keys[-1]] = value
        self.save()

    @property
    def all(self):
        return self._config


def get_config():
    return Config.get_instance()