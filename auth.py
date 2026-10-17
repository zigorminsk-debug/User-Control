"""
User Control — Модуль аутентификации.

Простая аутентификация на основе сессий Flask.
Управление пользователями и ролями.
"""

import os
import hashlib
import secrets
import datetime
import functools
from flask import session, redirect, url_for, request, jsonify

# Пользователи по умолчанию
DEFAULT_USERS = {
    "admin": {
        "password_hash": "",  # будет задан при первом запуске
        "role": "admin",
        "full_name": "Администратор",
        "created_at": "",
        "last_login": "",
        "is_active": True,
    }
}

USERS_FILE = "users.json"
_session_tokens = {}  # token -> {username, created_at, last_activity}


def _hash_password(password, salt=None):
    """Хеширование пароля с солью."""
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    return f"{salt}${h.hex()}"


def _verify_password(password, stored_hash):
    """Проверка пароля."""
    if not stored_hash or "$" not in stored_hash:
        return False
    salt, _ = stored_hash.split("$", 1)
    return _hash_password(password, salt) == stored_hash


def _load_users():
    """Загрузка пользователей из файла."""
    import json
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_users(users):
    """Сохранение пользователей в файл."""
    import json
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=4, ensure_ascii=False)


def init_auth():
    """Инициализация аутентификации. Создание admin-пользователя по умолчанию."""
    users = _load_users()
    if not users:
        default_password = "admin123"
        salt = secrets.token_hex(16)
        users = {
            "admin": {
                "password_hash": _hash_password(default_password, salt),
                "role": "admin",
                "full_name": "Администратор",
                "created_at": datetime.datetime.utcnow().isoformat(),
                "last_login": "",
                "is_active": True,
            }
        }
        _save_users(users)
        print(f"[AUTH] Создан пользователь по умолчанию: admin / {default_password}")
        print("[AUTH] ОБЯЗАТЕЛЬНО смените пароль после первого входа!")
    return users


def authenticate(username, password):
    """Аутентификация пользователя."""
    users = _load_users()
    user = users.get(username)
    if not user:
        return None
    if not user.get("is_active", True):
        return None
    if not _verify_password(password, user["password_hash"]):
        return None

    # Обновление времени входа
    user["last_login"] = datetime.datetime.utcnow().isoformat()
    users[username] = user
    _save_users(users)

    # Создание токена сессии
    token = secrets.token_urlsafe(32)
    _session_tokens[token] = {
        "username": username,
        "role": user["role"],
        "full_name": user.get("full_name", username),
        "created_at": datetime.datetime.utcnow(),
        "last_activity": datetime.datetime.utcnow(),
    }
    return token


def get_current_user():
    """Получить текущего пользователя из сессии Flask."""
    token = session.get("auth_token")
    if not token:
        return None
    user_data = _session_tokens.get(token)
    if not user_data:
        return None
    # Обновить активность
    user_data["last_activity"] = datetime.datetime.utcnow()
    return user_data


def logout():
    """Выход из системы."""
    token = session.get("auth_token")
    if token and token in _session_tokens:
        del _session_tokens[token]
    session.pop("auth_token", None)


def change_password(username, old_password, new_password):
    """Смена пароля пользователя."""
    users = _load_users()
    user = users.get(username)
    if not user:
        return False, "Пользователь не найден"
    if not _verify_password(old_password, user["password_hash"]):
        return False, "Неверный текущий пароль"
    if len(new_password) < 6:
        return False, "Пароль должен быть не менее 6 символов"

    user["password_hash"] = _hash_password(new_password)
    users[username] = user
    _save_users(users)
    return True, "Пароль изменён"


def add_user(username, password, role="viewer", full_name=""):
    """Добавление нового пользователя."""
    users = _load_users()
    if username in users:
        return False, "Пользователь уже существует"
    if len(password) < 6:
        return False, "Пароль должен быть не менее 6 символов"

    users[username] = {
        "password_hash": _hash_password(password),
        "role": role,
        "full_name": full_name or username,
        "created_at": datetime.datetime.utcnow().isoformat(),
        "last_login": "",
        "is_active": True,
    }
    _save_users(users)
    return True, "Пользователь создан"


def delete_user(username):
    """Удаление пользователя."""
    users = _load_users()
    if username not in users:
        return False, "Пользователь не найден"
    if username == "admin":
        return False, "Нельзя удалить администратора"
    del users[username]
    _save_users(users)
    return True, "Пользователь удалён"


def toggle_user(username):
    """Активация/деактивация пользователя."""
    users = _load_users()
    if username not in users:
        return False, "Пользователь не найден"
    if username == "admin":
        return False, "Нельзя деактивировать администратора"
    users[username]["is_active"] = not users[username].get("is_active", True)
    _save_users(users)
    state = "активирован" if users[username]["is_active"] else "деактивирован"
    return True, f"Пользователь {state}"


def list_users():
    """Получить список пользователей (без хешей паролей)."""
    users = _load_users()
    result = []
    for username, data in users.items():
        result.append({
            "username": username,
            "role": data.get("role", "viewer"),
            "full_name": data.get("full_name", username),
            "created_at": data.get("created_at", ""),
            "last_login": data.get("last_login", ""),
            "is_active": data.get("is_active", True),
        })
    return result


def login_required(f):
    """Декоратор для защиты маршрутов."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Декоратор для маршрутов, доступных только администраторам."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized"}), 401
            return redirect(url_for("login_page"))
        if user.get("role") != "admin":
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Forbidden"}), 403
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated