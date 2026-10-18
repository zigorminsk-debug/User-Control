# 🛡️ User Control — Система мониторинга действий пользователей

[![CI — Проверка кода](https://github.com/zigorminsk-debug/User-Control/actions/workflows/ci.yml/badge.svg)](https://github.com/zigorminsk-debug/User-Control/actions/workflows/ci.yml)
[![Build — Сборка](https://github.com/zigorminsk-debug/User-Control/actions/workflows/build.yml/badge.svg)](https://github.com/zigorminsk-debug/User-Control/actions/workflows/build.yml)

Комплексная система контроля и мониторинга действий пользователей на Windows Server с терминальными сессиями. GUI-панель + HTML-интерфейс с аутентификацией.

---

## 📋 Возможности

### 🚫 Мониторинг отказов в доступе
- Отслеживание попыток доступа к файлам без прав (Event IDs: 4656, 4663, 4674, 5140, 5145)
- Фиксация неудачных входов (Event ID: 4625)
- Определение процесса, пользователя и целевого файла
- Градация серьёзности: info / warning / critical

### 📋 Мониторинг буфера обмена (RDP/терминальные сессии)
- Массовое копирование (настраиваемые пороги по минутам и часам)
- Детектирование конфиденциальных данных: кредитные карты, пароли, приватные ключи
- Мониторинг копирования файлов с чувствительными расширениями (.key, .pem, .db, .sql, .pst...)
- Фиксация повторного копирования одного и того же содержимого

### 📁 Мониторинг файловых операций
- Копирование, перемещение, удаление, переименование файлов
- Копирование на внешние носители и USB-устройства (`\\tsclient\`, USB-диски)
- Операции с конфиденциальными файлами (.docx, .xlsx, .pdf, .db, .sql, .key...)
- Операции в нерабочее время (до 6:00 и после 22:00)
- Крупные файловые операции (>100 МБ)

### 🔌 Мониторинг USB-устройств
- Подключение/отключение USB-флешек и внешних дисков
- Информация о носителе: метка, объём, файловая система
- Мониторинг сетевых дисков и ресурсов

### ⚠️ Система оценки рисков (Risk Engine)
- Оценка риска 0–100 для каждого пользователя
- 5 уровней: низкий / средний / высокий / критический / экстремальный
- Факторы: отказы, подозрительные копирования, неудачные входы, конфиденциальные файлы
- Повторные попытки доступа к одним и тем же файлам

### 🔐 Аутентификация и управление доступом
- Логин/пароль с хешированием PBKDF2
- Роли: admin / operator / viewer
- Управление пользователями через веб-интерфейс
- Смена паролей, блокировка/разблокировка учёток

### 📄 Генератор отчётов
- HTML-отчёты по безопасности за любой период
- Экспорт данных в CSV (отказы, буфер, файлы, входы, оповещения)
- Оценки рисков и рекомендации в отчёте

### 🌐 Веб-интерфейс (HTML)
- Тёмная тема, адаптивный дизайн
- 12 страниц: дашборд, отказы, буфер, файлы, входы, сессии, оповещения, риски, отчёты, пользователи, настройки, логин
- Графики Chart.js, автообновление, экспорт CSV
- REST API для всех данных

### 🖥️ GUI-панель (Tkinter)
- Компактное окно с ключевыми метриками
- Журнал последних событий
- Быстрый доступ к веб-интерфейсу

### ⚙️ Служба Windows
- Установка как системная служба Windows
- Автозапуск при загрузке сервера

---

## 🚀 Установка

### Требования
- Windows Server 2016+ (или Windows 10/11 для тестирования)
- Python 3.9+
- Права администратора (для чтения Event Log)

### Быстрая установка
```cmd
:: Запуск от имени администратора!
setup.bat
```

### Ручная установка
```cmd
pip install -r requirements.txt

:: Включение аудита Windows
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

:: Установка службы
python main.py --install
```

---

## ▶️ Запуск

```cmd
python main.py                    # С GUI и веб-интерфейсом (браузер откроется сам)
python main.py --no-gui           # Только веб-интерфейс
python main.py --no-browser       # Без авто-открытия браузера
python main.py --port 9090        # Указание порта
```

### Управление службой
```cmd
sc start UserControlMonitor
sc stop UserControlMonitor
sc query UserControlMonitor
python main.py --uninstall        # Удаление
```

---

## 🌐 Веб-интерфейс

После запуска откройте `http://localhost:8080`

**Логин по умолчанию:** `admin` / `admin123` *(смените пароль после первого входа!)*

| Страница | URL | Описание |
|----------|-----|----------|
| Панель управления | `/` | Статистика, графики, последние события |
| Отказы в доступе | `/access-denied` | Отказы с фильтрами и пагинацией |
| Буфер обмена | `/clipboard` | Операции копирования RDP-сессий |
| Файловые операции | `/file-operations` | Копирование, перемещение, удаление |
| Входы в систему | `/login-events` | Успешные и неудачные входы |
| Активные сессии | `/sessions` | Текущие RDP-сессии |
| Оповещения | `/alerts` | Системные оповещения |
| Оценка рисков | `/risk-assessment` | Оценка рисков по пользователям |
| Отчёты | `/reports` | Генерация и экспорт отчётов |
| Пользователи | `/users` | Управление учётными записями |
| Настройки | `/settings` | Конфигурация мониторинга |

---

## 📁 Структура проекта

```
User-Control/
├── main.py              # Главный файл приложения
├── config.py            # Управление конфигурацией (config.json)
├── database.py          # SQLAlchemy-модели (SQLite)
├── auth.py              # Аутентификация, роли, управление пользователями
├── risk_engine.py       # Движок оценки рисков пользователей
├── reports.py           # Генератор HTML-отчётов
├── requirements.txt     # Зависимости Python
├── setup.bat            # Скрипт установки для Windows
├── .gitignore           # Игнорируемые файлы
├── README.md            # Документация
├── monitors/            # Модули мониторинга
│   ├── __init__.py
│   ├── event_monitor.py     # Windows Security Event Log
│   ├── clipboard_monitor.py # Буфер обмена RDP
│   ├── file_monitor.py      # Файловые операции
│   └── usb_monitor.py       # USB-устройства и сетевые ресурсы
└── web/                 # Веб-приложение (Flask)
    ├── app.py           # Flask + REST API + аутентификация
    ├── templates/       # 12 HTML-шаблонов
    │   ├── base.html, login.html, dashboard.html,
    │   ├── access_denied.html, clipboard.html,
    │   ├── file_operations.html, login_events.html,
    │   ├── alerts.html, sessions.html, risk.html,
    │   ├── reports.html, users.html, settings.html
    └── static/
        ├── css/style.css
        └── js/app.js
```

---

## ⚙️ Конфигурация

Файл `config.json` создаётся автоматически. Основные параметры:

```json
{
    "web_host": "0.0.0.0",
    "web_port": 8080,
    "monitoring": {
        "event_log_enabled": true,
        "clipboard_enabled": true,
        "file_access_enabled": true,
        "clipboard_poll_interval": 2,
        "file_access_scan_interval": 300
    },
    "alerts": {
        "clipboard_max_copies_per_minute": 50,
        "clipboard_max_copies_per_hour": 200,
        "file_access_max_denied_per_hour": 20
    },
    "monitored_paths": ["C:\\Users", "C:\\ProgramData"],
    "excluded_users": ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"]
}
```

---

## 🧪 Демо-режим

При запуске на Linux или без `pywin32` программа автоматически переходит в демо-режим с генерацией тестовых данных для демонстрации всех функций интерфейса.

---

## 📝 Лицензия

MIT License