@echo off
:: =============================================
:: User Control — Скрипт установки для Windows
:: Запускать от имени администратора!
:: =============================================

echo.
echo  ============================================
echo   User Control — Установка
echo  ============================================
echo.

:: Проверка прав администратор
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ОШИБКА] Запустите скрипт от имени администратора!
    echo ПКМ на файле - Запуск от имени администратора
    pause
    exit /b 1
)

:: Проверка Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ОШИБКА] Python не найден!
    echo Скачайте Python с https://www.python.org/downloads/
    echo Обязательно отметьте "Add Python to PATH"
    pause
    exit /b 1
)

echo [1/5] Установка зависимостей Python...
pip install flask flask-socketio psutil watchdog pywin32 apscheduler sqlalchemy python-dateutil
if %errorlevel% neq 0 (
    echo [ОШИБКА] Не удалось установить зависимости
    pause
    exit /b 1
)

echo.
echo [2/5] Пост-установка pywin32...
python Scripts\pywin32_postinstall.py -install 2>nul

echo.
echo [3/5] Включение аудита безопасности Windows...
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable

echo.
echo [4/5] Создание директорий...
if not exist logs mkdir logs

echo.
echo [5/5] Установка службы Windows...
python main.py --install
if %errorlevel% neq 0 (
    echo [ПРЕДУПРЕЖДЕНИЕ] Служба не установлена. Приложение можно запустить вручную:
    echo   python main.py
) else (
    sc config UserControlMonitor start= auto
    sc description UserControlMonitor "Мониторинг действий пользователей: отказы в доступе, буфер обмена, файловые операции"
    echo.
    echo Служба установлена. Запуск...
    sc start UserControlMonitor
)

echo.
echo  ============================================
echo   Установка завершена!
echo.
echo   Веб-интерфейс: http://localhost:8080
echo.
echo   Команды управления:
echo     sc start UserControlMonitor
echo     sc stop UserControlMonitor
echo     sc query UserControlMonitor
echo.
echo   Удаление службы:
echo     python main.py --uninstall
echo  ============================================
echo.
pause