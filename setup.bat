@echo off
chcp 65001 >nul
setlocal EnableExtensions

:: =============================================
:: User Control — Скрипт установки для Windows
:: Запускать от имени администратора!
:: =============================================

:: Переходим в папку скрипта (при «Запуске от имени администратора»
:: рабочей папкой становится System32 — это ломает относительные пути)
cd /d "%~dp0"

echo.
echo  ============================================
echo   User Control — Установка
echo  ============================================
echo.

:: Проверка прав администратора
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

:: Проверка pip (в некоторых установках есть python, но нет pip в PATH)
python -m pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ОШИБКА] Модуль pip не найден!
    echo Выполните: python -m ensurepip --upgrade
    echo и повторите установку.
    pause
    exit /b 1
)

echo [1/5] Установка зависимостей Python...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ОШИБКА] Не удалось установить зависимости
    pause
    exit /b 1
)

echo.
echo [2/5] Пост-установка pywin32...
for /f "delims=" %%i in ('python -c "import sysconfig; print(sysconfig.get_scripts_directory())"') do set "SCRIPTS_DIR=%%i"
if exist "%SCRIPTS_DIR%\pywin32_postinstall.py" (
    python "%SCRIPTS_DIR%\pywin32_postinstall.py" -install >nul 2>&1
) else (
    echo   pywin32_postinstall не найден, пропускаю
)

echo.
echo [3/5] Включение аудита безопасности Windows...
auditpol /set /subcategory:"File System" /success:enable /failure:enable >nul 2>&1
auditpol /set /subcategory:"File Share" /success:enable /failure:enable >nul 2>&1
auditpol /set /subcategory:"Logon" /success:enable /failure:enable >nul 2>&1
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable >nul 2>&1

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
    sc config UserControlMonitor start= auto >nul 2>&1
    sc description UserControlMonitor "Мониторинг действий пользователей: отказы в доступе, буфер обмена, файловые операции" >nul 2>&1
    echo.
    echo Служба установлена. Запуск...
    sc start UserControlMonitor
)

echo.
echo  ============================================
echo   Установка завершена!
echo.
echo   Запуск вручную:  python main.py
echo   Веб-интерфейс:   http://localhost:8080
echo   (браузер откроется автоматически)
echo.
echo   Команды управления службой:
echo     sc start UserControlMonitor
echo     sc stop UserControlMonitor
echo     sc query UserControlMonitor
echo.
echo   Удаление службы:
echo     python main.py --uninstall
echo  ============================================
echo.
pause
