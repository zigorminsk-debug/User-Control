# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec file для User Control
# Сборка: pyinstaller UserControl.spec
# Формат совместим с PyInstaller >= 5.0 и 6.x (без устаревших
# block_cipher / a.zipped_data / a.zipfiles)

import os

# Пути к ресурсам
web_templates = os.path.join('web', 'templates')
web_static = os.path.join('web', 'static')

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[
        (web_templates, os.path.join('web', 'templates')),
        (web_static, os.path.join('web', 'static')),
    ],
    hiddenimports=[
        'flask',
        'flask_socketio',
        'sqlalchemy',
        'sqlalchemy.dialects.sqlite',
        'sqlalchemy.sql.default_comparator',
        'jinja2',
        'werkzeug',
        'win32evtlog',
        'win32evtlogutil',
        'win32clipboard',
        'win32con',
        'win32ts',
        'win32security',
        'win32api',
        'win32service',
        'win32serviceutil',
        'servicemanager',
        'ctypes',
        'ctypes.wintypes',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',  # GUI опционален для службы
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'PIL',
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='UserControl',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
