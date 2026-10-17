# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec file для User Control
# Сборка: pyinstaller UserControl.spec

import sys
import os

block_cipher = None

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
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
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