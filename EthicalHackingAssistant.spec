# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[('translations', 'translations'), ('config', 'config'), ('README.md', '.')],
    hiddenimports=['prompt_toolkit', 'prompt_toolkit.application', 'prompt_toolkit.key_binding', 'prompt_toolkit.layout', 'prompt_toolkit.widgets', 'prompt_toolkit.shortcuts', 'prompt_toolkit.formatted_text', 'prompt_toolkit.styles', 'prompt_toolkit.completion', 'prompt_toolkit.history', 'prompt_toolkit.auto_suggest', 'prompt_toolkit.validation', 'psutil', 'uuid', 'json', 'logging', 'threading', 'subprocess', 'concurrent.futures', 'asyncio', 'queue', 'weakref', 'dataclasses', 'enum'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='EthicalHackingAssistant',
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
