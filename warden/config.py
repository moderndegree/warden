"""Config loading. Files are re-read on every call so edits apply without a restart.

Lookup order: $WARDEN_CONFIG_DIR, then ~/.config/warden, then the packaged defaults (warden/defaults/).
"""
import json
import os
from pathlib import Path

DEFAULTS = Path(__file__).resolve().parent / "defaults"


def config_dir():
    for d in (os.environ.get("WARDEN_CONFIG_DIR"), "~/.config/warden"):
        if d and (Path(d).expanduser() / "guard.json").is_file():
            return Path(d).expanduser()
    return DEFAULTS


def path(name):
    return config_dir() / name


def load(name):
    return json.loads(path(name).read_text())


def mtime(name):
    return path(name).stat().st_mtime_ns
