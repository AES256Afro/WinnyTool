"""
WinnyTool - Startup Manager Module

Enumerates, disables, and re-enables startup items from the Windows
registry, user startup folder, and scheduled tasks.
"""

import os
import glob
import shutil
import subprocess
import winreg


# ---------------------------------------------------------------------------
# Known heavy-impact applications (lowercase substrings)
# ---------------------------------------------------------------------------

_HIGH_IMPACT_APPS = frozenset({
    "chrome", "firefox", "msedge", "brave", "opera",          # browsers
    "onedrive", "dropbox", "googledrive", "icloud",            # cloud sync
    "teams", "slack", "discord", "zoom", "skype",              # comms
    "spotify", "steam", "epicgames", "origin",                 # media/gaming
    "adobeupdate", "javaupdatesched", "ccleaner",              # updaters
    "cortana", "yourphone", "gamebar",                         # bloat
})

_LOW_IMPACT_APPS = frozenset({
    "securityhealth", "windowsdefender", "realtek",            # system / drivers
    "igfx", "nvidia", "amd", "synaptics", "ctfmon",
    "windowsterminal", "powershell",
})


def _estimate_impact(name, command):
    """Heuristic impact classification based on known app patterns."""
    blob = (name + " " + command).lower()
    for pattern in _HIGH_IMPACT_APPS:
        if pattern in blob:
            return "High"
    for pattern in _LOW_IMPACT_APPS:
        if pattern in blob:
            return "Low"
    return "Medium"


# ---------------------------------------------------------------------------
# Disabled-item bookkeeping
# ---------------------------------------------------------------------------

_DISABLED_SUFFIX = ".WinnyToolDisabled"


# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------

_REGISTRY_LOCATIONS = [
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run",
     "HKLM\\...\\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
     "HKLM\\...\\RunOnce"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run",
     "HKCU\\...\\Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
     "HKCU\\...\\RunOnce"),
]


def _read_registry_run_keys():
    """Enumerate startup entries from all Run / RunOnce registry keys."""
    items = []
    for hive, subkey, location_label in _REGISTRY_LOCATIONS:
        try:
            with winreg.OpenKey(hive, subkey) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        i += 1
                        disabled = name.endswith(_DISABLED_SUFFIX)
                        display_name = (
                            name[: -len(_DISABLED_SUFFIX)] if disabled else name
                        )
                        items.append({
                            "name": display_name,
                            "command": value if isinstance(value, str) else str(value),
                            "location": location_label,
                            "enabled": not disabled,
                            "impact": _estimate_impact(display_name, str(value)),
                        })
                    except OSError:
                        break
        except OSError:
            continue
    return items


# ---------------------------------------------------------------------------
# Startup folder helpers
# ---------------------------------------------------------------------------

def _get_startup_folder():
    """Return the path to the current user's Startup folder."""
    return os.path.join(
        os.environ.get("APPDATA", ""),
        r"Microsoft\Windows\Start Menu\Programs\Startup",
    )


def _read_startup_folder():
    """Enumerate shortcuts/scripts in the Startup folder."""
    folder = _get_startup_folder()
    items = []
    if not os.path.isdir(folder):
        return items

    for entry in os.listdir(folder):
        full_path = os.path.join(folder, entry)
        if not os.path.isfile(full_path):
            continue
        disabled = entry.endswith(_DISABLED_SUFFIX)
        display_name = entry[: -len(_DISABLED_SUFFIX)] if disabled else entry
        items.append({
            "name": display_name,
            "command": full_path,
            "location": "Startup Folder",
            "enabled": not disabled,
            "impact": _estimate_impact(display_name, full_path),
        })
    return items


# ---------------------------------------------------------------------------
# Scheduled tasks helpers
# ---------------------------------------------------------------------------

def _read_scheduled_tasks():
    """Enumerate scheduled tasks that have boot or logon triggers."""
    items = []
    try:
        result = subprocess.run(
            ["schtasks", "/query", "/fo", "CSV", "/v"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return items

        lines = result.stdout.strip().splitlines()
        if len(lines) < 2:
            return items

        headers = [h.strip('"') for h in lines[0].split('","')]
        # Find relevant column indices
        col = {}
        for idx, h in enumerate(headers):
            hl = h.lower().strip()
            if "taskname" in hl:
                col["name"] = idx
            elif "task to run" in hl:
                col["command"] = idx
            elif "status" in hl and "status" not in col:
                col["status"] = idx
            elif "logon mode" in hl or "start" in hl.replace(" ", ""):
                # Different Windows versions use different header names
                if "trigger" not in col:
                    col["trigger"] = idx

        if "name" not in col:
            return items

        for line in lines[1:]:
            fields = [f.strip('"') for f in line.split('","')]
            if len(fields) <= max(col.values(), default=0):
                continue

            task_name = fields[col["name"]]
            command = fields[col.get("command", 0)]
            status = fields[col.get("status", 0)] if "status" in col else ""

            # Only include tasks likely to run at boot/logon
            raw_line_lower = line.lower()
            if not any(kw in raw_line_lower for kw in ("at logon", "at startup",
                                                        "boot", "logon")):
                continue

            # Skip deep Microsoft system tasks to reduce noise
            if task_name.startswith("\\Microsoft\\Windows\\"):
                continue

            enabled = status.lower() not in ("disabled",)
            items.append({
                "name": task_name,
                "command": command,
                "location": "Scheduled Task",
                "enabled": enabled,
                "impact": _estimate_impact(task_name, command),
            })
    except Exception:
        pass
    return items


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_startup_items():
    """Return a combined list of all startup items.

    Returns
    -------
    list[dict]
        Each dict contains: name, command, location, enabled, impact.
    """
    items = []
    items.extend(_read_registry_run_keys())
    items.extend(_read_startup_folder())
    items.extend(_read_scheduled_tasks())

    # Sort: enabled first, then by impact severity
    severity = {"High": 0, "Medium": 1, "Low": 2, "Unknown": 3}
    items.sort(key=lambda x: (not x["enabled"], severity.get(x["impact"], 99)))
    return items


def disable_startup_item(name, location):
    """Disable a startup entry by *name* at the given *location*.

    For registry entries the value is renamed with a disabled suffix.
    For Startup Folder items the file is renamed.
    For Scheduled Tasks the task is disabled via schtasks.

    Returns
    -------
    bool
        True on success.
    """
    if location == "Startup Folder":
        return _disable_startup_folder_item(name)
    elif location == "Scheduled Task":
        return _disable_scheduled_task(name)
    else:
        return _disable_registry_item(name, location)


def enable_startup_item(name, location):
    """Re-enable a previously disabled startup entry.

    Returns
    -------
    bool
        True on success.
    """
    if location == "Startup Folder":
        return _enable_startup_folder_item(name)
    elif location == "Scheduled Task":
        return _enable_scheduled_task(name)
    else:
        return _enable_registry_item(name, location)


# ---------------------------------------------------------------------------
# Internal disable / enable implementations
# ---------------------------------------------------------------------------

def _hive_and_subkey_for(location):
    """Map a location label back to (hive, subkey)."""
    for hive, subkey, label in _REGISTRY_LOCATIONS:
        if label == location:
            return hive, subkey
    return None, None


def _disable_registry_item(name, location):
    hive, subkey = _hive_and_subkey_for(location)
    if hive is None:
        return False
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_ALL_ACCESS) as key:
            value, reg_type = winreg.QueryValueEx(key, name)
            winreg.SetValueEx(key, name + _DISABLED_SUFFIX, 0, reg_type, value)
            winreg.DeleteValue(key, name)
        return True
    except OSError:
        return False


def _enable_registry_item(name, location):
    hive, subkey = _hive_and_subkey_for(location)
    if hive is None:
        return False
    disabled_name = name + _DISABLED_SUFFIX
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_ALL_ACCESS) as key:
            value, reg_type = winreg.QueryValueEx(key, disabled_name)
            winreg.SetValueEx(key, name, 0, reg_type, value)
            winreg.DeleteValue(key, disabled_name)
        return True
    except OSError:
        return False


def _disable_startup_folder_item(name):
    folder = _get_startup_folder()
    src = os.path.join(folder, name)
    dst = os.path.join(folder, name + _DISABLED_SUFFIX)
    try:
        os.rename(src, dst)
        return True
    except OSError:
        return False


def _enable_startup_folder_item(name):
    folder = _get_startup_folder()
    src = os.path.join(folder, name + _DISABLED_SUFFIX)
    dst = os.path.join(folder, name)
    try:
        os.rename(src, dst)
        return True
    except OSError:
        return False


def _disable_scheduled_task(name):
    try:
        result = subprocess.run(
            ["schtasks", "/change", "/tn", name, "/disable"],
            capture_output=True, text=True, timeout=15,
        )
        return result.returncode == 0
    except Exception:
        return False


def _enable_scheduled_task(name):
    try:
        result = subprocess.run(
            ["schtasks", "/change", "/tn", name, "/enable"],
            capture_output=True, text=True, timeout=15,
        )
        return result.returncode == 0
    except Exception:
        return False
