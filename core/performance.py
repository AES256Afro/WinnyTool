"""
WinnyTool - Performance Optimizer Module

Scans Windows system settings that may be degrading performance and
provides actionable fix recommendations.
"""

import os
import glob
import subprocess
import winreg
import ctypes
import shutil


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reg_read(hive, subkey, value_name, default=None):
    """Safely read a single registry value."""
    try:
        with winreg.OpenKey(hive, subkey) as key:
            data, _ = winreg.QueryValueEx(key, value_name)
            return data
    except (FileNotFoundError, OSError):
        return default


def _service_status(service_name):
    """Return the status string of a Windows service, or None."""
    try:
        result = subprocess.run(
            ["sc", "query", service_name],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            if "STATE" in line:
                # e.g.  "        STATE              : 4  RUNNING"
                parts = line.strip().split()
                return parts[-1] if parts else None
    except Exception:
        pass
    return None


def _dir_size(path):
    """Return total size in bytes of all files under *path*."""
    total = 0
    try:
        for dirpath, _dirnames, filenames in os.walk(path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                try:
                    total += os.path.getsize(fp)
                except OSError:
                    pass
    except OSError:
        pass
    return total


def _bytes_human(n):
    """Return a human-readable size string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _is_ssd():
    """Best-effort check whether the system drive is an SSD."""
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "Get-PhysicalDisk | Select-Object MediaType | Format-List"],
            capture_output=True, text=True, timeout=15,
        )
        return "SSD" in result.stdout
    except Exception:
        return None  # unknown


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_power_plan():
    """Detect current power plan; flag if not High / Ultimate Performance."""
    try:
        result = subprocess.run(
            ["powercfg", "/getactivescheme"],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout.strip()
        # Output example:
        # Power Scheme GUID: 381b4222-f694-...  (Balanced)
        plan_name = "Unknown"
        if "(" in output and ")" in output:
            plan_name = output.split("(")[-1].rstrip(")")

        high_perf_names = ("high performance", "ultimate performance")
        if plan_name.lower() not in high_perf_names:
            return {
                "issue": "Sub-optimal power plan",
                "description": (
                    f"Current power plan is '{plan_name}'. "
                    "High Performance or Ultimate Performance plans "
                    "reduce CPU throttling and improve responsiveness."
                ),
                "impact": "High",
                "current_value": plan_name,
                "recommended_value": "High Performance",
                "fix_action": {
                    "label": "Switch to High Performance",
                    "command": "powercfg /setactive SCHEME_MIN",
                },
            }
    except Exception as exc:
        return {
            "issue": "Could not read power plan",
            "description": str(exc),
            "impact": "Medium",
            "current_value": "Unknown",
            "recommended_value": "High Performance",
            "fix_action": None,
        }
    return None


def check_visual_effects():
    """Check visual-effects preference in the registry."""
    subkey = r"Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
    val = _reg_read(winreg.HKEY_CURRENT_USER, subkey, "VisualFXSetting")

    # 0 = Let Windows choose, 1 = Best appearance, 2 = Best performance, 3 = Custom
    labels = {0: "Let Windows choose", 1: "Best appearance",
              2: "Best performance", 3: "Custom"}
    current = labels.get(val, f"Unknown ({val})")

    if val is None or val in (0, 1):
        return {
            "issue": "Visual effects not optimised",
            "description": (
                f"Visual effects are set to '{current}'. "
                "Switching to 'Best performance' disables animations and "
                "transparency, freeing CPU/GPU resources."
            ),
            "impact": "Medium",
            "current_value": current,
            "recommended_value": "Best performance",
            "fix_action": {
                "label": "Set visual effects to Best Performance",
                "command": (
                    'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion'
                    '\\Explorer\\VisualEffects" /v VisualFXSetting /t REG_DWORD '
                    '/d 2 /f'
                ),
            },
        }
    return None


def check_startup_impact():
    """Use WMIC to enumerate startup items and flag high-impact ones."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_StartupCommand | Select-Object Name | Format-List"],
            capture_output=True, text=True, timeout=20,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        entries = result.stdout.strip()
        if not entries:
            return None

        # Count non-blank entry blocks
        blocks = [b for b in entries.split("\n\n") if b.strip()]
        if len(blocks) > 8:
            return {
                "issue": "Many startup programs detected",
                "description": (
                    f"Found {len(blocks)} startup items via WMIC. "
                    "Excessive startup programs slow boot time and "
                    "consume background resources."
                ),
                "impact": "High",
                "current_value": f"{len(blocks)} items",
                "recommended_value": "Review and disable unnecessary items",
                "fix_action": {
                    "label": "Open Task Manager Startup tab",
                    "command": "taskmgr /7 /startup",
                },
            }
    except Exception:
        pass
    return None


def check_background_apps():
    """Check whether background apps are allowed globally."""
    subkey = r"Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"
    val = _reg_read(winreg.HKEY_CURRENT_USER, subkey,
                    "GlobalUserDisabled", default=0)

    if val == 0:
        return {
            "issue": "Background apps are enabled",
            "description": (
                "Windows allows Store apps to run in the background, "
                "consuming CPU, memory and network even when not in use."
            ),
            "impact": "Medium",
            "current_value": "Enabled",
            "recommended_value": "Disabled",
            "fix_action": {
                "label": "Disable background apps",
                "command": (
                    'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion'
                    '\\BackgroundAccessApplications" /v GlobalUserDisabled '
                    '/t REG_DWORD /d 1 /f'
                ),
            },
        }
    return None


def check_search_indexing():
    """Check whether Windows Search indexer is running."""
    status = _service_status("WSearch")
    if status and status.upper() == "RUNNING":
        return {
            "issue": "Windows Search Indexer is running",
            "description": (
                "The Windows Search indexer continuously scans files, "
                "which can cause high disk and CPU usage, especially "
                "on HDDs or during large file operations."
            ),
            "impact": "Medium",
            "current_value": "Running",
            "recommended_value": "Disabled (if not relying on Windows Search)",
            "fix_action": {
                "label": "Stop and disable Windows Search",
                "command": "sc stop WSearch && sc config WSearch start= disabled",
            },
        }
    return None


def check_superfetch():
    """Check SysMain (Superfetch) status; recommend disabling on SSD."""
    status = _service_status("SysMain")
    if status is None:
        # Older naming
        status = _service_status("Superfetch")

    if status and status.upper() == "RUNNING":
        ssd = _is_ssd()
        if ssd is True:
            return {
                "issue": "SysMain (Superfetch) running on SSD",
                "description": (
                    "SysMain pre-caches frequently used apps into RAM. "
                    "On an SSD the benefit is negligible and the service "
                    "can cause unnecessary disk writes."
                ),
                "impact": "Low",
                "current_value": "Running (SSD detected)",
                "recommended_value": "Disabled on SSD",
                "fix_action": {
                    "label": "Disable SysMain service",
                    "command": "sc stop SysMain && sc config SysMain start= disabled",
                },
            }
        elif ssd is False:
            return {
                "issue": "SysMain (Superfetch) status",
                "description": (
                    "SysMain is running. On an HDD this can help, but if "
                    "you notice high disk usage it may be worth disabling."
                ),
                "impact": "Low",
                "current_value": "Running (HDD detected)",
                "recommended_value": "Monitor",
                "fix_action": None,
            }
    return None


def check_page_file():
    """Check pagefile configuration."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_PageFileUsage | Select-Object Name,AllocatedBaseSize,CurrentUsage | Format-List"],
            capture_output=True, text=True, timeout=10,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        output = result.stdout.strip()
        if not output:
            return {
                "issue": "No page file detected",
                "description": (
                    "No page file was found. While this saves disk space, "
                    "it can lead to crashes when physical RAM is exhausted."
                ),
                "impact": "High",
                "current_value": "None / disabled",
                "recommended_value": "System managed or 1.5x RAM",
                "fix_action": {
                    "label": "Open Virtual Memory settings",
                    "command": "SystemPropertiesPerformance.exe",
                },
            }
    except Exception:
        pass
    return None


def check_temp_files():
    """Calculate cumulative size of common temp directories."""
    temp_dirs = [
        os.environ.get("TEMP", ""),
        os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "Temp"),
        os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "Prefetch"),
    ]

    total = 0
    for d in temp_dirs:
        if d and os.path.isdir(d):
            total += _dir_size(d)

    if total > 500 * 1024 * 1024:  # > 500 MB
        return {
            "issue": "Large amount of temporary files",
            "description": (
                f"Temp directories contain {_bytes_human(total)} of data. "
                "Cleaning these can free disk space and sometimes improve "
                "performance."
            ),
            "impact": "Medium" if total > 1024 * 1024 * 1024 else "Low",
            "current_value": _bytes_human(total),
            "recommended_value": "< 500 MB",
            "fix_action": {
                "label": "Clean temp files",
                "command": (
                    'del /q/f/s "%TEMP%\\*" 2>nul & '
                    'del /q/f/s "%SYSTEMROOT%\\Temp\\*" 2>nul'
                ),
            },
        }
    return None


def check_disk_cleanup():
    """Estimate reclaimable space via common cleanup targets."""
    targets = []
    # Windows Update cleanup
    sxs = os.path.join(
        os.environ.get("SYSTEMROOT", r"C:\Windows"), "WinSxS", "Backup"
    )
    if os.path.isdir(sxs):
        targets.append(("WinSxS Backup", _dir_size(sxs)))

    # Recycle Bin (best-effort, per-drive $Recycle.Bin not always accessible)
    downloads = os.path.join(os.path.expanduser("~"), "Downloads")
    if os.path.isdir(downloads):
        targets.append(("Downloads folder", _dir_size(downloads)))

    total = sum(s for _, s in targets)
    if total > 1024 * 1024 * 1024:  # > 1 GB
        breakdown = ", ".join(f"{n}: {_bytes_human(s)}" for n, s in targets if s > 0)
        return {
            "issue": "Disk space can be reclaimed",
            "description": (
                f"Approximately {_bytes_human(total)} may be reclaimable. "
                f"Breakdown: {breakdown}."
            ),
            "impact": "Low",
            "current_value": _bytes_human(total),
            "recommended_value": "Run Disk Cleanup",
            "fix_action": {
                "label": "Launch Disk Cleanup",
                "command": "cleanmgr /d C",
            },
        }
    return None


def check_game_mode():
    """Check if Game Mode or Game Bar is enabled."""
    game_bar = _reg_read(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\GameBar",
        "AllowAutoGameMode",
    )
    game_dvr = _reg_read(
        winreg.HKEY_CURRENT_USER,
        r"System\GameConfigStore",
        "GameDVR_Enabled",
    )

    issues = []
    if game_bar is not None and game_bar != 0:
        issues.append("Game Mode is enabled")
    if game_dvr is not None and game_dvr != 0:
        issues.append("Game DVR is enabled")

    if issues:
        return {
            "issue": "Game Mode / Game Bar active",
            "description": (
                f"{'; '.join(issues)}. On non-gaming PCs these features "
                "can interfere with other workloads and record unwanted clips."
            ),
            "impact": "Low",
            "current_value": ", ".join(issues),
            "recommended_value": "Disabled (non-gaming PC)",
            "fix_action": {
                "label": "Disable Game Bar and DVR",
                "command": (
                    'reg add "HKCU\\Software\\Microsoft\\GameBar" '
                    '/v AllowAutoGameMode /t REG_DWORD /d 0 /f && '
                    'reg add "HKCU\\System\\GameConfigStore" '
                    '/v GameDVR_Enabled /t REG_DWORD /d 0 /f'
                ),
            },
        }
    return None


def check_notifications():
    """Check if excessive notification sources are enabled."""
    subkey = r"Software\Microsoft\Windows\CurrentVersion\PushNotifications"
    toast = _reg_read(winreg.HKEY_CURRENT_USER, subkey, "ToastEnabled", default=1)

    if toast == 1:
        # Count notification senders
        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Notifications\Settings",
            ) as key:
                count = winreg.QueryInfoKey(key)[0]  # number of subkeys
        except OSError:
            count = 0

        if count > 15:
            return {
                "issue": "Many notification sources enabled",
                "description": (
                    f"{count} apps are registered as notification senders. "
                    "Excessive notifications can interrupt focus and consume "
                    "resources rendering toast popups."
                ),
                "impact": "Low",
                "current_value": f"{count} sources, toasts enabled",
                "recommended_value": "Reduce to essential sources",
                "fix_action": {
                    "label": "Open Notification settings",
                    "command": "start ms-settings:notifications",
                },
            }
    return None


def check_transparency_effects():
    """Check if transparency/acrylic effects are enabled."""
    val = _reg_read(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        "EnableTransparency",
    )

    if val == 1:
        return {
            "issue": "Transparency effects enabled",
            "description": (
                "Windows transparency / acrylic blur effects are on. "
                "Disabling them reduces GPU compositing overhead, which "
                "is helpful on low-end hardware."
            ),
            "impact": "Low",
            "current_value": "Enabled",
            "recommended_value": "Disabled",
            "fix_action": {
                "label": "Disable transparency effects",
                "command": (
                    'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion'
                    '\\Themes\\Personalize" /v EnableTransparency '
                    '/t REG_DWORD /d 0 /f'
                ),
            },
        }
    return None


def check_tips_and_suggestions():
    """Check if Windows tips and suggestions are enabled."""
    subkey = r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    tips = _reg_read(winreg.HKEY_CURRENT_USER, subkey,
                     "SubscribedContent-338389Enabled", default=1)
    suggestions = _reg_read(winreg.HKEY_CURRENT_USER, subkey,
                            "SoftLandingEnabled", default=1)

    if tips == 1 or suggestions == 1:
        enabled = []
        if tips == 1:
            enabled.append("Tips")
        if suggestions == 1:
            enabled.append("Suggestions/Soft-landing")
        return {
            "issue": "Windows tips and suggestions enabled",
            "description": (
                f"{', '.join(enabled)} are active. These features run "
                "background tasks to curate content and can consume CPU "
                "and network bandwidth."
            ),
            "impact": "Low",
            "current_value": ", ".join(enabled),
            "recommended_value": "Disabled",
            "fix_action": {
                "label": "Disable tips and suggestions",
                "command": (
                    'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion'
                    '\\ContentDeliveryManager" '
                    '/v SubscribedContent-338389Enabled /t REG_DWORD /d 0 /f && '
                    'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion'
                    '\\ContentDeliveryManager" '
                    '/v SoftLandingEnabled /t REG_DWORD /d 0 /f'
                ),
            },
        }
    return None


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def scan_performance():
    """Run all performance checks and return a list of findings.

    Returns
    -------
    list[dict]
        Each dict has keys: issue, description, impact, current_value,
        recommended_value, fix_action (dict with label/command, or None).
    """
    checks = [
        check_power_plan,
        check_visual_effects,
        check_startup_impact,
        check_background_apps,
        check_search_indexing,
        check_superfetch,
        check_page_file,
        check_temp_files,
        check_disk_cleanup,
        check_game_mode,
        check_notifications,
        check_transparency_effects,
        check_tips_and_suggestions,
    ]

    findings = []
    for check_fn in checks:
        try:
            result = check_fn()
            if result is not None:
                findings.append(result)
        except Exception as exc:
            findings.append({
                "issue": f"Error in {check_fn.__name__}",
                "description": str(exc),
                "impact": "Unknown",
                "current_value": "Error",
                "recommended_value": "N/A",
                "fix_action": None,
            })

    # Sort by impact severity
    severity_order = {"High": 0, "Medium": 1, "Low": 2, "Unknown": 3}
    findings.sort(key=lambda f: severity_order.get(f["impact"], 99))

    return findings
