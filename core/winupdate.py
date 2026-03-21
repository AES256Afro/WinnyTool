"""
WinnyTool - Windows Update Status
Checks update history, pending updates, service status, and OS build support.
"""

import os
import re
import subprocess
from datetime import datetime, timedelta
from typing import Optional

try:
    import winreg
except ImportError:
    winreg = None


def get_update_history(count: int = 20) -> list[dict]:
    """
    Get recent Windows updates using PowerShell Get-HotFix.
    Returns a list of dicts with KB info, description, and install date.
    """
    updates = []
    try:
        ps_cmd = (
            f"Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue "
            f"| Select-Object -First {count} "
            f"| Format-Table HotFixID, Description, InstalledOn, InstalledBy -AutoSize "
            f"| Out-String -Width 300"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout.strip()
        lines = output.splitlines()

        # Skip header lines (blank, header, separator)
        data_started = False
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("---"):
                data_started = True
                continue
            if not data_started:
                continue

            parts = stripped.split(None, 3)
            if len(parts) >= 1:
                entry = {
                    "hotfix_id": parts[0] if len(parts) > 0 else "",
                    "description": parts[1] if len(parts) > 1 else "",
                    "installed_on": parts[2] if len(parts) > 2 else "",
                    "installed_by": parts[3] if len(parts) > 3 else "",
                }
                updates.append(entry)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return updates


def check_last_update_date() -> dict:
    """Flag if last update was more than 30 days ago."""
    info = {"last_update": None, "days_ago": None, "details": ""}

    try:
        ps_cmd = (
            "Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue "
            "| Select-Object -First 1 -ExpandProperty InstalledOn "
            "| Get-Date -Format 'yyyy-MM-dd'"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=20
        )
        date_str = result.stdout.strip()

        if date_str:
            try:
                last_date = datetime.strptime(date_str, "%Y-%m-%d")
                info["last_update"] = date_str
                info["days_ago"] = (datetime.now() - last_date).days

                if info["days_ago"] > 60:
                    info["details"] = (
                        f"Last update installed {info['days_ago']} days ago ({date_str}). "
                        "System is significantly behind on updates."
                    )
                elif info["days_ago"] > 30:
                    info["details"] = (
                        f"Last update installed {info['days_ago']} days ago ({date_str}). "
                        "Consider checking for updates."
                    )
                else:
                    info["details"] = (
                        f"Last update installed {info['days_ago']} days ago ({date_str})."
                    )
            except ValueError:
                info["details"] = f"Could not parse update date: {date_str}"
        else:
            info["details"] = "No update history found."

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        info["details"] = f"Could not check update history: {e}"

    return info


def check_pending_updates() -> dict:
    """
    Try to detect pending updates via registry and COM object fallback.
    """
    info = {"pending_count": 0, "pending_items": [], "details": ""}

    # Method 1: Check registry for pending reboot (indicates updates installed but not applied)
    reboot_pending = False
    if winreg:
        reboot_keys = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        ]
        for key_path in reboot_keys:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                winreg.CloseKey(key)
                reboot_pending = True
                break
            except (FileNotFoundError, OSError):
                continue

    # Method 2: Use PowerShell with COM object to check for pending updates
    try:
        ps_cmd = (
            "$UpdateSession = New-Object -ComObject Microsoft.Update.Session; "
            "$UpdateSearcher = $UpdateSession.CreateUpdateSearcher(); "
            "$SearchResult = $UpdateSearcher.Search('IsInstalled=0 and IsHidden=0'); "
            "$SearchResult.Updates | ForEach-Object { $_.Title } | Select-Object -First 10"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=60
        )
        output = result.stdout.strip()

        if output and result.returncode == 0:
            pending = [line.strip() for line in output.splitlines() if line.strip()]
            info["pending_count"] = len(pending)
            info["pending_items"] = pending

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # Build details
    parts = []
    if info["pending_count"] > 0:
        parts.append(f"{info['pending_count']} pending update(s) found.")
    if reboot_pending:
        parts.append("A system reboot is required to finish installing updates.")
        info["reboot_pending"] = True
    else:
        info["reboot_pending"] = False

    if not parts:
        info["details"] = "No pending updates detected."
    else:
        info["details"] = " ".join(parts)

    return info


def check_update_service() -> dict:
    """Verify the Windows Update service (wuauserv) is running."""
    info = {"running": False, "start_type": "", "details": ""}
    try:
        result = subprocess.run(
            ["sc", "query", "wuauserv"],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout

        state_match = re.search(r"STATE\s*:\s*\d+\s+(\w+)", output)
        if state_match:
            state = state_match.group(1)
            info["running"] = state.upper() == "RUNNING"
            info["details"] = f"Windows Update service is {state}."
        else:
            info["details"] = "Could not determine Windows Update service state."

        # Also check start type
        qc_result = subprocess.run(
            ["sc", "qc", "wuauserv"],
            capture_output=True, text=True, timeout=10
        )
        start_match = re.search(r"START_TYPE\s*:\s*\d+\s+(\S+)", qc_result.stdout)
        if start_match:
            info["start_type"] = start_match.group(1)
            if info["start_type"].upper() == "DISABLED":
                info["details"] += " WARNING: Service start type is DISABLED."

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        info["details"] = f"Could not check Windows Update service: {e}"

    return info


def get_os_build() -> dict:
    """Get current OS build and check if it's still supported."""
    info = {
        "build": "",
        "version": "",
        "product_name": "",
        "details": "",
    }

    if winreg:
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            )
            try:
                info["build"], _ = winreg.QueryValueEx(key, "CurrentBuildNumber")
            except FileNotFoundError:
                pass
            try:
                info["version"], _ = winreg.QueryValueEx(key, "DisplayVersion")
            except FileNotFoundError:
                try:
                    info["version"], _ = winreg.QueryValueEx(key, "ReleaseId")
                except FileNotFoundError:
                    pass
            try:
                info["product_name"], _ = winreg.QueryValueEx(key, "ProductName")
            except FileNotFoundError:
                pass
            try:
                ubr, _ = winreg.QueryValueEx(key, "UBR")
                info["ubr"] = ubr
            except FileNotFoundError:
                pass
            winreg.CloseKey(key)
        except (OSError, PermissionError):
            pass

    # Fallback: use systeminfo or ver
    if not info["build"]:
        try:
            result = subprocess.run(
                ["cmd", "/c", "ver"],
                capture_output=True, text=True, timeout=10
            )
            ver_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", result.stdout)
            if ver_match:
                info["build"] = ver_match.group(1)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    # Known end-of-service builds for Windows 10/11
    # (approximate - major feature update builds)
    eol_builds = {
        # Windows 10 builds that are end of life
        "19041": "Windows 10 2004 (EOL: Dec 2021)",
        "19042": "Windows 10 20H2 (EOL: Jun 2022)",
        "19043": "Windows 10 21H1 (EOL: Dec 2022)",
        "19044": "Windows 10 21H2 (EOL: Jun 2024)",
        "19045": "Windows 10 22H2 (EOL: Oct 2025)",
    }

    build_num = str(info["build"])
    ubr = info.get("ubr", "")
    full_build = f"{build_num}.{ubr}" if ubr else build_num

    info["details"] = (
        f"{info['product_name']} version {info['version']} "
        f"(Build {full_build})"
    )

    if build_num in eol_builds:
        eol_info = eol_builds[build_num]
        info["details"] += f" - {eol_info}"
        info["eol_warning"] = True
    else:
        info["eol_warning"] = False

    return info


def check_feature_update() -> dict:
    """Check if a feature update is available by comparing current build."""
    info = {"available": False, "details": ""}

    os_info = get_os_build()
    build = str(os_info.get("build", ""))

    # Windows 11 latest known builds (as of early 2026)
    # Build 22621 = 22H2, 22631 = 23H2, 26100 = 24H2
    win11_latest_build = 26100
    # Windows 10 latest = 19045 (22H2 - final)
    win10_latest_build = 19045

    try:
        build_int = int(build)
    except (ValueError, TypeError):
        info["details"] = "Could not determine current build number."
        return info

    product = os_info.get("product_name", "").lower()

    if "windows 11" in product or build_int >= 22000:
        if build_int < win11_latest_build:
            info["available"] = True
            info["details"] = (
                f"A newer Windows 11 feature update may be available. "
                f"Current build: {build}, latest known: {win11_latest_build}."
            )
        else:
            info["details"] = f"Running latest known Windows 11 build ({build})."
    elif "windows 10" in product or 19000 <= build_int < 22000:
        if build_int < win10_latest_build:
            info["available"] = True
            info["details"] = (
                f"A newer Windows 10 feature update is available. "
                f"Current build: {build}, latest: {win10_latest_build}."
            )
        else:
            info["details"] = (
                f"Running latest Windows 10 build ({build}). "
                "Consider upgrading to Windows 11 if hardware supports it."
            )
    else:
        info["details"] = f"OS build {build} - could not determine update availability."

    return info


def scan_updates() -> list[dict]:
    """
    Run all Windows Update checks and return a list of result dicts.
    Each dict: {"check": str, "status": str, "details": str, "fix_action": dict|None}
    """
    results = []

    # 1. OS build info
    try:
        os_info = get_os_build()
        eol = os_info.get("eol_warning", False)
        results.append({
            "check": "OS Build",
            "status": "Warning" if eol else "Good",
            "details": os_info["details"],
            "fix_action": {
                "label": "Check for Windows updates",
                "command": "ms-settings:windowsupdate",
            } if eol else None,
        })
    except Exception as e:
        results.append({
            "check": "OS Build",
            "status": "Warning",
            "details": f"Could not check OS build: {e}",
            "fix_action": None,
        })

    # 2. Last update date
    try:
        last = check_last_update_date()
        days = last.get("days_ago")
        if days is not None and days > 60:
            status = "Critical"
        elif days is not None and days > 30:
            status = "Warning"
        else:
            status = "Good"

        fix = None
        if status != "Good":
            fix = {
                "label": "Open Windows Update",
                "command": "ms-settings:windowsupdate",
            }

        results.append({
            "check": "Last Update Date",
            "status": status,
            "details": last["details"],
            "fix_action": fix,
        })
    except Exception as e:
        results.append({
            "check": "Last Update Date",
            "status": "Warning",
            "details": f"Could not check last update date: {e}",
            "fix_action": None,
        })

    # 3. Windows Update service
    try:
        svc = check_update_service()
        if svc["running"]:
            status = "Good"
            fix = None
        elif svc.get("start_type", "").upper() == "DISABLED":
            status = "Critical"
            fix = {
                "label": "Enable and start Windows Update service",
                "command": "sc config wuauserv start=auto && net start wuauserv",
            }
        else:
            status = "Warning"
            fix = {
                "label": "Start Windows Update service",
                "command": "net start wuauserv",
            }

        results.append({
            "check": "Windows Update Service",
            "status": status,
            "details": svc["details"],
            "fix_action": fix,
        })
    except Exception as e:
        results.append({
            "check": "Windows Update Service",
            "status": "Warning",
            "details": f"Could not check service: {e}",
            "fix_action": None,
        })

    # 4. Pending updates
    try:
        pending = check_pending_updates()
        if pending.get("reboot_pending"):
            status = "Warning"
            fix = {
                "label": "Restart to finish installing updates",
                "command": "shutdown /r /t 60 /c \"Restarting to complete Windows Updates\"",
            }
        elif pending["pending_count"] > 0:
            status = "Warning"
            items_preview = ", ".join(pending["pending_items"][:3])
            if pending["pending_count"] > 3:
                items_preview += f" (+{pending['pending_count'] - 3} more)"
            pending["details"] += f" Updates: {items_preview}"
            fix = {
                "label": "Install pending updates",
                "command": "ms-settings:windowsupdate",
            }
        else:
            status = "Good"
            fix = None

        results.append({
            "check": "Pending Updates",
            "status": status,
            "details": pending["details"],
            "fix_action": fix,
        })
    except Exception as e:
        results.append({
            "check": "Pending Updates",
            "status": "Warning",
            "details": f"Could not check pending updates: {e}",
            "fix_action": None,
        })

    # 5. Feature update
    try:
        feature = check_feature_update()
        if feature["available"]:
            status = "Warning"
            fix = {
                "label": "Check for feature updates",
                "command": "ms-settings:windowsupdate",
            }
        else:
            status = "Good"
            fix = None

        results.append({
            "check": "Feature Update",
            "status": status,
            "details": feature["details"],
            "fix_action": fix,
        })
    except Exception as e:
        results.append({
            "check": "Feature Update",
            "status": "Warning",
            "details": f"Could not check feature updates: {e}",
            "fix_action": None,
        })

    # 6. Recent update history summary
    try:
        history = get_update_history(5)
        if history:
            summary = "; ".join(
                f"{h['hotfix_id']} ({h['installed_on']})" for h in history[:5]
            )
            results.append({
                "check": "Recent Update History",
                "status": "Good",
                "details": f"Last {len(history)} updates: {summary}",
                "fix_action": None,
            })
        else:
            results.append({
                "check": "Recent Update History",
                "status": "Warning",
                "details": "No update history could be retrieved.",
                "fix_action": None,
            })
    except Exception as e:
        results.append({
            "check": "Recent Update History",
            "status": "Warning",
            "details": f"Could not retrieve history: {e}",
            "fix_action": None,
        })

    return results


if __name__ == "__main__":
    print("=== WinnyTool Windows Update Status ===\n")
    for item in scan_updates():
        icon = {"Good": "[OK]", "Warning": "[!!]", "Critical": "[XX]"}.get(item["status"], "[??]")
        print(f"{icon} {item['check']}: {item['status']}")
        print(f"    {item['details']}")
        if item["fix_action"]:
            print(f"    Fix: {item['fix_action']['label']}")
        print()
