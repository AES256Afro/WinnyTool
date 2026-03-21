"""
WinnyTool - Disk Health Checker
Scans disk drives for health, fragmentation, SMART status, and cleanup opportunities.
"""

import os
import shutil
import subprocess
import tempfile
import glob
import time
from pathlib import Path
from typing import Optional


def get_disk_info() -> list[dict]:
    """Get all drives with total/free space, filesystem type."""
    drives = []
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID,Size,FreeSpace,FileSystem,DriveType,VolumeName | Format-List"],
            capture_output=True, text=True, timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        current = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                if current.get("drive"):
                    drives.append(current)
                current = {}
                continue
            if " : " in line:
                key, _, value = line.partition(" : ")
                key, value = key.strip(), value.strip()
                if key == "DeviceID":
                    current["drive"] = value
                elif key == "Size":
                    current["total_bytes"] = int(value) if value.isdigit() else 0
                elif key == "FreeSpace":
                    current["free_bytes"] = int(value) if value.isdigit() else 0
                elif key == "FileSystem":
                    current["filesystem"] = value or "Unknown"
                elif key == "DriveType":
                    current["drive_type"] = int(value) if value.isdigit() else 0
                elif key == "VolumeName":
                    current["volume_name"] = value or ""
        if current.get("drive"):
            drives.append(current)
        # Fill defaults
        for d in drives:
            d.setdefault("volume_name", "")
            d.setdefault("filesystem", "Unknown")
            d.setdefault("drive_type", 0)
            d.setdefault("total_bytes", 0)
            d.setdefault("free_bytes", 0)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        # Fallback: use shutil.disk_usage on common drive letters
        for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
            drive_path = f"{letter}:\\"
            if os.path.exists(drive_path):
                try:
                    usage = shutil.disk_usage(drive_path)
                    drives.append({
                        "drive": f"{letter}:",
                        "volume_name": "",
                        "filesystem": "Unknown",
                        "drive_type": 3,
                        "total_bytes": usage.total,
                        "free_bytes": usage.free,
                    })
                except OSError:
                    continue
    return drives


def check_smart_status() -> list[dict]:
    """Get SMART health status for all physical drives via PowerShell."""
    results = []
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_DiskDrive | Select-Object Status,Model,Size,MediaType | Format-List"],
            capture_output=True, text=True, timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        current = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                if current.get("model"):
                    results.append(current)
                current = {}
                continue
            if " : " in line:
                key, _, value = line.partition(" : ")
                key, value = key.strip(), value.strip()
                if key == "Model":
                    current["model"] = value or "Unknown"
                elif key == "Status":
                    current["status"] = value or "Unknown"
                elif key == "Size":
                    try:
                        current["size"] = f"{int(value) / (1024**3):.1f} GB"
                    except (ValueError, TypeError):
                        current["size"] = ""
                elif key == "MediaType":
                    current["media_type"] = value or "Unknown"
        if current.get("model"):
            results.append(current)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return results


def _is_ssd(drive_letter: str) -> Optional[bool]:
    """Attempt to detect if a drive is SSD. Returns None if unknown."""
    try:
        # Use PowerShell to check media type
        ps_cmd = (
            f"Get-PhysicalDisk | Get-Disk | Get-Partition | "
            f"Where-Object DriveLetter -eq '{drive_letter[0]}' | "
            f"Get-Disk | Select-Object -ExpandProperty MediaType"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=15
        )
        output = result.stdout.strip().lower()
        if "ssd" in output or "solid" in output:
            return True
        if "hdd" in output or "unspecified" in output:
            return False
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return None


def check_fragmentation(drive_letter: str = "C:") -> dict:
    """
    Check if an HDD needs defragmentation via 'defrag /A /V'.
    Skips SSDs since defrag is unnecessary and harmful for them.
    """
    result_info = {
        "drive": drive_letter,
        "needs_defrag": False,
        "fragmentation_pct": None,
        "is_ssd": None,
        "details": "",
    }

    ssd = _is_ssd(drive_letter)
    result_info["is_ssd"] = ssd

    if ssd is True:
        result_info["details"] = f"{drive_letter} is an SSD - defragmentation skipped."
        return result_info

    try:
        proc = subprocess.run(
            ["defrag", drive_letter, "/A", "/V"],
            capture_output=True, text=True, timeout=120
        )
        output = proc.stdout + proc.stderr
        result_info["details"] = output.strip()

        # Try to parse fragmentation percentage
        for line in output.splitlines():
            line_lower = line.lower()
            if "fragmented" in line_lower and "%" in line:
                # Extract percentage
                parts = line.split("%")
                if parts:
                    num_str = parts[0].strip().split()[-1]
                    try:
                        pct = int(num_str)
                        result_info["fragmentation_pct"] = pct
                        result_info["needs_defrag"] = pct > 10
                    except ValueError:
                        pass
    except subprocess.TimeoutExpired:
        result_info["details"] = "Fragmentation analysis timed out."
    except (FileNotFoundError, OSError) as e:
        result_info["details"] = f"Could not run defrag analysis: {e}"

    return result_info


def check_trim_status() -> dict:
    """For SSDs, check if TRIM is enabled via fsutil."""
    info = {"trim_enabled": None, "details": ""}
    try:
        result = subprocess.run(
            ["fsutil", "behavior", "query", "DisableDeleteNotify"],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout.strip()
        info["details"] = output

        # DisableDeleteNotify = 0 means TRIM is enabled
        if "= 0" in output or "=0" in output:
            info["trim_enabled"] = True
        elif "= 1" in output or "=1" in output:
            info["trim_enabled"] = False
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        info["details"] = f"Could not check TRIM status: {e}"
    return info


def _dir_size(path: str) -> int:
    """Calculate total size of files in a directory (non-recursive-safe)."""
    total = 0
    try:
        for dirpath, dirnames, filenames in os.walk(path):
            for f in filenames:
                try:
                    fp = os.path.join(dirpath, f)
                    if os.path.isfile(fp):
                        total += os.path.getsize(fp)
                except (OSError, PermissionError):
                    continue
    except (OSError, PermissionError):
        pass
    return total


def estimate_cleanup() -> dict:
    """
    Calculate sizes of cleanable items:
    temp files, recycle bin, browser caches, Windows Update cleanup, old Windows.
    """
    estimates = {}

    # User temp
    user_temp = tempfile.gettempdir()
    estimates["user_temp"] = {
        "path": user_temp,
        "size_bytes": _dir_size(user_temp),
    }

    # Windows temp
    win_temp = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp")
    estimates["windows_temp"] = {
        "path": win_temp,
        "size_bytes": _dir_size(win_temp),
    }

    # Browser caches
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    browser_caches = {
        "chrome": os.path.join(local_app_data, "Google", "Chrome", "User Data", "Default", "Cache"),
        "edge": os.path.join(local_app_data, "Microsoft", "Edge", "User Data", "Default", "Cache"),
        "firefox_parent": os.path.join(local_app_data, "Mozilla", "Firefox", "Profiles"),
    }
    total_browser = 0
    for name, cache_path in browser_caches.items():
        if os.path.isdir(cache_path):
            total_browser += _dir_size(cache_path)
    estimates["browser_caches"] = {
        "size_bytes": total_browser,
    }

    # Windows Update cleanup (SoftwareDistribution\Download)
    sw_dist = os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"),
        "SoftwareDistribution", "Download"
    )
    estimates["windows_update_cache"] = {
        "path": sw_dist,
        "size_bytes": _dir_size(sw_dist),
    }

    # Old Windows installation (Windows.old)
    win_old = r"C:\Windows.old"
    estimates["old_windows"] = {
        "path": win_old,
        "size_bytes": _dir_size(win_old) if os.path.isdir(win_old) else 0,
    }

    # Recycle bin size estimate via PowerShell
    recycle_size = 0
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(New-Object -ComObject Shell.Application).Namespace(0x0A).Items() | "
             "Measure-Object -Property Size -Sum | Select-Object -ExpandProperty Sum"],
            capture_output=True, text=True, timeout=15
        )
        val = result.stdout.strip()
        if val.isdigit():
            recycle_size = int(val)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    estimates["recycle_bin"] = {"size_bytes": recycle_size}

    # Total
    estimates["total_bytes"] = sum(
        v.get("size_bytes", 0) for v in estimates.values() if isinstance(v, dict)
    )

    return estimates


def cleanup_temp_files(max_age_days: int = 7) -> dict:
    """Delete files in %TEMP% and Windows\\Temp older than max_age_days."""
    cutoff = time.time() - (max_age_days * 86400)
    deleted_count = 0
    freed_bytes = 0
    errors = 0

    temp_dirs = [
        tempfile.gettempdir(),
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp"),
    ]

    for temp_dir in temp_dirs:
        if not os.path.isdir(temp_dir):
            continue
        for dirpath, dirnames, filenames in os.walk(temp_dir, topdown=False):
            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                try:
                    if os.path.getmtime(fpath) < cutoff:
                        size = os.path.getsize(fpath)
                        os.remove(fpath)
                        deleted_count += 1
                        freed_bytes += size
                except (OSError, PermissionError):
                    errors += 1
            # Try to remove empty directories
            for dname in dirnames:
                dpath = os.path.join(dirpath, dname)
                try:
                    os.rmdir(dpath)
                except OSError:
                    pass

    return {
        "deleted_files": deleted_count,
        "freed_bytes": freed_bytes,
        "errors": errors,
    }


def get_large_files(path: str = "C:\\", top_n: int = 20) -> list[dict]:
    """Find the largest files on a drive or path."""
    files = []
    try:
        for dirpath, dirnames, filenames in os.walk(path):
            # Skip system directories that are slow or inaccessible
            dirnames[:] = [
                d for d in dirnames
                if d.lower() not in (
                    "$recycle.bin", "system volume information",
                    "windows", "program files", "program files (x86)"
                )
            ]
            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                try:
                    size = os.path.getsize(fpath)
                    files.append({"path": fpath, "size_bytes": size})
                except (OSError, PermissionError):
                    continue
    except (OSError, PermissionError):
        pass

    files.sort(key=lambda x: x["size_bytes"], reverse=True)
    return files[:top_n]


def _fmt_bytes(b: int) -> str:
    """Format bytes into a human-readable string."""
    if b < 0:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(b) < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


def scan_disk_health() -> list[dict]:
    """
    Run all disk health checks and return a list of result dicts.
    Each dict: {"check": str, "status": str, "details": str, "fix_action": dict|None}
    """
    results = []

    # 1. Disk space check
    try:
        drives = get_disk_info()
        for d in drives:
            if d["total_bytes"] == 0:
                continue
            free_pct = (d["free_bytes"] / d["total_bytes"]) * 100
            total_str = _fmt_bytes(d["total_bytes"])
            free_str = _fmt_bytes(d["free_bytes"])

            if free_pct < 5:
                status = "Critical"
            elif free_pct < 15:
                status = "Warning"
            else:
                status = "Good"

            details = (
                f"{d['drive']} ({d['filesystem']}) - "
                f"{free_str} free of {total_str} ({free_pct:.1f}% free)"
            )
            fix = None
            if status != "Good":
                fix = {
                    "label": f"Run Disk Cleanup on {d['drive']}",
                    "command": f"cleanmgr /d {d['drive'][0]}",
                }

            results.append({
                "check": f"Disk Space - {d['drive']}",
                "status": status,
                "details": details,
                "fix_action": fix,
            })
    except Exception as e:
        results.append({
            "check": "Disk Space",
            "status": "Warning",
            "details": f"Could not retrieve disk info: {e}",
            "fix_action": None,
        })

    # 2. SMART status
    try:
        smart = check_smart_status()
        if smart:
            for disk in smart:
                st = disk["status"].lower()
                if st == "ok":
                    status = "Good"
                elif st in ("pred fail", "degraded"):
                    status = "Critical"
                else:
                    status = "Warning"

                details = (
                    f"{disk['model']} ({disk['size']}, {disk['media_type']}) "
                    f"- SMART Status: {disk['status']}"
                )
                fix = None
                if status == "Critical":
                    fix = {
                        "label": "Back up data immediately - drive may be failing",
                        "command": "wbadmin start backup -backupTarget:D: -include:C: -quiet",
                    }
                results.append({
                    "check": f"SMART Health - {disk['model']}",
                    "status": status,
                    "details": details,
                    "fix_action": fix,
                })
        else:
            results.append({
                "check": "SMART Health",
                "status": "Warning",
                "details": "No SMART data available from WMIC.",
                "fix_action": None,
            })
    except Exception as e:
        results.append({
            "check": "SMART Health",
            "status": "Warning",
            "details": f"Could not check SMART status: {e}",
            "fix_action": None,
        })

    # 3. TRIM status (for SSDs)
    try:
        trim = check_trim_status()
        if trim["trim_enabled"] is True:
            results.append({
                "check": "SSD TRIM",
                "status": "Good",
                "details": "TRIM is enabled (DisableDeleteNotify = 0).",
                "fix_action": None,
            })
        elif trim["trim_enabled"] is False:
            results.append({
                "check": "SSD TRIM",
                "status": "Warning",
                "details": "TRIM is disabled. SSD performance may degrade over time.",
                "fix_action": {
                    "label": "Enable TRIM",
                    "command": "fsutil behavior set DisableDeleteNotify 0",
                },
            })
        else:
            results.append({
                "check": "SSD TRIM",
                "status": "Warning",
                "details": trim["details"] or "Could not determine TRIM status.",
                "fix_action": None,
            })
    except Exception as e:
        results.append({
            "check": "SSD TRIM",
            "status": "Warning",
            "details": f"Could not check TRIM: {e}",
            "fix_action": None,
        })

    # 4. Fragmentation (C: drive only by default)
    try:
        frag = check_fragmentation("C:")
        if frag["is_ssd"]:
            results.append({
                "check": "Fragmentation - C:",
                "status": "Good",
                "details": "C: is an SSD - defragmentation not needed.",
                "fix_action": None,
            })
        elif frag["fragmentation_pct"] is not None:
            pct = frag["fragmentation_pct"]
            if pct > 20:
                status = "Critical"
            elif pct > 10:
                status = "Warning"
            else:
                status = "Good"
            results.append({
                "check": "Fragmentation - C:",
                "status": status,
                "details": f"C: drive is {pct}% fragmented.",
                "fix_action": {
                    "label": "Defragment C: drive",
                    "command": "defrag C: /O",
                } if status != "Good" else None,
            })
        else:
            results.append({
                "check": "Fragmentation - C:",
                "status": "Warning",
                "details": frag["details"][:200] or "Could not determine fragmentation level.",
                "fix_action": None,
            })
    except Exception as e:
        results.append({
            "check": "Fragmentation - C:",
            "status": "Warning",
            "details": f"Could not check fragmentation: {e}",
            "fix_action": None,
        })

    # 5. Cleanup estimate
    try:
        cleanup = estimate_cleanup()
        total = cleanup.get("total_bytes", 0)
        if total > 5 * 1024**3:  # > 5 GB
            status = "Warning"
        else:
            status = "Good"

        parts = []
        for key in ("user_temp", "windows_temp", "browser_caches",
                     "windows_update_cache", "old_windows", "recycle_bin"):
            entry = cleanup.get(key, {})
            size = entry.get("size_bytes", 0)
            if size > 0:
                parts.append(f"{key}: {_fmt_bytes(size)}")

        details = f"Total reclaimable: {_fmt_bytes(total)}"
        if parts:
            details += " (" + ", ".join(parts) + ")"

        results.append({
            "check": "Disk Cleanup Potential",
            "status": status,
            "details": details,
            "fix_action": {
                "label": "Clean temp files older than 7 days",
                "command": "cleanmgr /sagerun:1",
            } if total > 500 * 1024**2 else None,
        })
    except Exception as e:
        results.append({
            "check": "Disk Cleanup Potential",
            "status": "Warning",
            "details": f"Could not estimate cleanup: {e}",
            "fix_action": None,
        })

    return results


if __name__ == "__main__":
    print("=== WinnyTool Disk Health Scan ===\n")
    for item in scan_disk_health():
        icon = {"Good": "[OK]", "Warning": "[!!]", "Critical": "[XX]"}.get(item["status"], "[??]")
        print(f"{icon} {item['check']}: {item['status']}")
        print(f"    {item['details']}")
        if item["fix_action"]:
            print(f"    Fix: {item['fix_action']['label']}")
        print()
