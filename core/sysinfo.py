"""
WinnyTool - System Information Dashboard
Collects comprehensive system hardware and software information using
PowerShell CIM instances (compatible with Windows 11 where WMIC is removed).
"""

import platform
import subprocess
import os
from datetime import datetime, timedelta


def _run_ps(command: str) -> str:
    """Run a PowerShell command and return its stripped output."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
        return ""


def _parse_format_list(raw: str) -> list[dict[str, str]]:
    """Parse PowerShell Format-List output into a list of dicts.

    Format-List produces lines like:
        Key : Value
    with blank lines separating records.
    """
    records = []
    current = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            if current:
                records.append(current)
                current = {}
            continue
        if " : " in line:
            key, _, value = line.partition(" : ")
            current[key.strip()] = value.strip()
        elif ":" in line:
            key, _, value = line.partition(":")
            current[key.strip()] = value.strip()
    if current:
        records.append(current)
    return records


def _get_cpu_info() -> dict:
    """Retrieve CPU name, cores, and threads."""
    info = {"cpu_name": "Unknown", "cpu_cores": 0, "cpu_threads": 0}
    raw = _run_ps(
        "Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors | Format-List"
    )
    if not raw:
        return info
    records = _parse_format_list(raw)
    if records:
        r = records[0]
        info["cpu_name"] = r.get("Name", "Unknown").strip()
        try:
            info["cpu_cores"] = int(r.get("NumberOfCores", 0))
        except ValueError:
            pass
        try:
            info["cpu_threads"] = int(r.get("NumberOfLogicalProcessors", 0))
        except ValueError:
            pass
    return info


def _get_ram_info() -> dict:
    """Retrieve total and available RAM."""
    info = {"ram_total": "Unknown", "ram_available": "Unknown"}
    raw = _run_ps(
        "Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory | Format-List"
    )
    if not raw:
        return info
    records = _parse_format_list(raw)
    if records:
        r = records[0]
        try:
            total_kb = int(r.get("TotalVisibleMemorySize", 0))
            info["ram_total"] = f"{total_kb / 1048576:.1f} GB"
        except (ValueError, TypeError):
            pass
        try:
            free_kb = int(r.get("FreePhysicalMemory", 0))
            info["ram_available"] = f"{free_kb / 1048576:.1f} GB"
        except (ValueError, TypeError):
            pass
    return info


def _get_gpu_name() -> str:
    """Retrieve GPU name(s)."""
    raw = _run_ps(
        "Get-CimInstance Win32_VideoController | Select-Object Name | Format-List"
    )
    if not raw:
        return "Unknown"
    records = _parse_format_list(raw)
    names = [r.get("Name", "").strip() for r in records if r.get("Name", "").strip()]
    return ", ".join(names) if names else "Unknown"


def _get_disk_drives() -> list[dict]:
    """Retrieve disk drive information."""
    drives = []
    raw = _run_ps(
        "Get-CimInstance Win32_DiskDrive | Select-Object Model,Size,MediaType | Format-List"
    )
    if not raw:
        return drives
    records = _parse_format_list(raw)
    for r in records:
        model = r.get("Model", "Unknown")
        media = r.get("MediaType", "")
        try:
            size_bytes = int(r.get("Size", 0))
            size_str = f"{size_bytes / (1024 ** 3):.0f} GB"
        except (ValueError, TypeError):
            size_str = "Unknown"

        # Detect SSD vs HDD from model name or media type
        model_lower = (model + " " + media).lower()
        if "ssd" in model_lower or "nvme" in model_lower or "solid" in model_lower:
            dtype = "SSD"
        elif "external" in model_lower:
            dtype = "External"
        elif "fixed" in model_lower:
            dtype = "HDD/SSD"
        else:
            dtype = media if media else "Unknown"

        drives.append({"model": model, "size": size_str, "type": dtype})
    return drives


def _get_uptime() -> str:
    """Calculate system uptime from last boot time."""
    raw = _run_ps(
        "Get-CimInstance Win32_OperatingSystem | Select-Object LastBootUpTime | Format-List"
    )
    if not raw:
        return "Unknown"
    records = _parse_format_list(raw)
    if not records:
        return "Unknown"
    boot_str = records[0].get("LastBootUpTime", "")
    if not boot_str:
        return "Unknown"
    # Try multiple date formats PowerShell may output
    for fmt in [
        "%m/%d/%Y %I:%M:%S %p",  # 3/19/2026 4:01:41 PM
        "%m/%d/%Y %H:%M:%S",     # 3/19/2026 16:01:41
        "%Y-%m-%d %H:%M:%S",     # 2026-03-19 16:01:41
        "%d/%m/%Y %H:%M:%S",     # 19/03/2026 16:01:41
        "%d/%m/%Y %I:%M:%S %p",  # 19/03/2026 4:01:41 PM
    ]:
        try:
            boot_time = datetime.strptime(boot_str, fmt)
            delta = datetime.now() - boot_time
            days = delta.days
            hours, remainder = divmod(delta.seconds, 3600)
            minutes, _ = divmod(remainder, 60)
            parts = []
            if days > 0:
                parts.append(f"{days}d")
            parts.append(f"{hours}h {minutes}m")
            return " ".join(parts)
        except ValueError:
            continue
    return boot_str  # Return raw string if parsing fails


def _get_installed_antivirus() -> list[str]:
    """Retrieve installed antivirus products."""
    raw = _run_ps(
        "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName | Format-List"
    )
    if not raw:
        return ["Unable to detect"]
    records = _parse_format_list(raw)
    products = [r.get("displayName", "").strip() for r in records if r.get("displayName", "").strip()]
    return products if products else ["None detected"]


def get_system_info() -> dict:
    """
    Collect comprehensive system information and return it as a dictionary.
    """
    info = {}

    # OS information
    info["os_name"] = platform.system()
    info["os_version"] = platform.version()
    info["os_build"] = platform.platform()
    info["architecture"] = platform.machine()

    # User and computer
    info["computer_name"] = platform.node()
    try:
        info["username"] = os.getlogin()
    except OSError:
        info["username"] = os.environ.get("USERNAME", "Unknown")

    # CPU
    cpu = _get_cpu_info()
    info["cpu_name"] = cpu["cpu_name"]
    info["cpu_cores"] = cpu["cpu_cores"]
    info["cpu_threads"] = cpu["cpu_threads"]

    # RAM
    ram = _get_ram_info()
    info["ram_total"] = ram["ram_total"]
    info["ram_available"] = ram["ram_available"]

    # GPU
    info["gpu_name"] = _get_gpu_name()

    # Disk drives
    info["disk_drives"] = _get_disk_drives()

    # Uptime
    info["uptime"] = _get_uptime()

    # Antivirus
    info["installed_antivirus"] = _get_installed_antivirus()

    return info


if __name__ == "__main__":
    import json
    data = get_system_info()
    print(json.dumps(data, indent=2))
