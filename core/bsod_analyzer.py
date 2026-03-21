"""
BSOD Analyzer module for WinnyTool.

Queries Windows Event Log for BugCheck / kernel power events and inspects
minidump files to surface recent Blue Screen of Death incidents along with
human-readable explanations and actionable fix suggestions.
"""

import subprocess
import os
import re
import glob
from datetime import datetime

# ---------------------------------------------------------------------------
# Comprehensive BSOD stop-code database
# ---------------------------------------------------------------------------

STOP_CODES = {
    "0x0000000A": {
        "name": "IRQL_NOT_LESS_OR_EQUAL",
        "common_causes": [
            "Faulty or incompatible device driver",
            "Defective hardware (RAM, NIC, GPU)",
            "Incompatible third-party software or antivirus",
        ],
        "fix_suggestions": [
            "Update or roll back recently installed drivers.",
            "Run Windows Memory Diagnostic to test RAM.",
            "Uninstall recently added software or antivirus.",
            "Boot into Safe Mode and check for driver conflicts.",
        ],
        "fix_actions": [
            {"label": "Open Device Manager", "command": "start devmgmt.msc"},
            {"label": "Run Memory Diagnostic", "command": "mdsched.exe"},
            {"label": "Run SFC Scan", "command": "sfc /scannow"},
        ],
    },
    "0x0000001E": {
        "name": "KMODE_EXCEPTION_NOT_HANDLED",
        "common_causes": [
            "Buggy kernel-mode driver",
            "Hardware incompatibility",
            "Corrupted system files",
        ],
        "fix_suggestions": [
            "Identify the faulting driver from the minidump and update or remove it.",
            "Run SFC and DISM to repair system files.",
            "Check for BIOS/UEFI firmware updates.",
        ],
        "fix_actions": [
            {"label": "Run SFC Scan", "command": "sfc /scannow"},
            {"label": "Run DISM Repair", "command": "DISM /Online /Cleanup-Image /RestoreHealth"},
            {"label": "Open Device Manager", "command": "start devmgmt.msc"},
        ],
    },
    "0x00000019": {
        "name": "BAD_POOL_HEADER",
        "common_causes": [
            "Corrupted memory pool header, often from a buggy driver",
            "Faulty RAM modules",
            "Disk corruption",
        ],
        "fix_suggestions": [
            "Run Windows Memory Diagnostic.",
            "Update or uninstall recently changed drivers.",
            "Run chkdsk to check for disk errors.",
        ],
        "fix_actions": [
            {"label": "Run Memory Diagnostic", "command": "mdsched.exe"},
            {"label": "Check Disk", "command": "chkdsk C: /f /r"},
            {"label": "Run SFC Scan", "command": "sfc /scannow"},
        ],
    },
    "0x00000024": {
        "name": "NTFS_FILE_SYSTEM",
        "common_causes": [
            "Corruption in NTFS file system structures",
            "Failing hard drive or SSD",
            "Bad disk sectors",
        ],
        "fix_suggestions": [
            "Run chkdsk /f /r on the affected volume.",
            "Check drive health with manufacturer diagnostic tools.",
            "Back up data immediately if the drive is failing.",
        ],
        "fix_actions": [
            {"label": "Check Disk", "command": "chkdsk C: /f /r"},
            {"label": "Run SFC Scan", "command": "sfc /scannow"},
            {"label": "Open Disk Management", "command": "start diskmgmt.msc"},
        ],
    },
    "0x0000003B": {
        "name": "SYSTEM_SERVICE_EXCEPTION",
        "common_causes": [
            "Buggy driver or system service",
            "Corrupted system files",
            "Incompatible antivirus or security software",
        ],
        "fix_suggestions": [
            "Update Windows and all drivers to the latest versions.",
            "Run SFC and DISM to repair system files.",
            "Temporarily disable third-party antivirus to test.",
        ],
        "fix_actions": [
            {"label": "Run SFC Scan", "command": "sfc /scannow"},
            {"label": "Run DISM Repair", "command": "DISM /Online /Cleanup-Image /RestoreHealth"},
            {"label": "Check Windows Update", "command": "start ms-settings:windowsupdate"},
        ],
    },
    "0x00000044": {
        "name": "MULTIPLE_IRP_COMPLETE_REQUESTS",
        "common_causes": [
            "Driver attempted to complete an IRP that was already complete",
            "Buggy file-system filter driver or disk driver",
        ],
        "fix_suggestions": [
            "Identify the faulting driver from the crash dump.",
            "Update storage and file-system filter drivers.",
            "Uninstall recently added backup or encryption software.",
        ],
        "fix_actions": [
            {"label": "Open Device Manager", "command": "start devmgmt.msc"},
            {"label": "Run SFC Scan", "command": "sfc /scannow"},
        ],
    },
    "0x00000050": {
        "name": "PAGE_FAULT_IN_NONPAGED_AREA",
        "common_causes": [
            "Faulty RAM",
            "Corrupted NTFS volume",
            "Buggy driver or antivirus software",
        ],
        "fix_suggestions": [
            "Run Windows Memory Diagnostic.",
            "Run chkdsk to repair file system errors.",
            "Update or remove recently installed drivers.",
        ],
        "fix_actions": [
            {"label": "Run Memory Diagnostic", "command": "mdsched.exe"},
            {"label": "Check Disk", "command": "chkdsk C: /f /r"},
            {"label": "Run SFC Scan", "command": "sfc /scannow"},
        ],
    },
    "0x0000007E": {
        "name": "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
        "common_causes": [
            "Driver threw an exception the error handler did not catch",
            "Incompatible driver after a Windows update",
            "Corrupted system files",
        ],
        "fix_suggestions": [
            "Identify the faulting driver in the dump file and update it.",
            "Run SFC and DISM scans.",
            "Roll back recent Windows updates if the issue started after an update.",
        ],
        "fix_actions": [
            {"label": "Run SFC Scan", "command": "sfc /scannow"},
            {"label": "Run DISM Repair", "command": "DISM /Online /Cleanup-Image /RestoreHealth"},
            {"label": "Open Device Manager", "command": "start devmgmt.msc"},
        ],
    },
    "0x0000007F": {
        "name": "UNEXPECTED_KERNEL_MODE_TRAP",
        "common_causes": [
            "Hardware failure (often RAM or CPU)",
            "Overclocking instability",
            "Kernel-mode software bug",
        ],
        "fix_suggestions": [
            "Reset any CPU/RAM overclocks to default.",
            "Run Windows Memory Diagnostic.",
            "Check CPU temperatures and ensure adequate cooling.",
        ],
        "fix_actions": [
            {"label": "Run Memory Diagnostic", "command": "mdsched.exe"},
            {"label": "Run SFC Scan", "command": "sfc /scannow"},
        ],
    },
    "0x0000009F": {
        "name": "DRIVER_POWER_STATE_FAILURE",
        "common_causes": [
            "Driver failed to handle a power state transition (sleep/wake)",
            "Outdated or incompatible network/USB/GPU driver",
            "Aggressive power-saving settings",
        ],
        "fix_suggestions": [
            "Update network adapter, USB, and GPU drivers.",
            "Disable USB selective suspend in Power Options.",
            "Change the power plan to High Performance temporarily.",
        ],
        "fix_actions": [
            {"label": "Open Device Manager", "command": "start devmgmt.msc"},
            {"label": "Open Power Options", "command": "start powercfg.cpl"},
            {"label": "Run SFC Scan", "command": "sfc /scannow"},
        ],
    },
    "0x000000BE": {
        "name": "ATTEMPTED_WRITE_TO_READONLY_MEMORY",
        "common_causes": [
            "Driver attempted to write to read-only memory",
            "Faulty RAM",
            "Corrupted driver binary",
        ],
        "fix_suggestions": [
            "Identify and update the faulting driver.",
            "Run Windows Memory Diagnostic.",
            "Run SFC to repair system files.",
        ],
        "fix_actions": [
            {"label": "Run Memory Diagnostic", "command": "mdsched.exe"},
            {"label": "Run SFC Scan", "command": "sfc /scannow"},
            {"label": "Open Device Manager", "command": "start devmgmt.msc"},
        ],
    },
    "0x000000C2": {
        "name": "BAD_POOL_CALLER",
        "common_causes": [
            "Driver made an invalid pool request",
            "Faulty RAM",
            "Corrupted driver",
        ],
        "fix_suggestions": [
            "Update or roll back recently changed drivers.",
            "Run Windows Memory Diagnostic.",
            "Run Driver Verifier to identify the culprit.",
        ],
        "fix_actions": [
            {"label": "Run Memory Diagnostic", "command": "mdsched.exe"},
            {"label": "Run SFC Scan", "command": "sfc /scannow"},
            {"label": "Open Device Manager", "command": "start devmgmt.msc"},
        ],
    },
    "0x000000D1": {
        "name": "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
        "common_causes": [
            "Driver accessed paged memory at an elevated IRQL",
            "Faulty or outdated network/storage driver",
            "Incompatible driver after OS update",
        ],
        "fix_suggestions": [
            "Update the faulting driver (often network or storage).",
            "Run Driver Verifier to pinpoint the driver.",
            "Uninstall recently installed drivers or software.",
        ],
        "fix_actions": [
            {"label": "Open Device Manager", "command": "start devmgmt.msc"},
            {"label": "Run SFC Scan", "command": "sfc /scannow"},
            {"label": "Run DISM Repair", "command": "DISM /Online /Cleanup-Image /RestoreHealth"},
        ],
    },
    "0x000000EA": {
        "name": "THREAD_STUCK_IN_DEVICE_DRIVER",
        "common_causes": [
            "GPU driver stuck in an infinite loop",
            "Overheating GPU",
            "Faulty graphics card",
        ],
        "fix_suggestions": [
            "Update or reinstall the GPU driver (use DDU for clean install).",
            "Check GPU temperatures and clean dust from heatsink/fans.",
            "Reduce GPU overclock if applicable.",
        ],
        "fix_actions": [
            {"label": "Open Device Manager", "command": "start devmgmt.msc"},
            {"label": "Check Windows Update", "command": "start ms-settings:windowsupdate"},
        ],
    },
    "0x000000EF": {
        "name": "CRITICAL_PROCESS_DIED",
        "common_causes": [
            "A critical system process (csrss.exe, wininit.exe, etc.) terminated unexpectedly",
            "Corrupted system files",
            "Disk corruption or failing storage",
        ],
        "fix_suggestions": [
            "Run SFC and DISM to repair system files.",
            "Run chkdsk to check for disk errors.",
            "Perform a clean boot to isolate third-party conflicts.",
        ],
        "fix_actions": [
            {"label": "Run SFC Scan", "command": "sfc /scannow"},
            {"label": "Run DISM Repair", "command": "DISM /Online /Cleanup-Image /RestoreHealth"},
            {"label": "Check Disk", "command": "chkdsk C: /f /r"},
        ],
    },
    "0x000000F4": {
        "name": "CRITICAL_OBJECT_TERMINATION",
        "common_causes": [
            "A critical system process or thread exited unexpectedly",
            "Failing hard drive or SSD",
            "Corrupted system files",
        ],
        "fix_suggestions": [
            "Check drive health with manufacturer tools.",
            "Run SFC and DISM to repair system files.",
            "Replace failing storage device.",
        ],
        "fix_actions": [
            {"label": "Run SFC Scan", "command": "sfc /scannow"},
            {"label": "Check Disk", "command": "chkdsk C: /f /r"},
            {"label": "Run DISM Repair", "command": "DISM /Online /Cleanup-Image /RestoreHealth"},
        ],
    },
    "0x000000FE": {
        "name": "BUGCODE_USB_DRIVER",
        "common_causes": [
            "Buggy USB host controller or device driver",
            "Faulty USB hardware",
            "Power management issue with USB devices",
        ],
        "fix_suggestions": [
            "Update USB host controller drivers.",
            "Disconnect all USB devices and reconnect one at a time.",
            "Disable USB selective suspend in Power Options.",
        ],
        "fix_actions": [
            {"label": "Open Device Manager", "command": "start devmgmt.msc"},
            {"label": "Open Power Options", "command": "start powercfg.cpl"},
        ],
    },
    "0x00000101": {
        "name": "CLOCK_WATCHDOG_TIMEOUT",
        "common_causes": [
            "A processor core did not respond in time",
            "CPU overclocking instability",
            "Firmware/BIOS issue or outdated microcode",
        ],
        "fix_suggestions": [
            "Reset CPU overclocks to default.",
            "Update BIOS/UEFI firmware.",
            "Check CPU temperatures and cooling.",
            "Update chipset drivers.",
        ],
        "fix_actions": [
            {"label": "Run SFC Scan", "command": "sfc /scannow"},
            {"label": "Check Windows Update", "command": "start ms-settings:windowsupdate"},
        ],
    },
    "0x0000010E": {
        "name": "VIDEO_MEMORY_MANAGEMENT_INTERNAL",
        "common_causes": [
            "GPU driver bug in video memory management",
            "Faulty GPU VRAM",
            "Overclocked GPU",
        ],
        "fix_suggestions": [
            "Update or reinstall the GPU driver.",
            "Remove any GPU overclock.",
            "Test with a different graphics card if available.",
        ],
        "fix_actions": [
            {"label": "Open Device Manager", "command": "start devmgmt.msc"},
            {"label": "Check Windows Update", "command": "start ms-settings:windowsupdate"},
        ],
    },
    "0x00000116": {
        "name": "VIDEO_TDR_TIMEOUT_DETECTED",
        "common_causes": [
            "GPU driver took too long to respond",
            "Overheating GPU",
            "Insufficient power to GPU",
        ],
        "fix_suggestions": [
            "Update the GPU driver to the latest version.",
            "Clean GPU heatsink and fans; check temperatures.",
            "Verify PSU has adequate wattage for the GPU.",
        ],
        "fix_actions": [
            {"label": "Open Device Manager", "command": "start devmgmt.msc"},
            {"label": "Check Windows Update", "command": "start ms-settings:windowsupdate"},
        ],
    },
    "0x00000117": {
        "name": "VIDEO_TDR_FAILURE",
        "common_causes": [
            "GPU driver failed to recover from a timeout",
            "Faulty or overheating GPU",
            "Incompatible GPU driver version",
        ],
        "fix_suggestions": [
            "Perform a clean GPU driver reinstall (use DDU).",
            "Check GPU temperatures under load.",
            "Try an older stable driver version.",
        ],
        "fix_actions": [
            {"label": "Open Device Manager", "command": "start devmgmt.msc"},
            {"label": "Check Windows Update", "command": "start ms-settings:windowsupdate"},
        ],
    },
    "0x00000124": {
        "name": "WHEA_UNCORRECTABLE_ERROR",
        "common_causes": [
            "Uncorrectable hardware error detected by WHEA",
            "Failing CPU, RAM, or motherboard component",
            "Overclocking instability",
        ],
        "fix_suggestions": [
            "Reset all overclocks to default immediately.",
            "Run Windows Memory Diagnostic.",
            "Update BIOS/UEFI firmware.",
            "Test CPU stability with a stress test tool.",
        ],
        "fix_actions": [
            {"label": "Run Memory Diagnostic", "command": "mdsched.exe"},
            {"label": "Run SFC Scan", "command": "sfc /scannow"},
        ],
    },
    "0x0000012B": {
        "name": "FAULTY_HARDWARE_CORRUPTED_PAGE",
        "common_causes": [
            "RAM returned corrupted data",
            "Failing memory module",
            "Motherboard memory controller issue",
        ],
        "fix_suggestions": [
            "Run Windows Memory Diagnostic.",
            "Test each RAM stick individually.",
            "Replace faulty RAM modules.",
        ],
        "fix_actions": [
            {"label": "Run Memory Diagnostic", "command": "mdsched.exe"},
            {"label": "Run SFC Scan", "command": "sfc /scannow"},
        ],
    },
    "0x00000133": {
        "name": "DPC_WATCHDOG_VIOLATION",
        "common_causes": [
            "Driver spent too long at a high IRQL (DPC level)",
            "SSD/NVMe firmware bug or outdated AHCI/NVMe driver",
            "Incompatible storage controller driver",
        ],
        "fix_suggestions": [
            "Update the SSD/NVMe firmware and storage controller driver.",
            "Switch SATA controller to AHCI mode if not already.",
            "Update all drivers via manufacturer websites.",
        ],
        "fix_actions": [
            {"label": "Open Device Manager", "command": "start devmgmt.msc"},
            {"label": "Run SFC Scan", "command": "sfc /scannow"},
            {"label": "Check Windows Update", "command": "start ms-settings:windowsupdate"},
        ],
    },
    "0x00000139": {
        "name": "KERNEL_SECURITY_CHECK_FAILURE",
        "common_causes": [
            "Kernel detected corruption of a critical data structure",
            "Driver or software caused a buffer overrun",
            "Outdated or incompatible driver",
        ],
        "fix_suggestions": [
            "Update all drivers, especially recently changed ones.",
            "Run SFC and DISM to repair system files.",
            "Perform a clean boot to isolate conflicting software.",
        ],
        "fix_actions": [
            {"label": "Run SFC Scan", "command": "sfc /scannow"},
            {"label": "Run DISM Repair", "command": "DISM /Online /Cleanup-Image /RestoreHealth"},
            {"label": "Open Device Manager", "command": "start devmgmt.msc"},
        ],
    },
    "0x0000013A": {
        "name": "KERNEL_MODE_HEAP_CORRUPTION",
        "common_causes": [
            "A driver corrupted the kernel-mode heap",
            "Memory corruption from buggy driver",
            "Faulty RAM",
        ],
        "fix_suggestions": [
            "Run Driver Verifier to identify the faulting driver.",
            "Run Windows Memory Diagnostic.",
            "Update all kernel-mode drivers.",
        ],
        "fix_actions": [
            {"label": "Run Memory Diagnostic", "command": "mdsched.exe"},
            {"label": "Run SFC Scan", "command": "sfc /scannow"},
            {"label": "Open Device Manager", "command": "start devmgmt.msc"},
        ],
    },
    "0x00000154": {
        "name": "UNEXPECTED_STORE_EXCEPTION",
        "common_causes": [
            "Store component caught an unexpected exception",
            "Failing SSD or hard drive",
            "Corrupted system files or antivirus conflict",
        ],
        "fix_suggestions": [
            "Run chkdsk to check for disk errors.",
            "Update SSD firmware and storage drivers.",
            "Disable fast startup in Power Options.",
        ],
        "fix_actions": [
            {"label": "Check Disk", "command": "chkdsk C: /f /r"},
            {"label": "Run SFC Scan", "command": "sfc /scannow"},
            {"label": "Open Power Options", "command": "start powercfg.cpl"},
        ],
    },
    "0x000001CA": {
        "name": "SYNTHETIC_WATCHDOG_TIMEOUT",
        "common_causes": [
            "System became unresponsive for an extended period",
            "Hyper-V or virtualization watchdog timeout",
            "Resource exhaustion (CPU, memory, or disk I/O)",
        ],
        "fix_suggestions": [
            "Check for resource-hungry processes in Task Manager.",
            "Update Hyper-V integration services if running in a VM.",
            "Check disk I/O and ensure storage is healthy.",
        ],
        "fix_actions": [
            {"label": "Open Task Manager", "command": "start taskmgr.exe"},
            {"label": "Check Disk", "command": "chkdsk C: /f /r"},
            {"label": "Run SFC Scan", "command": "sfc /scannow"},
        ],
    },
    "0x0000000D": {
        "name": "MUTEX_LEVEL_NUMBER_VIOLATION",
        "common_causes": [
            "Kernel mutex acquired out of order",
            "Third-party driver locking issue",
            "Rare kernel-level software bug",
        ],
        "fix_suggestions": [
            "Update all drivers to the latest versions.",
            "Uninstall recently added kernel-mode software.",
            "Run SFC and DISM scans.",
        ],
        "fix_actions": [
            {"label": "Run SFC Scan", "command": "sfc /scannow"},
            {"label": "Run DISM Repair", "command": "DISM /Online /Cleanup-Image /RestoreHealth"},
        ],
    },
    "0xC000021A": {
        "name": "STATUS_SYSTEM_PROCESS_TERMINATED",
        "common_causes": [
            "Winlogon.exe or Csrss.exe terminated unexpectedly",
            "Mismatched system DLLs after a failed update",
            "Corrupted Windows installation",
        ],
        "fix_suggestions": [
            "Run SFC and DISM from Recovery Environment.",
            "Use System Restore to revert to a known-good state.",
            "Perform an in-place Windows repair upgrade.",
        ],
        "fix_actions": [
            {"label": "Run SFC Scan", "command": "sfc /scannow"},
            {"label": "Run DISM Repair", "command": "DISM /Online /Cleanup-Image /RestoreHealth"},
            {"label": "Open System Restore", "command": "rstrui.exe"},
        ],
    },
    "0x000000C5": {
        "name": "DRIVER_CORRUPTED_EXPOOL",
        "common_causes": [
            "Driver corrupted the system pool",
            "Buggy kernel-mode driver",
            "Faulty RAM causing pool corruption",
        ],
        "fix_suggestions": [
            "Enable Driver Verifier to find the faulting driver.",
            "Run Windows Memory Diagnostic.",
            "Update all drivers.",
        ],
        "fix_actions": [
            {"label": "Run Memory Diagnostic", "command": "mdsched.exe"},
            {"label": "Open Device Manager", "command": "start devmgmt.msc"},
            {"label": "Run SFC Scan", "command": "sfc /scannow"},
        ],
    },
    "0x0000001A": {
        "name": "MEMORY_MANAGEMENT",
        "common_causes": [
            "Severe memory management error",
            "Faulty RAM",
            "Buggy driver corrupting memory structures",
        ],
        "fix_suggestions": [
            "Run Windows Memory Diagnostic.",
            "Test RAM sticks individually.",
            "Update drivers and run SFC.",
        ],
        "fix_actions": [
            {"label": "Run Memory Diagnostic", "command": "mdsched.exe"},
            {"label": "Run SFC Scan", "command": "sfc /scannow"},
            {"label": "Open Device Manager", "command": "start devmgmt.msc"},
        ],
    },
    "0x000000FC": {
        "name": "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY",
        "common_causes": [
            "Driver attempted to execute non-executable memory",
            "Faulty driver or malware",
            "DEP violation by a kernel driver",
        ],
        "fix_suggestions": [
            "Identify and update the faulting driver.",
            "Run a full antivirus/antimalware scan.",
            "Run SFC and DISM scans.",
        ],
        "fix_actions": [
            {"label": "Run SFC Scan", "command": "sfc /scannow"},
            {"label": "Open Windows Security", "command": "start windowsdefender:"},
            {"label": "Open Device Manager", "command": "start devmgmt.msc"},
        ],
    },
}

# Default info for unknown stop codes
_UNKNOWN_STOP_CODE = {
    "name": "UNKNOWN_STOP_CODE",
    "common_causes": [
        "Unknown or undocumented stop code.",
        "Could be driver, hardware, or software related.",
    ],
    "fix_suggestions": [
        "Run SFC and DISM to repair system files.",
        "Update all drivers to the latest versions.",
        "Run Windows Memory Diagnostic to test RAM.",
        "Search Microsoft documentation for the specific stop code.",
    ],
    "fix_actions": [
        {"label": "Run SFC Scan", "command": "sfc /scannow"},
        {"label": "Run DISM Repair", "command": "DISM /Online /Cleanup-Image /RestoreHealth"},
        {"label": "Run Memory Diagnostic", "command": "mdsched.exe"},
        {"label": "Open Device Manager", "command": "start devmgmt.msc"},
    ],
}


def _lookup_stop_code(code_str):
    """Look up a stop code in the database. Returns a dict with name, causes, suggestions, actions."""
    normalized = code_str.strip().upper()
    if not normalized.startswith("0X"):
        normalized = "0x" + normalized
    else:
        normalized = "0x" + normalized[2:]

    # Try exact match first
    if normalized in STOP_CODES:
        return STOP_CODES[normalized]

    # Try without leading zeros after 0x (e.g. 0xEF -> 0x000000EF)
    hex_digits = normalized[2:].lstrip("0") or "0"
    padded = "0x" + hex_digits.upper().zfill(8)
    if padded in STOP_CODES:
        return STOP_CODES[padded]

    return _UNKNOWN_STOP_CODE


def _query_event_log_wevtutil(count=10):
    """Query BugCheck events from the System event log using wevtutil."""
    events = []

    # Query Event ID 1001 (BugCheck / Windows Error Reporting)
    try:
        cmd = [
            "wevtutil", "qe", "System",
            "/q:*[System[(EventID=1001)]]",
            "/c:{}".format(count),
            "/f:text",
            "/rd:true",
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode == 0 and result.stdout.strip():
            events.extend(_parse_wevtutil_text(result.stdout, event_type="bugcheck"))
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # Query Event ID 41 (Kernel-Power — unexpected shutdown / power loss)
    try:
        cmd = [
            "wevtutil", "qe", "System",
            "/q:*[System[Provider[@Name='Microsoft-Windows-Kernel-Power'] and (EventID=41)]]",
            "/c:{}".format(count),
            "/f:text",
            "/rd:true",
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode == 0 and result.stdout.strip():
            events.extend(_parse_wevtutil_text(result.stdout, event_type="kernel_power"))
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return events


def _parse_wevtutil_text(text, event_type="bugcheck"):
    """Parse text-format output from wevtutil into a list of raw event dicts."""
    events = []
    # wevtutil /f:text outputs blocks separated by blank lines with key: value pairs
    blocks = re.split(r"\n\s*\n", text.strip())

    for block in blocks:
        if not block.strip():
            continue

        event = {"raw": block, "type": event_type}
        lines = block.strip().splitlines()

        for line in lines:
            if ":" in line:
                key, _, value = line.partition(":")
                key = key.strip().lower()
                value = value.strip()

                if "date" in key or "time" in key:
                    event["date"] = value
                elif key == "source":
                    event["source"] = value
                elif key == "event id":
                    event["event_id"] = value
                elif key == "description" or key == "message":
                    event.setdefault("description", "")
                    event["description"] += value + " "

        # Try to extract the bug check code from the description / raw text
        stop_code = _extract_stop_code(block)
        if stop_code:
            event["stop_code"] = stop_code

        params = _extract_parameters(block)
        if params:
            event["parameters"] = params

        events.append(event)

    return events


def _query_event_log_powershell(count=10):
    """Fallback: query BugCheck events using PowerShell Get-WinEvent."""
    events = []
    ps_script = (
        "Get-WinEvent -FilterHashtable @{{LogName='System'; ID=1001}} "
        "-MaxEvents {count} -ErrorAction SilentlyContinue | "
        "ForEach-Object {{ "
        "  '---EVENT---'; "
        "  'Date: ' + $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); "
        "  'Source: ' + $_.ProviderName; "
        "  'EventID: ' + $_.Id; "
        "  'Message: ' + ($_.Message -replace '\\r?\\n', ' '); "
        "  '---END---' "
        "}}"
    ).format(count=count)

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode == 0 and result.stdout.strip():
            blocks = result.stdout.split("---EVENT---")
            for block in blocks:
                block = block.replace("---END---", "").strip()
                if not block:
                    continue
                event = {"raw": block, "type": "bugcheck"}
                for line in block.splitlines():
                    if line.startswith("Date: "):
                        event["date"] = line[6:].strip()
                    elif line.startswith("Source: "):
                        event["source"] = line[8:].strip()
                    elif line.startswith("EventID: "):
                        event["event_id"] = line[9:].strip()
                    elif line.startswith("Message: "):
                        event["description"] = line[9:].strip()

                stop_code = _extract_stop_code(block)
                if stop_code:
                    event["stop_code"] = stop_code
                params = _extract_parameters(block)
                if params:
                    event["parameters"] = params

                events.append(event)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # Also query kernel power events
    ps_script_kp = (
        "Get-WinEvent -FilterHashtable @{{LogName='System'; ProviderName='Microsoft-Windows-Kernel-Power'; ID=41}} "
        "-MaxEvents {count} -ErrorAction SilentlyContinue | "
        "ForEach-Object {{ "
        "  '---EVENT---'; "
        "  'Date: ' + $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); "
        "  'Source: ' + $_.ProviderName; "
        "  'EventID: ' + $_.Id; "
        "  'Message: ' + ($_.Message -replace '\\r?\\n', ' '); "
        "  '---END---' "
        "}}"
    ).format(count=count)

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script_kp],
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode == 0 and result.stdout.strip():
            blocks = result.stdout.split("---EVENT---")
            for block in blocks:
                block = block.replace("---END---", "").strip()
                if not block:
                    continue
                event = {"raw": block, "type": "kernel_power"}
                for line in block.splitlines():
                    if line.startswith("Date: "):
                        event["date"] = line[6:].strip()
                    elif line.startswith("Source: "):
                        event["source"] = line[8:].strip()
                    elif line.startswith("EventID: "):
                        event["event_id"] = line[9:].strip()
                    elif line.startswith("Message: "):
                        event["description"] = line[9:].strip()
                events.append(event)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return events


def _extract_stop_code(text):
    """Extract a hex stop code from event text."""
    # Match patterns like "0x000000EF", "BugCheck 0xEF", "stop code: 0x000000EF"
    patterns = [
        r"(?:bug\s*check|stop\s*code|bsod)[:\s]+(?:0x)?([0-9A-Fa-f]{1,8})",
        r"0x([0-9A-Fa-f]{8,})",
        r"(?:code|error)[:\s]+(?:0x)?([0-9A-Fa-f]{4,8})",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            hex_val = match.group(1).upper().lstrip("0") or "0"
            return "0x" + hex_val.zfill(8)
    return None


def _extract_parameters(text):
    """Extract bug check parameters from event text."""
    # Match patterns like "parameters: 0x..., 0x..., 0x..., 0x..."
    match = re.search(
        r"(?:param(?:eter)?s?)[:\s]+(0x[0-9A-Fa-f]+(?:\s*,\s*0x[0-9A-Fa-f]+)*)",
        text,
        re.IGNORECASE,
    )
    if match:
        return match.group(1)

    # Try to find four hex values in a row
    match = re.search(
        r"(0x[0-9A-Fa-f]+)\s*,\s*(0x[0-9A-Fa-f]+)\s*,\s*(0x[0-9A-Fa-f]+)\s*,\s*(0x[0-9A-Fa-f]+)",
        text,
    )
    if match:
        return ", ".join(match.groups())

    return ""


def _check_minidump_files():
    """Check for minidump files in the Windows Minidump directory."""
    minidump_dir = r"C:\Windows\Minidump"
    dumps = []

    try:
        if not os.path.isdir(minidump_dir):
            return dumps

        dmp_files = glob.glob(os.path.join(minidump_dir, "*.dmp"))
        for dmp_path in sorted(dmp_files, key=os.path.getmtime, reverse=True):
            try:
                mtime = os.path.getmtime(dmp_path)
                dt = datetime.fromtimestamp(mtime)
                size_kb = os.path.getsize(dmp_path) / 1024

                dumps.append({
                    "file": os.path.basename(dmp_path),
                    "path": dmp_path,
                    "date": dt.strftime("%Y-%m-%d %H:%M:%S"),
                    "size_kb": round(size_kb, 1),
                })
            except OSError:
                continue
    except PermissionError:
        pass
    except OSError:
        pass

    return dumps


def get_recent_bsods(count=10):
    """
    Retrieve recent BSOD events from the Windows Event Log and minidump files.

    Args:
        count: Maximum number of events to retrieve.

    Returns:
        A list of dicts, each containing:
            - date (str): Date/time of the event.
            - stop_code (str): Hex stop code, e.g. "0x000000EF".
            - stop_code_name (str): Human-readable name, e.g. "CRITICAL_PROCESS_DIED".
            - parameters (str): Bug check parameters if available.
            - common_causes (list[str]): Likely causes for this stop code.
            - fix_suggestions (list[str]): Actionable fix suggestions.
            - fix_actions (list[dict]): Dicts with "label" and "command" keys.
            - source (str): Event source or "minidump".
            - description (str): Raw event description if available.

        Returns an empty list if no BSODs are found.
    """
    results = []
    seen_dates = set()

    # Try wevtutil first, then fall back to PowerShell
    raw_events = _query_event_log_wevtutil(count)
    if not raw_events:
        raw_events = _query_event_log_powershell(count)

    for event in raw_events:
        date = event.get("date", "Unknown")
        stop_code = event.get("stop_code", "")
        parameters = event.get("parameters", "")
        source = event.get("source", event.get("type", "Unknown"))
        description = event.get("description", "").strip()
        event_type = event.get("type", "bugcheck")

        # For kernel power events without a stop code, mark them specially
        if event_type == "kernel_power" and not stop_code:
            entry = {
                "date": date,
                "stop_code": "Kernel Power (Event 41)",
                "stop_code_name": "UNEXPECTED_KERNEL_POWER_LOSS",
                "parameters": parameters,
                "common_causes": [
                    "Unexpected power loss or hard shutdown",
                    "PSU failure or power fluctuation",
                    "Overheating causing emergency shutdown",
                    "System hang requiring forced reboot",
                ],
                "fix_suggestions": [
                    "Check PSU health and power connections.",
                    "Monitor CPU and GPU temperatures.",
                    "Check Event Log for preceding errors.",
                    "Ensure UPS or surge protector is functioning.",
                ],
                "fix_actions": [
                    {"label": "Open Event Viewer", "command": "start eventvwr.msc"},
                    {"label": "Open Power Options", "command": "start powercfg.cpl"},
                    {"label": "Run SFC Scan", "command": "sfc /scannow"},
                ],
                "source": source,
                "description": description,
            }
            results.append(entry)
            continue

        if stop_code:
            info = _lookup_stop_code(stop_code)
        else:
            # Skip events with no identifiable stop code (non-BSOD WER events)
            # Only include if the description mentions bugcheck or blue screen
            desc_lower = (description + event.get("raw", "")).lower()
            if not any(kw in desc_lower for kw in ("bugcheck", "blue screen", "bluescreen", "bsod", "stop error")):
                continue
            info = _UNKNOWN_STOP_CODE

        # Deduplicate by date+stop_code
        dedup_key = (date, stop_code)
        if dedup_key in seen_dates:
            continue
        seen_dates.add(dedup_key)

        entry = {
            "date": date,
            "stop_code": stop_code or "Unknown",
            "stop_code_name": info["name"],
            "parameters": parameters,
            "common_causes": list(info["common_causes"]),
            "fix_suggestions": list(info["fix_suggestions"]),
            "fix_actions": [dict(a) for a in info["fix_actions"]],
            "source": source,
            "description": description,
        }
        results.append(entry)

    # Also check minidump files and add them as supplementary info
    minidumps = _check_minidump_files()
    for dump in minidumps[:count]:
        # Check if we already have an event near this timestamp
        dump_date = dump["date"]
        already_covered = False
        for r in results:
            if r["date"][:16] == dump_date[:16]:  # Match to the minute
                # Attach dump file info to existing entry
                r.setdefault("minidump_file", dump["path"])
                already_covered = True
                break

        if not already_covered:
            # Add as a standalone entry from minidump
            entry = {
                "date": dump_date,
                "stop_code": "Unknown (minidump)",
                "stop_code_name": "MINIDUMP_FOUND",
                "parameters": "",
                "common_causes": [
                    "A crash dump was created but could not be correlated with an event log entry.",
                    "The crash may have occurred before event logging completed.",
                ],
                "fix_suggestions": [
                    "Analyze the minidump with WinDbg or BlueScreenView for details.",
                    "Run SFC and DISM to repair system files.",
                ],
                "fix_actions": [
                    {"label": "Run SFC Scan", "command": "sfc /scannow"},
                    {"label": "Run DISM Repair", "command": "DISM /Online /Cleanup-Image /RestoreHealth"},
                    {"label": "Open Device Manager", "command": "start devmgmt.msc"},
                ],
                "source": "minidump",
                "description": "Minidump file: {} ({} KB)".format(dump["file"], dump["size_kb"]),
                "minidump_file": dump["path"],
            }
            results.append(entry)

    # Sort by date descending, putting "Unknown" dates last
    def sort_key(item):
        d = item.get("date", "")
        if d and d != "Unknown":
            return d
        return ""

    results.sort(key=sort_key, reverse=True)

    return results[:count]


def get_bsod_summary():
    """
    Get a brief summary of recent BSOD activity.

    Returns:
        A dict with:
            - total_count (int): Number of BSODs found.
            - events (list): The BSOD events from get_recent_bsods().
            - most_common_code (str or None): The most frequently occurring stop code.
            - minidump_count (int): Number of minidump files found.
    """
    events = get_recent_bsods(count=20)

    # Count stop codes
    code_counts = {}
    for e in events:
        code = e.get("stop_code", "Unknown")
        if code not in ("Unknown", "Unknown (minidump)", "Kernel Power (Event 41)"):
            code_counts[code] = code_counts.get(code, 0) + 1

    most_common = None
    if code_counts:
        most_common = max(code_counts, key=code_counts.get)

    minidumps = _check_minidump_files()

    return {
        "total_count": len(events),
        "events": events,
        "most_common_code": most_common,
        "minidump_count": len(minidumps),
    }
