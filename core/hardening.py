"""
WinnyTool - System Hardening Module

Audits 28 Windows security settings across three tiers (Basic, Moderate,
Aggressive), reports their current state, and provides one-click fix commands.
"""

import logging
import os
import re
import subprocess
import winreg
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------

_CREATE_NO_WINDOW = 0x08000000


def _run_cmd(cmd: str, *, shell: bool = True, timeout: int = 15) -> Optional[str]:
    """Run *cmd* silently and return its stdout, or None on failure."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=shell,
            creationflags=_CREATE_NO_WINDOW,
        )
        return result.stdout.strip()
    except Exception as exc:
        logger.debug("Command failed (%s): %s", cmd, exc)
        return None


def _read_registry(hive, subkey: str, value_name: str):
    """Return a registry value, or None if not found."""
    try:
        with winreg.OpenKey(hive, subkey) as key:
            val, _ = winreg.QueryValueEx(key, value_name)
            return val
    except (FileNotFoundError, OSError):
        return None


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

# -- Basic tier -------------------------------------------------------------

def _check_firewall() -> Dict:
    """1. Windows Firewall on all profiles."""
    output = _run_cmd("netsh advfirewall show allprofiles state")
    if output is None:
        status = "Unknown"
    else:
        off_count = output.lower().count("off")
        status = "Disabled" if off_count > 0 else "Enabled"
    return {
        "setting": "Windows Firewall",
        "description": "Ensure the firewall is enabled for Domain, Private, and Public profiles.",
        "tier": "Basic",
        "status": status,
        "recommended": "Enable",
        "pros": ["Blocks unsolicited inbound connections", "First line of network defence"],
        "cons": ["May block some LAN services if rules are not configured"],
        "fix_action": {
            "label": "Enable Firewall (all profiles)",
            "command": "netsh advfirewall set allprofiles state on",
        },
    }


def _check_defender_realtime() -> Dict:
    """2. Windows Defender real-time protection."""
    output = _run_cmd("powershell -NoProfile -Command \"(Get-MpPreference).DisableRealtimeMonitoring\"")
    if output is None:
        status = "Unknown"
    elif output.strip().lower() == "false":
        status = "Enabled"
    elif output.strip().lower() == "true":
        status = "Disabled"
    else:
        status = "Unknown"
    return {
        "setting": "Defender Real-Time Protection",
        "description": "Windows Defender actively scans files and processes in real time.",
        "tier": "Basic",
        "status": status,
        "recommended": "Enable",
        "pros": ["Catches malware on execution", "Zero-day heuristic detection"],
        "cons": ["Slight CPU overhead during file operations"],
        "fix_action": {
            "label": "Enable real-time protection",
            "command": "powershell -NoProfile -Command \"Set-MpPreference -DisableRealtimeMonitoring $false\"",
        },
    }


def _check_remote_desktop() -> Dict:
    """3. Disable Remote Desktop."""
    val = _read_registry(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Terminal Server",
        "fDenyTSConnections",
    )
    if val is None:
        status = "Unknown"
    elif val == 1:
        status = "Enabled"       # Deny=1 means RDP is blocked (good)
    else:
        status = "Disabled"      # Deny=0 means RDP is allowed (bad)
    return {
        "setting": "Disable Remote Desktop",
        "description": "Prevent Remote Desktop Protocol connections to this machine.",
        "tier": "Basic",
        "status": status,
        "recommended": "Enable",
        "pros": ["Eliminates a major remote-attack vector", "Reduces exposure to brute-force attacks"],
        "cons": ["Cannot RDP into this machine remotely"],
        "fix_action": {
            "label": "Disable RDP",
            "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f',
        },
    }


def _check_uac() -> Dict:
    """4. User Account Control enabled."""
    val = _read_registry(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "EnableLUA",
    )
    if val is None:
        status = "Unknown"
    elif val == 1:
        status = "Enabled"
    else:
        status = "Disabled"
    return {
        "setting": "User Account Control (UAC)",
        "description": "Prompts for elevation before allowing system changes.",
        "tier": "Basic",
        "status": status,
        "recommended": "Enable",
        "pros": ["Prevents silent privilege escalation", "Blocks many malware install techniques"],
        "cons": ["Occasional elevation prompts for legitimate tasks"],
        "fix_action": {
            "label": "Enable UAC",
            "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA /t REG_DWORD /d 1 /f',
        },
    }


def _check_smbv1() -> Dict:
    """5. Disable SMBv1."""
    output = _run_cmd(
        'powershell -NoProfile -Command "(Get-SmbServerConfiguration).EnableSMB1Protocol"'
    )
    if output is None:
        status = "Unknown"
    elif output.strip().lower() == "false":
        status = "Enabled"       # SMBv1 is disabled (good)
    elif output.strip().lower() == "true":
        status = "Disabled"      # SMBv1 is still enabled (bad)
    else:
        status = "Unknown"
    return {
        "setting": "Disable SMBv1",
        "description": "Disable the legacy SMBv1 protocol vulnerable to EternalBlue and WannaCry.",
        "tier": "Basic",
        "status": status,
        "recommended": "Enable",
        "pros": ["Mitigates EternalBlue / WannaCry class attacks", "Removes obsolete protocol surface"],
        "cons": ["Very old devices (XP-era) may lose file-sharing access"],
        "fix_action": {
            "label": "Disable SMBv1",
            "command": 'powershell -NoProfile -Command "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"',
        },
    }


def _check_auto_updates() -> Dict:
    """6. Automatic Windows Updates."""
    val = _read_registry(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
        "NoAutoUpdate",
    )
    if val is None:
        # Key absent usually means auto-update is controlled by defaults (enabled).
        status = "Enabled"
    elif val == 0:
        status = "Enabled"
    else:
        status = "Disabled"
    return {
        "setting": "Automatic Windows Updates",
        "description": "Ensure Windows Update downloads and installs patches automatically.",
        "tier": "Basic",
        "status": status,
        "recommended": "Enable",
        "pros": ["Patches security vulnerabilities promptly", "Reduces manual maintenance"],
        "cons": ["Updates may cause unexpected reboots or compatibility issues"],
        "fix_action": {
            "label": "Enable automatic updates",
            "command": 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f',
        },
    }


def _check_screen_lock() -> Dict:
    """7. Screen lock timeout (15 min)."""
    val = _read_registry(
        winreg.HKEY_CURRENT_USER,
        r"Control Panel\Desktop",
        "ScreenSaveTimeOut",
    )
    if val is None:
        status = "Disabled"
    else:
        try:
            seconds = int(val)
            status = "Enabled" if 0 < seconds <= 900 else "Disabled"
        except (ValueError, TypeError):
            status = "Unknown"
    return {
        "setting": "Screen Lock Timeout",
        "description": "Lock the screen after 15 minutes of inactivity.",
        "tier": "Basic",
        "status": status,
        "recommended": "Enable",
        "pros": ["Prevents unauthorized physical access", "Protects unattended sessions"],
        "cons": ["May be inconvenient during long reads or presentations"],
        "fix_action": {
            "label": "Set screen lock to 15 min",
            "command": 'reg add "HKCU\\Control Panel\\Desktop" /v ScreenSaveTimeOut /t REG_SZ /d 900 /f',
        },
    }


def _check_guest_account() -> Dict:
    """8. Disable guest account."""
    output = _run_cmd("net user guest")
    if output is None:
        status = "Unknown"
    elif "account active" in output.lower():
        active_line = [l for l in output.splitlines() if "account active" in l.lower()]
        if active_line and "yes" in active_line[0].lower():
            status = "Disabled"   # Guest is active (bad)
        else:
            status = "Enabled"    # Guest is inactive (good)
    else:
        status = "Unknown"
    return {
        "setting": "Disable Guest Account",
        "description": "Disable the built-in Guest account to prevent unauthenticated access.",
        "tier": "Basic",
        "status": status,
        "recommended": "Enable",
        "pros": ["Prevents anonymous local logon", "Reduces attack surface"],
        "cons": ["Shared-kiosk scenarios may need a guest account"],
        "fix_action": {
            "label": "Disable guest account",
            "command": "net user guest /active:no",
        },
    }


# -- Moderate tier ----------------------------------------------------------

def _check_llmnr() -> Dict:
    """9. Disable LLMNR."""
    val = _read_registry(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
        "EnableMulticast",
    )
    if val is None:
        status = "Disabled"      # Key absent = LLMNR still active (bad)
    elif val == 0:
        status = "Enabled"       # Multicast disabled (good)
    else:
        status = "Disabled"
    return {
        "setting": "Disable LLMNR",
        "description": "Disable Link-Local Multicast Name Resolution to prevent spoofing attacks.",
        "tier": "Moderate",
        "status": status,
        "recommended": "Enable",
        "pros": ["Prevents LLMNR poisoning / credential theft", "Mitigates Responder-style attacks"],
        "cons": ["May break name resolution on small networks without a DNS server"],
        "fix_action": {
            "label": "Disable LLMNR",
            "command": 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f',
        },
    }


def _check_netbios() -> Dict:
    """10. Disable NetBIOS over TCP/IP."""
    output = _run_cmd(
        'powershell -NoProfile -Command "'
        "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true' "
        '| Select-Object -ExpandProperty TcpipNetbiosOptions"'
    )
    if output is None:
        status = "Unknown"
    else:
        # 2 = disabled on all adapters
        values = [v.strip() for v in output.splitlines() if v.strip().isdigit()]
        if all(v == "2" for v in values) and values:
            status = "Enabled"   # NetBIOS disabled on all (good)
        else:
            status = "Disabled"  # At least one adapter has NetBIOS on
    return {
        "setting": "Disable NetBIOS over TCP/IP",
        "description": "Disable NetBIOS name service to reduce broadcast-based attack surface.",
        "tier": "Moderate",
        "status": status,
        "recommended": "Enable",
        "pros": ["Eliminates NBNS poisoning vector", "Reduces broadcast traffic"],
        "cons": ["Breaks legacy NetBIOS name resolution", "Old printers or NAS devices may lose connectivity"],
        "fix_action": {
            "label": "Disable NetBIOS (all adapters)",
            "command": (
                'powershell -NoProfile -Command "'
                "$adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true'; "
                "foreach ($a in $adapters) { Invoke-CimMethod -InputObject $a -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=2} }"
                '"'
            ),
        },
    }


def _check_credential_guard() -> Dict:
    """11. Enable Credential Guard."""
    val = _read_registry(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
        "EnableVirtualizationBasedSecurity",
    )
    if val is None:
        status = "Disabled"
    elif val == 1:
        status = "Enabled"
    else:
        status = "Disabled"
    return {
        "setting": "Credential Guard",
        "description": "Use virtualisation-based security to protect cached credentials.",
        "tier": "Moderate",
        "status": status,
        "recommended": "Enable",
        "pros": ["Protects NTLM hashes and Kerberos tickets in isolated memory", "Mitigates pass-the-hash attacks"],
        "cons": ["Incompatible with some VM software", "Requires UEFI Secure Boot"],
        "fix_action": {
            "label": "Enable Credential Guard",
            "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f',
        },
    }


def _check_wdigest() -> Dict:
    """12. Disable WDigest authentication."""
    val = _read_registry(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
        "UseLogonCredential",
    )
    if val is None:
        # Absent key defaults to disabled on Win 8.1+ with KB2871997
        status = "Enabled"
    elif val == 0:
        status = "Enabled"       # WDigest credential caching off (good)
    else:
        status = "Disabled"      # Credentials stored in cleartext (bad)
    return {
        "setting": "Disable WDigest Authentication",
        "description": "Prevent WDigest from storing cleartext passwords in memory.",
        "tier": "Moderate",
        "status": status,
        "recommended": "Enable",
        "pros": ["Prevents cleartext credential theft from LSASS", "Mitigates Mimikatz-style attacks"],
        "cons": ["Breaks very old authentication systems requiring WDigest"],
        "fix_action": {
            "label": "Disable WDigest credential caching",
            "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f',
        },
    }


def _check_ps_execution_policy() -> Dict:
    """13. Restrict PowerShell execution policy."""
    output = _run_cmd('powershell -NoProfile -Command "Get-ExecutionPolicy"')
    if output is None:
        status = "Unknown"
    else:
        policy = output.strip().lower()
        # RemoteSigned or AllSigned or Restricted are considered hardened
        if policy in ("remotesigned", "allsigned", "restricted"):
            status = "Enabled"
        else:
            status = "Disabled"
    return {
        "setting": "Restrict PowerShell Execution Policy",
        "description": "Set execution policy to RemoteSigned so only signed remote scripts run.",
        "tier": "Moderate",
        "status": status,
        "recommended": "Enable",
        "pros": ["Blocks unsigned scripts downloaded from the internet", "Reduces script-based malware risk"],
        "cons": ["May break unsigned local scripts or dev workflows"],
        "fix_action": {
            "label": "Set policy to RemoteSigned",
            "command": 'powershell -NoProfile -Command "Set-ExecutionPolicy RemoteSigned -Force"',
        },
    }


def _check_audit_logon() -> Dict:
    """14. Enable audit logging for logon events."""
    output = _run_cmd('auditpol /get /category:"Logon/Logoff"')
    if output is None:
        status = "Unknown"
    else:
        # Look for "Success and Failure" on the Logon line
        if "success and failure" in output.lower():
            status = "Enabled"
        elif "success" in output.lower() or "failure" in output.lower():
            status = "Disabled"   # Only partial auditing
        else:
            status = "Disabled"
    return {
        "setting": "Audit Logon Events",
        "description": "Log successful and failed logon attempts for forensic analysis.",
        "tier": "Moderate",
        "status": status,
        "recommended": "Enable",
        "pros": ["Enables detection of brute-force attacks", "Provides forensic trail for incidents"],
        "cons": ["Increases event log size", "May require log rotation policy"],
        "fix_action": {
            "label": "Enable logon auditing",
            "command": 'auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable',
        },
    }


def _check_autorun() -> Dict:
    """15. Disable autorun/autoplay."""
    val = _read_registry(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "NoDriveTypeAutoRun",
    )
    if val is None:
        status = "Disabled"
    elif val == 255:
        status = "Enabled"       # Autorun blocked on all drive types
    else:
        status = "Disabled"
    return {
        "setting": "Disable Autorun / Autoplay",
        "description": "Prevent automatic execution of programs from removable media.",
        "tier": "Moderate",
        "status": status,
        "recommended": "Enable",
        "pros": ["Blocks USB-based malware auto-execution", "Prevents autorun worm propagation"],
        "cons": ["Must manually open USB drives and media"],
        "fix_action": {
            "label": "Disable autorun (all drives)",
            "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f',
        },
    }


def _check_min_password_length() -> Dict:
    """16. Set minimum password length to 12."""
    output = _run_cmd("net accounts")
    if output is None:
        status = "Unknown"
    else:
        match = re.search(r"Minimum password length\s+(\d+)", output, re.IGNORECASE)
        if match:
            length = int(match.group(1))
            status = "Enabled" if length >= 12 else "Disabled"
        else:
            status = "Unknown"
    return {
        "setting": "Minimum Password Length (12+)",
        "description": "Require local account passwords to be at least 12 characters.",
        "tier": "Moderate",
        "status": status,
        "recommended": "Enable",
        "pros": ["Resists brute-force and dictionary attacks", "Enforces stronger credentials"],
        "cons": ["Users must remember longer passwords"],
        "fix_action": {
            "label": "Set minimum password length to 12",
            "command": "net accounts /minpwlen:12",
        },
    }


def _check_password_complexity() -> Dict:
    """17. Enable password complexity requirements."""
    output = _run_cmd("net accounts")
    if output is None:
        status = "Unknown"
    else:
        # "Password must meet complexity requirements" is not in 'net accounts'.
        # We look for the policy via secedit export.
        sec_output = _run_cmd(
            'powershell -NoProfile -Command "'
            "$tmp = [System.IO.Path]::GetTempFileName(); "
            "secedit /export /cfg $tmp /quiet | Out-Null; "
            "$c = Get-Content $tmp; Remove-Item $tmp; "
            "($c | Select-String 'PasswordComplexity').ToString()"
            '"'
        )
        if sec_output and "= 1" in sec_output:
            status = "Enabled"
        elif sec_output and "= 0" in sec_output:
            status = "Disabled"
        else:
            status = "Unknown"
    return {
        "setting": "Password Complexity Requirements",
        "description": "Require passwords to contain uppercase, lowercase, digits, and symbols.",
        "tier": "Moderate",
        "status": status,
        "recommended": "Enable",
        "pros": ["Dramatically increases password entropy", "Meets compliance baselines (CIS, NIST)"],
        "cons": ["Requires mix of character types, harder to memorise"],
        "fix_action": {
            "label": "Enable password complexity",
            "command": (
                'powershell -NoProfile -Command "'
                "$tmp = [System.IO.Path]::GetTempFileName(); "
                "secedit /export /cfg $tmp /quiet | Out-Null; "
                "(Get-Content $tmp) -replace 'PasswordComplexity = 0','PasswordComplexity = 1' | Set-Content $tmp; "
                "secedit /configure /db secedit.sdb /cfg $tmp /quiet; "
                "Remove-Item $tmp"
                '"'
            ),
        },
    }


def _check_bitlocker() -> Dict:
    """18. Enable BitLocker status check."""
    output = _run_cmd("manage-bde -status C:")
    if output is None:
        status = "Unknown"
    else:
        if "fully encrypted" in output.lower() or "percentage encrypted: 100" in output.lower():
            status = "Enabled"
        elif "protection on" in output.lower():
            status = "Enabled"
        else:
            status = "Disabled"
    return {
        "setting": "BitLocker Drive Encryption",
        "description": "Encrypt the system drive to protect data at rest.",
        "tier": "Moderate",
        "status": status,
        "recommended": "Enable",
        "pros": ["Protects data if device is lost or stolen", "Required by many compliance frameworks"],
        "cons": ["Performance impact on older hardware", "Recovery key must be backed up"],
        "fix_action": {
            "label": "Open BitLocker settings",
            "command": "control /name Microsoft.BitLockerDriveEncryption",
        },
    }


# -- Aggressive tier --------------------------------------------------------

def _check_windows_script_host() -> Dict:
    """19. Disable Windows Script Host."""
    val = _read_registry(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows Script Host\Settings",
        "Enabled",
    )
    if val is None:
        status = "Disabled"      # Key absent = WSH is enabled (bad)
    elif val == 0:
        status = "Enabled"       # WSH disabled (good)
    else:
        status = "Disabled"
    return {
        "setting": "Disable Windows Script Host",
        "description": "Prevent execution of .vbs, .js, and .wsf scripts via Windows Script Host.",
        "tier": "Aggressive",
        "status": status,
        "recommended": "Enable",
        "pros": ["Blocks a major malware delivery mechanism", "Prevents .vbs/.js dropper scripts"],
        "cons": ["Breaks legitimate .vbs/.js scripts", "Some software installers may fail"],
        "fix_action": {
            "label": "Disable Windows Script Host",
            "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings" /v Enabled /t REG_DWORD /d 0 /f',
        },
    }


def _check_office_macros() -> Dict:
    """20. Block Office macros from internet-sourced documents."""
    # Check Word; if set there, assume policy covers Office suite
    val = _read_registry(
        winreg.HKEY_CURRENT_USER,
        r"SOFTWARE\Policies\Microsoft\Office\16.0\Word\Security",
        "blockcontentexecutionfrominternet",
    )
    if val is None:
        status = "Disabled"
    elif val == 1:
        status = "Enabled"
    else:
        status = "Disabled"
    apps = {"Word": "Word", "Excel": "Excel", "PowerPoint": "PowerPoint"}
    cmds = " && ".join(
        f'reg add "HKCU\\SOFTWARE\\Policies\\Microsoft\\Office\\16.0\\{app}\\Security" '
        f"/v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f"
        for app in apps.values()
    )
    return {
        "setting": "Block Office Macros (Internet)",
        "description": "Prevent Office macros from running in documents downloaded from the internet.",
        "tier": "Aggressive",
        "status": status,
        "recommended": "Enable",
        "pros": ["Blocks macro-based phishing payloads", "Major reduction in social-engineering risk"],
        "cons": ["Blocks legitimate macros from email attachments or downloads"],
        "fix_action": {
            "label": "Block internet macros (Word/Excel/PPT)",
            "command": cmds,
        },
    }


def _check_lsa_protection() -> Dict:
    """21. Enable LSA protection (RunAsPPL)."""
    val = _read_registry(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Lsa",
        "RunAsPPL",
    )
    if val is None:
        status = "Disabled"
    elif val == 1:
        status = "Enabled"
    else:
        status = "Disabled"
    return {
        "setting": "LSA Protection (RunAsPPL)",
        "description": "Run LSASS as a Protected Process Light to prevent credential dumping.",
        "tier": "Aggressive",
        "status": status,
        "recommended": "Enable",
        "pros": ["Blocks Mimikatz and similar LSASS memory dumpers", "Kernel-enforced protection"],
        "cons": ["May break third-party authentication providers or credential managers"],
        "fix_action": {
            "label": "Enable LSA RunAsPPL",
            "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f',
        },
    }


def _check_disable_ntlm() -> Dict:
    """22. Disable NTLM authentication (send NTLMv2 only, refuse LM & NTLM)."""
    val = _read_registry(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Lsa",
        "LmCompatibilityLevel",
    )
    if val is None:
        status = "Disabled"
    elif val >= 5:
        status = "Enabled"
    else:
        status = "Disabled"
    return {
        "setting": "Disable NTLM Authentication",
        "description": "Refuse LM and NTLM authentication; only allow NTLMv2 responses.",
        "tier": "Aggressive",
        "status": status,
        "recommended": "Enable",
        "pros": ["Eliminates pass-the-hash with weak LM/NTLM", "Forces modern authentication"],
        "cons": ["Breaks old apps/devices that rely on NTLM", "Some NAS or printers may lose authentication"],
        "fix_action": {
            "label": "Set LmCompatibilityLevel to 5",
            "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f',
        },
    }


def _check_asr_rules() -> Dict:
    """23. Enable Attack Surface Reduction rules."""
    output = _run_cmd(
        'powershell -NoProfile -Command "(Get-MpPreference).AttackSurfaceReductionRules_Ids"'
    )
    if output is None:
        status = "Unknown"
    elif output.strip():
        status = "Enabled"
    else:
        status = "Disabled"
    # Common ASR rule GUIDs
    asr_ids = [
        "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550",  # Block executable content from email
        "D4F940AB-401B-4EFC-AADC-AD5F3C50688A",  # Block Office apps creating child processes
        "3B576869-A4EC-4529-8536-B80A7769E899",  # Block Office apps creating executable content
        "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84",  # Block Office apps injecting into processes
        "D3E037E1-3EB8-44C8-A917-57927947596D",  # Block JS/VBS launching downloaded content
        "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC",  # Block execution of obfuscated scripts
        "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B",  # Block Win32 API calls from Office macros
    ]
    ids_str = ",".join(asr_ids)
    actions_str = ",".join(["1"] * len(asr_ids))  # 1 = Block
    return {
        "setting": "Attack Surface Reduction Rules",
        "description": "Enable Microsoft Defender ASR rules to block common attack techniques.",
        "tier": "Aggressive",
        "status": status,
        "recommended": "Enable",
        "pros": ["Blocks Office-based exploits, script abuse, and email threats", "Layered defence at the endpoint"],
        "cons": ["May block legitimate software behaviour", "Requires testing in audit mode first"],
        "fix_action": {
            "label": "Enable common ASR rules",
            "command": (
                f'powershell -NoProfile -Command "Add-MpPreference '
                f"-AttackSurfaceReductionRules_Ids {ids_str} "
                f'-AttackSurfaceReductionRules_Actions {actions_str}"'
            ),
        },
    }


def _check_named_pipes() -> Dict:
    """24. Restrict anonymous named pipe access."""
    val = _read_registry(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "RestrictNullSessAccess",
    )
    if val is None:
        status = "Disabled"
    elif val == 1:
        status = "Enabled"
    else:
        status = "Disabled"
    return {
        "setting": "Restrict Named Pipe Access",
        "description": "Restrict anonymous access to named pipes and shares.",
        "tier": "Aggressive",
        "status": status,
        "recommended": "Enable",
        "pros": ["Prevents anonymous enumeration of shares/users", "Blocks null-session attacks"],
        "cons": ["May break some RPC-dependent or legacy applications"],
        "fix_action": {
            "label": "Restrict null session pipe access",
            "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v RestrictNullSessAccess /t REG_DWORD /d 1 /f',
        },
    }


def _check_remote_assistance() -> Dict:
    """25. Disable Remote Assistance."""
    val = _read_registry(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Remote Assistance",
        "fAllowToGetHelp",
    )
    if val is None:
        status = "Unknown"
    elif val == 0:
        status = "Enabled"       # Remote Assistance disabled (good)
    else:
        status = "Disabled"      # Remote Assistance allowed (bad)
    return {
        "setting": "Disable Remote Assistance",
        "description": "Prevent remote assistance connections to this machine.",
        "tier": "Aggressive",
        "status": status,
        "recommended": "Enable",
        "pros": ["Closes another remote-access vector", "Reduces social-engineering risk"],
        "cons": ["IT support teams cannot remotely assist the user"],
        "fix_action": {
            "label": "Disable Remote Assistance",
            "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f',
        },
    }


def _check_cached_credentials() -> Dict:
    """26. Disable cached domain credentials."""
    val = _read_registry(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "CachedLogonsCount",
    )
    if val is None:
        status = "Disabled"      # Default is typically 10 cached logons
    else:
        try:
            count = int(val)
            status = "Enabled" if count == 0 else "Disabled"
        except (ValueError, TypeError):
            status = "Unknown"
    return {
        "setting": "Disable Cached Credentials",
        "description": "Set cached domain logon count to zero to prevent offline credential attacks.",
        "tier": "Aggressive",
        "status": status,
        "recommended": "Enable",
        "pros": ["Prevents offline cracking of cached domain hashes", "Forces live DC authentication"],
        "cons": ["Cannot log in when domain controller is unreachable (laptop/VPN scenarios)"],
        "fix_action": {
            "label": "Set cached logons to 0",
            "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v CachedLogonsCount /t REG_SZ /d 0 /f',
        },
    }


def _check_force_ntlmv2() -> Dict:
    """27. Force NTLMv2 only and disable LM hash storage."""
    lm_level = _read_registry(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Lsa",
        "LmCompatibilityLevel",
    )
    no_lm_hash = _read_registry(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Lsa",
        "NoLMHash",
    )
    if lm_level is not None and lm_level >= 5 and no_lm_hash == 1:
        status = "Enabled"
    elif lm_level is None and no_lm_hash is None:
        status = "Disabled"
    else:
        status = "Disabled"
    return {
        "setting": "Force NTLMv2 + Disable LM Hash Storage",
        "description": "Only permit NTLMv2 responses and prevent storage of weak LM hashes.",
        "tier": "Aggressive",
        "status": status,
        "recommended": "Enable",
        "pros": ["Eliminates LM hash credential theft", "Strongest NTLM configuration"],
        "cons": ["Breaks old apps/devices using legacy NTLM or LM authentication"],
        "fix_action": {
            "label": "Force NTLMv2 and disable LM hashes",
            "command": (
                'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f && '
                'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f'
            ),
        },
    }


def _check_winrm() -> Dict:
    """28. Disable WinRM service."""
    output = _run_cmd("sc query winrm")
    if output is None:
        status = "Unknown"
    else:
        if "STOPPED" in output:
            status = "Enabled"   # WinRM stopped (good)
        elif "RUNNING" in output:
            status = "Disabled"  # WinRM running (bad)
        else:
            status = "Unknown"
    return {
        "setting": "Disable WinRM Service",
        "description": "Disable Windows Remote Management to prevent remote PowerShell access.",
        "tier": "Aggressive",
        "status": status,
        "recommended": "Enable",
        "pros": ["Blocks remote PowerShell execution", "Reduces lateral-movement surface"],
        "cons": ["Breaks PowerShell remoting and some enterprise management tools"],
        "fix_action": {
            "label": "Disable WinRM",
            "command": "sc config winrm start=disabled && sc stop winrm",
        },
    }


# ---------------------------------------------------------------------------
# Check registry -- ordered by tier
# ---------------------------------------------------------------------------

_ALL_CHECKS = [
    # Basic
    _check_firewall,
    _check_defender_realtime,
    _check_remote_desktop,
    _check_uac,
    _check_smbv1,
    _check_auto_updates,
    _check_screen_lock,
    _check_guest_account,
    # Moderate
    _check_llmnr,
    _check_netbios,
    _check_credential_guard,
    _check_wdigest,
    _check_ps_execution_policy,
    _check_audit_logon,
    _check_autorun,
    _check_min_password_length,
    _check_password_complexity,
    _check_bitlocker,
    # Aggressive
    _check_windows_script_host,
    _check_office_macros,
    _check_lsa_protection,
    _check_disable_ntlm,
    _check_asr_rules,
    _check_named_pipes,
    _check_remote_assistance,
    _check_cached_credentials,
    _check_force_ntlmv2,
    _check_winrm,
]

_TIER_ORDER = {"Basic": 0, "Moderate": 1, "Aggressive": 2}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_hardening() -> List[Dict]:
    """Run every hardening check and return a list of result dicts."""
    results: List[Dict] = []
    for check_fn in _ALL_CHECKS:
        try:
            results.append(check_fn())
        except Exception as exc:
            logger.error("Hardening check %s failed: %s", check_fn.__name__, exc)
            results.append({
                "setting": check_fn.__name__.replace("_check_", "").replace("_", " ").title(),
                "description": "Check failed due to an unexpected error.",
                "tier": "Unknown",
                "status": "Unknown",
                "recommended": "Enable",
                "pros": [],
                "cons": [],
                "fix_action": {"label": "N/A", "command": ""},
            })
    return results


def get_tier_settings(tier: str) -> List[Dict]:
    """Return hardening settings for *tier* and all lower (safer) tiers.

    For example ``get_tier_settings("Moderate")`` returns both Basic and
    Moderate settings.  ``get_tier_settings("Basic")`` returns only Basic.
    """
    tier_cap = tier.capitalize()
    if tier_cap not in _TIER_ORDER:
        raise ValueError(f"Unknown tier {tier!r}. Expected Basic, Moderate, or Aggressive.")
    max_level = _TIER_ORDER[tier_cap]
    all_results = scan_hardening()
    return [r for r in all_results if _TIER_ORDER.get(r["tier"], 99) <= max_level]
