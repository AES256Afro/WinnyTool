"""
WinnyTool - Network Diagnostics
Checks DNS, latency, adapters, WiFi signal, firewall, proxy, hosts file, and TCP settings.
"""

import os
import re
import socket
import subprocess
import time
from typing import Optional

try:
    import winreg
except ImportError:
    winreg = None


def check_dns_settings() -> dict:
    """
    Get current DNS servers and flag if using ISP defaults.
    Suggests switching to 1.1.1.1 or 8.8.8.8 if using auto/ISP DNS.
    """
    info = {
        "dns_servers": [],
        "is_isp_default": False,
        "details": "",
    }

    well_known_dns = {
        "1.1.1.1": "Cloudflare",
        "1.0.0.1": "Cloudflare",
        "8.8.8.8": "Google",
        "8.8.4.4": "Google",
        "9.9.9.9": "Quad9",
        "149.112.112.112": "Quad9",
        "208.67.222.222": "OpenDNS",
        "208.67.220.220": "OpenDNS",
    }

    try:
        result = subprocess.run(
            ["netsh", "interface", "ip", "show", "dns"],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout

        # Extract DNS servers from output
        dns_servers = re.findall(
            r"(?:Statically Configured|DNS servers configured).*?:\s*([\d.]+)",
            output, re.IGNORECASE
        )
        # Also catch DHCP-assigned DNS
        if not dns_servers:
            dns_servers = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", output)

        info["dns_servers"] = list(set(dns_servers))

        if not dns_servers:
            info["is_isp_default"] = True
            info["details"] = "No custom DNS configured - likely using ISP defaults via DHCP."
        else:
            known = [
                f"{ip} ({well_known_dns[ip]})"
                for ip in dns_servers if ip in well_known_dns
            ]
            unknown = [ip for ip in dns_servers if ip not in well_known_dns]

            if unknown and not known:
                info["is_isp_default"] = True
                info["details"] = (
                    f"DNS servers: {', '.join(dns_servers)}. "
                    "These appear to be ISP-assigned. Consider using a faster public DNS."
                )
            else:
                info["details"] = f"DNS servers: {', '.join(known + unknown)}"

        # Check if DHCP is assigning DNS (another indicator of ISP defaults)
        if "DHCP" in output and "Register" not in output:
            if not any(ip in well_known_dns for ip in dns_servers):
                info["is_isp_default"] = True

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        info["details"] = f"Could not check DNS settings: {e}"

    return info


def check_latency() -> dict:
    """Ping common endpoints and report average latency."""
    targets = {
        "google.com": None,
        "cloudflare.com": None,
        "microsoft.com": None,
    }
    details_parts = []

    for host in targets:
        try:
            result = subprocess.run(
                ["ping", "-n", "4", "-w", "3000", host],
                capture_output=True, text=True, timeout=20
            )
            output = result.stdout

            # Parse average from "Average = XXms"
            match = re.search(r"Average\s*=\s*(\d+)\s*ms", output)
            if match:
                avg = int(match.group(1))
                targets[host] = avg
                details_parts.append(f"{host}: {avg}ms")
            else:
                # Check for total failure
                if "Request timed out" in output or "could not find host" in output.lower():
                    details_parts.append(f"{host}: unreachable")
                else:
                    details_parts.append(f"{host}: no data")
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            details_parts.append(f"{host}: error")

    valid = [v for v in targets.values() if v is not None]
    avg_all = sum(valid) / len(valid) if valid else None

    return {
        "per_host": targets,
        "average_ms": avg_all,
        "details": "; ".join(details_parts),
    }


def check_network_adapters() -> dict:
    """List adapters and flag if multiple are active (can cause routing issues)."""
    adapters = []
    try:
        result = subprocess.run(
            ["netsh", "interface", "show", "interface"],
            capture_output=True, text=True, timeout=10
        )
        lines = result.stdout.strip().splitlines()

        for line in lines:
            parts = line.split()
            if len(parts) >= 4 and parts[0] in ("Enabled", "Disabled"):
                admin_state = parts[0]
                conn_state = parts[1]
                iface_type = parts[2]
                name = " ".join(parts[3:])
                adapters.append({
                    "name": name,
                    "admin_state": admin_state,
                    "state": conn_state,
                    "type": iface_type,
                })
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return {
            "adapters": [],
            "multiple_active": False,
            "details": f"Could not list adapters: {e}",
        }

    connected = [a for a in adapters if a["state"] == "Connected"]
    multiple = len(connected) > 1

    details = f"{len(connected)} connected adapter(s): " + ", ".join(
        a["name"] for a in connected
    ) if connected else "No connected adapters found."

    if multiple:
        details += " (Multiple active adapters may cause routing issues.)"

    return {
        "adapters": adapters,
        "multiple_active": multiple,
        "details": details,
    }


def check_wifi_signal() -> dict:
    """If on WiFi, get signal strength via netsh wlan show interfaces."""
    info = {"connected": False, "signal_pct": None, "ssid": "", "details": ""}
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout

        if "There is no wireless interface" in output or not output.strip():
            info["details"] = "No wireless interface detected."
            return info

        # Parse SSID
        ssid_match = re.search(r"SSID\s*:\s*(.+)", output)
        if ssid_match:
            info["ssid"] = ssid_match.group(1).strip()

        # Parse signal
        signal_match = re.search(r"Signal\s*:\s*(\d+)%", output)
        if signal_match:
            info["signal_pct"] = int(signal_match.group(1))
            info["connected"] = True

        # Parse radio type
        radio_match = re.search(r"Radio type\s*:\s*(.+)", output)
        radio = radio_match.group(1).strip() if radio_match else ""

        if info["connected"]:
            info["details"] = (
                f"Connected to '{info['ssid']}' - Signal: {info['signal_pct']}%"
                + (f" ({radio})" if radio else "")
            )
        else:
            info["details"] = "WiFi adapter present but not connected."

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        info["details"] = f"Could not check WiFi: {e}"

    return info


def check_firewall_status() -> dict:
    """Verify Windows Firewall is enabled for all profiles."""
    profiles = {}
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles", "state"],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout
        current_profile = None

        for line in output.splitlines():
            line = line.strip()
            if "Profile Settings" in line:
                current_profile = line.split("Profile")[0].strip()
            elif line.startswith("State") and current_profile:
                state = line.split()[-1] if line.split() else "Unknown"
                profiles[current_profile] = state.upper() == "ON"

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return {
            "profiles": {},
            "all_enabled": False,
            "details": f"Could not check firewall: {e}",
        }

    all_on = all(profiles.values()) if profiles else False
    details_parts = [f"{name}: {'ON' if on else 'OFF'}" for name, on in profiles.items()]

    return {
        "profiles": profiles,
        "all_enabled": all_on,
        "details": "Firewall - " + ", ".join(details_parts) if details_parts else "No profiles found.",
    }


def check_proxy_settings() -> dict:
    """Check for unexpected proxy configs in registry."""
    info = {"proxy_enabled": False, "proxy_server": "", "details": ""}

    if winreg is None:
        info["details"] = "winreg not available (non-Windows platform)."
        return info

    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        )
        try:
            enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
            info["proxy_enabled"] = bool(enabled)
        except FileNotFoundError:
            pass

        try:
            server, _ = winreg.QueryValueEx(key, "ProxyServer")
            info["proxy_server"] = server
        except FileNotFoundError:
            pass

        winreg.CloseKey(key)

        if info["proxy_enabled"] and info["proxy_server"]:
            info["details"] = f"Proxy is ENABLED: {info['proxy_server']}"
        elif info["proxy_enabled"]:
            info["details"] = "Proxy is enabled but no server configured."
        else:
            info["details"] = "No proxy configured."

    except (OSError, PermissionError) as e:
        info["details"] = f"Could not read proxy settings: {e}"

    return info


def check_hosts_file() -> dict:
    """Check if hosts file has suspicious entries."""
    info = {"suspicious_entries": [], "details": ""}
    hosts_path = os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"),
        "System32", "drivers", "etc", "hosts"
    )

    # Well-known domains that should never be redirected
    sensitive_domains = {
        "google.com", "www.google.com",
        "microsoft.com", "www.microsoft.com",
        "facebook.com", "www.facebook.com",
        "login.microsoftonline.com",
        "update.microsoft.com",
        "windowsupdate.com",
    }

    try:
        with open(hosts_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                parts = stripped.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    hostname = parts[1].lower()

                    # Flag: known domain redirected to non-localhost
                    if hostname in sensitive_domains and ip not in ("127.0.0.1", "::1"):
                        info["suspicious_entries"].append({
                            "line": line_num,
                            "content": stripped,
                            "reason": f"Sensitive domain '{hostname}' redirected to {ip}",
                        })
                    # Flag: many entries pointing to same non-local IP
                    elif ip not in ("127.0.0.1", "::1", "0.0.0.0") and "localhost" not in hostname:
                        info["suspicious_entries"].append({
                            "line": line_num,
                            "content": stripped,
                            "reason": f"Custom entry: {hostname} -> {ip}",
                        })

        count = len(info["suspicious_entries"])
        if count == 0:
            info["details"] = "Hosts file looks clean."
        else:
            info["details"] = (
                f"Found {count} suspicious entr{'y' if count == 1 else 'ies'} in hosts file."
            )

    except (OSError, PermissionError) as e:
        info["details"] = f"Could not read hosts file: {e}"

    return info


def check_tcp_settings() -> dict:
    """Check receive window auto-tuning level and suggest optimal settings."""
    info = {"autotune_level": "", "details": ""}
    try:
        result = subprocess.run(
            ["netsh", "interface", "tcp", "show", "global"],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout

        match = re.search(r"Receive Window Auto-Tuning Level\s*:\s*(\S+)", output)
        if match:
            level = match.group(1).lower()
            info["autotune_level"] = level

            if level == "normal":
                info["details"] = "TCP auto-tuning is set to 'normal' (optimal)."
            elif level == "disabled":
                info["details"] = (
                    "TCP auto-tuning is DISABLED. This can limit throughput on "
                    "high-bandwidth connections."
                )
            else:
                info["details"] = f"TCP auto-tuning level: {level}."
        else:
            info["details"] = "Could not parse TCP auto-tuning level."

        # Also check ECN capability and timestamps
        ecn_match = re.search(r"ECN Capability\s*:\s*(\S+)", output)
        if ecn_match:
            info["ecn"] = ecn_match.group(1)

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        info["details"] = f"Could not check TCP settings: {e}"

    return info


def flush_dns() -> dict:
    """Flush the DNS resolver cache."""
    try:
        result = subprocess.run(
            ["ipconfig", "/flushdns"],
            capture_output=True, text=True, timeout=10
        )
        output = (result.stdout + result.stderr).strip()
        success = "successfully" in output.lower()
        return {
            "success": success,
            "details": output,
        }
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return {
            "success": False,
            "details": f"Failed to flush DNS: {e}",
        }


def scan_network() -> list[dict]:
    """
    Run all network diagnostic checks and return a list of result dicts.
    Each dict: {"check": str, "status": str, "details": str, "fix_action": dict|None}
    """
    results = []

    # 1. DNS settings
    try:
        dns = check_dns_settings()
        if dns["is_isp_default"]:
            status = "Warning"
            fix = {
                "label": "Set DNS to Cloudflare (1.1.1.1)",
                "command": 'netsh interface ip set dns "Ethernet" static 1.1.1.1',
            }
        else:
            status = "Good"
            fix = None

        results.append({
            "check": "DNS Configuration",
            "status": status,
            "details": dns["details"],
            "fix_action": fix,
        })
    except Exception as e:
        results.append({
            "check": "DNS Configuration",
            "status": "Warning",
            "details": f"Could not check DNS: {e}",
            "fix_action": None,
        })

    # 2. Latency
    try:
        latency = check_latency()
        avg = latency["average_ms"]
        if avg is None:
            status = "Critical"
            details = "Could not reach any endpoints. " + latency["details"]
        elif avg > 150:
            status = "Warning"
            details = f"High average latency: {avg:.0f}ms. {latency['details']}"
        else:
            status = "Good"
            details = f"Average latency: {avg:.0f}ms. {latency['details']}"

        results.append({
            "check": "Network Latency",
            "status": status,
            "details": details,
            "fix_action": None,
        })
    except Exception as e:
        results.append({
            "check": "Network Latency",
            "status": "Warning",
            "details": f"Could not check latency: {e}",
            "fix_action": None,
        })

    # 3. Network adapters
    try:
        adapters = check_network_adapters()
        status = "Warning" if adapters["multiple_active"] else "Good"
        results.append({
            "check": "Network Adapters",
            "status": status,
            "details": adapters["details"],
            "fix_action": None,
        })
    except Exception as e:
        results.append({
            "check": "Network Adapters",
            "status": "Warning",
            "details": f"Could not check adapters: {e}",
            "fix_action": None,
        })

    # 4. WiFi signal
    try:
        wifi = check_wifi_signal()
        if wifi["connected"]:
            sig = wifi["signal_pct"]
            if sig is not None and sig < 40:
                status = "Critical"
            elif sig is not None and sig < 65:
                status = "Warning"
            else:
                status = "Good"
        else:
            status = "Good"  # Not on WiFi is fine

        results.append({
            "check": "WiFi Signal",
            "status": status,
            "details": wifi["details"],
            "fix_action": None,
        })
    except Exception as e:
        results.append({
            "check": "WiFi Signal",
            "status": "Warning",
            "details": f"Could not check WiFi: {e}",
            "fix_action": None,
        })

    # 5. Firewall
    try:
        fw = check_firewall_status()
        if fw["all_enabled"]:
            status = "Good"
            fix = None
        else:
            status = "Critical"
            fix = {
                "label": "Enable Windows Firewall for all profiles",
                "command": "netsh advfirewall set allprofiles state on",
            }

        results.append({
            "check": "Windows Firewall",
            "status": status,
            "details": fw["details"],
            "fix_action": fix,
        })
    except Exception as e:
        results.append({
            "check": "Windows Firewall",
            "status": "Warning",
            "details": f"Could not check firewall: {e}",
            "fix_action": None,
        })

    # 6. Proxy settings
    try:
        proxy = check_proxy_settings()
        if proxy["proxy_enabled"]:
            status = "Warning"
            fix = {
                "label": "Disable proxy",
                "command": (
                    'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion'
                    '\\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f'
                ),
            }
        else:
            status = "Good"
            fix = None

        results.append({
            "check": "Proxy Settings",
            "status": status,
            "details": proxy["details"],
            "fix_action": fix,
        })
    except Exception as e:
        results.append({
            "check": "Proxy Settings",
            "status": "Warning",
            "details": f"Could not check proxy: {e}",
            "fix_action": None,
        })

    # 7. Hosts file
    try:
        hosts = check_hosts_file()
        if hosts["suspicious_entries"]:
            status = "Warning"
            fix = {
                "label": "Open hosts file for review",
                "command": "notepad C:\\Windows\\System32\\drivers\\etc\\hosts",
            }
        else:
            status = "Good"
            fix = None

        results.append({
            "check": "Hosts File",
            "status": status,
            "details": hosts["details"],
            "fix_action": fix,
        })
    except Exception as e:
        results.append({
            "check": "Hosts File",
            "status": "Warning",
            "details": f"Could not check hosts file: {e}",
            "fix_action": None,
        })

    # 8. TCP settings
    try:
        tcp = check_tcp_settings()
        level = tcp.get("autotune_level", "").lower()
        if level == "disabled":
            status = "Warning"
            fix = {
                "label": "Enable TCP auto-tuning",
                "command": "netsh int tcp set global autotuninglevel=normal",
            }
        elif level == "normal":
            status = "Good"
            fix = None
        else:
            status = "Good"
            fix = None

        results.append({
            "check": "TCP Settings",
            "status": status,
            "details": tcp["details"],
            "fix_action": fix,
        })
    except Exception as e:
        results.append({
            "check": "TCP Settings",
            "status": "Warning",
            "details": f"Could not check TCP settings: {e}",
            "fix_action": None,
        })

    return results


if __name__ == "__main__":
    print("=== WinnyTool Network Diagnostics ===\n")
    for item in scan_network():
        icon = {"Good": "[OK]", "Warning": "[!!]", "Critical": "[XX]"}.get(item["status"], "[??]")
        print(f"{icon} {item['check']}: {item['status']}")
        print(f"    {item['details']}")
        if item["fix_action"]:
            print(f"    Fix: {item['fix_action']['label']}")
        print()
