"""
router_security.py - Local-side router and network security diagnostics.

Performs DNS security, port scanning, WiFi analysis, network exposure,
and privacy checks using only Python standard library modules.
"""

import subprocess
import socket
import re
import os
import json
import logging
import struct
import time

try:
    import winreg
except ImportError:
    winreg = None

try:
    import urllib.request
    import urllib.error
except ImportError:
    urllib = None

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CREATE_NO_WINDOW = 0x08000000

WELL_KNOWN_SECURE_DNS = {
    "1.1.1.1", "1.0.0.1",                # Cloudflare
    "8.8.8.8", "8.8.4.4",                # Google
    "9.9.9.9", "149.112.112.112",         # Quad9
    "208.67.222.222", "208.67.220.220",   # OpenDNS
    "94.140.14.14", "94.140.15.15",       # AdGuard
}

STATUS_ORDER = {"Fail": 0, "Warning": 1, "Info": 2, "Pass": 3, "Unknown": 4}

DANGEROUS_PORTS = {
    23:    ("Telnet", "Fail"),
    21:    ("FTP", "Warning"),
    22:    ("SSH", "Warning"),
    80:    ("HTTP Admin Panel", "Warning"),
    443:   ("HTTPS Admin Panel", "Info"),
    3389:  ("RDP", "Fail"),
    8080:  ("HTTP Proxy/Admin", "Warning"),
    8443:  ("HTTPS Alt", "Warning"),
    161:   ("SNMP", "Fail"),
    5555:  ("Android ADB", "Fail"),
    7547:  ("TR-069 (ISP mgmt)", "Fail"),
    32764: ("Linksys Backdoor", "Fail"),
    1900:  ("UPnP SSDP", "Warning"),
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_cmd(cmd, timeout=10):
    """Run a subprocess command and return stdout. Never raises."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
        return result.stdout
    except Exception as exc:
        logger.debug("Command %s failed: %s", cmd, exc)
        return ""


def _read_registry(hive, subkey, value_name):
    """Read a registry value. Returns the value or None on failure."""
    if winreg is None:
        return None
    try:
        with winreg.OpenKey(hive, subkey) as key:
            val, _ = winreg.QueryValueEx(key, value_name)
            return val
    except (OSError, FileNotFoundError, PermissionError):
        return None


def _make_result(check, status, details, fix_suggestion="", fix_action=None):
    """Build a standardised result dict."""
    return {
        "check": check,
        "status": status,
        "details": details,
        "fix_suggestion": fix_suggestion,
        "fix_action": fix_action,  # {"label": str, "command": str} or None
    }


def get_default_gateway():
    """Parse ipconfig output to find the default gateway IP address."""
    try:
        output = _run_cmd(["ipconfig"], timeout=5)
        # Match lines like "Default Gateway . . . . . . . . . : 192.168.1.1"
        matches = re.findall(
            r"Default Gateway[\s.]*:\s*([\d]+\.[\d]+\.[\d]+\.[\d]+)", output
        )
        if matches:
            return matches[0]
    except Exception as exc:
        logger.debug("get_default_gateway error: %s", exc)
    return None


def _get_dns_servers():
    """Return a list of configured DNS server IPs from ipconfig /all."""
    output = _run_cmd(["ipconfig", "/all"], timeout=5)
    dns_servers = []
    in_dns_block = False
    for line in output.splitlines():
        if "DNS Servers" in line:
            in_dns_block = True
            match = re.search(r":\s*([\d]+\.[\d]+\.[\d]+\.[\d]+)", line)
            if match:
                dns_servers.append(match.group(1))
        elif in_dns_block:
            match = re.match(r"\s+([\d]+\.[\d]+\.[\d]+\.[\d]+)", line)
            if match:
                dns_servers.append(match.group(1))
            else:
                in_dns_block = False
    return dns_servers


# ---------------------------------------------------------------------------
# DNS Security Checks
# ---------------------------------------------------------------------------


def check_dns_servers():
    """Check if DNS servers are well-known secure providers."""
    name = "DNS Server Configuration"
    try:
        servers = _get_dns_servers()
        if not servers:
            return _make_result(name, "Unknown", "Could not determine DNS servers.")

        insecure = [s for s in servers if s not in WELL_KNOWN_SECURE_DNS]
        if not insecure:
            return _make_result(
                name, "Pass",
                f"DNS servers are secure providers: {', '.join(servers)}",
            )

        # Build a PowerShell fix command to set Cloudflare DNS on the active adapter
        ps_cmd = (
            "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | "
            "ForEach-Object { "
            "Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex "
            "-ServerAddresses ('1.1.1.1','1.0.0.1') }"
        )
        return _make_result(
            name, "Warning",
            f"DNS servers may be ISP defaults: {', '.join(insecure)}. "
            "Secure DNS providers (Cloudflare, Google, Quad9) offer better privacy.",
            fix_suggestion="Switch to a secure DNS provider such as Cloudflare (1.1.1.1) or Google (8.8.8.8).",
            fix_action={"label": "Set DNS to Cloudflare (1.1.1.1)", "command": ps_cmd},
        )
    except Exception as exc:
        logger.debug("check_dns_servers error: %s", exc)
        return _make_result(name, "Unknown", f"Error checking DNS servers: {exc}")


def check_dns_over_https():
    """Check if Windows DNS-over-HTTPS (DoH) is enabled."""
    name = "DNS-over-HTTPS (DoH)"
    try:
        val = _read_registry(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
            "EnableAutoDoh",
        )
        if val == 2:
            return _make_result(name, "Pass", "DNS-over-HTTPS is enabled (AutoDoh = 2).")
        elif val is not None:
            ps_cmd = (
                'Set-ItemProperty -Path '
                '"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters" '
                '-Name "EnableAutoDoh" -Value 2 -Type DWord'
            )
            return _make_result(
                name, "Warning",
                f"DNS-over-HTTPS is not fully enabled (EnableAutoDoh = {val}).",
                fix_suggestion="Enable DoH to encrypt DNS queries and prevent snooping.",
                fix_action={"label": "Enable DNS-over-HTTPS", "command": ps_cmd},
            )
        else:
            ps_cmd = (
                'New-ItemProperty -Path '
                '"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters" '
                '-Name "EnableAutoDoh" -Value 2 -PropertyType DWord -Force'
            )
            return _make_result(
                name, "Warning",
                "DNS-over-HTTPS registry key not found (DoH likely disabled).",
                fix_suggestion="Enable DoH to encrypt DNS queries and prevent snooping.",
                fix_action={"label": "Enable DNS-over-HTTPS", "command": ps_cmd},
            )
    except Exception as exc:
        logger.debug("check_dns_over_https error: %s", exc)
        return _make_result(name, "Unknown", f"Error checking DoH status: {exc}")


def check_dns_leak():
    """Resolve a known domain and check if the resolver is leaking to ISP."""
    name = "DNS Leak Test"
    try:
        # Resolve a well-known domain and see what DNS server answers
        # We use a simple heuristic: resolve whoami.akamai.net which returns
        # the IP of the DNS resolver. If it matches a known secure DNS range,
        # we consider it safe.
        try:
            resolver_ip = socket.gethostbyname("whoami.ds.akahelp.net")
        except socket.gaierror:
            resolver_ip = None

        if resolver_ip is None:
            return _make_result(
                name, "Info",
                "Could not perform DNS leak test (resolution failed).",
            )

        # Check if the resolver IP belongs to known secure DNS providers
        secure_prefixes = ("1.1.1.", "1.0.0.", "8.8.8.", "8.8.4.", "9.9.9.",
                           "149.112.", "208.67.")
        if any(resolver_ip.startswith(p) for p in secure_prefixes):
            return _make_result(
                name, "Pass",
                f"DNS resolver ({resolver_ip}) appears to be a secure provider.",
            )
        else:
            return _make_result(
                name, "Warning",
                f"DNS resolver IP ({resolver_ip}) does not match known secure DNS "
                "providers. Your DNS queries may be visible to your ISP.",
                fix_suggestion="Configure a secure DNS provider to prevent DNS leaks.",
            )
    except Exception as exc:
        logger.debug("check_dns_leak error: %s", exc)
        return _make_result(name, "Unknown", f"Error during DNS leak test: {exc}")


# ---------------------------------------------------------------------------
# Port Security Checks
# ---------------------------------------------------------------------------


def check_common_ports():
    """Scan common dangerous ports on the default gateway."""
    name = "Gateway Port Scan"
    try:
        gateway = get_default_gateway()
        if not gateway:
            return _make_result(name, "Unknown", "Could not determine default gateway.")

        open_ports = []
        for port, (service, severity) in DANGEROUS_PORTS.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((gateway, port))
                sock.close()
                if result == 0:
                    open_ports.append((port, service, severity))
            except Exception:
                pass

        if not open_ports:
            return _make_result(
                name, "Pass",
                f"No common dangerous ports are open on the gateway ({gateway}).",
            )

        # Determine worst severity
        worst = "Warning"
        details_parts = []
        for port, service, severity in open_ports:
            details_parts.append(f"Port {port} ({service}) - {severity}")
            if STATUS_ORDER.get(severity, 99) < STATUS_ORDER.get(worst, 99):
                worst = severity

        return _make_result(
            name, worst,
            f"Open ports on gateway {gateway}: " + "; ".join(details_parts),
            fix_suggestion=(
                "Disable unnecessary services on your router. Telnet, SNMP, "
                "TR-069, and backdoor ports are especially dangerous."
            ),
        )
    except Exception as exc:
        logger.debug("check_common_ports error: %s", exc)
        return _make_result(name, "Unknown", f"Error scanning ports: {exc}")


def check_upnp_status():
    """Check if UPnP is enabled by sending an SSDP M-SEARCH to the multicast address."""
    name = "UPnP Status"
    try:
        ssdp_request = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 2\r\n"
            "ST: upnp:rootdevice\r\n"
            "\r\n"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(3)
        sock.sendto(ssdp_request.encode(), ("239.255.255.250", 1900))

        responses = []
        try:
            while True:
                data, addr = sock.recvfrom(4096)
                responses.append((data.decode(errors="replace"), addr))
        except socket.timeout:
            pass
        finally:
            sock.close()

        if responses:
            devices = [addr[0] for _, addr in responses]
            return _make_result(
                name, "Warning",
                f"UPnP is active. {len(responses)} device(s) responded: "
                f"{', '.join(set(devices))}.",
                fix_suggestion=(
                    "Disable UPnP on your router to prevent malware from "
                    "automatically opening ports. Check your router admin panel."
                ),
            )
        else:
            return _make_result(
                name, "Pass",
                "No UPnP response detected. UPnP appears to be disabled.",
            )
    except Exception as exc:
        logger.debug("check_upnp_status error: %s", exc)
        return _make_result(name, "Unknown", f"Error checking UPnP: {exc}")


# ---------------------------------------------------------------------------
# Router Configuration Checks
# ---------------------------------------------------------------------------


def check_default_gateway_accessible():
    """Check if the default gateway web interface is reachable."""
    name = "Router Web Interface"
    try:
        gateway = get_default_gateway()
        if not gateway:
            return _make_result(name, "Unknown", "Could not determine default gateway.")

        accessible_on = []
        for port in (80, 443):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((gateway, port))
                sock.close()
                if result == 0:
                    accessible_on.append(port)
            except Exception:
                pass

        if accessible_on:
            ports_str = ", ".join(str(p) for p in accessible_on)
            return _make_result(
                name, "Info",
                f"Router web interface is accessible at {gateway} on port(s) {ports_str}.",
            )
        else:
            return _make_result(
                name, "Info",
                f"Router web interface at {gateway} does not appear accessible on port 80 or 443.",
            )
    except Exception as exc:
        logger.debug("check_default_gateway_accessible error: %s", exc)
        return _make_result(name, "Unknown", f"Error checking gateway accessibility: {exc}")


def check_router_default_credentials():
    """Try to detect router make/model and warn about default credentials."""
    name = "Router Default Credentials"
    try:
        gateway = get_default_gateway()
        if not gateway:
            return _make_result(name, "Unknown", "Could not determine default gateway.")

        # Common default credential patterns by manufacturer keyword
        default_creds = {
            "linksys": "admin / admin",
            "netgear": "admin / password",
            "dlink": "admin / (blank)",
            "d-link": "admin / (blank)",
            "tp-link": "admin / admin",
            "tplink": "admin / admin",
            "asus": "admin / admin",
            "belkin": "(none) / (blank)",
            "zyxel": "admin / 1234",
            "cisco": "admin / admin",
            "huawei": "admin / admin",
            "arris": "admin / password",
            "motorola": "admin / motorola",
            "ubiquiti": "ubnt / ubnt",
        }

        response_text = ""
        server_header = ""
        for scheme in ("http", "https"):
            try:
                url = f"{scheme}://{gateway}/"
                req = urllib.request.Request(url, method="GET")
                req.add_header("User-Agent", "WinnyTool/1.0")
                resp = urllib.request.urlopen(req, timeout=3)
                response_text = resp.read(4096).decode(errors="replace").lower()
                server_header = resp.getheader("Server", "").lower()
                break
            except Exception:
                continue

        if not response_text and not server_header:
            return _make_result(
                name, "Info",
                "Could not retrieve router web interface to check for default credentials.",
            )

        combined = response_text + " " + server_header
        detected_brands = []
        for brand, creds in default_creds.items():
            if brand in combined:
                detected_brands.append((brand.capitalize(), creds))

        if detected_brands:
            brand_info = "; ".join(
                f"{b} (default: {c})" for b, c in detected_brands
            )
            return _make_result(
                name, "Warning",
                f"Detected router brand(s): {brand_info}. "
                "Ensure you have changed the default login credentials.",
                fix_suggestion=(
                    "Log into your router admin panel and change the default "
                    "username and password immediately."
                ),
            )
        else:
            return _make_result(
                name, "Pass",
                "Router brand not identified in common default credential databases.",
            )
    except Exception as exc:
        logger.debug("check_router_default_credentials error: %s", exc)
        return _make_result(name, "Unknown", f"Error checking router credentials: {exc}")


# ---------------------------------------------------------------------------
# WiFi Security Checks
# ---------------------------------------------------------------------------


def check_wifi_encryption():
    """Check current WiFi authentication type."""
    name = "WiFi Encryption"
    try:
        output = _run_cmd(["netsh", "wlan", "show", "interfaces"], timeout=5)
        if not output or "not running" in output.lower():
            return _make_result(name, "Info", "WiFi is not connected or service not running.")

        auth_match = re.search(r"Authentication\s*:\s*(.+)", output)
        if not auth_match:
            return _make_result(name, "Unknown", "Could not determine WiFi authentication type.")

        auth_type = auth_match.group(1).strip()
        auth_upper = auth_type.upper()

        if "WPA3" in auth_upper:
            return _make_result(name, "Pass", f"WiFi authentication: {auth_type} (excellent).")
        elif "WPA2" in auth_upper:
            return _make_result(name, "Pass", f"WiFi authentication: {auth_type} (good).")
        elif "WPA" in auth_upper:
            return _make_result(
                name, "Warning",
                f"WiFi authentication: {auth_type}. WPA (v1) is outdated and vulnerable.",
                fix_suggestion="Upgrade your WiFi network to WPA2 or WPA3 in your router settings.",
            )
        elif "WEP" in auth_upper:
            return _make_result(
                name, "Fail",
                f"WiFi authentication: {auth_type}. WEP is critically insecure and can be cracked in minutes.",
                fix_suggestion="Immediately upgrade your WiFi encryption to WPA2 or WPA3.",
            )
        elif "OPEN" in auth_upper or auth_upper == "":
            return _make_result(
                name, "Fail",
                "WiFi network is OPEN (no encryption). All traffic is visible to anyone nearby.",
                fix_suggestion="Enable WPA2 or WPA3 encryption on your WiFi network immediately.",
            )
        else:
            return _make_result(name, "Info", f"WiFi authentication: {auth_type}.")

    except Exception as exc:
        logger.debug("check_wifi_encryption error: %s", exc)
        return _make_result(name, "Unknown", f"Error checking WiFi encryption: {exc}")


def check_wps_status():
    """Check if WPS is detected on the connected network's BSSID."""
    name = "WiFi Protected Setup (WPS)"
    try:
        # Get current BSSID
        iface_output = _run_cmd(["netsh", "wlan", "show", "interfaces"], timeout=5)
        bssid_match = re.search(r"BSSID\s*:\s*([0-9a-fA-F:]{17})", iface_output)
        if not bssid_match:
            return _make_result(name, "Info", "Not connected to WiFi or BSSID not found.")

        current_bssid = bssid_match.group(1).lower()

        # Scan networks for WPS info (netsh does not directly report WPS,
        # but we can look for hints in the detailed network output)
        net_output = _run_cmd(
            ["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=10
        )

        # Windows netsh doesn't directly report WPS status in all versions.
        # We parse what we can - some driver implementations include it.
        # Look for the BSSID section and any WPS-related info nearby.
        lines = net_output.splitlines()
        in_target_bssid = False
        for i, line in enumerate(lines):
            if current_bssid in line.lower():
                in_target_bssid = True
                continue
            if in_target_bssid:
                if "BSSID" in line and current_bssid not in line.lower():
                    break  # moved to next BSSID
                if "WPS" in line.upper():
                    return _make_result(
                        name, "Warning",
                        "WPS appears to be enabled on your connected WiFi network.",
                        fix_suggestion=(
                            "Disable WPS in your router settings. WPS PIN mode is "
                            "vulnerable to brute force attacks."
                        ),
                    )

        return _make_result(
            name, "Info",
            "WPS status could not be confirmed from available network data. "
            "Check your router admin panel to verify WPS is disabled.",
        )
    except Exception as exc:
        logger.debug("check_wps_status error: %s", exc)
        return _make_result(name, "Unknown", f"Error checking WPS status: {exc}")


def check_wifi_signal_strength():
    """Report WiFi signal quality and warn if below 50%."""
    name = "WiFi Signal Strength"
    try:
        output = _run_cmd(["netsh", "wlan", "show", "interfaces"], timeout=5)
        if not output:
            return _make_result(name, "Info", "WiFi is not connected or service not running.")

        signal_match = re.search(r"Signal\s*:\s*(\d+)%", output)
        if not signal_match:
            return _make_result(name, "Unknown", "Could not determine WiFi signal strength.")

        signal = int(signal_match.group(1))
        if signal >= 70:
            return _make_result(name, "Pass", f"WiFi signal strength: {signal}% (good).")
        elif signal >= 50:
            return _make_result(name, "Info", f"WiFi signal strength: {signal}% (fair).")
        else:
            return _make_result(
                name, "Warning",
                f"WiFi signal strength: {signal}% (weak). This may cause slow speeds and disconnections.",
                fix_suggestion=(
                    "Move closer to your router, reduce obstructions, or consider "
                    "a WiFi extender/mesh system."
                ),
            )
    except Exception as exc:
        logger.debug("check_wifi_signal_strength error: %s", exc)
        return _make_result(name, "Unknown", f"Error checking WiFi signal: {exc}")


# ---------------------------------------------------------------------------
# Network Exposure Checks
# ---------------------------------------------------------------------------


def check_remote_desktop():
    """Check if Remote Desktop Protocol (RDP) is enabled."""
    name = "Remote Desktop (RDP)"
    try:
        val = _read_registry(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Terminal Server",
            "fDenyTSConnections",
        )
        if val is None:
            return _make_result(name, "Unknown", "Could not read RDP registry setting.")

        if val == 1:
            return _make_result(name, "Pass", "Remote Desktop is disabled.")
        else:
            ps_cmd = (
                'Set-ItemProperty -Path '
                '"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" '
                '-Name "fDenyTSConnections" -Value 1 -Type DWord'
            )
            return _make_result(
                name, "Warning",
                "Remote Desktop is ENABLED. This is a common attack vector if exposed to the internet.",
                fix_suggestion="Disable RDP if not needed, or restrict it to VPN access only.",
                fix_action={"label": "Disable Remote Desktop", "command": ps_cmd},
            )
    except Exception as exc:
        logger.debug("check_remote_desktop error: %s", exc)
        return _make_result(name, "Unknown", f"Error checking RDP status: {exc}")


def check_smb_exposure():
    """Check if SMBv1 is enabled (deprecated and vulnerable)."""
    name = "SMBv1 Protocol"
    try:
        # Check via registry
        val = _read_registry(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "SMB1",
        )

        # Also check via PowerShell as a fallback
        ps_output = _run_cmd(
            ["powershell", "-NoProfile", "-Command",
             "Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol"],
            timeout=10,
        )

        smb1_enabled = False
        if val is not None:
            smb1_enabled = val != 0
        elif ps_output.strip().lower() == "true":
            smb1_enabled = True
        elif ps_output.strip().lower() == "false":
            smb1_enabled = False
        else:
            return _make_result(name, "Unknown", "Could not determine SMBv1 status.")

        if smb1_enabled:
            ps_cmd = (
                "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"
            )
            return _make_result(
                name, "Fail",
                "SMBv1 is ENABLED. This protocol is exploited by ransomware (WannaCry, NotPetya).",
                fix_suggestion="Disable SMBv1 immediately. Modern systems use SMBv2/v3.",
                fix_action={"label": "Disable SMBv1", "command": ps_cmd},
            )
        else:
            return _make_result(name, "Pass", "SMBv1 is disabled (good).")

    except Exception as exc:
        logger.debug("check_smb_exposure error: %s", exc)
        return _make_result(name, "Unknown", f"Error checking SMBv1 status: {exc}")


def check_network_discovery():
    """Check if network discovery firewall rules are enabled."""
    name = "Network Discovery"
    try:
        output = _run_cmd(
            ["netsh", "advfirewall", "firewall", "show", "rule",
             "name=Network Discovery"],
            timeout=10,
        )
        if not output:
            return _make_result(name, "Info", "Could not query network discovery rules.")

        enabled_count = len(re.findall(r"Enabled:\s*Yes", output, re.IGNORECASE))
        if enabled_count > 0:
            return _make_result(
                name, "Warning",
                f"Network Discovery is enabled ({enabled_count} rule(s) active). "
                "Your PC is visible to other devices on the network.",
                fix_suggestion=(
                    "Disable network discovery on public networks. Go to "
                    "Control Panel > Network and Sharing Center > Advanced sharing settings."
                ),
            )
        else:
            return _make_result(name, "Pass", "Network Discovery is disabled.")

    except Exception as exc:
        logger.debug("check_network_discovery error: %s", exc)
        return _make_result(name, "Unknown", f"Error checking network discovery: {exc}")


def check_firewall_profiles():
    """Verify all three Windows Firewall profiles are enabled."""
    name = "Windows Firewall Profiles"
    try:
        output = _run_cmd(
            ["netsh", "advfirewall", "show", "allprofiles", "state"],
            timeout=5,
        )
        if not output:
            return _make_result(name, "Unknown", "Could not query firewall profiles.")

        profiles = {"Domain": None, "Private": None, "Public": None}
        current_profile = None
        for line in output.splitlines():
            for p in profiles:
                if p in line and "Profile" in line:
                    current_profile = p
            if current_profile and "State" in line:
                profiles[current_profile] = "ON" in line.upper()
                current_profile = None

        disabled = [p for p, enabled in profiles.items() if enabled is False]
        unknown = [p for p, enabled in profiles.items() if enabled is None]

        if disabled:
            ps_cmd = "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"
            return _make_result(
                name, "Fail",
                f"Firewall DISABLED for profile(s): {', '.join(disabled)}.",
                fix_suggestion="Enable the Windows Firewall for all profiles immediately.",
                fix_action={"label": "Enable All Firewall Profiles", "command": ps_cmd},
            )
        elif unknown:
            return _make_result(
                name, "Warning",
                f"Could not confirm status for profile(s): {', '.join(unknown)}.",
            )
        else:
            return _make_result(
                name, "Pass",
                "All Windows Firewall profiles (Domain, Private, Public) are enabled.",
            )
    except Exception as exc:
        logger.debug("check_firewall_profiles error: %s", exc)
        return _make_result(name, "Unknown", f"Error checking firewall profiles: {exc}")


# ---------------------------------------------------------------------------
# Privacy Checks
# ---------------------------------------------------------------------------


def check_proxy_settings():
    """Check if a proxy is configured in Windows Internet Settings."""
    name = "Proxy Configuration"
    try:
        proxy_enabled = _read_registry(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "ProxyEnable",
        )
        proxy_server = _read_registry(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "ProxyServer",
        )

        if proxy_enabled and proxy_server:
            return _make_result(
                name, "Warning",
                f"A proxy is configured: {proxy_server}. "
                "Verify this is intentional and trusted.",
                fix_suggestion=(
                    "If you did not set this proxy, it could be redirecting your "
                    "traffic. Remove it via Settings > Network > Proxy."
                ),
            )
        else:
            return _make_result(name, "Pass", "No system proxy is configured.")

    except Exception as exc:
        logger.debug("check_proxy_settings error: %s", exc)
        return _make_result(name, "Unknown", f"Error checking proxy settings: {exc}")


def check_hosts_file_tampering():
    """Check the hosts file for suspicious redirects of well-known domains."""
    name = "Hosts File Integrity"
    try:
        hosts_path = os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"),
            "System32", "drivers", "etc", "hosts",
        )
        if not os.path.exists(hosts_path):
            return _make_result(name, "Unknown", "Hosts file not found.")

        suspicious_domains = {
            "google.com", "www.google.com",
            "facebook.com", "www.facebook.com",
            "microsoft.com", "www.microsoft.com",
            "apple.com", "www.apple.com",
            "amazon.com", "www.amazon.com",
            "paypal.com", "www.paypal.com",
            "bankofamerica.com", "chase.com",
            "wellsfargo.com", "citibank.com",
            "login.microsoftonline.com",
            "accounts.google.com",
            "windowsupdate.com", "update.microsoft.com",
        }

        suspicious_entries = []
        try:
            with open(hosts_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        hostname = parts[1].lower()
                        # Skip localhost entries
                        if hostname in ("localhost", "localhost.localdomain"):
                            continue
                        if hostname in suspicious_domains:
                            suspicious_entries.append(f"{ip} -> {hostname}")
        except PermissionError:
            return _make_result(
                name, "Unknown",
                "Permission denied reading hosts file. Run as administrator.",
            )

        if suspicious_entries:
            return _make_result(
                name, "Fail",
                f"Hosts file contains suspicious redirects for well-known domains: "
                f"{'; '.join(suspicious_entries[:5])}",
                fix_suggestion=(
                    "Your hosts file may have been tampered with by malware. "
                    "Review and remove suspicious entries from "
                    f"{hosts_path}"
                ),
            )
        else:
            return _make_result(name, "Pass", "Hosts file shows no suspicious redirects.")

    except Exception as exc:
        logger.debug("check_hosts_file_tampering error: %s", exc)
        return _make_result(name, "Unknown", f"Error checking hosts file: {exc}")


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------


def scan_router_security():
    """
    Run all router and network security checks.

    Returns a list of result dicts sorted by severity (Fail first, then
    Warning, Info, Pass, Unknown).
    """
    checks = [
        # DNS Security
        check_dns_servers,
        check_dns_over_https,
        check_dns_leak,
        # Port Security
        check_common_ports,
        check_upnp_status,
        # Router Configuration
        check_default_gateway_accessible,
        check_router_default_credentials,
        # WiFi Security
        check_wifi_encryption,
        check_wps_status,
        check_wifi_signal_strength,
        # Network Exposure
        check_remote_desktop,
        check_smb_exposure,
        check_network_discovery,
        check_firewall_profiles,
        # Privacy
        check_proxy_settings,
        check_hosts_file_tampering,
    ]

    results = []
    for check_fn in checks:
        try:
            result = check_fn()
            results.append(result)
        except Exception as exc:
            logger.error("Unexpected error in %s: %s", check_fn.__name__, exc)
            results.append(
                _make_result(check_fn.__name__, "Unknown", f"Unexpected error: {exc}")
            )

    # Sort by severity: Fail > Warning > Info > Pass > Unknown
    results.sort(key=lambda r: STATUS_ORDER.get(r.get("status", "Unknown"), 99))
    return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    for item in scan_router_security():
        print(f"[{item['status']:>7}] {item['check']}: {item['details']}")
        if item.get("fix_suggestion"):
            print(f"          FIX: {item['fix_suggestion']}")
        if item.get("fix_action"):
            print(f"          CMD: {item['fix_action']['command']}")
        print()
