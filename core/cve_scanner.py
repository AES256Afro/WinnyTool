"""
WinnyTool - CVE Scanner Module

Scans installed Windows software and OS version against a local CVE database,
checks for missing security patches (KBs), and returns actionable findings.
"""

import json
import os
import re
import subprocess
import logging
import webbrowser
import functools
from typing import List, Dict, Optional, Callable, Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_DB_PATH = os.path.normpath(os.path.join(_MODULE_DIR, "..", "data", "cve_db.json"))


# ---------------------------------------------------------------------------
# CVE Database helpers
# ---------------------------------------------------------------------------

def _load_cve_db(db_path: str = _DEFAULT_DB_PATH) -> List[Dict]:
    """Load CVE entries from the local JSON database."""
    try:
        with open(db_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("cves", [])
    except FileNotFoundError:
        logger.error("CVE database not found at %s", db_path)
        return []
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse CVE database: %s", exc)
        return []


def update_cve_db(db_path: str = _DEFAULT_DB_PATH) -> bool:
    """Placeholder for CVE database refresh logic.

    In a production implementation this would:
    - Fetch the latest CVE feed from NVD / MSRC APIs
    - Merge new entries into the local JSON file
    - Validate the schema before writing

    Returns True on success.
    """
    logger.info("update_cve_db called for %s -- not yet implemented", db_path)
    # TODO: implement remote fetch & merge
    return False


# ---------------------------------------------------------------------------
# System information gathering
# ---------------------------------------------------------------------------

def _get_os_version() -> str:
    """Return a human-readable Windows version string."""
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        ) as key:
            product_name = winreg.QueryValueEx(key, "ProductName")[0]
            # DisplayVersion (e.g., "23H2") available on Win10 2004+
            try:
                display_ver = winreg.QueryValueEx(key, "DisplayVersion")[0]
            except OSError:
                display_ver = ""
            build = winreg.QueryValueEx(key, "CurrentBuildNumber")[0]
            version_str = f"{product_name} {display_ver} (Build {build})".strip()
            return version_str
    except Exception as exc:
        logger.warning("Could not read OS version from registry: %s", exc)
    # Fallback
    try:
        result = subprocess.run(
            ["cmd", "/c", "ver"],
            capture_output=True, text=True, timeout=10,
        )
        return result.stdout.strip()
    except Exception:
        return "Unknown Windows Version"


def _get_installed_software() -> List[Dict[str, str]]:
    """Enumerate installed software from the Windows registry.

    Reads both 64-bit and 32-bit (Wow6432Node) uninstall keys.
    Returns a list of dicts with 'name' and 'version' keys.
    """
    software_list: List[Dict[str, str]] = []
    registry_paths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ]

    try:
        import winreg
    except ImportError:
        logger.error("winreg module not available -- not running on Windows?")
        return software_list

    for reg_path in registry_paths:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                subkey_count = winreg.QueryInfoKey(key)[0]
                for i in range(subkey_count):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name) as subkey:
                            try:
                                name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                            except OSError:
                                continue  # skip entries without a display name
                            try:
                                version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                            except OSError:
                                version = ""
                            software_list.append({
                                "name": str(name),
                                "version": str(version),
                            })
                    except OSError:
                        continue
        except OSError:
            logger.debug("Registry path not found: %s", reg_path)

    return software_list


def _get_installed_kbs() -> set:
    """Retrieve the set of installed Windows KB patch IDs.

    Tries ``wmic qfe`` first, falls back to ``systeminfo``.
    Returns a set of strings like {'KB5004945', 'KB5005565', ...}.
    """
    kbs: set = set()

    # Approach 1: PowerShell Get-HotFix (works on modern Windows 11)
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-HotFix | Select-Object -ExpandProperty HotFixID"],
            capture_output=True, text=True, timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if re.match(r"^KB\d+", line, re.IGNORECASE):
                    kbs.add(line.upper())
            if kbs:
                return kbs
    except Exception as exc:
        logger.debug("Get-HotFix failed: %s", exc)

    # Approach 2: systeminfo
    try:
        result = subprocess.run(
            ["systeminfo"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0:
            for match in re.finditer(r"(KB\d+)", result.stdout, re.IGNORECASE):
                kbs.add(match.group(1).upper())
    except Exception as exc:
        logger.debug("systeminfo failed: %s", exc)

    return kbs


# ---------------------------------------------------------------------------
# Matching logic
# ---------------------------------------------------------------------------

def _normalize(text: str) -> str:
    """Lower-case and collapse whitespace for fuzzy comparison."""
    return re.sub(r"\s+", " ", text.lower().strip())


def _software_matches(affected: str, software_list: List[Dict[str, str]], os_version: str) -> bool:
    """Return True if the affected_software string matches any installed software or the OS version."""
    affected_norm = _normalize(affected)

    # Check against OS version string
    if affected_norm and affected_norm in _normalize(os_version):
        return True

    # Check against installed software names
    for sw in software_list:
        sw_name_norm = _normalize(sw["name"])
        if affected_norm in sw_name_norm or sw_name_norm in affected_norm:
            return True

    # Broad keyword matching for OS-level components
    os_lower = _normalize(os_version)
    os_component_keywords = [
        "windows smb", "windows print spooler", "mshtml",
        "microsoft support diagnostic tool", "windows cryptoapi",
        "windows dns server", "windows lsa", "windows http",
        "windows graphics", "windows kernel", "windows clfs",
        "windows ole", "windows smartscreen", "windows storage",
        "windows iis", "windows server", "windows",
    ]
    if affected_norm in os_component_keywords:
        # These are OS-level components -- check if running a matching Windows version
        for ver_keyword in ["windows 10", "windows 11", "windows server"]:
            if ver_keyword in os_lower:
                return True

    return False


def _version_affected(cve_entry: Dict, software_list: List[Dict[str, str]], os_version: str) -> bool:
    """Check if any affected_versions token appears in the OS version or installed software versions."""
    affected_versions = cve_entry.get("affected_versions", [])
    if not affected_versions:
        return True  # no version constraint means assume affected

    os_lower = _normalize(os_version)
    for av in affected_versions:
        av_norm = _normalize(av)
        if av_norm in os_lower:
            return True
        for sw in software_list:
            if av_norm in _normalize(sw["name"]) or av_norm in _normalize(sw.get("version", "")):
                return True
    return False


def _make_fix_action(reference_url: str, kb_patch: Optional[str] = None) -> Callable:
    """Create a callable that opens the reference URL or Microsoft Update Catalog for the KB."""
    def _open_url(url: str = reference_url) -> None:
        webbrowser.open(url)

    if kb_patch:
        catalog_url = f"https://www.catalog.update.microsoft.com/Search.aspx?q={kb_patch}"
        def _open_kb(url: str = catalog_url, ref: str = reference_url) -> None:
            webbrowser.open(url)
        return _open_kb

    return _open_url


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_cves(db_path: str = _DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Run a CVE scan and return a list of findings.

    Each finding dict contains:
        cve_id            - CVE identifier (str)
        severity          - Critical / High / Medium / Low (str)
        description       - Human-readable description (str)
        affected_software - What component is affected (str)
        fix               - Recommended remediation steps (str)
        fix_action        - Callable that opens the relevant fix URL, or None
    """
    logger.info("Starting CVE scan ...")
    cve_entries = _load_cve_db(db_path)
    if not cve_entries:
        logger.warning("No CVE entries loaded -- returning empty results.")
        return []

    os_version = _get_os_version()
    logger.info("Detected OS: %s", os_version)

    software_list = _get_installed_software()
    logger.info("Found %d installed software entries.", len(software_list))

    installed_kbs = _get_installed_kbs()
    logger.info("Found %d installed KBs.", len(installed_kbs))

    results: List[Dict[str, Any]] = []

    for entry in cve_entries:
        cve_id = entry.get("cve_id", "UNKNOWN")
        affected_sw = entry.get("affected_software", "")
        kb_patch = entry.get("kb_patch")
        reference_url = entry.get("reference_url", "")

        # Step 1: Does the affected software/component match anything installed?
        if not _software_matches(affected_sw, software_list, os_version):
            continue

        # Step 2: Version check
        if not _version_affected(entry, software_list, os_version):
            continue

        # Step 3: If there is a KB patch, check if it is already installed
        if kb_patch and kb_patch.upper() in installed_kbs:
            logger.debug("CVE %s mitigated by installed patch %s", cve_id, kb_patch)
            continue

        # Build the fix description
        fix_text = entry.get("fix_description", "No fix information available.")
        if kb_patch:
            fix_text += f" (Install {kb_patch})"

        results.append({
            "cve_id": cve_id,
            "severity": entry.get("severity", "Unknown"),
            "description": entry.get("description", ""),
            "affected_software": affected_sw,
            "fix": fix_text,
            "fix_action": _make_fix_action(reference_url, kb_patch),
        })

    # Sort by severity: Critical first, then High, Medium, Low
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
    results.sort(key=lambda r: severity_order.get(r["severity"], 4))

    logger.info("CVE scan complete. %d potential vulnerabilities found.", len(results))
    return results


# ---------------------------------------------------------------------------
# Convenience: run as standalone script
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    findings = scan_cves()
    if not findings:
        print("No known CVE vulnerabilities detected.")
    else:
        print(f"\n{'='*80}")
        print(f" {len(findings)} potential vulnerabilities found")
        print(f"{'='*80}\n")
        for f in findings:
            print(f"[{f['severity'].upper()}] {f['cve_id']}")
            print(f"  Affected: {f['affected_software']}")
            print(f"  {f['description']}")
            print(f"  Fix: {f['fix']}")
            print()
