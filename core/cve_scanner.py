"""
WinnyTool - CVE Scanner Module

Scans installed Windows software and OS version against a local CVE database,
checks for missing security patches (KBs), and returns actionable findings.
"""

import json
import os
import re
import csv
import subprocess
import logging
import webbrowser
import urllib.request
import urllib.parse
import datetime
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


def _save_cve_db(cves: List[Dict], db_path: str = _DEFAULT_DB_PATH) -> bool:
    """Write CVE entries back to the JSON database file."""
    data = {
        "version": "1.1.0",
        "last_updated": datetime.datetime.now().strftime("%Y-%m-%d"),
        "cves": cves,
    }
    try:
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        with open(db_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except (OSError, TypeError) as exc:
        logger.error("Failed to save CVE database: %s", exc)
        return False


def _validate_cve_entry(entry: Dict) -> Dict:
    """Validate and normalize a CVE entry to match expected schema.
    Returns the validated entry or raises ValueError."""
    cve_id = entry.get("cve_id", "").strip()
    if not cve_id or not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
        raise ValueError(f"Invalid CVE ID: {cve_id!r}")
    valid_severities = {"Critical", "High", "Medium", "Low"}
    severity = entry.get("severity", "Medium")
    if severity not in valid_severities:
        severity = "Medium"
    result = {
        "cve_id": cve_id,
        "severity": severity,
        "description": entry.get("description", ""),
        "affected_software": entry.get("affected_software", ""),
        "affected_versions": entry.get("affected_versions", []),
        "fix_description": entry.get("fix_description", ""),
        "kb_patch": entry.get("kb_patch") or None,
        "reference_url": entry.get("reference_url", ""),
    }
    # Preserve optional extended fields
    if entry.get("kb_patches"):
        result["kb_patches"] = entry["kb_patches"]
    if entry.get("patch_date"):
        result["patch_date"] = entry["patch_date"]
    return result


def get_cve_db_stats(db_path: str = _DEFAULT_DB_PATH) -> Dict[str, Any]:
    """Return stats about the current CVE database."""
    try:
        with open(db_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        cves = data.get("cves", [])
        severity_counts = {}
        for c in cves:
            sev = c.get("severity", "Unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        return {
            "total": len(cves),
            "last_updated": data.get("last_updated", "Unknown"),
            "version": data.get("version", "Unknown"),
            "by_severity": severity_counts,
        }
    except Exception:
        return {"total": 0, "last_updated": "Unknown", "version": "Unknown", "by_severity": {}}


def add_cve_manually(cve_dict: Dict, db_path: str = _DEFAULT_DB_PATH) -> str:
    """Validate and add a single CVE entry to the database.
    Returns the CVE ID on success, raises ValueError on validation failure."""
    validated = _validate_cve_entry(cve_dict)
    cves = _load_cve_db(db_path)
    # Deduplicate
    existing_ids = {c["cve_id"] for c in cves}
    if validated["cve_id"] in existing_ids:
        raise ValueError(f"{validated['cve_id']} already exists in database")
    cves.append(validated)
    if not _save_cve_db(cves, db_path):
        raise RuntimeError("Failed to write CVE database")
    return validated["cve_id"]


def import_cves_from_file(filepath: str, db_path: str = _DEFAULT_DB_PATH) -> Dict[str, int]:
    """Import CVEs from a JSON or CSV file.

    JSON format: either a list of CVE dicts, or {"cves": [...]}.
    CSV format: columns must include cve_id, severity, description,
                affected_software. Optional: affected_versions (semicolon-separated),
                fix_description, kb_patch, reference_url.

    Returns {"imported": N, "skipped": N, "errors": N}.
    """
    filepath = filepath.strip()
    ext = os.path.splitext(filepath)[1].lower()
    new_entries = []

    if ext == ".json":
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            raw_entries = data
        elif isinstance(data, dict):
            raw_entries = data.get("cves", data.get("vulnerabilities", []))
        else:
            raise ValueError("JSON file must contain a list or object with 'cves' key")
        for entry in raw_entries:
            new_entries.append(entry)

    elif ext == ".csv":
        with open(filepath, "r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                entry = {
                    "cve_id": row.get("cve_id", "").strip(),
                    "severity": row.get("severity", "Medium").strip(),
                    "description": row.get("description", "").strip(),
                    "affected_software": row.get("affected_software", "").strip(),
                    "affected_versions": [
                        v.strip() for v in row.get("affected_versions", "").split(";") if v.strip()
                    ],
                    "fix_description": row.get("fix_description", "").strip(),
                    "kb_patch": row.get("kb_patch", "").strip() or None,
                    "reference_url": row.get("reference_url", "").strip(),
                }
                new_entries.append(entry)
    else:
        raise ValueError(f"Unsupported file type: {ext}. Use .json or .csv")

    # Load existing, deduplicate, validate, merge
    cves = _load_cve_db(db_path)
    existing_ids = {c["cve_id"] for c in cves}
    stats = {"imported": 0, "skipped": 0, "errors": 0}

    for entry in new_entries:
        try:
            validated = _validate_cve_entry(entry)
            if validated["cve_id"] in existing_ids:
                stats["skipped"] += 1
                continue
            cves.append(validated)
            existing_ids.add(validated["cve_id"])
            stats["imported"] += 1
        except ValueError:
            stats["errors"] += 1

    if stats["imported"] > 0:
        _save_cve_db(cves, db_path)

    return stats


def _parse_cve5_record(data: Dict) -> Optional[Dict]:
    """Parse a single CVE 5.x record (from cve.org CVE-List download) into WinnyTool format.

    Handles the schema used by https://www.cve.org/downloads (CVE_RECORD with
    cveMetadata + containers.cna structure).
    Returns a validated CVE dict, or None if not parseable/not relevant.
    """
    try:
        # Must be a published CVE record
        metadata = data.get("cveMetadata", {})
        if metadata.get("state") != "PUBLISHED":
            return None

        cve_id = metadata.get("cveId", "")
        if not cve_id:
            return None

        cna = data.get("containers", {}).get("cna", {})
        if not cna:
            return None

        # Description - prefer English
        desc = ""
        for d in cna.get("descriptions", []):
            if d.get("lang", "").startswith("en"):
                desc = d.get("value", "")
                # Strip HTML tags if present
                desc = re.sub(r"<[^>]+>", "", desc).strip()
                break
        if not desc:
            descs = cna.get("descriptions", [])
            if descs:
                desc = re.sub(r"<[^>]+>", "", descs[0].get("value", "")).strip()

        # Affected products
        affected_products = []
        affected_versions = []
        for aff in cna.get("affected", []):
            vendor = aff.get("vendor", "Unknown")
            product = aff.get("product", "Unknown")
            affected_products.append(f"{vendor} {product}")
            for ver in aff.get("versions", []):
                if ver.get("status") == "affected":
                    v = ver.get("version", "")
                    if v:
                        affected_versions.append(v)

        affected_sw = ", ".join(affected_products) if affected_products else "Unknown"

        # Severity from metrics (CVSS v3.1 / v3.0 / v2)
        severity = "Medium"
        for metric_block in cna.get("metrics", []):
            for key in ["cvssV3_1", "cvssV3_0", "cvssV31", "cvssV30"]:
                cvss = metric_block.get(key, {})
                if cvss:
                    raw_sev = cvss.get("baseSeverity", "")
                    sev_map = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}
                    severity = sev_map.get(raw_sev.upper(), "Medium")
                    break

        # References
        ref_url = ""
        for ref in cna.get("references", []):
            url = ref.get("url", "")
            if url:
                ref_url = url
                break

        entry = {
            "cve_id": cve_id,
            "severity": severity,
            "description": desc[:500] if desc else f"Vulnerability in {affected_sw}",
            "affected_software": affected_sw,
            "affected_versions": affected_versions[:10],
            "fix_description": "Apply the latest security updates from the vendor.",
            "kb_patch": None,
            "reference_url": ref_url,
        }

        return _validate_cve_entry(entry)
    except Exception:
        return None


def import_cves_from_folder(
    folder_path: str,
    db_path: str = _DEFAULT_DB_PATH,
    filter_vendors: Optional[List[str]] = None,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> Dict[str, int]:
    """Recursively import CVE 5.x JSON files from a folder (e.g., cve.org CVE-List download).

    Walks the folder tree, reads each .json file, parses it as a CVE 5.x record,
    and merges new entries into the local database with deduplication.

    Args:
        folder_path: Root folder containing CVE JSON files (supports nested year/prefix structure).
        db_path: Path to the local CVE database.
        filter_vendors: Optional list of vendor keywords to filter by (e.g., ["microsoft", "windows"]).
                        If None, imports ALL CVEs found.
        progress_callback: Optional callback(processed, total) for progress updates.

    Returns {"imported": N, "skipped": N, "errors": N, "scanned": N}.
    """
    folder_path = os.path.normpath(folder_path)
    if not os.path.isdir(folder_path):
        raise ValueError(f"Not a valid folder: {folder_path}")

    # Collect all JSON file paths first
    json_files = []
    for root, _dirs, files in os.walk(folder_path):
        for fname in files:
            if fname.lower().endswith(".json") and fname.upper().startswith("CVE-"):
                json_files.append(os.path.join(root, fname))

    total = len(json_files)
    stats = {"scanned": total, "imported": 0, "skipped": 0, "errors": 0}

    if total == 0:
        return stats

    # Load existing DB
    cves = _load_cve_db(db_path)
    existing_ids = {c["cve_id"] for c in cves}

    # Normalize vendor filter
    vendor_filters = None
    if filter_vendors:
        vendor_filters = [v.lower() for v in filter_vendors]

    for idx, fpath in enumerate(json_files):
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)

            parsed = _parse_cve5_record(data)
            if parsed is None:
                stats["errors"] += 1
                continue

            # Apply vendor filter if specified
            if vendor_filters:
                sw_lower = parsed.get("affected_software", "").lower()
                if not any(v in sw_lower for v in vendor_filters):
                    stats["skipped"] += 1
                    continue

            if parsed["cve_id"] in existing_ids:
                stats["skipped"] += 1
                continue

            cves.append(parsed)
            existing_ids.add(parsed["cve_id"])
            stats["imported"] += 1

        except (json.JSONDecodeError, OSError):
            stats["errors"] += 1

        # Progress callback every 100 files
        if progress_callback and (idx + 1) % 100 == 0:
            progress_callback(idx + 1, total)

    if progress_callback:
        progress_callback(total, total)

    if stats["imported"] > 0:
        _save_cve_db(cves, db_path)

    return stats


def fetch_nvd_cves(
    keyword: str = "microsoft windows",
    max_results: int = 50,
    db_path: str = _DEFAULT_DB_PATH,
) -> Dict[str, int]:
    """Fetch CVEs from the NVD API 2.0 and merge into local database.

    Args:
        keyword: Search keyword for NVD API.
        max_results: Maximum number of CVEs to fetch (capped at 200).
        db_path: Path to local CVE database.

    Returns {"imported": N, "skipped": N, "errors": N, "fetched": N}.
    """
    max_results = min(max_results, 200)
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": str(max_results),
    }
    url = f"{base_url}?{urllib.parse.urlencode(params)}"

    logger.info("Fetching CVEs from NVD: %s", url)
    req = urllib.request.Request(url, headers={"User-Agent": "WinnyTool/1.0"})

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        logger.error("NVD API request failed: %s", exc)
        raise RuntimeError(f"Failed to fetch from NVD: {exc}")

    vulnerabilities = data.get("vulnerabilities", [])
    stats = {"fetched": len(vulnerabilities), "imported": 0, "skipped": 0, "errors": 0}

    cves = _load_cve_db(db_path)
    existing_ids = {c["cve_id"] for c in cves}

    severity_map = {
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
    }

    for vuln_wrapper in vulnerabilities:
        try:
            cve_data = vuln_wrapper.get("cve", {})
            cve_id = cve_data.get("id", "")
            if not cve_id or cve_id in existing_ids:
                stats["skipped"] += 1
                continue

            # Extract description (English preferred)
            descriptions = cve_data.get("descriptions", [])
            desc = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            if not desc and descriptions:
                desc = descriptions[0].get("value", "")

            # Extract severity from CVSS metrics
            severity = "Medium"
            metrics = cve_data.get("metrics", {})
            for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                metric_list = metrics.get(metric_key, [])
                if metric_list:
                    raw_sev = metric_list[0].get("cvssData", {}).get("baseSeverity", "")
                    severity = severity_map.get(raw_sev.upper(), "Medium")
                    break

            # Extract references
            refs = cve_data.get("references", [])
            ref_url = refs[0].get("url", "") if refs else ""

            # Extract affected software from configurations
            affected_sw = "Windows"
            configurations = cve_data.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        criteria = match.get("criteria", "")
                        if "microsoft" in criteria.lower():
                            # Extract product name from CPE
                            parts = criteria.split(":")
                            if len(parts) >= 5:
                                vendor = parts[3]
                                product = parts[4].replace("_", " ").title()
                                affected_sw = f"{vendor.title()} {product}"
                            break

            entry = {
                "cve_id": cve_id,
                "severity": severity,
                "description": desc[:500],
                "affected_software": affected_sw,
                "affected_versions": [],
                "fix_description": "Apply the latest security updates from Microsoft.",
                "kb_patch": None,
                "reference_url": ref_url,
            }

            validated = _validate_cve_entry(entry)
            cves.append(validated)
            existing_ids.add(cve_id)
            stats["imported"] += 1
        except Exception as exc:
            logger.debug("Failed to parse NVD entry: %s", exc)
            stats["errors"] += 1

    if stats["imported"] > 0:
        _save_cve_db(cves, db_path)

    return stats


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


def _detect_os_type() -> Dict[str, str]:
    """Detect whether the system is Windows 10 or Windows 11, plus the version (e.g., 23H2).

    Returns a dict with keys:
        'os_family': 'Windows 10', 'Windows 11', or 'Unknown'
        'os_version': e.g., '23H2', '24H2', '22H2', '1507', or ''
        'build': e.g., '22631', or ''
    """
    result = {"os_family": "Unknown", "os_version": "", "build": ""}
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        ) as key:
            product_name = winreg.QueryValueEx(key, "ProductName")[0]
            try:
                display_ver = winreg.QueryValueEx(key, "DisplayVersion")[0]
            except OSError:
                display_ver = ""
            try:
                build = winreg.QueryValueEx(key, "CurrentBuildNumber")[0]
            except OSError:
                build = ""

            result["build"] = str(build)
            result["os_version"] = display_ver

            # Windows 11 builds start at 22000+
            # Windows 10 builds are below 22000
            build_int = int(build) if build.isdigit() else 0
            if "windows 11" in product_name.lower() or build_int >= 22000:
                result["os_family"] = "Windows 11"
            elif "windows 10" in product_name.lower() or (10240 <= build_int < 22000):
                result["os_family"] = "Windows 10"
            elif "windows server" in product_name.lower():
                result["os_family"] = "Windows Server"
            else:
                result["os_family"] = product_name
    except Exception as exc:
        logger.warning("Could not detect OS type from registry: %s", exc)
    return result


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


def _get_last_update_date():
    """Get the date of the most recent installed Windows update.

    Returns a datetime.date or None.
    """
    from datetime import datetime as _dt
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-HotFix | Sort-Object InstalledOn -Descending | "
             "Select-Object -First 1 -ExpandProperty InstalledOn"],
            capture_output=True, text=True, timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode == 0 and result.stdout.strip():
            date_str = result.stdout.strip().split()[0]
            # Try common formats
            for fmt in ("%m/%d/%Y", "%Y-%m-%d", "%d/%m/%Y", "%m-%d-%Y"):
                try:
                    return _dt.strptime(date_str, fmt).date()
                except ValueError:
                    continue
    except Exception as exc:
        logger.debug("_get_last_update_date failed: %s", exc)
    return None


# Map fix_description month references to approximate patch dates
_PATCH_MONTH_MAP = {
    "january": 1, "february": 2, "march": 3, "april": 4,
    "may": 5, "june": 6, "july": 7, "august": 8,
    "september": 9, "october": 10, "november": 11, "december": 12,
}


def _extract_patch_date(fix_description: str):
    """Try to extract a (year, month) from fix_description like 'Apply the March 2025 Patch Tuesday update.'

    Returns a datetime.date (set to last day of that month) or None.
    """
    from datetime import date as _date
    if not fix_description:
        return None
    desc_lower = fix_description.lower()
    for month_name, month_num in _PATCH_MONTH_MAP.items():
        if month_name in desc_lower:
            # Look for a 4-digit year nearby
            match = re.search(r"(\d{4})", fix_description)
            if match:
                year = int(match.group(1))
                if 2020 <= year <= 2030:
                    # Use the 15th of the month as the patch date
                    try:
                        return _date(year, month_num, 15)
                    except ValueError:
                        pass
    return None


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


def _make_fix_action(reference_url: str, kb_patch: Optional[str] = None, local_fix: Optional[Dict] = None) -> Dict:
    """Returns a dict with 'view' and 'apply' action dicts.

    'view'  - opens the MSRC advisory / reference URL in a browser.
    'apply' - runs a local remediation command (install patch, disable
              service, registry tweak, etc.).
    """
    result: Dict[str, Any] = {}

    # View advisory button
    if reference_url:
        result["view"] = {"label": "View Advisory", "command": reference_url}
    elif kb_patch:
        # Fallback to Update Catalog only if no advisory URL
        catalog_url = f"https://www.catalog.update.microsoft.com/Search.aspx?q={kb_patch}"
        result["view"] = {"label": "View Advisory", "command": catalog_url}

    # Download KB button - direct link to Microsoft Update Catalog
    if kb_patch:
        catalog_url = f"https://www.catalog.update.microsoft.com/Search.aspx?q={kb_patch}"
        result["download"] = {"label": f"Download {kb_patch}", "command": catalog_url}

    # Apply fix button - local remediation
    if local_fix:
        fix_type = local_fix.get("type", "")
        fix_cmd = local_fix.get("command", "")
        fix_desc = local_fix.get("description", "Apply fix")
        result["apply"] = {
            "label": "Apply Fix",
            "type": fix_type,
            "command": fix_cmd,
            "description": fix_desc,
        }
    elif kb_patch:
        # Default: try to install via Windows Update
        result["apply"] = {
            "label": "Open Windows Update",
            "type": "windows_update",
            "command": 'powershell -NoProfile -Command "Start-Process ms-settings:windowsupdate-action"',
            "description": f"Open Windows Update to install {kb_patch}",
        }

    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _resolve_kb_for_os(entry: Dict, os_info: Dict[str, str]) -> List[str]:
    """Return a list of KB patch IDs relevant to the detected OS.

    Checks the os-specific ``kb_patches`` dict first, then falls back to the
    legacy ``kb_patch`` string.  Returns all applicable KBs so any match counts.
    """
    kbs: List[str] = []
    kb_patches = entry.get("kb_patches", {})
    os_family = os_info.get("os_family", "")
    os_version = os_info.get("os_version", "")  # e.g. "23H2", "24H2"

    if kb_patches and os_family:
        # Try most-specific key first: "Windows 11 23H2", then "Windows 11", then "Windows 10"
        lookup_keys = []
        if os_version:
            lookup_keys.append(f"{os_family} {os_version}")
        lookup_keys.append(os_family)

        for key in lookup_keys:
            if key in kb_patches:
                kbs.append(kb_patches[key].upper())
                break

    # Always include the legacy kb_patch as a fallback
    legacy = entry.get("kb_patch")
    if legacy and legacy.upper() not in kbs:
        kbs.append(legacy.upper())

    return kbs


def _os_is_affected(entry: Dict, os_info: Dict[str, str]) -> bool:
    """Check whether the CVE's affected_versions list includes the detected OS.

    If affected_versions contains generic entries like 'Windows 10' or 'Windows 11',
    match against os_info['os_family'].  If it contains specific versions like
    'Windows 10 version 1507', require an exact match against os_family + os_version.

    Returns True if the CVE applies to this OS, False if it definitely does not.
    """
    affected_versions = entry.get("affected_versions", [])
    if not affected_versions:
        return True  # No version constraint -- assume affected

    os_family = os_info.get("os_family", "").lower()  # e.g. "windows 11"
    os_version = os_info.get("os_version", "").lower()  # e.g. "23h2"

    for av in affected_versions:
        av_lower = av.lower().strip()
        # Exact match for specific versions like "Windows 10 version 1507"
        if "version" in av_lower:
            # Build the full string for comparison
            full_os = f"{os_family} version {os_version}" if os_version else os_family
            if av_lower == full_os or av_lower in full_os:
                return True
            continue
        # Generic match: "Windows 10", "Windows 11", "Windows Server 2022"
        if av_lower == os_family:
            return True
        if av_lower in os_family or os_family in av_lower:
            return True
    return False


def _get_patch_date(entry: Dict) -> Optional[datetime.date]:
    """Get the patch date for a CVE entry.

    Prefers the explicit ``patch_date`` field (ISO format string), falls back
    to parsing the fix_description text.
    """
    # Use explicit patch_date field if present
    patch_date_str = entry.get("patch_date")
    if patch_date_str:
        try:
            return datetime.datetime.strptime(patch_date_str, "%Y-%m-%d").date()
        except (ValueError, TypeError):
            pass

    # Fall back to extracting from fix_description
    return _extract_patch_date(entry.get("fix_description", ""))


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

    os_info = _detect_os_type()
    logger.info(
        "OS family: %s, version: %s, build: %s",
        os_info["os_family"], os_info["os_version"], os_info["build"],
    )

    software_list = _get_installed_software()
    logger.info("Found %d installed software entries.", len(software_list))

    installed_kbs = _get_installed_kbs()
    logger.info("Found %d installed KBs.", len(installed_kbs))

    last_update_date = _get_last_update_date()
    logger.info("Last Windows update date: %s", last_update_date)

    results: List[Dict[str, Any]] = []

    for entry in cve_entries:
        cve_id = entry.get("cve_id", "UNKNOWN")
        affected_sw = entry.get("affected_software", "")
        reference_url = entry.get("reference_url", "")

        # Step 1: Does the affected software/component match anything installed?
        if not _software_matches(affected_sw, software_list, os_version):
            continue

        # Step 2: Check if the CVE applies to this OS family/version
        # (e.g., skip Win10-only CVEs on Win11 and vice versa)
        if not _os_is_affected(entry, os_info):
            logger.debug(
                "CVE %s skipped: does not affect %s %s",
                cve_id, os_info["os_family"], os_info["os_version"],
            )
            continue

        # Step 3: Legacy version check (for non-OS software version matching)
        if not _version_affected(entry, software_list, os_version):
            continue

        # Step 4: Check if any applicable KB patch is installed
        # Use OS-specific KB lookup, then fall back to legacy kb_patch
        applicable_kbs = _resolve_kb_for_os(entry, os_info)
        kb_installed = False
        for kb in applicable_kbs:
            if kb in installed_kbs:
                logger.debug("CVE %s mitigated by installed patch %s", cve_id, kb)
                kb_installed = True
                break
        if kb_installed:
            continue

        # Step 5: Check if a cumulative update newer than the CVE patch date
        # is installed (cumulative updates supersede individual KBs --
        # if the latest installed update is newer, the fix is included)
        patch_date = _get_patch_date(entry)
        if patch_date and last_update_date and last_update_date >= patch_date:
            logger.debug(
                "CVE %s likely mitigated: last update %s >= patch date %s",
                cve_id, last_update_date, patch_date,
            )
            continue

        # Determine the best KB to recommend for this OS
        display_kb = applicable_kbs[0] if applicable_kbs else entry.get("kb_patch")

        # Build the fix description
        fix_text = entry.get("fix_description", "No fix information available.")
        if display_kb:
            fix_text += f" (Install {display_kb})"

        results.append({
            "cve_id": cve_id,
            "severity": entry.get("severity", "Unknown"),
            "description": entry.get("description", ""),
            "affected_software": affected_sw,
            "fix": fix_text,
            "fix_action": _make_fix_action(reference_url, display_kb, entry.get("local_fix")),
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
