# WinnyTool

A Windows system diagnostic and optimization tool with a dark-themed GUI. WinnyTool scans for vulnerabilities, analyzes BSODs, detects performance bottlenecks, and provides one-click fixes.

![Version](https://img.shields.io/badge/Version-1.2.0-orange)
![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D6)
![License](https://img.shields.io/badge/License-GPL%20v3-green)

---

## Features

### CVE Scanner
- Local database of **36 real Windows CVEs** (2024-2026) focused on recent and actively exploited vulnerabilities
- Checks installed software and OS patches against known vulnerabilities
- **Dual action buttons** per CVE: "View CVE" links to MSRC advisory, "Apply Fix" runs the remediation locally (Windows Update, disable service, registry mitigation, etc.)
- Links to Microsoft Security Response Center for full advisory details
- **CVE Feed Import** - Pull new CVEs from NVD (NIST), CISA KEV, or custom JSON feeds
- **Manual CVE Entry** - Add custom CVEs through the GUI with full metadata (severity, affected software, fix info)
- Automatic deduplication when importing from multiple sources

### System Hardening (NEW)
Three-tier hardening profiles with full transparency on what each setting does:

- **Basic** (8 checks) - Safe for all users. Firewall, Defender real-time protection, UAC, SMBv1 disable, auto-updates, screen lock, guest account disable, Remote Desktop
- **Moderate** (10 checks) - For security-conscious users. Adds LLMNR/NetBIOS disable, Credential Guard, WDigest protection, PowerShell execution policy, audit logging, autorun disable, password policies, BitLocker
- **Aggressive** (10 checks) - Maximum security, may break some workflows. Windows Script Host disable, Office macro restrictions, LSA protection, NTLM disable, ASR rules, named pipe restrictions, cached credential limits, NTLMv2 enforcement

Each setting shows:
- Current system status (Enabled/Disabled)
- **Pros** - Security benefits of enabling
- **Cons** - What might break or become inconvenient
- One-click **Apply Fix** button with confirmation

### BSOD Analyzer
- Reads the last 10 Blue Screen of Death events from Windows Event Log
- Maps 33 known stop codes to human-readable names, common causes, and fix suggestions
- Checks for minidump files in `C:\Windows\Minidump\`
- Clickable fix buttons (Run SFC, DISM Repair, Check Disk, Update Drivers, etc.)

### Performance Optimizer
- 13 system checks: power plan, visual effects, background apps, search indexing, Superfetch, page file, temp files, Game Mode, transparency effects, tips/suggestions, and more
- Flags settings that slow down your system with impact ratings (High/Medium/Low)

### Startup Manager
- Scans registry Run/RunOnce keys, Startup folder, and scheduled tasks
- Impact estimation based on known heavy applications
- Disable/enable startup items directly from the GUI

### Disk Health
- SMART status for all physical drives
- TRIM status for SSDs, fragmentation analysis for HDDs
- Temp file cleanup and reclaimable space estimation
- Large file finder

### Network Diagnostics
- DNS configuration check with recommendations (Cloudflare, Google DNS)
- Latency testing to multiple endpoints
- Firewall status, proxy settings, hosts file inspection
- TCP auto-tuning analysis

### Windows Update Status
- Patch history with last update date tracking
- Flags systems overdue for updates (>30 days)
- Pending update and reboot detection
- OS build EOL checking

### System Info Dashboard
- CPU, RAM, GPU, disk drives, uptime, and antivirus at a glance

### UI Scaling (NEW)
- **Preset modes**: Compact (80%), Normal (100%), Large (140%)
- **Fine-tune slider**: Adjust from 80% to 200% for any display
- Settings persist across sessions via `data/settings.json`
- Scales all fonts, sidebar width, and widget padding proportionally

### Additional Features
- **GitHub Auto-Updater** - Checks for new releases on launch
- **HTML Report Export** - Generate styled reports of all findings
- **Scan History** - SQLite-backed history tracking with trend data
- **Full Scan Mode** - Run all diagnostics with a single click

---

## CVE Database Management

WinnyTool ships with 36 built-in CVEs (2024-2026) and supports multiple ways to expand the database:

### 1. NVD Feed (NIST)
Pull CVEs from the National Vulnerability Database filtered to Windows-related entries. Requires a free NVD API key from https://nvd.nist.gov/developers/request-an-api-key.

### 2. CISA KEV Feed
Import the Known Exploited Vulnerabilities catalog - actively exploited CVEs that CISA mandates federal agencies to patch.

### 3. Manual Entry
Add custom CVEs directly through the GUI with fields for:
- CVE ID, severity (Critical/High/Medium/Low)
- Description and affected software/versions
- Fix description, KB patch number, and reference URL

### 4. Custom JSON Import
Import any JSON file matching the WinnyTool schema:
```json
[
  {
    "cve_id": "CVE-2024-XXXXX",
    "severity": "High",
    "description": "Description here",
    "affected_software": ["Software Name"],
    "affected_versions": ["1.0", "2.0"],
    "fix_description": "Update to latest version",
    "kb_patch": "KB1234567",
    "reference_url": "https://msrc.microsoft.com/..."
  }
]
```

All imports are deduplicated automatically - existing CVE IDs are skipped.

---

## Screenshot

The GUI features a dark theme with sidebar navigation. Every finding includes clickable **"Apply Fix"** buttons that confirm before executing.

---

## Requirements

- **Python 3.10+**
- **Windows 10/11**
- No external dependencies - uses only Python standard library (tkinter, sqlite3, subprocess, winreg, etc.)

---

## Installation

```bash
git clone https://github.com/AES256Afro/WinnyTool.git
cd WinnyTool
python winnytool.py
```

For full functionality, run as Administrator:
```bash
# Right-click Command Prompt -> Run as Administrator
python winnytool.py
```

---

## Project Structure

```
WinnyTool/
├── winnytool.py              # Main GUI application
├── requirements.txt          # Dependency info
├── LICENSE                   # GPL v3
├── core/
│   ├── cve_scanner.py        # CVE database matching + feed import
│   ├── hardening.py          # 3-tier system hardening (28 checks)
│   ├── bsod_analyzer.py      # BSOD event log parsing
│   ├── performance.py        # Performance optimization checks
│   ├── startup_mgr.py        # Startup item management
│   ├── disk_health.py        # Disk diagnostics
│   ├── network_diag.py       # Network diagnostics
│   ├── winupdate.py          # Windows Update status
│   ├── sysinfo.py            # System information collection
│   ├── updater.py            # GitHub release auto-updater
│   ├── reporter.py           # HTML/text report generation
│   └── history.py            # SQLite scan history
└── data/
    ├── cve_db.json           # CVE database (36 entries, 2024-2026)
    └── settings.json         # User preferences (UI scale, etc.)
```

---

## Compatibility

- Uses **PowerShell CIM instances** instead of WMIC, fully compatible with Windows 11 builds where WMIC has been removed
- Tested on Windows 11 Build 26200

---

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

---

## Changelog

### v1.2.0 (2026-03-21)
**New Features:**
- **UI Scaling** - Settings page with Compact/Normal/Large presets and a fine-tune slider (80%-200%). Persists across sessions
- **Focused CVE Database** - Stripped pre-2024 entries, now ships with 36 CVEs covering 2024-2026 only
- **Dual CVE Action Buttons** - Each CVE now has two buttons: "View CVE" (opens MSRC advisory) and "Apply Fix" (runs local remediation — installs KB patches, disables vulnerable services, applies registry mitigations)
- **Folder/File CVE Import** - Drag-and-drop or browse to import entire folders of CVE JSON files (compatible with CVE-List repository format)

**Improvements:**
- CVE fix actions now execute locally instead of just linking to Microsoft Update Catalog
- Local fixes include: `wusa.exe` KB installation, service disable via `sc`, registry mitigations, and PowerShell commands
- All fix actions require user confirmation before executing

### v1.1.0 (2026-03-21)
**New Features:**
- **System Hardening** - 3-tier hardening page (Basic/Moderate/Aggressive) with 28 security checks, pros/cons for each setting, and one-click apply
- **CVE Feed Import** - Pull CVEs from NVD (NIST) and CISA KEV feeds directly in the GUI
- **Manual CVE Entry** - Add custom CVEs through a form with full metadata fields
- **Custom JSON Import** - Import CVE databases from any JSON file matching the WinnyTool schema
- Automatic CVE deduplication across all import sources

**Improvements:**
- CVE scanner now supports version-aware matching and KB patch cross-referencing
- Hardening checks read live system state via registry and system commands
- All new GUI pages follow the existing dark theme with sidebar navigation

### v1.0.0 (2026-03-21)
- Initial release
- CVE Scanner with 30 built-in CVEs (2017-2025)
- BSOD Analyzer with 33 stop codes
- Performance Optimizer with 13 system checks
- Startup Manager with disable/enable support
- Disk Health, Network Diagnostics, Windows Update status
- System Info Dashboard
- HTML Report Export, Scan History, GitHub Auto-Updater
- Dark-themed GUI with clickable fix buttons
