# WinnyTool

A Windows system diagnostic and optimization tool with a dark-themed GUI. WinnyTool scans for vulnerabilities, analyzes BSODs, detects performance bottlenecks, and provides one-click fixes.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%2011-0078D6)
![License](https://img.shields.io/badge/License-GPL%20v3-green)

---

## Features

### CVE Scanner
- Local database of 30 real Windows CVEs (2017-2025) including PrintNightmare, Zerologon, Follina, Log4Shell, and more
- Checks installed software and OS patches against known vulnerabilities
- Links to Microsoft Update Catalog for remediation

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

### Additional Features
- **GitHub Auto-Updater** - Checks for new releases on launch
- **HTML Report Export** - Generate styled reports of all findings
- **Scan History** - SQLite-backed history tracking with trend data
- **Full Scan Mode** - Run all diagnostics with a single click

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
│   ├── cve_scanner.py        # CVE database matching
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
    └── cve_db.json           # CVE database (30 entries)
```

---

## Compatibility

- Uses **PowerShell CIM instances** instead of WMIC, fully compatible with Windows 11 builds where WMIC has been removed
- Tested on Windows 11 Build 26200

---

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
