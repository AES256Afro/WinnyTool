"""
WinnyTool - Report Exporter
Generates styled HTML or plain-text diagnostic reports from scan results.
Uses only stdlib modules (html, datetime, os, platform).
"""

import html
import os
import platform
from datetime import datetime
from typing import Optional


# Severity color mapping for HTML reports
SEVERITY_COLORS = {
    "critical": "#dc3545",
    "high": "#fd7e14",
    "medium": "#ffc107",
    "low": "#28a745",
    "info": "#17a2b8",
}

# All expected scan result sections
SECTION_LABELS = {
    "system_info": "System Information",
    "cve_results": "CVE / Vulnerability Scan",
    "bsod_results": "BSOD Analysis",
    "performance_results": "Performance Analysis",
    "startup_items": "Startup Items",
    "disk_results": "Disk Health",
    "network_results": "Network Diagnostics",
    "update_results": "Windows Update Status",
}


def _get_output_dir() -> str:
    """Return the Desktop path if it exists, otherwise Documents, otherwise CWD."""
    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    if os.path.isdir(desktop):
        return desktop
    documents = os.path.join(os.path.expanduser("~"), "Documents")
    if os.path.isdir(documents):
        return documents
    return os.getcwd()


def _severity_badge_html(severity: str) -> str:
    """Return an inline-styled HTML span for a severity level."""
    sev = severity.lower() if severity else "info"
    color = SEVERITY_COLORS.get(sev, "#6c757d")
    return (
        f'<span style="background-color:{color};color:#fff;padding:2px 8px;'
        f'border-radius:4px;font-size:0.85em;font-weight:bold;">'
        f'{html.escape(severity.upper())}</span>'
    )


def _build_html_header(timestamp: str) -> str:
    """Build the HTML document header with embedded CSS."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WinnyTool Diagnostic Report</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background: #f5f5f5; color: #333; line-height: 1.6;
        padding: 20px;
    }}
    .container {{ max-width: 960px; margin: 0 auto; }}
    .header {{
        background: linear-gradient(135deg, #1a1a2e, #16213e);
        color: #fff; padding: 30px; border-radius: 10px;
        margin-bottom: 24px; text-align: center;
    }}
    .header h1 {{ font-size: 2em; margin-bottom: 6px; }}
    .header p {{ opacity: 0.8; font-size: 0.95em; }}
    .section {{
        background: #fff; border-radius: 8px; padding: 20px;
        margin-bottom: 16px; box-shadow: 0 2px 6px rgba(0,0,0,0.08);
    }}
    .section h2 {{
        font-size: 1.3em; color: #1a1a2e; border-bottom: 2px solid #eee;
        padding-bottom: 8px; margin-bottom: 14px;
    }}
    table {{
        width: 100%; border-collapse: collapse; font-size: 0.9em;
    }}
    th {{
        background: #1a1a2e; color: #fff; padding: 10px 12px;
        text-align: left;
    }}
    td {{ padding: 8px 12px; border-bottom: 1px solid #eee; }}
    tr:nth-child(even) {{ background: #f9f9f9; }}
    .footer {{
        text-align: center; color: #999; font-size: 0.85em;
        margin-top: 20px; padding: 10px;
    }}
    .kv-table td:first-child {{
        font-weight: bold; width: 200px; color: #555;
    }}
</style>
</head>
<body>
<div class="container">
<div class="header">
    <h1>WinnyTool</h1>
    <p>Windows System Diagnostic Report</p>
    <p>Generated: {html.escape(timestamp)} | {html.escape(platform.node())}</p>
</div>
"""


def _render_system_info_html(sys_info) -> str:
    """Render the system_info section as an HTML key-value table."""
    if not sys_info:
        return ""
    lines = ['<div class="section">', "<h2>System Information</h2>"]
    lines.append('<table class="kv-table">')

    if isinstance(sys_info, dict):
        for key, value in sys_info.items():
            display_key = key.replace("_", " ").title()
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value) if value else "N/A"
            lines.append(
                f"<tr><td>{html.escape(str(display_key))}</td>"
                f"<td>{html.escape(str(value))}</td></tr>"
            )
    elif isinstance(sys_info, list):
        for item in sys_info:
            if isinstance(item, dict):
                for key, value in item.items():
                    lines.append(
                        f"<tr><td>{html.escape(str(key))}</td>"
                        f"<td>{html.escape(str(value))}</td></tr>"
                    )

    lines.append("</table></div>")
    return "\n".join(lines)


def _render_findings_html(section_key: str, label: str, findings) -> str:
    """Render a findings section as an HTML table with severity badges."""
    if not findings:
        return ""

    lines = ['<div class="section">', f"<h2>{html.escape(label)}</h2>"]
    lines.append("<table><thead><tr>")

    if isinstance(findings, list) and findings:
        if isinstance(findings[0], dict):
            headers = list(findings[0].keys())
            for h in headers:
                lines.append(f"<th>{html.escape(h.replace('_', ' ').title())}</th>")
            lines.append("</tr></thead><tbody>")

            for row in findings:
                lines.append("<tr>")
                for h in headers:
                    val = str(row.get(h, ""))
                    if h.lower() == "severity":
                        lines.append(f"<td>{_severity_badge_html(val)}</td>")
                    else:
                        lines.append(f"<td>{html.escape(val)}</td>")
                lines.append("</tr>")
        else:
            lines.append("<th>Item</th></tr></thead><tbody>")
            for item in findings:
                lines.append(f"<tr><td>{html.escape(str(item))}</td></tr>")
    else:
        lines.append("<th>Details</th></tr></thead><tbody>")
        lines.append(f"<tr><td>{html.escape(str(findings))}</td></tr>")

    lines.append("</tbody></table></div>")
    return "\n".join(lines)


def _generate_html_report(scan_results: dict) -> str:
    """Generate a full HTML report and return the file path."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    parts = [_build_html_header(timestamp)]

    # System info section (special layout)
    if "system_info" in scan_results:
        parts.append(_render_system_info_html(scan_results["system_info"]))

    # All other sections
    for key, label in SECTION_LABELS.items():
        if key == "system_info":
            continue
        if key in scan_results and scan_results[key]:
            parts.append(_render_findings_html(key, label, scan_results[key]))

    # Footer
    parts.append(
        '<div class="footer">'
        f"Generated by WinnyTool v1.0 | {html.escape(timestamp)}"
        "</div></div></body></html>"
    )

    # Save file
    output_dir = _get_output_dir()
    filename = f"WinnyTool_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(parts))

    return filepath


def _generate_text_report(scan_results: dict) -> str:
    """Generate a plain-text report and return the file path."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "=" * 70,
        "  WinnyTool - Windows System Diagnostic Report",
        f"  Generated: {timestamp}",
        f"  Computer:  {platform.node()}",
        "=" * 70,
        "",
    ]

    # System info
    sys_info = scan_results.get("system_info")
    if sys_info and isinstance(sys_info, dict):
        lines.append("-" * 40)
        lines.append("  SYSTEM INFORMATION")
        lines.append("-" * 40)
        for key, value in sys_info.items():
            display_key = key.replace("_", " ").title()
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value) if value else "N/A"
            lines.append(f"  {display_key:<25} {value}")
        lines.append("")

    # Other sections
    for key, label in SECTION_LABELS.items():
        if key == "system_info":
            continue
        findings = scan_results.get(key)
        if not findings:
            continue

        lines.append("-" * 40)
        lines.append(f"  {label.upper()}")
        lines.append("-" * 40)

        if isinstance(findings, list):
            for item in findings:
                if isinstance(item, dict):
                    for k, v in item.items():
                        display_k = k.replace("_", " ").title()
                        lines.append(f"  {display_k}: {v}")
                    lines.append("")
                else:
                    lines.append(f"  - {item}")
        else:
            lines.append(f"  {findings}")
        lines.append("")

    lines.append("=" * 70)
    lines.append(f"  End of Report | WinnyTool v1.0 | {timestamp}")
    lines.append("=" * 70)

    # Save file
    output_dir = _get_output_dir()
    filename = f"WinnyTool_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return filepath


def generate_report(scan_results: dict, format: str = "html") -> str:
    """
    Generate a diagnostic report from scan results.

    Args:
        scan_results: Dictionary with keys matching SECTION_LABELS:
            - system_info: dict of system info key/value pairs
            - cve_results: list of dicts with vulnerability findings
            - bsod_results: list of dicts with BSOD analysis
            - performance_results: list of dicts with performance metrics
            - startup_items: list of dicts with startup entries
            - disk_results: list of dicts with disk health data
            - network_results: list of dicts with network diagnostics
            - update_results: list of dicts with Windows update status
        format: "html" or "text"

    Returns:
        str: Absolute file path of the generated report.
    """
    fmt = format.lower().strip()
    if fmt == "text" or fmt == "txt":
        return _generate_text_report(scan_results)
    else:
        return _generate_html_report(scan_results)


if __name__ == "__main__":
    # Example usage with dummy data
    sample = {
        "system_info": {
            "os_name": "Windows 11",
            "cpu_name": "Intel i7-12700K",
            "ram_total": "32 GB",
        },
        "cve_results": [
            {"cve_id": "CVE-2024-1234", "severity": "High", "description": "Sample vulnerability"},
        ],
        "bsod_results": [],
        "performance_results": [
            {"metric": "CPU Usage", "value": "45%", "severity": "Low"},
        ],
    }
    path = generate_report(sample, "html")
    print(f"Report saved to: {path}")
