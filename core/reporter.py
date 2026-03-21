"""
WinnyTool - Report Exporter
Generates styled HTML or plain-text diagnostic reports from scan results.
Uses only stdlib modules (html, datetime, os, platform).
"""

import html
import os
import platform
import base64
import struct
import zlib
import zipfile
from datetime import datetime
from typing import Optional

# Embedded logo for HTML reports (64x64 shield PNG)
REPORT_LOGO_B64 = "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAABN0lEQVR42u3bQQ7CIBCF4TmFi+68gEdw5z16fU+h+4aWAWZgKP9LWNlU3hfa2FRECCHkJN/P/rvLAAAAAAAAAAAAAKgC2LbXtAMAAAAAwATgLBFKXs3NdAVERMjNCQAAjG+CkRA0cwkJcBUAAAgOUIpgkdryAADg+CygnYAHQAnUUADL3Bag5LhhAI/nOznOkvv8eKz2OM13HscwgJJSFlgAADAAQDtxzUS9zhkKQFPe+rwAtABYI3gAuJZvvRmOBDArn3pRWjPZkvIt521+IeqF4AHQtXzukhgN0KX4FcJIgO7lU5eEdXkNQrcl34rgARCifAqiB0Co4hoES4Cw5XOXRGv5cEu+9vdCzZiqfOlzhLb89HsOlixfe0lMu+St/3W67DacpfciiSy8IUtk4V1pQgghpH/+KOkdDNK04DEAAAAASUVORK5CYII="


# Severity color mapping for HTML reports
SEVERITY_COLORS = {
    "critical": "#dc3545",
    "high": "#fd7e14",
    "medium": "#ffc107",
    "low": "#28a745",
    "info": "#17a2b8",
    "pass": "#28a745",
    "fail": "#dc3545",
    "warning": "#ffc107",
    "unknown": "#6c757d",
}

# Map from scan_results keys to display names
SECTION_LABELS = {
    "system_info": "System Information",
    "cve": "CVE / Vulnerability Scan",
    "bsod": "BSOD Analysis",
    "performance": "Performance Analysis",
    "startup": "Startup Items",
    "disk": "Disk Health",
    "network": "Network Diagnostics",
    "updates": "Windows Update Status",
    "hardening": "System Hardening",
    "router": "Router & Network Security",
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
    sev = severity.lower().strip() if severity else "info"
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
    .container {{ max-width: 1100px; margin: 0 auto; }}
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
    .section h2 .count {{
        font-size: 0.75em; color: #666; font-weight: normal;
    }}
    table {{
        width: 100%; border-collapse: collapse; font-size: 0.9em;
    }}
    th {{
        background: #1a1a2e; color: #fff; padding: 10px 12px;
        text-align: left;
    }}
    td {{ padding: 8px 12px; border-bottom: 1px solid #eee; vertical-align: top; }}
    tr:nth-child(even) {{ background: #f9f9f9; }}
    .footer {{
        text-align: center; color: #999; font-size: 0.85em;
        margin-top: 20px; padding: 10px;
    }}
    .kv-table td:first-child {{
        font-weight: bold; width: 200px; color: #555;
    }}
    .fix-text {{ color: #0d6efd; font-size: 0.85em; }}
    .ref-link {{ color: #0d6efd; text-decoration: none; }}
    .ref-link:hover {{ text-decoration: underline; }}
    .summary-box {{
        background: #e8f4fd; border-left: 4px solid #0d6efd;
        padding: 12px 16px; margin-bottom: 16px; border-radius: 4px;
    }}
</style>
</head>
<body>
<div class="container">
<div class="header">
    <img src="data:image/png;base64,{REPORT_LOGO_B64}" alt="WinnyTool" style="width:64px;height:64px;margin-bottom:10px;">
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


def _render_cve_section(findings) -> str:
    """Render CVE findings with severity badges, descriptions, and fix info."""
    if not findings:
        return ""
    lines = ['<div class="section">',
             f'<h2>CVE / Vulnerability Scan <span class="count">({len(findings)} finding(s))</span></h2>']
    lines.append("<table><thead><tr>")
    lines.append("<th>Severity</th><th>CVE ID</th><th>Description</th><th>Software</th><th>Fix</th><th>Reference</th>")
    lines.append("</tr></thead><tbody>")

    for item in findings:
        sev = item.get("severity", "Medium")
        cve_id = item.get("cve_id", "")
        desc = item.get("description", "")
        software = item.get("affected_software", "")
        if isinstance(software, list):
            software = ", ".join(software)
        fix = item.get("fix", item.get("fix_description", ""))
        ref = item.get("reference_url", "")
        ref_html = f'<a class="ref-link" href="{html.escape(ref)}" target="_blank">View Advisory</a>' if ref else ""

        lines.append(f"<tr>")
        lines.append(f"<td>{_severity_badge_html(sev)}</td>")
        lines.append(f"<td><strong>{html.escape(str(cve_id))}</strong></td>")
        lines.append(f"<td>{html.escape(str(desc))}</td>")
        lines.append(f"<td>{html.escape(str(software))}</td>")
        lines.append(f'<td class="fix-text">{html.escape(str(fix))}</td>')
        lines.append(f"<td>{ref_html}</td>")
        lines.append("</tr>")

    lines.append("</tbody></table></div>")
    return "\n".join(lines)


def _render_bsod_section(findings) -> str:
    """Render BSOD analysis with stop codes and fix suggestions."""
    if not findings:
        return ""
    lines = ['<div class="section">',
             f'<h2>BSOD Analysis <span class="count">({len(findings)} event(s))</span></h2>']
    lines.append("<table><thead><tr>")
    lines.append("<th>Date</th><th>Stop Code</th><th>Name</th><th>Common Causes</th><th>Fix Suggestions</th>")
    lines.append("</tr></thead><tbody>")

    for item in findings:
        date = item.get("date", "")
        code = item.get("stop_code", "")
        name = item.get("stop_code_name", "Unknown")
        causes = item.get("common_causes", [])
        if isinstance(causes, list):
            causes = "<br>".join(html.escape(str(c)) for c in causes[:3])
        else:
            causes = html.escape(str(causes))
        fixes = item.get("fix_suggestions", [])
        if isinstance(fixes, list):
            fixes = "<br>".join(html.escape(str(f)) for f in fixes[:3])
        else:
            fixes = html.escape(str(fixes))

        lines.append(f"<tr><td>{html.escape(str(date))}</td>")
        lines.append(f"<td><strong>{html.escape(str(code))}</strong></td>")
        lines.append(f"<td>{html.escape(str(name))}</td>")
        lines.append(f"<td>{causes}</td>")
        lines.append(f"<td>{fixes}</td></tr>")

    lines.append("</tbody></table></div>")
    return "\n".join(lines)


def _render_performance_section(findings) -> str:
    """Render performance findings with impact levels."""
    if not findings:
        return ""
    lines = ['<div class="section">',
             f'<h2>Performance Analysis <span class="count">({len(findings)} finding(s))</span></h2>']
    lines.append("<table><thead><tr>")
    lines.append("<th>Impact</th><th>Issue</th><th>Description</th><th>Current</th><th>Recommended</th>")
    lines.append("</tr></thead><tbody>")

    for item in findings:
        impact = item.get("impact", "Medium")
        issue = item.get("issue", "")
        desc = item.get("description", "")
        current = item.get("current_value", "")
        recommended = item.get("recommended_value", "")

        lines.append(f"<tr><td>{_severity_badge_html(impact)}</td>")
        lines.append(f"<td><strong>{html.escape(str(issue))}</strong></td>")
        lines.append(f"<td>{html.escape(str(desc))}</td>")
        lines.append(f"<td>{html.escape(str(current))}</td>")
        lines.append(f"<td>{html.escape(str(recommended))}</td></tr>")

    lines.append("</tbody></table></div>")
    return "\n".join(lines)


def _render_startup_section(findings) -> str:
    """Render startup items with source and impact."""
    if not findings:
        return ""
    lines = ['<div class="section">',
             f'<h2>Startup Items <span class="count">({len(findings)} item(s))</span></h2>']
    lines.append("<table><thead><tr>")
    lines.append("<th>Impact</th><th>Name</th><th>Command</th><th>Source</th><th>Location</th>")
    lines.append("</tr></thead><tbody>")

    for item in findings:
        impact = item.get("impact", "Unknown")
        name = item.get("name", "")
        cmd = item.get("command", "")
        source = item.get("source", "")
        location = item.get("location", "")

        lines.append(f"<tr><td>{_severity_badge_html(impact)}</td>")
        lines.append(f"<td><strong>{html.escape(str(name))}</strong></td>")
        lines.append(f"<td style='font-size:0.8em;word-break:break-all;'>{html.escape(str(cmd))}</td>")
        lines.append(f"<td>{html.escape(str(source))}</td>")
        lines.append(f"<td style='font-size:0.8em;'>{html.escape(str(location))}</td></tr>")

    lines.append("</tbody></table></div>")
    return "\n".join(lines)


def _render_check_section(section_key, label, findings) -> str:
    """Render generic check-based sections (disk, network, updates, router)."""
    if not findings:
        return ""
    lines = ['<div class="section">',
             f'<h2>{html.escape(label)} <span class="count">({len(findings)} finding(s))</span></h2>']
    lines.append("<table><thead><tr>")
    lines.append("<th>Status</th><th>Check</th><th>Details</th><th>Fix</th>")
    lines.append("</tr></thead><tbody>")

    for item in findings:
        if not isinstance(item, dict):
            lines.append(f"<tr><td colspan='4'>{html.escape(str(item))}</td></tr>")
            continue
        status = item.get("status", item.get("severity", "Info"))
        check = item.get("check", item.get("setting", ""))
        details = item.get("details", item.get("description", ""))
        fix = item.get("fix_suggestion", item.get("fix", item.get("fix_description", "")))

        lines.append(f"<tr><td>{_severity_badge_html(status)}</td>")
        lines.append(f"<td><strong>{html.escape(str(check))}</strong></td>")
        lines.append(f"<td>{html.escape(str(details))}</td>")
        lines.append(f'<td class="fix-text">{html.escape(str(fix))}</td></tr>')

    lines.append("</tbody></table></div>")
    return "\n".join(lines)


def _render_hardening_section(findings) -> str:
    """Render hardening findings with tier, status, pros, and cons."""
    if not findings:
        return ""
    lines = ['<div class="section">',
             f'<h2>System Hardening <span class="count">({len(findings)} check(s))</span></h2>']
    lines.append("<table><thead><tr>")
    lines.append("<th>Status</th><th>Tier</th><th>Setting</th><th>Description</th><th>Pros</th><th>Cons</th>")
    lines.append("</tr></thead><tbody>")

    for item in findings:
        if not isinstance(item, dict):
            continue
        status = item.get("status", "Unknown")
        tier = item.get("tier", "")
        setting = item.get("setting", "")
        desc = item.get("description", "")
        pros = item.get("pros", "")
        cons = item.get("cons", "")

        status_color = "Pass" if status == "Enabled" else "Fail" if status == "Disabled" else "Unknown"
        lines.append(f"<tr><td>{_severity_badge_html(status_color)}</td>")
        lines.append(f"<td>{html.escape(str(tier))}</td>")
        lines.append(f"<td><strong>{html.escape(str(setting))}</strong></td>")
        lines.append(f"<td>{html.escape(str(desc))}</td>")
        lines.append(f"<td style='color:#28a745;'>{html.escape(str(pros))}</td>")
        lines.append(f"<td style='color:#dc3545;'>{html.escape(str(cons))}</td></tr>")

    lines.append("</tbody></table></div>")
    return "\n".join(lines)


def _generate_html_report(scan_results: dict) -> str:
    """Generate a full HTML report and return the file path."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    parts = [_build_html_header(timestamp)]

    # Summary box
    total = sum(len(v) for k, v in scan_results.items() if k != "system_info" and isinstance(v, list))
    parts.append(f'<div class="summary-box"><strong>Total Findings: {total}</strong> across {len(scan_results)} scan categories</div>')

    # System info section (special layout)
    if "system_info" in scan_results:
        parts.append(_render_system_info_html(scan_results["system_info"]))

    # CVE section
    if "cve" in scan_results and scan_results["cve"]:
        parts.append(_render_cve_section(scan_results["cve"]))

    # BSOD section
    if "bsod" in scan_results and scan_results["bsod"]:
        parts.append(_render_bsod_section(scan_results["bsod"]))

    # Performance section
    if "performance" in scan_results and scan_results["performance"]:
        parts.append(_render_performance_section(scan_results["performance"]))

    # Startup section
    if "startup" in scan_results and scan_results["startup"]:
        parts.append(_render_startup_section(scan_results["startup"]))

    # Hardening section
    if "hardening" in scan_results and scan_results["hardening"]:
        parts.append(_render_hardening_section(scan_results["hardening"]))

    # Generic check-based sections (disk, network, updates, router)
    for key in ("disk", "network", "updates", "router"):
        label = SECTION_LABELS.get(key, key.title())
        if key in scan_results and scan_results[key]:
            parts.append(_render_check_section(key, label, scan_results[key]))

    # Footer
    parts.append(
        '<div class="footer">'
        f'<img src="data:image/png;base64,{REPORT_LOGO_B64}" alt="WinnyTool" style="width:24px;height:24px;vertical-align:middle;margin-right:6px;opacity:0.6;">'
        f"Generated by WinnyTool v1.4 | {html.escape(timestamp)}"
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

    # All sections with actual keys
    for key, label in SECTION_LABELS.items():
        if key == "system_info":
            continue
        findings = scan_results.get(key)
        if not findings:
            continue

        lines.append("-" * 70)
        lines.append(f"  {label.upper()} ({len(findings)} finding(s))")
        lines.append("-" * 70)

        if isinstance(findings, list):
            for item in findings:
                if isinstance(item, dict):
                    # CVE format
                    if "cve_id" in item:
                        lines.append(f"  [{item.get('severity', '')}] {item['cve_id']}")
                        lines.append(f"    {item.get('description', '')}")
                        fix = item.get("fix", item.get("fix_description", ""))
                        if fix:
                            lines.append(f"    Fix: {fix}")
                        ref = item.get("reference_url", "")
                        if ref:
                            lines.append(f"    Ref: {ref}")
                    # Performance format
                    elif "issue" in item:
                        lines.append(f"  [{item.get('impact', '')}] {item['issue']}")
                        lines.append(f"    {item.get('description', '')}")
                        cur = item.get("current_value", "")
                        rec = item.get("recommended_value", "")
                        if cur:
                            lines.append(f"    Current: {cur}")
                        if rec:
                            lines.append(f"    Recommended: {rec}")
                    # BSOD format
                    elif "stop_code" in item:
                        lines.append(f"  {item.get('date', '')} - {item.get('stop_code', '')} ({item.get('stop_code_name', '')})")
                        causes = item.get("common_causes", [])
                        if causes:
                            lines.append(f"    Causes: {', '.join(str(c) for c in causes[:3])}")
                        fixes = item.get("fix_suggestions", [])
                        if fixes:
                            lines.append(f"    Fixes: {', '.join(str(f) for f in fixes[:3])}")
                    # Startup format
                    elif "name" in item and "source" in item:
                        lines.append(f"  [{item.get('impact', '')}] {item['name']}")
                        lines.append(f"    Source: {item.get('source', '')} | Command: {item.get('command', '')}")
                    # Hardening format
                    elif "setting" in item:
                        lines.append(f"  [{item.get('status', '')}] {item['setting']} (Tier: {item.get('tier', '')})")
                        lines.append(f"    {item.get('description', '')}")
                    # Standard check format
                    elif "check" in item:
                        lines.append(f"  [{item.get('status', '')}] {item['check']}")
                        lines.append(f"    {item.get('details', '')}")
                        fix = item.get("fix_suggestion", item.get("fix", ""))
                        if fix:
                            lines.append(f"    Fix: {fix}")
                    else:
                        for k, v in item.items():
                            if k == "fix_action":
                                continue
                            lines.append(f"    {k}: {v}")
                    lines.append("")
                else:
                    lines.append(f"  - {item}")
        else:
            lines.append(f"  {findings}")
        lines.append("")

    lines.append("=" * 70)
    lines.append(f"  End of Report | WinnyTool v1.4 | {timestamp}")
    lines.append("=" * 70)

    # Save file
    output_dir = _get_output_dir()
    filename = f"WinnyTool_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return filepath


def _generate_csv_report(scan_results: dict) -> str:
    """Generate a CSV report and return the file path."""
    import csv

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = _get_output_dir()
    filename = f"WinnyTool_Report_{timestamp}.csv"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Category", "Severity/Status", "Item", "Details", "Fix", "Reference"])

        for key, label in SECTION_LABELS.items():
            if key == "system_info":
                sys_info = scan_results.get("system_info")
                if sys_info and isinstance(sys_info, dict):
                    for k, v in sys_info.items():
                        if isinstance(v, list):
                            v = ", ".join(str(x) for x in v) if v else "N/A"
                        writer.writerow(["System Info", "", k.replace("_", " ").title(), str(v), "", ""])
                continue

            findings = scan_results.get(key)
            if not findings or not isinstance(findings, list):
                continue

            for item in findings:
                if not isinstance(item, dict):
                    writer.writerow([label, "", str(item), "", "", ""])
                    continue

                if "cve_id" in item:
                    writer.writerow([
                        label, item.get("severity", ""),
                        item.get("cve_id", ""), item.get("description", ""),
                        item.get("fix", item.get("fix_description", "")),
                        item.get("reference_url", ""),
                    ])
                elif "stop_code" in item:
                    causes = item.get("common_causes", [])
                    if isinstance(causes, list):
                        causes = "; ".join(str(c) for c in causes[:3])
                    writer.writerow([
                        label, "",
                        item.get("stop_code", ""), item.get("stop_code_name", ""),
                        str(causes), item.get("date", ""),
                    ])
                elif "issue" in item:
                    writer.writerow([
                        label, item.get("impact", ""),
                        item.get("issue", ""), item.get("description", ""),
                        item.get("recommended_value", ""), "",
                    ])
                elif "setting" in item:
                    writer.writerow([
                        label, item.get("status", ""),
                        item.get("setting", ""), item.get("description", ""),
                        item.get("pros", ""), item.get("cons", ""),
                    ])
                elif "check" in item:
                    writer.writerow([
                        label, item.get("status", item.get("severity", "")),
                        item.get("check", ""), item.get("details", item.get("description", "")),
                        item.get("fix_suggestion", item.get("fix", "")), "",
                    ])
                elif "name" in item:
                    writer.writerow([
                        label, item.get("impact", ""),
                        item.get("name", ""), f"Source: {item.get('source', '')}",
                        item.get("command", ""), "",
                    ])
                else:
                    writer.writerow([label, "", str(item), "", "", ""])

    return filepath


# ============================================================
# PDF Report Generator (stdlib only - raw PDF construction)
# ============================================================

class _PDFBuilder:
    """Minimal PDF builder using raw PDF syntax. Stdlib only."""

    def __init__(self):
        self.objects = []  # list of byte-string objects
        self.pages = []    # list of page object indices
        self._current_page_lines = []
        self._page_y = 750  # current Y position on page
        self._line_height = 12
        self._margin_left = 50
        self._margin_right = 50
        self._page_width = 612  # US Letter
        self._page_height = 792
        self._usable_width = self._page_width - self._margin_left - self._margin_right
        self._font_size = 10

    def _escape_pdf_text(self, text: str) -> str:
        """Escape special characters for PDF text strings."""
        text = str(text)
        text = text.replace("\\", "\\\\")
        text = text.replace("(", "\\(")
        text = text.replace(")", "\\)")
        # Replace non-ASCII with '?'
        result = []
        for ch in text:
            if 32 <= ord(ch) < 127:
                result.append(ch)
            elif ch == '\n':
                result.append(' ')
            else:
                result.append('?')
        return "".join(result)

    def _new_page(self):
        """Flush current page and start a new one."""
        if self._current_page_lines:
            self._flush_page()
        self._page_y = 750
        self._current_page_lines = []

    def _flush_page(self):
        """Convert accumulated lines into a PDF page object."""
        if not self._current_page_lines:
            return
        stream_lines = ["BT"]
        stream_lines.append(f"/F1 {self._font_size} Tf")
        for (x, y, size, text, bold) in self._current_page_lines:
            font = "/F2" if bold else "/F1"
            stream_lines.append(f"{font} {size} Tf")
            stream_lines.append(f"{x} {y} Td")
            stream_lines.append(f"({self._escape_pdf_text(text)}) Tj")
            stream_lines.append(f"-{x} -{y} Td")
        stream_lines.append("ET")
        stream_content = "\n".join(stream_lines)
        stream_bytes = stream_content.encode("latin-1", errors="replace")

        # Stream object
        stream_obj_idx = self._add_object(
            f"<< /Length {len(stream_bytes)} >>\nstream\n".encode("latin-1")
            + stream_bytes
            + b"\nendstream"
        )

        # Page object (will be finalized later with parent ref)
        page_obj_idx = self._add_object(None)  # placeholder
        self.pages.append((page_obj_idx, stream_obj_idx))
        self._current_page_lines = []

    def _add_object(self, data) -> int:
        """Add a PDF object and return its index (1-based obj number will be index+1)."""
        self.objects.append(data)
        return len(self.objects) - 1

    def _check_page_break(self, lines_needed: int = 1):
        """Start a new page if we'd overflow."""
        needed_space = lines_needed * self._line_height + 20
        if self._page_y - needed_space < 50:
            self._flush_page()
            self._page_y = 750
            self._current_page_lines = []

    def add_text(self, text: str, size: int = 10, bold: bool = False, indent: int = 0):
        """Add a line of text at the current position."""
        self._check_page_break()
        x = self._margin_left + indent
        # Truncate very long lines
        max_chars = int((self._usable_width - indent) / (size * 0.5))
        if len(text) > max_chars:
            text = text[:max_chars - 3] + "..."
        self._current_page_lines.append((x, self._page_y, size, text, bold))
        self._page_y -= self._line_height
        if size > 12:
            self._page_y -= (size - 10)

    def add_blank_line(self):
        self._page_y -= self._line_height

    def add_separator(self):
        self.add_text("-" * 80, size=8)

    def _truncate_text(self, text: str, max_width_chars: int = 90) -> str:
        """Truncate text to fit within available width."""
        text = str(text).replace("\n", " ").replace("\r", "")
        if len(text) > max_width_chars:
            return text[:max_width_chars - 3] + "..."
        return text

    def build(self) -> bytes:
        """Build the complete PDF file as bytes."""
        # Flush any remaining page content
        if self._current_page_lines:
            self._flush_page()

        if not self.pages:
            # Empty PDF - add a blank page
            self._current_page_lines = [(50, 750, 12, "No scan data available.", False)]
            self._flush_page()

        # Now build the PDF structure:
        # obj 1: Catalog
        # obj 2: Pages
        # obj 3: Font Helvetica
        # obj 4: Font Helvetica-Bold
        # obj 5+: page streams and page objects

        pdf_objects = []

        # 1 - Catalog
        pdf_objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")

        # 2 - Pages (placeholder, filled after we know page refs)
        pdf_objects.append(None)

        # 3 - Font (Helvetica)
        pdf_objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

        # 4 - Font (Helvetica-Bold)
        pdf_objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")

        # Add stream objects and page objects
        page_refs = []
        for (page_placeholder_idx, stream_placeholder_idx) in self.pages:
            # Stream object
            stream_data = self.objects[stream_placeholder_idx]
            stream_obj_num = len(pdf_objects) + 1
            pdf_objects.append(stream_data)

            # Page object
            page_obj_num = len(pdf_objects) + 1
            page_obj = (
                f"<< /Type /Page /Parent 2 0 R "
                f"/MediaBox [0 0 {self._page_width} {self._page_height}] "
                f"/Contents {stream_obj_num} 0 R "
                f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> >>"
            ).encode("latin-1")
            pdf_objects.append(page_obj)
            page_refs.append(f"{page_obj_num} 0 R")

        # Fill in Pages object
        kids = " ".join(page_refs)
        pdf_objects[1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_refs)} >>".encode("latin-1")

        # Build the raw PDF bytes
        output = bytearray()
        output.extend(b"%PDF-1.4\n")
        output.extend(b"%\xe2\xe3\xcf\xd3\n")

        offsets = []
        for i, obj_data in enumerate(pdf_objects):
            offsets.append(len(output))
            obj_num = i + 1
            output.extend(f"{obj_num} 0 obj\n".encode("latin-1"))
            if isinstance(obj_data, bytes):
                output.extend(obj_data)
            else:
                output.extend(str(obj_data).encode("latin-1"))
            output.extend(b"\nendobj\n")

        # Cross-reference table
        xref_offset = len(output)
        output.extend(b"xref\n")
        output.extend(f"0 {len(pdf_objects) + 1}\n".encode("latin-1"))
        output.extend(b"0000000000 65535 f \n")
        for offset in offsets:
            output.extend(f"{offset:010d} 00000 n \n".encode("latin-1"))

        # Trailer
        output.extend(b"trailer\n")
        output.extend(f"<< /Size {len(pdf_objects) + 1} /Root 1 0 R >>\n".encode("latin-1"))
        output.extend(b"startxref\n")
        output.extend(f"{xref_offset}\n".encode("latin-1"))
        output.extend(b"%%EOF\n")

        return bytes(output)


def _generate_pdf_report(scan_results: dict) -> str:
    """
    Generate a PDF report using raw PDF syntax (no external libraries).

    The PDF contains:
      - WinnyTool header with version
      - System info table
      - All scan sections with findings and severity markers
      - Footer with timestamp

    Returns the absolute file path of the generated PDF.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pdf = _PDFBuilder()

    # === Header ===
    pdf.add_text("=" * 72, size=8)
    pdf.add_text("WinnyTool v1.4 - Windows System Diagnostic Report", size=16, bold=True)
    pdf.add_text(f"Generated: {timestamp}  |  Computer: {platform.node()}", size=9)
    pdf.add_text("=" * 72, size=8)
    pdf.add_blank_line()

    # === Summary ===
    total = sum(len(v) for k, v in scan_results.items() if k != "system_info" and isinstance(v, list))
    pdf.add_text(f"Total Findings: {total} across {len(scan_results)} scan categories", size=10, bold=True)
    pdf.add_blank_line()

    # === System Info ===
    sys_info = scan_results.get("system_info")
    if sys_info and isinstance(sys_info, dict):
        pdf.add_separator()
        pdf.add_text("SYSTEM INFORMATION", size=12, bold=True)
        pdf.add_separator()
        for key, value in sys_info.items():
            display_key = key.replace("_", " ").title()
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value) if value else "N/A"
            line = f"{display_key:<28} {value}"
            pdf.add_text(pdf._truncate_text(line), size=9, indent=10)
        pdf.add_blank_line()

    # === Scan Sections ===
    severity_markers = {
        "critical": "[!!!]", "high": "[!! ]", "medium": "[ ! ]",
        "low": "[ . ]", "info": "[ i ]", "pass": "[ + ]",
        "fail": "[ X ]", "warning": "[ ! ]", "enabled": "[ + ]",
        "disabled": "[ X ]", "unknown": "[ ? ]",
    }

    for key, label in SECTION_LABELS.items():
        if key == "system_info":
            continue
        findings = scan_results.get(key)
        if not findings or not isinstance(findings, list):
            continue

        pdf._check_page_break(3)
        pdf.add_separator()
        pdf.add_text(f"{label.upper()} ({len(findings)} finding(s))", size=12, bold=True)
        pdf.add_separator()

        for item in findings:
            if not isinstance(item, dict):
                pdf.add_text(f"  - {pdf._truncate_text(str(item))}", size=9)
                continue

            pdf._check_page_break(4)

            # CVE format
            if "cve_id" in item:
                sev = item.get("severity", "Medium").lower()
                marker = severity_markers.get(sev, "[ ? ]")
                pdf.add_text(f"{marker} {item['cve_id']} - {item.get('severity', '')}", size=10, bold=True)
                desc = item.get("description", "")
                if desc:
                    pdf.add_text(pdf._truncate_text(desc), size=9, indent=20)
                fix = item.get("fix", item.get("fix_description", ""))
                if fix:
                    pdf.add_text(f"Fix: {pdf._truncate_text(fix)}", size=8, indent=20)
                ref = item.get("reference_url", "")
                if ref:
                    pdf.add_text(f"Ref: {pdf._truncate_text(ref)}", size=8, indent=20)

            # BSOD format
            elif "stop_code" in item:
                pdf.add_text(
                    f"[!!!] {item.get('date', '')} - {item.get('stop_code', '')} "
                    f"({item.get('stop_code_name', '')})",
                    size=10, bold=True,
                )
                causes = item.get("common_causes", [])
                if isinstance(causes, list) and causes:
                    pdf.add_text(f"Causes: {', '.join(str(c) for c in causes[:3])}", size=8, indent=20)
                fixes = item.get("fix_suggestions", [])
                if isinstance(fixes, list) and fixes:
                    pdf.add_text(f"Fixes: {', '.join(str(f) for f in fixes[:3])}", size=8, indent=20)

            # Performance format
            elif "issue" in item:
                impact = item.get("impact", "Medium").lower()
                marker = severity_markers.get(impact, "[ ? ]")
                pdf.add_text(f"{marker} {item.get('issue', '')}", size=10, bold=True)
                desc = item.get("description", "")
                if desc:
                    pdf.add_text(pdf._truncate_text(desc), size=9, indent=20)
                cur = item.get("current_value", "")
                rec = item.get("recommended_value", "")
                if cur:
                    pdf.add_text(f"Current: {pdf._truncate_text(str(cur))}", size=8, indent=20)
                if rec:
                    pdf.add_text(f"Recommended: {pdf._truncate_text(str(rec))}", size=8, indent=20)

            # Startup format
            elif "name" in item and "source" in item:
                impact = item.get("impact", "unknown").lower()
                marker = severity_markers.get(impact, "[ ? ]")
                pdf.add_text(f"{marker} {item.get('name', '')}", size=10, bold=True)
                pdf.add_text(
                    f"Source: {item.get('source', '')} | Command: {pdf._truncate_text(item.get('command', ''))}",
                    size=8, indent=20,
                )

            # Hardening format
            elif "setting" in item:
                status = item.get("status", "Unknown").lower()
                marker = severity_markers.get(status, "[ ? ]")
                tier = item.get("tier", "")
                pdf.add_text(f"{marker} {item.get('setting', '')} (Tier: {tier})", size=10, bold=True)
                desc = item.get("description", "")
                if desc:
                    pdf.add_text(pdf._truncate_text(desc), size=9, indent=20)

            # Standard check format
            elif "check" in item:
                status = item.get("status", item.get("severity", "Info")).lower()
                marker = severity_markers.get(status, "[ ? ]")
                pdf.add_text(f"{marker} {item.get('check', '')}", size=10, bold=True)
                details = item.get("details", item.get("description", ""))
                if details:
                    pdf.add_text(pdf._truncate_text(str(details)), size=9, indent=20)
                fix = item.get("fix_suggestion", item.get("fix", ""))
                if fix:
                    pdf.add_text(f"Fix: {pdf._truncate_text(str(fix))}", size=8, indent=20)

            # Generic dict format
            else:
                for k, v in item.items():
                    if k == "fix_action":
                        continue
                    pdf.add_text(f"{k}: {pdf._truncate_text(str(v))}", size=9, indent=10)

            pdf.add_blank_line()

    # === Footer ===
    pdf._check_page_break(3)
    pdf.add_separator()
    pdf.add_text(f"End of Report | WinnyTool v1.4 | {timestamp}", size=9, bold=True)
    pdf.add_separator()

    # Save file
    output_dir = _get_output_dir()
    filename = f"WinnyTool_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "wb") as f:
        f.write(pdf.build())

    return filepath


def generate_all_reports_zip(scan_results: dict) -> str:
    """
    Generate HTML, Text, CSV, and PDF reports, then package them into a single ZIP file.

    The ZIP is named WinnyTool_Reports_YYYYMMDD_HHMMSS.zip and saved to Desktop.
    Individual report files are cleaned up after zipping.

    Returns the absolute file path of the ZIP file.
    """
    # Generate all four report formats
    report_files = []
    try:
        report_files.append(_generate_html_report(scan_results))
        report_files.append(_generate_text_report(scan_results))
        report_files.append(_generate_csv_report(scan_results))
        report_files.append(_generate_pdf_report(scan_results))
    except Exception:
        # If any format fails, continue with what we have
        pass

    if not report_files:
        raise RuntimeError("Failed to generate any report files.")

    # Create ZIP
    output_dir = _get_output_dir()
    zip_filename = f"WinnyTool_Reports_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
    zip_filepath = os.path.join(output_dir, zip_filename)

    with zipfile.ZipFile(zip_filepath, "w", zipfile.ZIP_DEFLATED) as zf:
        for fpath in report_files:
            if fpath and os.path.isfile(fpath):
                zf.write(fpath, os.path.basename(fpath))

    # Clean up individual files
    for fpath in report_files:
        try:
            if fpath and os.path.isfile(fpath):
                os.remove(fpath)
        except OSError:
            pass

    return zip_filepath


def generate_report(scan_results: dict, format: str = "html") -> str:
    """
    Generate a diagnostic report from scan results.

    Args:
        scan_results: Dictionary with keys matching scan module outputs:
            - system_info: dict of system info key/value pairs
            - cve: list of CVE findings
            - bsod: list of BSOD events
            - performance: list of performance issues
            - startup: list of startup items
            - disk: list of disk health checks
            - network: list of network diagnostics
            - updates: list of Windows Update checks
            - hardening: list of hardening checks
            - router: list of router security checks
        format: "html", "text", "txt", "csv", "pdf", or "zip"

    Returns:
        str: Absolute file path of the generated report (or ZIP archive).
    """
    fmt = format.lower().strip()
    if fmt == "text" or fmt == "txt":
        return _generate_text_report(scan_results)
    elif fmt == "csv":
        return _generate_csv_report(scan_results)
    elif fmt == "pdf":
        return _generate_pdf_report(scan_results)
    elif fmt == "zip":
        return generate_all_reports_zip(scan_results)
    else:
        return _generate_html_report(scan_results)
