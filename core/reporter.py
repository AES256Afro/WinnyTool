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
        format: "html" or "text"

    Returns:
        str: Absolute file path of the generated report.
    """
    fmt = format.lower().strip()
    if fmt == "text" or fmt == "txt":
        return _generate_text_report(scan_results)
    else:
        return _generate_html_report(scan_results)
