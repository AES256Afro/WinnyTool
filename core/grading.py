"""
WinnyTool - Security Grading Module

Provides an OpenSCAP-style security grading system for Windows systems.
Aggregates results from all WinnyTool scan modules and produces:
  1. An overall letter grade (A+ through F)
  2. Category scores with individual grades
  3. Detailed breakdown with recommendations

Grading scale follows standard academic-style thresholds:
  A+ = 97-100  |  A = 93-96  |  A- = 90-92
  B+ = 87-89   |  B = 83-86  |  B- = 80-82
  C+ = 77-79   |  C = 73-76  |  C- = 70-72
  D+ = 67-69   |  D = 63-66  |  D- = 60-62
  F  = 0-59

Uses only Python standard library.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Grade scale definition
# ---------------------------------------------------------------------------
# Each entry: (min_score, grade_letter)
# Ordered from highest to lowest so we can iterate and return the first match.
_GRADE_SCALE: List[Tuple[int, str]] = [
    (97, "A+"),
    (93, "A"),
    (90, "A-"),
    (87, "B+"),
    (83, "B"),
    (80, "B-"),
    (77, "C+"),
    (73, "C"),
    (70, "C-"),
    (67, "D+"),
    (63, "D"),
    (60, "D-"),
    (0,  "F"),
]

# ---------------------------------------------------------------------------
# Grade color mapping (hex colors for UI display)
# ---------------------------------------------------------------------------
_GRADE_COLORS: Dict[str, str] = {
    "A+": "#00c853",  # Green  - Hardened, exceeds best practices
    "A":  "#00c853",
    "A-": "#00c853",
    "B+": "#64dd17",  # Light green - Good, minor improvements needed
    "B":  "#64dd17",
    "B-": "#64dd17",
    "C+": "#ffd600",  # Yellow - Acceptable, several weaknesses
    "C":  "#ffd600",
    "C-": "#ffd600",
    "D+": "#ff6d00",  # Orange - Below average, needs attention
    "D":  "#ff6d00",
    "D-": "#ff6d00",
    "F":  "#ff1744",  # Red - Critical security issues
}

# ---------------------------------------------------------------------------
# Scoring categories and their default weights
# ---------------------------------------------------------------------------
# Each category maps scan result keys to a weight (percentage of total score).
# The weights must sum to 100.
_DEFAULT_CATEGORIES: Dict[str, Dict[str, Any]] = {
    "Windows Updates": {
        "weight": 20,
        "result_key": "update_results",
        "description": "Update recency, pending updates, OS build EOL status",
    },
    "CVE Exposure": {
        "weight": 20,
        "result_key": "cve_results",
        "description": "Number and severity of unpatched CVEs found",
    },
    "System Hardening": {
        "weight": 20,
        "result_key": "hardening_results",
        "description": "Hardening check results (basic / moderate / aggressive tiers)",
    },
    "Network Security": {
        "weight": 15,
        "result_key": "network_results",
        "description": "Firewall, DNS, open ports, RDP, SMB exposure",
    },
    "Antivirus & Defender": {
        "weight": 10,
        "result_key": "performance_results",  # Defender checks live in performance scans
        "description": "Real-time protection status, definition currency",
    },
    "Account Security": {
        "weight": 10,
        "result_key": "performance_results",  # UAC / account checks in performance scans
        "description": "UAC level, guest account status, password policies",
    },
    "Disk & Data": {
        "weight": 5,
        "result_key": "disk_results",
        "description": "BitLocker, SMART status, temp file bloat",
    },
}

# ---------------------------------------------------------------------------
# Severity deduction values
# ---------------------------------------------------------------------------
# When a check fails, we deduct points from that category's 100-point base
# score.  Warnings deduct half the amount of a fail.
_SEVERITY_DEDUCTIONS: Dict[str, int] = {
    "critical": 20,
    "high":     15,
    "medium":   10,
    "low":      5,
}

# Check names (substrings) that belong to each grading category.
# Used to route individual check results from the flat scan lists into the
# correct scoring bucket.
_CATEGORY_CHECK_MAP: Dict[str, List[str]] = {
    "Windows Updates": [
        "os build", "last update", "windows update service",
        "pending update", "feature update", "update history",
    ],
    "CVE Exposure": [
        "cve",  # CVE results use a different schema (see _score_cve_results)
    ],
    "System Hardening": [
        "hardening", "uac", "bitlocker", "secure boot", "smb signing",
        "remote desktop", "rdp", "credential guard", "audit",
    ],
    "Network Security": [
        "dns", "firewall", "latency", "wifi", "adapters", "proxy",
        "hosts file", "tcp", "open port", "smb", "rdp",
    ],
    "Antivirus & Defender": [
        "defender", "antivirus", "real-time protection", "virus",
        "definition", "malware", "tamper protection",
    ],
    "Account Security": [
        "uac", "guest account", "password", "lock screen",
        "auto-logon", "account", "admin",
    ],
    "Disk & Data": [
        "disk space", "smart", "trim", "fragmentation",
        "cleanup", "bitlocker", "temp file",
    ],
}

# Keywords that map to recommendation priorities.
_RECOMMENDATION_PRIORITY: Dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


# ===================================================================
# Public API
# ===================================================================

def get_grade_letter(score: float) -> str:
    """Convert a numeric score (0-100) to a letter grade.

    Args:
        score: Numeric score between 0 and 100.

    Returns:
        Letter grade string (e.g. "A+", "B-", "F").
    """
    # Clamp to 0-100 range
    score = max(0, min(100, score))
    for threshold, letter in _GRADE_SCALE:
        if score >= threshold:
            return letter
    return "F"


def get_grade_color(grade: str) -> str:
    """Return a hex color string for the given letter grade.

    Args:
        grade: A letter grade string (e.g. "A+", "C-", "F").

    Returns:
        Hex color code string (e.g. "#00c853").
    """
    return _GRADE_COLORS.get(grade, "#ff1744")


def calculate_grade(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """Calculate an overall security grade from aggregated scan results.

    This is the main entry point. It accepts results from all WinnyTool scan
    modules and produces a comprehensive grading report.

    Args:
        scan_results: Dict with any of these keys (all optional):
            - "cve_results":        list[dict] from cve_scanner.scan_cves()
            - "hardening_results":  list[dict] from hardening.scan_hardening()
            - "performance_results":list[dict] from performance.scan_performance()
            - "network_results":    list[dict] from network_diag.scan_network()
            - "update_results":     list[dict] from winupdate.scan_updates()
            - "disk_results":       list[dict] from disk_health.scan_disk_health()
            - "router_results":     list[dict] from router_security.scan_router_security()

    Returns:
        Dict containing:
            - overall_score (int):  0-100
            - overall_grade (str):  Letter grade
            - categories (dict):    Per-category breakdown
            - top_recommendations (list): Top 5 most impactful fixes
            - summary (str):        Human-readable summary
    """
    if scan_results is None:
        scan_results = {}

    # ------------------------------------------------------------------
    # Step 1: Score each category
    # ------------------------------------------------------------------
    category_reports: Dict[str, Dict[str, Any]] = {}
    active_weights: Dict[str, int] = {}

    for cat_name, cat_info in _DEFAULT_CATEGORIES.items():
        result_key = cat_info["result_key"]
        raw_results = scan_results.get(result_key, [])

        # Determine if this category has data to score.
        # CVE results use a different schema than the standard check format.
        if cat_name == "CVE Exposure":
            cve_data = scan_results.get("cve_results", [])
            if not cve_data and "cve_results" not in scan_results:
                # No CVE data provided at all -- skip this category
                logger.debug("Skipping category '%s': no data provided.", cat_name)
                continue
            score, findings, recommendations = _score_cve_results(cve_data)
        elif cat_name == "System Hardening":
            hardening_data = scan_results.get("hardening_results", [])
            if not hardening_data and "hardening_results" not in scan_results:
                logger.debug("Skipping category '%s': no data provided.", cat_name)
                continue
            score, findings, recommendations = _score_standard_results(
                hardening_data, cat_name
            )
        else:
            # For categories that share a result_key (e.g. Antivirus & Account
            # Security both pull from performance_results), we filter checks
            # by name to route them to the correct category.
            filtered = _filter_results_for_category(raw_results, cat_name)

            # Also pull from router_results for Network Security
            if cat_name == "Network Security":
                router_data = scan_results.get("router_results", [])
                if router_data:
                    filtered.extend(
                        _filter_results_for_category(router_data, cat_name)
                    )
                    # If router results exist but no network results matched,
                    # use router data directly.
                    if not filtered:
                        filtered = router_data

            # Skip if no relevant data exists at all
            if not filtered and result_key not in scan_results:
                # Check if any other source might have data for this category
                has_any_data = _has_any_data_for_category(scan_results, cat_name)
                if not has_any_data:
                    logger.debug("Skipping category '%s': no data provided.", cat_name)
                    continue

            score, findings, recommendations = _score_standard_results(
                filtered, cat_name
            )

        grade = get_grade_letter(score)
        category_reports[cat_name] = {
            "score": score,
            "grade": grade,
            "color": get_grade_color(grade),
            "findings": findings,
            "recommendations": recommendations,
        }
        active_weights[cat_name] = cat_info["weight"]

    # ------------------------------------------------------------------
    # Step 2: Redistribute weights so active categories sum to 100%
    # ------------------------------------------------------------------
    total_active_weight = sum(active_weights.values())
    if total_active_weight == 0:
        # No categories had data at all -- return a neutral result
        return _empty_grade_result()

    # Normalise: each category's effective weight = (original / total_active) * 100
    normalised_weights: Dict[str, float] = {}
    for cat_name, weight in active_weights.items():
        normalised_weights[cat_name] = (weight / total_active_weight) * 100

    # ------------------------------------------------------------------
    # Step 3: Calculate weighted overall score
    # ------------------------------------------------------------------
    overall_score = 0.0
    for cat_name, report in category_reports.items():
        cat_weight_pct = normalised_weights[cat_name] / 100.0
        overall_score += report["score"] * cat_weight_pct

    overall_score = int(round(overall_score))
    overall_score = max(0, min(100, overall_score))
    overall_grade = get_grade_letter(overall_score)

    # ------------------------------------------------------------------
    # Step 4: Collect top recommendations across all categories
    # ------------------------------------------------------------------
    all_recs = _collect_all_recommendations(category_reports)
    top_recs = all_recs[:5]  # Top 5 most impactful

    # ------------------------------------------------------------------
    # Step 5: Build the summary string
    # ------------------------------------------------------------------
    summary = _build_summary(overall_score, overall_grade, category_reports)

    return {
        "overall_score": overall_score,
        "overall_grade": overall_grade,
        "overall_color": get_grade_color(overall_grade),
        "categories": category_reports,
        "top_recommendations": top_recs,
        "summary": summary,
    }


def generate_summary(grade_result: Dict[str, Any]) -> str:
    """Generate a human-readable summary string from a grade result dict.

    Args:
        grade_result: The dict returned by calculate_grade().

    Returns:
        A multi-line summary string suitable for display.
    """
    if not grade_result:
        return "No grading data available."

    lines = []
    score = grade_result.get("overall_score", 0)
    grade = grade_result.get("overall_grade", "F")

    # Header
    lines.append(f"=== WinnyTool Security Grade: {grade} ({score}/100) ===")
    lines.append("")

    # Interpretation
    lines.append(_grade_interpretation(grade))
    lines.append("")

    # Category breakdown
    categories = grade_result.get("categories", {})
    if categories:
        lines.append("Category Breakdown:")
        lines.append("-" * 50)
        for cat_name, report in categories.items():
            cat_grade = report.get("grade", "?")
            cat_score = report.get("score", 0)
            finding_count = len(report.get("findings", []))
            lines.append(
                f"  {cat_name:<25} {cat_grade:>3} ({cat_score:>3}/100)"
                f"  [{finding_count} finding(s)]"
            )
        lines.append("")

    # Top recommendations
    top_recs = grade_result.get("top_recommendations", [])
    if top_recs:
        lines.append("Top Recommendations:")
        lines.append("-" * 50)
        for i, rec in enumerate(top_recs, 1):
            priority = rec.get("priority", "medium").upper()
            lines.append(f"  {i}. [{priority}] {rec.get('text', 'N/A')}")
        lines.append("")

    # Footer
    lines.append(
        "Run WinnyTool regularly to track your security posture over time."
    )

    return "\n".join(lines)


# ===================================================================
# Internal scoring helpers
# ===================================================================

def _score_cve_results(
    cve_results: List[Dict[str, Any]],
) -> Tuple[int, List[Dict], List[Dict]]:
    """Score CVE exposure based on the number and severity of unpatched CVEs.

    CVE results use a different schema than other modules:
        {"cve_id": str, "severity": str, "description": str, ...}

    Scoring logic:
        - Start at 100 points
        - Deduct per CVE based on severity:
            Critical = -20, High = -15, Medium = -10, Low = -5
        - Floor at 0

    Returns:
        (score, findings_list, recommendations_list)
    """
    score = 100
    findings = []
    recommendations = []

    if not cve_results:
        # No CVEs found -- perfect score for this category
        findings.append({
            "check": "CVE Scan",
            "status": "Pass",
            "details": "No unpatched CVEs detected.",
        })
        return score, findings, recommendations

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for cve in cve_results:
        sev = cve.get("severity", "Medium").lower()
        deduction = _SEVERITY_DEDUCTIONS.get(sev, 10)
        score -= deduction
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        findings.append({
            "check": cve.get("cve_id", "Unknown CVE"),
            "status": "Fail",
            "severity": cve.get("severity", "Medium"),
            "details": cve.get("description", ""),
        })

    # Build recommendations based on what was found
    if severity_counts["critical"] > 0:
        recommendations.append({
            "text": (
                f"URGENT: {severity_counts['critical']} critical CVE(s) detected. "
                "Install all pending security patches immediately via Windows Update."
            ),
            "priority": "critical",
            "category": "CVE Exposure",
        })

    if severity_counts["high"] > 0:
        recommendations.append({
            "text": (
                f"{severity_counts['high']} high-severity CVE(s) found. "
                "Apply security updates as soon as possible."
            ),
            "priority": "high",
            "category": "CVE Exposure",
        })

    total_cves = sum(severity_counts.values())
    if total_cves > 0 and severity_counts["critical"] == 0:
        recommendations.append({
            "text": (
                f"{total_cves} unpatched CVE(s) found. Run Windows Update "
                "and update third-party software to reduce exposure."
            ),
            "priority": "medium",
            "category": "CVE Exposure",
        })

    score = max(0, score)
    return score, findings, recommendations


def _score_standard_results(
    results: List[Dict[str, Any]],
    category_name: str,
) -> Tuple[int, List[Dict], List[Dict]]:
    """Score a category using the standard check result format.

    Standard scan results have the shape:
        {"check": str, "status": str, "details": str, "fix_action": dict|None}
    where status is one of: "Good", "Warning", "Critical", or for performance
    results: {"impact": "High"/"Medium"/"Low"}.

    Scoring logic:
        - Start at 100 points
        - Each failed/critical check deducts points based on severity
        - Each warning deducts half the fail amount
        - "Good" / "Pass" checks contribute no deduction
        - Floor at 0

    Returns:
        (score, findings_list, recommendations_list)
    """
    score = 100
    findings = []
    recommendations = []

    if not results:
        # No checks available -- give a neutral 100 (no penalties)
        findings.append({
            "check": category_name,
            "status": "Pass",
            "details": "No issues detected or no checks available.",
        })
        return score, findings, recommendations

    for result in results:
        check_name = result.get("check", result.get("issue", "Unknown"))
        status = _normalise_status(result)
        severity = _infer_severity(result)
        details = result.get("details", result.get("description", ""))

        findings.append({
            "check": check_name,
            "status": status,
            "severity": severity,
            "details": details,
        })

        if status == "Fail":
            # Full deduction
            deduction = _SEVERITY_DEDUCTIONS.get(severity.lower(), 10)
            score -= deduction

            # Generate a recommendation for this failure
            rec_text = _make_recommendation(check_name, details, result)
            recommendations.append({
                "text": rec_text,
                "priority": severity.lower(),
                "category": category_name,
            })

        elif status == "Warning":
            # Half deduction for warnings
            deduction = _SEVERITY_DEDUCTIONS.get(severity.lower(), 10) // 2
            score -= deduction

            # Warnings also get a (lower priority) recommendation
            rec_text = _make_recommendation(check_name, details, result)
            recommendations.append({
                "text": rec_text,
                "priority": "low" if severity.lower() == "low" else "medium",
                "category": category_name,
            })

        # "Pass" / "Good" / "Info" = no deduction

    score = max(0, score)
    return score, findings, recommendations


def _normalise_status(result: Dict[str, Any]) -> str:
    """Map various status strings to a consistent set: Pass, Warning, Fail.

    Different scan modules use different status conventions:
        - network/disk/update: "Good", "Warning", "Critical"
        - performance: uses "impact" field with "High"/"Medium"/"Low"

    Returns one of: "Pass", "Warning", "Fail".
    """
    # Standard status field (network, disk, update modules)
    status = result.get("status", "").strip()
    status_lower = status.lower()

    if status_lower in ("good", "pass", "ok", "info"):
        return "Pass"
    elif status_lower in ("critical", "fail", "error"):
        return "Fail"
    elif status_lower == "warning":
        return "Warning"

    # Performance module uses "impact" instead of "status"
    impact = result.get("impact", "").strip().lower()
    if impact == "high":
        return "Fail"
    elif impact == "medium":
        return "Warning"
    elif impact == "low":
        return "Warning"

    # If the result has a "current_value" and "recommended_value" that differ,
    # treat it as a finding (performance module pattern)
    current = result.get("current_value", "")
    recommended = result.get("recommended_value", "")
    if current and recommended and current != recommended and current != "N/A":
        return "Warning"

    # Default: treat unknown as Pass (don't penalise what we can't classify)
    return "Pass"


def _infer_severity(result: Dict[str, Any]) -> str:
    """Infer severity level from a check result.

    Tries multiple fields: "severity", "status", "impact".
    Returns one of: "Critical", "High", "Medium", "Low".
    """
    # Explicit severity field (CVE results)
    sev = result.get("severity", "").strip().lower()
    if sev in ("critical", "high", "medium", "low"):
        return sev.capitalize()

    # Map status to severity
    status = result.get("status", "").strip().lower()
    if status == "critical":
        return "Critical"
    elif status in ("fail", "error"):
        return "High"
    elif status == "warning":
        return "Medium"

    # Performance module: map impact to severity
    impact = result.get("impact", "").strip().lower()
    if impact == "high":
        return "High"
    elif impact == "medium":
        return "Medium"
    elif impact == "low":
        return "Low"

    return "Medium"  # Default assumption


def _filter_results_for_category(
    results: List[Dict[str, Any]],
    category_name: str,
) -> List[Dict[str, Any]]:
    """Filter a flat list of check results to those belonging to a category.

    Uses the _CATEGORY_CHECK_MAP to match check names (case-insensitive
    substring matching).

    Args:
        results: List of scan result dicts.
        category_name: Name of the grading category.

    Returns:
        Filtered list of results relevant to this category.
    """
    keywords = _CATEGORY_CHECK_MAP.get(category_name, [])
    if not keywords:
        return results  # No filter defined -- return all

    filtered = []
    for result in results:
        check_name = result.get("check", result.get("issue", "")).lower()
        details = result.get("details", result.get("description", "")).lower()

        for kw in keywords:
            if kw in check_name or kw in details:
                filtered.append(result)
                break

    return filtered


def _has_any_data_for_category(
    scan_results: Dict[str, Any],
    category_name: str,
) -> bool:
    """Check if any scan results dict contains data relevant to a category.

    Looks across all provided result lists to see if any check names match
    the category's keyword filter.
    """
    keywords = _CATEGORY_CHECK_MAP.get(category_name, [])
    if not keywords:
        return False

    for key, results_list in scan_results.items():
        if not isinstance(results_list, list):
            continue
        for result in results_list:
            check_name = result.get("check", result.get("issue", "")).lower()
            for kw in keywords:
                if kw in check_name:
                    return True
    return False


def _make_recommendation(
    check_name: str,
    details: str,
    result: Dict[str, Any],
) -> str:
    """Generate a human-readable recommendation for a failed/warning check.

    If the result includes a fix_action with a label, use that.
    Otherwise, construct a generic recommendation from the check name.
    """
    fix_action = result.get("fix_action")
    if fix_action and isinstance(fix_action, dict):
        label = fix_action.get("label", "")
        if label:
            return f"{check_name}: {label}"

    # For CVE-style results
    fix_text = result.get("fix", "")
    if fix_text:
        return f"{check_name}: {fix_text}"

    # Generic fallback
    if details:
        # Truncate long details for the recommendation
        short_details = details[:120] + "..." if len(details) > 120 else details
        return f"Address issue in '{check_name}': {short_details}"

    return f"Review and address '{check_name}'."


def _collect_all_recommendations(
    category_reports: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Collect and rank all recommendations across all categories.

    Sorts by priority: critical > high > medium > low.
    Returns the sorted list (caller can slice for top N).
    """
    all_recs = []
    for _cat_name, report in category_reports.items():
        recs = report.get("recommendations", [])
        all_recs.extend(recs)

    # Sort by priority (lower number = higher priority)
    all_recs.sort(
        key=lambda r: _RECOMMENDATION_PRIORITY.get(
            r.get("priority", "medium"), 2
        )
    )

    # Deduplicate: remove recs with identical text
    seen_texts = set()
    unique_recs = []
    for rec in all_recs:
        text = rec.get("text", "")
        if text not in seen_texts:
            seen_texts.add(text)
            unique_recs.append(rec)

    return unique_recs


def _build_summary(
    overall_score: int,
    overall_grade: str,
    category_reports: Dict[str, Dict[str, Any]],
) -> str:
    """Build a concise summary string describing the overall security posture.

    Example output:
        "Your system has a C+ security rating (78/100). 3 critical issues
         and 7 warnings were found across 5 categories. Top concern:
         CVE Exposure scored D- (60/100)."
    """
    # Count totals across all categories
    total_critical = 0
    total_warnings = 0
    total_pass = 0
    worst_cat_name = None
    worst_cat_score = 101  # Sentinel

    for cat_name, report in category_reports.items():
        findings = report.get("findings", [])
        for f in findings:
            status = f.get("status", "Pass")
            if status == "Fail":
                total_critical += 1
            elif status == "Warning":
                total_warnings += 1
            else:
                total_pass += 1

        if report["score"] < worst_cat_score:
            worst_cat_score = report["score"]
            worst_cat_name = cat_name

    parts = []
    parts.append(
        f"Your system has a {overall_grade} security rating ({overall_score}/100)."
    )

    issue_parts = []
    if total_critical > 0:
        issue_parts.append(
            f"{total_critical} critical issue{'s' if total_critical != 1 else ''}"
        )
    if total_warnings > 0:
        issue_parts.append(
            f"{total_warnings} warning{'s' if total_warnings != 1 else ''}"
        )

    if issue_parts:
        parts.append(
            f"{' and '.join(issue_parts)} found across "
            f"{len(category_reports)} categor{'ies' if len(category_reports) != 1 else 'y'}."
        )
    else:
        parts.append(
            f"No issues found across {len(category_reports)} "
            f"categor{'ies' if len(category_reports) != 1 else 'y'}."
        )

    if worst_cat_name and worst_cat_score < overall_score:
        worst_grade = category_reports[worst_cat_name]["grade"]
        parts.append(
            f"Top concern: {worst_cat_name} scored "
            f"{worst_grade} ({worst_cat_score}/100)."
        )

    return " ".join(parts)


def _grade_interpretation(grade: str) -> str:
    """Return a short interpretation of what the grade means."""
    first_char = grade[0] if grade else "F"
    interpretations = {
        "A": "Excellent security posture. Your system is well hardened and up to date.",
        "B": "Good security posture with minor improvements needed.",
        "C": "Acceptable but several weaknesses were identified that should be addressed.",
        "D": "Below average. Multiple security issues need attention.",
        "F": "Critical security issues detected. Immediate action is required.",
    }
    return interpretations.get(first_char, interpretations["F"])


def _empty_grade_result() -> Dict[str, Any]:
    """Return a neutral grade result when no scan data is available."""
    return {
        "overall_score": 0,
        "overall_grade": "F",
        "overall_color": get_grade_color("F"),
        "categories": {},
        "top_recommendations": [
            {
                "text": "Run a full WinnyTool scan to generate a security grade.",
                "priority": "high",
                "category": "General",
            }
        ],
        "summary": (
            "No scan data available. Run a full WinnyTool scan to "
            "evaluate your system's security posture."
        ),
    }
