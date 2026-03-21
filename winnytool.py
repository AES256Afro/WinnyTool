#!/usr/bin/env python3
"""
WinnyTool - Windows System Diagnostic & Optimization Tool
Main GUI Application
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import os
import sys
import json
import ctypes
import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import sysinfo, cve_scanner, bsod_analyzer, performance
from core import startup_mgr, disk_health, network_diag, winupdate
from core import updater, reporter, history, hardening
from core.router_security import scan_router_security
from core.grading import calculate_grade, get_grade_color
from core.resources import get_security_resources, open_resource

VERSION = "1.4.0"
APP_NAME = "WinnyTool"

# --- Color Scheme ---
COLORS = {
    "bg_dark": "#1a1a2e",
    "bg_medium": "#16213e",
    "bg_light": "#0f3460",
    "accent": "#e94560",
    "accent_hover": "#ff6b81",
    "text_primary": "#ffffff",
    "text_secondary": "#a0a0b0",
    "success": "#2ecc71",
    "warning": "#f39c12",
    "critical": "#e74c3c",
    "info": "#3498db",
    "card_bg": "#1e2a4a",
    "button_bg": "#0f3460",
    "button_hover": "#1a4a7a",
    "scrollbar": "#2a3a5a",
}

SEVERITY_COLORS = {
    "Critical": "#e74c3c",
    "High": "#e67e22",
    "Medium": "#f39c12",
    "Low": "#3498db",
    "Good": "#2ecc71",
    "Warning": "#f39c12",
    "Unknown": "#95a5a6",
}


def is_admin():
    """Check if running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


class WinnyToolApp:
    # Base font sizes (at 100% scale)
    BASE_FONT_SIZES = {
        "regular": 10,
        "title": 18,
        "subtitle": 11,
        "card_title": 12,
        "sidebar_title": 16,
        "sidebar": 9,
        "status": 9,
        "severity": 10,
        "accent_button": 10,
        "fix_button": 9,
        "view_advisory_button": 9,
        "apply_fix_button": 9,
        "sidebar_button": 11,
        "sidebar_active_button": 11,
    }
    BASE_SIDEBAR_WIDTH = 220
    SETTINGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "settings.json")

    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME} v{VERSION}")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        self.root.configure(bg=COLORS["bg_dark"])

        # Set window icon
        try:
            icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "winnytool.ico")
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except Exception:
            pass

        # Initialize scan history DB
        try:
            history.init_db()
        except Exception:
            pass

        self.scan_results = {}
        self.current_page = None

        # Load UI scale from settings
        self.ui_scale = self._load_settings().get("ui_scale", 100)

        self._build_styles()
        self._build_layout()
        self._show_dashboard()

        # Check for updates on launch (background)
        threading.Thread(target=self._check_updates_bg, daemon=True).start()

    def _load_settings(self):
        """Load settings from data/settings.json."""
        try:
            with open(self.SETTINGS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"ui_scale": 100}

    def _save_settings(self, settings):
        """Save settings to data/settings.json."""
        try:
            os.makedirs(os.path.dirname(self.SETTINGS_FILE), exist_ok=True)
            with open(self.SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(settings, f, indent=2)
        except Exception:
            pass

    def _scaled(self, base_size):
        """Return a font size scaled by the current ui_scale percentage."""
        return max(6, round(base_size * self.ui_scale / 100))

    def _build_styles(self):
        """Configure ttk styles for dark theme."""
        self.style = ttk.Style()
        self.style.theme_use("clam")

        self.style.configure("Dark.TFrame", background=COLORS["bg_dark"])
        self.style.configure("Card.TFrame", background=COLORS["card_bg"])
        self.style.configure("Medium.TFrame", background=COLORS["bg_medium"])

        self._apply_scale(self.ui_scale)

    def _apply_scale(self, scale_percent):
        """Apply UI scale to all font sizes and sidebar width."""
        self.ui_scale = scale_percent
        s = self._scaled

        self.style.configure(
            "Dark.TLabel",
            background=COLORS["bg_dark"],
            foreground=COLORS["text_primary"],
            font=("Segoe UI", s(self.BASE_FONT_SIZES["regular"])),
        )
        self.style.configure(
            "Card.TLabel",
            background=COLORS["card_bg"],
            foreground=COLORS["text_primary"],
            font=("Segoe UI", s(self.BASE_FONT_SIZES["regular"])),
        )
        self.style.configure(
            "Title.TLabel",
            background=COLORS["bg_dark"],
            foreground=COLORS["text_primary"],
            font=("Segoe UI", s(self.BASE_FONT_SIZES["title"]), "bold"),
        )
        self.style.configure(
            "Subtitle.TLabel",
            background=COLORS["bg_dark"],
            foreground=COLORS["text_secondary"],
            font=("Segoe UI", s(self.BASE_FONT_SIZES["subtitle"])),
        )
        self.style.configure(
            "CardTitle.TLabel",
            background=COLORS["card_bg"],
            foreground=COLORS["text_primary"],
            font=("Segoe UI", s(self.BASE_FONT_SIZES["card_title"]), "bold"),
        )
        self.style.configure(
            "SidebarTitle.TLabel",
            background=COLORS["bg_medium"],
            foreground=COLORS["accent"],
            font=("Segoe UI", s(self.BASE_FONT_SIZES["sidebar_title"]), "bold"),
        )
        self.style.configure(
            "Sidebar.TLabel",
            background=COLORS["bg_medium"],
            foreground=COLORS["text_secondary"],
            font=("Segoe UI", s(self.BASE_FONT_SIZES["sidebar"])),
        )
        self.style.configure(
            "Status.TLabel",
            background=COLORS["bg_dark"],
            foreground=COLORS["text_secondary"],
            font=("Segoe UI", s(self.BASE_FONT_SIZES["status"])),
        )

        # Severity label styles
        for sev, color in SEVERITY_COLORS.items():
            self.style.configure(
                f"{sev}.TLabel",
                background=COLORS["card_bg"],
                foreground=color,
                font=("Segoe UI", s(self.BASE_FONT_SIZES["severity"]), "bold"),
            )

        self.style.configure(
            "Accent.TButton",
            background=COLORS["accent"],
            foreground=COLORS["text_primary"],
            font=("Segoe UI", s(self.BASE_FONT_SIZES["accent_button"]), "bold"),
            borderwidth=0,
            padding=(12, 6),
        )
        self.style.map(
            "Accent.TButton",
            background=[("active", COLORS["accent_hover"])],
        )
        self.style.configure(
            "Fix.TButton",
            background=COLORS["success"],
            foreground=COLORS["text_primary"],
            font=("Segoe UI", s(self.BASE_FONT_SIZES["fix_button"]), "bold"),
            borderwidth=0,
            padding=(8, 4),
        )
        self.style.map(
            "Fix.TButton",
            background=[("active", "#27ae60")],
        )
        self.style.configure(
            "ViewAdvisory.TButton",
            background=COLORS["info"],
            foreground=COLORS["text_primary"],
            font=("Segoe UI", s(self.BASE_FONT_SIZES["view_advisory_button"]), "bold"),
            borderwidth=0,
            padding=(8, 4),
        )
        self.style.map(
            "ViewAdvisory.TButton",
            background=[("active", "#2980b9")],
        )
        self.style.configure(
            "ApplyFix.TButton",
            background=COLORS["success"],
            foreground=COLORS["text_primary"],
            font=("Segoe UI", s(self.BASE_FONT_SIZES["apply_fix_button"]), "bold"),
            borderwidth=0,
            padding=(8, 4),
        )
        self.style.map(
            "ApplyFix.TButton",
            background=[("active", "#27ae60")],
        )
        self.style.configure(
            "Sidebar.TButton",
            background=COLORS["bg_medium"],
            foreground=COLORS["text_primary"],
            font=("Segoe UI", s(self.BASE_FONT_SIZES["sidebar_button"])),
            borderwidth=0,
            padding=(16, 10),
            anchor="w",
        )
        self.style.map(
            "Sidebar.TButton",
            background=[
                ("active", COLORS["bg_light"]),
                ("pressed", COLORS["accent"]),
            ],
        )
        self.style.configure(
            "SidebarActive.TButton",
            background=COLORS["bg_light"],
            foreground=COLORS["accent"],
            font=("Segoe UI", s(self.BASE_FONT_SIZES["sidebar_active_button"]), "bold"),
            borderwidth=0,
            padding=(16, 10),
            anchor="w",
        )

        # Progress bar
        self.style.configure(
            "Accent.Horizontal.TProgressbar",
            background=COLORS["accent"],
            troughcolor=COLORS["bg_light"],
            borderwidth=0,
        )

        # Scale the sidebar width if it has been built
        scaled_width = max(150, round(self.BASE_SIDEBAR_WIDTH * self.ui_scale / 100))
        if hasattr(self, "sidebar"):
            self.sidebar.configure(width=scaled_width)

    def _build_layout(self):
        """Build the main application layout."""
        # Main container
        self.main_frame = ttk.Frame(self.root, style="Dark.TFrame")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Sidebar
        scaled_width = max(150, round(self.BASE_SIDEBAR_WIDTH * self.ui_scale / 100))
        self.sidebar = ttk.Frame(self.main_frame, style="Medium.TFrame", width=scaled_width)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)
        self.sidebar.pack_propagate(False)

        # App title in sidebar
        title_frame = ttk.Frame(self.sidebar, style="Medium.TFrame")
        title_frame.pack(fill=tk.X, pady=(20, 5), padx=10)
        ttk.Label(title_frame, text=APP_NAME, style="SidebarTitle.TLabel").pack(
            anchor="w"
        )
        ttk.Label(title_frame, text=f"v{VERSION}", style="Sidebar.TLabel").pack(
            anchor="w"
        )

        admin_text = "Administrator" if is_admin() else "Standard User"
        admin_color = COLORS["success"] if is_admin() else COLORS["warning"]
        admin_label = ttk.Label(title_frame, text=admin_text, style="Sidebar.TLabel")
        admin_label.pack(anchor="w", pady=(2, 0))
        admin_label.configure(foreground=admin_color)

        ttk.Separator(self.sidebar, orient="horizontal").pack(
            fill=tk.X, padx=10, pady=10
        )

        # Navigation buttons
        self.nav_buttons = {}
        nav_items = [
            ("dashboard", "Dashboard"),
            ("cve", "CVE Scanner"),
            ("bsod", "BSOD Analyzer"),
            ("performance", "Performance"),
            ("hardening", "Hardening"),
            ("startup", "Startup Manager"),
            ("disk", "Disk Health"),
            ("network", "Network"),
            ("router_security", "Router Security"),
            ("security_grade", "Security Grade"),
            ("updates", "Windows Update"),
            ("history", "Scan History"),
            ("check_updates", "Check for Updates"),
        ]

        for key, label in nav_items:
            btn = ttk.Button(
                self.sidebar,
                text=f"  {label}",
                style="Sidebar.TButton",
                command=lambda k=key: self._navigate(k),
            )
            btn.pack(fill=tk.X, padx=5, pady=1)
            self.nav_buttons[key] = btn

        # Bottom sidebar buttons
        spacer = ttk.Frame(self.sidebar, style="Medium.TFrame")
        spacer.pack(fill=tk.BOTH, expand=True)

        ttk.Separator(self.sidebar, orient="horizontal").pack(
            fill=tk.X, padx=10, pady=5
        )

        resources_btn = ttk.Button(
            self.sidebar,
            text="  Resources",
            style="Sidebar.TButton",
            command=lambda: self._navigate("resources"),
        )
        resources_btn.pack(fill=tk.X, padx=5, pady=1)
        self.nav_buttons["resources"] = resources_btn

        settings_btn = ttk.Button(
            self.sidebar,
            text="  Settings",
            style="Sidebar.TButton",
            command=lambda: self._navigate("settings"),
        )
        settings_btn.pack(fill=tk.X, padx=5, pady=1)
        self.nav_buttons["settings"] = settings_btn

        ttk.Button(
            self.sidebar,
            text="  Export Report",
            style="Sidebar.TButton",
            command=self._export_report,
        ).pack(fill=tk.X, padx=5, pady=1)

        ttk.Button(
            self.sidebar,
            text="  Run Full Scan",
            style="Sidebar.TButton",
            command=self._run_full_scan,
        ).pack(fill=tk.X, padx=5, pady=1)

        # Content area
        self.content_frame = ttk.Frame(self.main_frame, style="Dark.TFrame")
        self.content_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        self.status_bar = ttk.Label(
            self.root, textvariable=self.status_var, style="Status.TLabel"
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)

    def _navigate(self, page):
        """Navigate to a page."""
        # Update sidebar button styles
        for key, btn in self.nav_buttons.items():
            if key == page:
                btn.configure(style="SidebarActive.TButton")
            else:
                btn.configure(style="Sidebar.TButton")

        self.current_page = page
        pages = {
            "dashboard": self._show_dashboard,
            "cve": self._show_cve,
            "bsod": self._show_bsod,
            "performance": self._show_performance,
            "hardening": self._show_hardening,
            "startup": self._show_startup,
            "disk": self._show_disk,
            "network": self._show_network,
            "updates": self._show_updates,
            "history": self._show_history,
            "router_security": self._show_router_security,
            "security_grade": self._show_security_grade,
            "resources": self._show_resources,
            "settings": self._show_settings,
            "check_updates": self._show_check_updates,
        }
        pages.get(page, self._show_dashboard)()

    def _clear_content(self):
        """Clear the content area."""
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def _make_scrollable(self, parent):
        """Create a scrollable frame inside parent. Returns the inner frame."""
        canvas = tk.Canvas(parent, bg=COLORS["bg_dark"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scroll_frame = ttk.Frame(canvas, style="Dark.TFrame")

        scroll_frame.bind(
            "<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas_window = canvas.create_window((0, 0), window=scroll_frame, anchor="nw")

        def on_canvas_configure(event):
            canvas.itemconfig(canvas_window, width=event.width)

        canvas.bind("<Configure>", on_canvas_configure)
        canvas.configure(yscrollcommand=scrollbar.set)

        # Mousewheel scrolling
        def on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas.bind_all("<MouseWheel>", on_mousewheel)

        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        return scroll_frame

    def _create_page_header(self, parent, title, subtitle=""):
        """Create a page header."""
        header = ttk.Frame(parent, style="Dark.TFrame")
        header.pack(fill=tk.X, padx=20, pady=(20, 10))
        ttk.Label(header, text=title, style="Title.TLabel").pack(anchor="w")
        if subtitle:
            ttk.Label(header, text=subtitle, style="Subtitle.TLabel").pack(
                anchor="w", pady=(2, 0)
            )
        return header

    def _create_result_card(self, parent, result, category="generic"):
        """Create a result card with fix button."""
        card = ttk.Frame(parent, style="Card.TFrame")
        card.pack(fill=tk.X, padx=20, pady=4)

        # Inner padding
        inner = ttk.Frame(card, style="Card.TFrame")
        inner.pack(fill=tk.X, padx=15, pady=10)

        # Top row: severity + title
        top_row = ttk.Frame(inner, style="Card.TFrame")
        top_row.pack(fill=tk.X)

        severity = result.get("severity") or result.get("impact") or result.get("status", "Unknown")
        sev_style = f"{severity}.TLabel" if severity in SEVERITY_COLORS else "Unknown.TLabel"

        severity_label = ttk.Label(
            top_row, text=f"[{severity}]", style=sev_style
        )
        severity_label.pack(side=tk.LEFT, padx=(0, 8))

        title_text = (
            result.get("issue")
            or result.get("check")
            or result.get("cve_id", "")
        )
        ttk.Label(
            top_row, text=title_text, style="CardTitle.TLabel"
        ).pack(side=tk.LEFT, fill=tk.X)

        # Description
        desc = (
            result.get("description")
            or result.get("details")
            or result.get("fix", "")
        )
        if desc:
            desc_label = ttk.Label(
                inner,
                text=desc,
                style="Card.TLabel",
                wraplength=700,
            )
            desc_label.pack(anchor="w", pady=(5, 0))

        # Extra info line
        extra_parts = []
        if result.get("affected_software"):
            extra_parts.append(f"Software: {result['affected_software']}")
        if result.get("current_value"):
            extra_parts.append(f"Current: {result['current_value']}")
        if result.get("recommended_value"):
            extra_parts.append(f"Recommended: {result['recommended_value']}")
        if extra_parts:
            ttk.Label(
                inner,
                text=" | ".join(extra_parts),
                style="Card.TLabel",
                foreground=COLORS["text_secondary"],
            ).pack(anchor="w", pady=(3, 0))

        # Manual fix instructions (CVE results)
        fix_description = result.get("fix_description") or result.get("fix")
        category = result.get("category", "")
        if fix_description and category == "cve":
            ttk.Label(
                inner,
                text=f"How to fix manually: {fix_description}",
                style="Card.TLabel",
                foreground="#4fc3f7",
                wraplength=700,
            ).pack(anchor="w", pady=(5, 0))
        elif fix_description or result.get("fix_suggestion"):
            # Non-CVE results with a fix or fix_suggestion
            fix_text = fix_description or result.get("fix_suggestion", "")
            if fix_text:
                ttk.Label(
                    inner,
                    text=f"Suggested fix: {fix_text}",
                    style="Card.TLabel",
                    foreground="#4fc3f7",
                    wraplength=700,
                ).pack(anchor="w", pady=(5, 0))

        # Fix button(s)
        fix_action = result.get("fix_action")
        fix_actions = result.get("fix_actions", [])

        btn_frame = ttk.Frame(inner, style="Card.TFrame")
        btn_frame.pack(anchor="w", pady=(8, 0))

        # New dual-action format: fix_action has "view" and/or "apply" keys
        if fix_action and isinstance(fix_action, dict):
            view_info = fix_action.get("view")
            apply_info = fix_action.get("apply")

            if view_info or apply_info:
                # New format with view/apply sub-dicts
                if view_info and view_info.get("command"):
                    btn = ttk.Button(
                        btn_frame,
                        text=f">> {view_info.get('label', 'View Advisory')}",
                        style="ViewAdvisory.TButton",
                        command=lambda url=view_info["command"]: self._open_advisory(url),
                    )
                    btn.pack(side=tk.LEFT, padx=(0, 8))

                # Download KB button (opens Microsoft Update Catalog)
                download_info = fix_action.get("download")
                if download_info and download_info.get("command"):
                    btn = ttk.Button(
                        btn_frame,
                        text=f">> {download_info.get('label', 'Download KB')}",
                        style="Accent.TButton",
                        command=lambda url=download_info["command"]: self._open_advisory(url),
                    )
                    btn.pack(side=tk.LEFT, padx=(0, 8))

                if apply_info and apply_info.get("command"):
                    btn = ttk.Button(
                        btn_frame,
                        text=f">> {apply_info.get('label', 'Apply Fix')}",
                        style="ApplyFix.TButton",
                        command=lambda info=apply_info: self._apply_local_fix(info),
                    )
                    btn.pack(side=tk.LEFT, padx=(0, 8))
            elif fix_action.get("command"):
                # Backward compat: old single-action format with "label"/"command"
                fix_actions = [fix_action] + fix_actions

        # Render any remaining fix_actions (old format or extra actions)
        for action in fix_actions[:3]:
            label = action.get("label", "Apply Fix")
            command = action.get("command", "")
            if command:
                btn = ttk.Button(
                    btn_frame,
                    text=f">> {label}",
                    style="Fix.TButton",
                    command=lambda cmd=command, lbl=label: self._execute_fix(cmd, lbl),
                )
                btn.pack(side=tk.LEFT, padx=(0, 8))

    def _open_advisory(self, url):
        """Open a CVE advisory URL in the default browser."""
        import webbrowser
        webbrowser.open(url)

    def _apply_local_fix(self, fix_info):
        """Apply a local fix from CVE scan results."""
        fix_type = fix_info.get("type", "")
        command = fix_info.get("command", "")
        description = fix_info.get("description", "Apply fix")

        confirm = messagebox.askyesno(
            "Apply Local Fix",
            f"Are you sure you want to apply this fix?\n\n"
            f"Action: {description}\n"
            f"Type: {fix_type}\n\n"
            f"Some fixes may require administrator privileges and a system restart.",
            icon="warning",
        )
        if not confirm:
            return

        self.status_var.set(f"Applying fix: {description}...")
        self.root.update()

        def run_local_fix():
            try:
                import subprocess as sp
                if fix_type == "windows_update":
                    # Open Windows Update settings
                    os.system(command)
                    self.root.after(0, lambda: messagebox.showinfo(
                        "Windows Update",
                        "Windows Update has been opened.\n"
                        "Please check for and install available updates.",
                    ))
                elif fix_type in ("command", "service_disable", "registry"):
                    if is_admin():
                        result = sp.run(
                            command, shell=True, capture_output=True,
                            text=True, timeout=120,
                            creationflags=getattr(sp, "CREATE_NO_WINDOW", 0),
                        )
                        if result.returncode == 0:
                            self.root.after(0, lambda: messagebox.showinfo(
                                "Fix Applied",
                                f"Successfully applied:\n{description}\n\n"
                                f"{result.stdout[:500] if result.stdout else 'Done.'}\n\n"
                                f"A restart may be required for changes to take effect.",
                            ))
                        else:
                            self.root.after(0, lambda: messagebox.showwarning(
                                "Warning",
                                f"Command completed with issues:\n{result.stderr[:500]}",
                            ))
                    else:
                        # Elevate via UAC
                        ctypes.windll.shell32.ShellExecuteW(
                            None, "runas", "cmd.exe", f"/c {command}", None, 1
                        )
                        self.root.after(0, lambda: messagebox.showinfo(
                            "Fix Applied",
                            f"Elevated command executed.\n{description}\n\n"
                            "A restart may be required for changes to take effect.",
                        ))
                else:
                    # Unknown type - try running as command
                    os.system(command)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror(
                    "Error", f"Failed to apply fix:\n{str(e)}"
                ))
            finally:
                self.root.after(0, lambda: self.status_var.set("Ready"))

        threading.Thread(target=run_local_fix, daemon=True).start()

    def _execute_fix(self, command, label):
        """Execute a fix action with confirmation."""
        confirm = messagebox.askyesno(
            "Apply Fix",
            f"Are you sure you want to apply this fix?\n\n"
            f"Action: {label}\n"
            f"Command: {command}\n\n"
            f"Some fixes may require administrator privileges.",
            icon="warning",
        )
        if not confirm:
            return

        self.status_var.set(f"Applying fix: {label}...")
        self.root.update()

        def run_fix():
            try:
                # Handle special commands
                if command.startswith("start "):
                    os.system(command)
                elif command.startswith("http"):
                    import webbrowser
                    webbrowser.open(command)
                else:
                    import subprocess
                    # Run elevated if possible
                    if is_admin():
                        result = subprocess.run(
                            command,
                            shell=True,
                            capture_output=True,
                            text=True,
                            timeout=120,
                        )
                        if result.returncode == 0:
                            self.root.after(
                                0,
                                lambda: messagebox.showinfo(
                                    "Success",
                                    f"Fix applied successfully!\n\n{result.stdout[:500] if result.stdout else 'Done.'}",
                                ),
                            )
                        else:
                            self.root.after(
                                0,
                                lambda: messagebox.showwarning(
                                    "Warning",
                                    f"Command completed with issues:\n{result.stderr[:500]}",
                                ),
                            )
                    else:
                        # Try to run with UAC elevation
                        ctypes.windll.shell32.ShellExecuteW(
                            None, "runas", "cmd.exe", f"/c {command}", None, 1
                        )
            except Exception as e:
                self.root.after(
                    0,
                    lambda: messagebox.showerror(
                        "Error", f"Failed to apply fix:\n{str(e)}"
                    ),
                )
            finally:
                self.root.after(0, lambda: self.status_var.set("Ready"))

        threading.Thread(target=run_fix, daemon=True).start()

    def _run_scan_threaded(self, scan_func, scan_name, callback):
        """Run a scan in a background thread."""
        self.status_var.set(f"Scanning: {scan_name}...")
        self.root.update()

        def do_scan():
            try:
                results = scan_func()
                self.root.after(0, lambda: callback(results))
                self.root.after(0, lambda: self.status_var.set("Scan complete"))
            except Exception as e:
                self.root.after(
                    0,
                    lambda: messagebox.showerror(
                        "Scan Error", f"{scan_name} failed:\n{str(e)}"
                    ),
                )
                self.root.after(0, lambda: self.status_var.set("Scan failed"))
                self.root.after(0, lambda: callback([]))

        threading.Thread(target=do_scan, daemon=True).start()

    # ===== PAGE: Dashboard =====
    def _show_dashboard(self):
        self._clear_content()
        self._navigate_highlight("dashboard")
        scroll = self._make_scrollable(self.content_frame)

        self._create_page_header(
            scroll,
            f"Welcome to {APP_NAME}",
            "Windows System Diagnostic & Optimization Tool",
        )

        # System info cards
        info_frame = ttk.Frame(scroll, style="Dark.TFrame")
        info_frame.pack(fill=tk.X, padx=20, pady=10)

        # Loading indicator
        loading = ttk.Label(
            info_frame, text="Loading system information...", style="Subtitle.TLabel"
        )
        loading.pack(anchor="w")

        def load_sysinfo():
            try:
                info = sysinfo.get_system_info()
                self.scan_results["system_info"] = info
                self.root.after(0, lambda: self._populate_dashboard(info_frame, info, loading))
            except Exception as e:
                self.root.after(
                    0, lambda: loading.configure(text=f"Error loading system info: {e}")
                )

        threading.Thread(target=load_sysinfo, daemon=True).start()

        # Quick action buttons
        action_frame = ttk.Frame(scroll, style="Dark.TFrame")
        action_frame.pack(fill=tk.X, padx=20, pady=15)

        ttk.Label(
            action_frame, text="Quick Actions", style="Title.TLabel"
        ).pack(anchor="w", pady=(0, 10))

        btn_grid = ttk.Frame(action_frame, style="Dark.TFrame")
        btn_grid.pack(fill=tk.X)

        actions = [
            ("Run Full Scan", self._run_full_scan),
            ("CVE Scan", lambda: self._navigate("cve")),
            ("BSOD Analysis", lambda: self._navigate("bsod")),
            ("Performance Check", lambda: self._navigate("performance")),
            ("Startup Manager", lambda: self._navigate("startup")),
            ("Disk Health", lambda: self._navigate("disk")),
            ("Network Test", lambda: self._navigate("network")),
            ("Check Updates", lambda: self._navigate("updates")),
        ]

        for i, (text, cmd) in enumerate(actions):
            btn = ttk.Button(btn_grid, text=text, style="Accent.TButton", command=cmd)
            btn.grid(row=i // 4, column=i % 4, padx=5, pady=5, sticky="ew")

        for col in range(4):
            btn_grid.columnconfigure(col, weight=1)

    def _populate_dashboard(self, parent, info, loading_label):
        """Populate dashboard with system info."""
        loading_label.destroy()

        # System info grid
        cards_data = [
            ("Operating System", f"{info.get('os_name', 'N/A')}\nBuild {info.get('os_build', 'N/A')}"),
            ("Processor", info.get("cpu_name", "N/A")),
            ("Memory", f"{info.get('ram_total', 'N/A')} total\n{info.get('ram_available', 'N/A')} available"),
            ("Graphics", info.get("gpu_name", "N/A")),
            ("Computer", f"{info.get('computer_name', 'N/A')}\n{info.get('username', 'N/A')}"),
            ("Uptime", info.get("uptime", "N/A")),
        ]

        grid = ttk.Frame(parent, style="Dark.TFrame")
        grid.pack(fill=tk.X)

        for i, (title, value) in enumerate(cards_data):
            card = ttk.Frame(grid, style="Card.TFrame")
            card.grid(row=i // 3, column=i % 3, padx=5, pady=5, sticky="nsew")

            inner = ttk.Frame(card, style="Card.TFrame")
            inner.pack(fill=tk.BOTH, padx=12, pady=10)

            ttk.Label(inner, text=title, style="CardTitle.TLabel").pack(anchor="w")
            ttk.Label(
                inner,
                text=str(value),
                style="Card.TLabel",
                wraplength=300,
            ).pack(anchor="w", pady=(4, 0))

        for col in range(3):
            grid.columnconfigure(col, weight=1)

    def _navigate_highlight(self, page):
        """Highlight the active nav button."""
        for key, btn in self.nav_buttons.items():
            if key == page:
                btn.configure(style="SidebarActive.TButton")
            else:
                btn.configure(style="Sidebar.TButton")

    # ===== PAGE: CVE Scanner =====
    def _show_cve(self):
        self._clear_content()
        self._navigate_highlight("cve")
        scroll = self._make_scrollable(self.content_frame)

        header = self._create_page_header(
            scroll,
            "CVE Scanner",
            "Check your system against known vulnerabilities",
        )

        # CVE database stats
        stats = cve_scanner.get_cve_db_stats()
        stats_frame = ttk.Frame(header, style="Dark.TFrame")
        stats_frame.pack(anchor="w", pady=(5, 0))
        ttk.Label(
            stats_frame,
            text=f"Database: {stats['total']} CVEs | Last updated: {stats['last_updated']}",
            style="Subtitle.TLabel",
        ).pack(side=tk.LEFT)

        # Action buttons row
        btn_frame = ttk.Frame(header, style="Dark.TFrame")
        btn_frame.pack(anchor="w", pady=(10, 0))

        ttk.Button(
            btn_frame,
            text="Scan Now",
            style="Accent.TButton",
            command=lambda: self._run_cve_scan(scroll),
        ).pack(side=tk.LEFT, padx=(0, 8))

        ttk.Button(
            btn_frame,
            text="Fetch from NVD",
            style="Accent.TButton",
            command=lambda: self._fetch_nvd_cves(scroll),
        ).pack(side=tk.LEFT, padx=(0, 8))

        ttk.Button(
            btn_frame,
            text="Import File",
            style="Accent.TButton",
            command=lambda: self._import_cve_file(scroll),
        ).pack(side=tk.LEFT, padx=(0, 8))

        ttk.Button(
            btn_frame,
            text="Import Folder",
            style="Accent.TButton",
            command=lambda: self._import_cve_folder(scroll),
        ).pack(side=tk.LEFT, padx=(0, 8))

        ttk.Button(
            btn_frame,
            text="Add Manually",
            style="Accent.TButton",
            command=self._add_cve_manually_dialog,
        ).pack(side=tk.LEFT)

        # --- Drag & drop zone ---
        drop_frame = tk.Frame(scroll, bg="#1a2332", highlightbackground="#e74c6f",
                              highlightthickness=2, cursor="hand2")
        drop_frame.pack(fill=tk.X, padx=20, pady=(15, 5))
        drop_inner = tk.Frame(drop_frame, bg="#1a2332")
        drop_inner.pack(padx=20, pady=15)
        tk.Label(
            drop_inner, text="Drag & Drop CVE Files or Folders Here",
            bg="#1a2332", fg="#8899aa", font=("Segoe UI", 11),
        ).pack()
        tk.Label(
            drop_inner, text="Supports: Individual .json files, folders with CVE 5.x records, or .csv files",
            bg="#1a2332", fg="#556677", font=("Segoe UI", 9),
        ).pack()
        tk.Label(
            drop_inner,
            text="(Or click 'Import File' / 'Import Folder' buttons above)",
            bg="#1a2332", fg="#556677", font=("Segoe UI", 9, "italic"),
        ).pack()
        # Bind drop target using Windows OLE drag-drop via tkdnd if available,
        # otherwise this is a visual hint to use the buttons
        self._setup_drop_target(drop_frame, scroll)

        # Show cached results if available
        if "cve" in self.scan_results:
            self._display_results(scroll, self.scan_results["cve"], "cve")

    def _run_cve_scan(self, parent):
        def on_results(results):
            self.scan_results["cve"] = results
            try:
                history.save_scan("cve", results)
            except Exception:
                pass
            self._display_results(parent, results, "cve")

        self._run_scan_threaded(cve_scanner.scan_cves, "CVE Scanner", on_results)

    def _fetch_nvd_cves(self, parent):
        """Fetch CVEs from NVD API in background."""
        self.status_var.set("Fetching CVEs from NVD...")
        self.root.update()

        def do_fetch():
            try:
                stats = cve_scanner.fetch_nvd_cves()
                self.root.after(0, lambda: messagebox.showinfo(
                    "NVD Fetch Complete",
                    f"Fetched: {stats['fetched']}\n"
                    f"Imported: {stats['imported']}\n"
                    f"Skipped (duplicates): {stats['skipped']}\n"
                    f"Errors: {stats['errors']}",
                ))
                self.root.after(0, lambda: self._show_cve())  # Refresh page
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror(
                    "NVD Fetch Failed", str(e),
                ))
            finally:
                self.root.after(0, lambda: self.status_var.set("Ready"))

        threading.Thread(target=do_fetch, daemon=True).start()

    def _import_cve_file(self, parent):
        """Import CVEs from a JSON or CSV file."""
        filepath = filedialog.askopenfilename(
            title="Import CVE Database",
            filetypes=[
                ("JSON files", "*.json"),
                ("CSV files", "*.csv"),
                ("All files", "*.*"),
            ],
        )
        if not filepath:
            return

        self.status_var.set("Importing CVEs...")
        self.root.update()

        def do_import():
            try:
                stats = cve_scanner.import_cves_from_file(filepath)
                self.root.after(0, lambda: messagebox.showinfo(
                    "Import Complete",
                    f"Imported: {stats['imported']}\n"
                    f"Skipped (duplicates): {stats['skipped']}\n"
                    f"Errors: {stats['errors']}",
                ))
                self.root.after(0, lambda: self._show_cve())  # Refresh page
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror(
                    "Import Failed", str(e),
                ))
            finally:
                self.root.after(0, lambda: self.status_var.set("Ready"))

        threading.Thread(target=do_import, daemon=True).start()

    def _import_cve_folder(self, parent):
        """Import CVEs from a folder of CVE 5.x JSON files (e.g., cve.org download)."""
        folder = filedialog.askdirectory(title="Select CVE Folder (e.g., CVE-List or year folder)")
        if not folder:
            return

        # Ask whether to filter by vendor
        filter_choice = messagebox.askyesnocancel(
            "Filter CVEs",
            "Do you want to import only Windows/Microsoft CVEs?\n\n"
            "Yes = Microsoft/Windows only\n"
            "No = Import ALL CVEs (may be thousands)\n"
            "Cancel = Abort",
        )
        if filter_choice is None:
            return

        vendor_filter = ["microsoft", "windows"] if filter_choice else None

        self.status_var.set("Scanning folder for CVE files...")
        self.root.update()

        def do_folder_import():
            try:
                def progress_cb(done, total):
                    self.root.after(0, lambda d=done, t=total:
                        self.status_var.set(f"Processing CVE files... {d}/{t}"))

                stats = cve_scanner.import_cves_from_folder(
                    folder, filter_vendors=vendor_filter, progress_callback=progress_cb,
                )
                filter_text = " (Microsoft/Windows filter)" if vendor_filter else " (all vendors)"
                self.root.after(0, lambda: messagebox.showinfo(
                    "Folder Import Complete",
                    f"Files scanned: {stats['scanned']}\n"
                    f"Imported: {stats['imported']}{filter_text}\n"
                    f"Skipped (duplicates/filtered): {stats['skipped']}\n"
                    f"Errors: {stats['errors']}",
                ))
                self.root.after(0, lambda: self._show_cve())
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror(
                    "Folder Import Failed", str(e),
                ))
            finally:
                self.root.after(0, lambda: self.status_var.set("Ready"))

        threading.Thread(target=do_folder_import, daemon=True).start()

    def _setup_drop_target(self, drop_widget, parent_scroll):
        """Set up drag-and-drop file/folder import on the given widget.

        Uses tkdnd (tkinterdnd2) if available, otherwise falls back to
        making the drop zone clickable as a file/folder picker.
        """
        try:
            # Try to enable tkdnd if the extension is available
            self.root.tk.eval('package require tkdnd')
            drop_widget.tk.call('tkdnd::drop_target', 'register', drop_widget._w, ('DND_Files',))

            def on_drop(event):
                # event.data contains space-separated paths (braces around paths with spaces)
                paths = self.root.tk.splitlist(event.data) if hasattr(event, 'data') else []
                self._handle_dropped_paths(list(paths), parent_scroll)
                return event.action if hasattr(event, 'action') else 'copy'

            drop_widget.bind('<<Drop>>', on_drop)
        except Exception:
            # tkdnd not available - make the zone clickable as a fallback
            def on_click(event):
                choice = messagebox.askyesno(
                    "Import CVEs",
                    "Would you like to select a folder?\n\n"
                    "Yes = Select folder of CVE files\n"
                    "No = Select individual file(s)",
                )
                if choice:
                    self._import_cve_folder(parent_scroll)
                else:
                    self._import_cve_file(parent_scroll)

            drop_widget.bind('<Button-1>', on_click)
            for child in drop_widget.winfo_children():
                child.bind('<Button-1>', on_click)
                for grandchild in child.winfo_children():
                    grandchild.bind('<Button-1>', on_click)

    def _handle_dropped_paths(self, paths, parent_scroll):
        """Process dropped files/folders for CVE import."""
        if not paths:
            return

        folders = [p for p in paths if os.path.isdir(p)]
        files = [p for p in paths if os.path.isfile(p) and p.lower().endswith(('.json', '.csv'))]

        if not folders and not files:
            messagebox.showwarning("No CVE Files", "No .json or .csv files or folders found in drop.")
            return

        self.status_var.set("Processing dropped files...")
        self.root.update()

        def do_drop_import():
            total_stats = {"scanned": 0, "imported": 0, "skipped": 0, "errors": 0}

            # Import individual files
            for fpath in files:
                try:
                    # Check if it's a CVE 5.x individual file or a WinnyTool-format file
                    with open(fpath, "r", encoding="utf-8") as f:
                        data = json.load(f)

                    if isinstance(data, dict) and data.get("dataType") == "CVE_RECORD":
                        # Single CVE 5.x file - use folder import on parent dir
                        parsed = cve_scanner._parse_cve5_record(data)
                        if parsed:
                            try:
                                cve_scanner.add_cve_manually(parsed)
                                total_stats["imported"] += 1
                            except ValueError:
                                total_stats["skipped"] += 1
                        else:
                            total_stats["errors"] += 1
                    else:
                        # WinnyTool format or list format
                        stats = cve_scanner.import_cves_from_file(fpath)
                        total_stats["imported"] += stats["imported"]
                        total_stats["skipped"] += stats["skipped"]
                        total_stats["errors"] += stats["errors"]
                    total_stats["scanned"] += 1
                except Exception:
                    total_stats["errors"] += 1
                    total_stats["scanned"] += 1

            # Import folders
            for folder in folders:
                try:
                    stats = cve_scanner.import_cves_from_folder(folder)
                    total_stats["scanned"] += stats["scanned"]
                    total_stats["imported"] += stats["imported"]
                    total_stats["skipped"] += stats["skipped"]
                    total_stats["errors"] += stats["errors"]
                except Exception:
                    total_stats["errors"] += 1

            self.root.after(0, lambda: messagebox.showinfo(
                "Drop Import Complete",
                f"Files scanned: {total_stats['scanned']}\n"
                f"Imported: {total_stats['imported']}\n"
                f"Skipped: {total_stats['skipped']}\n"
                f"Errors: {total_stats['errors']}",
            ))
            self.root.after(0, lambda: self._show_cve())
            self.root.after(0, lambda: self.status_var.set("Ready"))

        threading.Thread(target=do_drop_import, daemon=True).start()

    def _add_cve_manually_dialog(self):
        """Show a dialog to manually add a CVE entry."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add CVE Manually")
        dialog.geometry("550x520")
        dialog.configure(bg=COLORS["bg_dark"])
        dialog.transient(self.root)
        dialog.grab_set()

        fields = {}
        field_defs = [
            ("cve_id", "CVE ID (e.g., CVE-2024-12345):", ""),
            ("severity", "Severity:", "Medium"),
            ("description", "Description:", ""),
            ("affected_software", "Affected Software:", ""),
            ("affected_versions", "Affected Versions (comma-separated):", ""),
            ("fix_description", "Fix Description:", ""),
            ("kb_patch", "KB Patch (optional):", ""),
            ("reference_url", "Reference URL (optional):", ""),
        ]

        for key, label, default in field_defs:
            lbl = tk.Label(
                dialog, text=label, bg=COLORS["bg_dark"],
                fg=COLORS["text_primary"], font=("Segoe UI", 10),
            )
            lbl.pack(anchor="w", padx=15, pady=(8, 2))

            if key == "severity":
                var = tk.StringVar(value=default)
                combo = ttk.Combobox(
                    dialog, textvariable=var,
                    values=["Critical", "High", "Medium", "Low"],
                    state="readonly", width=40,
                )
                combo.pack(anchor="w", padx=15)
                fields[key] = var
            elif key == "description":
                txt = tk.Text(
                    dialog, height=3, width=50,
                    bg=COLORS["card_bg"], fg=COLORS["text_primary"],
                    insertbackground=COLORS["text_primary"],
                    font=("Segoe UI", 10),
                )
                txt.pack(anchor="w", padx=15)
                fields[key] = txt
            else:
                var = tk.StringVar(value=default)
                entry = tk.Entry(
                    dialog, textvariable=var, width=55,
                    bg=COLORS["card_bg"], fg=COLORS["text_primary"],
                    insertbackground=COLORS["text_primary"],
                    font=("Segoe UI", 10),
                )
                entry.pack(anchor="w", padx=15)
                fields[key] = var

        def submit():
            try:
                desc = fields["description"].get("1.0", tk.END).strip() if isinstance(fields["description"], tk.Text) else fields["description"].get()
                versions_raw = fields["affected_versions"].get()
                versions = [v.strip() for v in versions_raw.split(",") if v.strip()]

                cve_dict = {
                    "cve_id": fields["cve_id"].get().strip(),
                    "severity": fields["severity"].get(),
                    "description": desc,
                    "affected_software": fields["affected_software"].get().strip(),
                    "affected_versions": versions,
                    "fix_description": fields["fix_description"].get().strip(),
                    "kb_patch": fields["kb_patch"].get().strip() or None,
                    "reference_url": fields["reference_url"].get().strip(),
                }

                cve_id = cve_scanner.add_cve_manually(cve_dict)
                messagebox.showinfo("Success", f"{cve_id} added to database.")
                dialog.destroy()
                self._show_cve()  # Refresh
            except (ValueError, RuntimeError) as e:
                messagebox.showerror("Error", str(e))

        btn_frame = tk.Frame(dialog, bg=COLORS["bg_dark"])
        btn_frame.pack(pady=15)

        ttk.Button(btn_frame, text="Add CVE", style="Accent.TButton", command=submit).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(btn_frame, text="Cancel", style="Sidebar.TButton", command=dialog.destroy).pack(
            side=tk.LEFT, padx=5
        )

    # ===== PAGE: BSOD Analyzer =====
    def _show_bsod(self):
        self._clear_content()
        self._navigate_highlight("bsod")
        scroll = self._make_scrollable(self.content_frame)

        header = self._create_page_header(
            scroll,
            "BSOD Analyzer",
            "Review recent Blue Screen of Death events with fix suggestions",
        )

        scan_btn = ttk.Button(
            header,
            text="Analyze BSODs",
            style="Accent.TButton",
            command=lambda: self._run_bsod_scan(scroll),
        )
        scan_btn.pack(anchor="w", pady=(10, 0))

        if "bsod" in self.scan_results:
            self._display_bsod_results(scroll, self.scan_results["bsod"])

    def _run_bsod_scan(self, parent):
        def on_results(results):
            self.scan_results["bsod"] = results
            try:
                history.save_scan("bsod", results)
            except Exception:
                pass
            self._display_bsod_results(parent, results)

        self._run_scan_threaded(
            bsod_analyzer.get_recent_bsods, "BSOD Analyzer", on_results
        )

    def _display_bsod_results(self, parent, results):
        """Display BSOD results with detailed cards."""
        # Clear previous results
        for w in parent.winfo_children():
            if isinstance(w, ttk.Frame) and w.cget("style") == "Card.TFrame":
                w.destroy()

        if not results:
            ttk.Label(
                parent,
                text="No BSOD events found. Your system appears stable!",
                style="Subtitle.TLabel",
            ).pack(padx=20, pady=20, anchor="w")
            return

        count_label = ttk.Label(
            parent,
            text=f"Found {len(results)} BSOD event(s)",
            style="Subtitle.TLabel",
        )
        count_label.pack(padx=20, pady=(10, 5), anchor="w")

        for bsod in results:
            card = ttk.Frame(parent, style="Card.TFrame")
            card.pack(fill=tk.X, padx=20, pady=4)

            inner = ttk.Frame(card, style="Card.TFrame")
            inner.pack(fill=tk.X, padx=15, pady=10)

            # Header
            top = ttk.Frame(inner, style="Card.TFrame")
            top.pack(fill=tk.X)

            ttk.Label(
                top,
                text="[Critical]",
                style="Critical.TLabel",
            ).pack(side=tk.LEFT, padx=(0, 8))

            stop_name = bsod.get("stop_code_name", "Unknown")
            stop_code = bsod.get("stop_code", "N/A")
            ttk.Label(
                top,
                text=f"{stop_name} ({stop_code})",
                style="CardTitle.TLabel",
            ).pack(side=tk.LEFT)

            ttk.Label(
                top,
                text=bsod.get("date", ""),
                style="Card.TLabel",
                foreground=COLORS["text_secondary"],
            ).pack(side=tk.RIGHT)

            # Parameters
            if bsod.get("parameters"):
                ttk.Label(
                    inner,
                    text=f"Parameters: {bsod['parameters']}",
                    style="Card.TLabel",
                    foreground=COLORS["text_secondary"],
                ).pack(anchor="w", pady=(5, 0))

            # Common causes
            causes = bsod.get("common_causes", [])
            if causes:
                ttk.Label(
                    inner,
                    text="Common Causes:",
                    style="CardTitle.TLabel",
                ).pack(anchor="w", pady=(8, 2))
                for cause in causes:
                    ttk.Label(
                        inner,
                        text=f"  - {cause}",
                        style="Card.TLabel",
                        wraplength=700,
                    ).pack(anchor="w")

            # Fix suggestions
            suggestions = bsod.get("fix_suggestions", [])
            if suggestions:
                ttk.Label(
                    inner,
                    text="Suggested Fixes:",
                    style="CardTitle.TLabel",
                ).pack(anchor="w", pady=(8, 2))
                for sug in suggestions:
                    ttk.Label(
                        inner,
                        text=f"  - {sug}",
                        style="Card.TLabel",
                        wraplength=700,
                    ).pack(anchor="w")

            # Fix action buttons
            actions = bsod.get("fix_actions", [])
            if actions:
                btn_frame = ttk.Frame(inner, style="Card.TFrame")
                btn_frame.pack(anchor="w", pady=(8, 0))
                for action in actions[:4]:
                    label = action.get("label", "Fix")
                    command = action.get("command", "")
                    if command:
                        ttk.Button(
                            btn_frame,
                            text=f">> {label}",
                            style="Fix.TButton",
                            command=lambda c=command, l=label: self._execute_fix(c, l),
                        ).pack(side=tk.LEFT, padx=(0, 8))

    # ===== PAGE: Performance =====
    def _show_performance(self):
        self._clear_content()
        self._navigate_highlight("performance")
        scroll = self._make_scrollable(self.content_frame)

        header = self._create_page_header(
            scroll,
            "Performance Optimizer",
            "Detect settings that may be slowing down your system",
        )

        scan_btn = ttk.Button(
            header,
            text="Scan Performance",
            style="Accent.TButton",
            command=lambda: self._run_perf_scan(scroll),
        )
        scan_btn.pack(anchor="w", pady=(10, 0))

        if "performance" in self.scan_results:
            self._display_results(scroll, self.scan_results["performance"], "performance")

    def _run_perf_scan(self, parent):
        def on_results(results):
            self.scan_results["performance"] = results
            try:
                history.save_scan("performance", results)
            except Exception:
                pass
            self._display_results(parent, results, "performance")

        self._run_scan_threaded(
            performance.scan_performance, "Performance Optimizer", on_results
        )

    # ===== PAGE: System Hardening =====
    def _show_hardening(self):
        self._clear_content()
        self._navigate_highlight("hardening")
        scroll = self._make_scrollable(self.content_frame)

        header = self._create_page_header(
            scroll,
            "System Hardening",
            "Security hardening recommendations in three tiers",
        )

        # Tier selector
        tier_frame = ttk.Frame(header, style="Dark.TFrame")
        tier_frame.pack(anchor="w", pady=(10, 0))

        self._hardening_tier = tk.StringVar(value="Basic")

        tier_descriptions = {
            "Basic": "Safe for everyone - essential security settings",
            "Moderate": "Recommended for most users - stronger protections",
            "Aggressive": "Maximum security - may break some workflows",
        }

        for tier in ["Basic", "Moderate", "Aggressive"]:
            rb = tk.Radiobutton(
                tier_frame,
                text=f" {tier}",
                variable=self._hardening_tier,
                value=tier,
                bg=COLORS["bg_dark"],
                fg=COLORS["text_primary"],
                selectcolor=COLORS["bg_light"],
                activebackground=COLORS["bg_dark"],
                activeforeground=COLORS["accent"],
                font=("Segoe UI", 11, "bold"),
                indicatoron=True,
                command=lambda: self._refresh_hardening(scroll),
            )
            rb.pack(side=tk.LEFT, padx=(0, 20))

        # Tier description
        self._tier_desc_label = ttk.Label(
            header,
            text=tier_descriptions["Basic"],
            style="Subtitle.TLabel",
        )
        self._tier_desc_label.pack(anchor="w", pady=(5, 0))

        # Buttons
        btn_frame = ttk.Frame(header, style="Dark.TFrame")
        btn_frame.pack(anchor="w", pady=(10, 0))

        ttk.Button(
            btn_frame,
            text="Scan Current Status",
            style="Accent.TButton",
            command=lambda: self._run_hardening_scan(scroll),
        ).pack(side=tk.LEFT, padx=(0, 8))

        ttk.Button(
            btn_frame,
            text="Apply All for This Tier",
            style="Accent.TButton",
            command=lambda: self._apply_all_hardening(),
        ).pack(side=tk.LEFT)

        # Results container
        self._hardening_results_frame = ttk.Frame(scroll, style="Dark.TFrame")
        self._hardening_results_frame.pack(fill=tk.X)

        if "hardening" in self.scan_results:
            self._display_hardening_results(self.scan_results["hardening"])

    def _refresh_hardening(self, scroll):
        """Refresh hardening display when tier changes."""
        tier = self._hardening_tier.get()
        tier_descriptions = {
            "Basic": "Safe for everyone - essential security settings",
            "Moderate": "Recommended for most users - stronger protections",
            "Aggressive": "Maximum security - may break some workflows",
        }
        self._tier_desc_label.configure(text=tier_descriptions.get(tier, ""))
        if "hardening" in self.scan_results:
            self._display_hardening_results(self.scan_results["hardening"])

    def _run_hardening_scan(self, scroll):
        """Run hardening scan in background."""
        def on_results(results):
            self.scan_results["hardening"] = results
            self._display_hardening_results(results)

        self._run_scan_threaded(
            hardening.scan_hardening, "System Hardening", on_results
        )

    def _display_hardening_results(self, results):
        """Display hardening results filtered by selected tier."""
        # Clear previous
        for w in self._hardening_results_frame.winfo_children():
            w.destroy()

        selected_tier = self._hardening_tier.get()
        tier_order = ["Basic", "Moderate", "Aggressive"]
        max_tier_idx = tier_order.index(selected_tier)
        allowed_tiers = set(tier_order[: max_tier_idx + 1])

        filtered = [r for r in results if r.get("tier") in allowed_tiers]

        if not filtered:
            ttk.Label(
                self._hardening_results_frame,
                text="No settings found. Run a scan first.",
                style="Subtitle.TLabel",
            ).pack(padx=20, pady=20)
            return

        # Group by tier
        for tier in tier_order:
            if tier not in allowed_tiers:
                continue
            tier_items = [r for r in filtered if r.get("tier") == tier]
            if not tier_items:
                continue

            # Tier header
            tier_header = ttk.Frame(self._hardening_results_frame, style="Dark.TFrame")
            tier_header.pack(fill=tk.X, padx=20, pady=(15, 5))

            tier_color = {"Basic": COLORS["success"], "Moderate": COLORS["warning"], "Aggressive": COLORS["critical"]}
            tier_lbl = ttk.Label(
                tier_header,
                text=f"{tier} Tier",
                style="Title.TLabel",
            )
            tier_lbl.pack(anchor="w")
            tier_lbl.configure(foreground=tier_color.get(tier, COLORS["text_primary"]))

            for item in tier_items:
                card = ttk.Frame(self._hardening_results_frame, style="Card.TFrame")
                card.pack(fill=tk.X, padx=20, pady=4)

                inner = ttk.Frame(card, style="Card.TFrame")
                inner.pack(fill=tk.X, padx=15, pady=10)

                # Top row: status icon + setting name
                top = ttk.Frame(inner, style="Card.TFrame")
                top.pack(fill=tk.X)

                status = item.get("status", "Unknown")
                recommended = item.get("recommended", "Enable")
                # Determine if current state matches recommendation
                is_compliant = (
                    (status == "Enabled" and recommended == "Enable")
                    or (status == "Disabled" and recommended == "Disable")
                )

                status_text = "PASS" if is_compliant else "NEEDS FIX"
                status_color = COLORS["success"] if is_compliant else COLORS["critical"]

                status_lbl = ttk.Label(top, text=f"[{status_text}]", style="Card.TLabel")
                status_lbl.pack(side=tk.LEFT, padx=(0, 8))
                status_lbl.configure(foreground=status_color, font=("Segoe UI", 10, "bold"))

                ttk.Label(
                    top, text=item.get("setting", ""), style="CardTitle.TLabel"
                ).pack(side=tk.LEFT)

                ttk.Label(
                    top, text=f"Currently: {status}", style="Card.TLabel",
                    foreground=COLORS["text_secondary"],
                ).pack(side=tk.RIGHT)

                # Description
                ttk.Label(
                    inner, text=item.get("description", ""),
                    style="Card.TLabel", wraplength=700,
                ).pack(anchor="w", pady=(5, 0))

                # Pros and Cons side by side
                pros_cons = ttk.Frame(inner, style="Card.TFrame")
                pros_cons.pack(fill=tk.X, pady=(8, 0))

                # Pros
                pros_frame = ttk.Frame(pros_cons, style="Card.TFrame")
                pros_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, anchor="n")

                pros_title = ttk.Label(pros_frame, text="Pros:", style="Card.TLabel")
                pros_title.pack(anchor="w")
                pros_title.configure(foreground=COLORS["success"], font=("Segoe UI", 9, "bold"))

                for pro in item.get("pros", []):
                    pro_lbl = ttk.Label(
                        pros_frame, text=f"  + {pro}",
                        style="Card.TLabel", wraplength=340,
                    )
                    pro_lbl.pack(anchor="w")
                    pro_lbl.configure(foreground=COLORS["success"])

                # Cons
                cons_frame = ttk.Frame(pros_cons, style="Card.TFrame")
                cons_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, anchor="n")

                cons_title = ttk.Label(cons_frame, text="Cons:", style="Card.TLabel")
                cons_title.pack(anchor="w")
                cons_title.configure(foreground=COLORS["warning"], font=("Segoe UI", 9, "bold"))

                for con in item.get("cons", []):
                    con_lbl = ttk.Label(
                        cons_frame, text=f"  - {con}",
                        style="Card.TLabel", wraplength=340,
                    )
                    con_lbl.pack(anchor="w")
                    con_lbl.configure(foreground=COLORS["warning"])

                # Fix button (only show if not compliant)
                if not is_compliant:
                    fix = item.get("fix_action", {})
                    if fix and fix.get("command"):
                        btn_fr = ttk.Frame(inner, style="Card.TFrame")
                        btn_fr.pack(anchor="w", pady=(8, 0))
                        ttk.Button(
                            btn_fr,
                            text=f">> {fix.get('label', 'Apply Fix')}",
                            style="Fix.TButton",
                            command=lambda c=fix["command"], l=fix["label"]: self._execute_fix(c, l),
                        ).pack(side=tk.LEFT)

    def _apply_all_hardening(self):
        """Apply all hardening fixes for the selected tier."""
        if "hardening" not in self.scan_results:
            messagebox.showinfo("No Data", "Run a hardening scan first.")
            return

        tier = self._hardening_tier.get()
        tier_order = ["Basic", "Moderate", "Aggressive"]
        max_tier_idx = tier_order.index(tier)
        allowed_tiers = set(tier_order[: max_tier_idx + 1])

        fixes = []
        for item in self.scan_results["hardening"]:
            if item.get("tier") not in allowed_tiers:
                continue
            status = item.get("status", "Unknown")
            recommended = item.get("recommended", "Enable")
            is_compliant = (
                (status == "Enabled" and recommended == "Enable")
                or (status == "Disabled" and recommended == "Disable")
            )
            if not is_compliant:
                fix = item.get("fix_action", {})
                if fix and fix.get("command"):
                    fixes.append(fix)

        if not fixes:
            messagebox.showinfo("All Good", f"All {tier} tier settings are already compliant!")
            return

        confirm = messagebox.askyesno(
            "Apply All Fixes",
            f"Apply {len(fixes)} fix(es) for {tier} tier and below?\n\n"
            f"This will modify system settings. Some changes may require a restart.\n"
            f"Administrator privileges are required.",
            icon="warning",
        )
        if not confirm:
            return

        self.status_var.set(f"Applying {len(fixes)} hardening fixes...")
        self.root.update()

        def apply_all():
            success = 0
            failed = 0
            for fix in fixes:
                try:
                    import subprocess as sp
                    cmd = fix["command"]
                    if cmd.startswith("powershell"):
                        sp.run(cmd, shell=True, capture_output=True, timeout=30,
                               creationflags=getattr(sp, "CREATE_NO_WINDOW", 0))
                    elif cmd.startswith("start "):
                        os.system(cmd)
                    else:
                        sp.run(cmd, shell=True, capture_output=True, timeout=30,
                               creationflags=getattr(sp, "CREATE_NO_WINDOW", 0))
                    success += 1
                except Exception:
                    failed += 1

            self.root.after(0, lambda: messagebox.showinfo(
                "Hardening Complete",
                f"Applied: {success}\nFailed: {failed}\n\n"
                f"Some changes may require a restart to take effect.",
            ))
            self.root.after(0, lambda: self.status_var.set("Ready"))
            # Re-scan to update status
            self.root.after(500, lambda: self._show_hardening())

        threading.Thread(target=apply_all, daemon=True).start()

    # ===== PAGE: Startup Manager =====
    def _show_startup(self):
        self._clear_content()
        self._navigate_highlight("startup")
        scroll = self._make_scrollable(self.content_frame)

        header = self._create_page_header(
            scroll,
            "Startup Manager",
            "Manage programs that run at startup",
        )

        scan_btn = ttk.Button(
            header,
            text="Scan Startup Items",
            style="Accent.TButton",
            command=lambda: self._run_startup_scan(scroll),
        )
        scan_btn.pack(anchor="w", pady=(10, 0))

        if "startup" in self.scan_results:
            self._display_startup_results(scroll, self.scan_results["startup"])

    def _run_startup_scan(self, parent):
        def on_results(results):
            self.scan_results["startup"] = results
            self._display_startup_results(parent, results)

        self._run_scan_threaded(
            startup_mgr.get_startup_items, "Startup Manager", on_results
        )

    def _display_startup_results(self, parent, results):
        for w in parent.winfo_children():
            if isinstance(w, ttk.Frame) and w.cget("style") == "Card.TFrame":
                w.destroy()

        if not results:
            ttk.Label(parent, text="No startup items found.", style="Subtitle.TLabel").pack(
                padx=20, pady=20
            )
            return

        ttk.Label(
            parent,
            text=f"Found {len(results)} startup item(s)",
            style="Subtitle.TLabel",
        ).pack(padx=20, pady=(10, 5), anchor="w")

        for item in results:
            card = ttk.Frame(parent, style="Card.TFrame")
            card.pack(fill=tk.X, padx=20, pady=4)

            inner = ttk.Frame(card, style="Card.TFrame")
            inner.pack(fill=tk.X, padx=15, pady=10)

            top = ttk.Frame(inner, style="Card.TFrame")
            top.pack(fill=tk.X)

            impact = item.get("impact", "Unknown")
            sev_style = f"{impact}.TLabel" if impact in SEVERITY_COLORS else "Unknown.TLabel"
            ttk.Label(top, text=f"[{impact}]", style=sev_style).pack(
                side=tk.LEFT, padx=(0, 8)
            )

            ttk.Label(
                top, text=item.get("name", "Unknown"), style="CardTitle.TLabel"
            ).pack(side=tk.LEFT)

            enabled = item.get("enabled", True)
            status_text = "Enabled" if enabled else "Disabled"
            status_color = COLORS["warning"] if enabled else COLORS["text_secondary"]
            status_l = ttk.Label(top, text=status_text, style="Card.TLabel")
            status_l.pack(side=tk.RIGHT)
            status_l.configure(foreground=status_color)

            ttk.Label(
                inner,
                text=f"Command: {item.get('command', 'N/A')}",
                style="Card.TLabel",
                foreground=COLORS["text_secondary"],
            ).pack(anchor="w", pady=(4, 0))

            ttk.Label(
                inner,
                text=f"Location: {item.get('location', 'N/A')}",
                style="Card.TLabel",
                foreground=COLORS["text_secondary"],
            ).pack(anchor="w")

            if enabled and impact in ("High", "Medium"):
                btn_frame = ttk.Frame(inner, style="Card.TFrame")
                btn_frame.pack(anchor="w", pady=(6, 0))
                ttk.Button(
                    btn_frame,
                    text=">> Disable",
                    style="Fix.TButton",
                    command=lambda n=item["name"], l=item["location"]: self._disable_startup(
                        n, l
                    ),
                ).pack(side=tk.LEFT)

    def _disable_startup(self, name, location):
        confirm = messagebox.askyesno(
            "Disable Startup Item",
            f"Disable '{name}' from starting with Windows?\n\nLocation: {location}",
        )
        if confirm:
            try:
                startup_mgr.disable_startup_item(name, location)
                messagebox.showinfo("Success", f"'{name}' has been disabled.")
                self._show_startup()  # Refresh
            except Exception as e:
                messagebox.showerror("Error", f"Failed to disable: {e}")

    # ===== PAGE: Disk Health =====
    def _show_disk(self):
        self._clear_content()
        self._navigate_highlight("disk")
        scroll = self._make_scrollable(self.content_frame)

        header = self._create_page_header(
            scroll, "Disk Health", "Check disk status and cleanup opportunities"
        )

        scan_btn = ttk.Button(
            header,
            text="Scan Disks",
            style="Accent.TButton",
            command=lambda: self._run_disk_scan(scroll),
        )
        scan_btn.pack(anchor="w", pady=(10, 0))

        if "disk" in self.scan_results:
            self._display_results(scroll, self.scan_results["disk"], "disk")

    def _run_disk_scan(self, parent):
        def on_results(results):
            self.scan_results["disk"] = results
            try:
                history.save_scan("disk", results)
            except Exception:
                pass
            self._display_results(parent, results, "disk")

        self._run_scan_threaded(disk_health.scan_disk_health, "Disk Health", on_results)

    # ===== PAGE: Network =====
    def _show_network(self):
        self._clear_content()
        self._navigate_highlight("network")
        scroll = self._make_scrollable(self.content_frame)

        header = self._create_page_header(
            scroll, "Network Diagnostics", "Test connectivity and detect misconfigurations"
        )

        scan_btn = ttk.Button(
            header,
            text="Run Diagnostics",
            style="Accent.TButton",
            command=lambda: self._run_net_scan(scroll),
        )
        scan_btn.pack(anchor="w", pady=(10, 0))

        if "network" in self.scan_results:
            self._display_results(scroll, self.scan_results["network"], "network")

    def _run_net_scan(self, parent):
        def on_results(results):
            self.scan_results["network"] = results
            try:
                history.save_scan("network", results)
            except Exception:
                pass
            self._display_results(parent, results, "network")

        self._run_scan_threaded(network_diag.scan_network, "Network Diagnostics", on_results)

    # ===== PAGE: Windows Update =====
    def _show_updates(self):
        self._clear_content()
        self._navigate_highlight("updates")
        scroll = self._make_scrollable(self.content_frame)

        header = self._create_page_header(
            scroll, "Windows Update Status", "Check for missing updates and patch status"
        )

        scan_btn = ttk.Button(
            header,
            text="Check Updates",
            style="Accent.TButton",
            command=lambda: self._run_update_scan(scroll),
        )
        scan_btn.pack(anchor="w", pady=(10, 0))

        if "updates" in self.scan_results:
            self._display_results(scroll, self.scan_results["updates"], "updates")

    def _run_update_scan(self, parent):
        def on_results(results):
            self.scan_results["updates"] = results
            try:
                history.save_scan("updates", results)
            except Exception:
                pass
            self._display_results(parent, results, "updates")

        self._run_scan_threaded(winupdate.scan_updates, "Windows Update", on_results)

    # ===== PAGE: Scan History =====
    def _show_history(self):
        self._clear_content()
        self._navigate_highlight("history")
        scroll = self._make_scrollable(self.content_frame)

        header = self._create_page_header(
            scroll, "Scan History", "View previous scan results and trends"
        )

        try:
            scans = history.get_scan_history(limit=20)
        except Exception:
            scans = []

        if not scans:
            ttk.Label(
                scroll,
                text="No scan history yet. Run some scans to see results here.",
                style="Subtitle.TLabel",
            ).pack(padx=20, pady=20)
            return

        for scan in scans:
            card = ttk.Frame(scroll, style="Card.TFrame")
            card.pack(fill=tk.X, padx=20, pady=4)

            inner = ttk.Frame(card, style="Card.TFrame")
            inner.pack(fill=tk.X, padx=15, pady=10)

            top = ttk.Frame(inner, style="Card.TFrame")
            top.pack(fill=tk.X)

            ttk.Label(
                top,
                text=scan.get("scan_type", "Unknown").upper(),
                style="CardTitle.TLabel",
            ).pack(side=tk.LEFT, padx=(0, 10))

            ttk.Label(
                top,
                text=scan.get("timestamp", ""),
                style="Card.TLabel",
                foreground=COLORS["text_secondary"],
            ).pack(side=tk.RIGHT)

            stats_text = (
                f"Total: {scan.get('total_issues', 0)} | "
                f"Critical: {scan.get('critical_count', 0)} | "
                f"High: {scan.get('high_count', 0)} | "
                f"Medium: {scan.get('medium_count', 0)} | "
                f"Low: {scan.get('low_count', 0)}"
            )
            ttk.Label(inner, text=stats_text, style="Card.TLabel").pack(
                anchor="w", pady=(5, 0)
            )

    # ===== Generic Result Display =====
    def _display_results(self, parent, results, category):
        """Display generic scan results."""
        # Clear previous result cards
        for w in parent.winfo_children():
            if isinstance(w, ttk.Frame) and w.cget("style") == "Card.TFrame":
                w.destroy()

        if not results:
            ttk.Label(
                parent,
                text="No issues found. Everything looks good!",
                style="Subtitle.TLabel",
            ).pack(padx=20, pady=20, anchor="w")
            return

        ttk.Label(
            parent,
            text=f"Found {len(results)} item(s)",
            style="Subtitle.TLabel",
        ).pack(padx=20, pady=(10, 5), anchor="w")

        for result in results:
            self._create_result_card(parent, result, category)

    # ===== PAGE: Router Security =====
    def _show_router_security(self):
        self._clear_content()
        self._navigate_highlight("router_security")
        scroll = self._make_scrollable(self.content_frame)

        header = self._create_page_header(
            scroll,
            "Router & Network Security",
            "Scan your router and local network for security issues",
        )

        scan_btn = ttk.Button(
            header,
            text="Run Router Security Scan",
            style="Accent.TButton",
            command=lambda: self._run_router_security_scan(scroll),
        )
        scan_btn.pack(anchor="w", pady=(10, 0))

        # Results container
        self._router_results_frame = ttk.Frame(scroll, style="Dark.TFrame")
        self._router_results_frame.pack(fill=tk.X)

        if "router_security" in self.scan_results:
            self._display_router_security_results(self.scan_results["router_security"])

    def _run_router_security_scan(self, parent):
        """Run router security scan in background."""
        def on_results(results):
            self.scan_results["router_security"] = results
            try:
                history.save_scan("router_security", results)
            except Exception:
                pass
            self._display_router_security_results(results)

        self._run_scan_threaded(
            scan_router_security, "Router Security", on_results
        )

    def _display_router_security_results(self, results):
        """Display router security scan results as color-coded cards."""
        for w in self._router_results_frame.winfo_children():
            w.destroy()

        if not results:
            ttk.Label(
                self._router_results_frame,
                text="No results. Run a scan first.",
                style="Subtitle.TLabel",
            ).pack(padx=20, pady=20)
            return

        status_colors = {
            "Pass": "#00c853",
            "Warning": "#ffd600",
            "Fail": "#ff1744",
            "Info": "#00bcd4",
        }

        for item in results:
            card = ttk.Frame(self._router_results_frame, style="Card.TFrame")
            card.pack(fill=tk.X, padx=20, pady=4)

            inner = ttk.Frame(card, style="Card.TFrame")
            inner.pack(fill=tk.X, padx=15, pady=10)

            # Top row: status badge + check name
            top = ttk.Frame(inner, style="Card.TFrame")
            top.pack(fill=tk.X)

            status = item.get("status", "Info")
            color = status_colors.get(status, "#00bcd4")

            status_lbl = ttk.Label(top, text=f"[{status}]", style="Card.TLabel")
            status_lbl.pack(side=tk.LEFT, padx=(0, 8))
            status_lbl.configure(foreground=color, font=("Segoe UI", 10, "bold"))

            ttk.Label(
                top, text=item.get("check", ""), style="CardTitle.TLabel"
            ).pack(side=tk.LEFT)

            # Details
            details = item.get("details", "")
            if details:
                ttk.Label(
                    inner, text=details, style="Card.TLabel",
                    wraplength=700,
                ).pack(anchor="w", pady=(5, 0))

            # Fix suggestion
            fix_suggestion = item.get("fix_suggestion", "")
            if fix_suggestion:
                fix_lbl = ttk.Label(
                    inner, text=f"Fix: {fix_suggestion}",
                    style="Card.TLabel", wraplength=700,
                )
                fix_lbl.pack(anchor="w", pady=(5, 0))
                fix_lbl.configure(foreground=COLORS["text_secondary"])

            # Apply Fix button if fix_action exists with a command
            fix_action = item.get("fix_action")
            if fix_action and fix_action.get("command"):
                fix_btn = ttk.Button(
                    inner,
                    text=f"Apply Fix: {fix_action.get('label', 'Fix')}",
                    style="Accent.TButton",
                    command=lambda cmd=fix_action["command"]: self._apply_router_fix(cmd),
                )
                fix_btn.pack(anchor="w", pady=(8, 0))

    def _apply_router_fix(self, command):
        """Apply a router security fix command in a background thread."""
        import subprocess

        confirm = messagebox.askyesno(
            "Apply Fix",
            f"Are you sure you want to apply this fix?\n\n"
            f"Command: {command[:200]}\n\n"
            f"This may require administrator privileges.",
            icon="warning",
        )
        if not confirm:
            return

        def do_fix():
            try:
                # Detect PowerShell commands and route through powershell.exe
                ps_keywords = ("Get-", "Set-", "New-Item", "Remove-Item",
                               "ForEach-Object", "$_.", "Where-Object")
                if any(kw in command for kw in ps_keywords):
                    full_cmd = ["powershell", "-NoProfile", "-ExecutionPolicy",
                                "Bypass", "-Command", command]
                    result = subprocess.run(
                        full_cmd, capture_output=True, text=True, timeout=30,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    )
                else:
                    result = subprocess.run(
                        command, shell=True, capture_output=True, text=True, timeout=30,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    )
                if result.returncode != 0:
                    raise RuntimeError(result.stderr.strip() or f"Exit code {result.returncode}")
                self.root.after(
                    0, lambda: self.status_var.set("Fix applied successfully")
                )
                self.root.after(
                    0,
                    lambda: messagebox.showinfo(
                        "Fix Applied", "The fix was applied. Re-run the scan to verify."
                    ),
                )
            except Exception as e:
                self.root.after(
                    0,
                    lambda: messagebox.showerror(
                        "Fix Failed", f"Failed to apply fix:\n{str(e)}"
                    ),
                )

        threading.Thread(target=do_fix, daemon=True).start()

    # ===== PAGE: Security Grade =====
    def _show_security_grade(self):
        self._clear_content()
        self._navigate_highlight("security_grade")
        scroll = self._make_scrollable(self.content_frame)

        header = self._create_page_header(
            scroll,
            "Security Grade",
            "Run all scans and calculate your overall security grade",
        )

        btn_row = ttk.Frame(header, style="Dark.TFrame")
        btn_row.pack(anchor="w", pady=(10, 0))

        scan_btn = ttk.Button(
            btn_row,
            text="Calculate Security Grade",
            style="Accent.TButton",
            command=lambda: self._run_security_grade(scroll),
        )
        scan_btn.pack(side=tk.LEFT)

        export_btn = ttk.Button(
            btn_row,
            text="Export Report",
            style="TButton",
            command=lambda: self._export_grade_report(
                getattr(self, "_last_grade_result", None)
            ),
        )
        export_btn.pack(side=tk.LEFT, padx=(10, 0))

        # Results container
        self._grade_results_frame = ttk.Frame(scroll, style="Dark.TFrame")
        self._grade_results_frame.pack(fill=tk.X)

    def _run_security_grade(self, parent):
        """Run all scans and calculate security grade."""
        self.status_var.set("Running all scans for security grade...")
        self.root.update()

        # Clear previous results
        for w in self._grade_results_frame.winfo_children():
            w.destroy()

        progress_label = ttk.Label(
            self._grade_results_frame,
            text="Running all scans... This may take a few minutes.",
            style="Subtitle.TLabel",
        )
        progress_label.pack(padx=20, pady=20)

        def do_grade():
            scan_data = {}
            scans = [
                ("CVE Scanner", cve_scanner.scan_cves, "cve_results"),
                ("System Hardening", hardening.scan_hardening, "hardening_results"),
                ("Performance", performance.scan_performance, "performance_results"),
                ("Network", network_diag.scan_network, "network_results"),
                ("Windows Update", winupdate.scan_updates, "update_results"),
                ("Disk Health", disk_health.scan_disk_health, "disk_results"),
                ("Router Security", scan_router_security, "router_results"),
            ]

            for name, func, key in scans:
                self.root.after(
                    0,
                    lambda n=name: progress_label.configure(
                        text=f"Scanning: {n}..."
                    ),
                )
                try:
                    scan_data[key] = func()
                except Exception:
                    scan_data[key] = []

            self.root.after(
                0, lambda: progress_label.configure(text="Calculating grade...")
            )

            try:
                grade_result = calculate_grade(scan_data)
            except Exception as e:
                self.root.after(
                    0,
                    lambda: messagebox.showerror(
                        "Grade Error", f"Failed to calculate grade:\n{str(e)}"
                    ),
                )
                self.root.after(0, lambda: self.status_var.set("Grade calculation failed"))
                return

            self.root.after(0, lambda: self._display_security_grade(grade_result))
            self.root.after(0, lambda: self.status_var.set("Security grade calculated"))

        threading.Thread(target=do_grade, daemon=True).start()

    def _display_security_grade(self, grade_result):
        """Display the security grade results."""
        self._last_grade_result = grade_result
        for w in self._grade_results_frame.winfo_children():
            w.destroy()

        # Overall grade card
        grade_card = ttk.Frame(self._grade_results_frame, style="Card.TFrame")
        grade_card.pack(fill=tk.X, padx=20, pady=10)

        grade_inner = ttk.Frame(grade_card, style="Card.TFrame")
        grade_inner.pack(fill=tk.X, padx=15, pady=15)

        overall_grade = grade_result.get("overall_grade", "?")
        overall_score = grade_result.get("overall_score", 0)
        overall_color = grade_result.get("overall_color", COLORS["text_primary"])

        # Large letter grade
        grade_lbl = ttk.Label(
            grade_inner,
            text=overall_grade,
            style="Card.TLabel",
        )
        grade_lbl.pack(anchor="w")
        grade_lbl.configure(foreground=overall_color, font=("Segoe UI", 48, "bold"))

        # Numeric score
        score_lbl = ttk.Label(
            grade_inner,
            text=f"Overall Score: {overall_score}/100",
            style="CardTitle.TLabel",
        )
        score_lbl.pack(anchor="w", pady=(5, 0))

        # Category breakdown
        categories = grade_result.get("categories", {})
        if categories:
            cat_header = ttk.Label(
                self._grade_results_frame,
                text="Category Breakdown",
                style="Title.TLabel",
            )
            cat_header.pack(anchor="w", padx=20, pady=(15, 5))

            for cat_name, cat_data in categories.items():
                cat_card = ttk.Frame(self._grade_results_frame, style="Card.TFrame")
                cat_card.pack(fill=tk.X, padx=20, pady=3)

                cat_inner = ttk.Frame(cat_card, style="Card.TFrame")
                cat_inner.pack(fill=tk.X, padx=15, pady=8)

                cat_row = ttk.Frame(cat_inner, style="Card.TFrame")
                cat_row.pack(fill=tk.X)

                # Category name
                ttk.Label(
                    cat_row, text=cat_name, style="CardTitle.TLabel",
                ).pack(side=tk.LEFT)

                # Grade letter on the right
                cat_grade = cat_data.get("grade", "?")
                cat_color = cat_data.get("color", COLORS["text_primary"])
                cat_grade_lbl = ttk.Label(
                    cat_row, text=cat_grade, style="Card.TLabel",
                )
                cat_grade_lbl.pack(side=tk.RIGHT, padx=(8, 0))
                cat_grade_lbl.configure(
                    foreground=cat_color, font=("Segoe UI", 14, "bold")
                )

                # Finding count on the right
                findings_list = cat_data.get("findings", [])
                finding_count = len(findings_list) if isinstance(findings_list, list) else 0
                ttk.Label(
                    cat_row,
                    text=f"{finding_count} finding(s)",
                    style="Card.TLabel",
                    foreground=COLORS["text_secondary"],
                ).pack(side=tk.RIGHT, padx=(0, 10))

                # Score bar
                cat_score = cat_data.get("score", 0)
                bar_frame = ttk.Frame(cat_inner, style="Card.TFrame")
                bar_frame.pack(fill=tk.X, pady=(5, 0))

                bar_canvas = tk.Canvas(
                    bar_frame, height=12, bg=COLORS["bg_dark"],
                    highlightthickness=0,
                )
                bar_canvas.pack(fill=tk.X)

                def draw_bar(canvas, score, color, event=None):
                    canvas.delete("all")
                    w = canvas.winfo_width()
                    if w <= 1:
                        w = 400
                    fill_w = max(0, int(w * score / 100))
                    canvas.create_rectangle(0, 0, w, 12, fill=COLORS["bg_dark"], outline="")
                    canvas.create_rectangle(0, 0, fill_w, 12, fill=color, outline="")

                bar_canvas.bind(
                    "<Configure>",
                    lambda e, c=bar_canvas, s=cat_score, cl=cat_color: draw_bar(c, s, cl, e),
                )

                # Expandable findings details
                if isinstance(findings_list, list) and findings_list:
                    # Container for findings (collapsed by default for Pass-heavy categories)
                    fail_findings = [f for f in findings_list if f.get("status") in ("Fail", "Critical", "Warning")]
                    if fail_findings:
                        findings_container = ttk.Frame(cat_inner, style="Card.TFrame")
                        findings_container.pack(fill=tk.X, pady=(8, 0))

                        status_colors = {
                            "Fail": "#ff1744", "Critical": "#ff1744",
                            "Warning": "#ffd600", "Pass": "#00c853", "Info": "#00bcd4",
                        }

                        for finding in fail_findings:
                            f_frame = ttk.Frame(findings_container, style="Card.TFrame")
                            f_frame.pack(fill=tk.X, pady=2, padx=(10, 0))

                            # Status + check name row
                            f_top = ttk.Frame(f_frame, style="Card.TFrame")
                            f_top.pack(fill=tk.X)

                            f_status = finding.get("status", "Info")
                            f_sev = finding.get("severity", "Medium")
                            f_color = status_colors.get(f_status, "#00bcd4")

                            status_lbl = ttk.Label(f_top, text=f"[{f_sev}]", style="Card.TLabel")
                            status_lbl.pack(side=tk.LEFT, padx=(0, 6))
                            status_lbl.configure(foreground=f_color, font=("Segoe UI", 9, "bold"))

                            ttk.Label(
                                f_top, text=finding.get("check", ""),
                                style="Card.TLabel",
                            ).pack(side=tk.LEFT)

                            # Description
                            f_details = finding.get("details", "")
                            if f_details:
                                ttk.Label(
                                    f_frame, text=f_details, style="Card.TLabel",
                                    wraplength=650,
                                ).pack(anchor="w", padx=(20, 0), pady=(2, 0))

                            # Software info
                            f_sw = finding.get("affected_software", "")
                            if f_sw:
                                ttk.Label(
                                    f_frame, text=f"Software: {f_sw}",
                                    style="Card.TLabel", foreground=COLORS["text_secondary"],
                                ).pack(anchor="w", padx=(20, 0), pady=(2, 0))

                            # Manual fix instructions
                            f_fix_desc = finding.get("fix_description", "")
                            if f_fix_desc:
                                fix_lbl = ttk.Label(
                                    f_frame, text=f"How to fix: {f_fix_desc}",
                                    style="Card.TLabel", wraplength=650,
                                )
                                fix_lbl.pack(anchor="w", padx=(20, 0), pady=(2, 0))
                                fix_lbl.configure(foreground="#4fc3f7")

                            # Fix suggestion (for non-CVE findings)
                            f_fix_sug = finding.get("fix_suggestion", "")
                            if f_fix_sug and not f_fix_desc:
                                fix_lbl = ttk.Label(
                                    f_frame, text=f"Suggested fix: {f_fix_sug}",
                                    style="Card.TLabel", wraplength=650,
                                )
                                fix_lbl.pack(anchor="w", padx=(20, 0), pady=(2, 0))
                                fix_lbl.configure(foreground="#4fc3f7")

                            # Action buttons row
                            f_btn_frame = ttk.Frame(f_frame, style="Card.TFrame")
                            f_btn_frame.pack(anchor="w", padx=(20, 0), pady=(4, 4))

                            # Buttons from fix_action (view/download/apply)
                            f_fix_action = finding.get("fix_action")
                            if f_fix_action and isinstance(f_fix_action, dict):
                                # View Advisory button
                                view_info = f_fix_action.get("view")
                                if view_info and view_info.get("command"):
                                    ttk.Button(
                                        f_btn_frame,
                                        text=f">> {view_info.get('label', 'View Advisory')}",
                                        style="ViewAdvisory.TButton",
                                        command=lambda url=view_info["command"]: self._open_advisory(url),
                                    ).pack(side=tk.LEFT, padx=(0, 8))

                                # Download KB button
                                download_info = f_fix_action.get("download")
                                if download_info and download_info.get("command"):
                                    ttk.Button(
                                        f_btn_frame,
                                        text=f">> {download_info.get('label', 'Download KB')}",
                                        style="Accent.TButton",
                                        command=lambda url=download_info["command"]: self._open_advisory(url),
                                    ).pack(side=tk.LEFT, padx=(0, 8))

                                # Apply fix / Open Windows Update button
                                apply_info = f_fix_action.get("apply")
                                if apply_info and apply_info.get("command"):
                                    ttk.Button(
                                        f_btn_frame,
                                        text=f">> {apply_info.get('label', 'Apply Fix')}",
                                        style="ApplyFix.TButton",
                                        command=lambda info=apply_info: self._apply_local_fix(info),
                                    ).pack(side=tk.LEFT, padx=(0, 8))

                            # Fallback: direct reference_url if no fix_action
                            elif finding.get("reference_url"):
                                ttk.Button(
                                    f_btn_frame,
                                    text=">> View Details Online",
                                    style="ViewAdvisory.TButton",
                                    command=lambda url=finding["reference_url"]: self._open_advisory(url),
                                ).pack(side=tk.LEFT, padx=(0, 8))

                            # Separator between findings
                            ttk.Separator(findings_container, orient="horizontal").pack(
                                fill=tk.X, padx=10, pady=2,
                            )

        # Top 5 recommendations
        recs = grade_result.get("top_recommendations", [])
        if recs:
            rec_header = ttk.Label(
                self._grade_results_frame,
                text="Top Recommendations",
                style="Title.TLabel",
            )
            rec_header.pack(anchor="w", padx=20, pady=(15, 5))

            rec_card = ttk.Frame(self._grade_results_frame, style="Card.TFrame")
            rec_card.pack(fill=tk.X, padx=20, pady=4)

            rec_inner = ttk.Frame(rec_card, style="Card.TFrame")
            rec_inner.pack(fill=tk.X, padx=15, pady=10)

            for i, rec in enumerate(recs[:5], 1):
                rec_text = rec if isinstance(rec, str) else rec.get("text", str(rec))
                ttk.Label(
                    rec_inner,
                    text=f"{i}. {rec_text}",
                    style="Card.TLabel",
                    wraplength=700,
                ).pack(anchor="w", pady=2)

        # Summary
        summary = grade_result.get("summary", "")
        if summary:
            summary_header = ttk.Label(
                self._grade_results_frame,
                text="Summary",
                style="Title.TLabel",
            )
            summary_header.pack(anchor="w", padx=20, pady=(15, 5))

            summary_card = ttk.Frame(self._grade_results_frame, style="Card.TFrame")
            summary_card.pack(fill=tk.X, padx=20, pady=4)

            summary_inner = ttk.Frame(summary_card, style="Card.TFrame")
            summary_inner.pack(fill=tk.X, padx=15, pady=10)

            ttk.Label(
                summary_inner,
                text=summary,
                style="Card.TLabel",
                wraplength=700,
            ).pack(anchor="w")

        # Export Report button at bottom of results
        export_btn = ttk.Button(
            self._grade_results_frame,
            text="Export Report",
            style="Accent.TButton",
            command=lambda: self._export_grade_report(grade_result),
        )
        export_btn.pack(anchor="w", padx=20, pady=(15, 10))

    def _export_grade_report(self, grade_result):
        """Export the security grade report as a styled HTML file to the Desktop."""
        if not grade_result:
            messagebox.showwarning(
                "No Results",
                "No security grade results to export. Run the scan first.",
            )
            return

        today = datetime.date.today().isoformat()
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        filename = f"WinnyTool_SecurityGrade_{today}.html"
        filepath = os.path.join(desktop, filename)

        overall_grade = grade_result.get("overall_grade", "?")
        overall_score = grade_result.get("overall_score", 0)
        overall_color = grade_result.get("overall_color", "#ffffff")
        categories = grade_result.get("categories", {})
        recs = grade_result.get("top_recommendations", [])
        summary = grade_result.get("summary", "")

        # Build category rows
        cat_rows = ""
        for cat_name, cat_data in categories.items():
            cat_grade = cat_data.get("grade", "?")
            cat_score = cat_data.get("score", 0)
            cat_color = cat_data.get("color", "#ffffff")
            findings = cat_data.get("findings", 0)
            bar_width = max(0, min(100, cat_score))
            cat_rows += f"""
            <tr>
                <td>{cat_name}</td>
                <td style="color:{cat_color};font-weight:bold;font-size:1.2em;">{cat_grade}</td>
                <td>{cat_score}/100</td>
                <td>
                    <div class="bar-bg"><div class="bar-fill" style="width:{bar_width}%;background:{cat_color};"></div></div>
                </td>
                <td>{findings} finding(s)</td>
            </tr>"""

        # Build recommendation items
        rec_items = ""
        for i, rec in enumerate(recs, 1):
            if isinstance(rec, dict):
                rec_text = rec.get("text", str(rec))
                fix_action = rec.get("fix_action")
                fix_link = rec.get("link", "")
            else:
                rec_text = str(rec)
                fix_action = None
                fix_link = ""

            item_html = f"<li>{rec_text}"
            if fix_link:
                item_html += f' <a href="{fix_link}" target="_blank">[More Info]</a>'
            if fix_action:
                cmd = fix_action if isinstance(fix_action, str) else fix_action.get("command", "")
                if cmd:
                    item_html += f'<pre class="code-block">{cmd}</pre>'
            item_html += "</li>"
            rec_items += item_html

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WinnyTool Security Grade Report - {today}</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background: {COLORS['bg_dark']};
        color: {COLORS['text_primary']};
        padding: 40px;
        line-height: 1.6;
    }}
    .container {{ max-width: 900px; margin: 0 auto; }}
    h1 {{ color: {COLORS['accent']}; margin-bottom: 5px; font-size: 1.8em; }}
    h2 {{ color: {COLORS['text_primary']}; margin: 30px 0 15px 0; font-size: 1.3em; }}
    .subtitle {{ color: {COLORS['text_secondary']}; margin-bottom: 25px; }}
    .grade-card {{
        background: {COLORS['card_bg']};
        border-radius: 10px;
        padding: 30px;
        text-align: center;
        margin-bottom: 30px;
    }}
    .grade-letter {{
        font-size: 96px;
        font-weight: bold;
        color: {overall_color};
        line-height: 1;
    }}
    .grade-score {{
        font-size: 1.3em;
        color: {COLORS['text_secondary']};
        margin-top: 8px;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        background: {COLORS['card_bg']};
        border-radius: 8px;
        overflow: hidden;
    }}
    th, td {{ padding: 12px 16px; text-align: left; }}
    th {{ background: {COLORS['bg_light']}; color: {COLORS['text_secondary']}; font-weight: 600; }}
    tr:not(:last-child) td {{ border-bottom: 1px solid {COLORS['bg_light']}; }}
    .bar-bg {{
        background: {COLORS['bg_dark']};
        border-radius: 6px;
        height: 12px;
        width: 100%;
        min-width: 120px;
    }}
    .bar-fill {{ height: 12px; border-radius: 6px; transition: width 0.3s; }}
    .rec-list {{ list-style: none; padding: 0; }}
    .rec-list li {{
        background: {COLORS['card_bg']};
        border-radius: 8px;
        padding: 14px 18px;
        margin-bottom: 8px;
    }}
    .rec-list a {{ color: {COLORS['info']}; text-decoration: none; }}
    .rec-list a:hover {{ text-decoration: underline; }}
    .code-block {{
        background: {COLORS['bg_dark']};
        border: 1px solid {COLORS['bg_light']};
        border-radius: 6px;
        padding: 10px 14px;
        margin-top: 8px;
        font-family: 'Cascadia Code', 'Consolas', monospace;
        font-size: 0.9em;
        color: {COLORS['success']};
        white-space: pre-wrap;
        word-break: break-all;
        cursor: text;
        user-select: all;
    }}
    .summary-card {{
        background: {COLORS['card_bg']};
        border-radius: 8px;
        padding: 20px;
        color: {COLORS['text_secondary']};
    }}
    .footer {{
        margin-top: 40px;
        text-align: center;
        color: {COLORS['text_secondary']};
        font-size: 0.85em;
    }}
</style>
</head>
<body>
<div class="container">
    <h1>WinnyTool Security Grade Report</h1>
    <p class="subtitle">Generated on {today}</p>

    <div class="grade-card">
        <div class="grade-letter">{overall_grade}</div>
        <div class="grade-score">Overall Score: {overall_score} / 100</div>
    </div>

    <h2>Category Breakdown</h2>
    <table>
        <thead>
            <tr><th>Category</th><th>Grade</th><th>Score</th><th>Progress</th><th>Findings</th></tr>
        </thead>
        <tbody>{cat_rows}
        </tbody>
    </table>

    {"<h2>Top Recommendations</h2><ol class='rec-list'>" + rec_items + "</ol>" if rec_items else ""}

    {"<h2>Summary</h2><div class='summary-card'>" + summary + "</div>" if summary else ""}

    <div class="footer">
        WinnyTool v{VERSION} &mdash; Windows System Diagnostic &amp; Optimization Tool
    </div>
</div>
</body>
</html>"""

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html)
            messagebox.showinfo(
                "Report Exported",
                f"Security grade report saved to:\n{filepath}",
            )
        except Exception as e:
            messagebox.showerror(
                "Export Failed",
                f"Failed to save report:\n{str(e)}",
            )

    # ===== PAGE: Resources =====
    def _show_resources(self):
        self._clear_content()
        self._navigate_highlight("resources")
        scroll = self._make_scrollable(self.content_frame)

        self._create_page_header(
            scroll,
            "Security Resources",
            "Curated links to security tools, channels, and communities",
        )

        resources = get_security_resources()

        for category, items in resources.items():
            # Category header
            cat_lbl = ttk.Label(
                scroll,
                text=category,
                style="Title.TLabel",
            )
            cat_lbl.pack(anchor="w", padx=20, pady=(15, 5))
            cat_lbl.configure(foreground=COLORS["accent"])

            for resource in items:
                res_card = ttk.Frame(scroll, style="Card.TFrame")
                res_card.pack(fill=tk.X, padx=20, pady=2)

                res_inner = ttk.Frame(res_card, style="Card.TFrame")
                res_inner.pack(fill=tk.X, padx=15, pady=8)

                # Resource name as clickable label
                name_lbl = ttk.Label(
                    res_inner,
                    text=resource.get("name", ""),
                    style="CardTitle.TLabel",
                    cursor="hand2",
                )
                name_lbl.pack(anchor="w")
                name_lbl.configure(foreground=COLORS["info"])
                name_lbl.bind(
                    "<Button-1>",
                    lambda e, url=resource.get("url", ""): open_resource(url),
                )

                # Description
                desc = resource.get("description", "")
                if desc:
                    ttk.Label(
                        res_inner,
                        text=desc,
                        style="Card.TLabel",
                        foreground=COLORS["text_secondary"],
                    ).pack(anchor="w", pady=(2, 0))

    # ===== PAGE: Settings =====
    def _show_settings(self):
        self._clear_content()
        self._navigate_highlight("settings")
        scroll = self._make_scrollable(self.content_frame)

        self._create_page_header(
            scroll,
            "Settings",
            "Customize the application appearance",
        )

        # UI Scale section
        scale_card = ttk.Frame(scroll, style="Card.TFrame")
        scale_card.pack(fill=tk.X, padx=20, pady=10)

        scale_inner = ttk.Frame(scale_card, style="Card.TFrame")
        scale_inner.pack(fill=tk.X, padx=15, pady=15)

        ttk.Label(
            scale_inner, text="UI Scale", style="CardTitle.TLabel"
        ).pack(anchor="w")

        ttk.Label(
            scale_inner,
            text="Adjust the size of all text and the sidebar width.",
            style="Card.TLabel",
            foreground=COLORS["text_secondary"],
        ).pack(anchor="w", pady=(4, 10))

        # Current scale display
        scale_value_var = tk.StringVar(value=f"{self.ui_scale}%")
        scale_display = ttk.Label(
            scale_inner, textvariable=scale_value_var, style="CardTitle.TLabel"
        )
        scale_display.pack(anchor="w", pady=(0, 5))

        # Slider
        scale_var = tk.IntVar(value=self.ui_scale)

        def on_scale_change(val):
            pct = int(float(val))
            scale_var.set(pct)
            scale_value_var.set(f"{pct}%")

        slider = tk.Scale(
            scale_inner,
            from_=80,
            to=200,
            orient=tk.HORIZONTAL,
            variable=scale_var,
            command=on_scale_change,
            bg=COLORS["card_bg"],
            fg=COLORS["text_primary"],
            troughcolor=COLORS["bg_light"],
            highlightthickness=0,
            sliderrelief="flat",
            length=400,
            font=("Segoe UI", self._scaled(self.BASE_FONT_SIZES["sidebar"])),
        )
        slider.pack(anchor="w", pady=(0, 10))

        # Preset buttons
        preset_frame = ttk.Frame(scale_inner, style="Card.TFrame")
        preset_frame.pack(anchor="w", pady=(0, 10))

        presets = [
            ("Compact (80%)", 80),
            ("Normal (100%)", 100),
            ("Large (140%)", 140),
        ]

        for label, value in presets:
            ttk.Button(
                preset_frame,
                text=label,
                style="Accent.TButton",
                command=lambda v=value: (scale_var.set(v), on_scale_change(v)),
            ).pack(side=tk.LEFT, padx=(0, 8))

        # Apply button
        def apply_scale():
            new_scale = scale_var.get()
            self._apply_scale(new_scale)
            self._save_settings({"ui_scale": new_scale})
            self.status_var.set(f"UI scale set to {new_scale}%")

        ttk.Button(
            scale_inner,
            text="Apply Scale",
            style="Accent.TButton",
            command=apply_scale,
        ).pack(anchor="w", pady=(5, 0))

    # ===== Full Scan =====
    def _run_full_scan(self):
        """Run all scans sequentially."""
        self._clear_content()
        self._navigate_highlight("dashboard")

        scroll = self._make_scrollable(self.content_frame)
        self._create_page_header(scroll, "Full System Scan", "Running all diagnostics...")

        progress = ttk.Progressbar(
            scroll, style="Accent.Horizontal.TProgressbar", length=400, mode="determinate"
        )
        progress.pack(padx=20, pady=10, anchor="w")

        status_label = ttk.Label(scroll, text="Starting...", style="Subtitle.TLabel")
        status_label.pack(padx=20, anchor="w")

        results_frame = ttk.Frame(scroll, style="Dark.TFrame")
        results_frame.pack(fill=tk.X)

        def full_scan():
            scans = [
                ("CVE Scanner", cve_scanner.scan_cves, "cve"),
                ("BSOD Analyzer", bsod_analyzer.get_recent_bsods, "bsod"),
                ("Performance", performance.scan_performance, "performance"),
                ("Startup Items", startup_mgr.get_startup_items, "startup"),
                ("Disk Health", disk_health.scan_disk_health, "disk"),
                ("Network", network_diag.scan_network, "network"),
                ("Windows Update", winupdate.scan_updates, "updates"),
                ("System Hardening", hardening.scan_hardening, "hardening"),
            ]

            total = len(scans)
            all_results = {}

            for i, (name, func, key) in enumerate(scans):
                self.root.after(
                    0, lambda n=name: status_label.configure(text=f"Scanning: {n}...")
                )
                self.root.after(
                    0, lambda v=(i / total * 100): progress.configure(value=v)
                )

                try:
                    result = func()
                    all_results[key] = result
                    self.scan_results[key] = result
                except Exception as e:
                    all_results[key] = []
                    self.scan_results[key] = []

            self.root.after(0, lambda: progress.configure(value=100))
            self.root.after(
                0, lambda: status_label.configure(text="Full scan complete!")
            )
            self.root.after(0, lambda: self.status_var.set("Full scan complete"))

            # Save to history
            try:
                for key, results in all_results.items():
                    history.save_scan(key, results)
            except Exception:
                pass

            # Show summary
            def show_summary():
                total_issues = sum(len(v) for v in all_results.values())
                summary_card = ttk.Frame(results_frame, style="Card.TFrame")
                summary_card.pack(fill=tk.X, padx=20, pady=10)

                inner = ttk.Frame(summary_card, style="Card.TFrame")
                inner.pack(fill=tk.X, padx=15, pady=10)

                ttk.Label(
                    inner,
                    text=f"Scan Complete - {total_issues} total findings",
                    style="CardTitle.TLabel",
                ).pack(anchor="w")

                for name, _, key in scans:
                    count = len(all_results.get(key, []))
                    color = COLORS["success"] if count == 0 else COLORS["warning"]
                    lbl = ttk.Label(
                        inner,
                        text=f"  {name}: {count} item(s)",
                        style="Card.TLabel",
                    )
                    lbl.pack(anchor="w", pady=1)
                    lbl.configure(foreground=color)

                # --- Action buttons ---
                btn_frame = ttk.Frame(inner, style="Card.TFrame")
                btn_frame.pack(fill=tk.X, pady=(15, 5))

                ttk.Label(
                    btn_frame, text="Export Results:", style="Card.TLabel"
                ).pack(side=tk.LEFT, padx=(0, 10))

                ttk.Button(
                    btn_frame, text="HTML Report",
                    style="Accent.TButton",
                    command=self._export_report,
                ).pack(side=tk.LEFT, padx=5)

                ttk.Button(
                    btn_frame, text="Text Report",
                    style="Accent.TButton",
                    command=lambda: self._export_text_report(all_results),
                ).pack(side=tk.LEFT, padx=5)

                ttk.Button(
                    btn_frame, text="CSV Export",
                    style="Accent.TButton",
                    command=lambda: self._export_csv_report(all_results),
                ).pack(side=tk.LEFT, padx=5)

                ttk.Button(
                    btn_frame, text="Security Grade",
                    style="Accent.TButton",
                    command=lambda: self._navigate("security_grade"),
                ).pack(side=tk.LEFT, padx=5)

                # --- View individual section buttons ---
                view_frame = ttk.Frame(inner, style="Card.TFrame")
                view_frame.pack(fill=tk.X, pady=(10, 5))

                ttk.Label(
                    view_frame, text="View Details:", style="Card.TLabel"
                ).pack(side=tk.LEFT, padx=(0, 10))

                page_map = {
                    "CVE Scanner": "cve_scanner",
                    "BSOD Analyzer": "bsod",
                    "Performance": "performance",
                    "Startup Items": "startup",
                    "Disk Health": "disk_health",
                    "Network": "network",
                    "Windows Update": "winupdate",
                    "System Hardening": "hardening",
                }
                for name, _, key in scans:
                    count = len(all_results.get(key, []))
                    if count > 0:
                        page = page_map.get(name, "dashboard")
                        ttk.Button(
                            view_frame,
                            text=f"{name} ({count})",
                            command=lambda p=page: self._navigate(p),
                        ).pack(side=tk.LEFT, padx=3, pady=2)

            self.root.after(0, show_summary)

        threading.Thread(target=full_scan, daemon=True).start()

    # ===== Text Report Export =====
    def _export_text_report(self, results=None):
        """Export scan results as a plain text file."""
        data = results or self.scan_results
        if not any(data.values()):
            messagebox.showinfo("No Data", "Run some scans first before exporting.")
            return
        try:
            import datetime as _dt
            desktop = os.path.join(os.path.expanduser("~"), "Desktop")
            if not os.path.isdir(desktop):
                desktop = os.path.join(os.path.expanduser("~"), "Documents")
            filepath = os.path.join(desktop, f"WinnyTool_Report_{_dt.date.today()}.txt")

            with open(filepath, "w", encoding="utf-8") as f:
                f.write("=" * 70 + "\n")
                f.write(f"  WinnyTool v{VERSION} - System Scan Report\n")
                f.write(f"  Generated: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 70 + "\n\n")

                section_names = {
                    "cve": "CVE Scanner", "bsod": "BSOD Analyzer",
                    "performance": "Performance", "startup": "Startup Items",
                    "disk": "Disk Health", "network": "Network",
                    "updates": "Windows Update", "hardening": "System Hardening",
                    "router": "Router Security",
                }
                for key, items in data.items():
                    if not items:
                        continue
                    name = section_names.get(key, key.title())
                    f.write(f"\n{'─' * 70}\n")
                    f.write(f"  {name} ({len(items)} finding(s))\n")
                    f.write(f"{'─' * 70}\n\n")
                    for item in items:
                        if isinstance(item, dict):
                            # CVE format
                            if "cve_id" in item:
                                f.write(f"  [{item.get('severity', '')}] {item['cve_id']}\n")
                                f.write(f"    {item.get('description', '')}\n")
                                f.write(f"    Fix: {item.get('fix', item.get('fix_description', ''))}\n")
                                ref = item.get('reference_url', '')
                                if ref:
                                    f.write(f"    Ref: {ref}\n")
                            # Standard check format
                            elif "check" in item:
                                status = item.get("status", "")
                                f.write(f"  [{status}] {item['check']}\n")
                                f.write(f"    {item.get('details', '')}\n")
                                fix = item.get("fix_suggestion", item.get("fix", ""))
                                if fix:
                                    f.write(f"    Fix: {fix}\n")
                            # Performance format
                            elif "issue" in item:
                                f.write(f"  [{item.get('impact', '')}] {item['issue']}\n")
                                f.write(f"    {item.get('description', '')}\n")
                            # Startup format
                            elif "name" in item:
                                f.write(f"  {item['name']}\n")
                                f.write(f"    Source: {item.get('source', '')} | Impact: {item.get('impact', '')}\n")
                            else:
                                f.write(f"  {item}\n")
                        else:
                            f.write(f"  {item}\n")
                        f.write("\n")

            messagebox.showinfo("Report Exported", f"Text report saved to:\n{filepath}")
            os.startfile(filepath)
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export text report:\n{e}")

    # ===== CSV Report Export =====
    def _export_csv_report(self, results=None):
        """Export scan results as a CSV file."""
        data = results or self.scan_results
        if not any(data.values()):
            messagebox.showinfo("No Data", "Run some scans first before exporting.")
            return
        try:
            import datetime as _dt
            import csv
            desktop = os.path.join(os.path.expanduser("~"), "Desktop")
            if not os.path.isdir(desktop):
                desktop = os.path.join(os.path.expanduser("~"), "Documents")
            filepath = os.path.join(desktop, f"WinnyTool_Report_{_dt.date.today()}.csv")

            section_names = {
                "cve": "CVE Scanner", "bsod": "BSOD Analyzer",
                "performance": "Performance", "startup": "Startup Items",
                "disk": "Disk Health", "network": "Network",
                "updates": "Windows Update", "hardening": "System Hardening",
                "router": "Router Security",
            }

            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Category", "Severity/Status", "Item", "Details", "Fix/Recommendation", "Reference"])

                for key, items in data.items():
                    if not items:
                        continue
                    cat = section_names.get(key, key.title())
                    for item in items:
                        if not isinstance(item, dict):
                            writer.writerow([cat, "", str(item), "", "", ""])
                            continue
                        if "cve_id" in item:
                            writer.writerow([
                                cat, item.get("severity", ""),
                                item["cve_id"], item.get("description", ""),
                                item.get("fix", item.get("fix_description", "")),
                                item.get("reference_url", ""),
                            ])
                        elif "check" in item:
                            writer.writerow([
                                cat, item.get("status", ""),
                                item["check"], item.get("details", ""),
                                item.get("fix_suggestion", item.get("fix", "")),
                                "",
                            ])
                        elif "issue" in item:
                            writer.writerow([
                                cat, item.get("impact", ""),
                                item["issue"], item.get("description", ""),
                                item.get("recommended_value", ""),
                                "",
                            ])
                        elif "name" in item:
                            writer.writerow([
                                cat, item.get("impact", ""),
                                item["name"], f"Source: {item.get('source', '')}",
                                item.get("command", ""),
                                "",
                            ])
                        else:
                            writer.writerow([cat, "", str(item), "", "", ""])

            messagebox.showinfo("Report Exported", f"CSV report saved to:\n{filepath}")
            os.startfile(filepath)
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export CSV report:\n{e}")

    # ===== Export Report =====
    def _export_report(self):
        """Export scan results to HTML report."""
        if not any(self.scan_results.values()):
            messagebox.showinfo(
                "No Data", "Run some scans first before exporting a report."
            )
            return

        try:
            filepath = reporter.generate_report(self.scan_results, format="html")
            messagebox.showinfo(
                "Report Exported",
                f"Report saved to:\n{filepath}\n\nOpening in browser...",
            )
            os.startfile(filepath)
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export report:\n{e}")

    # ===== Auto-Update Check =====
    def _check_updates_bg(self):
        """Check for updates in background on launch."""
        try:
            result = updater.check_for_updates()
            if result.get("update_available"):
                self.root.after(0, lambda: self._show_update_prompt(result))
        except Exception:
            pass  # Silent fail on update check

    def _show_update_prompt(self, update_info):
        """Show update available dialog with download-and-install capability."""
        import webbrowser
        import tempfile
        import zipfile
        import shutil

        download_url = update_info.get("download_url", "")
        if not download_url:
            messagebox.showinfo(
                "Update Available",
                f"A new version v{update_info['latest_version']} is available, "
                f"but no downloadable asset was found.\n\n"
                f"Please visit the GitHub releases page manually.",
            )
            return

        # Build the prompt dialog
        dlg = tk.Toplevel(self.root)
        dlg.title("Update Available")
        dlg.configure(bg=COLORS["bg_dark"])
        dlg.geometry("480x320")
        dlg.resizable(False, False)
        dlg.transient(self.root)
        dlg.grab_set()

        frame = ttk.Frame(dlg, style="Dark.TFrame")
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        ttk.Label(
            frame,
            text=f"A new version of {APP_NAME} is available!",
            style="CardTitle.TLabel",
        ).pack(anchor="w")

        ttk.Label(
            frame,
            text=f"Current: v{update_info['current_version']}    Latest: v{update_info['latest_version']}",
            style="Card.TLabel",
        ).pack(anchor="w", pady=(8, 4))

        notes = update_info.get("release_notes", "")[:300]
        if notes:
            ttk.Label(
                frame,
                text=notes,
                style="Card.TLabel",
                wraplength=430,
                foreground=COLORS["text_secondary"],
            ).pack(anchor="w", pady=(4, 10))

        progress_var = tk.DoubleVar(value=0)
        progress_bar = ttk.Progressbar(frame, variable=progress_var, maximum=100)
        progress_bar.pack(fill=tk.X, pady=(5, 2))
        progress_bar.pack_forget()  # hidden initially

        status_var = tk.StringVar(value="")
        status_lbl = ttk.Label(frame, textvariable=status_var, style="Card.TLabel")
        status_lbl.pack(anchor="w")

        btn_frame = ttk.Frame(frame, style="Dark.TFrame")
        btn_frame.pack(fill=tk.X, pady=(10, 0))

        def _do_download_install():
            """Download and install the update in a background thread."""
            progress_bar.pack(fill=tk.X, pady=(5, 2))
            install_btn.configure(state="disabled")
            browser_btn.configure(state="disabled")

            def worker():
                try:
                    import urllib.request as urlreq

                    filename = download_url.rsplit("/", 1)[-1] if "/" in download_url else "winnytool_update"
                    dest = os.path.join(tempfile.gettempdir(), filename)

                    self.root.after(0, lambda: status_var.set(f"Downloading {filename}..."))

                    req = urlreq.Request(download_url, headers={"User-Agent": "WinnyTool-Updater"})
                    with urlreq.urlopen(req, timeout=120) as resp:
                        total = resp.headers.get("Content-Length")
                        total = int(total) if total else None
                        downloaded = 0
                        with open(dest, "wb") as f:
                            while True:
                                chunk = resp.read(65536)
                                if not chunk:
                                    break
                                f.write(chunk)
                                downloaded += len(chunk)
                                if total:
                                    pct = (downloaded / total) * 100
                                    self.root.after(0, lambda p=pct: progress_var.set(p))
                                    self.root.after(
                                        0,
                                        lambda d=downloaded, t=total: status_var.set(
                                            f"Downloading... {d // 1024} / {t // 1024} KB"
                                        ),
                                    )

                    self.root.after(0, lambda: progress_var.set(100))
                    self.root.after(0, lambda: status_var.set("Download complete. Installing..."))

                    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

                    if ext == "zip":
                        extract_dir = os.path.join(tempfile.gettempdir(), "winnytool_update_extract")
                        if os.path.isdir(extract_dir):
                            shutil.rmtree(extract_dir, ignore_errors=True)
                        with zipfile.ZipFile(dest, "r") as zf:
                            zf.extractall(extract_dir)
                        # Copy extracted files over the current installation
                        app_dir = os.path.dirname(os.path.abspath(__file__))
                        for root_dir, dirs, files in os.walk(extract_dir):
                            rel = os.path.relpath(root_dir, extract_dir)
                            target_dir = os.path.join(app_dir, rel)
                            os.makedirs(target_dir, exist_ok=True)
                            for fname in files:
                                src = os.path.join(root_dir, fname)
                                dst = os.path.join(target_dir, fname)
                                try:
                                    shutil.copy2(src, dst)
                                except PermissionError:
                                    pass  # skip locked files
                        self.root.after(
                            0,
                            lambda: status_var.set("Update extracted. Please restart WinnyTool."),
                        )
                        self.root.after(
                            0,
                            lambda: messagebox.showinfo(
                                "Update Installed",
                                "Files have been updated. Please restart WinnyTool for changes to take effect.",
                            ),
                        )
                    elif ext in ("exe", "msi"):
                        self.root.after(0, lambda: status_var.set("Launching installer..."))
                        if ext == "msi":
                            import subprocess
                            subprocess.Popen(
                                ["msiexec", "/i", dest],
                                creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
                            )
                        else:
                            os.startfile(dest)
                        self.root.after(
                            0,
                            lambda: messagebox.showinfo(
                                "Installer Launched",
                                "The installer has been launched. WinnyTool will close.",
                            ),
                        )
                        self.root.after(500, self.root.destroy)
                    else:
                        # Unknown type - open containing folder
                        self.root.after(
                            0,
                            lambda: status_var.set(f"Downloaded to {dest}"),
                        )
                        os.startfile(os.path.dirname(dest))

                except Exception as e:
                    self.root.after(
                        0,
                        lambda: status_var.set(f"Download failed: {e}"),
                    )
                    self.root.after(0, lambda: install_btn.configure(state="normal"))
                    self.root.after(0, lambda: browser_btn.configure(state="normal"))

            threading.Thread(target=worker, daemon=True).start()

        def _open_browser():
            webbrowser.open(download_url)
            dlg.destroy()

        install_btn = ttk.Button(
            btn_frame,
            text="Download & Install",
            style="Accent.TButton",
            command=_do_download_install,
        )
        install_btn.pack(side=tk.LEFT, padx=(0, 5))

        browser_btn = ttk.Button(
            btn_frame,
            text="Open in Browser",
            command=_open_browser,
        )
        browser_btn.pack(side=tk.LEFT, padx=5)

        ttk.Button(
            btn_frame,
            text="Skip",
            command=dlg.destroy,
        ).pack(side=tk.RIGHT)

    # ===== PAGE: Check for Updates =====
    def _show_check_updates(self):
        """Show the Check for Updates page with current version info and a Check Now button."""
        self._clear_content()
        self._navigate_highlight("check_updates")
        scroll = self._make_scrollable(self.content_frame)

        self._create_page_header(
            scroll,
            "Check for Updates",
            "Manually check for new WinnyTool releases",
        )

        # Version info card
        info_card = ttk.Frame(scroll, style="Card.TFrame")
        info_card.pack(fill=tk.X, padx=20, pady=10)
        info_inner = ttk.Frame(info_card, style="Card.TFrame")
        info_inner.pack(fill=tk.X, padx=15, pady=15)

        ttk.Label(
            info_inner, text="Current Version", style="CardTitle.TLabel"
        ).pack(anchor="w")
        ttk.Label(
            info_inner,
            text=f"v{VERSION}",
            style="Card.TLabel",
            font=("Segoe UI", 16, "bold"),
        ).pack(anchor="w", pady=(4, 8))
        ttk.Label(
            info_inner,
            text=f"Repository: {updater.GITHUB_REPO}",
            style="Card.TLabel",
            foreground=COLORS["text_secondary"],
        ).pack(anchor="w")

        # Result card (hidden until check runs)
        result_card = ttk.Frame(scroll, style="Card.TFrame")
        result_inner = ttk.Frame(result_card, style="Card.TFrame")
        result_inner.pack(fill=tk.X, padx=15, pady=15)

        result_var = tk.StringVar(value="")
        result_lbl = ttk.Label(
            result_inner,
            textvariable=result_var,
            style="Card.TLabel",
            wraplength=600,
        )
        result_lbl.pack(anchor="w")

        update_btn_frame = ttk.Frame(result_inner, style="Card.TFrame")

        # Check Now button
        action_card = ttk.Frame(scroll, style="Card.TFrame")
        action_card.pack(fill=tk.X, padx=20, pady=10)
        action_inner = ttk.Frame(action_card, style="Card.TFrame")
        action_inner.pack(fill=tk.X, padx=15, pady=15)

        def do_check():
            check_btn.configure(state="disabled")
            result_var.set("Checking for updates...")
            result_card.pack(fill=tk.X, padx=20, pady=10)

            # Clear old update buttons
            for w in update_btn_frame.winfo_children():
                w.destroy()

            def worker():
                try:
                    info = updater.check_for_updates()
                except Exception as e:
                    self.root.after(
                        0, lambda: result_var.set(f"Error checking for updates: {e}")
                    )
                    self.root.after(0, lambda: check_btn.configure(state="normal"))
                    return

                def show_result():
                    check_btn.configure(state="normal")
                    if info.get("update_available"):
                        result_lbl.configure(foreground=COLORS["success"])
                        result_var.set(
                            f"Update available!  Latest: v{info['latest_version']}\n\n"
                            f"{info.get('release_notes', '')[:400]}"
                        )
                        # Show assets info
                        assets = info.get("assets", [])
                        if assets:
                            asset_text = "  |  ".join(
                                f"{a['name']} ({a['size'] // 1024} KB)" for a in assets
                            )
                            ttk.Label(
                                result_inner,
                                text=f"Assets: {asset_text}",
                                style="Card.TLabel",
                                foreground=COLORS["text_secondary"],
                                wraplength=600,
                            ).pack(anchor="w", pady=(6, 0))

                        update_btn_frame.pack(anchor="w", pady=(10, 0))
                        ttk.Button(
                            update_btn_frame,
                            text="Download & Install",
                            style="Accent.TButton",
                            command=lambda: self._show_update_prompt(info),
                        ).pack(side=tk.LEFT, padx=(0, 5))
                    else:
                        result_lbl.configure(foreground=COLORS["text_secondary"])
                        result_var.set(
                            f"You are up to date!  (v{info['current_version']})"
                        )

                self.root.after(0, show_result)

            threading.Thread(target=worker, daemon=True).start()

        check_btn = ttk.Button(
            action_inner,
            text="Check Now",
            style="Accent.TButton",
            command=do_check,
        )
        check_btn.pack(anchor="w")


def main():
    """Main entry point."""
    root = tk.Tk()

    # High DPI awareness
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

    app = WinnyToolApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
