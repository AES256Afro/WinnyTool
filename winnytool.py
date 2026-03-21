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

VERSION = "1.0.0"
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
    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME} v{VERSION}")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        self.root.configure(bg=COLORS["bg_dark"])

        # Try to set icon
        try:
            self.root.iconbitmap(default="")
        except Exception:
            pass

        # Initialize scan history DB
        try:
            history.init_db()
        except Exception:
            pass

        self.scan_results = {}
        self.current_page = None

        self._build_styles()
        self._build_layout()
        self._show_dashboard()

        # Check for updates on launch (background)
        threading.Thread(target=self._check_updates_bg, daemon=True).start()

    def _build_styles(self):
        """Configure ttk styles for dark theme."""
        self.style = ttk.Style()
        self.style.theme_use("clam")

        self.style.configure("Dark.TFrame", background=COLORS["bg_dark"])
        self.style.configure("Card.TFrame", background=COLORS["card_bg"])
        self.style.configure("Medium.TFrame", background=COLORS["bg_medium"])

        self.style.configure(
            "Dark.TLabel",
            background=COLORS["bg_dark"],
            foreground=COLORS["text_primary"],
            font=("Segoe UI", 10),
        )
        self.style.configure(
            "Card.TLabel",
            background=COLORS["card_bg"],
            foreground=COLORS["text_primary"],
            font=("Segoe UI", 10),
        )
        self.style.configure(
            "Title.TLabel",
            background=COLORS["bg_dark"],
            foreground=COLORS["text_primary"],
            font=("Segoe UI", 18, "bold"),
        )
        self.style.configure(
            "Subtitle.TLabel",
            background=COLORS["bg_dark"],
            foreground=COLORS["text_secondary"],
            font=("Segoe UI", 11),
        )
        self.style.configure(
            "CardTitle.TLabel",
            background=COLORS["card_bg"],
            foreground=COLORS["text_primary"],
            font=("Segoe UI", 12, "bold"),
        )
        self.style.configure(
            "SidebarTitle.TLabel",
            background=COLORS["bg_medium"],
            foreground=COLORS["accent"],
            font=("Segoe UI", 16, "bold"),
        )
        self.style.configure(
            "Sidebar.TLabel",
            background=COLORS["bg_medium"],
            foreground=COLORS["text_secondary"],
            font=("Segoe UI", 9),
        )
        self.style.configure(
            "Status.TLabel",
            background=COLORS["bg_dark"],
            foreground=COLORS["text_secondary"],
            font=("Segoe UI", 9),
        )

        # Severity label styles
        for sev, color in SEVERITY_COLORS.items():
            self.style.configure(
                f"{sev}.TLabel",
                background=COLORS["card_bg"],
                foreground=color,
                font=("Segoe UI", 10, "bold"),
            )

        self.style.configure(
            "Accent.TButton",
            background=COLORS["accent"],
            foreground=COLORS["text_primary"],
            font=("Segoe UI", 10, "bold"),
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
            font=("Segoe UI", 9, "bold"),
            borderwidth=0,
            padding=(8, 4),
        )
        self.style.map(
            "Fix.TButton",
            background=[("active", "#27ae60")],
        )
        self.style.configure(
            "Sidebar.TButton",
            background=COLORS["bg_medium"],
            foreground=COLORS["text_primary"],
            font=("Segoe UI", 11),
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
            font=("Segoe UI", 11, "bold"),
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

    def _build_layout(self):
        """Build the main application layout."""
        # Main container
        self.main_frame = ttk.Frame(self.root, style="Dark.TFrame")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Sidebar
        self.sidebar = ttk.Frame(self.main_frame, style="Medium.TFrame", width=220)
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
            ("updates", "Windows Update"),
            ("history", "Scan History"),
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

        # Fix button(s)
        fix_action = result.get("fix_action")
        fix_actions = result.get("fix_actions", [])

        btn_frame = ttk.Frame(inner, style="Card.TFrame")
        btn_frame.pack(anchor="w", pady=(8, 0))

        if fix_action and isinstance(fix_action, dict):
            fix_actions = [fix_action] + fix_actions

        for action in fix_actions[:3]:  # Max 3 buttons per card
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

            self.root.after(0, show_summary)

        threading.Thread(target=full_scan, daemon=True).start()

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
        """Show update available notification."""
        response = messagebox.askyesno(
            "Update Available",
            f"A new version of {APP_NAME} is available!\n\n"
            f"Current: v{update_info['current_version']}\n"
            f"Latest: v{update_info['latest_version']}\n\n"
            f"{update_info.get('release_notes', '')[:300]}\n\n"
            f"Would you like to download the update?",
        )
        if response and update_info.get("download_url"):
            import webbrowser
            webbrowser.open(update_info["download_url"])


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
