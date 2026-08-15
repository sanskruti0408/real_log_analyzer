import tkinter as tk
from tkinter import ttk, messagebox
import sys
import os
import socket

DEVICE_NAME = socket.gethostname()

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.parser   import fetch_logs, parse_logs
from core.detector import run_all_detections
from core.reporter import generate_txt_report, generate_csv_report

# ── Colours ───────────────────────────────────────────────
BG       = "#0d1117"
PANEL    = "#161b22"
ACCENT   = "#58a6ff"
TEXT     = "#c9d1d9"
CRITICAL = "#ff4444"
HIGH     = "#ff8c00"
MEDIUM   = "#ffd700"
LOW      = "#00cc44"

SEVERITY_COLORS = {
    "CRITICAL" : CRITICAL,
    "HIGH"     : HIGH,
    "MEDIUM"   : MEDIUM,
    "LOW"      : LOW
}

class Dashboard:
    def __init__(self, root):
        self.root        = root
        self.all_threats = []
        self.root.title("🛡️ Log Analysis & Threat Detection Tool")
        self.root.configure(bg=BG)
        self.root.geometry("1100x700")
        self.root.resizable(True, True)
        self.build_ui()

    def build_ui(self):
        # ── Title Bar ─────────────────────────────────────
        title_frame = tk.Frame(self.root, bg=PANEL, pady=10)
        title_frame.pack(fill="x")

        tk.Label(
            title_frame,
            text="🛡️  Log Analysis & Threat Detection Tool",
            bg=PANEL, fg=ACCENT,
            font=("Consolas", 16, "bold")
        ).pack(side="left", padx=20)

        tk.Label(
            title_frame,
            text=f"Real-Time SOC Dashboard — {DEVICE_NAME}",
            bg=PANEL, fg=TEXT,
            font=("Consolas", 10)
        ).pack(side="right", padx=20)

        # ── Control Bar ───────────────────────────────────
        control_frame = tk.Frame(self.root, bg=BG, pady=8)
        control_frame.pack(fill="x", padx=15)

        tk.Button(
            control_frame,
            text="🖥️  Scan My Device",
            command=self.scan_device,
            bg="#8957e5", fg="white",
            font=("Consolas", 10, "bold"),
            relief="flat", padx=10, pady=5, cursor="hand2"
        ).pack(side="left", padx=5)

        tk.Button(
            control_frame,
            text="💾  Export TXT",
            command=self.export_txt,
            bg="#238636", fg="white",
            font=("Consolas", 10, "bold"),
            relief="flat", padx=10, pady=5, cursor="hand2"
        ).pack(side="left", padx=5)

        tk.Button(
            control_frame,
            text="💾  Export CSV",
            command=self.export_csv,
            bg="#238636", fg="white",
            font=("Consolas", 10, "bold"),
            relief="flat", padx=10, pady=5, cursor="hand2"
        ).pack(side="left", padx=5)

        tk.Button(
            control_frame,
            text="🗑️  Clear",
            command=self.clear_all,
            bg="#da3633", fg="white",
            font=("Consolas", 10, "bold"),
            relief="flat", padx=10, pady=5, cursor="hand2"
        ).pack(side="left", padx=5)

        # ── Days Back Selector ────────────────────────────────
        tk.Label(
            control_frame, text="Scan last:",
            bg=BG, fg=TEXT,
            font=("Consolas", 10)
        ).pack(side="left", padx=(20, 2))

        self.days_var = tk.StringVar(value="7")
        days_menu = ttk.Combobox(
            control_frame,
            textvariable=self.days_var,
            values=["1", "3", "7", "14", "30"],
            width=5,
            state="readonly"
        )
        days_menu.pack(side="left", padx=5)

        tk.Label(
            control_frame, text="days",
            bg=BG, fg=TEXT,
            font=("Consolas", 10)
        ).pack(side="left")

        # ── Search Bar ────────────────────────────────────
        tk.Label(
            control_frame, text="🔍",
            bg=BG, fg=TEXT,
            font=("Consolas", 12)
        ).pack(side="left", padx=(20, 2))

        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda *a: self.filter_threats())
        tk.Entry(
            control_frame,
            textvariable=self.search_var,
            bg=PANEL, fg=TEXT,
            insertbackground=TEXT,
            font=("Consolas", 10),
            relief="flat", width=20
        ).pack(side="left", padx=5)

        # ── Severity Filter ───────────────────────────────
        self.filter_var = tk.StringVar(value="ALL")
        for sev in ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            color = SEVERITY_COLORS.get(sev, ACCENT)
            tk.Radiobutton(
                control_frame, text=sev,
                variable=self.filter_var, value=sev,
                command=self.filter_threats,
                bg=BG, fg=color,
                selectcolor=BG,
                font=("Consolas", 9, "bold"),
                activebackground=BG
            ).pack(side="left", padx=4)

        # ── Summary Cards ─────────────────────────────────
        self.summary_frame = tk.Frame(self.root, bg=BG)
        self.summary_frame.pack(fill="x", padx=15, pady=5)
        self.summary_labels = {}

        for sev, color in [
            ("CRITICAL", CRITICAL),
            ("HIGH",     HIGH),
            ("MEDIUM",   MEDIUM),
            ("LOW",      LOW),
            ("TOTAL",    ACCENT)
        ]:
            card = tk.Frame(self.summary_frame, bg=PANEL, padx=15, pady=8)
            card.pack(side="left", padx=5)
            tk.Label(
                card, text=sev,
                bg=PANEL, fg=color,
                font=("Consolas", 9, "bold")
            ).pack()
            lbl = tk.Label(
                card, text="0",
                bg=PANEL, fg=color,
                font=("Consolas", 18, "bold")
            )
            lbl.pack()
            self.summary_labels[sev] = lbl

        # ── Threat Table ──────────────────────────────────
        table_frame = tk.Frame(self.root, bg=BG)
        table_frame.pack(fill="both", expand=True, padx=15, pady=5)

        columns = ("severity", "threat_type", "account",
                   "computer", "source", "date", "details")
        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            height=20
        )

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
            background=PANEL, foreground=TEXT,
            fieldbackground=PANEL, rowheight=28,
            font=("Consolas", 9))
        style.configure("Treeview.Heading",
            background=BG, foreground=ACCENT,
            font=("Consolas", 9, "bold"), relief="flat")
        style.map("Treeview",
            background=[("selected", "#1f6feb")])

        headers = {
            "severity"    : ("Severity",    90),
            "threat_type" : ("Threat Type", 200),
            "account"     : ("Account",     120),
            "computer"    : ("Computer",    120),
            "source"      : ("Source",      150),
            "date"        : ("Date",        160),
            "details"     : ("Details",     350),
        }

        for col, (head, width) in headers.items():
            self.tree.heading(col, text=head)
            self.tree.column(col, width=width, anchor="w")

        scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.tree.yview
        )
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # ── Status Bar ────────────────────────────────────
        self.status_var = tk.StringVar(
            value="Ready — Click 'Scan My Device' to begin analysis."
        )
        tk.Label(
            self.root,
            textvariable=self.status_var,
            bg=PANEL, fg=TEXT,
            font=("Consolas", 9),
            anchor="w", padx=10
        ).pack(fill="x", side="bottom")

    # ── Methods ───────────────────────────────────────────
    def scan_device(self, days=30):
        from core.parser import fetch_logs, parse_logs
        from core.detector import run_all_detections

        self.status_var.set("[*] Scanning real device logs...")
        self.root.update()

        all_logs = []
        for log_name in ["System", "Security", "Application"]:
            raw  = fetch_logs(log_name, count=5000, days=days)
            logs = parse_logs(raw)
            all_logs.extend(logs)

        threats = run_all_detections(all_logs)
        self.all_threats.extend(threats)
        self.refresh_table(self.all_threats)
        self.status_var.set(
            f"[+] Scan complete! {len(threats)} threats found."
        )
        
    def refresh_table(self, threats):
        for row in self.tree.get_children():
            self.tree.delete(row)

        for t in threats:
            color = SEVERITY_COLORS.get(t.get("severity"), TEXT)
            self.tree.insert(
                "", "end",
                values=(
                    t.get("severity"),
                    t.get("threat_type"),
                    t.get("account")   or "N/A",
                    t.get("computer")  or "N/A",
                    t.get("source")   or "N/A",
                    t.get("date")      or "N/A",
                    t.get("details")   or "N/A",
                ),
                tags=(t.get("severity"),)
            )
            self.tree.tag_configure(
                t.get("severity"), foreground=color
            )

        self.update_summary(threats)

    def update_summary(self, threats):
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = len([
                t for t in threats
                if t.get("severity") == sev
            ])
            self.summary_labels[sev].config(text=str(count))
        self.summary_labels["TOTAL"].config(
            text=str(len(threats))
        )

    def filter_threats(self):
        keyword  = self.search_var.get().lower()
        sev      = self.filter_var.get()
        filtered = [
            t for t in self.all_threats
            if (sev == "ALL" or t.get("severity") == sev)
            and (keyword in str(t).lower())
        ]
        self.refresh_table(filtered)

    def export_txt(self):
        if not self.all_threats:
            messagebox.showwarning(
                "No Data",
                "Scan your device first!"
            )
            return
        generate_txt_report(self.all_threats)
        messagebox.showinfo(
            "Exported",
            "Report saved to exports/report.txt"
        )

    def export_csv(self):
        if not self.all_threats:
            messagebox.showwarning(
                "No Data",
                "Scan your device first!"
            )
            return
        generate_csv_report(self.all_threats)
        messagebox.showinfo(
            "Exported",
            "Report saved to exports/report.csv"
        )

    def clear_all(self):
        self.all_threats = []
        self.refresh_table([])
        self.status_var.set(
            "Cleared. Click 'Scan My Device' to scan again."
        )

# ── Entry Point ───────────────────────────────────────────
if __name__ == "__main__":
    root = tk.Tk()
    app  = Dashboard(root)
    root.mainloop()
