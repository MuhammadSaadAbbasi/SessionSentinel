"""
SessionSentinel - Local Attack Lab
A visual, bounded demonstration against seeded local test accounts only.

Requirements:
    pip install requests

Run from your backend/project folder:
    python attacker.py

The simulator is hard-bound to loopback. Brute force tries distinct wrong
passwords on one demo user; password spray tries one fixed wrong password on
each of two demo users. It stops on HTTP 429. It does not spoof or rotate IPs.
"""

import queue
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox

import requests

API_URL = "http://127.0.0.1:8000/login"
DEMO_EMAIL = "ali@test.com"
DEMO_EMAILS = ["ali@test.com", "sara@test.com"]
DEVICE_ID = "sessionsentinel-attacker-lab"
WRONG_PASSWORDS = [
    "DefinitelyWrong-01!", "DefinitelyWrong-02!", "DefinitelyWrong-03!",
    "DefinitelyWrong-04!", "DefinitelyWrong-05!", "DefinitelyWrong-06!",
    "DefinitelyWrong-07!", "DefinitelyWrong-08!", "DefinitelyWrong-09!",
    "DefinitelyWrong-10!",
]

BG = "#09090b"
PANEL = "#151114"
PANEL2 = "#0d0b0d"
RED = "#ff263b"
RED_DARK = "#6e1420"
GREEN = "#ff3b4f"
CYAN = "#ff8a8a"
TEXT = "#f0e7e8"
MUTED = "#9c8589"
AMBER = "#ffb454"


class AttackLab:
    def __init__(self, root):
        self.root = root
        self.root.title("SENTINEL // THREAT SIMULATION CONSOLE")
        self.root.geometry("1120x740")
        self.root.minsize(980, 680)
        self.root.configure(bg=BG)
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("TCombobox", fieldbackground="#21191c", background="#21191c",
                        foreground=TEXT, arrowcolor=RED, bordercolor="#54202a")
        style.map("TCombobox", fieldbackground=[("readonly", "#21191c")],
                  foreground=[("readonly", TEXT)])
        style.configure("TEntry", fieldbackground="#21191c", foreground=TEXT,
                        insertcolor=RED, bordercolor="#54202a")

        self.events = queue.Queue()
        self.running = False
        self.worker = None
        self.frame = 0
        self.scan_y = 0
        self.attempt_count = 0
        self.after_id = None

        self._build_ui()
        self._animate()
        self._poll_events()
        self._log("LAB READY — waiting for operator.")
        self._log("Target locked to one local seeded test account.")
        self._log("No real credentials or external targets are used.")

    def _build_ui(self):
        header = tk.Frame(self.root, bg=BG)
        header.pack(fill="x", padx=22, pady=(18, 10))
        tk.Label(header, text="●", fg=RED, bg=BG,
                 font=("Consolas", 15, "bold")).pack(side="left", padx=(0, 8))
        tk.Label(header, text="SENTINEL", fg=RED, bg=BG,
                 font=("Consolas", 25, "bold")).pack(side="left")
        tk.Label(header, text="// THREAT SIMULATION CONSOLE", fg=TEXT, bg=BG,
                 font=("Consolas", 14, "bold")).pack(side="left", padx=(10, 0))
        tk.Label(header, text="CONTAINED LAB  |  LOOPBACK ONLY", fg=AMBER, bg=BG,
                 font=("Consolas", 10, "bold")).pack(side="right", pady=10)
        tk.Frame(self.root, bg=RED, height=2).pack(fill="x", padx=22)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True, padx=22, pady=8)
        left = tk.Frame(body, bg=PANEL, highlightbackground="#64202a",
                        highlightthickness=1, width=310)
        left.pack(side="left", fill="y", padx=(0, 12))
        left.pack_propagate(False)
        right = tk.Frame(body, bg=PANEL, highlightbackground="#64202a",
                         highlightthickness=1)
        right.pack(side="left", fill="both", expand=True)

        tk.Label(left, text="THREAT ACTOR // SIMULATED", fg=CYAN, bg=PANEL,
                 font=("Consolas", 11, "bold")).pack(anchor="w", padx=15, pady=(14, 6))
        self.avatar = tk.Canvas(left, width=270, height=245, bg=PANEL2,
                                highlightthickness=0)
        self.avatar.pack(padx=15, fill="x")
        tk.Label(left, text="UNATTRIBUTED OPERATOR", fg=RED, bg=PANEL,
                 font=("Consolas", 13, "bold")).pack(pady=(12, 2))
        tk.Label(left, text="SIMULATED CHARACTER // NOT A REAL PERSON",
                 fg=MUTED, bg=PANEL, font=("Consolas", 8)).pack()

        tk.Frame(left, bg="#64202a", height=1).pack(fill="x", padx=15, pady=15)
        tk.Label(left, text="TARGET // LOCAL TEST ACCOUNT", fg=MUTED, bg=PANEL,
                 font=("Consolas", 9, "bold")).pack(anchor="w", padx=15)
        tk.Label(left, text=DEMO_EMAIL, fg=TEXT, bg=PANEL,
                 font=("Consolas", 12, "bold")).pack(anchor="w", padx=15, pady=(4, 10))
        tk.Label(left, text="MODE", fg=MUTED, bg=PANEL,
                 font=("Consolas", 9, "bold")).pack(anchor="w", padx=15)
        self.mode_var = tk.StringVar(value="Brute force")
        self.mode_box = ttk.Combobox(left, textvariable=self.mode_var,
                                     values=["Brute force", "Password spray", "Token demo"],
                                     state="readonly")
        self.mode_box.pack(fill="x", padx=15, pady=(4, 10))
        self.login_email_var = tk.StringVar(value=DEMO_EMAIL)
        self.login_password_var = tk.StringVar()
        self.start_btn = tk.Button(
            left, text="▶  START DEMO", command=self.start_demo,
            bg=RED, fg="white", activebackground="#d92e45",
            activeforeground="white", relief="flat", cursor="hand2",
            font=("Consolas", 11, "bold"), pady=11
        )
        self.start_btn.pack(fill="x", padx=15, pady=(4, 8))
        self.stop_btn = tk.Button(
            left, text="■  STOP", command=self.stop_demo,
            bg="#263541", fg=TEXT, activebackground="#344957",
            relief="flat", cursor="hand2", font=("Consolas", 10, "bold"),
            pady=9, state="disabled"
        )
        self.stop_btn.pack(fill="x", padx=15)
        self.token_form = tk.Frame(left, bg=PANEL)
        tk.Label(self.token_form, text="TOKEN DEMO // LOCAL TEST LOGIN", fg=MUTED, bg=PANEL,
                 font=("Consolas", 9, "bold")).pack(anchor="w", pady=(10, 2))
        ttk.Entry(self.token_form, textvariable=self.login_email_var).pack(fill="x", pady=(2, 5))
        ttk.Entry(self.token_form, textvariable=self.login_password_var, show="•").pack(fill="x")
        self.mode_box.bind("<<ComboboxSelected>>", self._toggle_token_form)

        tk.Label(right, text="LIVE TELEMETRY  /  AUTH EVENTS", fg=CYAN, bg=PANEL,
                 font=("Consolas", 11, "bold")).pack(anchor="w", padx=16, pady=(14, 8))
        self.terminal = tk.Text(
            right, bg="#05090d", fg=GREEN, insertbackground=GREEN,
            selectbackground="#234438", relief="flat", wrap="word",
            font=("Consolas", 10), padx=13, pady=12, height=22
        )
        self.terminal.pack(fill="both", expand=True, padx=15)
        self.terminal.tag_config("bad", foreground=RED)
        self.terminal.tag_config("warn", foreground=AMBER)
        self.terminal.tag_config("info", foreground=CYAN)

        stats = tk.Frame(right, bg=PANEL)
        stats.pack(fill="x", padx=15, pady=12)
        self.attempt_var = tk.StringVar(value="0 / 10")
        self.status_var = tk.StringVar(value="STANDBY")
        self._stat(stats, "ATTEMPTS", self.attempt_var, 0)
        self._stat(stats, "DEFENSE STATUS", self.status_var, 1)

        footer = tk.Frame(self.root, bg=BG)
        footer.pack(fill="x", padx=22, pady=(0, 15))
        tk.Label(footer, text="DETECTION POLICY  //  R1 HIGH: 5 FAILURES  •  CRITICAL: 10",
                 fg=MUTED, bg=BG, font=("Consolas", 9)).pack(side="left")
        tk.Label(footer, text="⚠ AUTHORIZED LOCAL TESTING ONLY",
                 fg=RED, bg=BG, font=("Consolas", 9, "bold")).pack(side="right")

    def _stat(self, parent, label, variable, column):
        card = tk.Frame(parent, bg=PANEL2, padx=12, pady=9)
        card.grid(row=0, column=column, sticky="ew", padx=(0, 8))
        parent.grid_columnconfigure(column, weight=1)
        tk.Label(card, text=label, fg=MUTED, bg=PANEL2,
                 font=("Consolas", 8, "bold")).pack(anchor="w")
        tk.Label(card, textvariable=variable, fg=GREEN if column == 0 else AMBER,
                 bg=PANEL2, font=("Consolas", 13, "bold")).pack(anchor="w", pady=(3, 0))

    def _toggle_token_form(self, _event=None):
        if self.mode_var.get() == "Token demo":
            self.token_form.pack(fill="x", padx=15, pady=(0, 8))
        else:
            self.token_form.pack_forget()

    def _draw_avatar(self):
        c = self.avatar
        c.delete("all")
        w, h = 270, 245
        c.create_rectangle(8, 8, w-8, h-8, outline="#203441")
        # Decorative scan lines
        for y in range(12, h, 8):
            c.create_line(10, y, w-10, y, fill="#101f29")
        # Hood silhouette
        c.create_oval(57, 25, 213, 210, fill="#101820", outline=RED, width=2)
        c.create_polygon(55, 125, 77, 49, 135, 23, 193, 49, 216, 125,
                         194, 205, 76, 205, fill="#17232d", outline="#314653", width=2)
        # Face mask
        c.create_oval(83, 68, 187, 179, fill="#080d12", outline="#435765", width=2)
        blink = self.frame % 48 in (0, 1, 2)
        eye_color = "#0b1117" if blink else RED
        if blink:
            c.create_line(99, 113, 126, 113, fill=RED, width=3)
            c.create_line(144, 113, 171, 113, fill=RED, width=3)
        else:
            c.create_polygon(96, 104, 130, 110, 124, 124, 98, 119,
                             fill=eye_color, outline=RED)
            c.create_polygon(140, 110, 174, 104, 172, 119, 146, 124,
                             fill=eye_color, outline=RED)
        c.create_line(135, 124, 128, 151, 143, 151, fill="#536775", width=2)
        c.create_line(110, 165, 160, 165, fill=RED_DARK, width=3)
        # Animated circuit traces
        pulse = self.frame % 20
        c.create_line(25, 190, 48, 190, 60, 178, 76, 178,
                      fill=CYAN if pulse < 10 else "#28505a", width=2)
        c.create_line(194, 178, 210, 178, 222, 190, 245, 190,
                      fill=CYAN if pulse >= 10 else "#28505a", width=2)
        c.create_text(135, 224, text="OPERATOR // SIMULATED",
                      fill=MUTED, font=("Consolas", 8))

    def _animate(self):
        self.frame += 1
        self._draw_avatar()
        self.root.after(110, self._animate)

    def _log(self, message, tag=None):
        stamp = time.strftime("%H:%M:%S")
        self.terminal.insert("end", f"[{stamp}] {message}\n", tag or "")
        self.terminal.see("end")

    def start_demo(self):
        if self.running:
            return
        if not messagebox.askyesno(
            "Confirm local simulation",
            ("Brute force and password spray use deliberately wrong passwords.\n"
             "Token demo sends one login using the test credentials entered in the form.\n\n"
             "All requests target 127.0.0.1 only. No source IPs are spoofed. Continue?")
        ):
            return
        self.running = True
        self.attempt_count = 0
        mode = self.mode_var.get()
        total = len(WRONG_PASSWORDS) if mode == "Brute force" else (1 if mode == "Token demo" else len(DEMO_EMAILS))
        self.attempt_var.set(f"0 / {total}")
        self.status_var.set("SIMULATION RUNNING")
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self._log(f"SIMULATION STARTED — {self.mode_var.get()} — loopback only.", "info")
        self.worker = threading.Thread(target=self._run_requests, daemon=True)
        self.worker.start()

    def _run_requests(self):
        mode = self.mode_var.get()
        if mode == "Token demo":
            pairs = [(self.login_email_var.get().strip(), self.login_password_var.get())]
        elif mode == "Brute force":
            pairs = [(DEMO_EMAIL, password) for password in WRONG_PASSWORDS]
        else:
            pairs = [(email, "DefinitelyWrong-Spray-01!") for email in DEMO_EMAILS]
        for index, (email, password) in enumerate(pairs, start=1):
            if not self.running:
                self.events.put(("log", "Operator stopped the simulation.", "warn"))
                break
            try:
                response = requests.post(
                    API_URL,
                    json={
                    "email": email,
                        "password": password,
                        "device_id": DEVICE_ID,
                    },
                    timeout=4,
                )
                self.events.put(("attempt", index))
                if response.status_code == 401:
                    self.events.put(("log", f"Attempt {index:02d}: email={email} password={password} — HTTP 401.", "bad"))
                elif response.status_code == 429:
                    self.events.put(("log", f"Attempt {index:02d}: email={email} password={password} — HTTP 429; throttled.", "warn"))
                    self.events.put(("defense", "R1 THROTTLE ACTIVE"))
                    break
                elif response.status_code == 403:
                    self.events.put(("log", f"Attempt {index:02d}: email={email} password={password} — HTTP 403; policy blocked.", "warn"))
                    break
                else:
                    self.events.put(("log", f"Attempt {index:02d}: email={email} password={password} — HTTP {response.status_code}.", "info"))
                    if response.status_code == 200:
                        try:
                            token = response.json().get("token")
                        except (ValueError, AttributeError):
                            token = None
                        if token:
                            self.events.put(("token", token))
                        self.events.put(("log", "Login succeeded. Token shown in the dedicated result window.", "info"))
                        break
            except requests.RequestException as exc:
                self.events.put(("log", f"Connection error: {exc}", "bad"))
                self.events.put(("defense", "BACKEND UNREACHABLE"))
                break
            time.sleep(0.45)
        self.events.put(("finished", None))

    def _poll_events(self):
        try:
            while True:
                kind, value, *extra = self.events.get_nowait()
                if kind == "log":
                    self._log(value, extra[0] if extra else None)
                elif kind == "attempt":
                    self.attempt_count = value
                    total = len(WRONG_PASSWORDS) if self.mode_var.get() == "Brute force" else (1 if self.mode_var.get() == "Token demo" else len(DEMO_EMAILS))
                    self.attempt_var.set(f"{value} / {total}")
                elif kind == "token":
                    messagebox.showinfo(
                        "Local demo session token",
                        f"{value}\n\nKeep this token private. It grants access to this session.",
                    )
                elif kind == "defense":
                    self.status_var.set(value)
                elif kind == "finished":
                    self.running = False
                    self.start_btn.config(state="normal")
                    self.stop_btn.config(state="disabled")
                    if self.status_var.get() == "SIMULATION RUNNING":
                        self.status_var.set("DEMO COMPLETE")
                    self._log("SIMULATION FINISHED.", "info")
        except queue.Empty:
            pass
        self.root.after(100, self._poll_events)

    def stop_demo(self):
        self.running = False
        self.status_var.set("STOPPING...")
        self.stop_btn.config(state="disabled")


if __name__ == "__main__":
    root = tk.Tk()
    app = AttackLab(root)
    root.mainloop()
