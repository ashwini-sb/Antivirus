import os
import hashlib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import time
import json
from datetime import datetime


class AntivirusGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🦅 Real Antivirus - Eagle Vision Edition")
        self.root.geometry("980x680")
        self.root.configure(bg="#0a0f1f")

        
        self.virus_db = {
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Generic.Trojan",
            "5d41402abc4b2a76b9719d911017c592": "EICAR.Test.Virus",
            "d41d8cd98f00b204e9800998ecf8427e": "Suspicious.EmptyFile"
        }

        self.scanned_files = []
        self.infected_files = []

        self.setup_ui()

    def setup_ui(self):
        # Title
        title_frame = tk.Frame(self.root, bg="#0a0f1f")
        title_frame.pack(pady=25)

        title = tk.Label(
            title_frame,
            text="🦅 REAL ANTIVIRUS",
            font=("Orbitron", 26, "bold"),
            fg="#00ffff",
            bg="#0a0f1f"
        )
        title.pack()
        subtitle = tk.Label(
            title_frame,
            text="EAGLE VISION CYBER EDITION",
            font=("Rajdhani", 14),
            fg="#9d8bff",
            bg="#0a0f1f"
        )
        subtitle.pack()

        # Control Panel - Centered
        control_frame = tk.Frame(self.root, bg="#101425", highlightthickness=1)
        control_frame.config(highlightbackground="#00ffff", highlightcolor="#00ffff")
        control_frame.pack(pady=35)

        style = {"font": ("Rajdhani", 13, "bold"), "width": 20, "height": 2, "relief": "flat"}

        # Centering buttons using pack
        scan_btn = tk.Button(control_frame, text="🔍 SCAN FOLDER", command=self.select_and_scan,
                             bg="#00ffff", fg="#000", activebackground="#38bdf8", **style)
        scan_btn.pack(side="left", padx=25, pady=15)

        export_btn = tk.Button(control_frame, text="📁 EXPORT REPORT", command=self.export_report,
                               bg="#a855f7", fg="#fff", activebackground="#c084fc", **style)
        export_btn.pack(side="left", padx=25, pady=15)

        clear_btn = tk.Button(control_frame, text="🧹 CLEAR LOGS", command=self.clear_logs,
                              bg="#f43f5e", fg="#fff", activebackground="#fb7185", **style)
        clear_btn.pack(side="left", padx=25, pady=15)

        # Progress bar
        tk.Label(self.root, text="SCAN PROGRESS", bg="#0a0f1f", fg="#00ffff",
                 font=("Orbitron", 12, "bold")).pack(pady=(20, 5))
        self.progress = ttk.Progressbar(self.root, orient="horizontal", length=800, mode="determinate")
        self.progress.pack(pady=10)

        self.stats_label = tk.Label(self.root, text="", fg="#9d8bff", bg="#0a0f1f", font=("Rajdhani", 12))
        self.stats_label.pack()

        # Log Frame
        log_frame = tk.Frame(self.root, bg="#101425", highlightthickness=1)
        log_frame.config(highlightbackground="#a855f7", highlightcolor="#a855f7")
        log_frame.pack(padx=20, pady=25, fill="both", expand=True)

        log_title = tk.Label(log_frame, text="SYSTEM LOGS", font=("Orbitron", 12, "bold"),
                             bg="#101425", fg="#00ffff")
        log_title.pack(pady=5)

        self.log_text = tk.Text(
            log_frame, height=18, width=100, bg="#0f172a", fg="#00ff99",
            insertbackground="#fff", font=("Consolas", 10), relief="flat", padx=10, pady=10
        )
        self.log_text.pack(padx=10, pady=10, fill="both", expand=True)

        self.log("🦅 Eagle Vision Antivirus System Initialized Successfully.")

   
    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()

    
    def select_and_scan(self):
        folder = filedialog.askdirectory(title="Select Folder to Scan")
        if not folder:
            return

        self.scanned_files.clear()
        self.infected_files.clear()
        self.log_text.delete(1.0, tk.END)
        self.log(f"🌀 Initiating scan in folder: {folder}")

        files = [os.path.join(dp, f) for dp, dn, filenames in os.walk(folder) for f in filenames]
        total = len(files)
        if total == 0:
            self.log("⚠ No files found in the selected directory.")
            return

        self.progress["value"] = 0
        self.progress["maximum"] = total
        infected_count = 0

        for i, file_path in enumerate(files):
            self.root.update_idletasks()
            infected = self.scan_file(file_path)
            if infected:
                infected_count += 1
            self.progress["value"] = i + 1
            time.sleep(0.03)

        self.stats_label.config(
            text=f"FILES SCANNED: {total} | INFECTED: {infected_count} | CLEAN: {total - infected_count}"
        )
        self.log("✅ SCAN COMPLETED SUCCESSFULLY")


    def scan_file(self, file_path):
        try:
            with open(file_path, "rb") as f:
                sha256_hash = hashlib.sha256(f.read()).hexdigest()
            self.scanned_files.append(file_path)

            if sha256_hash in self.virus_db:
                virus_name = self.virus_db[sha256_hash]
                self.infected_files.append({"file": file_path, "virus": virus_name})
                self.log(f"⚠ INFECTED → {file_path} ({virus_name})")
                return True
            else:
                self.log(f"✔ CLEAN → {file_path}")
                return False
        except Exception as e:
            self.log(f"❌ ERROR scanning {file_path}: {e}")
            return False

   
    def export_report(self):
        if not self.scanned_files:
            messagebox.showwarning("No Data", "Please run a scan before exporting a report.")
            return

        report_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_scanned": len(self.scanned_files),
            "infected": len(self.infected_files),
            "infected_files": self.infected_files,
        }

        with open("scan_report.json", "w") as f:
            json.dump(report_data, f, indent=4)

        self.log("📁 Report exported as scan_report.json")
        messagebox.showinfo("Export Successful", "Report saved successfully!")

    
    def clear_logs(self):
        self.log_text.delete(1.0, tk.END)
        self.stats_label.config(text="")
        self.log("🧹 Logs cleared. Ready for next operation.")



if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("TProgressbar", troughcolor="#1e293b", background="#00ffff", thickness=18, bordercolor="#000")

    app = AntivirusGUI(root)
    root.mainloop()