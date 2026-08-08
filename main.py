from core.parser import fetch_logs, parse_logs
from core.detector import run_all_detections
from core.reporter import generate_txt_report, generate_csv_report
import tkinter as tk
from gui.dashboard import Dashboard

log_names = [
    "System",
    "Security",
    "Application"
]

all_logs = []

for log_name in log_names:
    raw = fetch_logs(log_name, 50)
    logs = parse_logs(raw)
    all_logs.extend(logs)

threats = run_all_detections(all_logs)

print(f"\n{'='*60}")
print(f" THREATS DETECTED : {len(threats)}")
print(f"{'='*60}\n")

for t in threats:
    print(f"[{t.get('severity')}] {t.get('threat_type')}")
    print(f" Account      : {t.get('account')}")
    print(f" Computer     : {t.get('computer')}")
    print(f" Date         : {t.get('date')}")
    print(f" Details      : {t.get('details')}")
    print()
    

generate_txt_report(threats)
generate_csv_report(threats)

if __name__ == "__main__":
    root = tk.Tk()
    app  = Dashboard(root)
    root.mainloop()



