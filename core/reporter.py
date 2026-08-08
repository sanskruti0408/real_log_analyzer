import csv
import os
from datetime import datetime
import socket

DEVICE_NAME = socket.gethostname()


def generate_txt_report(threats, filepath="exports/report.txt"):
    os.makedirs("exports", exist_ok= True)

    with open(filepath, 'w') as f:
        # Header
        f.write("=" * 60 + "\n")
        f.write(" LOG ANALYSIS & THREAT DETECTION REPORT \n")
        f.write(f" Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f" Computer  : {DEVICE_NAME}\n")
        f.write("=" * 60 + "\n\n")

        #Summary
        critical = len([t for t in threats if t.get('severity') == 'CRITICAL'])
        high     = len([t for t in threats if t.get('severity') == 'HIGH'])
        medium   = len([t for t in threats if t.get('severity') == 'MEDIUM'])
        low      = len([t for t in threats if t.get('severity') == 'LOW']) 

        f.write(" SUMMARY\n")
        f.write(f" Total Threats : {len(threats)}\n")
        f.write(f" CRITICAL      : {critical}\n")
        f.write(f" HIGH          : {high}\n")
        f.write(f" MEDIUM        : {medium}\n")
        f.write(f" LOW           : {low}\n")
        f.write(f"\n" + "=" * 60 + "\n")
        f.write(" DETAILED FINDING\n")
        f.write("=" * 60 + "\n\n")

        # Detailed threats
        for i, t in enumerate(threats, 1):
            f.write(f" [{i}] [{t.get('severity')}] {t.get('threat_type')}\n")
            f.write(f"  Account  : {t.get('account')}\n")
            f.write(f"  Computer : {t.get('computer')}\n")
            f.write(f"  Date     : {t.get('date')}\n")
            f.write(f"  Event ID : {t.get('event_id')}\n")
            f.write(f"  Details  : {t.get('details')}\n")
            f.write("\n")

        f.write("=" * 60 + "\n")
        f.write(" END OF REPORT\n")
        f.write("=" * 60 + "\n")

    print(f"[+] TXT report saved -> {filepath}")


def generate_csv_report(threats, filepath="exports/report.csv"):
    os.makedirs("exports", exist_ok = True)

    with open(filepath, 'w',  newline='') as f:
        fieldnames = [
            "threat_type","severity", "account",
            "computer", "date", "event_id", "details"
            ]
        writer = csv.DictWriter(f, fieldnames = fieldnames)
        writer.writeheader()

        for t in threats:
            writer.writerow({
                "threat_type"  : t.get("threat_type"),
                "severity"     : t.get("severity"),
                "account"     : t.get("account"),
                "computer"    : t.get("computer"),
                "date"        : t.get("date"),
                "event_id"    : t.get("event_id"),
                "details"     : t.get("details")
                })

    print(f"[+] CSV report saved -> {filepath}")




        
