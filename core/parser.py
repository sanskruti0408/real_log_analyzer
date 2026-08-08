import subprocess
import re
from datetime import datetime

def fetch_logs(log_name, count):
    cmd = f'wevtutil qe {log_name} /c:{count} /f:text /rd:true'

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        shell=True
    )
    return result.stdout

def parse_logs(raw_text):
    events = raw_text.strip().split("\n\n")
    parsed = []

    for event in events:
        if not event.strip():
            continue

        data = {
            "log_name"      : None,
            "source"        : None,
            "date"          : None,
            "event_id"      : None,
            "level"         : None,
            "user_name"     : None,
            "computer"      : None,
            "description"   : None,
            "log_type"      : "windows"
            }


        lines = event.strip().split("\n")

        i=0

        while i < len(lines):
            line = lines[i].strip()

            if ":" in line:
                key, value = line.split(":",1)
                key = key.strip().lower().replace(" ", "_")
               
                value = value.strip()
                

                if key == "log_name":
                    data["log_name"] = value.strip()
                elif key == "source":
                    data["source"] = value.strip()
                elif key == "date":
                    data["date"] = value.strip()
                elif key == "event_id":
                    data["event_id"] = value.strip()
                elif key == "level":
                    data["level"] = value.strip()
                elif key == "user_name":
                    if value and value not in ["N/A", "-", ""]:
                        data["user_name"] = value.strip()
                elif key == "computer":
                    data["computer"] = value.strip()
                elif key == "description":
                    i+=1
                    desc = []
                    
                    while i < len(lines) and lines[i].strip():
                        desc.append(lines[i].strip())
                        i += 1
                    data["description"] = " ".join(desc)
            i += 1

        parsed.append(data)
    return parsed
        
