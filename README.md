# 🛡️ Log Analysis & Threat Detection Tool

A real-time Python-based SOC (Security Operations Center) tool 
that reads actual Windows Event Logs, detects suspicious 
activities automatically, and displays results on a 
professional dark-themed GUI dashboard.



## 📌 Features

- ✅ Reads real Windows Event Logs (System, Security, Application)
- ✅ Detects Privilege Escalation
- ✅ Detects Brute Force Attacks (time-based sliding window)
- ✅ Detects Account Lockouts
- ✅ Detects New User Creation
- ✅ Detects Unusual Login Times (night + weekends)
- ✅ Detects External IP Logins
- ✅ Detects New Service Installation
- ✅ Detects Audit Log Clearing
- ✅ Correlation Engine (combines multiple indicators)
- ✅ Severity Levels (CRITICAL / HIGH / MEDIUM / LOW)
- ✅ Export reports as TXT and CSV
- ✅ Real-time Search and Filter
- ✅ Dark-themed SOC Dashboard
---

- 🔹 Historical Log Scanning
- 
- Allows users to select the number of past days to scan.
- Supports scanning logs from a selected time range instead of only recent/current events.
- Helps analyse historical security activity and identify threats that occurred earlier.
- Displays the results through the SOC dashboard and generates corresponding TXT and CSV reports.

---

## 🗂️ Project Structure

real_log_analyzer/
│
├── main.py # Entry point
├── README.md
│
├── core/
│ ├── parser.py # Log collection + parsing engine
│ ├── detector.py # Threat detection + correlation
│ └── reporter.py # TXT + CSV report generation
│
├── gui/
│ └── dashboard.py # Tkinter SOC Dashboard
│
└── exports/ # Generated reports saved here



## ⚙️ Requirements

- Python 3.x
- Windows OS (uses wevtutil for log collection)
- Run as Administrator (required for Security logs)
- tkinter (built-in with Python)
- No external libraries needed!



## 🚀 How to Run

```bash
git clone https://github.com/yourusername/real-log-analyzer.git
cd real-log-analyzer
```

Right click IDLE → Run as Administrator

```bash
python main.py
```



## 🔍 How to Use

1. Run `main.py` as Administrator
2. Click **🖥️ Scan My Device**
3. Wait for scan to complete
4. View detected threats with colour coded severity
5. Use **Search** and **Filter** to narrow results
6. Click **Export TXT** or **Export CSV** to save report

---

## 🎯 Threat Detection Rules

| Threat | Event ID | Severity |
|--------|----------|----------|
| Brute Force Attack | 4625 | CRITICAL |
| Privilege Escalation | 4672, 4732 | HIGH |
| New User Created | 4720 | HIGH |
| New Service Installed | 7045 | HIGH |
| Account Lockout | 4740 | MEDIUM |
| Unusual Login Time | 4624 | MEDIUM |
| External IP Login | 4624 | MEDIUM |
| Audit Log Cleared | 1102 | CRITICAL |

---

## 🧠 Correlation Rules

| Combination | Upgraded Severity |
|-------------|------------------|
| New User + Unusual Time + External IP | CRITICAL |
| Brute Force + Successful Login | CRITICAL |
| Privilege Escalation + Unusual Time | CRITICAL |

---

## 👩‍💻 Built By

**Sanskruti**  
Diploma in Computer Engineering  
Dr. D. Y. Patil Polytechnic, Kasaba Bawada  
Cyber Security & Ethical Hacking Internship Project — 2026

