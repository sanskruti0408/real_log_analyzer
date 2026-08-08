import re
from datetime import datetime
from collections import defaultdict

# Configuration Rules
BRUTE_FORCE_LIMIT   =5
TIME_WINDOW_MINUTES =5
UNUSUAL_HOUR_START  =23
UNUSUAL_HOUR_END    =5

# Event IDs
EVENT_IDS = {
    "4624" : "Successful Logon",
    "4625" : "Failed Logon",
    "4720" : "User Account Created",
    "4726" : "User Account Deleted",
    "4732" : "User Added to Privileged Group",
    "4740" : "Account Locked Out",
    "4672" : "Special Privileges Assigned",
    "7045" : "New Service Installed",
    "1102" : "Audit Log Cleared"
    }

# Helper Functions

def parse_date(date_str):
    if not date_str:
        return None
    try:
        date_str = date_str.strip()
        if "T" in date_str:
            date_str = date_str[:19].replace("T", " ")
        return datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None

def is_internal_ip(ip):
    if not ip:
        return False
    
    ip = ip.strip()
    if ip in ["N/A", "-", "Local", "::1", "127.0.0.1"]:
        return True
    
    # Class A private
    if ip.startswith("10."):
        return True
    
    # Class C private
    if ip.startswith("192.168."):
        return True
    
    # Class B private - only 172.16 to 172.31
    if ip.startswith("172."):
        second_octet = int(ip.split(".")[1])
        return 16 <= second_octet <= 31
    
    return False

def make_threat(threat_type, severity, log, extra=None):
    if extra is None:
        extra = {}
    return {
        "threat_type"   : threat_type,
        "severity"      : severity,
        "event_id"      : log.get("event_id"),
        "account"       : log.get("user_name"),
        "computer"      : log.get("computer"),
        "source"        : log.get("source"),
        "date"          : log.get("date"),
        "description"   : log.get("description"),
        **extra
        }

# Detection Fuctions

def detect_bruteforce(logs):
    threats  = []
    failed   = defaultdict(list)

    for log in logs:
        if log.get("event_id") == "4625":
            account   = log.get("user_name", "Unknown")
            date      = parse_date(log.get("date"))
            if date:
                failed[account].append((date, log))

    for account, attempts in failed.items():
        attempts.sort(key=lambda x: x[0])

        window = []
        for attempt in attempts:
            window.append(attempt)
            window = [
                a for a in window
                if (attempt[0] - a[0]).total_seconds()
                <= TIME_WINDOW_MINUTES * 60
            ]

            if len(window) >= BRUTE_FORCE_LIMIT:
                first_log = window[0][1]
                last_log  = window[-1][1]
                threats.append(make_threat(
                    threat_type     = "Brute Force Attack",
                    severity        = "HIGH",
                    log             = first_log,
                    extra           = {
                        "attempts"   : len(window),
                        "first_seen" : window[0][0].strftime("%Y-%m-%d %H:%M:%S"),
                        "last_seen"  : window[-1][0].strftime("%Y-%m-%d %H:%M:%S"),
                        "details"    : f"{len(window)} failed logon attempts for "
                                       f"'{account}' within "
                                       f"{TIME_WINDOW_MINUTES} minutes."
                    }
                ))
                break

    return threats

def detect_account_lockout(logs):
    threats = []
    
    for log in logs:
        if log.get("event_id") == "4740":
            threats.append(make_threat(
                threat_type    ="Account Lockout",
                severity       = "Medium",
                log            = log,
                extra          = {
                    "details" : f"Account '{log.get('user_name', 'Unknown')}' "
                                f"was locked out on {log.get('computer')}."
                    }
                ))

    return threats

def detect_new_user(logs):
    threats = []

    for log in logs:
        if log.get("event_id") == "4720":
            threats.append(make_threat(
                threat_type = "New User Account created",
                severity    = "HIGH",
                log         = log,
                extra       = {
                    "details" : f"New user '{log.get('user_name', 'unknown')}' "
                                f"was craeted on {log.get('computer')}."
                    }
                ))

    return threats

def detect_privileges_escalation(logs):
    threats = []

    for log in logs:
        if log.get("event_id") in ["4672", "4732"]:
            threats.append(make_threat(
                threat_type = "Privilege Escalation",
                severity    = "HIGH",
                log         = log,
                extra       = {
                    "details" : f"Special privileges assigned to"
                                f"'{log.get('user_name') or 'Windows Service'}' "
                                f"on {log.get('computer')}."
                    }
                ))

    return threats

def detect_service_installation(logs):
    threats = []

    for log in logs:
        if log.get("event_id") == "7045":
            threats.append(make_threat(
                threat_type = "New Service Installed",
                severity    = "HIGH",
                log         = log,
                extra       = {
                    "details" : f"A new service was installed "
                                f"on {log.get('computer')}. "
                                f"Source: {log.get('source')}."
                    }
                ))

    return threats

def detect_log_clearing(logs):
    threats = []

    for log in logs:
        if log.get("event_id") == "1102":
            threats.append(make_threat(
                threat_type = "Audit Log Cleared",
                severity    = "CRITICAL",
                log         = log,
                extra       = {
                    "details" : f"Security audit log was cleared by "
                                f"'{log.get('user_name', 'Unknown')}' "
                                f"on {log.get('computer')}. "
                                f"This may indicate an attempt to hide activity."
                    }
                ))

    return threats

def detect_unusual_login(logs):
    threats = []

    for log in logs:
        if log.get("event_id") == "4624":
            date = parse_date(log.get("date"))
            if not date:
                continue

            hour    = date.hour
            weekend = date.weekday() >=5

            is_unusual_hour = (
                hour >= UNUSUAL_HOUR_START or
                hour <= UNUSUAL_HOUR_END
                )

            if is_unusual_hour or weekend:
                reason = []
                if is_unusual_hour:
                    reason.append(f"login at {date.strftime('%H:%M:%S')}")
                if weekend:
                    reason.append(f"login on {date.strftime('%A')}")

                threats.append(make_threat(
                    threat_type     = "Unusual Login Time",
                    severity        = "MEDIUM",
                    log             = log,
                    extra           = {
                        "details" : f"Suspicious login by "
                                    f"'{log.get('user_name') or 'Windows Service'}' - "
                                    f"{' and '.join(reason)}."
                        }
                    ))

    return threats
                
def detect_external_ip(logs):
    threats = []

    for log in logs:
        if log.get("event_id") == "4624":
            desc = log.get("description", "") or ""
            ip_match       = re.search(r'Source Network Address:\s+([\d.]+)', desc)

            if not ip_match:
                continue

            ip          = ip_match.group(1)
            internal    = is_internal_ip(ip)

            if internal is False:
                threats.append(make_threat(
                    threat_type = "External IP Login",
                    severity    = "MEDIUM",
                    log         = log,
                    extra       = {
                        "is_internal" : False,
                        "details"     : f"Successful login from "
                                        f"external IP '{ip}' "
                                        f"on {log.get('computer')}."
                        }
                    ))

    return threats

def run_all_detections(logs):
    threats = []

    # running all individual detections
    threats.extend(detect_bruteforce(logs))
    threats.extend(detect_account_lockout(logs))
    threats.extend(detect_new_user(logs))
    threats.extend(detect_privileges_escalation(logs))
    threats.extend(detect_service_installation(logs))
    threats.extend(detect_log_clearing(logs))
    threats.extend(detect_unusual_login(logs))
    threats.extend(detect_external_ip(logs))

    # Correlation Engine

    correlated = []

    for i, threat in enumerate(threats):
        account = threat.get("account")
        date    = parse_date(threat.get("date"))

        if not account or not date:
            correlated.append(threat)
            continue

        # find related threats for same account
        related = [
            t for j, t in enumerate(threats)
            if j != i
            and t.get("account") == account
            ]
        related_types = [t.get("threat_type") for t in related]

        # Correlation Rule 1
        # New user + unusual time + external IP = Critical

        if (
            threat.get("threat_type") == "New User Account Created"
            and "Unusual Login Time" in related_types
            and "External IP Login"  in related_types
            ):

            threat["severity"] = "CRITICAL"
            threat["details"]  = (
                f"CRITICAL: New user '{account}' created "
                f"during unusual hours from external IP. "
                f"Possible backdoor account!"
                )

        # Correlation Rule 2
        # Brute force + successful login = Critical

        elif (
            threat.get("threat_type") == "Brute Force Attack"
            and "Successful Logon" in related_types
            ):
            threat["severity"] = "CRITICAL"
            threat["details"] = (
               f"CRITICAL: Brute force attack on '{account}' "
                f"followed by successful login. "
                f"Account may be compromised!"
               )
        
        # Correlation Rule 3
        # Privilege escalation + unusual time = Critical
 
        elif (
            threat.get("threat_type") == "Privilege Escalation"
            and "Unusual Login Time" in related_types
            ):
            threat["severity"] = "CRITICAL"
            threat["details"]  = (
                f"CRITICAL: Privilege escalation for '{account}' "
                f"during unusual hours. "
                f"Possible insider threat!"
                )
            
        correlated.append(threat)

    # Sorting by severity
    severity_order = {
            "CRITICAL" : 0,
            "HIGH"     : 1,
            "MEDIUM"   : 2,
            "LOW"      : 3
            }

    correlated.sort(
            key=lambda x: severity_order.get(x.get("severity"),4)
            )
        
   

    # Remove Duplicates
    seen    = set()
    uniqued = []
    for threat in correlated:
        key = (
            threat.get("threat_type"),
            threat.get("account"),
            threat.get("computer")
            
            )
        if key not in seen:
            seen.add(key)
            uniqued.append(threat)
    return uniqued
