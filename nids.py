import re
from collections import Counter
import datetime

# Simulated network traffic log - real Snort/Suricata would sniff live
LOG_FILE = "traffic.log"
ALERT_FILE = "alerts.log"

RULES = {
    "SQL Injection Attempt": r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
    "XSS Attempt": r"(<script|%3Cscript)",
    "Port Scan": r"PORT_SCAN",
    "Brute Force": r"Failed login.*count>5",
    "ICMP Flood": r"ICMP.*flood"
}

def monitor():
    alerts = []
    with open(LOG_FILE) as f:
        for line in f:
            for name, pattern in RULES.items():
                if re.search(pattern, line, re.IGNORECASE):
                    timestamp = datetime.datetime.now()
                    msg = f"[{timestamp}] ALERT: {name} - {line.strip()}"
                    print(msg)
                    alerts.append(msg)
    
    with open(ALERT_FILE, "w") as out:
        out.write("\n".join(alerts))
    
    # Summary
    print(f"\nTotal alerts: {len(alerts)}")
    return alerts

if __name__ == "__main__":
    monitor()
