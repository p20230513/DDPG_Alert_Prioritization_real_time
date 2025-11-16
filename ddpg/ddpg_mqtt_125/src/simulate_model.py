#!/usr/bin/env python3
"""
simulate_model.py
---------------------------------------
Provides alert-type definitions and mapping utilities
for both static and live DDPG alert prioritization.

Used by:
  - evaluate_ddpg_live.py (real-time Snort alerts)
"""

import os
import json
import time

# ==============================================================
# 1. Define alert types (extend this as your rule set grows)
# ==============================================================

# These are example categories derived from Snort signatures.
# Add or modify according to your Snort local.rules messages.
alert_types = [
    "TCP Traffic Detected",
    "UDP Traffic Detected",
    "ICMP ping Nmap",
    "loopback IP",
    "same src/dst IP",
    "SQL Injection",
    "Port Scan",
    "SYN Flood"
]

# ==============================================================
# 2. Map alert messages to alert-type indices
# ==============================================================

def get_alert_type_index(msg: str) -> int:
    """
    Given a Snort alert message string, return its corresponding
    alert type index based on the alert_types list.
    """
    if not msg:
        return -1
    msg_lower = msg.lower()
    for i, t in enumerate(alert_types):
        if t.lower() in msg_lower:
            return i
    return -1  # unknown / not matched


# ==============================================================
# 3. Optional: read live Snort alerts (for testing or standalone)
# ==============================================================

def read_snort_alerts(json_alert_file):
    """
    Tail Snort's alert_json.txt and yield structured alert events.
    This helper is used internally by evaluate_ddpg_live.py
    if you want to test alert parsing independently.
    """
    if not os.path.exists(json_alert_file):
        print(f"[ERROR] Snort alert file not found: {json_alert_file}")
        return

    print(f"[INFO] Tailing Snort JSON alerts from {json_alert_file}")
    with open(json_alert_file, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            try:
                data = json.loads(line)
                msg = data.get("alert", {}).get("msg", "")
                idx = get_alert_type_index(msg)
                yield {
                    "alert_type_idx": idx,
                    "msg": msg,
                    "src": data.get("src_ip"),
                    "dst": data.get("dest_ip"),
                    "proto": data.get("proto")
                }
            except json.JSONDecodeError:
                continue


# ==============================================================
# 4. Example test (optional)
# ==============================================================

if __name__ == "__main__":
    # Example self-test (reads first 5 alerts if file exists)
    alert_file = os.path.expandvars(
        "$VIRTUAL_ENV/snort3/var/log/snort/alert_json.txt"
    )
    for i, alert in enumerate(read_snort_alerts(alert_file)):
        print(alert)
        if i >= 5:
            break

