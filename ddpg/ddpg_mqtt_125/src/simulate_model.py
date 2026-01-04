#!/usr/bin/env python3
"""
simulate_model.py
---------------------------------------
Provides alert-type definitions and mapping utilities
for both static and live DDPG alert prioritization.

Used by:
  - evaluate_ddpg_live.py (real-time Snort alerts)
  - alert_json_loader.py (model creation from Snort alerts)
"""

import os
import json
import time

# ==============================================================
# Define alert/attack types matching local.rules and scapy_traffic.py
# ==============================================================

# Attack types matching Snort local.rules (10 attack types)
attack_types = [
    "SYN_FLOOD",
    "SQL_INJECTION", 
    "HTTP_C2",
    "PORT_SCAN",
    "BRUTE_FORCE",
    "DDOS",
    "XSS",
    "COMMAND_INJECTION",
    "MALWARE_DOWNLOAD",
    "DNS_TUNNELING",
]

# Legacy alert_types for backward compatibility
alert_types = attack_types

# Map Snort message patterns to attack type indices
# Matches messages like "HTTP_C2 tag detected", "SYN_FLOOD tag detected", etc.
MSG_TO_ATTACK_INDEX = {
    "syn_flood tag": 0,
    "syn_flood": 0,
    "sql_injection tag": 1,
    "sql_injection": 1,
    "http_c2 tag": 2,
    "http_c2": 2,
    "port_scan tag": 3,
    "port_scan": 3,
    "brute_force tag": 4,
    "brute_force": 4,
    "ddos tag": 5,
    "ddos": 5,
    "xss tag": 6,
    "xss": 6,
    "cross-site scripting": 6,
    "command_injection tag": 7,
    "command_injection": 7,
    "malware_download tag": 8,
    "malware_download": 8,
    "dns_tunneling tag": 9,
    "dns_tunneling": 9,
}

# ==============================================================
# Map alert messages to alert-type indices
# ==============================================================

def get_alert_type_index(msg: str) -> int:
    """
    Given a Snort alert message string, return its corresponding
    attack type index based on the attack_types list.
    """
    if not msg:
        return -1
    msg_lower = msg.lower()
    for pattern, idx in MSG_TO_ATTACK_INDEX.items():
        if pattern in msg_lower:
            return idx
    return -1  # unknown / not matched


def get_attack_type_name(msg: str) -> str:
    """
    Given a Snort alert message string, return the attack type name.
    """
    idx = get_alert_type_index(msg)
    if idx >= 0 and idx < len(attack_types):
        return attack_types[idx]
    return None


# ==============================================================
# read live Snort alerts (for testing or standalone)
# ==============================================================

def read_snort_alerts(json_alert_file):
    """
    Tail Snort's alert_json.txt and yield structured alert events.
    This helper is used internally by evaluate_ddpg_live.py
    if you want to test alert parsing independently.
    
    Extracts priority and classification from Snort alert format:
    { "timestamp": "...", "msg": "...", "class": "...", "priority": 1 }
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
                # Support both old format (nested alert) and new format (flat)
                if "alert" in data:
                    msg = data.get("alert", {}).get("msg", "")
                    src = data.get("src_ip")
                    dst = data.get("dest_ip")
                    proto = data.get("proto")
                    classification = data.get("alert", {}).get("class", "")
                    priority = data.get("alert", {}).get("priority", 3)
                else:
                    # New Snort format: flat structure
                    msg = data.get("msg", "")
                    src = data.get("src_ap", "").split(":")[0] if ":" in data.get("src_ap", "") else data.get("src_ap", "")
                    dst = data.get("dst_ap", "").split(":")[0] if ":" in data.get("dst_ap", "") else data.get("dst_ap", "")
                    proto = data.get("proto", "")
                    classification = data.get("class", "")
                    priority = data.get("priority", 3)
                
                idx = get_alert_type_index(msg)
                yield {
                    "alert_type_idx": idx,
                    "msg": msg,
                    "src": src,
                    "dst": dst,
                    "proto": proto,
                    "classification": classification,
                    "priority": priority,
                    "timestamp": data.get("timestamp", "")
                }
            except json.JSONDecodeError:
                continue

if __name__ == "__main__":
    # Example self-test (reads first 5 alerts if file exists)
    alert_file = os.path.expandvars(
        "$VIRTUAL_ENV/snort3/var/log/snort/alert_json.txt"
    )
    for i, alert in enumerate(read_snort_alerts(alert_file)):
        print(alert)
        if i >= 5:
            break

