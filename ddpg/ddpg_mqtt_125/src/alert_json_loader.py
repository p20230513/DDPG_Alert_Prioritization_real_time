#!/usr/bin/env python3
"""
alert_json_loader.py
---------------------------------------
Loads and analyzes Snort alert_json.txt to create Model instances for real-time
DDPG alert prioritization training/evaluation.

Supports the new Snort alert format with classification and priority fields:
{ "timestamp": "...", "proto": "TCP", "src_ap": "...", "dst_ap": "...",
  "rule": "...", "action": "allow", "msg": "...", "sid": ...,
  "class": "...", "priority": 1 }
"""

import json
import os
import numpy as np
from collections import defaultdict, Counter
from model import PoissonDistribution, AlertType, AttackType, Model

# ==============================================================
# Attack type definitions matching scapy_traffic.py and local.rules
# ==============================================================
ATTACK_TYPES = [
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

# Map Snort message patterns to attack types
# Matches messages like "HTTP_C2 tag detected", "SYN_FLOOD tag detected", etc.
MSG_TO_ATTACK_MAP = {
    "syn_flood tag": "SYN_FLOOD",
    "syn_flood": "SYN_FLOOD",
    "sql_injection tag": "SQL_INJECTION",
    "sql_injection": "SQL_INJECTION",
    "http_c2 tag": "HTTP_C2",
    "http_c2": "HTTP_C2",
    "port_scan tag": "PORT_SCAN",
    "port_scan": "PORT_SCAN",
    "brute_force tag": "BRUTE_FORCE",
    "brute_force": "BRUTE_FORCE",
    "ddos tag": "DDOS",
    "ddos": "DDOS",
    "xss tag": "XSS",
    "xss": "XSS",
    "cross-site scripting": "XSS",
    "command_injection tag": "COMMAND_INJECTION",
    "command_injection": "COMMAND_INJECTION",
    "malware_download tag": "MALWARE_DOWNLOAD",
    "malware_download": "MALWARE_DOWNLOAD",
    "dns_tunneling tag": "DNS_TUNNELING",
    "dns_tunneling": "DNS_TUNNELING",
}

# Classification to severity mapping (higher = more severe)
# Handles both Snort formats: "Attempted Denial of Service" and "attempted-dos"
CLASS_SEVERITY = {
    # Standard lowercase-hyphen format
    "attempted-dos": 3,
    "attempted denial of service": 3,  # Snort format with spaces
    "web-application-attack": 3,
    "web application attack": 3,
    "trojan-activity": 4,
    "trojan activity": 4,
    "attempted-recon": 2,
    "attempted reconnaissance": 2,
    "suspicious-login": 3,
    "suspicious login": 3,
    "protocol-command-decode": 2,
    "protocol command decode": 2,
    "attempted-admin": 4,
    "attempted administrator": 4,
    "misc-attack": 2,
    "misc attack": 2,
    "default": 1,
}

# Attack cost and loss based on classification severity and priority
ATTACK_PARAMS = {
    "SYN_FLOOD": {"base_cost": 80.0, "base_loss": 3.6},
    "SQL_INJECTION": {"base_cost": 60.0, "base_loss": 4.0},
    "HTTP_C2": {"base_cost": 74.0, "base_loss": 5.5},
    "PORT_SCAN": {"base_cost": 20.0, "base_loss": 1.4},
    "BRUTE_FORCE": {"base_cost": 52.0, "base_loss": 2.7},
    "DDOS": {"base_cost": 135.0, "base_loss": 4.3},
    "XSS": {"base_cost": 40.0, "base_loss": 3.0},
    "COMMAND_INJECTION": {"base_cost": 65.0, "base_loss": 4.5},
    "MALWARE_DOWNLOAD": {"base_cost": 90.0, "base_loss": 5.0},
    "DNS_TUNNELING": {"base_cost": 45.0, "base_loss": 2.5},
}


def get_attack_type_from_msg(msg: str) -> str:
    """
    Extract attack type from Snort alert message.
    Returns attack type name or None if not matched.
    """
    if not msg:
        return None
    msg_lower = msg.lower()
    for pattern, attack_type in MSG_TO_ATTACK_MAP.items():
        if pattern in msg_lower:
            return attack_type
    return None


def get_attack_type_index(attack_name: str) -> int:
    """Get index of attack type in ATTACK_TYPES list."""
    try:
        return ATTACK_TYPES.index(attack_name)
    except ValueError:
        return -1


def load_alert_json(alert_file_path, max_alerts=None, from_line=0):
    """
    Load alerts from alert_json.txt file (Snort JSON format).
    
    Args:
        alert_file_path: Path to alert_json.txt file
        max_alerts: Maximum number of alerts to load (None = all)
        from_line: Start reading from this line number (0 = from beginning)
    
    Returns:
        List of parsed alert dictionaries with extracted fields.
    
    Note:
        - Reads file once at call time (static snapshot)
        - For continuously updated files, call this function periodically
        - Use from_line parameter to read only new alerts (future enhancement)
    """
    alerts = []
    
    if not os.path.exists(alert_file_path):
        raise FileNotFoundError(f"Alert file not found: {alert_file_path}")
    
    print(f"[INFO] Loading alerts from: {alert_file_path}")
    if from_line > 0:
        print(f"[INFO] Starting from line: {from_line}")
    if max_alerts:
        print(f"[INFO] Maximum alerts to load: {max_alerts}")
    
    with open(alert_file_path, 'r', encoding='utf-8', errors='replace') as f:
        # Skip to starting line if specified
        for _ in range(from_line):
            try:
                next(f)
            except StopIteration:
                break
        
        # Python 3.7 compatible: enumerate doesn't support start parameter
        # So we manually track line numbers
        line_num = from_line
        for line in f:
            line_num += 1
            if max_alerts and len(alerts) >= max_alerts:
                print(f"[INFO] Reached maximum alert limit: {max_alerts}")
                break
                
            line = line.strip()
            if not line:
                continue
            try:
                alert_data = json.loads(line)
                
                # Extract fields from new Snort format
                parsed = {
                    "timestamp": alert_data.get("timestamp", ""),
                    "proto": alert_data.get("proto", ""),
                    "src_ap": alert_data.get("src_ap", ""),
                    "dst_ap": alert_data.get("dst_ap", ""),
                    "rule": alert_data.get("rule", ""),
                    "action": alert_data.get("action", ""),
                    "msg": alert_data.get("msg", ""),
                    "sid": alert_data.get("sid", 0),
                    "classification": alert_data.get("class", ""),
                    "priority": alert_data.get("priority", 3),
                }
                
                # Derive attack type from message
                parsed["attack_type"] = get_attack_type_from_msg(parsed["msg"])
                
                alerts.append(parsed)
            except json.JSONDecodeError as e:
                print(f"[WARN] Skipping invalid JSON at line {line_num}: {e}")
                continue
    
    print(f"[INFO] Loaded {len(alerts)} alerts from JSON file")
    return alerts


def load_alert_json_streaming(alert_file_path, last_position=0):
    """
    FUTURE ENHANCEMENT: Stream alerts from continuously updated file.
    
    This function is designed for true real-time processing where alert_json.txt
    is continuously updated. It tracks file position and only reads new alerts.
    
    Args:
        alert_file_path: Path to alert_json.txt file
        last_position: Last byte position read (0 = from beginning)
    
    Returns:
        Tuple of (alerts_list, new_position)
        - alerts_list: New alerts since last_position
        - new_position: Current file position for next call
    
    Usage (future):
        last_pos = 0
        while True:
            alerts, last_pos = load_alert_json_streaming(alert_file_path, last_pos)
            if alerts:
                # Process new alerts
                update_model_with_alerts(alerts)
            time.sleep(1)  # Check every second
    """
    alerts = []
    
    if not os.path.exists(alert_file_path):
        return alerts, last_position
    
    try:
        with open(alert_file_path, 'r', encoding='utf-8', errors='replace') as f:
            # Seek to last position
            f.seek(last_position)
            
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    alert_data = json.loads(line)
                    parsed = {
                        "timestamp": alert_data.get("timestamp", ""),
                        "proto": alert_data.get("proto", ""),
                        "src_ap": alert_data.get("src_ap", ""),
                        "dst_ap": alert_data.get("dst_ap", ""),
                        "rule": alert_data.get("rule", ""),
                        "action": alert_data.get("action", ""),
                        "msg": alert_data.get("msg", ""),
                        "sid": alert_data.get("sid", 0),
                        "classification": alert_data.get("class", ""),
                        "priority": alert_data.get("priority", 3),
                    }
                    parsed["attack_type"] = get_attack_type_from_msg(parsed["msg"])
                    alerts.append(parsed)
                except json.JSONDecodeError:
                    continue
            
            new_position = f.tell()
    except Exception as e:
        print(f"[ERROR] Error reading alert file: {e}")
        return alerts, last_position
    
    return alerts, new_position


def analyze_alerts(alerts):
    """
    Analyze alerts to extract statistics for model creation.
    Uses classification and priority from Snort alerts.
    
    Returns:
        - attack_type_counts: dict mapping attack type -> count
        - attack_type_priorities: dict mapping attack type -> list of priorities
        - attack_type_classes: dict mapping attack type -> list of classifications
    """
    attack_type_counts = Counter()
    attack_type_priorities = defaultdict(list)
    attack_type_classes = defaultdict(list)
    
    for alert in alerts:
        attack_type = alert.get("attack_type")
        if attack_type:
            attack_type_counts[attack_type] += 1
            attack_type_priorities[attack_type].append(alert.get("priority", 3))
            attack_type_classes[attack_type].append(alert.get("classification", ""))
    
    return attack_type_counts, attack_type_priorities, attack_type_classes


def create_model_from_alerts(alert_file_path, def_budget, adv_budget, 
                              min_alert_count=1, max_alerts=None, use_streaming=False):
    """
    Create a Model instance from Snort alert_json.txt file.
    Uses classification and priority from alerts to determine attack parameters.
    
    Args:
        alert_file_path: Path to alert_json.txt file
        def_budget: Defender budget
        adv_budget: Adversary budget
        min_alert_count: Minimum alerts needed to include an attack type
        max_alerts: Maximum alerts to read (None = all, for testing)
        use_streaming: If True, use streaming loader (future enhancement)
    
    Returns:
        Model object
    
    Note:
        - CURRENT: Reads file once at call time (static snapshot)
        - FUTURE: use_streaming=True will enable continuous updates
    """
    # Load and analyze alerts
    if use_streaming:
        # Future enhancement: streaming mode
        print("[WARN] Streaming mode not yet fully implemented, using static load")
        alerts = load_alert_json(alert_file_path, max_alerts=max_alerts)
    else:
        # Current implementation: static snapshot
        alerts = load_alert_json(alert_file_path, max_alerts=max_alerts)
    
    if len(alerts) == 0:
        raise ValueError("No alerts found in alert_json.txt file")
    
    attack_type_counts, attack_type_priorities, attack_type_classes = analyze_alerts(alerts)
    
    # Determine which attack types were observed
    observed_attacks = [at for at in ATTACK_TYPES if attack_type_counts.get(at, 0) >= min_alert_count]
    
    if len(observed_attacks) == 0:
        print("[WARN] No attack types detected, using all default attack types")
        observed_attacks = ATTACK_TYPES.copy()
    
    print(f"[INFO] Observed attack types: {observed_attacks}")
    print(f"[INFO] Attack counts: {dict(attack_type_counts)}")
    
    # Create alert types - one per observed attack type
    # Each attack type generates its own alert type
    alert_type_objects = []
    for i, attack_name in enumerate(observed_attacks):
        count = attack_type_counts.get(attack_name, 100)
        # Poisson mean based on observed count (scaled)
        poisson_mean = max(count, 10)
        alert_type_objects.append(
            AlertType(1.0, PoissonDistribution(poisson_mean), f"t{i+1}_{attack_name}")
        )
    
    # Create attack types with parameters based on priority and classification
    attack_type_objects = []
    for attack_idx, attack_name in enumerate(observed_attacks):
        # Get base parameters
        params = ATTACK_PARAMS.get(attack_name, {"base_cost": 50.0, "base_loss": 2.0})
        base_cost = params["base_cost"]
        base_loss = params["base_loss"]
        
        # Adjust based on average priority (lower priority number = higher severity)
        priorities = attack_type_priorities.get(attack_name, [2])
        avg_priority = np.mean(priorities) if priorities else 2
        # Priority 1 = highest severity, multiply loss; Priority 3 = lowest
        priority_factor = (4 - avg_priority) / 2.0  # Maps 1->1.5, 2->1.0, 3->0.5
        
        # Adjust based on classification severity
        classes = attack_type_classes.get(attack_name, ["default"])
        if classes:
            # Get most common classification
            class_counts = Counter(classes)
            most_common_class = class_counts.most_common(1)[0][0] if class_counts else "default"
            # Normalize classification: lowercase, replace spaces with hyphens for matching
            normalized_class = most_common_class.lower().strip()
            # Try exact match first, then try with spaces/hyphens normalized
            class_severity = CLASS_SEVERITY.get(normalized_class, 
                                                CLASS_SEVERITY.get(normalized_class.replace(" ", "-"),
                                                                   CLASS_SEVERITY.get(normalized_class.replace("-", " "),
                                                                                     CLASS_SEVERITY["default"])))
        else:
            class_severity = CLASS_SEVERITY["default"]
        
        # Final cost and loss
        attack_cost = base_cost * (class_severity / 3.0)
        attack_loss = base_loss * priority_factor * (class_severity / 2.0)
        
        # pr_alert: probability vector - this attack triggers its corresponding alert type
        pr_alert = [0.0] * len(alert_type_objects)
        pr_alert[attack_idx] = 0.9  # High probability of triggering its own alert
        
        attack_type_objects.append(
            AttackType([attack_loss], attack_cost, pr_alert, attack_name)
        )
        
        print(f"[INFO] Attack {attack_name}: cost={attack_cost:.2f}, loss={attack_loss:.2f}, "
              f"avg_priority={avg_priority:.1f}, class_severity={class_severity}")
    
    # Create model
    model = Model(1, alert_type_objects, attack_type_objects, def_budget, adv_budget)
    
    print(f"[INFO] Created model with {len(alert_type_objects)} alert types and {len(attack_type_objects)} attack types")
    
    return model


def test_model_from_alerts(alert_file_path, def_budget, adv_budget):
    """
    Wrapper function compatible with test_model_snort/test_model_fraud interface.
    Creates a model from alert_json.txt file.
    
    Note: This reads the file once at call time. For continuously updated files,
    you need to call this function again to get updated models.
    """
    return create_model_from_alerts(alert_file_path, def_budget, adv_budget)


def test_defense_realtime(model, state):
    """
    Compute investigation action for real-time alerts based on priority.
    Prioritizes alerts with higher severity (lower priority number).
    """
    delta = []
    for h in range(model.horizon):
        delta.append([0] * len(model.alert_types))
    
    remain_budget = model.def_budget
    used_budget = 0.0
    
    # Get attack priorities from ATTACK_PARAMS (lower = higher priority)
    attack_names = [at.name for at in model.attack_types]
    
    # Sort by base_loss (higher loss = investigate first)
    sorted_indices = sorted(
        range(len(attack_names)),
        key=lambda i: ATTACK_PARAMS.get(attack_names[i], {}).get("base_loss", 0),
        reverse=True
    )
    
    for idx in sorted_indices:
        if remain_budget > 0 and idx < len(model.alert_types):
            delta[0][idx] = min(
                int(remain_budget / model.alert_types[idx].cost),
                state.N[0][idx]
            )
            used_budget += delta[0][idx] * model.alert_types[idx].cost
            remain_budget = model.def_budget - used_budget
    
    return delta


def test_attack_realtime(model, state):
    """
    Compute attack action for real-time scenario.
    Distributes adversary budget among attacks based on cost-effectiveness.
    """
    alpha = []
    for a in model.attack_types:
        # Cost-effective attacks get higher probability
        effectiveness = ATTACK_PARAMS.get(a.name, {}).get("base_loss", 2.0) / a.cost
        alpha.append(min(effectiveness, 1.0))
    
    # Normalize to budget
    total_cost = sum(model.attack_types[i].cost * alpha[i] for i in range(len(alpha)))
    if total_cost > model.adv_budget:
        factor = model.adv_budget / total_cost
        alpha = [a * factor for a in alpha]
    
    return alpha
