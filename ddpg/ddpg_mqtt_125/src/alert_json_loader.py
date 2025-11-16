#!/usr/bin/env python3
"""
alert_json_loader.py
---------------------------------------
Loads and analyzes alert.json to create Model instances for training/evaluation.
"""

import json
import os
import numpy as np
from collections import defaultdict, Counter
from model import PoissonDistribution, AlertType, AttackType, Model
from simulate_model import alert_types, get_alert_type_index


def load_alert_json(alert_file_path):
    """
    Load all alerts from alert.json file.
    Returns a list of parsed alert dictionaries.
    """
    alerts = []
    
    if not os.path.exists(alert_file_path):
        raise FileNotFoundError(f"Alert file not found: {alert_file_path}")
    
    print(f"[INFO] Loading alerts from: {alert_file_path}")
    
    with open(alert_file_path, 'r', encoding='utf-8', errors='replace') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                alert_data = json.loads(line)
                alerts.append(alert_data)
            except json.JSONDecodeError as e:
                print(f"[WARN] Skipping invalid JSON at line {line_num}: {e}")
                continue
    
    print(f"[INFO] Loaded {len(alerts)} alerts from JSON file")
    return alerts


def analyze_alerts(alerts):
    """
    Analyze alerts to extract statistics for model creation.
    Returns:
        - alert_type_counts: dict mapping alert type index -> count
        - attack_type_mapping: dict mapping attack signatures -> attack type index
        - alert_attack_correlation: dict mapping (alert_type_idx, attack_signature) -> count
    """
    alert_type_counts = Counter()
    attack_signatures = Counter()
    alert_attack_correlation = defaultdict(int)
    
    # Map attack signatures from scapy_traffic.py
    attack_signature_map = {
        "ATTACK_SYN_FLOOD_2025": "SYN_FLOOD",
        "ATTACK_PORT_SCAN_2025": "PORT_SCAN",
        "ATTACK_SQL_INJECTION_2025": "SQL_INJECTION"
    }
    
    for alert_data in alerts:
        alert_info = alert_data.get("alert", {})
        msg = alert_info.get("msg", "") or alert_info.get("signature", "")
        raw_payload = alert_data.get("payload", "")
        
        # Get alert type index
        alert_type_idx = get_alert_type_index(msg)
        if alert_type_idx >= 0:
            alert_type_counts[alert_type_idx] += 1
        
        # Detect attack signatures from payload
        attack_type = None
        if raw_payload:
            payload_str = raw_payload if isinstance(raw_payload, str) else str(raw_payload)
            payload_bytes = payload_str.encode() if isinstance(payload_str, str) else payload_str
            for sig_key, attack_name in attack_signature_map.items():
                sig_bytes = sig_key.encode() if isinstance(sig_key, str) else sig_key
                if sig_bytes in payload_bytes:
                    attack_type = attack_name
                    break
        
        # Also check message for attack keywords
        if attack_type is None:
            msg_lower = msg.lower()
            if "syn flood" in msg_lower or "syn_flood" in msg_lower:
                attack_type = "SYN_FLOOD"
            elif "port scan" in msg_lower or "port_scan" in msg_lower:
                attack_type = "PORT_SCAN"
            elif "sql injection" in msg_lower or "sql_injection" in msg_lower:
                attack_type = "SQL_INJECTION"
        
        if attack_type:
            attack_signatures[attack_type] += 1
            if alert_type_idx >= 0:
                alert_attack_correlation[(alert_type_idx, attack_type)] += 1
    
    return alert_type_counts, attack_signatures, alert_attack_correlation


def create_model_from_alerts(alert_file_path, def_budget, adv_budget, 
                              min_alert_count=10, default_attack_cost=50.0, 
                              default_attack_loss=2.0):
    """
    Create a Model instance from alert.json file.
    
    Args:
        alert_file_path: Path to alert.json file
        def_budget: Defender budget
        adv_budget: Adversary budget
        min_alert_count: Minimum alerts needed to create an alert type
        default_attack_cost: Default cost for attack types if not inferrable
        default_attack_loss: Default loss for attack types if not inferrable
    
    Returns:
        Model object
    """
    # Load and analyze alerts
    alerts = load_alert_json(alert_file_path)
    if len(alerts) == 0:
        raise ValueError("No alerts found in alert.json file")
    
    alert_type_counts, attack_signatures, alert_attack_correlation = analyze_alerts(alerts)
    
    # Create alert types
    # Use Poisson distribution with mean = average count per time unit
    # For simplicity, we'll use the total count as an estimate
    total_alerts = len(alerts)
    num_alert_types = len(alert_type_counts)
    
    alert_type_objects = []
    alert_type_names = []
    
    # Create alert types based on observed alert types
    for idx in sorted(alert_type_counts.keys()):
        count = alert_type_counts[idx]
        if count >= min_alert_count:
            # Estimate Poisson mean: scale by a factor to get per-time-step rate
            # Assuming alerts are collected over multiple time steps
            # For now, use the count directly (can be adjusted)
            poisson_mean = max(count / max(1, total_alerts / 100), 1.0)
            alert_name = alert_types[idx] if idx < len(alert_types) else f"t{idx+1}"
            alert_type_objects.append(
                AlertType(1.0, PoissonDistribution(poisson_mean), alert_name)
            )
            alert_type_names.append(alert_name)
    
    # If no alert types found, create default ones
    if len(alert_type_objects) == 0:
        print("[WARN] No valid alert types found, creating default alert types")
        for i, alert_name in enumerate(alert_types[:min(4, len(alert_types))]):
            alert_type_objects.append(
                AlertType(1.0, PoissonDistribution(100), alert_name)
            )
            alert_type_names.append(alert_name)
    
    # Create attack types
    attack_type_objects = []
    unique_attacks = sorted(set(attack_signatures.keys()))
    
    if len(unique_attacks) == 0:
        # Create default attack types if none detected
        print("[WARN] No attack types detected, creating default attack types")
        unique_attacks = ["SYN_FLOOD", "PORT_SCAN"]
    
    for attack_idx, attack_name in enumerate(unique_attacks):
        # Estimate attack cost (can be based on frequency or use default)
        attack_cost = default_attack_cost * (1.0 + attack_idx * 0.2)
        
        # Estimate loss (can be based on severity or use default)
        attack_loss = default_attack_loss * (1.0 + attack_idx * 0.3)
        
        # Create pr_alert vector: probability of triggering each alert type
        pr_alert = []
        total_attacks = attack_signatures[attack_name]
        
        for alert_idx in range(len(alert_type_objects)):
            # Count how many times this attack triggered this alert type
            correlation_count = alert_attack_correlation.get(
                (alert_idx, attack_name), 0
            )
            # Probability = correlation_count / total_attacks (if > 0)
            if total_attacks > 0:
                prob = min(correlation_count / total_attacks, 1.0)
            else:
                # Default: higher probability for first alert type
                prob = 0.8 if alert_idx == 0 else 0.1
            pr_alert.append(prob)
        
        # If pr_alert is empty or all zeros, set default values
        if len(pr_alert) == 0 or sum(pr_alert) == 0:
            pr_alert = [0.8 if i == 0 else 0.1 for i in range(len(alert_type_objects))]
        
        attack_type_objects.append(
            AttackType([attack_loss], attack_cost, pr_alert, attack_name)
        )
    
    # Create model
    model = Model(1, alert_type_objects, attack_type_objects, def_budget, adv_budget)
    
    print(f"[INFO] Created model with {len(alert_type_objects)} alert types and {len(attack_type_objects)} attack types")
    print(f"[INFO] Alert types: {[at.name for at in alert_type_objects]}")
    print(f"[INFO] Attack types: {[at.name for at in attack_type_objects]}")
    
    return model


def test_model_from_alerts(alert_file_path, def_budget, adv_budget):
    """
    Wrapper function compatible with test_model_snort/test_model_fraud interface.
    Creates a model from alert.json file.
    """
    return create_model_from_alerts(alert_file_path, def_budget, adv_budget)

