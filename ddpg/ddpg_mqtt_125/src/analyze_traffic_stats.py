#!/usr/bin/env python3
"""
Analyze 2-day traffic collection stats and generate test.py calibration report.
Usage:
  python3 analyze_traffic_stats.py
"""

import re
import os
import sys
from datetime import datetime

# Get paths from environment
VENV = os.environ.get('VIRTUAL_ENV', os.path.expandvars('$HOME/ddpg_workspace/AlertPrioritization/venv37'))
LOG_DIR = os.path.join(VENV, 'snort3/var/log/snort')
TRAFFIC_LOG = os.path.join(LOG_DIR, 'traffic_gen.log')
ALERT_JSON = os.path.join(LOG_DIR, 'alert_json.txt')

print("[+] Real-Time DDPG: Traffic Statistics Analysis")
print(f"    Log Directory: {LOG_DIR}")
print(f"    Timestamp: {datetime.now().isoformat()}\n")

# ============================================================
# Parse Traffic Log (scapy_traffic.py window stats)
# ============================================================
if not os.path.exists(TRAFFIC_LOG):
    print(f"[ERROR] Traffic log not found: {TRAFFIC_LOG}")
    sys.exit(1)

with open(TRAFFIC_LOG, 'r') as f:
    content = f.read()

# Find all windows
windows = content.split('[WINDOW COMPLETE]')
print(f"[+] Total windows collected: {len(windows) - 1}")

if len(windows) < 2:
    print("[ERROR] No complete windows found. Collection may still be running.")
    sys.exit(1)

benign_per_window = []
attack_totals = {}
attack_per_window = []
window_data = []

for i, window in enumerate(windows[1:]):
    if 'Benign events:' in window:
        # Parse benign count
        benign_match = re.search(r'Benign events: (\d+)', window)
        if not benign_match:
            continue
        benign = int(benign_match.group(1))
        benign_per_window.append(benign)
        
        # Parse attack counts
        window_attacks = {}
        total_attacks = 0
        for line in window.split('\n'):
            attack_match = re.search(r'(attack_\w+): (\d+)', line)
            if attack_match:
                atk_name, count = attack_match.groups()
                count = int(count)
                window_attacks[atk_name] = count
                attack_totals[atk_name] = attack_totals.get(atk_name, 0) + count
                total_attacks += count
        
        attack_per_window.append(total_attacks)
        window_data.append({
            'window': i + 1,
            'benign': benign,
            'attacks': total_attacks,
            'distribution': window_attacks
        })

if not benign_per_window:
    print("[ERROR] No window data parsed. Check traffic_gen.log format.")
    sys.exit(1)

# ============================================================
# Statistics: Benign Traffic
# ============================================================
print("\n" + "="*70)
print("BENIGN TRAFFIC ANALYSIS (Realistic Background Noise)")
print("="*70)
print(f"Windows analyzed:      {len(benign_per_window)}")
print(f"Min per window:        {min(benign_per_window)}")
print(f"Max per window:        {max(benign_per_window)}")
print(f"Avg per window:        {sum(benign_per_window) / len(benign_per_window):.1f}")
print(f"Total benign alerts:   {sum(benign_per_window)}")
print(f"Expected (12/min):     {12 * 30 * len(benign_per_window)} (theoretical)")

# ============================================================
# Statistics: Attack Distribution
# ============================================================
print("\n" + "="*70)
print("ATTACK DISTRIBUTION (2-Day Aggregated)")
print("="*70)
print(f"{'Attack Type':<30} {'Count':>10} {'Avg/Day':>10} {'%':>8} {'Poisson Mean':>15}")
print("-"*70)

total_attacks = sum(attack_totals.values())
for atk in sorted(attack_totals.keys()):
    count = attack_totals[atk]
    avg_per_day = count / 2  # 2-day collection
    pct = 100.0 * count / total_attacks if total_attacks > 0 else 0
    poisson_mean = int(avg_per_day) if avg_per_day >= 1 else 1
    print(f"{atk:<30} {count:>10} {avg_per_day:>10.1f} {pct:>7.1f}% {poisson_mean:>15}")

print("-"*70)
print(f"{'TOTAL':<30} {total_attacks:>10}")

# ============================================================
# Ratio Analysis
# ============================================================
print("\n" + "="*70)
print("TRAFFIC RATIO ANALYSIS")
print("="*70)
benign_total = sum(benign_per_window)
ratio = benign_total / total_attacks if total_attacks > 0 else 0
print(f"Total benign:          {benign_total}")
print(f"Total attacks:         {total_attacks}")
print(f"Benign:Attack ratio:   {ratio:.1f}:1 (expected ~24:1)")
print(f"Attack percentage:     {100*total_attacks/(benign_total+total_attacks):.2f}%")

# ============================================================
# Verification: Alert JSON
# ============================================================
print("\n" + "="*70)
print("ALERT_JSON.TXT VERIFICATION (Snort-Generated)")
print("="*70)

if os.path.exists(ALERT_JSON):
    with open(ALERT_JSON, 'r') as f:
        alert_lines = f.readlines()
    print(f"Total lines in alert_json.txt: {len(alert_lines)}")
    
    # Count attack types in alert JSON
    alert_types_found = {}
    benign_found = 0
    for line in alert_lines:
        if 'ATTACK_' in line:
            match = re.search(r'ATTACK_([A-Z_]*_2025)', line)
            if match:
                atk_type = 'ATTACK_' + match.group(1)
                alert_types_found[atk_type] = alert_types_found.get(atk_type, 0) + 1
        elif 'BENIGN' in line:
            benign_found += 1
    
    print(f"\nAttack types in alert_json.txt:")
    for atk in sorted(alert_types_found.keys()):
        print(f"  {atk}: {alert_types_found[atk]}")
    
    print(f"\nBenign (from alert_json.txt): {benign_found}")
    print(f"Expected attack types (10): {len(alert_types_found)}")
    
    if len(alert_types_found) == 10:
        print("✓ All 10 attack types present in alert_json.txt")
    else:
        print(f"✗ WARNING: Only {len(alert_types_found)}/10 attack types found")
else:
    print(f"[WARNING] alert_json.txt not found: {ALERT_JSON}")

# ============================================================
# Generate test.py Calibration Template
# ============================================================
print("\n" + "="*70)
print("CALIBRATION TEMPLATE FOR test.py")
print("="*70)
print("\nUpdate test_model_realtime() with observed Poisson means:\n")

print("def test_model_realtime(def_budget, adv_budget):")
print("  alert_types = [")

# Map attack names to indices
attack_mapping = {
    'attack_syn_flood': ('t1_SYN_FLOOD', 0),
    'attack_sql_injection': ('t2_SQL_INJECTION', 1),
    'attack_http_c2': ('t3_HTTP_C2', 2),
    'attack_port_scan': ('t4_PORT_SCAN', 3),
    'attack_brute_force': ('t5_BRUTE_FORCE', 4),
    'attack_ddos': ('t6_DDOS', 5),
    'attack_xss': ('t7_XSS', 6),
    'attack_command_injection': ('t8_COMMAND_INJECTION', 7),
    'attack_malware_download': ('t9_MALWARE_DOWNLOAD', 8),
    'attack_dns_tunneling': ('t10_DNS_TUNNELING', 9),
}

for atk_func_name, (alert_name, idx) in sorted(attack_mapping.items(), key=lambda x: x[1][1]):
    count = attack_totals.get(atk_func_name, 0)
    poisson_mean = max(1, int(count / 2))  # 2-day average
    print(f"      AlertType(1.0, PoissonDistribution({poisson_mean:3}), \"{alert_name}\"),")

print("  ]")
print("\n  attack_types = [")

# Attack costs and losses (from original test_model_realtime)
attack_params = {
    'attack_syn_flood': ('[3.6]', '80.0', 0),
    'attack_sql_injection': ('[4.0]', '60.0', 1),
    'attack_http_c2': ('[5.5]', '74.0', 2),
    'attack_port_scan': ('[1.4]', '20.0', 3),
    'attack_brute_force': ('[2.7]', '52.0', 4),
    'attack_ddos': ('[4.3]', '135.0', 5),
    'attack_xss': ('[3.0]', '40.0', 6),
    'attack_command_injection': ('[4.5]', '65.0', 7),
    'attack_malware_download': ('[5.0]', '90.0', 8),
    'attack_dns_tunneling': ('[2.5]', '45.0', 9),
}

for atk_func_name, (cost, loss, idx) in sorted(attack_params.items(), key=lambda x: x[1][2]):
    alert_name_short = atk_func_name.replace('attack_', '').upper()
    pr_alert = [0.0] * 10
    pr_alert[idx] = 0.9  # Default: 90% triggers own alert
    print(f"      AttackType({cost}, {loss}, {pr_alert}, \"{alert_name_short}\"),")

print("  ]")
print("\n  model = Model(1, alert_types, attack_types, def_budget, adv_budget)")
print("  return model")

# ============================================================
# Final Summary
# ============================================================
print("\n" + "="*70)
print("VALIDATION SUMMARY")
print("="*70)

checklist = {
    "✓ Alert file exists": os.path.exists(ALERT_JSON),
    "✓ All 10 attack types present": len(alert_types_found) == 10 if 'alert_types_found' in locals() else False,
    "✓ Reasonable window count": len(benign_per_window) >= 40,
    "✓ Benign:Attack ratio ~24:1": 20 <= ratio <= 30,
    "✓ test.py template generated": True,
}

for check, result in checklist.items():
    status = "PASS" if result else "FAIL"
    print(f"  {check}: {status}")

print("\n[+] Next steps:")
print("    1. Copy alert_types[] and attack_types[] from template above into test.py")
print("    2. Update test_defense_snort() priority array for 10 alerts")
print("    3. Run: python3 double_oracle.py realtime 1000 120 1")
print("    4. Evaluate: python3 evaluate_ddpg.py realtime uniform 1000 120 greedy 120 1")

print("\n[+] Analysis complete!")
