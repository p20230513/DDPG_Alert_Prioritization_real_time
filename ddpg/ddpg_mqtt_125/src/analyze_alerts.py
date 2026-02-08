#!/usr/bin/env python3
"""
analyze_alerts.py - Analyze Snort alert_json.txt and extract model parameters
================================================================================

Parses Snort alerts from alert_json.txt and generates:
1. Per-alert-type statistics (counts, rates)
2. Poisson mean calculations (λ per alert type per window)
3. Window-based aggregation (30-min windows)
4. Model parameter extraction (for test.py calibration)

Usage:
    python3 analyze_alerts.py [--alert-file PATH] [--window-minutes 30] [--output json|csv|python]

Output:
    - JSON: alert_stats.json (complete statistics)
    - CSV: alert_stats.csv (per-alert-type summary)
    - Python: alert_stats_template.py (copy-paste into test.py)
"""

import json
import re
import sys
import argparse
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import os

# Alert type definitions
ATTACK_TYPES = [
    "SYN_FLOOD", "PORT_SCAN", "SQL_INJECTION", "HTTP_C2", "DNS_TUNNELING",
    "BRUTE_FORCE", "DDOS", "XSS", "COMMAND_INJECTION", "MALWARE_DOWNLOAD"
]

BENIGN_TYPES = [
    "BENIGN_HTTP", "BENIGN_DNS", "BENIGN_ICMP", "BENIGN_SSH", "BENIGN_TLS",
    "BENIGN_SMTP", "BENIGN_NTP", "BENIGN_FTP", "BENIGN_LDAP", "BENIGN_MYSQL"
]

ALL_TYPES = ATTACK_TYPES + BENIGN_TYPES


def parse_timestamp(ts_str):
    """Parse Snort timestamp format (MM/DD-HH:MM:SS.microseconds)"""
    try:
        # Format: 02/07-07:36:27.436569
        return datetime.strptime(ts_str.split('.')[0], "%m/%d-%H:%M:%S")
    except:
        return None


def classify_alert(msg):
    """Extract alert type from Snort message"""
    msg_lower = msg.lower()
    
    # Check attack types
    for atk_type in ATTACK_TYPES:
        if atk_type.lower() in msg_lower:
            return atk_type, "attack"
    
    # Check benign types
    for benign_type in BENIGN_TYPES:
        if benign_type.lower() in msg_lower:
            return benign_type, "benign"
    
    return None, None


def analyze_alerts(alert_file, window_minutes=30):
    """
    Parse alert_json.txt and generate statistics
    
    Returns:
        dict: {
            'summary': {...},
            'per_type': {...},
            'windows': [...],
            'poisson_means': {...}
        }
    """
    
    if not os.path.exists(alert_file):
        raise FileNotFoundError(f"Alert file not found: {alert_file}")
    
    # Storage structures
    all_alerts = []
    alerts_by_type = defaultdict(list)
    alerts_by_window = defaultdict(lambda: defaultdict(int))
    type_counters = Counter()
    class_counters = Counter()
    
    # Parse alert file
    with open(alert_file, 'r') as f:
        for line_num, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                alert = json.loads(line)
                
                # Check for tagged alert
                msg = alert.get('msg', '')
                if 'tag detected' not in msg.lower():
                    continue
                
                # Classify
                alert_type, class_type = classify_alert(msg)
                if alert_type is None:
                    continue
                
                # Parse timestamp
                ts_str = alert.get('timestamp', '')
                ts = parse_timestamp(ts_str)
                
                # Store alert
                alert_data = {
                    'line': line_num,
                    'timestamp': ts,
                    'type': alert_type,
                    'class': class_type,
                    'msg': msg,
                    'sid': alert.get('sid', 0),
                    'raw': alert
                }
                all_alerts.append(alert_data)
                alerts_by_type[alert_type].append(alert_data)
                type_counters[alert_type] += 1
                class_counters[class_type] += 1
                
                # Assign to window (if timestamp available)
                if ts:
                    # Round down to nearest window boundary
                    window_id = (ts.hour * 60 + ts.minute) // window_minutes
                    alerts_by_window[window_id][alert_type] += 1
                
            except json.JSONDecodeError:
                continue
            except Exception as e:
                print(f"Warning: Error parsing line {line_num}: {e}", file=sys.stderr)
                continue
    
    # Calculate statistics
    result = {
        'summary': {
            'total_alerts': len(all_alerts),
            'benign_alerts': class_counters['benign'],
            'attack_alerts': class_counters['attack'],
            'alert_types_detected': len(type_counters),
            'windows_detected': len(alerts_by_window),
        },
        'per_type': {},
        'windows': [],
        'poisson_means': {},
    }
    
    # Per-type statistics
    for alert_type in sorted(ALL_TYPES):
        count = type_counters.get(alert_type, 0)
        if count > 0 or alert_type in BENIGN_TYPES or alert_type in ATTACK_TYPES:
            result['per_type'][alert_type] = {
                'count': count,
                'class': 'benign' if alert_type.startswith('BENIGN_') else 'attack',
            }
    
    # Window-based statistics
    if alerts_by_window:
        for window_id in sorted(alerts_by_window.keys()):
            window_data = {
                'window_id': window_id,
                'benign': 0,
                'attacks': 0,
                'alert_breakdown': {}
            }
            
            for alert_type, count in alerts_by_window[window_id].items():
                window_data['alert_breakdown'][alert_type] = count
                if alert_type.startswith('BENIGN_'):
                    window_data['benign'] += count
                else:
                    window_data['attacks'] += count
            
            result['windows'].append(window_data)
    
    # Calculate Poisson means
    if result['windows']:
        # Per-type lambda across all windows
        for alert_type in sorted(ALL_TYPES):
            counts_per_window = []
            for window in result['windows']:
                count = window['alert_breakdown'].get(alert_type, 0)
                counts_per_window.append(count)
            
            if counts_per_window and sum(counts_per_window) > 0:
                lambda_mean = sum(counts_per_window) / len(counts_per_window)
                result['poisson_means'][alert_type] = {
                    'lambda': lambda_mean,
                    'per_window': counts_per_window,
                    'total': sum(counts_per_window),
                    'windows': len(counts_per_window),
                }
    
    return result


def format_json_output(stats):
    """Format statistics as JSON"""
    # Convert datetime objects for JSON serialization
    def serialize_datetime(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Type {type(obj)} not serializable")
    
    return json.dumps(stats, default=serialize_datetime, indent=2)


def format_csv_output(stats):
    """Format statistics as CSV"""
    lines = []
    lines.append("Alert Type,Count,Class,Lambda (Mean),Windows with Data")
    
    for alert_type, poisson_data in sorted(stats['poisson_means'].items()):
        alert_class = 'benign' if alert_type.startswith('BENIGN_') else 'attack'
        count = stats['per_type'][alert_type]['count']
        lambda_mean = poisson_data['lambda']
        windows_with_data = len([c for c in poisson_data['per_window'] if c > 0])
        
        lines.append(f"{alert_type},{count},{alert_class},{lambda_mean:.2f},{windows_with_data}")
    
    # Add summary row
    total_benign = stats['summary']['benign_alerts']
    total_attacks = stats['summary']['attack_alerts']
    lines.append(f"\nSummary")
    lines.append(f"Total Benign Alerts,{total_benign}")
    lines.append(f"Total Attack Alerts,{total_attacks}")
    lines.append(f"Total Alerts,{stats['summary']['total_alerts']}")
    lines.append(f"Windows Detected,{stats['summary']['windows_detected']}")
    
    return '\n'.join(lines)


def format_python_output(stats):
    """Generate Python code template for test.py calibration"""
    lines = []
    lines.append("# ============================================================")
    lines.append("# GENERATED MODEL PARAMETERS FROM ALERT ANALYSIS")
    lines.append("# Copy these into test.py for model calibration")
    lines.append("# ============================================================")
    lines.append("")
    lines.append("from models import AlertType, PoissonDistribution")
    lines.append("")
    lines.append("# Alert type definitions with Poisson means extracted from real data")
    lines.append("ALERT_TYPES = [")
    
    # Attack types
    lines.append("    # ATTACKS (10 types)")
    for alert_type in ATTACK_TYPES:
        if alert_type in stats['poisson_means']:
            lambda_mean = stats['poisson_means'][alert_type]['lambda']
            cost = 1.0 if alert_type != "SYN_FLOOD" else 2.0  # Example: SYN_FLOOD costs more
            lines.append(f"    AlertType({cost}, PoissonDistribution({lambda_mean:.2f}), 't_{alert_type}'),  # λ={lambda_mean:.2f}")
        else:
            lines.append(f"    AlertType(1.0, PoissonDistribution(0.5), 't_{alert_type}'),  # NOT OBSERVED - using default")
    
    lines.append("")
    lines.append("    # BENIGN (10 types)")
    for alert_type in BENIGN_TYPES:
        if alert_type in stats['poisson_means']:
            lambda_mean = stats['poisson_means'][alert_type]['lambda']
            lines.append(f"    AlertType(1.0, PoissonDistribution({lambda_mean:.2f}), 't_{alert_type}'),  # λ={lambda_mean:.2f}")
        else:
            lines.append(f"    AlertType(1.0, PoissonDistribution(12.0), 't_{alert_type}'),  # NOT OBSERVED - using default benign")
    
    lines.append("]")
    lines.append("")
    lines.append("# Statistics from analysis")
    lines.append(f"TOTAL_ALERTS = {stats['summary']['total_alerts']}")
    lines.append(f"BENIGN_ALERTS = {stats['summary']['benign_alerts']}")
    lines.append(f"ATTACK_ALERTS = {stats['summary']['attack_alerts']}")
    lines.append(f"WINDOWS_COLLECTED = {stats['summary']['windows_detected']}")
    lines.append("")
    lines.append("# Per-window averages")
    if stats['windows']:
        avg_benign = sum(w['benign'] for w in stats['windows']) / len(stats['windows'])
        avg_attacks = sum(w['attacks'] for w in stats['windows']) / len(stats['windows'])
        lines.append(f"AVG_BENIGN_PER_WINDOW = {avg_benign:.1f}")
        lines.append(f"AVG_ATTACKS_PER_WINDOW = {avg_attacks:.1f}")
    
    return '\n'.join(lines)


def print_summary(stats):
    """Print human-readable summary"""
    print("\n" + "="*80)
    print("ALERT ANALYSIS SUMMARY")
    print("="*80)
    print(f"\nTotal Alerts Parsed: {stats['summary']['total_alerts']}")
    print(f"  Benign: {stats['summary']['benign_alerts']}")
    print(f"  Attacks: {stats['summary']['attack_alerts']}")
    print(f"Alert Types Detected: {stats['summary']['alert_types_detected']}")
    print(f"Windows Detected: {stats['summary']['windows_detected']}")
    
    print("\n" + "-"*80)
    print("PER-TYPE STATISTICS (Poisson λ Mean)")
    print("-"*80)
    
    print("\nBENIGN TYPES:")
    for alert_type in BENIGN_TYPES:
        if alert_type in stats['poisson_means']:
            data = stats['poisson_means'][alert_type]
            print(f"  {alert_type:20s}: λ={data['lambda']:6.2f}  (total={data['total']:3d}, avg/window={data['lambda']:5.2f})")
        else:
            print(f"  {alert_type:20s}: NOT OBSERVED")
    
    print("\nATTACK TYPES:")
    for alert_type in ATTACK_TYPES:
        if alert_type in stats['poisson_means']:
            data = stats['poisson_means'][alert_type]
            print(f"  {alert_type:20s}: λ={data['lambda']:6.2f}  (total={data['total']:3d}, avg/window={data['lambda']:5.2f})")
        else:
            print(f"  {alert_type:20s}: NOT OBSERVED")
    
    if stats['windows']:
        print("\n" + "-"*80)
        print("PER-WINDOW BREAKDOWN")
        print("-"*80)
        for window in stats['windows']:
            print(f"\nWindow {window['window_id']}: {window['benign']} benign + {window['attacks']} attacks")
            for alert_type, count in sorted(window['alert_breakdown'].items()):
                if count > 0:
                    print(f"  {alert_type:20s}: {count:3d}")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Snort alert_json.txt and extract model parameters"
    )
    parser.add_argument(
        "--alert-file",
        default="/home/vikash/ddpg_workspace/AlertPrioritization/venv37/snort3/var/log/snort/alert_json.txt",
        help="Path to alert_json.txt file"
    )
    parser.add_argument(
        "--window-minutes",
        type=int,
        default=30,
        help="Window duration in minutes (default: 30)"
    )
    parser.add_argument(
        "--output",
        choices=['summary', 'json', 'csv', 'python'],
        default='summary',
        help="Output format"
    )
    parser.add_argument(
        "--outfile",
        help="Output file (default: stdout)"
    )
    
    args = parser.parse_args()
    
    try:
        print(f"[*] Analyzing alerts from: {args.alert_file}", file=sys.stderr)
        stats = analyze_alerts(args.alert_file, args.window_minutes)
        
        # Generate output
        if args.output == 'summary':
            output = ''
            print_summary(stats)
        elif args.output == 'json':
            output = format_json_output(stats)
        elif args.output == 'csv':
            output = format_csv_output(stats)
        elif args.output == 'python':
            output = format_python_output(stats)
        
        # Write output
        if args.output != 'summary':
            if args.outfile:
                with open(args.outfile, 'w') as f:
                    f.write(output)
                print(f"[+] Output written to: {args.outfile}", file=sys.stderr)
            else:
                print(output)
    
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
