#!/usr/bin/env python3
"""
scapy_traffic.py — Real-time tagged traffic generator for Snort + DDPG
----------------------------------------------------------------------

Generates both benign and malicious traffic patterns on a specified interface.
Each attack carries a unique payload/tag so Snort rules can differentiate them,
allowing your RL agent to prioritize distinct alert types.

Usage:
    python3 src/scapy_traffic.py --iface lo --interval 0.5 --ratio 0.4 --continuous
"""

import argparse
import random
import time
from scapy.all import (
    IP, TCP, UDP, ICMP, send, RandIP, RandShort, Raw
)

# ============================================================
# Tagged Attack Signatures (for Snort to detect)
# ============================================================
SIGNATURES = {
    "SYN_FLOOD": b"ATTACK_SYN_FLOOD_2025",
    "PORT_SCAN": b"ATTACK_PORT_SCAN_2025",
    "SQL_INJECTION": b"ATTACK_SQL_INJECTION_2025"
}

# ============================================================
# Benign Traffic Generators
# ============================================================
def benign_http(dst="127.0.0.1"):
    pkt = IP(dst=dst) / TCP(dport=80, sport=RandShort(), flags="S") / Raw(
        b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    )
    return pkt

def benign_dns(dst="127.0.0.1"):
    pkt = IP(dst=dst) / UDP(dport=53, sport=RandShort()) / Raw(b"\x12\x34 benign query")
    return pkt

def benign_icmp(dst="127.0.0.1"):
    pkt = IP(dst=dst) / ICMP()
    return pkt

# ============================================================
# Attack Traffic Generators (Tagged)
# ============================================================
def attack_syn_flood(dst="127.0.0.1", count=5):
    tag = SIGNATURES["SYN_FLOOD"]
    pkts = [
        IP(src=str(RandIP()), dst=dst) / TCP(sport=RandShort(), dport=80, flags="S") / Raw(tag)
        for _ in range(count)
    ]
    return pkts, "SYN_FLOOD"

def attack_port_scan(dst="127.0.0.1", ports=None):
    tag = SIGNATURES["PORT_SCAN"]
    if ports is None:
        ports = list(range(20, 30))
    pkts = [
        IP(src=str(RandIP()), dst=dst) / TCP(sport=RandShort(), dport=p, flags="S") / Raw(tag)
        for p in ports
    ]
    return pkts, "PORT_SCAN"

def attack_sql_injection(dst="127.0.0.1"):
    tag = SIGNATURES["SQL_INJECTION"]
    payload = b"GET /login.php?user=admin' OR '1'='1 -- " + tag
    pkt = IP(dst=dst) / TCP(dport=80, sport=RandShort(), flags="PA") / Raw(payload)
    return pkt, "SQL_INJECTION"

# ============================================================
# Main Traffic Loop
# ============================================================
def run_traffic(iface, ratio, interval, continuous):
    benign_funcs = [benign_http, benign_dns, benign_icmp]
    attack_funcs = [attack_syn_flood, attack_port_scan, attack_sql_injection]
    dst_ip = "127.0.0.1" if iface == "lo" else "192.168.0.100"  # adjust per network

    print(f"\n[+] Starting Tagged Scapy traffic on interface: {iface}")
    print(f"    Benign:Attack ratio = {1 - ratio:.1f}:{ratio:.1f}, interval = {interval}s\n")

    try:
        while True:
            if random.random() < ratio:
                atk_func = random.choice(attack_funcs)
                pkts, atk_name = atk_func(dst_ip)

                if isinstance(pkts, list):
                    send(pkts, iface=iface, verbose=False)
                    print(f"[ATTACK] {atk_name} ({len(pkts)} pkts) sent with tag={SIGNATURES[atk_name].decode()}")
                else:
                    send(pkts, iface=iface, verbose=False)
                    print(f"[ATTACK] {atk_name} sent with tag={SIGNATURES[atk_name].decode()}")
            else:
                func = random.choice(benign_funcs)
                pkt = func(dst_ip)
                send(pkt, iface=iface, verbose=False)
                print(f"[BENIGN] {func.__name__}")

            time.sleep(interval)
            if not continuous:
                break
    except KeyboardInterrupt:
        print("\n[+] Traffic generator stopped.")


# ============================================================
# CLI Entrypoint
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="Scapy-based traffic generator with Snort attack tagging.")
    parser.add_argument("--iface", default="lo", help="Interface to send packets on (default: lo)")
    parser.add_argument("--interval", type=float, default=0.5, help="Time between packets (seconds)")
    parser.add_argument("--ratio", type=float, default=0.3, help="Fraction of malicious packets [0–1]")
    parser.add_argument("--continuous", action="store_true", help="Run continuously (default: one cycle)")
    args = parser.parse_args()

    run_traffic(args.iface, args.ratio, args.interval, args.continuous)


if __name__ == "__main__":
    main()
    
