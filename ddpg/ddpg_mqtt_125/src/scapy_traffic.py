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
import os
import json
from datetime import datetime, timedelta
from scapy.all import (
    IP, TCP, UDP, ICMP, send, RandIP, RandShort, Raw
)

# ============================================================
# Tagged Attack Signatures (for Snort to detect)
# ============================================================
SIGNATURES = {
    "SYN_FLOOD": b"ATTACK_SYN_FLOOD_2025",
    "PORT_SCAN": b"ATTACK_PORT_SCAN_2025",
    "SQL_INJECTION": b"ATTACK_SQL_INJECTION_2025",
    "HTTP_C2": b"ATTACK_HTTP_C2_2025",
    "DNS_TUNNELING": b"ATTACK_DNS_TUNNELING_2025",
    "BRUTE_FORCE": b"ATTACK_BRUTE_FORCE_2025",
    "DDOS": b"ATTACK_DDOS_2025",
    "XSS": b"ATTACK_XSS_2025",
    "COMMAND_INJECTION": b"ATTACK_COMMAND_INJECTION_2025",
    "MALWARE_DOWNLOAD": b"ATTACK_MALWARE_DOWNLOAD_2025"
}

# ============================================================
# Benign Traffic Generators
# ============================================================
def benign_http(dst="127.0.0.1"):
    # Randomize path and user-agent to increase variety
    path = random.choice(["/", "/index.html", "/home", "/login.php", "/api/data", "/search?q=test"]) 
    user_agent = random.choice([b"curl/7.79", b"Mozilla/5.0", b"Wget/1.20", b"python-requests/2.25"]) 
    payload = b"GET " + path.encode() + b" HTTP/1.1\r\nHost: example.com\r\nUser-Agent: " + user_agent + b"\r\n\r\n"
    pkt = IP(dst=dst) / TCP(dport=80, sport=RandShort(), flags="PA") / Raw(payload)
    return pkt

def benign_dns(dst="127.0.0.1"):
    # Randomize DNS query names to simulate benign DNS traffic
    qname = random.choice([b"example.com", b"api.example.com", b"cdn.example.com", b"login.example.com"])
    pkt = IP(dst=dst) / UDP(dport=53, sport=RandShort()) / Raw(b"\x12\x34 " + qname)
    return pkt

def benign_icmp(dst="127.0.0.1"):
    pkt = IP(dst=dst) / ICMP()
    return pkt

def benign_ssh(dst="127.0.0.1"):
    # Simulate SSH keepalive / connection attempt
    payload = b"SSH-2.0-OpenSSH_7.4\r\n"
    pkt = IP(dst=dst) / TCP(dport=22, sport=RandShort(), flags="PA") / Raw(payload)
    return pkt

def benign_tls(dst="127.0.0.1"):
    # Simulate TLS ClientHello-like bytes (not full handshake)
    payload = b"\x16\x03\x01\x00\x2e\x01\x00\x00\x2a\x03\x03" + b"\x00" * 20
    pkt = IP(dst=dst) / TCP(dport=443, sport=RandShort(), flags="PA") / Raw(payload)
    return pkt

def benign_smtp(dst="127.0.0.1"):
    # Simulate SMTP HELO/EHLO
    payload = b"HELO example.com\r\n"
    pkt = IP(dst=dst) / TCP(dport=25, sport=RandShort(), flags="PA") / Raw(payload)
    return pkt

def benign_ntp(dst="127.0.0.1"):
    # Simple NTP request-like payload
    payload = b"\x1b" + b"\x00" * 47
    pkt = IP(dst=dst) / UDP(dport=123, sport=RandShort()) / Raw(payload)
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
# Main Traffic Loop with 30-min windowing and attack counting
# ============================================================
def run_traffic(iface, ratio, interval, continuous, benign_rate_per_min, malicious_rate_per_min, cooccurrence_prob=0.05, duration_minutes=30):
    benign_funcs = [benign_http, benign_dns, benign_icmp, benign_ssh, benign_tls, benign_smtp, benign_ntp]
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
    dst_ip = "127.0.0.1" if iface == "lo" else "192.168.0.100"

    print(f"\n[+] Starting Tagged Scapy traffic on interface: {iface}")
    print(f"    Live Poisson rates: benign={benign_rate_per_min}/min malicious={malicious_rate_per_min}/min")
    print(f"    Window duration: {duration_minutes} minutes")

    # convert rates to per-second lambdas for expovariate
    benign_lambda = benign_rate_per_min / 60.0 if benign_rate_per_min > 0 else None
    malicious_lambda = malicious_rate_per_min / 60.0 if malicious_rate_per_min > 0 else None

    # Track attack counts per window
    # Create a mapping of attack type names (returned from attack functions)
    attack_type_names = [
        "SYN_FLOOD", "PORT_SCAN", "SQL_INJECTION", "HTTP_C2", "DNS_TUNNELING",
        "BRUTE_FORCE", "DDOS", "XSS", "COMMAND_INJECTION", "MALWARE_DOWNLOAD"
    ]
    attack_counts = {atk_type: 0 for atk_type in attack_type_names}
    benign_count = 0
    window_start = time.time()
    window_duration_sec = duration_minutes * 60

    try:
        while True:
            elapsed = time.time() - window_start
            
            # Check if window is complete
            if elapsed >= window_duration_sec:
                # Print stats for completed window
                print(f"\n[WINDOW COMPLETE] {duration_minutes}-min window stats:")
                print(f"  Benign events: {benign_count}")
                for atk_name, count in sorted(attack_counts.items()):
                    print(f"  {atk_name}: {count}")
                
                # Reset counters for next window
                benign_count = 0
                attack_counts = {atk_type: 0 for atk_type in attack_type_names}
                window_start = time.time()
                
                if not continuous:
                    break
            
            # sample next inter-arrival times (seconds)
            next_benign = random.expovariate(benign_lambda) if benign_lambda else float('inf')
            next_malicious = random.expovariate(malicious_lambda) if malicious_lambda else float('inf')

            # Emit whichever arrives first (benign or malicious)
            if next_malicious < next_benign:
                # emit a malicious event
                time.sleep(next_malicious)
                atk_func = random.choice(attack_funcs)
                pkts, atk_name = atk_func(dst_ip, count=1)
                if isinstance(pkts, list):
                    send(pkts, iface=iface, verbose=False)
                else:
                    send(pkts, iface=iface, verbose=False)
                print(f"[ATTACK] {atk_name} sent with tag={SIGNATURES[atk_name].decode()}")
                attack_counts[atk_name] += 1

                # optional co-occurrence: emit 0-2 extra related alerts at same time
                if random.random() < cooccurrence_prob:
                    extra_count = random.randint(1, 2)
                    for _ in range(extra_count):
                        extra_atk = random.choice(attack_funcs)
                        pkts2, name2 = extra_atk(dst_ip, count=1)
                        if isinstance(pkts2, list):
                            send(pkts2, iface=iface, verbose=False)
                        else:
                            send(pkts2, iface=iface, verbose=False)
                        print(f"[ATTACK-CO] {name2} sent (co-occur)")
                        attack_counts[name2] += 1
            else:
                # emit benign event
                time.sleep(next_benign)
                func = random.choice(benign_funcs)
                pkt = func(dst_ip)
                send(pkt, iface=iface, verbose=False)
                print(f"[BENIGN] {func.__name__}")
                benign_count += 1

            if not continuous:
                break
    except KeyboardInterrupt:
        print("\n[+] Traffic generator stopped.")


def _make_alert_record(atk_name, src_ip, dst_ip, proto='TCP', rule=None, action='allow', sid=0, classification='default', priority=2, timestamp=None):
    if timestamp is None:
        timestamp = datetime.utcnow().isoformat() + 'Z'
    return {
        "timestamp": timestamp,
        "proto": proto,
        "src_ap": src_ip,
        "dst_ap": dst_ip,
        "rule": rule or f"{atk_name}_rule",
        "action": action,
        "msg": f"{atk_name} tag detected",
        "sid": sid,
        "class": classification,
        "priority": priority,
    }

def replay_to_alert_json(out_path, events, timespan_minutes=30):
    """
    Write synthetic alert JSON lines to `out_path` with timestamps spread over `timespan_minutes`.
    """
    if events <= 0:
        raise ValueError("events must be > 0")
    start = datetime.utcnow()
    total_seconds = int(timespan_minutes * 60)
    with open(out_path, 'w', encoding='utf-8') as f:
        for i in range(events):
            t = start + timedelta(seconds=(i * total_seconds) // events)
            evt = events[i] if isinstance(events, list) else events
            # if events is a list of dicts, use it; otherwise skip
            if isinstance(events, list):
                record = evt
            else:
                record = evt
            # ensure timestamp format
            record['timestamp'] = t.isoformat() + 'Z'
            f.write(json.dumps(record) + '\n')
    print(f"[+] Wrote {events if not isinstance(events, list) else len(events)} alerts to {out_path}")

# ============================================================
# CLI Entrypoint
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="Scapy-based traffic generator with Snort attack tagging.")
    parser.add_argument("--iface", default="lo", help="Interface to send packets on (default: lo)")
    parser.add_argument("--interval", type=float, default=0.5, help="Time between packets (seconds)")
    parser.add_argument("--ratio", type=float, default=0.3, help="Fraction of malicious packets [0–1]")
    parser.add_argument("--continuous", action="store_true", help="Run continuously (default: one cycle)")
    # Live-mode uses Poisson rates instead of burst counts per the paper
    parser.add_argument("--replay", action="store_true", help="Generate alert_json file with timestamps over a timespan instead of sending live packets")
    parser.add_argument("--events", type=int, default=500, help="(legacy) Number of alert events to generate in replay mode (ignored when using rate args)")
    parser.add_argument("--timespan-minutes", type=int, default=30, help="Total timespan in minutes for generated timestamps (replay mode)")
    parser.add_argument("--out-file", default=None, help="Output path for alert JSON lines (replay mode). Defaults to $VIRTUAL_ENV/snort3/var/log/snort/alert_json.txt if available")
    parser.add_argument("--benign-rate", type=float, default=5.0, help="Mean benign alerts per minute (Poisson process)")
    parser.add_argument("--malicious-rate", type=float, default=0.5, help="Mean malicious alerts per minute (Poisson process)")
    parser.add_argument("--cooccurrence-prob", type=float, default=0.05, help="Probability an attack triggers co-occurring additional alerts at the same timestamp")
    parser.add_argument("--duration-minutes", type=int, default=30, help="Duration in minutes per window for live mode (default: 30 min windows)")
    args = parser.parse_args()

    if args.replay:
        # Build simple alert records list and write to out-file with timestamps spanning the timespan
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
        dst_ip = "127.0.0.1" if args.iface == "lo" else "192.168.0.100"
        events = []
        # classification mapping to match snort rules' classtype semantics
        class_map = {
            'SYN_FLOOD': ('attempted-dos', 1),
            'DDOS': ('attempted-dos', 1),
            'SQL_INJECTION': ('web-application-attack', 1),
            'HTTP_C2': ('trojan-activity', 1),
            'PORT_SCAN': ('attempted-recon', 2),
            'BRUTE_FORCE': ('suspicious-login', 1),
            'XSS': ('web-application-attack', 1),
            'COMMAND_INJECTION': ('web-application-attack', 1),
            'MALWARE_DOWNLOAD': ('trojan-activity', 1),
            'DNS_TUNNELING': ('protocol-command-decode', 2),
        }
        # Use Poisson processes (via exponential inter-arrival times) to generate event timestamps
        timespan_seconds = int(args.timespan_minutes * 60)

        def generate_timestamps(rate_per_min):
            # rate_per_min: expected events per minute
            if rate_per_min <= 0:
                return []
            rate_per_sec = rate_per_min / 60.0
            ts = []
            t = 0.0
            while True:
                # expovariate expects lambda (events per second)
                wait = random.expovariate(rate_per_sec)
                t += wait
                if t > timespan_seconds:
                    break
                ts.append(t)
            return ts

        benign_ts = generate_timestamps(args.benign_rate)
        malicious_ts = generate_timestamps(args.malicious_rate)

        # create benign event records
        for offset in benign_ts:
            t = datetime.utcnow() + timedelta(seconds=offset)
            rec = _make_alert_record('BENIGN', src_ip=str(RandIP()), dst_ip=dst_ip, classification='not-suspicious', priority=3, timestamp=t.isoformat() + 'Z')
            events.append(rec)

        # create malicious event records, with optional co-occurrence
        for offset in malicious_ts:
            t = datetime.utcnow() + timedelta(seconds=offset)
            atk_func = random.choice(attack_funcs)
            _, atk_name = atk_func(dst_ip, count=1)
            clas, prio = class_map.get(atk_name, ('default', 2))
            rec = _make_alert_record(atk_name, src_ip=str(RandIP()), dst_ip=dst_ip, classification=clas, priority=prio, timestamp=t.isoformat() + 'Z')
            events.append(rec)

            # co-occurrence: with some probability, emit 1-2 additional related alerts at same timestamp
            if random.random() < args.cooccurrence_prob:
                extra_count = random.randint(1, 2)
                for _ in range(extra_count):
                    extra_atk = random.choice(attack_funcs)
                    _, extra_name = extra_atk(dst_ip, count=1)
                    extra_clas, extra_prio = class_map.get(extra_name, ('default', 2))
                    extra_rec = _make_alert_record(extra_name, src_ip=str(RandIP()), dst_ip=dst_ip, classification=extra_clas, priority=extra_prio, timestamp=t.isoformat() + 'Z')
                    events.append(extra_rec)

        out_file = args.out_file
        if out_file is None:
            venv = os.environ.get('VIRTUAL_ENV')
            if venv:
                out_file = os.path.join(venv, 'snort3', 'var', 'log', 'snort', 'alert_json.txt')
            else:
                out_file = os.path.join(os.getcwd(), 'alert_json.txt')

        # sort events by timestamp (ISO strings compare correctly) and write out
        events.sort(key=lambda r: r.get('timestamp', ''))
        with open(out_file, 'w', encoding='utf-8') as f:
            for rec in events:
                f.write(json.dumps(rec) + '\n')
        print(f"[+] Wrote {len(events)} alerts to {out_file} spanning {args.timespan_minutes} minutes (benign_rate={args.benign_rate}/min malicious_rate={args.malicious_rate}/min)")
    else:
        run_traffic(args.iface, args.ratio, args.interval, args.continuous, args.benign_rate, args.malicious_rate, args.cooccurrence_prob, args.duration_minutes)


if __name__ == "__main__":
    main()
    
