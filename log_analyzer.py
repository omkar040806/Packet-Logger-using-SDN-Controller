#!/usr/bin/env python3
"""
Log Analyzer for Packet Logger Project
========================================
Reads packet_log.txt produced by the POX controller and generates:
  - Protocol distribution summary
  - Top talkers (src/dst IP pairs)
  - Timeline of packet arrivals
  - Export to CSV for Wireshark-style analysis

Usage:
    python3 log_analyzer.py [path_to_log]
    Default log path: ./pox_controller/logs/packet_log.txt
"""

import sys
import re
import os
import csv
from collections import defaultdict
from datetime import datetime


# ---------------------------------------------------------------------------
# Regex patterns for log parsing
# ---------------------------------------------------------------------------
RE_TIMESTAMP = re.compile(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\]")
RE_PKT_NUM   = re.compile(r"PKT#(\d+)")
RE_SW        = re.compile(r"SW=(\S+)")
RE_IN_PORT   = re.compile(r"IN_PORT=(\d+)")
RE_ETH       = re.compile(r"ETH (\S+) -> (\S+) \[(\w+)\]")
RE_IP        = re.compile(r"IP (\S+) -> (\S+) proto=(\S+)")
RE_TCP       = re.compile(r"TCP sport=(\d+) dport=(\d+) flags=(\S+)")
RE_UDP       = re.compile(r"UDP sport=(\d+) dport=(\d+)")
RE_ICMP      = re.compile(r"ICMP type=\d+\((\w[\w ]*)\)")
RE_ARP       = re.compile(r"ARP (\w+)")
RE_ACTION    = re.compile(r"└─ (\w+)")


def parse_log(log_path):
    """Parse the packet log file into a list of dicts."""
    records = []
    current = {}

    with open(log_path) as f:
        for line in f:
            line = line.strip()

            ts_m = RE_TIMESTAMP.search(line)
            if not ts_m:
                continue
            ts = ts_m.group(1)

            # Packet header line
            if "PKT#" in line:
                if current:
                    records.append(current)
                current = {"timestamp": ts, "action": ""}

                m = RE_PKT_NUM.search(line)
                if m: current["pkt_num"] = int(m.group(1))

                m = RE_SW.search(line)
                if m: current["switch"] = m.group(1)

                m = RE_IN_PORT.search(line)
                if m: current["in_port"] = int(m.group(1))

                m = RE_ETH.search(line)
                if m:
                    current["src_mac"]   = m.group(1)
                    current["dst_mac"]   = m.group(2)
                    current["eth_type"]  = m.group(3)
                    current["protocol"]  = m.group(3)

                m = RE_IP.search(line)
                if m:
                    current["src_ip"]   = m.group(1)
                    current["dst_ip"]   = m.group(2)
                    current["protocol"] = m.group(3)

                m = RE_TCP.search(line)
                if m:
                    current["src_port"] = int(m.group(1))
                    current["dst_port"] = int(m.group(2))
                    current["flags"]    = m.group(3)

                m = RE_UDP.search(line)
                if m:
                    current["src_port"] = int(m.group(1))
                    current["dst_port"] = int(m.group(2))

                m = RE_ICMP.search(line)
                if m:
                    current["icmp_type"] = m.group(1)

                m = RE_ARP.search(line)
                if m:
                    current["protocol"] = "ARP"

            # Action line (FORWARD / FLOOD)
            elif "└─" in line and current:
                m = RE_ACTION.search(line)
                if m: current["action"] = m.group(1)

    if current:
        records.append(current)

    return records


def print_summary(records):
    proto_count  = defaultdict(int)
    action_count = defaultdict(int)
    ip_pairs     = defaultdict(int)

    for r in records:
        proto = r.get("protocol", "UNKNOWN")
        proto_count[proto]  += 1
        action_count[r.get("action", "?")] += 1

        src = r.get("src_ip", r.get("src_mac", "?"))
        dst = r.get("dst_ip", r.get("dst_mac", "?"))
        ip_pairs[(src, dst)] += 1

    total = len(records)
    print("\n" + "=" * 60)
    print(f"  PACKET LOGGER — ANALYSIS REPORT")
    print(f"  Total packets captured: {total}")
    print("=" * 60)

    print("\n📊 Protocol Distribution:")
    for proto, cnt in sorted(proto_count.items(), key=lambda x: -x[1]):
        bar = "█" * int(30 * cnt / max(total, 1))
        print(f"  {proto:<12} {cnt:>5} pkts  {bar}")

    print("\n📡 Forwarding Actions:")
    for action, cnt in sorted(action_count.items(), key=lambda x: -x[1]):
        print(f"  {action:<10} {cnt:>5}")

    print("\n🔝 Top 10 Talker Pairs (src -> dst):")
    for (src, dst), cnt in sorted(ip_pairs.items(), key=lambda x: -x[1])[:10]:
        print(f"  {src:<18} -> {dst:<18} : {cnt:>4} pkts")

    print("=" * 60 + "\n")


def export_csv(records, out_path="packet_analysis.csv"):
    """Export parsed records to CSV."""
    fields = ["pkt_num", "timestamp", "switch", "in_port",
              "src_mac", "dst_mac", "eth_type", "protocol",
              "src_ip", "dst_ip", "src_port", "dst_port",
              "flags", "icmp_type", "action"]
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)
    print(f"✅  CSV exported → {out_path}")


if __name__ == "__main__":
    default_log = os.path.join(
        os.path.dirname(__file__),
        "pox_controller", "logs", "packet_log.txt"
    )
    log_path = sys.argv[1] if len(sys.argv) > 1 else default_log

    if not os.path.exists(log_path):
        print(f"❌  Log file not found: {log_path}")
        print("    Run the controller + topology first, then re-run this script.")
        sys.exit(1)

    print(f"📂  Parsing log: {log_path}")
    records = parse_log(log_path)
    print_summary(records)

    csv_path = os.path.join(os.path.dirname(log_path), "packet_analysis.csv")
    export_csv(records, csv_path)
