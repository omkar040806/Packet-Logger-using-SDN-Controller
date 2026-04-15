from pox.core import core
import pox.openflow.libopenflow_01 as of

from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp
from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp

import os
from datetime import datetime

log = core.getLogger()

# -----------------------------
# CONFIGURATION
# -----------------------------

# Firewall rule: block traffic from h1 to h4
BLOCK_SRC_IP = "10.0.0.1"
BLOCK_DST_IP = "10.0.0.4"

# Print statistics after every 20 packets
STATS_INTERVAL = 20

# Path for saving log file
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "packet_log.txt")

# -----------------------------
# GLOBAL VARIABLES
# -----------------------------

# Stores learned MAC-to-port mapping for each switch
mac_to_port = {}

# Counts total packets processed
packet_counter = 0

# Stores protocol statistics
protocol_stats = {}

# Stores first packet time for each switch
switch_first_packet_time = {}

# -----------------------------
# HELPER FUNCTIONS
# -----------------------------

def now():
    # Return current timestamp
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

def write_log(line):
    # Save log line to file
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def log_line(msg):
    # Print log line to POX terminal and file
    full = "[%s] %s" % (now(), msg)
    log.info(full)
    write_log(full)

def inc_proto(proto):
    # Increase count for a protocol
    protocol_stats[proto] = protocol_stats.get(proto, 0) + 1

def show_stats():
    # Print protocol statistics
    total = sum(protocol_stats.values())
    log_line("--------------------------------------------------")
    log_line("STATS | Total packets: %d" % total)
    for proto, count in sorted(protocol_stats.items(), key=lambda x: x[1], reverse=True):
        pct = (count * 100.0 / total) if total else 0
        log_line("  %-12s : %5d packets  (%4.1f%%)" % (proto, count, pct))
    log_line("--------------------------------------------------")

def dpid_str(dpid):
    # Convert switch DPID to string
    return str(dpid)

def get_tcp_flags_string(tcp_pkt):
    # Return readable TCP flags
    flags = []
    if tcp_pkt.SYN: flags.append("SYN")
    if tcp_pkt.ACK: flags.append("ACK")
    if tcp_pkt.FIN: flags.append("FIN")
    if tcp_pkt.RST: flags.append("RST")
    if tcp_pkt.PSH: flags.append("PSH")
    if tcp_pkt.URG: flags.append("URG")
    return "|".join(flags) if flags else "-"

def icmp_type_name(t):
    # Return readable ICMP type name
    names = {
        0: "Echo Reply",
        3: "Destination Unreachable",
        5: "Redirect",
        8: "Echo Request",
        11: "Time Exceeded"
    }
    return names.get(t, "Unknown")

def install_forward_flow(event, packet, out_port):
    # Install flow rule for forwarding
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match.from_packet(packet, event.port)
    msg.idle_timeout = 30
    msg.hard_timeout = 60
    msg.priority = 20
    msg.actions.append(of.ofp_action_output(port=out_port))
    event.connection.send(msg)

def install_drop_flow(event, packet):
    # Install flow rule with no action = drop packet
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match.from_packet(packet, event.port)
    msg.idle_timeout = 30
    msg.hard_timeout = 60
    msg.priority = 100
    event.connection.send(msg)

def send_packet(event, out_port):
    # Send current packet to a given port
    msg = of.ofp_packet_out()
    msg.data = event.ofp
    msg.actions.append(of.ofp_action_output(port=out_port))
    event.connection.send(msg)

def flood(event):
    # Flood packet to all ports
    send_packet(event, of.OFPP_FLOOD)

# -----------------------------
# MAIN CONTROLLER CLASS
# -----------------------------

class PacketLogger(object):
    def __init__(self, connection):
        # Save switch connection and DPID
        self.connection = connection
        self.dpid = connection.dpid
        connection.addListeners(self)

        # Create MAC table for new switch
        if self.dpid not in mac_to_port:
            mac_to_port[self.dpid] = {}

        # Log switch connection
        log_line("Switch connected: DPID=%s" % dpid_str(self.dpid))
        log.info("[+] Switch %s connected.", dpid_str(self.dpid))

        # Initialize first packet time
        if self.dpid not in switch_first_packet_time:
            switch_first_packet_time[self.dpid] = None

    def _handle_PacketIn(self, event):
        # Called whenever switch sends a packet to controller
        global packet_counter

        packet = event.parsed
        if not packet.parsed:
            return

        packet_counter += 1

        dpid = dpid_str(self.dpid)
        in_port = event.port
        src_mac = str(packet.src)
        dst_mac = str(packet.dst)

        # Learn source MAC address
        mac_to_port[self.dpid][src_mac] = in_port

        # Log first packet latency note
        if switch_first_packet_time[self.dpid] is None:
            switch_first_packet_time[self.dpid] = datetime.now()
            log_line(
                "First packet seen on switch %s -> this packet experiences controller involvement (higher initial latency expected)."
                % dpid
            )

        eth_name = "UNKNOWN"
        details = ""
        action_msg = ""

        src_ip = None
        dst_ip = None

        # ---------------- ARP PACKET ----------------
        if packet.type == ethernet.ARP_TYPE:
            eth_name = "ARP"
            inc_proto("ARP")

            arp_pkt = packet.find('arp')
            if arp_pkt:
                src_ip = str(arp_pkt.protosrc)
                dst_ip = str(arp_pkt.protodst)
                op = "REQUEST" if arp_pkt.opcode == arp.REQUEST else "REPLY"
                details = " | ARP %s who-has=%s tell=%s" % (op, dst_ip, src_ip)

        # ---------------- IPv4 PACKET ----------------
        elif packet.type == ethernet.IP_TYPE:
            ip_pkt = packet.find('ipv4')
            if ip_pkt:
                src_ip = str(ip_pkt.srcip)
                dst_ip = str(ip_pkt.dstip)

                # Apply firewall rule
                if src_ip == BLOCK_SRC_IP and dst_ip == BLOCK_DST_IP:
                    inc_proto("BLOCKED")
                    eth_name = "IPv4"
                    details = " | IP %s -> %s proto=%s | FIREWALL BLOCKED" % (
                        src_ip, dst_ip, ip_pkt.protocol
                    )

                    line = "PKT#%06d | SW=%s IN_PORT=%s | ETH %s -> %s [%s]%s" % (
                        packet_counter, dpid, in_port, src_mac, dst_mac, eth_name, details
                    )
                    log_line(line)

                    install_drop_flow(event, packet)
                    action_msg = "  └─ DROP rule installed for %s -> %s" % (src_ip, dst_ip)
                    log_line(action_msg)
                    return

                # ICMP packet
                if ip_pkt.protocol == ipv4.ICMP_PROTOCOL:
                    eth_name = "IPv4"
                    inc_proto("ICMP")
                    icmp_pkt = packet.find('icmp')
                    if icmp_pkt:
                        details = " | IP %s -> %s proto=ICMP | ICMP type=%s(%s) code=%s" % (
                            src_ip, dst_ip, icmp_pkt.type, icmp_type_name(icmp_pkt.type), icmp_pkt.code
                        )
                    else:
                        details = " | IP %s -> %s proto=ICMP" % (src_ip, dst_ip)

                # TCP packet
                elif ip_pkt.protocol == ipv4.TCP_PROTOCOL:
                    eth_name = "IPv4"
                    inc_proto("TCP")
                    tcp_pkt = packet.find('tcp')
                    if tcp_pkt:
                        details = " | IP %s -> %s proto=TCP | TCP sport=%s dport=%s flags=%s" % (
                            src_ip, dst_ip, tcp_pkt.srcport, tcp_pkt.dstport, get_tcp_flags_string(tcp_pkt)
                        )
                    else:
                        details = " | IP %s -> %s proto=TCP" % (src_ip, dst_ip)

                # UDP packet
                elif ip_pkt.protocol == ipv4.UDP_PROTOCOL:
                    eth_name = "IPv4"
                    inc_proto("UDP")
                    udp_pkt = packet.find('udp')
                    if udp_pkt:
                        details = " | IP %s -> %s proto=UDP | UDP sport=%s dport=%s" % (
                            src_ip, dst_ip, udp_pkt.srcport, udp_pkt.dstport
                        )
                    else:
                        details = " | IP %s -> %s proto=UDP" % (src_ip, dst_ip)

                # Other IPv4 packet
                else:
                    eth_name = "IPv4"
                    inc_proto("IPv4")
                    details = " | IP %s -> %s proto=%s" % (src_ip, dst_ip, ip_pkt.protocol)
            else:
                eth_name = "IPv4"
                inc_proto("IPv4")

        # ---------------- IPv6 PACKET ----------------
        elif packet.type == ethernet.IPV6_TYPE:
            eth_name = "IPv6"
            inc_proto("IPv6")

        # ---------------- OTHER PACKET ----------------
        else:
            eth_name = hex(packet.type)
            inc_proto("OTHER")

        # Log packet details
        line = "PKT#%06d | SW=%s IN_PORT=%s | ETH %s -> %s [%s]%s" % (
            packet_counter, dpid, in_port, src_mac, dst_mac, eth_name, details
        )
        log_line(line)

        # Learning switch logic
        if dst_mac in mac_to_port[self.dpid]:
            out_port = mac_to_port[self.dpid][dst_mac]
            install_forward_flow(event, packet, out_port)
            send_packet(event, out_port)
            action_msg = "  └─ FORWARD to port %s | flow rule installed" % out_port
        else:
            flood(event)
            action_msg = "  └─ FLOOD (unknown dst %s)" % dst_mac

        # Log action taken
        log_line(action_msg)

        # Print stats periodically
        if packet_counter % STATS_INTERVAL == 0:
            show_stats()

# -----------------------------
# POX ENTRY POINT
# -----------------------------

def _handle_ConnectionUp(event):
    # Create controller object for each connected switch
    PacketLogger(event.connection)

def launch():
    # Start controller module
    log_line("============================================================")
    log_line("PacketLogger Controller STARTED")
    log_line("============================================================")
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    log.info("PacketLogger module loaded. Waiting for switches...")
