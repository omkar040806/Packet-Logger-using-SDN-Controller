#!/usr/bin/env python3

"""
Mininet Topology for Packet Logger Project
==========================================
Topology:
h1, h2 ---- s1 ---- s2 ---- h3, h4

This topology demonstrates:
  - Same-switch forwarding
  - Cross-switch forwarding
  - Flooding (ARP / unknown destination)
  - Firewall blocking
  - Protocol variety (ICMP, TCP, UDP)

References:
  - Mininet Python API: http://mininet.org/api/
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink


def build_topology():
    """Build and return the Mininet network."""
    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,        # assign MACs 00:00:00:00:00:01, etc.
        autoStaticArp=False      # keep ARP so controller sees ARP packets
    )

    # ---- Controller (POX running on localhost:6633) -------------------
    info("*** Adding POX controller\n")
    c0 = net.addController(
        "c0",
        controller=RemoteController,
        ip="127.0.0.1",
        port=6633
    )

    # ---- Switches -----------------------------------------------------
    info("*** Adding switches\n")
    s1 = net.addSwitch("s1", protocols="OpenFlow10")
    s2 = net.addSwitch("s2", protocols="OpenFlow10")

    # ---- Hosts --------------------------------------------------------
    info("*** Adding hosts\n")
    h1 = net.addHost("h1", ip="10.0.0.1/24")
    h2 = net.addHost("h2", ip="10.0.0.2/24")
    h3 = net.addHost("h3", ip="10.0.0.3/24")
    h4 = net.addHost("h4", ip="10.0.0.4/24")   # extra host on s2

    # ---- Links --------------------------------------------------------
    info("*** Adding links\n")
    # Host links (100 Mbps, 1 ms delay)
    net.addLink(h1, s1, bw=100, delay="1ms")
    net.addLink(h2, s1, bw=100, delay="1ms")
    net.addLink(h3, s2, bw=100, delay="1ms")
    net.addLink(h4, s2, bw=100, delay="1ms")
    # Switch-to-switch uplink (1 Gbps, 5 ms delay)
    net.addLink(s1, s2, bw=1000, delay="5ms")

    return net, c0


def run():
    setLogLevel("info")
    net, c0 = build_topology()

    info("*** Starting network\n")
    net.build()
    c0.start()
    net.get("s1").start([c0])
    net.get("s2").start([c0])

    info("\n" + "=" * 60 + "\n")
    info("  Packet Logger Topology is UP\n")
    info("  Hosts : h1=10.0.0.1  h2=10.0.0.2  h3=10.0.0.3  h4=10.0.0.4\n")
    info("  Ctrl  : POX @ 127.0.0.1:6633\n")
    info("=" * 60 + "\n")
    info("  Quick test commands:\n")
    info("    mininet> h1 ping -c 4 h2        # ICMP\n")
    info("    mininet> h1 ping -c 4 h3        # cross-switch ICMP\n")
    info("    mininet> h2 iperf -s &          # iperf server\n")
    info("    mininet> h1 iperf -c h2 -t 5   # iperf TCP client\n")
    info("    mininet> h1 iperf -c h2 -u -t 5 # iperf UDP client\n")
    info("    mininet> pingall               # all-pairs ping\n")
    info("    mininet> sh ovs-ofctl -O OpenFlow10 dump-flows s1\n")
    info("    mininet> sh ovs-ofctl -O OpenFlow10 dump-flows s2\n")
    info("=" * 60 + "\n")

    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == "__main__":
    run()
