# Packet Logger using SDN Controller (POX + Mininet)

## Problem Statement
Capture and log packets traversing the network using controller events.

## Objective
This project demonstrates Software Defined Networking using Mininet and the POX controller.  
The controller captures packets using `packet_in`, identifies protocols, logs packet details, installs flow rules, and enforces a firewall policy.

## Features
- Packet header capture
- Protocol identification: ARP, IPv4, ICMP, TCP, UDP, IPv6
- Packet logging to file
- Learning switch behavior
- OpenFlow flow rule installation
- Firewall rule: block `h1 -> h4`
- Log analyzer for protocol distribution and talker pairs

## Topology
```text
h1, h2 ---- s1 ---- s2 ---- h3, h4
