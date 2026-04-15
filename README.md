# 📡 Packet Logger using SDN Controller (POX + Mininet)

---

## 🧩 Problem Statement
Capture and log packets traversing the network using SDN controller events.

---

## 🎯 Objective
This project demonstrates **Software Defined Networking (SDN)** using:

- 🧠 POX Controller  
- 🌐 Mininet  

The controller performs:

- Packet capture using `PacketIn`
- Protocol identification (ARP, ICMP, TCP, UDP, IPv6)
- Packet logging
- Flow rule installation
- Firewall enforcement

---

## 🚀 Features

- ✅ Packet header capture  
- ✅ Protocol identification  
- ✅ Learning switch implementation  
- ✅ Flow rule installation  
- ✅ Firewall (block specific traffic)  
- ✅ Packet logging to file  
- ✅ Log analysis (protocol stats + talker pairs)  

---

## 🌐 Network Topology

```
h1, h2 ---- s1 ---- s2 ---- h3, h4
```

| Host | IP Address |
|------|-----------|
| h1   | 10.0.0.1  |
| h2   | 10.0.0.2  |
| h3   | 10.0.0.3  |
| h4   | 10.0.0.4  |

---

## 📁 Project Structure

```
cn/
├── README.md
├── mininet_topology.py
├── log_analyzer.py
├── requirements.txt
├── screenshots/
├── sample_outputs/
├── report_notes/
└── pox/
    ├── pox.py
    ├── logs/
    └── pox/
        └── misc/
            └── packet_logger.py
```

---

## ⚙️ Setup Instructions

### 1️⃣ Start POX Controller

```bash
cd ~/cn/pox
python3 pox.py log.level --DEBUG openflow.of_01 misc.packet_logger
```

---

### 2️⃣ Start Mininet Topology

Open another terminal:

```bash
cd ~/cn
sudo mn -c
sudo python3 mininet_topology.py
```

---

## 🧪 Test Scenarios

### ✅ Scenario 1: Same Switch Communication
```bash
h1 ping -c 3 h2
```

---

### ✅ Scenario 2: Cross-Switch Communication
```bash
h1 ping -c 3 h3
```

---

### 🚫 Scenario 3: Firewall (Blocked Traffic)
```bash
h1 ping -c 3 h4
```

**Expected:** Request fails (blocked by controller)

---

### 📊 Scenario 4: TCP Traffic
```bash
h2 iperf -s &
h1 iperf -c h2 -t 10
```

---

## 🔍 Flow Table Inspection

Run in a separate terminal:

```bash
sudo ovs-ofctl -O OpenFlow10 dump-flows s1
sudo ovs-ofctl -O OpenFlow10 dump-flows s2
```

Or inside Mininet:

```bash
sh ovs-ofctl -O OpenFlow10 dump-flows s1
sh ovs-ofctl -O OpenFlow10 dump-flows s2
```

---

## 📈 Log Analysis

```bash
cd ~/cn
python3 log_analyzer.py pox/logs/packet_log.txt
```

---

## 📊 Expected Results

- First packet goes to controller → higher latency  
- Flow rules installed → faster forwarding  
- Unknown MAC → FLOOD  
- Known MAC → FORWARD  
- Firewall blocks `10.0.0.1 → 10.0.0.4`  
- Logs show protocol details  

### Analyzer Output Includes:
- Protocol distribution  
- Forwarding actions  
- Top talker pairs  

---

## 📸 Screenshots Included

- Controller startup  
- h1 → h2 ping  
- h1 → h3 ping  
- h1 → h4 blocked  
- TCP iperf test  
- Flow tables (s1 & s2)  
- Analyzer output  

---

## 📚 References

- POX Controller Documentation  
- Mininet Documentation  
- OpenFlow Protocol  

---

## 🏁 Conclusion

This project demonstrates:

- SDN architecture  
- Controller-based packet processing  
- Flow rule optimization  
- Firewall-based security  
- Network traffic analysis  

---

## 👨‍💻 Author

- Omkar
