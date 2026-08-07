#!/usr/bin/env python3
"""
Generate challenge.pcap for W03 cybersecurity course.

Contains three anomalous traffic scenarios mixed with baseline traffic:
  1. DGA / DNS Beaconing: random subdomain DNS queries → NXDOMAIN responses
  2. HTTP credential leak: HTTP POST with plaintext username/password
  3. TLS Downgrade: TLS 1.0 Client Hello (version 0x0301)

Usage: python3 gen_challenge_pcap.py
Output: challenge.pcap (in same directory)
"""

import os, struct, random, string, time
from scapy.all import (
    Ether, IP, TCP, UDP,
    DNS, DNSQR, DNSRR,
    Raw, wrpcap, RandShort
)

# ── helpers ──────────────────────────────────────────────────────────────────
CLIENT_IP   = "10.0.2.15"
GATEWAY_MAC = "52:54:00:12:34:56"
CLIENT_MAC  = "08:00:27:ab:cd:ef"
DNS_SERVER  = "8.8.8.8"
EVIL_DOMAIN = "evil-c2.ru"
HTTP_SERVER = "203.0.113.10"   # TEST-NET-3, documentation range
HTTP_PORT   = 80
TLS_SERVER  = "198.51.100.5"   # TEST-NET-2, documentation range
TLS_PORT    = 443

pkt_list = []
ts_base = 1749470400.0   # 2026-06-09 08:00:00 UTC

def ts(offset):
    return ts_base + offset

def ip_udp_dns(src, dst, sport, dport, dns_layer):
    return Ether(src=CLIENT_MAC, dst=GATEWAY_MAC) / \
           IP(src=src, dst=dst, ttl=64) / \
           UDP(sport=sport, dport=dport) / \
           dns_layer

def ip_tcp(src, dst, sport, dport, flags, seq=1000, ack=0, payload=b""):
    pkt = Ether(src=CLIENT_MAC, dst=GATEWAY_MAC) / \
          IP(src=src, dst=dst, ttl=64) / \
          TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
    if payload:
        pkt = pkt / Raw(load=payload)
    return pkt

# ── Baseline: 5 normal DNS queries ───────────────────────────────────────────
normal_domains = [
    ("www.google.com", "142.250.185.68"),
    ("github.com",     "20.27.177.113"),
]
for i, (domain, ip_ans) in enumerate(normal_domains):
    q  = ip_udp_dns(CLIENT_IP, DNS_SERVER, 50000+i, 53,
                    DNS(id=100+i, rd=1, qd=DNSQR(qname=domain)))
    r  = ip_udp_dns(DNS_SERVER, CLIENT_IP, 53, 50000+i,
                    DNS(id=100+i, qr=1, rd=1, ra=1,
                        qd=DNSQR(qname=domain),
                        an=DNSRR(rrname=domain, type="A", ttl=300, rdata=ip_ans)))
    q.time = ts(i*2)
    r.time = ts(i*2 + 0.05)
    pkt_list += [q, r]

# ── Scenario 1: DGA Beaconing ─────────────────────────────────────────────────
# 20 queries to random-looking subdomains → all NXDOMAIN
# Subdomain looks like base64-encoded data (characteristic of DGA / DNS tunneling)
dga_base_offset = 10.0

def random_subdomain():
    """Generate a DGA-style subdomain: 8-16 hex/base64 chars."""
    chars = string.ascii_lowercase + string.digits
    length = random.randint(8, 16)
    return ''.join(random.choices(chars, k=length))

random.seed(42)  # reproducible
offset = dga_base_offset
for i in range(20):
    subdomain = random_subdomain()
    fqdn = f"{subdomain}.{EVIL_DOMAIN}"
    txid = 200 + i
    if i > 0:
        offset += random.uniform(28, 32)   # ~30 sec beaconing interval (realistic C2), accumulated

    q = ip_udp_dns(CLIENT_IP, DNS_SERVER, 51000+i, 53,
                   DNS(id=txid, rd=1, qd=DNSQR(qname=fqdn)))
    # NXDOMAIN = rcode 3, no answer section
    r = ip_udp_dns(DNS_SERVER, CLIENT_IP, 53, 51000+i,
                   DNS(id=txid, qr=1, rd=1, ra=1, rcode=3,
                       qd=DNSQR(qname=fqdn)))
    q.time = ts(offset)
    r.time = ts(offset + 0.08)
    pkt_list += [q, r]

# ── Scenario 2: HTTP POST with plaintext credentials ─────────────────────────
# Full TCP handshake + HTTP POST + Server 200 OK response
http_offset = 700.0
sport_http = 54321

def make_http_session():
    pkts = []
    seq_c = 1000
    seq_s = 5000
    sport = sport_http

    # SYN
    syn = ip_tcp(CLIENT_IP, HTTP_SERVER, sport, HTTP_PORT, "S", seq=seq_c)
    syn.time = ts(http_offset)
    pkts.append(syn)

    # SYN-ACK
    synack = ip_tcp(HTTP_SERVER, CLIENT_IP, HTTP_PORT, sport, "SA",
                    seq=seq_s, ack=seq_c+1)
    synack.time = ts(http_offset + 0.01)
    pkts.append(synack)

    # ACK
    ack = ip_tcp(CLIENT_IP, HTTP_SERVER, sport, HTTP_PORT, "A",
                 seq=seq_c+1, ack=seq_s+1)
    ack.time = ts(http_offset + 0.02)
    pkts.append(ack)

    # HTTP POST request
    post_body = b"username=admin&password=P%40ssw0rd123&remember=on"
    post_req = (
        b"POST /login HTTP/1.1\r\n"
        b"Host: internal-portal.corp\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(post_body)).encode() + b"\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        b"Connection: keep-alive\r\n"
        b"\r\n" + post_body
    )
    post_pkt = ip_tcp(CLIENT_IP, HTTP_SERVER, sport, HTTP_PORT, "PA",
                      seq=seq_c+1, ack=seq_s+1, payload=post_req)
    post_pkt.time = ts(http_offset + 0.05)
    pkts.append(post_pkt)
    seq_c += len(post_req)

    # Server ACK
    ack_s = ip_tcp(HTTP_SERVER, CLIENT_IP, HTTP_PORT, sport, "A",
                   seq=seq_s+1, ack=seq_c+1)
    ack_s.time = ts(http_offset + 0.06)
    pkts.append(ack_s)

    # Server HTTP 200 response
    resp_body = b"<html><body>Login successful. Redirecting...</body></html>"
    http_resp = (
        b"HTTP/1.1 302 Found\r\n"
        b"Location: /dashboard\r\n"
        b"Content-Type: text/html\r\n"
        b"Content-Length: " + str(len(resp_body)).encode() + b"\r\n"
        b"Set-Cookie: session=abc123xyz; HttpOnly\r\n"
        b"\r\n" + resp_body
    )
    resp_pkt = ip_tcp(HTTP_SERVER, CLIENT_IP, HTTP_PORT, sport, "PA",
                      seq=seq_s+1, ack=seq_c+1, payload=http_resp)
    resp_pkt.time = ts(http_offset + 0.08)
    pkts.append(resp_pkt)
    seq_s += len(http_resp)

    # Client ACK + FIN
    fin = ip_tcp(CLIENT_IP, HTTP_SERVER, sport, HTTP_PORT, "FA",
                 seq=seq_c+1, ack=seq_s+1)
    fin.time = ts(http_offset + 0.10)
    pkts.append(fin)

    return pkts

pkt_list += make_http_session()

# ── Scenario 3: TLS 1.0 Downgrade ────────────────────────────────────────────
# Build a TLS 1.0 Client Hello manually using raw bytes
# TLS record:  type=0x16 (Handshake), version=0x0301 (TLS 1.0), length=...
# Handshake:   type=0x01 (ClientHello), length=...
#   ClientHello: legacy_version=0x0301, random(32), session_id=0, ciphers, extensions

tls_offset = 800.0
sport_tls = 55555

def build_tls10_client_hello():
    """Build a minimal TLS 1.0 ClientHello."""
    # Random (32 bytes)
    client_random = bytes(range(32))
    # Cipher suites: TLS_RSA_WITH_AES_128_CBC_SHA (0x002F), TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000A)
    cipher_suites = b"\x00\x02\x00\x2F"  # length=2, one suite
    # Compression: null
    compression = b"\x01\x00"
    # No extensions for TLS 1.0 downgrade demo (keeps it minimal)

    # ClientHello body
    ch_body = (
        b"\x03\x01"          # legacy_version = TLS 1.0
        + client_random
        + b"\x00"            # session_id length = 0
        + cipher_suites
        + compression
    )

    # Handshake header: type=1 (ClientHello), length(3 bytes)
    ch_len = len(ch_body)
    handshake = b"\x01" + struct.pack(">I", ch_len)[1:]  + ch_body

    # TLS Record header: content_type=0x16 (Handshake), version=0x0301 (TLS 1.0), length
    record_len = len(handshake)
    tls_record = b"\x16\x03\x01" + struct.pack(">H", record_len) + handshake

    return tls_record

def make_tls10_session():
    pkts = []
    seq_c = 2000
    seq_s = 7000
    sport = sport_tls

    # SYN
    syn = ip_tcp(CLIENT_IP, TLS_SERVER, sport, TLS_PORT, "S", seq=seq_c)
    syn.time = ts(tls_offset)
    pkts.append(syn)

    # SYN-ACK
    synack = ip_tcp(TLS_SERVER, CLIENT_IP, TLS_PORT, sport, "SA",
                    seq=seq_s, ack=seq_c+1)
    synack.time = ts(tls_offset + 0.01)
    pkts.append(synack)

    # ACK
    ack = ip_tcp(CLIENT_IP, TLS_SERVER, sport, TLS_PORT, "A",
                 seq=seq_c+1, ack=seq_s+1)
    ack.time = ts(tls_offset + 0.02)
    pkts.append(ack)

    # TLS 1.0 ClientHello
    ch_data = build_tls10_client_hello()
    ch_pkt = ip_tcp(CLIENT_IP, TLS_SERVER, sport, TLS_PORT, "PA",
                    seq=seq_c+1, ack=seq_s+1, payload=ch_data)
    ch_pkt.time = ts(tls_offset + 0.05)
    pkts.append(ch_pkt)
    seq_c += len(ch_data)

    # Server rejects (TLS Alert: 0x15 = Alert, level=2 fatal, desc=70 = protocol_version)
    alert_data = b"\x15\x03\x01\x00\x02\x02\x46"  # fatal, protocol_version
    alert_pkt = ip_tcp(TLS_SERVER, CLIENT_IP, TLS_PORT, sport, "PA",
                       seq=seq_s+1, ack=seq_c+1, payload=alert_data)
    alert_pkt.time = ts(tls_offset + 0.08)
    pkts.append(alert_pkt)

    # FIN
    fin = ip_tcp(CLIENT_IP, TLS_SERVER, sport, TLS_PORT, "FA",
                 seq=seq_c+1, ack=seq_s+1+len(alert_data))
    fin.time = ts(tls_offset + 0.10)
    pkts.append(fin)

    return pkts

pkt_list += make_tls10_session()

# ── Sort by timestamp and write ───────────────────────────────────────────────
pkt_list.sort(key=lambda p: float(p.time))
outfile = os.path.join(os.path.dirname(os.path.abspath(__file__)), "challenge.pcap")
wrpcap(outfile, pkt_list)
print(f"Written {len(pkt_list)} packets to {outfile}")

# ── Quick verification ────────────────────────────────────────────────────────
from scapy.all import rdpcap
pkts = rdpcap(outfile)
print(f"\nVerification ({len(pkts)} packets):")

dns_queries = [p for p in pkts if p.haslayer(DNS) and p[DNS].qr == 0]
nxdomain    = [p for p in pkts if p.haslayer(DNS) and p[DNS].qr == 1 and p[DNS].rcode == 3]
http_post   = [p for p in pkts if p.haslayer(Raw) and b"POST /login" in bytes(p[Raw])]
tls10_ch    = [p for p in pkts if p.haslayer(Raw) and bytes(p[Raw])[:3] == b"\x16\x03\x01"
               and bytes(p[Raw])[5:6] == b"\x01"]  # Handshake ClientHello

print(f"  DNS queries:              {len(dns_queries)}")
print(f"  DNS NXDOMAIN responses:   {len(nxdomain)}")
print(f"  HTTP POST /login:         {len(http_post)}")
print(f"  TLS 1.0 ClientHello:      {len(tls10_ch)}")

if http_post:
    raw = bytes(http_post[0][Raw])
    cred_idx = raw.find(b"username=")
    if cred_idx >= 0:
        print(f"  HTTP POST body preview:   {raw[cred_idx:cred_idx+50]}")
