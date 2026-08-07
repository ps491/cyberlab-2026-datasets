#!/usr/bin/env python3
"""Week14 — SOC Alerts Generator (50 alerts, TP/FP mix)"""
import csv, os, random
from datetime import datetime, timedelta

BASE_DIR = "week14_soc/dataset"
os.makedirs(BASE_DIR, exist_ok=True)

random.seed(42)

base_ts = datetime(2026, 6, 7, 0, 0, 0)

# (rule_name, category, severity, expected_verdict, src_ip, dst_ip, dst_port, description)
ALERT_TEMPLATES = [
    # True Positives (TP) — Real threats
    ("SQL_INJECTION_DETECTED",    "Web Attack",   "High",   "TP", "185.220.101.42", "10.0.0.100", 80,   "SQL injection pattern in GET parameter"),
    ("SQL_INJECTION_DETECTED",    "Web Attack",   "High",   "TP", "103.21.244.0",   "10.0.0.100", 80,   "UNION SELECT payload detected in GET parameter /search"),
    ("BRUTE_FORCE_SSH",           "Auth Attack",  "Medium", "TP", "45.152.66.23",   "10.0.0.10",  22,   "300 failed SSH login attempts in 5 min"),
    ("BRUTE_FORCE_LOGIN",         "Auth Attack",  "High",   "TP", "185.234.219.42", "10.0.0.100", 80,   "99 failed web login attempts"),
    ("MALWARE_C2_BEACON",         "Malware",      "Critical","TP","10.0.0.20",      "198.51.100.77",443, "Periodic 30s beacon to known C2 IP"),
    ("MALWARE_C2_BEACON",         "Malware",      "Critical","TP","10.0.0.20",      "198.51.100.77",443, "C2 communication pattern (TLS)"),
    ("DATA_EXFILTRATION",         "Data Loss",    "Critical","TP","10.0.0.20",      "198.51.100.77",443, "Outbound transfer >10MB to external C2"),
    ("WEBSHELL_ACCESS",           "Intrusion",    "Critical","TP","185.220.101.42", "10.0.0.100", 80,   "GET /uploads/shell.php?cmd= pattern"),
    ("DIRECTORY_TRAVERSAL",       "Web Attack",   "High",   "TP", "91.108.56.22",   "10.0.0.100", 80,   "Path traversal ../../etc/passwd"),
    ("XSS_REFLECTED",             "Web Attack",   "Medium", "TP", "203.0.113.88",   "10.0.0.100", 80,   "Reflected XSS payload <script>alert(1)"),
    ("PORT_SCAN_EXTERNAL",        "Recon",        "Medium", "TP", "45.76.211.31",   "10.0.0.0",   0,    "SYN scan against /24 subnet from Internet"),
    ("SUSPICIOUS_DOWNLOAD",       "Malware",      "High",   "TP", "10.0.0.30",      "185.220.101.99",80, "EXE download from suspicious IP"),
    ("LATERAL_MOVEMENT_SMB",      "Intrusion",    "High",   "TP", "10.0.0.20",      "10.0.0.50",  445,  "Unusual SMB admin share access"),
    ("PRIVILEGE_ESCALATION",      "Intrusion",    "Critical","TP","10.0.0.20",      "10.0.0.100", 0,    "Sudo command executed by non-admin user"),
    ("PHISHING_URL_CLICK",        "Phishing",     "High",   "TP", "10.0.0.45",      "corp-portal-update.xyz",443,"User clicked link to corp-portal-update.xyz from email client"),
    # False Positives (FP) — Legitimate traffic flagged
    ("SQL_INJECTION_DETECTED",    "Web Attack",   "High",   "FP", "10.0.0.5",       "10.0.0.100", 80,   "Security scanner (Nessus) internal scan authorized"),
    ("BRUTE_FORCE_SSH",           "Auth Attack",  "Medium", "FP", "10.0.0.200",     "10.0.0.10",  22,   "Automated deployment script (Ansible)"),
    ("BRUTE_FORCE_LOGIN",         "Auth Attack",  "High",   "FP", "10.0.0.1",       "10.0.0.100", 80,   "Load balancer health check"),
    ("DATA_EXFILTRATION",         "Data Loss",    "Critical","FP","10.0.0.50",      "52.84.125.30",443, "Scheduled cloud backup to AWS S3"),
    ("DATA_EXFILTRATION",         "Data Loss",    "Critical","FP","10.0.0.10",      "52.216.165.48",443, "Scheduled cloud backup to AWS S3, 4.2GB transferred"),
    ("PORT_SCAN_INTERNAL",        "Recon",        "Medium", "FP", "10.0.0.200",     "10.0.0.0",   0,    "IT asset inventory scan (weekly)"),
    ("PORT_SCAN_INTERNAL",        "Recon",        "Medium", "FP", "10.0.0.201",     "10.0.0.0",   0,    "IT vulnerability scan (Nessus)"),
    ("UNUSUAL_OUTBOUND",          "Data Loss",    "Medium", "FP", "10.0.0.40",      "8.8.8.8",    53,   "High DNS query volume — legitimate CDN"),
    ("MALWARE_C2_BEACON",         "Malware",      "Critical","FP","10.0.0.60",      "13.107.42.14",443, "Periodic connection to Microsoft Teams CDN (Teams heartbeat)"),
    ("BRUTE_FORCE_SSH",           "Auth Attack",  "Medium", "FP", "10.0.0.202",     "10.0.0.10",  22,   "CI/CD pipeline deployment (Jenkins)"),
    ("SQL_INJECTION_DETECTED",    "Web Attack",   "High",   "FP", "10.0.0.5",       "10.0.0.100", 80,   "Pentest team authorized scan"),
    ("SUSPICIOUS_DOWNLOAD",       "Malware",      "Medium", "FP", "10.0.0.67",      "download.microsoft.com",443,"Windows Update legitimate download (KB5034441), 512MB"),
    ("DIRECTORY_TRAVERSAL",       "Web Attack",   "High",   "FP", "10.0.0.5",       "10.0.0.100", 80,   "Web app scanner (DAST authorized)"),
    ("UNUSUAL_OUTBOUND",          "Data Loss",    "Medium", "FP", "10.0.0.45",      "34.117.59.81",443, "Google Workspace sync"),
    ("PORT_SCAN_INTERNAL",        "Recon",        "Medium", "FP", "10.0.0.203",     "10.0.0.0",   0,    "Network monitoring agent (Zabbix)"),
]

rows = [["alert_id","timestamp","src_ip","dst_ip","dst_port","rule_name",
         "severity","category","description","expected_verdict"]]

random.shuffle(ALERT_TEMPLATES)
ts = base_ts
for i, (rule, cat, sev, verdict, src, dst, port, desc) in enumerate(ALERT_TEMPLATES, 1):
    ts += timedelta(minutes=random.randint(10, 45))
    rows.append([
        f"ALT-{i:04d}",
        ts.strftime("%Y-%m-%d %H:%M:%S"),
        src, dst, port,
        rule, sev, cat, desc,
        verdict
    ])

# Pad to 50 with random benign/flagged items
extra_fps = [
    ("UNUSUAL_TRAFFIC_VOLUME","Network","Low","FP","10.0.0.70","10.0.0.100",80,"High HTTP traffic — marketing campaign"),
    ("AUTH_FAILURE_MULTIPLE","Auth Attack","Low","FP","10.0.0.80","10.0.0.100",443,"Password manager auto-fill error"),
    ("UNUSUAL_OUTBOUND","Data Loss","Medium","FP","10.0.0.55","1.1.1.1",53,"Cloudflare DNS — legitimate"),
    ("SCAN_DETECTED","Recon","Low","FP","10.0.0.204","10.0.0.0",0,"SNMP community scan (network team)"),
    ("BRUTE_FORCE_LOGIN","Auth Attack","Medium","FP","10.0.0.90","10.0.0.100",80,"SharePoint crawler (internal)"),
    ("UNUSUAL_OUTBOUND","Data Loss","Medium","FP","10.0.0.95","api.slack.com",443,"Slack webhook — DevOps notification"),
    ("SQL_INJECTION_DETECTED","Web Attack","High","FP","10.0.0.5","10.0.0.100",80,"SAST scanner false positive"),
    ("AUTH_FAILURE_MULTIPLE","Auth Attack","Low","FP","10.0.0.100","10.0.0.200",389,"LDAP bind retry after config change"),
    ("UNUSUAL_TRAFFIC_VOLUME","Network","Low","TP","10.0.0.22","198.51.100.77",443,"Sustained high-volume to C2"),
    ("SUSPICIOUS_PROCESS","Endpoint","High","TP","10.0.0.20","",0,"cmd.exe spawned by apache2"),
    ("WEBSHELL_ACCESS","Intrusion","Critical","TP","45.155.205.12","10.0.0.100",80,"GET /tmp/cmd.php?c=whoami"),
    ("LATERAL_MOVEMENT_SMB","Intrusion","High","TP","10.0.0.22","10.0.0.55",445,"Admin share mapping from compromised host"),
    ("XSS_STORED","Web Attack","High","TP","203.0.113.99","10.0.0.100",80,"Stored XSS in comment field"),
    ("DATA_EXFILTRATION","Data Loss","Critical","TP","10.0.0.22","185.234.219.42",443,"Large encrypted transfer to IOC IP, 4.8GB"),
    ("PHISHING_URL_CLICK","Phishing","High","TP","10.0.0.18","malware-update.xyz",80,"Known malware distribution domain"),
    ("PORT_SCAN_EXTERNAL","Recon","Medium","TP","91.108.56.33","10.0.0.0",0,"Shodan-like scan from TOR exit node"),
    ("BRUTE_FORCE_SSH","Auth Attack","Medium","TP","196.203.14.55","10.0.0.12",22,"External SSH brute force"),
    ("SQL_INJECTION_DETECTED","Web Attack","High","TP","103.21.244.12","10.0.0.100",80,"Blind SQLi time-based payload"),
    ("MALWARE_C2_BEACON","Malware","Critical","TP","10.0.0.33","198.51.100.77",443,"New host beaconing same C2"),
    ("PRIVILEGE_ESCALATION","Intrusion","Critical","TP","10.0.0.22","",0,"Cron job modification by www-data"),
]

for i, (rule, cat, sev, verdict, src, dst, port, desc) in enumerate(extra_fps, len(ALERT_TEMPLATES)+1):
    if len(rows) >= 51:
        break
    ts += timedelta(minutes=random.randint(5, 30))
    rows.append([f"ALT-{i:04d}", ts.strftime("%Y-%m-%d %H:%M:%S"),
                 src, dst, port, rule, sev, cat, desc, verdict])

# ── §14.10 案例分析因果順序修正 ─────────────────────────────────────────────
# book/ch14/ch14-10.md 的 TechCorp 攻擊鏈敘事要求時間順序為：
#   SQLi(0028) < Webshell(0025) < 命令執行(0040) < C2(0007) < 橫向移動(0008) < 提權(0018) < 外洩(0044)
# 原始隨機排列的時間戳不滿足此因果順序（部分早期步驟時間反而晚於後期步驟）。
# 直接把這 7 筆的既有時間戳依因果順序重新指派（同一組時間值互相交換，
# 不引入新時間、不影響其他 43 筆），使敘事與資料一致。
CAUSAL_ORDER = ["ALT-0028", "ALT-0025", "ALT-0040", "ALT-0007", "ALT-0008", "ALT-0018", "ALT-0044"]
by_id = {r[0]: r for r in rows[1:]}
slot_timestamps = sorted(by_id[aid][1] for aid in CAUSAL_ORDER)
for aid, ts_value in zip(CAUSAL_ORDER, slot_timestamps):
    by_id[aid][1] = ts_value

with open(f"{BASE_DIR}/alerts.csv", "w", newline="", encoding="utf-8-sig") as f:
    csv.writer(f).writerows(rows)

tp = sum(1 for r in rows[1:] if r[-1]=="TP")
fp = sum(1 for r in rows[1:] if r[-1]=="FP")
print(f"alerts.csv: {len(rows)-1} alerts — TP={tp}, FP={fp}")
