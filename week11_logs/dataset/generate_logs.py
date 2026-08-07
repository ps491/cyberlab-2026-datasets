#!/usr/bin/env python3
"""Week11 — Apache Log Generator (3 scenarios)"""
import random, os
from datetime import datetime, timedelta

BASE_DIR = "week11_logs/dataset"
os.makedirs(BASE_DIR, exist_ok=True)

NORMAL_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
]

def line(ts, ip, method, path, status, size, ua=None, referer="-"):
    ua = ua or random.choice(NORMAL_UAS)
    t = ts.strftime("%d/%b/%Y:%H:%M:%S +0800")
    return f'{ip} - - [{t}] "{method} {path} HTTP/1.1" {status} {size} "{referer}" "{ua}"'

# ─── Case01: SQL Injection ───────────────────────────────────────────────────
def case01_sqli():
    ATTACKER = "192.168.1.150"
    UA = "sqlmap/1.7.8#stable (https://sqlmap.org)"
    ts = datetime(2026, 6, 5, 14, 20, 0)
    rows = []
    normal_ips = ["10.0.0.5", "10.0.0.6", "10.0.0.7"]

    # Normal background traffic
    for _ in range(15):
        rows.append(line(ts, random.choice(normal_ips), "GET",
                         random.choice(["/", "/products", "/about"]),
                         200, random.randint(800, 4000)))
        ts += timedelta(seconds=random.randint(20, 60))

    # Attacker starts
    ts = datetime(2026, 6, 5, 14, 45, 0)
    sqli_paths = [
        "/store/product.php?id=1",
        "/store/product.php?id=1'",
        "/store/product.php?id=1 AND 1=1--",
        "/store/product.php?id=1 AND 1=2--",
        "/store/product.php?id=1 ORDER BY 1--",
        "/store/product.php?id=1 ORDER BY 2--",
        "/store/product.php?id=1 ORDER BY 3--",
        "/store/product.php?id=1 ORDER BY 4--",
        "/store/product.php?id=1 UNION SELECT NULL,NULL,NULL--",
        "/store/product.php?id=1 UNION SELECT 1,database(),3--",
        "/store/product.php?id=1 UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--",
        "/store/product.php?id=1 UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name=0x7573657273--",
        "/store/product.php?id=1 UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users--",
    ]
    statuses = [200,500,200,200,200,200,200,500,200,200,200,200,200]
    for i, p in enumerate(sqli_paths):
        st = statuses[i]
        rows.append(line(ts, ATTACKER, "GET", p, st,
                         random.randint(1500,5000) if st==200 else 312, ua=UA))
        ts += timedelta(seconds=random.randint(3, 8))

    with open(f"{BASE_DIR}/case01_sqli.log", "w") as f:
        f.write("\n".join(rows) + "\n")
    print(f"case01_sqli.log: {len(rows)} lines, attacker={ATTACKER}")

# ─── Case02: Directory Scan ──────────────────────────────────────────────────
def case02_scan():
    ATTACKER = "10.0.0.30"
    UA = "gobuster/3.6"
    ts = datetime(2026, 6, 6, 9, 15, 0)
    rows = []
    paths_200 = ["/admin", "/backup", "/config", "/uploads", "/api", "/.git"]
    all_paths = (paths_200 +
                 [f"/dir{i}" for i in range(1, 50)] +
                 ["/wp-admin", "/phpmyadmin", "/.env", "/robots.txt",
                  "/sitemap.xml", "/login", "/dashboard", "/panel"])
    random.shuffle(all_paths)

    for p in all_paths:
        st = 200 if p in paths_200 else (301 if p in ["/admin","/api"] else 404)
        size = random.randint(800,3000) if st==200 else random.randint(150,300)
        rows.append(line(ts, ATTACKER, "GET", p, st, size, ua=UA))
        ts += timedelta(milliseconds=random.randint(100, 400))

    with open(f"{BASE_DIR}/case02_scan.log", "w") as f:
        f.write("\n".join(rows) + "\n")
    print(f"case02_scan.log: {len(rows)} lines, attacker={ATTACKER}")

# ─── Case03: Brute Force ─────────────────────────────────────────────────────
def case03_bruteforce():
    ATTACKER = "185.234.219.42"
    UA = "Hydra/9.4"
    ts = datetime(2026, 6, 7, 3, 22, 0)
    rows = []
    passwords = (["admin","123456","password","letmein","qwerty","abc123",
                  "monkey","dragon","baseball","iloveyou","master","sunshine",
                  "ashley","bailey","passw0rd","shadow","123123","654321",
                  "superman","michael"] +
                 [f"pass{i}" for i in range(1, 81)])

    # 99 failed attempts
    for pw in passwords[:99]:
        rows.append(line(ts, ATTACKER, "POST",
                         f"/admin/login.php", 401, 287, ua=UA))
        ts += timedelta(seconds=random.uniform(0.8, 2.5))

    # Success on attempt 100
    rows.append(line(ts, ATTACKER, "POST", "/admin/login.php", 302, 0, ua=UA))
    ts += timedelta(seconds=1)
    rows.append(line(ts, ATTACKER, "GET", "/admin/dashboard", 200, 8432, ua=UA))

    with open(f"{BASE_DIR}/case03_bruteforce.log", "w") as f:
        f.write("\n".join(rows) + "\n")
    print(f"case03_bruteforce.log: {len(rows)} lines, attacker={ATTACKER}")

case01_sqli()
case02_scan()
case03_bruteforce()
