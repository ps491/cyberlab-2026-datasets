#!/usr/bin/env python3
"""Week07 — SQLi Attack Log Generator"""
import random, os
from datetime import datetime, timedelta

OUTPUT = "week07_sqli/dataset/access.log"

NORMAL_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
]
ATTACKER_IP  = "10.10.10.50"
ATTACKER_UA  = "python-requests/2.31.0"

NORMAL_PATHS = ["/", "/index.php", "/about.php", "/products.php",
                "/products.php?id=1", "/products.php?id=2",
                "/products.php?id=3", "/login.php",
                "/css/style.css", "/js/app.js", "/images/logo.png",
                "/contact.php", "/search.php?q=laptop"]

SQLI_PAYLOADS = [
    "/products.php?id=1'",
    "/products.php?id=1 OR 1=1--",
    "/products.php?id=1' OR '1'='1",
    "/products.php?id=1 UNION SELECT NULL--",
    "/products.php?id=1 UNION SELECT NULL,NULL--",
    "/products.php?id=1 UNION SELECT NULL,NULL,NULL--",
    "/products.php?id=1 UNION SELECT 1,database(),3--",
    "/products.php?id=1 UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--",
    "/products.php?id=1 UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'--",
    "/products.php?id=1 UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users--",
    "/login.php",  # attacker trying login after dump
]

def apache_line(ts, ip, method, path, status, size, referer="-", ua=None):
    if ua is None:
        ua = random.choice(NORMAL_AGENTS)
    t = ts.strftime("%d/%b/%Y:%H:%M:%S +0800")
    return f'{ip} - - [{t}] "{method} {path} HTTP/1.1" {status} {size} "{referer}" "{ua}"'

def generate():
    lines = []
    base = datetime(2026, 6, 7, 8, 30, 0)

    # Phase 1: Normal traffic 08:30–10:29 (80 requests)
    normal_ips = ["192.168.1.10", "192.168.1.11", "192.168.1.12",
                  "192.168.1.20", "203.0.113.5"]
    ts = base
    for _ in range(80):
        ip = random.choice(normal_ips)
        path = random.choice(NORMAL_PATHS)
        status = 200 if not path.endswith(('.css','.js','.png')) else 200
        size = random.randint(500, 8000)
        lines.append(apache_line(ts, ip, "GET", path, status, size))
        ts += timedelta(seconds=random.randint(15, 90))

    # Phase 2: Attacker reconnaissance 10:30 (5 normal requests)
    ts = base.replace(hour=10, minute=30)
    for path in ["/", "/robots.txt", "/sitemap.xml", "/login.php", "/products.php?id=1"]:
        lines.append(apache_line(ts, ATTACKER_IP, "GET", path, 200, random.randint(800,3000), ua=ATTACKER_UA))
        ts += timedelta(seconds=random.randint(3, 8))

    # Phase 3: SQLi attempts 10:35–10:42
    ts = base.replace(hour=10, minute=35)
    statuses = [200, 500, 200, 500, 500, 500, 200, 200, 200, 200, 302]
    for i, payload in enumerate(SQLI_PAYLOADS):
        st = statuses[i] if i < len(statuses) else 200
        size = random.randint(1200, 4500) if st == 200 else random.randint(300, 600)
        lines.append(apache_line(ts, ATTACKER_IP, "GET", payload, st, size, ua=ATTACKER_UA))
        ts += timedelta(seconds=random.randint(4, 12))

    # Phase 4: Resume normal traffic after attack
    for _ in range(20):
        ip = random.choice(normal_ips)
        path = random.choice(NORMAL_PATHS)
        lines.append(apache_line(ts, ip, "GET", path, 200, random.randint(500,6000)))
        ts += timedelta(seconds=random.randint(20, 120))

    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Generated {len(lines)} lines → {OUTPUT}")

generate()
