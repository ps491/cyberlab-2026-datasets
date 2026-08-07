#!/usr/bin/env python3
"""
Week01 — Synthetic SSH auth.log Generator

情境設計（雲端版）：
  這份 Log 代表「一台公司內部伺服器 web-prod-01 匯出的 auth.log」，交給學生分析。
  它刻意不是學生自己那台機器的 Log——雲端環境下每位學生的主機名稱與 IP 都不同，
  把分析對象設計成外部證據檔，情境才成立，也更貼近真實 IR 工作（你分析的永遠
  是別人的機器）。

  - 攻擊者 10.0.2.2：487 次失敗，集中於 10:21–10:22（暴力破解高峰），
    最終於 10:23:44 以 backup 帳號登入成功（§1.7 comm -12 的教學案例）
  - 攻擊者 10.0.2.3：93 次失敗，對 admin 帳號進行字典攻擊
  - 散佈來源 192.168.1.100：7 次失敗（偵察行為）
  - 正常使用者 sysadmin 從 10.10.20.35（管理網段工作站）登入

  攻擊來源皆為內網位址，情境上代表「已被入侵的內部主機正在橫向移動」。

auth.log 欄位對照（§1.6 awk 取欄位說明）：
  $1  $2        $3        $4          $5           $6      $7        $8  $9       $10  $11       $12   $13    $14
  Jun 25        10:21:03  web-prod-01 sshd[12301]: Failed  password  for root     from 10.0.2.2  port  50001  ssh2

輸出：week01_linux/dataset/auth.log
"""

import random
import os
from datetime import datetime, timedelta

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "auth.log")

# 固定亂數種子：讓每位學生在自己的 Codespace 產生的 auth.log 完全一致
# （PID、來源埠、時間抖動都相同），教師才能公布唯一的參考輸出供對答案。
random.seed(20260625)

HOSTNAME = "web-prod-01"
MONTH = "Jun"
DAY = "25"

ATTACKER1 = "10.0.2.2"
ATTACKER2 = "10.0.2.3"
SCANNER   = "192.168.1.100"
LEGIT_IP  = "10.10.20.35"
LEGIT_USER = "sysadmin"

# 帳號清單：attacker1 使用（§1.6 Step 3 教學：帳號清單攻擊）
ACCOUNTS_A1 = ["root"] * 6 + ["admin"] * 2 + ["backup"] * 1 + ["ubuntu"] * 1
ACCOUNTS_A2 = ["admin"]
PORT_COUNTER = [50000]

def next_port():
    PORT_COUNTER[0] += 1
    return PORT_COUNTER[0]

def pid():
    return random.randint(12000, 13500)

def fmt_time(dt):
    return dt.strftime("%H:%M:%S")

def failed_line(dt, ip, user):
    return (f"{MONTH} {DAY} {fmt_time(dt)} {HOSTNAME} sshd[{pid()}]: "
            f"Failed password for {user} from {ip} port {next_port()} ssh2")

def accepted_line(dt, ip, user):
    return (f"{MONTH} {DAY} {fmt_time(dt)} {HOSTNAME} sshd[{pid()}]: "
            f"Accepted password for {user} from {ip} port {next_port()} ssh2")

def disconnected_line(dt, ip, user):
    return (f"{MONTH} {DAY} {fmt_time(dt)} {HOSTNAME} sshd[{pid()}]: "
            f"Disconnected from user {user} {ip} port {next_port()}")

lines = []  # (datetime, text)

# ── 正常登入：09:00–09:30，sysadmin 從管理網段 10.10.20.35 ─────────────────
t = datetime(2026, 6, 25, 9, 0, 12)
lines.append((t, accepted_line(t, LEGIT_IP, LEGIT_USER)))
t += timedelta(seconds=random.randint(1800, 2400))
lines.append((t, disconnected_line(t, LEGIT_IP, LEGIT_USER)))

# ── 散佈來源 192.168.1.100：7 次，09:45–10:15 ─────────────────────────────
scanner_times = sorted([
    datetime(2026, 6, 25, 9, 45, 0) + timedelta(minutes=random.randint(0, 30), seconds=random.randint(0, 59))
    for _ in range(7)
])
for t in scanner_times:
    lines.append((t, failed_line(t, SCANNER, random.choice(["root", "admin"]))))

# ── attacker2（10.0.2.3）：93 次，10:18–10:35 ─────────────────────────────
t = datetime(2026, 6, 25, 10, 18, 3)
for i in range(93):
    t += timedelta(seconds=random.uniform(0.8, 1.5))
    lines.append((t, failed_line(t, ATTACKER2, random.choice(ACCOUNTS_A2))))

# ── attacker1（10.0.2.2）：487 次 ─────────────────────────────────────────
# 10:20：暖機期，15 次
t = datetime(2026, 6, 25, 10, 20, 1)
for _ in range(15):
    t += timedelta(seconds=random.uniform(1.2, 2.5))
    lines.append((t, failed_line(t, ATTACKER1, random.choice(ACCOUNTS_A1))))

# 10:21：高峰，200 次（§1.6 fig-05 要看到此分鐘突增）
t = datetime(2026, 6, 25, 10, 21, 0)
for _ in range(200):
    t += timedelta(seconds=random.uniform(0.25, 0.35))
    lines.append((t, failed_line(t, ATTACKER1, random.choice(ACCOUNTS_A1))))

# 10:22：持續，190 次
t = datetime(2026, 6, 25, 10, 22, 0)
for _ in range(190):
    t += timedelta(seconds=random.uniform(0.25, 0.35))
    lines.append((t, failed_line(t, ATTACKER1, random.choice(ACCOUNTS_A1))))

# 10:23：收尾，80 次 → 然後成功登入（§1.6 comm -12 的關鍵案例）
t = datetime(2026, 6, 25, 10, 23, 0)
for _ in range(80):
    t += timedelta(seconds=random.uniform(0.3, 0.5))
    lines.append((t, failed_line(t, ATTACKER1, random.choice(ACCOUNTS_A1))))

# 10:23:44 — 暴力破解成功：backup 帳號（§1.6 Step 4 與案例分析的核心）
success_t = datetime(2026, 6, 25, 10, 23, 44)
lines.append((success_t, accepted_line(success_t, ATTACKER1, "backup")))

# 10:24–10:25：成功後繼續少量探測（2 次，模擬確認存取）
t = datetime(2026, 6, 25, 10, 24, 5)
lines.append((t, failed_line(t, ATTACKER1, "ubuntu")))
t += timedelta(seconds=3)
lines.append((t, failed_line(t, ATTACKER1, "ubuntu")))

# ── 合計驗證（開發期間用，產出時不印）─────────────────────────────────────
a1_fail = sum(1 for _, l in lines if ATTACKER1 in l and "Failed" in l)
a2_fail = sum(1 for _, l in lines if ATTACKER2 in l and "Failed" in l)
sc_fail  = sum(1 for _, l in lines if SCANNER  in l and "Failed" in l)
assert a1_fail == 487, f"attacker1 failures = {a1_fail}, expected 487"
assert a2_fail == 93,  f"attacker2 failures = {a2_fail}, expected 93"
assert sc_fail == 7,   f"scanner  failures = {sc_fail}, expected 7"

# ── 排序並寫出 ────────────────────────────────────────────────────────────
lines.sort(key=lambda x: x[0])
output = "\n".join(text for _, text in lines) + "\n"

os.makedirs(os.path.dirname(OUTPUT_PATH) if os.path.dirname(OUTPUT_PATH) else ".", exist_ok=True)
with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    f.write(output)

total = len(lines)
print(f"Generated: {OUTPUT_PATH} ({total} lines) — "
      f"A1={a1_fail} A2={a2_fail} Scanner={sc_fail} "
      f"Success=1 (backup@10:23:44)")
