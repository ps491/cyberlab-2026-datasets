#!/usr/bin/env python3
"""Week09 — Password Hash Generator"""
import hashlib, os

OUTPUT = "week09_password/dataset/hashes.txt"

# 密碼清單：弱密碼（可被 John 破解）+ 強密碼（無法輕易破解）
PASSWORDS = [
    ("admin",    "password123"),
    ("user1",    "123456"),
    ("alice",    "letmein"),
    ("bob",      "qwerty"),
    ("charlie",  "iloveyou"),
    ("dave",     "sunshine"),
    ("eve",      "monkey"),
    ("frank",    "dragon"),
    # 強密碼（不在 rockyou.txt 裡）
    ("svc_acct", "X9#kP2$mLq7@nR4"),
    ("backup",   "Tr0ub4dor&3"),
]

def md5(s):    return hashlib.md5(s.encode()).hexdigest()
def sha1(s):   return hashlib.sha1(s.encode()).hexdigest()
def sha256(s): return hashlib.sha256(s.encode()).hexdigest()

lines = ["# Week09 Password Cracking Lab — hashes.txt",
         "# Format: username:hash_type:hash",
         "# Crack with: john --format=raw-md5 hashes_md5.txt",
         ""]

# MD5 section
lines.append("# === MD5 Hashes ===")
with open("week09_password/dataset/hashes_md5.txt", "w") as f_md5:
    for user, pw in PASSWORDS:
        h = md5(pw)
        lines.append(f"{user}:MD5:{h}")
        f_md5.write(f"{user}:{h}\n")

lines.append("")
# SHA1 section
lines.append("# === SHA1 Hashes ===")
with open("week09_password/dataset/hashes_sha1.txt", "w") as f_sha1:
    for user, pw in PASSWORDS:
        h = sha1(pw)
        lines.append(f"{user}:SHA1:{h}")
        f_sha1.write(f"{user}:{h}\n")

lines.append("")
lines.append("# === Notes ===")
lines.append("# MD5 format for John: john --format=raw-md5 hashes_md5.txt")
lines.append("# SHA1 format for John: john --format=raw-sha1 hashes_sha1.txt")
lines.append("# Wordlist: john --wordlist=/usr/share/wordlists/rockyou.txt")
lines.append("")
lines.append("# Challenge questions:")
lines.append("# 1. Which accounts use weak passwords?")
lines.append("# 2. Which accounts are safe from dictionary attacks?")
lines.append("# 3. What password policy would prevent these vulnerabilities?")

os.makedirs("week09_password/dataset", exist_ok=True)
with open(OUTPUT, "w") as f:
    f.write("\n".join(lines) + "\n")
print(f"Generated hashes.txt, hashes_md5.txt, hashes_sha1.txt")

