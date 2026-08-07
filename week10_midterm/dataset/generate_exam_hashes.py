#!/usr/bin/env python3
"""
Week10 Midterm Exam — Hash File Generator

Generates exam-hashes.txt with mixed MD5 and SHA1 hashes.
MD5 = 32 hex chars, SHA1 = 40 hex chars (format identification exercise).

Usage: python week10_midterm/dataset/generate_exam_hashes.py
Run from: teaching-assets/ directory
"""

import hashlib
import os

OUTPUT = "week10_midterm/dataset/exam-hashes.txt"

ACCOUNTS = [
    # (username, password, algo, crackable)
    ("alice",    "password",          "md5",  True),
    ("bob",      "123456",            "md5",  True),
    ("carol",    "letmein",           "md5",  True),
    ("dave",     "hello",             "sha1", True),
    ("eve",      "password",          "sha1", True),
    ("sysadmin", "X9kZp#2$mQvL8!",   "md5",  False),
]

def md5(s):
    return hashlib.md5(s.encode()).hexdigest()

def sha1(s):
    return hashlib.sha1(s.encode()).hexdigest()

os.makedirs("week10_midterm/dataset", exist_ok=True)

lines = []
for user, pw, algo, crackable in ACCOUNTS:
    h = md5(pw) if algo == "md5" else sha1(pw)
    lines.append(f"{user}:{h}")

with open(OUTPUT, "w") as f:
    f.write("\n".join(lines) + "\n")

print(f"Generated {OUTPUT}")
print()
print("Hash summary (teacher reference):")
for user, pw, algo, crackable in ACCOUNTS:
    h = md5(pw) if algo == "md5" else sha1(pw)
    status = "crackable" if crackable else "NOT crackable"
    print(f"  {user:10s} {algo.upper():5s} {h}  ({pw if crackable else '(complex)'}) [{status}]")

print()
print("Crack commands (for verification):")
print("  john --format=raw-md5  --wordlist=/usr/share/wordlists/rockyou.txt exam-hashes.txt")
print("  john --format=raw-sha1 --wordlist=/usr/share/wordlists/rockyou.txt exam-hashes.txt")
print("  john --show exam-hashes.txt")
