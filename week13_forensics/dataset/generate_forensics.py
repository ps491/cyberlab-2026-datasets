#!/usr/bin/env python3
"""Week13 — Digital Forensics CSV Generator (v1.1)

變更說明（v1.1，2026-06-18）：
  - browser_history: 新增 14:02:15 記錄（修正時序盲點；行數 10 → 11）
  - usb_history: 新增 16:30:52 Directory List 事件（修正行數 7 → 8）
  - downloads: update_v2.exe sha256 改為真實計算值（配合教學佔位 exe 檔）
  - 新增 update_v2.exe 教學佔位檔（供學生 sha256sum 練習）

IP 一致性：185.220.101.99 符合 module3-design-spec.md §5.2 主線 IP 表（W13 + W14）
"""
import csv, hashlib, os

BASE_DIR = "week13_forensics/dataset"
os.makedirs(BASE_DIR, exist_ok=True)

# ─── update_v2.exe（教學佔位檔，供 sha256sum 練習）────────────────────────
fake_exe_content = (
    "CYBERLAB-W13-FORENSICS-DATASET\r\n"
    "update_v2.exe (educational placeholder for digital forensics training)\r\n"
    "Origin: http://185.220.101.99/tools/update_v2.exe\r\n"
    "This file is NOT malware. For educational use only.\r\n"
    "CyberLab Teaching Asset v1.0\r\n"
)
exe_path = os.path.join(BASE_DIR, "update_v2.exe")
with open(exe_path, "w", newline="") as f:
    f.write(fake_exe_content)

exe_bytes = fake_exe_content.encode("utf-8")
exe_sha256 = hashlib.sha256(exe_bytes).hexdigest()
exe_size = len(exe_bytes)

# ─── browser_history.csv（11 筆）────────────────────────────────────────────
browser_rows = [
    ["timestamp",            "url",                                               "title",                      "visit_count", "browser"],
    ["2026-06-01 08:45:12",  "https://mail.company.com",                         "Company Webmail",              45, "Chrome"],
    ["2026-06-01 09:03:22",  "https://www.google.com/search?q=quarterly+report", "Google Search",                12, "Chrome"],
    ["2026-06-01 09:15:44",  "https://docs.company.com/reports/Q1-2026",         "Q1 2026 Financial Report",      3, "Chrome"],
    ["2026-06-01 10:30:01",  "https://www.youtube.com",                          "YouTube",                       8, "Chrome"],
    ["2026-06-01 11:00:33",  "https://docs.company.com/clients/export",          "Client Database Export",        2, "Chrome"],
    ["2026-06-01 13:45:07",  "http://185.220.101.99/tools",                      "Free Download Tools",           1, "Chrome"],
    ["2026-06-01 13:45:31",  "http://185.220.101.99/tools/update_v2.exe",        "Download: update_v2.exe",       3, "Chrome"],
    ["2026-06-01 13:46:02",  "http://185.220.101.99/tools/update_v2.exe",        "Download: update_v2.exe",       1, "Chrome"],
    ["2026-06-01 14:02:15",  "https://docs.company.com/clients/export",          "Client Database Export",        1, "Chrome"],  # v1.1 新增：下載前再次確認頁面
    ["2026-06-01 14:15:22",  "https://mail.company.com",                         "Company Webmail",               2, "Chrome"],
    ["2026-06-01 16:20:55",  "https://www.google.com",                           "Google",                        1, "Chrome"],
]

with open(os.path.join(BASE_DIR, "browser_history.csv"), "w", newline="") as f:
    csv.writer(f).writerows(browser_rows)

# ─── downloads.csv（3 筆）───────────────────────────────────────────────────
download_rows = [
    ["timestamp",            "filename",            "source_url",                                  "size_bytes", "sha256",                "status"],
    ["2026-06-01 09:15:51",  "Q1-2026-Report.pdf",  "https://docs.company.com/reports/Q1-2026",   2456789,      "a3f4d7e8b2c1f6...9e0a", "completed"],
    ["2026-06-01 13:46:05",  "update_v2.exe",       "http://185.220.101.99/tools/update_v2.exe",  exe_size,     exe_sha256,              "completed"],
    ["2026-06-01 14:02:33",  "client_export.xlsx",  "https://docs.company.com/clients/export",    892341,       "b8c3e1f4a7d2...5c9f",   "completed"],
]

with open(os.path.join(BASE_DIR, "downloads.csv"), "w", newline="") as f:
    csv.writer(f).writerows(download_rows)

# ─── usb_history.csv（8 筆）─────────────────────────────────────────────────
usb_rows = [
    ["timestamp",            "event",          "device_name",            "serial_number",  "volume_label", "drive_letter", "files_transferred", "total_bytes"],
    ["2026-06-01 08:12:04",  "Connected",      "Kingston DataTraveler",  "3201KD9ABCD4",   "KINGSTON",     "E:",           0,                   0],
    ["2026-06-01 08:15:33",  "Disconnected",   "Kingston DataTraveler",  "3201KD9ABCD4",   "KINGSTON",     "E:",           0,                   0],
    ["2026-06-01 16:30:44",  "Connected",      "Kingston DataTraveler",  "3201KD9ABCD4",   "KINGSTON",     "E:",           0,                   0],
    ["2026-06-01 16:30:52",  "Directory List", "Kingston DataTraveler",  "3201KD9ABCD4",   "KINGSTON",     "E:",           0,                   0],  # v1.1 新增：Windows Explorer 自動掃描 USB 目錄
    ["2026-06-01 16:31:12",  "File Copy",      "Kingston DataTraveler",  "3201KD9ABCD4",   "KINGSTON",     "E:",           1,                   2456789],
    ["2026-06-01 16:31:55",  "File Copy",      "Kingston DataTraveler",  "3201KD9ABCD4",   "KINGSTON",     "E:",           1,                   892341],
    ["2026-06-01 16:32:41",  "File Copy",      "Kingston DataTraveler",  "3201KD9ABCD4",   "KINGSTON",     "E:",           1,                   1843200],
    ["2026-06-01 16:33:10",  "Disconnected",   "Kingston DataTraveler",  "3201KD9ABCD4",   "KINGSTON",     "E:",           3,                   5192330],
]

with open(os.path.join(BASE_DIR, "usb_history.csv"), "w", newline="") as f:
    csv.writer(f).writerows(usb_rows)

print("=== W13 Dataset Generator v1.1 ===")
print(f"browser_history.csv : {len(browser_rows)-1} 筆（含標頭共 {len(browser_rows)} 行）")
print(f"downloads.csv       : {len(download_rows)-1} 筆")
print(f"usb_history.csv     : {len(usb_rows)-1} 筆")
print(f"update_v2.exe       : {exe_size} bytes")
print(f"update_v2.exe SHA256: {exe_sha256}")
print(f"USB 外洩總量         : {5192330/1000/1000:.2f} MB（SI）/ {5192330/1024/1024:.2f} MiB")
