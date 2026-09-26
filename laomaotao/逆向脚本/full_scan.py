# -*- coding: utf-8 -*-
import os
_BASE = os.environ.get("PE_BASE") or os.getcwd()
"""全文件扫描：UTF-16 可打印串（含中文）+ 关键 ASCII 串，找密码/路径/URL"""
import re

PATH = os.path.join(_BASE, "laomaotao", "work", "LaoMaoTao.exe")
raw = open(PATH, "rb").read()
N = len(raw)
print(f"文件大小 {N}")

# ---- UTF-16 全文件 ----
print("\n=== UTF-16LE 可打印串（含中文，>=2字符）===")
u16 = re.findall(rb"(?:[\x20-\x7e\x81-\xfe]\x00){2,80}", raw)
seen = set(); cnt = 0
for m in u16:
    t = m.decode("utf-16le", errors="replace")
    if t in seen: continue
    seen.add(t)
    # 过滤重复字符噪声
    if re.fullmatch(r"([\x80-\xfe])\1{2,}", t): continue
    if re.fullmatch(r"[\s\x00-\x1f\uFFFD]+", t): continue
    cnt += 1
    if cnt <= 400:
        print(f"  {t!r}")
print(f"(UTF-16 共 {cnt} 条)")

# ---- 关键 ASCII 串 ----
print("\n=== 关键 ASCII 串（路径/URL/命令/关键字上下文）===")
kw = re.compile(rb"[\x20-\x7e]{5,}")
found = set()
for m in kw.finditer(raw):
    s = m.group().decode("ascii", errors="replace")
    if not re.search(r"(?i)(\.7z|\.exe|\.dll|http|www\.|ftp|/temp|\\temp|cmd\.|/c | -p|password|passwd|XOR|\\x[0-9a-f]{2}|777|ReadProcessMemory|WriteProcessMemory|VirtualAlloc|CreateRemote|OpenProcess|GetProcAddress|Download|update|\.ini|\.cfg|mshta|powershell|cscript|wscript|schtasks|reg add|runas|net user|sc create|driver|\.sys|\\drivers|\\\\device\\|\\.\\\\)", s, re.I):
        continue
    if s not in found:
        found.add(s)
        if len(found) <= 250:
            print(f"  {s!r}")
print(f"(ASCII 关键串 {len(found)} 条)")
