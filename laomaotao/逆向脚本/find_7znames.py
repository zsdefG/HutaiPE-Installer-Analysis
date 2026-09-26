# -*- coding: utf-8 -*-
import os
_BASE = os.environ.get("PE_BASE") or os.getcwd()
"""搜索 7z 文件名/路径在 exe 中的引用位置（ASCII + UTF-16），定位解压代码"""
import re

PATH = os.path.join(_BASE, "laomaotao", "work", "LaoMaoTao.exe")
raw = open(PATH, "rb").read()

names = ["Driver.7z", "UD.7z", "PACmd.7z", "Qemu.7z", "Ver.7z", "Other.7z", "Boot.7z",
         "7za.dll", "7z.dll", "CLbMiT", "LaoMaoTao", "Data", "Backup", "System",
         "Config.ini", "03PE.wim", "10PE64.wim", "ExTools.wim"]

print("=== ASCII 引用 ===")
for nm in names:
    b = nm.encode("ascii")
    pos = [m.start() for m in re.finditer(re.escape(b), raw)]
    if pos:
        for p in pos:
            s = max(0, p-50); e = min(len(raw), p+len(b)+50)
            print(f"  {nm}: 0x{p:x} ctx={raw[s:e]!r}")

print("\n=== UTF-16LE 引用 ===")
for nm in names:
    b = nm.encode("utf-16le")
    pos = [m.start() for m in re.finditer(re.escape(b), raw)]
    if pos:
        for p in pos:
            s = max(0, p-50); e = min(len(raw), p+len(b)+50)
            print(f"  {nm}: 0x{p:x} ctx={raw[s:e]!r}")
