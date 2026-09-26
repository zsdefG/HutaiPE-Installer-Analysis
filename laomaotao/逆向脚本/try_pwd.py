# -*- coding: utf-8 -*-
import os
_BASE = os.environ.get("PE_BASE") or os.getcwd()
"""批量测试候选密码（用 Ver.7z 快速验证 headers 加密）"""
import subprocess, sys

seven = r"D:\7-Zip\7z.exe"
target = os.path.join(_BASE, "laomaotao", "work", "Ver.7z")

candidates = [
    "123456", "12345678", "888888", "88888888", "666666", "000000",
    "laomaotao", "LaoMaoTao", "LAOMAOTAO", "Laomaotao", "lmt", "LMT",
    "laomaotao.net", "www.laomaotao.net", "LaoMaoTao.net", "LaoMaoTao.7z",
    "dabaicai", "DaBaiCai", "abc123", "123", "1234", "111111", "0000",
    "123456789", "qwerty", "admin", "password", "11111111", "99999999",
    "66668888", "laomaotao888", "88886666",
]

found = None
for p in candidates:
    r = subprocess.run([seven, "t", target, "-p" + p, "-y"],
                       capture_output=True, text=True, encoding="gbk", errors="replace",
                       timeout=30)
    out = r.stdout + r.stderr
    if "Everything is Ok" in out or "OK" in out.upper().replace("NOT OK",""):
        # 排除 “NOT OK”
        if "Wrong password" not in out and "Not OK" not in out and "Error" not in out:
            found = p
            print(f"[HIT] 密码 = {p!r}")
            break
    else:
        print(f"try {p!r}: fail")

if not found:
    print("\n常见候选均失败，需反汇编定位密码")
