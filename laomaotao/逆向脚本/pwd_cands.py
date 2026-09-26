# -*- coding: utf-8 -*-
"""从 dump_delphi_strs_out.txt 中筛选密码风格候选串（混合大小写+数字+特殊字符）"""
import re

PATH = r"d:\文档\workbuddy\Safe\my\laomaotao\dump_delphi_strs_out.txt"
cands = []
for line in open(PATH, encoding="utf-8"):
    m = re.match(r"0x([0-9a-f]+) len=\s+(\d+) '(.*)'", line.rstrip("\n"))
    if not m:
        continue
    off, ln, s = int(m.group(1), 16), int(m.group(2)), m.group(3)
    if not (6 <= ln <= 32):
        continue
    # 排除明显非密码
    if re.search(r"[\s/\\:;,=<>%]|http|\.com|\.net|\.dll|\.exe|\.7z|\.wim|\.img|\.ini|\.bin|SOFTWARE|HKEY|\\\\", s, re.I):
        continue
    has_lower = re.search(r"[a-z]", s) is not None
    has_upper = re.search(r"[A-Z]", s) is not None
    has_digit = re.search(r"\d", s) is not None
    has_special = re.search(r"[^A-Za-z0-9]", s) is not None
    # 密码特征：含特殊字符；或 混合大小写+数字 且非纯单词
    if has_special:
        cands.append((off, s))
    elif has_digit and has_lower and has_upper and not re.fullmatch(r"[A-Za-z]+\d+", s):
        cands.append((off, s))

print(f"候选 {len(cands)} 条：")
for off, s in cands:
    print(f"0x{off:08x} len={len(s):2d} {s!r}")
