# -*- coding: utf-8 -*-
"""全文件扫描：ASCII 长串 + UTF-16 可打印串 + 形如 key=value 的配置项，按偏移排序输出"""
import re, struct

PATH = r"d:\文档\workbuddy\Safe\my\laomaotao\work\LaoMaoTao.exe"
raw = open(PATH, "rb").read()
N = len(raw)

out = []

# --- ASCII 可打印串（>=4 字符） ---
for m in re.finditer(rb"[\x20-\x7e]{4,}", raw):
    s = m.group(0).decode("ascii")
    out.append((m.start(), "A", s))

# --- UTF-16LE 可打印串（>=3 字符，含中文） ---
# 扫描连续非零的偶数对齐字节对
i = 0
while i + 2 <= N:
    hi = raw[i+1]
    lo = raw[i]
    if hi == 0 and (0x20 <= lo <= 0x7e or lo >= 0x80):
        j = i
        chars = []
        while j + 2 <= N:
            l2 = raw[j]; h2 = raw[j+1]
            if h2 == 0 and (0x20 <= l2 <= 0x7e or l2 >= 0x80):
                chars.append(l2)
                j += 2
            else:
                break
        if len(chars) >= 3:
            s = bytes(chars).decode("utf-16le", errors="replace")
            out.append((i, "U", s))
            i = j
            continue
    i += 2

out.sort(key=lambda x: x[0])
print(f"总命中 {len(out)} 条\n")
for off, kind, s in out:
    print(f"0x{off:08x} [{kind}] {s!r}")
