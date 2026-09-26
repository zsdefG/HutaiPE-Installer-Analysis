# -*- coding: utf-8 -*-
import os
_BASE = os.environ.get("PE_BASE") or os.getcwd()
"""提取 Delphi UnicodeString 常量（正确结构）：
   头: B0 04 (cp=1200) | 02 00 (elemSize=2) | FF FF FF FF (refCount=-1) | <len:4> | <utf16 数据>
   同时兼容其他 codepage 变体（cp + elemSize 1/2）。
"""
import re, struct

PATH = os.path.join(_BASE, "laomaotao", "work", "LaoMaoTao.exe")
raw = open(PATH, "rb").read()
N = len(raw)
print(f"file size: {N:#x} ({N})")

results = []
# UTF-16 常量头: B0 04 (cp=1200 LE) | 02 00 (elemSize) | FF FF FF FF (refCount=-1)
HEAD = b"\xb0\x04\x02\x00\xff\xff\xff\xff"
for m in re.finditer(re.escape(HEAD), raw):
    start = m.end()
    if start + 4 > N:
        continue
    ln = struct.unpack_from("<i", raw, start)[0]
    if not (1 <= ln <= 0x10000):
        continue
    data_start = start + 4
    data = raw[data_start:data_start + ln*2]
    if len(data) < ln*2:
        continue
    try:
        s = data.decode("utf-16le")
    except Exception:
        continue
    results.append((m.start(), ln, s))

print(f"UTF-16 (cp1200) 字符串常量共 {len(results)} 条\n")
for off, ln, s in results:
    print(f"0x{off:08x} len={ln:4d} {s!r}")
