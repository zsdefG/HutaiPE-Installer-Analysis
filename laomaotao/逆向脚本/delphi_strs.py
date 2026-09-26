# -*- coding: utf-8 -*-
import os
_BASE = os.environ.get("PE_BASE") or os.getcwd()
"""提取 Delphi UnicodeString 常量：结构 02 00 <len:4> 00 00 00 00 FF FF FF FF <utf16数据>"""
import re, struct

PATH = os.path.join(_BASE, "laomaotao", "work", "LaoMaoTao.exe")
raw = open(PATH, "rb").read()

# 模式: elemSize(2)\x02\x00, charLength(4), refCount(4)=\xff\xff\xff\xff, 字符数据
results = []
pat = re.compile(rb"\x02\x00(....)\xff\xff\xff\xff")
for m in pat.finditer(raw):
    ln = struct.unpack_from("<i", m.group(1))[0]
    if not (1 <= ln <= 512):
        continue
    start = m.end()
    data = raw[start:start + ln*2]
    if len(data) < ln*2:
        continue
    # 校验：数据后跟 0x00 00 结束，且字符基本都是有效 Unicode
    s = data.decode("utf-16le", errors="replace")
    if "\ufffd" in s:
        continue
    # 只保留有意义的（可打印或中文）
    if re.fullmatch(r"[\s\uFFFD\u0000-\u001f]*", s):
        continue
    results.append((m.start(), ln, s))

print(f"Delphi 字符串常量共 {len(results)} 条\n")
# 打印全部（按出现位置）
for off, ln, s in results:
    print(f"0x{off:08x} len={ln:4d} {s!r}")
