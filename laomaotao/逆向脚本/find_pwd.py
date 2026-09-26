# -*- coding: utf-8 -*-
import os
_BASE = os.environ.get("PE_BASE") or os.getcwd()
"""LaoMaoTao.exe：挖掘 7z 解压密码候选（短 ASCII/UTF-16 字符串 + 7za 相关线索）"""
import re, struct, pefile

PATH = os.path.join(_BASE, "laomaotao", "work", "LaoMaoTao.exe")
raw = open(PATH, "rb").read()
pe = pefile.PE(PATH, fast_load=False)

# 各节范围（文件偏移）
secs = []
for s in pe.sections:
    n = s.Name.rstrip(b"\x00").decode(errors="replace")
    secs.append((n, s.PointerToRawData, s.PointerToRawData + s.SizeOfRawData))
print("=== 节范围 ===")
for n, a, b in secs:
    print(f"  {n:10s} file 0x{a:x} - 0x{b:x}")

# 短字符串候选：3-20 字符纯可见 ASCII，位于 .data/.rdata/.itext 附近
def short_strs(data, minlen=3, maxlen=20):
    res = []
    i = 0
    n = len(data)
    while i < n:
        c = data[i]
        if 0x20 <= c < 0x7f:
            j = i
            while j < n and 0x20 <= data[j] < 0x7f:
                j += 1
            L = j - i
            if minlen <= L <= maxlen:
                res.append((i, data[i:j].decode("ascii")))
            i = j
        else:
            i += 1
    return res

print("\n=== .data/.rdata 短字符串（3-20 字符）===")
for n, a, b in secs:
    if n not in (".data", ".rdata", ".itext", ".didata"):
        continue
    d = raw[a:b]
    strs = short_strs(d)
    # 过滤明显噪声
    noise = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$|^[A-Z]{1,4}$|^[a-z]{1,3}$|^(var|end|nil|true|false|and|or|not|div|mod|asm|for|while|repeat|until|case|begin|const|type|unit|uses|function|procedure)$", re.I)
    seen = set()
    cnt = 0
    for off, s in strs:
        if noise.match(s) or s in seen:
            continue
        # 候选：含数字混合、或常见密码特征
        if re.search(r"\d", s) or len(s) >= 6 or re.search(r"[.!@#$%^&*]", s):
            seen.add(s)
            cnt += 1
            if cnt <= 150:
                print(f"  0x{a+off:x} [{n}] {s!r}")
    print(f"  ({n} 候选 {cnt} 条)")

print("\n=== UTF-16LE 短字符串（.data 范围）===")
for n, a, b in secs:
    if n not in (".data", ".rdata"):
        continue
    d = raw[a:b]
    u16 = re.findall(rb"(?:[\x20-\x7e]\x00){3,20}", d)
    seen = set()
    for m in u16:
        s = m.decode("utf-16le")
        if len(s) >= 3 and s not in seen:
            seen.add(s)
            print(f"  [{n}] {s!r}")
    print(f"  ({n} UTF16 共 {len(seen)} 条)")

print("\n=== 7za/SevenZip/解压相关字符串 ===")
for kw in (b"7za", b"SevenZip", b"7z", b"LZMA", b"Extract", b"extract", b"Password", b"password", b"decrypt", b"Unpack", b"unpack"):
    for m in re.finditer(re.escape(kw), raw):
        s = max(0, m.start()-40); e = min(len(raw), m.end()+40)
        print(f"  0x{m.start():x}: {repr(raw[s:e])}")
