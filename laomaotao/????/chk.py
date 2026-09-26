# -*- coding: utf-8 -*-
"""检查 .itext 节、7za 相关字符串（多编码）、.rsrc 资源结构"""
import pefile, struct, re

PATH = r"d:\文档\workbuddy\Safe\my\laomaotao\work\LaoMaoTao.exe"
raw = open(PATH, "rb").read()
pe = pefile.PE(PATH, fast_load=False)

print("=== .itext 节内容（前 256 字节 hex）===")
itext = [s for s in pe.sections if s.Name.rstrip(b"\x00") == b".itext"][0]
d = itext.get_data()
print(d[:256].hex(" "))
print("ASCII:", repr(d[:200]))

print("\n=== 7za/LZMA/SevenZip/Extract/Password 字符串（ASCII/UTF-16）===")
kws = [b"7za", b"SevenZip", b"LZMA", b"7-Zip", b"7z", b"Extract", b"Password", b"password", b"-p", b"XOR", b"Decode", b"decode", b"Unpack", b"unpack", b"inflate", b"Compress"]
seen = set()
for kw in kws:
    for m in re.finditer(re.escape(kw), raw):
        s = max(0, m.start()-30); e = min(len(raw), m.end()+30)
        ctx = raw[s:e]
        if ctx not in seen:
            seen.add(ctx)
            print(f"  0x{m.start():x}: {repr(ctx)}")
# UTF-16
for kw in [w.encode("utf-16le") for w in ["7za", "SevenZip", "LZMA", "Password", "password", "Extract", "7-Zip"]]:
    for m in re.finditer(re.escape(kw), raw):
        s = max(0, m.start()-30); e = min(len(raw), m.end()+30)
        ctx = raw[s:e]
        if ctx not in seen:
            seen.add(ctx)
            print(f"  0x{m.start():x} [UTF16]: {repr(ctx)}")

print("\n=== .rsrc 资源枚举 ===")
if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
    def walk(entry, depth=0, path=""):
        for e in entry.directory.entries:
            if e.name:
                n = str(e.name)
            else:
                n = str(e.id)
            if hasattr(e, "directory"):
                walk(e, depth+1, path + "/" + n)
            else:
                if e.data:
                    rva, sz = e.data.struct.OffsetToData, e.data.struct.Size
                    print(f"  {path}/{n}: RVA 0x{rva:x} size {sz}")
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        walk(entry, 1, "")
else:
    print("无资源目录")

print("\n=== .rsrc 段熵与内部魔数 ===")
rsrc = [s for s in pe.sections if s.Name.rstrip(b"\x00") == b".rsrc"][0]
rd = rsrc.get_data()
from collections import Counter
import math
c = Counter(rd); n = len(rd)
ent = -sum((v/n)*math.log2(v/n) for v in c.values())
print(f".rsrc size={len(rd)} 熵={ent:.2f}")
for magic, name in [(b"MZ", "PE"), (b"PK\x03\x04", "ZIP"), (b"7z\xbc\xaf\x27\x1c", "7z"), (b"\x1f\x8b", "gzip"), (b"BM", "BMP")]:
    pos = [m.start() for m in re.finditer(re.escape(magic), rd)]
    print(f"  {name}: {len(pos)} 处 {[hex(p) for p in pos[:5]]}")

print("\n=== 版本/清单信息 ===")
try:
    fi = pe.FileInfo
    for f in fi:
        if f.Key == b"VS_VERSION_INFO":
            for s in f.StringTable:
                for k, v in s.entries.items():
                    print(f"  {k.decode(errors='replace')}: {v.decode(errors='replace')}")
except Exception as ex:
    print("无版本信息:", ex)
