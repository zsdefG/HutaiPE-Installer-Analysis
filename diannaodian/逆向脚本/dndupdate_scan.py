# -*- coding: utf-8 -*-
import os
_BASE = os.environ.get("PE_BASE") or os.getcwd()
"""DNDUpdate.exe 侦察：PE 结构/签名/壳 + URL 与下载执行线索字符串"""
import pefile, math, re, struct, datetime

PATH = os.path.join(_BASE, "diannaodian", "work", "pe", "extract10", "DNDUpdate.exe")
raw = open(PATH, "rb").read()
pe = pefile.PE(PATH, fast_load=False)

def entropy(b):
    if not b: return 0
    from collections import Counter
    c = Counter(b); n = len(b)
    return -sum((v/n) * math.log2(v/n) for v in c.values())

print("=== PE 头 ===")
print(f"Size={len(raw)}  Machine=0x{pe.FILE_HEADER.Machine:x}  Sections={pe.FILE_HEADER.NumberOfSections}")
ts = pe.FILE_HEADER.TimeDateStamp
print(f"TimeDateStamp=0x{ts:x}  编译时间={datetime.datetime.utcfromtimestamp(ts)} UTC")
print(f"EntryPoint=0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}  ImageBase=0x{pe.OPTIONAL_HEADER.ImageBase:x}")
print(f"Subsystem={pe.OPTIONAL_HEADER.Subsystem}  DllChar=0x{pe.OPTIONAL_HEADER.DllCharacteristics:x}")
print("Sections:")
for s in pe.sections:
    n = s.Name.rstrip(b"\x00").decode(errors="replace")
    d = s.get_data()
    print(f"  {n:10s} VS={s.Misc_VirtualSize:#x} RawSize={s.SizeOfRawData:#x} 熵={entropy(d):.2f}")

print("\n=== 导入表 ===")
if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
    for e in pe.DIRECTORY_ENTRY_IMPORT:
        print(f"  {e.dll.decode(errors='replace')}: {len(e.imports)}")

print("\n=== URL / 下载线索 ===")
def scan(pattern, label, minlen=4):
    pat = re.compile(pattern)
    res = []
    for m in pat.finditer(raw):
        s = m.group().decode("latin1", errors="replace")
        if s not in res: res.append(s)
    print(f"-- {label} ({len(res)}条) --")
    for s in res[:50]:
        print(f"   {s!r}")

scan(rb"https?://[\x21-\x7e]{4,200}", "HTTP URL")
scan(rb"/type[: ]?[\x21-\x7e]{0,30}", "/type 参数")
scan(rb"downexec|startup|\.json|update", "update/downexec/json 关键词")
