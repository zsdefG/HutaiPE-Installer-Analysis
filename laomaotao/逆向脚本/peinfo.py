# -*- coding: utf-8 -*-
import os
_BASE = os.environ.get("PE_BASE") or os.getcwd()
"""LaoMaoTao.exe PE 结构/熵/签名/壳判断 + 密码线索字符串"""
import pefile, math, re, struct, os

PATH = os.path.join(_BASE, "laomaotao", "work", "LaoMaoTao.exe")
raw = open(PATH, "rb").read()
pe = pefile.PE(PATH, fast_load=False)

def entropy(b):
    if not b: return 0
    from collections import Counter
    c = Counter(b); n = len(b)
    return -sum((v/n) * math.log2(v/n) for v in c.values())

print("=== PE 头 ===")
print(f"Size={len(raw)}  Machine=0x{pe.FILE_HEADER.Machine:x}  Sections={pe.FILE_HEADER.NumberOfSections}")
print(f"TimeDateStamp=0x{pe.FILE_HEADER.TimeDateStamp:x}")
ts = pe.FILE_HEADER.TimeDateStamp
import datetime
print(f"  编译时间={datetime.datetime.utcfromtimestamp(ts)} UTC")
print(f"EntryPoint=0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}  ImageBase=0x{pe.OPTIONAL_HEADER.ImageBase:x}")
print(f"Subsystem={pe.OPTIONAL_HEADER.Subsystem}  DllChar=0x{pe.OPTIONAL_HEADER.DllCharacteristics:x}")
print(f"Sections:")
for s in pe.sections:
    n = s.Name.rstrip(b"\x00").decode(errors="replace")
    d = s.get_data()
    print(f"  {n:10s} VS={s.Misc_VirtualSize:#x} RawSize={s.SizeOfRawData:#x} 熵={entropy(d):.2f}")
print(f"CertDir(安全目录): off=0x{pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress:x} size={pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size}")

print("\n=== 签名 ===")
cert_off = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress
cert_sz = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
if cert_off and cert_sz:
    print(f"存在数字签名目录(偏移0x{cert_off:x} 大小0x{cert_sz:x})")
    # WIN_CERTIFICATE header: dwLength dwRevision dwCertType
    if cert_off + 8 <= len(raw):
        dwLen, rev, ctype = struct.unpack_from("<IHH", raw, cert_off)
        print(f"  WIN_CERT: length={dwLen} revision={rev:#x} type={ctype:#x} (0x0002=PKCS#7)")
else:
    print("无数字签名目录 (未签名)")

print("\n=== 导入表 ===")
if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
    dlls = {}
    for e in pe.DIRECTORY_ENTRY_IMPORT:
        dlls[e.dll.decode(errors="replace")] = len(e.imports)
    for d, n in sorted(dlls.items()):
        print(f"  {d}: {n}")
else:
    print("无导入表 (可能加壳/压缩)")

print("\n=== 密码/解压线索字符串 ===")
for enc, name in ((lambda b: b, "ascii"), (lambda b: b.decode("utf-16le").encode("latin1"), "utf16")):
    pass
def scan(pattern, label, enc="ascii"):
    pat = re.compile(pattern)
    res = []
    for m in pat.finditer(raw):
        try:
            s = m.group().decode(enc)
        except Exception:
            continue
        if s not in res: res.append(s)
    print(f"-- {label} ({len(res)}条) --")
    for s in res[:40]:
        print(f"   {s!r}")

scan(rb"[\x20-\x7e]{3,}", "ASCII 含关键词")
kw = re.compile(("(?i)(pass|pwd|key|passwd|密码|解密|解压|encrypt|decrypt|cipher|7z|zip|boot|ud|driver|admin|password)").encode("utf-8"))
hits = []
for m in kw.finditer(raw):
    s = max(0, m.start()-40); e = min(len(raw), m.end()+40)
    ctx = raw[s:e]
    hits.append(ctx)
seen = set(); out = []
for h in hits:
    if h not in seen:
        seen.add(h); out.append(h)
print(f"-- 关键词上下文 (ASCII, {len(out)}条, 前50) --")
for h in out[:50]:
    print("   ", repr(h))
