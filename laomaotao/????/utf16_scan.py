# -*- coding: utf-8 -*-
"""扫描 .data 全部 UTF-16/GBK 字符串（含中文），找密码常量"""
import pefile, struct, re

PATH = r"d:\文档\workbuddy\Safe\my\laomaotao\work\LaoMaoTao.exe"
raw = open(PATH, "rb").read()
pe = pefile.PE(PATH, fast_load=False)

data = [s for s in pe.sections if s.Name.rstrip(b"\x00") == b".data"][0]
dd = data.get_data()
print(f".data: file 0x{data.PointerToRawData:x} size {len(dd)}")

print("\n=== .data UTF-16LE 字符串（>=2 字符，含中文，前 300）===")
u16 = re.findall(rb"(?:[\x20-\x7e\x80-\xff]\x00){2,80}", dd)
seen = set(); cnt = 0
for m in u16:
    t = m.decode("utf-16le", errors="replace")
    # 过滤明显数据（重复字符）
    if t in seen: continue
    seen.add(t)
    if re.fullmatch(r"([\x00-\x1f]|\uFFFD)+", t): continue
    cnt += 1
    if cnt <= 300:
        print(f"  {t!r}")
print(f"(UTF-16 共 {cnt} 条)")

print("\n=== .data GBK 中文短串（字节模式）===")
gbk_cands = []
i = 0
n = len(dd)
while i < n:
    b = dd[i]
    if 0x81 <= b <= 0xfe:  # GBK lead
        if i+1 < n and 0x40 <= dd[i+1] <= 0xfe and dd[i+1] != 0x7f:
            j = i
            s = bytearray()
            while j+1 < n:
                b1 = dd[j]; b2 = dd[j+1]
                if (0x81 <= b1 <= 0xfe and 0x40 <= b2 <= 0xfe and b2 != 0x7f):
                    s += bytes([b1, b2]); j += 2
                else:
                    break
            if len(s) >= 4:
                try:
                    t = s.decode("gbk")
                    if not re.fullmatch(r"[\s\uFFFD]+", t):
                        gbk_cands.append((i, t))
                except Exception:
                    pass
                i = j
                continue
    i += 1
print(f"GBK 中文串 {len(gbk_cands)} 条，前 100：")
for off, t in gbk_cands[:100]:
    print(f"  0x{data.PointerToRawData+off:x}: {t!r}")
