# -*- coding: utf-8 -*-
import re, math, collections

exe = open(r"d:\文档\workbuddy\Safe\my\laomaotao\work\pkg\pe_scripts\PECMD.EXE", "rb").read()
print(f"PECMD.EXE {len(exe)} bytes")

# 1) 定位关键字符串偏移
for pat in [b"CMPa", b"CMPS", b"PECMD.INI", b"PECMD.IN", b"1.WCS", b".wcs", b"autoapp", b"Cipher", b"Indata", b"RCDATA", b"PECMD.LOG"]:
    offs = [m.start() for m in re.finditer(re.escape(pat), exe)]
    print(f"{pat.decode():12s} @ {[hex(o) for o in offs[:8]]}{' ...' if len(offs)>8 else ''} (共{len(offs)})")

# 2) 检查每个 CMPa 引用点附近的字符串上下文（看是否明文"PECMD"等说明）
print("\n=== CMPa 附近上下文 ===")
for o in [m.start() for m in re.finditer(b"CMPa", exe)]:
    ctx = exe[max(0,o-24):o+24]
    print(f"@0x{o:06x}: {ctx!r}")

# 3) 扫描 256 字节高熵块（潜在密钥表/加密脚本内嵌）
print("\n=== 高熵 256B 窗口 (ent>7.9, 连续) ===")
n = len(exe)
high = []
for i in range(0, n-256, 256):
    blk = exe[i:i+256]
    freq = collections.Counter(blk)
    if len(freq) < 200: continue
    ent = -sum((c/256)*math.log2(c/256) for c in freq.values())
    if ent > 7.9:
        high.append((i, round(ent,3)))
# 合并连续
merged = []
for i, e in high:
    if merged and i - merged[-1][-1] <= 256:
        merged[-1] = (merged[-1][0], i+256)
    else:
        merged.append([i, i+256])
print(f"高熵区段 {len(merged)} 个:")
for a, b in merged[:30]:
    print(f"  0x{a:06x}-0x{b:06x} ({b-a} bytes)")
