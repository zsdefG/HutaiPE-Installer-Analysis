# -*- coding: utf-8 -*-
"""扫描 FAT12/16/32 磁盘镜像中的 8.3 目录项与长文件名，输出文件列表"""
import re, sys

def scan_fat(path):
    raw = open(path, "rb").read()
    print(f"=== {path} ({len(raw)} bytes) ===")
    # FAT 目录项: 32 字节, 首字节 0xE5 删除, 0x00 结束
    files = []
    # 8.3 名: 11 字节, 属性字节 0x0F 是长文件名记录(跳过), 0x10 目录
    for m in re.finditer(rb"[A-Z0-9\x80-\xff\$%\x27\x60\-_~!@#^&(){}[\].]{11}", raw):
        pass  # 8.3 需按 32 字节对齐解析
    # 简单方式: 按 32 字节对齐扫描整个文件找目录项
    n = len(raw)
    for off in range(0, n - 32, 32):
        e = raw[off:off+32]
        first = e[0]
        if first in (0x00, 0xE5) or first < 0x20:
            continue
        attr = e[11]
        if attr == 0x0F:
            continue  # 长文件名
        name = e[0:8].rstrip(b" ").decode("latin1", errors="replace")
        ext = e[8:11].rstrip(b" ").decode("latin1", errors="replace")
        if not name or any(c in name for c in "\x00\xff"):
            continue
        if any(0x80 <= ord(c) <= 0xff for c in name + ext):
            continue
        fname = f"{name}.{ext}" if ext else name
        size = int.from_bytes(e[28:32], "little")
        files.append((off, fname, size, "D" if attr & 0x10 else "F"))
    # 去重（按 名字+大小）
    seen = set(); out = []
    for off, fn, sz, t in files:
        k = (fn, sz, t)
        if k in seen: continue
        seen.add(k); out.append((off, fn, sz, t))
    print(f"共 {len(out)} 个目录项：")
    for off, fn, sz, t in sorted(out, key=lambda x: x[1]):
        print(f"  {t} {sz:>10d}  {fn}")

for p in sys.argv[1:]:
    scan_fat(p)
