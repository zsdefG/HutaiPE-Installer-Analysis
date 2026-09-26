# -*- coding: utf-8 -*-
import os
_BASE = os.environ.get("PE_BASE") or os.getcwd()
"""完整资源树 dump：打印每个叶子路径/类型/大小/熵，dump 全部数据"""
import pefile, os, math
from collections import Counter

p = os.path.join(_BASE, "diannaodian", "work", "pe", "extract10", "raid_unpacked", "Sysset.exe")
outdir = os.path.join(_BASE, "diannaodian", "work", "pe", "extract10", "rsrc_full")
os.makedirs(outdir, exist_ok=True)
pe = pefile.PE(p, fast_load=False)
img = pe.get_memory_mapped_image()

def ent(b):
    if not b: return 0
    c = Counter(b); n = len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values()) if n else 0

def nm(e):
    return str(e.name) if e.name else f"<id {e.struct.Id}>"

count = 0
def walk(e, path, depth):
    global count
    sub = getattr(e, "directory", None)
    if sub is not None:
        for c in sub.entries:
            walk(c, path + [nm(e)], depth+1)
        return
    ed = getattr(e, "data", None)
    if ed is None:
        return
    size = getattr(ed.struct, "Size", None)
    off = getattr(ed.struct, "OffsetToData", None)
    if not size or not off:
        return
    raw = img[off:off+size]
    count += 1
    print(f"[{count:02d}] {'/'.join(path+[nm(e)])}  VA=0x{off:x} size={size} 熵={ent(raw):.2f}  head={raw[:8].hex()}")
    open(os.path.join(outdir, f"r{count:02d}_{'_'.join(x.replace(chr(92),'').replace('/','').replace('<','').replace('>','') for x in path+[nm(e)])}"), "wb").write(raw)

for e in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    walk(e, [], 0)
print("total leaves:", count)
