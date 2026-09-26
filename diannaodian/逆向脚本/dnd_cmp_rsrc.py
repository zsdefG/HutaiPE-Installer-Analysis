# -*- coding: utf-8 -*-
import os
_BASE = os.environ.get("PE_BASE") or os.getcwd()
"""电脑店 Sysset.exe 资源提取 + 与大白菜(DBC_*)/老毛桃(LMT_*)三方 SHA-256 比对"""
import pefile, os, hashlib, sys

sysset = os.path.join(_BASE, "diannaodian", "work", "pe", "extract10", "raid_unpacked", "Sysset.exe")
outdir = os.path.join(_BASE, "diannaodian", "work", "pe", "extract10", "sysset_rsrc")
dbc_dir = os.path.join(_BASE, "baicai", "submit_samples", "setsys_rsrc")
lmt_dir = os.path.join(_BASE, "laomaotao", "work", "pkg", "pe_scripts", "raid_payload", "taoset_rsrc")
os.makedirs(outdir, exist_ok=True)

def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

pe = pefile.PE(sysset, fast_load=False)
res = {}
if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
    def walk(entry, path):
        sub = getattr(entry, "directory", None)
        if sub is not None:
            for e in sub.entries:
                walk(e, path + [entry.name])
            return
        try:
            ed = getattr(entry, "data", None)
            name = str(entry.name) if entry.name else f"id{entry.struct.Id}"
            size = getattr(ed, "struct", None) and getattr(ed.struct, "Size", None)
            off = getattr(ed, "struct", None) and getattr(ed.struct, "OffsetToData", None)
            if size and off:
                raw = pe.get_memory_mapped_image()[off:off+size]
                res[name] = raw
        except Exception as e:
            print("  ERR", path, e)
    for e in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        walk(e, [])

print(f"资源总数: {len(res)}")
names = sorted(res.keys())
print("资源名:", ", ".join(names))
for n in names:
    with open(os.path.join(outdir, f"DND_{n}"), "wb") as f:
        f.write(res[n])

# 收集三方言
dbc = {f[4:]: os.path.join(dbc_dir, f) for f in os.listdir(dbc_dir) if f.startswith("DBC_")}
lmt = {f[4:]: os.path.join(lmt_dir, f) for f in os.listdir(lmt_dir) if f.startswith("LMT_")}
dnd = {n: os.path.join(outdir, f"DND_{n}") for n in names}

allnames = sorted(set(dbc) | set(lmt) | set(dnd))
print(f"\n{'资源名':<16} {'电脑店vs大白菜':<12} {'电脑店vs老毛桃':<12} {'三方言':<8}")
for n in allnames:
    hd = sha(dbc[n]) if n in dbc else "-"
    hl = sha(lmt[n]) if n in lmt else "-"
    hn = sha(dnd[n]) if n in dnd else "-"
    same_d = "相同" if hn != "-" and hn == hd else ("缺失" if n not in dbc else "不同")
    same_l = "相同" if hn != "-" and hn == hl else ("缺失" if n not in lmt else "不同")
    tri = "三方一致" if (hn != "-" and hn == hd == hl) else "-"
    print(f"{n:<16} {same_d:<12} {same_l:<12} {tri:<8}")

# 汇总
same_dbc = sum(1 for n in allnames if n in dnd and n in dbc and sha(dnd[n]) == sha(dbc[n]))
same_lmt = sum(1 for n in allnames if n in dnd and n in lmt and sha(dnd[n]) == sha(lmt[n]))
print(f"\n=== 汇总 ===")
print(f"电脑店 Sysset vs 大白菜 SetSys: {same_dbc}/{len(set(dbc)&set(dnd))} 个共有资源逐字节相同")
print(f"电脑店 Sysset vs 老毛桃 TaoSet: {same_lmt}/{len(set(lmt)&set(dnd))} 个共有资源逐字节相同")
