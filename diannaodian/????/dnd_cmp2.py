# -*- coding: utf-8 -*-
"""电脑店 Sysset.exe 资源提取 + 与大白菜(DBC_*)/老毛桃(LMT_*)三方 SHA-256 比对
采用 dnd_rsrc_dump.py 验证过的完整 walk，叶子名为路径中非 "id N" 的命名段。"""
import pefile, os, hashlib, re, sys

sysset = r"d:\文档\workbuddy\Safe\my\diannaodian\work\pe\extract10\raid_unpacked\Sysset.exe"
outdir = r"d:\文档\workbuddy\Safe\my\diannaodian\work\pe\extract10\sysset_rsrc"
dbc_dir = r"d:\文档\workbuddy\Safe\my\baicai\submit_samples\setsys_rsrc"
lmt_dir = r"d:\文档\workbuddy\Safe\my\laomaotao\work\pkg\pe_scripts\raid_payload\taoset_rsrc"
os.makedirs(outdir, exist_ok=True)

def sha(p):
    h = hashlib.sha256()
    try:
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    except Exception as e:
        print(f"[sha-fail] {p!r}: {e}", file=sys.stderr)
        raise
    return h.hexdigest()

pe = pefile.PE(sysset, fast_load=False)
img = pe.get_memory_mapped_image()

def nm(e):
    return str(e.name) if e.name else f"<id {e.struct.Id}>"

dnd_bytes = {}   # name -> raw bytes
count = 0
def walk(e, path):
    global count
    sub = getattr(e, "directory", None)
    if sub is not None:
        for c in sub.entries:
            walk(c, path + [nm(e)])
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
    # 资源名 = 路径中第一个非 "id N" 段；无则按类型归名（仅 type24 清单映射为 None）
    name = None
    for seg in path + [nm(e)]:
        if not re.fullmatch(r"<id \d+>", seg):
            name = seg
            break
    if name is None:
        segs = path + [nm(e)]
        t = re.match(r"<id (\d+)>", segs[0]).group(1) if segs else "0"
        name = "None" if t == "24" else f"t{t}_{segs[1] if len(segs) > 1 else ''}"
    if name in dnd_bytes:
        print(f"  [warn] 重名 {name} 被覆盖 (先前 {len(dnd_bytes[name])} -> {size})")
    dnd_bytes[name] = raw
    print(f"[{count:02d}] {name:<20} size={size}")

for e in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    walk(e, [])
print(f"total leaves: {count}, 命名资源数: {len(dnd_bytes)}")

# 落盘 DND_* 并映射 name -> 路径
dnd = {}
for n, raw in dnd_bytes.items():
    fn = "DND_" + n.replace("<", "").replace(">", "").replace("/", "_").replace("\\", "_")
    with open(os.path.join(outdir, fn), "wb") as f:
        f.write(raw)
    dnd[n] = os.path.join(outdir, fn)

# 收集三方
dbc = {f[4:]: os.path.join(dbc_dir, f) for f in os.listdir(dbc_dir) if f.startswith("DBC_")}
lmt = {f[4:]: os.path.join(lmt_dir, f) for f in os.listdir(lmt_dir) if f.startswith("LMT_")}

def h_of(mapping, n):
    return sha(mapping[n]) if n in mapping else None

allnames = sorted(set(dbc) | set(lmt) | set(dnd))
print(f"\n{'资源名':<20} {'电脑店':<10} {'大白菜':<10} {'老毛桃':<10} {'DND=DBC':<7} {'DND=LMT':<7}")
for n in allnames:
    hd = h_of(dbc, n); hl = h_of(lmt, n); hn = h_of(dnd, n)
    sd = "相同" if (hn and hd and hn == hd) else ("缺失" if not hd else "不同")
    sl = "相同" if (hn and hl and hn == hl) else ("缺失" if not hl else "不同")
    print(f"{n:<20} {('Y' if hn else '-'):<10} {('Y' if hd else '-'):<10} {('Y' if hl else '-'):<10} {sd:<7} {sl:<7}")

same_d = sum(1 for n in dnd if n in dbc and sha(dnd[n]) == sha(dbc[n]))
same_l = sum(1 for n in dnd if n in lmt and sha(dnd[n]) == sha(lmt[n]))
print(f"\n=== 汇总 ===")
print(f"电脑店 Sysset vs 大白菜 SetSys: {same_d}/{len(set(dbc) & set(dnd))} 个共有资源逐字节相同")
print(f"电脑店 Sysset vs 老毛桃 TaoSet: {same_l}/{len(set(lmt) & set(dnd))} 个共有资源逐字节相同")

# 逐资源哈希表（供报告引用）
print(f"\n=== 逐资源 SHA-256 ===")
for n in allnames:
    line = f"{n}:"
    for tag, m in (("DND", dnd), ("DBC", dbc), ("LMT", lmt)):
        hh = h_of(m, n)
        line += f" {tag}={hh[:16]}.." if hh else f" {tag}=---"
    print(line)
