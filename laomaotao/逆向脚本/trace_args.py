# -*- coding: utf-8 -*-
import os
_BASE = os.environ.get("PE_BASE") or os.getcwd()
"""回溯关键 API 调用点的参数（push 立即数→字符串解析，ASCII+UTF-16）"""
import pefile, struct, re
from capstone import *
from capstone.x86_const import *

PATH = os.path.join(_BASE, "laomaotao", "work", "LaoMaoTao.exe")
raw = open(PATH, "rb").read()
pe = pefile.PE(PATH, fast_load=False)

# 文件偏移<->VA
secs = []
for s in pe.sections:
    secs.append((s.Name.rstrip(b"\x00").decode(errors="replace"), s.VirtualAddress,
                 s.PointerToRawData, s.SizeOfRawData, s.Misc_VirtualSize))

def va_to_off(va):
    rva = va - pe.OPTIONAL_HEADER.ImageBase
    for n, vaddr, praw, sz, vsz in secs:
        if vaddr <= rva < vaddr + max(vsz, sz):
            return praw + (rva - vaddr)
    return None

def read_str(va, maxlen=64):
    off = va_to_off(va)
    if off is None:
        return None
    # ASCII
    chunk = raw[off:off+maxlen]
    s = chunk.split(b"\x00")[0]
    if all(0x20 <= c < 0x7f for c in s) and len(s) >= 2:
        return ("A", s.decode("ascii"))
    # UTF-16
    u = chunk[:maxlen*2]
    try:
        t = u.decode("utf-16le").split("\x00")[0]
        if t and all(0x20 <= ord(c) < 0x7f for c in t) and len(t) >= 2:
            return ("U", t)
    except Exception:
        pass
    return None

text = [s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text"][0]
code = text.get_data()
base_va = pe.OPTIONAL_HEADER.ImageBase + text.VirtualAddress

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
md.skipdata = True

instrs = []
for ins in md.disasm(code, base_va):
    instrs.append((ins.address, ins.mnemonic, ins.op_str))

# 目标调用点 + 名称
targets = {
    0x410ff0: "CreateProcessW",
    0x410e70: "CreateProcessAsUserW",
    0x40df34: "LoadLibraryA",
    0x411354: "LoadLibraryW",
    0x41135c: "LoadLibraryW(2)",
    0x4125f4: "LoadLibraryW(3)",
    0x42b1e9: "LoadLibraryW(4)",
    0x4e499b: "LoadLibraryW(5)",
    0x50ef50: "LoadLibraryW(6)",
    0x529db4: "HttpSendRequestA",
    0x529de4: "InternetOpenUrlW",
    0x529dec: "InternetOpenUrlA",
    0x62ca64: "OpenSCManagerW",
    0x411eac: "SetWindowsHookExW",
    0x5a65e8: "SetWindowsHookExW(2)",
    0x410e90: "LookupPrivilegeValueW",
}

# 反汇编顺序存 dict
addr_idx = {a: i for i, (a, m, o) in enumerate(instrs)}

for tva, name in targets.items():
    print(f"\n===== {name} @ 0x{tva:x} =====")
    if tva not in addr_idx:
        print("  (不在反汇编范围)")
        continue
    i0 = addr_idx[tva]
    # 回溯前 35 条指令（跳过 call）
    seg = instrs[max(0, i0-35):i0+1]
    for a, m, o in seg:
        tag = ""
        if m == "push":
            mm = re.match(r"^0x[0-9a-fA-F]+$", o)
            if mm:
                v = int(o, 16)
                r = read_str(v)
                if r:
                    tag = f"  ; STR[{r[0]}] {r[1]!r}"
                else:
                    tag = f"  ; imm=0x{v:x}"
        elif m in ("mov", "lea") and re.search(r"0x[0-9a-fA-F]+", o):
            mm = re.search(r"0x([0-9a-fA-F]+)", o)
            if mm:
                v = int(mm.group(1), 16)
                r = read_str(v)
                if r:
                    tag = f"  ; STR[{r[0]}] {r[1]!r}"
        print(f"    0x{a:x}: {m} {o}{tag}")
