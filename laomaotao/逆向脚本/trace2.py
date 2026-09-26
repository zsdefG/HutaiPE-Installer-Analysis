# -*- coding: utf-8 -*-
"""LaoMaoTao.exe v2：识别 thunk，定位真正 call 调用点并回溯参数"""
import pefile, struct, re
from capstone import *
from capstone.x86_const import *

PATH = r"d:\文档\workbuddy\Safe\my\laomaotao\work\LaoMaoTao.exe"
raw = open(PATH, "rb").read()
pe = pefile.PE(PATH, fast_load=False)

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
    if off is None or off < 0 or off + 2 > len(raw):
        return None
    chunk = raw[off:off+maxlen]
    s = chunk.split(b"\x00")[0]
    if all(0x20 <= c < 0x7f for c in s) and len(s) >= 2:
        return ("A", s.decode("ascii"))
    try:
        t = chunk.decode("utf-16le").split("\x00")[0]
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
addr_idx = {a: i for i, (a, m, o) in enumerate(instrs)}

# IAT 槽
iat_addr = {}
for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
    for imp in e.imports:
        if imp.name:
            iat_addr[imp.address] = imp.name.decode(errors="replace")

# 1. thunk: jmp [IAT] 在 .text 中
thunks = {}
for a, m, o in instrs:
    if m == "jmp":
        mm = re.match(r"(?:dword ptr )?\[0x([0-9a-fA-F]+)\]", o)
        if mm:
            slot = int(mm.group(1), 16)
            if slot in iat_addr:
                thunks[a] = iat_addr[slot]

# 2. call 到 thunk 的调用点
KEY = {"CreateProcessW", "CreateProcessA", "CreateProcessAsUserW", "CreateProcessAsUserA",
       "WinExec", "ShellExecuteW", "ShellExecuteA", "LoadLibraryW", "LoadLibraryA",
       "LoadLibraryExW", "LoadLibraryExA", "HttpSendRequestA", "HttpSendRequestW",
       "InternetOpenUrlW", "InternetOpenUrlA", "OpenSCManagerW", "OpenSCManagerA",
       "SetWindowsHookExW", "SetWindowsHookExA", "URLDownloadToFileW", "URLDownloadToFileA",
       "GetTempPathW", "GetTempPathA", "GetModuleFileNameW", "GetModuleFileNameA",
       "RegSetValueExW", "RegSetValueExA", "RegCreateKeyExW", "RegCreateKeyExA",
       "LookupPrivilegeValueW", "LookupPrivilegeValueA", "AdjustTokenPrivileges",
       "CopyFileW", "CopyFileA", "MoveFileW", "MoveFileA", "GetProcAddress",
       "socket", "connect", "WSAStartup", "InternetConnectA", "InternetConnectW",
       "FtpPutFileA", "FtpPutFileW", "StartServiceW", "StartServiceA", "CreateServiceW",
       "CreateServiceA", "OpenSCManagerW", "OpenSCManagerA", "RegDeleteValueW",
       "RegDeleteKeyW", "ShellExecuteExW", "ShellExecuteExA"}
call_sites = {}
for a, m, o in instrs:
    if m == "call" and re.match(r"^0x[0-9a-fA-F]+$", o):
        tgt = int(o, 16)
        if tgt in thunks and thunks[tgt] in KEY:
            call_sites.setdefault(thunks[tgt], []).append(a)

print("=== 关键 API 调用点（真正 call 点）===")
for name, sites in sorted(call_sites.items()):
    print(f"  {name}: {', '.join(hex(x) for x in sites)}")

# 3. 对每个调用点回溯参数
for name, sites in call_sites.items():
    for cs_va in sites:
        if cs_va not in addr_idx:
            continue
        i0 = addr_idx[cs_va]
        print(f"\n===== {name} @ 0x{cs_va:x} =====")
        seg = instrs[max(0, i0-25):i0+1]
        for a, m, o in seg:
            tag = ""
            if m == "push":
                mm = re.match(r"^0x[0-9a-fA-F]+$", o)
                if mm:
                    v = int(o, 16)
                    r = read_str(v)
                    tag = f"  ; STR[{r[0]}] {r[1]!r}" if r else f"  ; imm=0x{v:x}"
            elif m in ("mov", "lea") and re.search(r"0x[0-9a-fA-F]+", o):
                mm = re.search(r"0x([0-9a-fA-F]+)", o)
                if mm:
                    v = int(mm.group(1), 16)
                    r = read_str(v)
                    if r:
                        tag = f"  ; STR[{r[0]}] {r[1]!r}"
            print(f"    0x{a:x}: {m} {o}{tag}")
