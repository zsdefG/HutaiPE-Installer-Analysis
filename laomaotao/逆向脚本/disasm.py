# -*- coding: utf-8 -*-
"""LaoMaoTao.exe：定位进程创建/LoadLibrary/文件操作调用点，回溯密码相关字符串"""
import pefile, struct, re
from capstone import *
from capstone.x86_const import *

PATH = r"d:\文档\workbuddy\Safe\my\laomaotao\work\LaoMaoTao.exe"
raw = open(PATH, "rb").read()
pe = pefile.PE(PATH, fast_load=False)

# ---- 1. 收集关键 API 的 IAT 地址 (VA) ----
KEY_APIS = {
    "CreateProcessA": [], "CreateProcessW": [], "WinExec": [], "ShellExecuteA": [],
    "ShellExecuteW": [], "ShellExecuteExA": [], "ShellExecuteExW": [],
    "LoadLibraryA": [], "LoadLibraryW": [], "LoadLibraryExA": [], "LoadLibraryExW": [],
    "GetProcAddress": [], "CreateFileA": [], "CreateFileW": [], "CopyFileA": [],
    "CopyFileW": [], "MoveFileA": [], "MoveFileW": [], "DeleteFileA": [], "DeleteFileW": [],
    "RegSetValueExA": [], "RegSetValueExW": [], "RegCreateKeyExA": [], "RegCreateKeyExW": [],
    "SetWindowsHookExA": [], "SetWindowsHookExW": [], "GetTempPathA": [], "GetTempPathW": [],
    "URLDownloadToFileA": [], "URLDownloadToFileW": [], "InternetOpenUrlA": [], "InternetOpenUrlW": [],
    "HttpSendRequestA": [], "HttpSendRequestW": [], "socket": [], "connect": [], "recv": [],
    "send": [], "WSAStartup": [], "GetModuleFileNameA": [], "GetModuleFileNameW": [],
    "RegOpenKeyExA": [], "RegOpenKeyExW": [], "StartServiceA": [], "StartServiceW": [],
    "CreateServiceA": [], "CreateServiceW": [], "OpenSCManagerA": [], "OpenSCManagerW": [],
    "CreateProcessAsUserA": [], "CreateProcessAsUserW": [], "AdjustTokenPrivileges": [],
    "SeDebugPrivilege": [], "WNetAddConnectionA": [], "WNetAddConnectionW": [],
    "lookupPrivilegeValueA": [], "LookupPrivilegeValueA": [], "LookupPrivilegeValueW": [],
    "GetCurrentProcess": [], "OpenProcessToken": [], "ImpersonateLoggedOnUser": [],
    "FindFirstFileA": [], "FindFirstFileW": [], "WriteFile": [], "ReadFile": [],
    "CreateDirectoryA": [], "CreateDirectoryW": [], "SetFileAttributesA": [], "SetFileAttributesW": [],
}
iat_addr = {}  # IAT slot VA -> api name
for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
    dll = e.dll.decode(errors="replace").lower()
    for imp in e.imports:
        if not imp.name:
            continue
        nm = imp.name.decode(errors="replace")
        iat_addr[imp.address] = nm  # imp.address = IAT VA (imagebase+offset)

print(f"IAT 槽总数: {len(iat_addr)}")

# ---- 2. 全量反汇编 .text ----
text = [s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text"][0]
code = text.get_data()
base_va = pe.OPTIONAL_HEADER.ImageBase + text.VirtualAddress
print(f".text: file 0x{text.PointerToRawData:x} VA 0x{base_va:x} size 0x{len(code):x}")

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
md.skipdata = True

# 收集: (va, mnemonic, op_str)
calls = []      # call 指令
push_imm = []   # push imm32（可能是字符串地址/常量）
import re as _re

hits = []
thunks = {}  # thunk_va -> api name (jmp [IAT])
for ins in md.disasm(code, base_va):
    m = ins.mnemonic
    op = ins.op_str
    if m in ("call", "jmp"):
        mm = _re.match(r"(?:dword ptr )?\[0x([0-9a-fA-F]+)\]", op)
        if mm:
            slot = int(mm.group(1), 16)
            if slot in iat_addr:
                nm = iat_addr[slot]
                if m == "jmp":
                    thunks[ins.address] = nm
                hits.append((ins.address, nm))
        calls.append((ins.address, op))
    elif m == "push" and _re.match(r"^0x[0-9a-fA-F]+$", op):
        v = int(op, 16)
        push_imm.append((ins.address, v))

print(f"call/jmp: {len(calls)}  push imm: {len(push_imm)}  thunks: {len(thunks)}")

# ---- 3. 关键 API 调用点：直接 call [IAT] 或 call thunk ----
print("\n=== 关键 API 调用点 (VA) ===")
seen_hit = set()
for va, name in hits:
    if name in KEY_APIS:
        print(f"  0x{va:x}: call {name}")
        seen_hit.add(va)

# call 到 thunk 的调用点
call_thunk = 0
for va, op in calls:
    if _re.match(r"^0x[0-9a-fA-F]+$", op):
        tgt = int(op, 16)
        if tgt in thunks and thunks[tgt] in KEY_APIS:
            nm = thunks[tgt]
            print(f"  0x{va:x}: call thunk({tgt:#x}) -> {nm}")
            call_thunk += 1
            seen_hit.add(va)
print(f"(直接+thunk 命中 {len(seen_hit)})")

# ---- 4. 查找 push 了 .data/.rdata 中可读字符串地址的指令（回溯 10 条）----
data_rva_lo = pe.OPTIONAL_HEADER.ImageBase + [s for s in pe.sections if s.Name.rstrip(b'\x00')==b'.data'][0].VirtualAddress
data_rva_hi = data_rva_lo + [s for s in pe.sections if s.Name.rstrip(b'\x00')==b'.data'][0].Misc_VirtualSize
rdata_lo = pe.OPTIONAL_HEADER.ImageBase + [s for s in pe.sections if s.Name.rstrip(b'\x00')==b'.rdata'][0].VirtualAddress
rdata_hi = rdata_lo + [s for s in pe.sections if s.Name.rstrip(b'\x00')==b'.rdata'][0].Misc_VirtualSize

print("\n=== push 立即数 → .data/.rdata 区域 (前 60) ===")
cnt = 0
for va, v in push_imm:
    if data_rva_lo <= v < data_rva_hi or rdata_lo <= v < rdata_hi:
        # 读取该地址内容
        if data_rva_lo <= v < data_rva_hi:
            off = text.PointerToRawData + (v - base_va)
        # 简化：统一按 VA->文件偏移算
        rva = v - pe.OPTIONAL_HEADER.ImageBase
        off = None
        for s in pe.sections:
            if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
                off = s.PointerToRawData + (rva - s.VirtualAddress)
                break
        if off is None:
            continue
        chunk = raw[off:off+40]
        if all(0x20 <= c < 0x7f or c == 0 for c in chunk[:32]) and any(0x20 <= c < 0x7f for c in chunk[:8]):
            s = chunk.split(b"\x00")[0].decode("ascii", errors="replace")
            if len(s) >= 3:
                print(f"  0x{va:x}: push 0x{v:x} -> {s!r}")
                cnt += 1
                if cnt >= 60:
                    break
