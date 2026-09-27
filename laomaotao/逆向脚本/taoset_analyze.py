# -*- coding: utf-8 -*-
"""
TaoSet.exe（老毛桃核心组件）静态分析脚本
功能：对 UPX 脱壳后的 TaoSet 二进制做三层分析——
  1) 收割候选密码串（ASCII + UTF-16LE）→ 输出 pwd_cands.txt
  2) 定位关键 UTF-16 日志字符串的 VA 及 .text 内引用点（xref）
  3) 反汇编指定 VA 区间（capstone x86，标注 IAT 符号）

用法（在样本根目录运行，或设置 PE_BASE 环境变量）：
    python taoset_analyze.py scan <脱壳exe路径>
    python taoset_analyze.py xref <脱壳exe路径>
    python taoset_analyze.py dis  <脱壳exe路径> <起始VA十六进制> <长度十六进制>

示例：
    python taoset_analyze.py scan my\\laomaotao\\work\\pkg\\pe_scripts\\pe10_raid\\unpacked\\TaoSet.exe
依赖：pefile / capstone（pip install pefile capstone）
"""
import os
import re
import struct
import sys

try:
    import pefile
except ImportError:
    pefile = None

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    from capstone.x86_const import X86_REG_EAX
except ImportError:
    Cs = None

_BASE = os.environ.get("PE_BASE") or os.getcwd()

# 本次分析定位到的关键日志字符串（函数名/流程名）
KEY_STRINGS = [
    "Extract7zFile_Section: %s 7ZipFile: %s, Pass: %s, Path: %s, Extract: %s, ProcessExitCode: %d",
    "PE-_PE_InstallSysset_InputSupportFile: %s",
    "PE-_PE_InstallSysset_RegFile: %s, FileExists: %s",
    "Extract7zFile_Section: %s not Is7ZipFile: %s, DecodeMethod: %s, Ret: %s, Is7ZipFile: %s",
    "E:\\OneDrive - tp.edu.tw\\Program\\Hutai\\LaoMaoTao\\taoset-delphi\\NativeXml.pas",
]


def _va2off(pe, raw, va):
    rva = va - pe.OPTIONAL_HEADER.ImageBase
    for s in pe.sections:
        size = max(s.Misc_VirtualSize, s.SizeOfRawData)
        if s.VirtualAddress <= rva < s.VirtualAddress + size:
            return s.PointerToRawData + (rva - s.VirtualAddress)
    return None


def _off2va(pe, off):
    for s in pe.sections:
        end = s.PointerToRawData + s.SizeOfRawData
        if s.PointerToRawData <= off < end:
            return pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress + (off - s.PointerToRawData)
    return None


def cmd_scan(exe):
    with open(exe, "rb") as f:
        d = f.read()
    cands = set()
    for m in re.finditer(rb"[\x20-\x7e]{4,40}", d):
        cands.add(m.group(0).decode("ascii"))
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){4,40}", d):
        cands.add(m.group(0).decode("utf-16-le", "ignore"))
    filt = set()
    for s in cands:
        if len(s) < 5 or len(s) > 40:
            continue
        if " " in s or "/" in s or "\\" in s:
            continue
        if re.search(r'[.;:|,()\[\]{}<>"\'=]', s):
            continue
        if sum(c.isalnum() for c in s) < len(s) * 0.7:
            continue
        filt.add(s)
    out = os.path.join(_BASE, "my", "laomaotao", "taoset_pwd_cands.txt")
    with open(out, "w", encoding="utf-8") as f:
        for s in sorted(filt):
            f.write(s + "\n")
    print("候选密码串:", len(filt), "->", out)


def cmd_xref(exe):
    if pefile is None:
        print("缺少 pefile")
        return
    raw = open(exe, "rb").read()
    pe = pefile.PE(exe, fast_load=False)
    for t in KEY_STRINGS:
        b = t.encode("utf-16-le") + b"\x00\x00"
        off = raw.find(b)
        va = _off2va(pe, off) if off != -1 else None
        print("STR", repr(t[:48]), "off=%s" % (hex(off) if off != -1 else -1),
              "VA=%s" % (hex(va) if va else None))
        if va is None:
            continue
        text = [s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text"]
        if not text:
            continue
        code = text[0].get_data()
        code_base = pe.OPTIONAL_HEADER.ImageBase + text[0].VirtualAddress
        pat = struct.pack("<I", va)
        xs = [m.start() for m in re.finditer(re.escape(pat), code)]
        print("   xref:", [hex(code_base + x) for x in xs[:10]], "count", len(xs))


def cmd_dis(exe, start_hex, length_hex):
    if pefile is None or Cs is None:
        print("缺少 pefile/capstone")
        return
    start = int(start_hex, 16)
    length = int(length_hex, 16)
    raw = open(exe, "rb").read()
    pe = pefile.PE(exe, fast_load=False)
    off = _va2off(pe, raw, start)
    if off is None:
        print("VA 不在文件内")
        return
    code = raw[off:off + length]
    iat = {}
    for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = e.dll.decode(errors="replace")
        for imp in e.imports:
            if imp.name:
                iat[imp.address] = dll + "!" + imp.name.decode(errors="replace")
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    md.skipdata = True
    for ins in md.disasm(code, start):
        line = "0x%x: %-8s %s" % (ins.address, ins.mnemonic, ins.op_str)
        m = re.search(r"\[(0x[0-9a-fA-F]+)\]", ins.op_str)
        if m and int(m.group(1), 16) in iat:
            line += "  ; -> " + iat[int(m.group(1), 16)]
        if ins.mnemonic in ("call", "jmp"):
            m2 = re.search(r"0x[0-9a-fA-F]+", ins.op_str)
            if m2 and int(m2.group(0), 16) in iat:
                line += "  ; -> " + iat[int(m2.group(0), 16)]
        print(line)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    mode = sys.argv[1]
    exe = sys.argv[2]
    if mode == "scan":
        cmd_scan(exe)
    elif mode == "xref":
        cmd_xref(exe)
    elif mode == "dis" and len(sys.argv) == 5:
        cmd_dis(exe, sys.argv[3], sys.argv[4])
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
