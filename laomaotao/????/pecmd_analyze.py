# -*- coding: utf-8 -*-
import re, math, sys, collections

ini = open(r"d:\文档\workbuddy\Safe\my\laomaotao\work\pkg\pe_scripts\PECMD.INI", "rb").read()
print(f"PECMD.INI {len(ini)} bytes")
print("前64:", ini[:64].hex(" "))
print("后32:", ini[-32:].hex(" "))
freq = collections.Counter(ini)
ent = -sum((c/len(ini))*math.log2(c/len(ini)) for c in freq.values())
print(f"熵: {ent:.3f} bits/byte | 唯一字节数: {len(freq)}/256")
print("前8字节出现频次:", [freq[b] for b in ini[:8]])
# XOR 单字节密钥尝试: 若明文为文本, 密文 Xor key 后应可见 ASCII
for k in range(256):
    dec = bytes(b ^ k for b in ini[:512])
    score = sum(1 for b in dec if 32 <= b < 127 or b in (9,10,13))
    if score > 400:
        print(f"[XOR候选] key=0x{k:02x} score={score}: {dec[:80]!r}")

exe = open(r"d:\文档\workbuddy\Safe\my\laomaotao\work\pkg\pe_scripts\PECMD.EXE", "rb").read()
print(f"\nPECMD.EXE {len(exe)} bytes")
s = exe.decode("latin1")
print("\n=== CMPS/加密相关 ===")
for m in sorted(set(re.findall(r'[\x20-\x7e]{3,40}', s))):
    if re.search(r'(?i)cmps|decrypt|encrypt|cipher|xor|key|loadini|pecmd\.ini|\.wcs', m):
        print(" ", m)
print("\n=== 疑似密钥/口令串(含@!#等) ===")
for m in sorted(set(re.findall(r'[\x20-\x7e]{6,32}', s))):
    if re.search(r'[A-Za-z0-9]{4,}[!@#$%^&*]{1,}', m) and not re.search(r'(?i)http|\.dll|\.exe|\.sys|\.ini|message|script|command', m):
        print(" ", m)
