# -*- coding: utf-8 -*-
"""CMPa LZ 解压 4 变体测试: msb(LSB/MSB位流) x abs(距离/绝对索引)"""
import struct

raw = open(r"d:\文档\workbuddy\Safe\my\laomaotao\work\pkg\pe_scripts\PECMD.INI", "rb").read()
K = 0x5aa59669
seed = struct.unpack_from("<I", raw, 8)[0]
X = (((seed >> 16) << 16) | ((seed & 0xffff) ^ 0x14)) ^ K
X &= 0xffffffff
n = 0x10
xd = bytearray()
for b in raw[0x10:]:
    t = ((2 * n + 3) * X) & 0xffffffff
    k = ((t >> 21) & 0x7E) ^ ((t >> 14) & 0xFF) ^ ((t >> 7) & 0xFF) ^ (t & 0xFF)
    xd.append(b ^ k)
    n += 1
data = bytes(xd)

def run(msb, abs_off):
    window = bytearray([0x20] * 4096)
    wpos = 0xfee
    out = bytearray()
    i = 0
    uVar2 = 0
    def rb():
        nonlocal i
        b = data[i]; i += 1
        return b
    def getbit():
        nonlocal uVar2
        if ((uVar2 >> 9) & 1) == 0:
            uVar2 = rb() | 0xff00
        b = (uVar2 >> 8) & 1 if msb else (uVar2 & 1)
        uVar2 = (uVar2 << 1) & 0xffff if msb else (uVar2 >> 1)
        return b
    try:
        while True:
            if getbit() == 1:
                c = rb()
                window[wpos] = c; out.append(c)
                wpos = (wpos + 1) & 0xfff
            else:
                a = rb(); b2 = rb()
                off = a | ((b2 & 0xf0) << 4)
                ln = (b2 & 0xf) + 3
                for j in range(ln):
                    c = window[(off + j) & 0xfff] if abs_off else window[(wpos - off) & 0xfff]
                    window[wpos] = c; out.append(c)
                    wpos = (wpos + 1) & 0xfff
    except IndexError:
        pass
    return bytes(out)

for msb in (False, True):
    for ab in (False, True):
        o = run(msb, ab)
        txt = o.decode("utf-16-le", errors="replace")
        score = sum(1 for ch in txt[:400] if ch in "\n\r ENVI_CALL=EXECLOGOFINDLOADTEAMDEVIPUTF>%:\\/\"'$&*-.@!#_[]")
        print(f"msb={int(msb)} abs={int(ab)}: len={len(o)} score={score} head={o[:20].hex(' ')}")
        print(f"   text: {txt[:80]!r}")
        out_p = r"d:\文档\workbuddy\Safe\my\laomaotao\work\pkg\pe_scripts\PECMD.INI.dec_%d%d" % (msb, ab)
        open(out_p, "wb").write(o)
