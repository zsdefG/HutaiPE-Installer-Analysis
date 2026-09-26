# -*- coding: utf-8 -*-
"""PECMD CMPa 'a' 模式解密器 — 算法来源 daiaji/pecmd-decompile (docs/cmpa_cryptography_notes.md)
格式: [0x00] 00000000 + CMPa | [0x08] seed LE | [0x0C] 00000000 | [0x10] XOR(LZ(明文))
明文 UTF-16LE
"""
import struct, sys

K = 0x5aa59669
MODE = 0x14

def unxor(data, seed):
    X = (((seed >> 16) << 16) | ((seed & 0xffff) ^ MODE)) ^ K
    X &= 0xffffffff
    n = 0x10
    out = bytearray()
    for b in data:
        t = ((2 * n + 3) * X) & 0xffffffff
        k = ((t >> 21) & 0x7E) ^ ((t >> 14) & 0xFF) ^ ((t >> 7) & 0xFF) ^ (t & 0xFF)
        out.append(b ^ k)
        n += 1
    return bytes(out)

def unlz(data):
    """LZ77 变体: 4KB 环形窗, 预填 0x20, wpos 从 0xfee 起, 位流 uVar2"""
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
        b = uVar2 & 1
        uVar2 >>= 1
        return b
    try:
        while True:
            if getbit() == 1:
                c = rb()
                window[wpos] = c
                out.append(c)
                wpos = (wpos + 1) & 0xfff
            else:
                a = rb(); b2 = rb()
                off = a | ((b2 & 0xf0) << 4)
                ln = (b2 & 0xf) + 3
                for j in range(ln):
                    c = window[(off + j) & 0xfff]
                    window[wpos] = c
                    out.append(c)
                    wpos = (wpos + 1) & 0xfff
    except IndexError:
        pass
    return bytes(out)

def decrypt(path):
    raw = open(path, "rb").read()
    assert raw[4:8] == b"CMPa", "不是 CMPa 魔数"
    seed = struct.unpack_from("<I", raw, 8)[0]
    mode = raw[7]  # 魔数第4字节 a/M/S
    print(f"[{path}] seed=0x{seed:08x} mode=0x{mode:02x} 数据长度={len(raw)-0x10}")
    xd = unxor(raw[0x10:], seed)
    plain = unlz(xd)
    out_p = path + ".dec"
    open(out_p, "wb").write(plain)
    try:
        txt = plain.decode("utf-16-le")
        open(path + ".dec.txt", "w", encoding="utf-8").write(txt)
        print(f"明文 {len(plain)} bytes -> {out_p} (+.txt), 首80字符: {txt[:80]!r}")
    except Exception as e:
        print("UTF-16 解码失败:", e)

if __name__ == "__main__":
    for p in sys.argv[1:]:
        decrypt(p)
