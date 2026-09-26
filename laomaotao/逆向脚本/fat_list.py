#!/usr/bin/env python3
"""Minimal FAT12/16 reader: list files recursively, extract all files to outdir."""
import sys, os

def read_fat(img):
    bps = int.from_bytes(img[11:13], 'little')          # bytes per sector
    spc = img[13]                                       # sectors per cluster
    rsvd = int.from_bytes(img[14:16], 'little')         # reserved sectors
    nfats = img[16]
    root_ents = int.from_bytes(img[17:19], 'little')
    tot_sec16 = int.from_bytes(img[19:21], 'little')
    fatsz16 = int.from_bytes(img[22:24], 'little')      # sectors per FAT
    tot_sec = tot_sec16 if tot_sec16 else int.from_bytes(img[32:36], 'little')
    fatsz = fatsz16 if fatsz16 else int.from_bytes(img[36:40], 'little')
    root_off = (rsvd + nfats * fatsz) * bps
    root_sectors = (root_ents * 32 + bps - 1) // bps
    data_off = root_off + root_sectors * bps
    cluster_size = bps * spc
    return bps, spc, fatsz, root_off, root_ents, data_off, cluster_size

def entry_type(attr):
    if attr & 0x10: return 'D'
    return 'F'

def parse_dir(img, start_cluster, path, bps, spc, fatsz, root_off, root_ents, data_off, cluster_size, outdir, depth=0):
    entries = []
    if start_cluster == 0:  # root dir
        off = root_off
        size = root_ents * 32
    else:
        off = data_off + (start_cluster - 2) * cluster_size
        size = 0x7fffffff
    pos = off
    cl = start_cluster
    nxt = None
    while True:
        if pos + 32 > len(img): break
        name = img[pos:pos+11]
        attr = img[pos+11]
        first = int.from_bytes(img[pos+26:pos+28], 'little') | (int.from_bytes(img[pos+20:pos+22], 'little') << 16)
        fsize = int.from_bytes(img[pos+28:pos+32], 'little')
        if name[0] == 0xE5 or name[0] == 0x05: pass
        elif name[0] == 0x2E: pass  # . and ..
        elif name[0] == 0x00:
            if start_cluster != 0:
                # next cluster
                nxt = next_cluster(img, cl, bps, spc, fatsz)
                if nxt < 2 or nxt >= 0xFFF8: break
                cl = nxt
                pos = data_off + (cl - 2) * cluster_size
                continue
            else:
                break
        elif attr == 0x0F:
            pass  # LFN, skip
        else:
            if attr & 0x08:  # volume label
                pos += 32; continue
            typ = entry_type(attr)
            nm = name.decode('cp437', errors='replace').rstrip(' ')
            if attr == 0x10 and name[:3] == b'.': pass
            # clean name
            base = name[:8].decode('cp437', errors='replace').rstrip(' ')
            ext = name[8:11].decode('cp437', errors='replace').rstrip(' ')
            fn = (base + ('.' + ext if ext else ''))
            if typ == 'D':
                entries.append((path + '/' + fn, 'D', first, 0))
            else:
                entries.append((path + '/' + fn, 'F', first, fsize))
        pos += 32

    # extract
    for (fp, typ, cl0, sz) in entries:
        if typ == 'D':
            if cl0 >= 2:
                parse_dir(img, cl0, fp, bps, spc, fatsz, root_off, root_ents, data_off, cluster_size, outdir, depth+1)
        else:
            data = read_file(img, cl0, sz, bps, spc, fatsz, data_off, cluster_size)
            rel = fp.lstrip('/').replace('/', os.sep)
            dst = os.path.join(outdir, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            try:
                open(dst, 'wb').write(data)
            except Exception:
                pass
            if depth <= 2 or sz > 50000:
                print(f'  {fp}  {sz}')

def read_file(img, cl0, size, bps, spc, fatsz, data_off, cluster_size):
    out = bytearray()
    cl = cl0
    while cl >= 2 and len(out) < size:
        off = data_off + (cl - 2) * cluster_size
        out += img[off:off+cluster_size]
        cl = next_cluster(img, cl, bps, spc, fatsz)
        if cl >= 0xFFF8: break
    return bytes(out[:size])

def fat_type(img, bps, spc, fatsz, rsvd, nfats):
    # estimate cluster count
    tot_sec16 = int.from_bytes(img[19:21], 'little')
    tot_sec = tot_sec16 if tot_sec16 else int.from_bytes(img[32:36], 'little')
    root_ents = int.from_bytes(img[17:19], 'little')
    data_sec = tot_sec - (rsvd + nfats*fatsz) - ((root_ents*32 + bps-1)//bps)
    nclusters = data_sec // spc
    return 12 if nclusters < 4085 else 16 if nclusters < 65525 else 32

def next_cluster(img, cl, bps, spc, fatsz):
    global RSVD, NFATS
    ft = fat_type(img, bps, spc, fatsz, RSVD, NFATS)
    fat_off = RSVD * bps
    if ft == 12:
        off = fat_off + cl + cl//2
        e = int.from_bytes(img[off:off+2], 'little')
        return e >> 4 if cl & 1 else e & 0xFFF
    e = int.from_bytes(img[fat_off + cl*2 : fat_off + cl*2 + 2], 'little')
    return e & 0xFFFF

if __name__ == '__main__':
    imgpath = sys.argv[1]
    outdir = sys.argv[2] if len(sys.argv) > 2 else imgpath + '_files'
    img = open(imgpath, 'rb').read()
    bps, spc, fatsz, root_off, root_ents, data_off, cluster_size = read_fat(img)
    global RSVD, NFATS
    RSVD = int.from_bytes(img[14:16], 'little')
    NFATS = img[16]
    print(f'[{os.path.basename(imgpath)}] bps={bps} spc={spc} fatsz={fatsz} root_ents={root_ents} cluster_size={cluster_size}')
    parse_dir(img, 0, '', bps, spc, fatsz, root_off, root_ents, data_off, cluster_size, outdir)
