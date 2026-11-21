"""Paquets ACL envoyés vs acquittés par le contrôleur (Number of Completed Packets) pour un handle, dans une fenêtre."""
import struct, sys, datetime
EPOCH_DELTA = 0x00dcddb30f2f8000
def ts(t): return datetime.datetime.fromtimestamp((t - EPOCH_DELTA) / 1e6).strftime("%H:%M:%S.%f")[:-3]
path, handle = sys.argv[1], int(sys.argv[2], 16)
d = open(path, "rb").read(); off = 16
while off + 24 <= len(d):
    olen, ilen, flags, drops, t = struct.unpack(">IIIIq", d[off:off+24]); off += 24
    p = d[off:off+ilen]; off += ilen
    if not p: continue
    rx = flags & 1
    if p[0] == 2:
        hf, ln = struct.unpack("<HH", p[1:5])
        if hf & 0xFFF == handle:
            print(f"{ts(t)} {'RX' if rx else 'TX'} ACL pb={(hf>>12)&3} len={ln}")
    elif p[0] == 4 and p[1] == 0x13:
        n = p[3]
        for i in range(n):
            h, c = struct.unpack("<HH", p[4+4*i:8+4*i])
            if h & 0xFFF == handle:
                print(f"{ts(t)}    NOCP completed={c}")
    elif p[0] == 4 and p[1] == 0x3E and p[3] == 0x03:
        h = struct.unpack("<H", p[5:7])[0] & 0xFFF
        if h == handle: print(f"{ts(t)}    ConnUpdate")
