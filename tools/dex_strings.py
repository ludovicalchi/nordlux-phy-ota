"""Extrait les chaînes d'un ou plusieurs fichiers .dex et filtre par regex.
Usage : python dex_strings.py <regex> <fichier.dex> [...]  (sortie : fichier<TAB>chaîne)"""
import re, struct, sys, os

def uleb(b, o):
    r = s = 0
    while True:
        x = b[o]; o += 1
        r |= (x & 0x7F) << s; s += 7
        if x < 0x80:
            return r, o

def strings(path):
    b = open(path, "rb").read()
    n, off = struct.unpack("<II", b[0x38:0x40])
    for i in range(n):
        so = struct.unpack("<I", b[off + 4 * i: off + 4 * i + 4])[0]
        _, p = uleb(b, so)
        e = b.index(b"\0", p)
        yield b[p:e].decode("utf-8", "replace")

pat = re.compile(sys.argv[1], re.I)
for f in sys.argv[2:]:
    for s in strings(f):
        if pat.search(s):
            print(f"{os.path.basename(f)}\t{s}")
