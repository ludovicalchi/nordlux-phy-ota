"""Parseur btsnoop (H4) minimal : connexions LE, ATT, focus sur une MAC cible."""
import struct, sys, datetime
from collections import defaultdict

PATH = sys.argv[1]
_pos = [a for a in sys.argv[2:] if not a.startswith("--")]
if not _pos:
    sys.exit("usage : parse_btsnoop.py <btsnoop_hci.log> <MAC cible> [--all]")
TARGET = _pos[0].upper()
VERBOSE_DATA = "--all" in sys.argv

EPOCH_DELTA = 0x00dcddb30f2f8000  # µs entre 0000-01-01 et 1970-01-01

def ts(t):
    return datetime.datetime.fromtimestamp((t - EPOCH_DELTA) / 1e6).strftime("%H:%M:%S.%f")[:-3]

def mac(b):
    return ":".join(f"{x:02X}" for x in reversed(b))

def uuid_str(b):
    if len(b) == 2:
        return f"0x{struct.unpack('<H', b)[0]:04X}"
    h = b[::-1].hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"

ATT_NAMES = {0x01: "ErrorRsp", 0x02: "MTUReq", 0x03: "MTURsp", 0x04: "FindInfoReq", 0x05: "FindInfoRsp",
             0x08: "ReadByTypeReq", 0x09: "ReadByTypeRsp", 0x0A: "ReadReq", 0x0B: "ReadRsp",
             0x10: "ReadByGroupReq", 0x11: "ReadByGroupRsp", 0x12: "WriteReq", 0x13: "WriteRsp",
             0x52: "WriteCmd", 0x1B: "Notify", 0x1D: "Indicate", 0x1E: "Confirm"}
DISC_REASONS = {0x08: "Connection Timeout (supervision)", 0x13: "Remote User Terminated", 0x16: "Local Host Terminated",
                0x3E: "Failed to be Established", 0x22: "LL Response Timeout", 0x3B: "Unacceptable Conn Params",
                0x1F: "Unspecified Error", 0x28: "Instant Passed", 0x3D: "MIC Failure"}

with open(PATH, "rb") as f:
    data = f.read()
assert data[:8] == b"btsnoop\0", "pas un btsnoop"
ver, dlt = struct.unpack(">II", data[8:16])
print(f"btsnoop v{ver} datalink={dlt}, {len(data)} octets")

off = 16
records = []
while off + 24 <= len(data):
    olen, ilen, flags, drops, t = struct.unpack(">IIIIq", data[off:off + 24])
    off += 24
    records.append((t, flags, data[off:off + ilen]))
    off += ilen
print(f"{len(records)} paquets, de {ts(records[0][0])} à {ts(records[-1][0])}\n")

handle_mac = {}
att_handles = defaultdict(dict)  # mac -> {handle: uuid}
reasm = {}
adv_seen = []
create_conn = []
events = []   # (t, text) pour la cible
att_log = []  # (t, mac, dir, opcode, payload)
macs_conn = []

def on_att(t, h, direction, pdu):
    m = handle_mac.get(h, f"handle 0x{h:03X}?")
    if not pdu:
        return
    op = pdu[0]
    att_log.append((t, m, direction, op, pdu[1:]))
    # Cartographie des caractéristiques
    if op == 0x09 and len(pdu) > 2:
        ln = pdu[1]
        body = pdu[2:]
        for i in range(0, len(body) - ln + 1, ln):
            e = body[i:i + ln]
            if ln in (7, 21):  # déclaration de caractéristique
                val_h = struct.unpack("<H", e[3:5])[0]
                att_handles[m][val_h] = (uuid_str(e[5:]), e[2])
    elif op == 0x05 and len(pdu) > 2:
        fmt = pdu[1]
        step = 4 if fmt == 1 else 18
        body = pdu[2:]
        for i in range(0, len(body) - step + 1, step):
            hh = struct.unpack("<H", body[i:i + 2])[0]
            att_handles[m].setdefault(hh, (uuid_str(body[i + 2:i + step]), None))

for t, flags, p in records:
    if not p:
        continue
    direction = "RX" if flags & 1 else "TX"
    typ, p = p[0], p[1:]
    if typ == 0x01 and len(p) >= 3:  # commande HCI
        opc = struct.unpack("<H", p[:2])[0]
        prm = p[3:]
        if opc == 0x200D and len(prm) >= 12:  # LE Create Connection
            create_conn.append((t, mac(prm[6:12])))
        elif opc == 0x2043 and len(prm) >= 10:  # LE Extended Create Connection
            create_conn.append((t, mac(prm[3:9])))
        elif opc == 0x0406 and len(prm) >= 3:  # Disconnect
            h = struct.unpack("<H", prm[:2])[0] & 0xFFF
            if handle_mac.get(h) == TARGET:
                events.append((t, f"→ HCI Disconnect demandé par le téléphone, raison 0x{prm[2]:02X}"))
    elif typ == 0x04 and len(p) >= 2:  # événement HCI
        ev, prm = p[0], p[2:]
        if ev == 0x3E:
            sub = prm[0]
            if sub in (0x01, 0x0A) and len(prm) >= 12:
                st = prm[1]
                h = struct.unpack("<H", prm[2:4])[0] & 0xFFF
                m = mac(prm[6:12])
                if st == 0:
                    handle_mac[h] = m
                macs_conn.append((t, m, h, st))
                if m == TARGET:
                    events.append((t, f"LE Connection Complete status=0x{st:02X} handle=0x{h:03X}"))
            elif sub == 0x02:  # adv report legacy
                n = prm[1]; i = 2
                for _ in range(n):
                    if i + 9 > len(prm): break
                    m = mac(prm[i + 3:i + 9]); dl = prm[i + 9]
                    if m == TARGET: adv_seen.append(t)
                    i += 10 + dl + 1
            elif sub == 0x0D:  # extended adv report
                n = prm[1]; i = 2
                for _ in range(n):
                    if i + 24 > len(prm): break
                    m = mac(prm[i + 3:i + 9]); dl = prm[i + 23]
                    if m == TARGET: adv_seen.append(t)
                    i += 24 + dl
            elif sub == 0x03 and len(prm) >= 10:  # conn update
                h = struct.unpack("<H", prm[2:4])[0] & 0xFFF
                if handle_mac.get(h) == TARGET:
                    itv, lat, to = struct.unpack("<HHH", prm[4:10])
                    events.append((t, f"Conn Update interval={itv*1.25:.2f}ms latency={lat} timeout={to*10}ms"))
            elif sub == 0x0C and len(prm) >= 6:  # PHY update
                h = struct.unpack("<H", prm[2:4])[0] & 0xFFF
                if handle_mac.get(h) == TARGET:
                    events.append((t, f"PHY Update tx={prm[4]} rx={prm[5]}"))
            elif sub == 0x07 and len(prm) >= 11:  # data length change
                h = struct.unpack("<H", prm[1:3])[0] & 0xFFF
                if handle_mac.get(h) == TARGET:
                    events.append((t, f"Data Length Change maxTx={struct.unpack('<H', prm[3:5])[0]}"))
        elif ev == 0x05 and len(prm) >= 4:  # Disconnection Complete
            h = struct.unpack("<H", prm[1:3])[0] & 0xFFF
            m = handle_mac.get(h)
            r = prm[3]
            macs_conn.append((t, m, h, f"DISC 0x{r:02X} {DISC_REASONS.get(r, '')}"))
            if m == TARGET:
                events.append((t, f"Disconnection Complete raison 0x{r:02X} {DISC_REASONS.get(r, '')}"))
    elif typ == 0x02 and len(p) >= 4:  # ACL
        hf, ln = struct.unpack("<HH", p[:4])
        h, pb = hf & 0xFFF, (hf >> 12) & 3
        frag = p[4:4 + ln]
        key = (h, direction)
        if pb in (0, 2):
            if len(frag) < 4: continue
            l2len = struct.unpack("<H", frag[:2])[0]
            reasm[key] = [l2len, bytearray(frag)]
        elif pb == 1 and key in reasm:
            reasm[key][1] += frag
        else:
            continue
        l2len, buf = reasm[key]
        if len(buf) >= l2len + 4:
            cid = struct.unpack("<H", buf[2:4])[0]
            if cid == 0x0004:
                on_att(t, h, direction, bytes(buf[4:4 + l2len]))
            del reasm[key]

print("=== Connexions LE (toutes) ===")
for t, m, h, st in macs_conn:
    flag = "  <== CIBLE" if m == TARGET else ""
    print(f"{ts(t)} handle=0x{h:03X} {m} {st if isinstance(st, str) else f'CONNECT status=0x{st:02X}'}{flag}")

print(f"\n=== LE Create Connection émis ({len(create_conn)}) ===")
for t, m in create_conn:
    print(f"{ts(t)} -> {m}{'  <== CIBLE' if m == TARGET else ''}")

print(f"\n=== Annonces de la cible vues : {len(adv_seen)}", end="")
if adv_seen:
    print(f" (de {ts(adv_seen[0])} à {ts(adv_seen[-1])})")
else:
    print()

print("\n=== Table GATT découverte pour la cible ===")
for hh, (u, props) in sorted(att_handles.get(TARGET, {}).items()):
    print(f"  handle 0x{hh:04X} {u} props={'' if props is None else f'0x{props:02X}'}")

tgt_att = [a for a in att_log if a[1] == TARGET]
print(f"\n=== ATT avec la cible : {len(tgt_att)} PDU ===")
from collections import Counter
cnt = Counter((d, ATT_NAMES.get(op, hex(op))) for _, _, d, op, _ in tgt_att)
for k, v in sorted(cnt.items()):
    print(f"  {k[0]} {k[1]}: {v}")

hmap = att_handles.get(TARGET, {})
def hname(hh):
    u = hmap.get(hh, ("?",))[0]
    short = u.split("-")[0] if "-" in u else u
    return f"0x{hh:04X}({short})"

print("\n=== Chronologie (cible) ===")
merged = [(t, "EVT", e) for t, e in events]
wc_run = []
def flush_wc():
    if wc_run:
        t0, t1, n, tot, h0, first, last = wc_run[0][0], wc_run[-1][0], len(wc_run), sum(len(x[2]) for x in wc_run), wc_run[0][1], wc_run[0][2], wc_run[-1][2]
        merged.append((t0, "ATT", f"TX WriteCmd x{n} sur {hname(h0)}, {tot} octets utiles, {ts(t0)}→{ts(t1)}\n"
                                   f"      1er: {first[:24].hex(' ')}\n      dern: {last[:24].hex(' ')}"))
        wc_run.clear()
for t, m, d, op, pl in tgt_att:
    if op == 0x52 and not VERBOSE_DATA:
        hh = struct.unpack("<H", pl[:2])[0]
        wc_run.append((t, hh, pl[2:]))
        continue
    flush_wc()
    name = ATT_NAMES.get(op, f"op 0x{op:02X}")
    if op in (0x12, 0x52, 0x1B, 0x1D, 0x0A, 0x0B) and len(pl) >= 2 and op not in (0x0B,):
        hh = struct.unpack("<H", pl[:2])[0]
        merged.append((t, "ATT", f"{d} {name} {hname(hh)} [{len(pl)-2}] {pl[2:].hex(' ')}"))
    elif op == 0x01 and len(pl) >= 4:
        merged.append((t, "ATT", f"{d} ErrorRsp req=0x{pl[0]:02X} handle=0x{struct.unpack('<H', pl[1:3])[0]:04X} err=0x{pl[3]:02X}"))
    else:
        merged.append((t, "ATT", f"{d} {name} {pl[:40].hex(' ')}"))
flush_wc()
for t, k, txt in sorted(merged, key=lambda x: x[0]):
    print(f"{ts(t)} {txt}")
