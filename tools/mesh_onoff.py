"""Client Bluetooth Mesh minimal via GATT Proxy (bleak) pour les ampoules Nordlux Smart (PHY6222).

IMPORTANT : sur ces ampoules, les commandes SIG standard (Generic OnOff, Light Lightness) sont
acquittées mais SANS effet sur la lumière. L'app Nordlux détourne Light CTL Set ; utiliser :
  nx-on / nx-off      : CTL Set lightness 0, température 10000 (ON) / 15000 (OFF)      [validé]
  nx-bri <0-100>      : CTL Set lightness = %, température = 800 + teinte %, trans. 400 ms [validé]
Le bridge Nordlux, s'il est allumé, peut réimposer l'ancien niveau juste après (constaté une fois).

Clés lues dans mesh/mesh_keys.json (cf. nordlux_mesh_keys.py). Adresse source locale et
numéro de séquence persistés dans mesh/local_state.json (ne jamais réutiliser un SEQ).

Usage (--mac = proxy BLE, --dst = adresse unicast du nœud) :
  python mesh_onoff.py nx-on  --mac AA:BB:CC:DD:EE:FF --dst 0x2005
  python mesh_onoff.py nx-off --mac ... --dst ...
  python mesh_onoff.py nx-bri 40 --mac ... --dst ... [--cct-pct 100] [--listen 15]
  python mesh_onoff.py status --mac ... --dst ...      # diagnostic : états standard (sans lien avec la lumière)
  python mesh_onoff.py on|off|bri|cct|test|test-bri    # commandes standard, diagnostic seulement
  python mesh_onoff.py selftest                        # vecteurs de test de la spécification Mesh
"""
import argparse, asyncio, json, os, sys, time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.cmac import CMAC

MESH = Path(__file__).resolve().parent.parent / "mesh"
PROXY_IN = "00002add-0000-1000-8000-00805f9b34fb"
PROXY_OUT = "00002ade-0000-1000-8000-00805f9b34fb"


# ------------------------------------------------------------------ crypto Mesh
def cmac(key, msg):
    c = CMAC(algorithms.AES(key)); c.update(msg); return c.finalize()


def aes_ecb(key, block):
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return e.update(block) + e.finalize()


def s1(m): return cmac(bytes(16), m)
def k1(n, salt, p): return cmac(cmac(salt, n), p)
def k3(n): return k1(n, s1(b"smk3"), b"id64\x01")[-8:]
def k4(n): return cmac(cmac(s1(b"smk4"), n), b"id6\x01")[-1] & 0x3F


def k2(n, p=b"\x00"):
    t = cmac(s1(b"smk2"), n)
    t1 = cmac(t, p + b"\x01"); t2 = cmac(t, t1 + p + b"\x02"); t3 = cmac(t, t2 + p + b"\x03")
    return t1[15] & 0x7F, t2, t3


def xor(a, b): return bytes(x ^ y for x, y in zip(a, b))


def selftest():
    """Vecteurs de la spécification Mesh Profile (§8.1)."""
    nid, ek, pk = k2(bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00"))
    ok = (nid == 0x7F and ek.hex() == "9f589181a0f50de73c8070c7a6d27f46"
          and pk.hex() == "4c715bd4a64b938f99b453351653124f")
    ok &= k3(bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00")).hex() == "ff046958233db014"
    ok &= k4(bytes.fromhex("3216d1509884b533248541792b877f98")) == 0x38
    return ok


class Mesh:
    def __init__(self, netkey, appkey, iv_index, src, seq):
        self.nid, self.ek, self.pk = k2(netkey)
        self.netid = k3(netkey)
        self.appkey, self.aid = appkey, k4(appkey)
        self.iv, self.src, self.seq = iv_index, src, seq

    def next_seq(self):
        s = self.seq; self.seq += 1; return s

    def _net(self, ctl, ttl, dst, transport, proxy=False):
        seq = self.next_seq()
        ctl_ttl = (ctl << 7) | ttl
        iv4, seq3, src2 = self.iv.to_bytes(4, "big"), seq.to_bytes(3, "big"), self.src.to_bytes(2, "big")
        nonce = bytes([0x03 if proxy else 0x00, 0x00 if proxy else ctl_ttl]) + seq3 + src2 + b"\x00\x00" + iv4
        enc = AESCCM(self.ek, tag_length=8 if ctl else 4).encrypt(nonce, dst.to_bytes(2, "big") + transport, None)
        pecb = aes_ecb(self.pk, b"\x00" * 5 + iv4 + enc[:7])
        return bytes([((self.iv & 1) << 7) | self.nid]) + xor(bytes([ctl_ttl]) + seq3 + src2, pecb[:6]) + enc

    def access_pdu(self, dst, access, ttl=5):
        seq_peek = self.seq  # le SEQ de l'AppNonce doit être celui du paquet réseau
        nonce = b"\x01\x00" + seq_peek.to_bytes(3, "big") + self.src.to_bytes(2, "big") \
            + dst.to_bytes(2, "big") + self.iv.to_bytes(4, "big")
        upper = AESCCM(self.appkey, tag_length=4).encrypt(nonce, access, None)
        if len(upper) > 15:
            raise ValueError("message trop long pour un PDU non segmenté")
        return b"\x00" + self._net(0, ttl, dst, bytes([0x40 | self.aid]) + upper)   # Proxy PDU : réseau

    def proxy_cfg(self, payload):
        return b"\x02" + self._net(1, 0, 0x0000, payload, proxy=True)               # Proxy PDU : config

    def decode(self, pdu):
        """Renvoie (type, src, dst, données) ou None."""
        kind, body = pdu[0] & 0x3F, pdu[1:]
        if kind == 0x01:
            return ("beacon", None, None, body)
        if kind not in (0x00, 0x02) or len(body) < 14 or (body[0] & 0x7F) != self.nid:
            return None
        iv = self.iv if (body[0] >> 7) == (self.iv & 1) else self.iv - 1
        iv4 = iv.to_bytes(4, "big")
        hdr = xor(body[1:7], aes_ecb(self.pk, b"\x00" * 5 + iv4 + body[7:14])[:6])
        ctl, seq3, src = hdr[0] >> 7, hdr[1:4], int.from_bytes(hdr[4:6], "big")
        proxy = kind == 0x02
        nonce = bytes([0x03 if proxy else 0x00, 0x00 if proxy else hdr[0]]) + seq3 + hdr[4:6] + b"\x00\x00" + iv4
        try:
            plain = AESCCM(self.ek, tag_length=8 if ctl else 4).decrypt(nonce, body[7:], None)
        except Exception:
            return None
        dst, tr = int.from_bytes(plain[:2], "big"), plain[2:]
        if proxy:
            return ("proxycfg", src, dst, tr)
        if ctl:
            return ("control", src, dst, tr)
        if tr[0] & 0x80:
            return ("segmented", src, dst, tr)
        if not (tr[0] & 0x40) or (tr[0] & 0x3F) != self.aid:
            return ("other-key", src, dst, tr)
        anonce = b"\x01\x00" + seq3 + hdr[4:6] + plain[:2] + iv4
        try:
            return ("access", src, dst, AESCCM(self.appkey, tag_length=4).decrypt(anonce, tr[1:], None))
        except Exception:
            return None


# ------------------------------------------------------------------ modèles SIG
OP = {  # nom -> (opcode requête, opcode statut attendu)
    "onoff_get": (b"\x82\x01", b"\x82\x04"), "onoff_set": (b"\x82\x02", b"\x82\x04"),
    "light_get": (b"\x82\x4b", b"\x82\x4e"), "light_set": (b"\x82\x4c", b"\x82\x4e"),
    "light_last_get": (b"\x82\x53", b"\x82\x54"), "light_range_get": (b"\x82\x57", b"\x82\x58"),
    "ctl_get": (b"\x82\x5d", b"\x82\x60"), "ctl_set": (b"\x82\x5e", b"\x82\x60"),
    "ctl_range_get": (b"\x82\x62", b"\x82\x63"),
}
u16 = lambda b, i: int.from_bytes(b[i:i + 2], "little")
pct = lambda v: f"{100 * v / 65535:.0f} %"


def transition(ms):
    """Encodage Generic Default Transition Time (pas de 100 ms, 1 s, 10 s ou 10 min)."""
    for res, step in ((0, 100), (1, 1000), (2, 10000), (3, 600000)):
        n = round(ms / step)
        if n <= 0x3E:
            return (res << 6) | n
    return 0x3E | 0xC0


def parse_status(acc):
    op, p = acc[:2], acc[2:]
    if op == b"\x82\x04":
        s = {"on": bool(p[0])}
        if len(p) >= 3: s.update(target_on=bool(p[1]), remaining=p[2])
        return s
    if op == b"\x82\x4e":
        s = {"lightness": u16(p, 0)}
        if len(p) >= 5: s.update(target=u16(p, 2), remaining=p[4])
        return s
    if op == b"\x82\x54":
        return {"last": u16(p, 0)}
    if op in (b"\x82\x58", b"\x82\x63"):
        return {"status": p[0], "min": u16(p, 1), "max": u16(p, 3)}
    if op == b"\x82\x60":
        s = {"lightness": u16(p, 0), "temperature": u16(p, 2)}
        if len(p) >= 9: s.update(target_lightness=u16(p, 4), target_temperature=u16(p, 6), remaining=p[8])
        return s
    return {"raw": acc.hex()}


def describe(acc):
    s = parse_status(acc)
    if "on" in s: return "ON" if s["on"] else "OFF"
    if "temperature" in s: return f"luminosité {pct(s['lightness'])} ({s['lightness']}), {s['temperature']} K"
    if "lightness" in s:
        t = f" → {pct(s['target'])} (transition)" if s.get("remaining") else ""
        return f"luminosité {pct(s['lightness'])} ({s['lightness']}){t}"
    if "last" in s: return f"dernière luminosité non nulle {pct(s['last'])}"
    if "min" in s: return f"plage {s['min']}–{s['max']} (statut {s['status']})"
    return s["raw"]


# ------------------------------------------------------------------ BLE
async def run(args):
    from bleak import BleakClient, BleakScanner

    keys = json.loads((MESH / "mesh_keys.json").read_text(encoding="utf-8"))[0]
    state_f = MESH / "local_state.json"
    state = json.loads(state_f.read_text()) if state_f.exists() else {"src": "0x7F01", "seq": 1}
    src = int(state["src"], 16)
    mesh = Mesh(bytes.fromhex(keys["netKey"]), bytes.fromhex(keys["appKeyValue"]),
                keys.get("ivIndex") or 0, src, state["seq"])

    def save():
        state["seq"] = mesh.seq
        state_f.write_text(json.dumps(state, indent=2))

    print(f"src 0x{src:04X}, seq {mesh.seq}, NID 0x{mesh.nid:02X}, AID 0x{mesh.aid:02X}, Network ID {mesh.netid.hex()}")
    dev = await BleakScanner.find_device_by_address(args.mac, timeout=15)
    if not dev:
        sys.exit("ampoule non trouvée")
    client = None
    for attempt in range(1, 6):
        try:
            client = BleakClient(dev, timeout=20)
            await client.connect()
            break
        except Exception as e:
            print(f"connexion {attempt}/5 échouée : {e!r}")
            await asyncio.sleep(1)
    else:
        sys.exit("pas de connexion")
    q = asyncio.Queue()
    try:
        if not client.services.get_characteristic(PROXY_IN):
            sys.exit("pas de service Mesh Proxy (0x1828) sur cet appareil")
        await client.start_notify(PROXY_OUT, lambda _h, d: q.put_nowait(bytes(d)))
        print(f"connectée (MTU {client.mtu_size})")

        async def recv(timeout, want):
            end = time.monotonic() + timeout
            while (left := end - time.monotonic()) > 0:
                try:
                    raw = await asyncio.wait_for(q.get(), left)
                except asyncio.TimeoutError:
                    break
                r = mesh.decode(raw)
                if r is None:
                    print(f"   (PDU non déchiffrable : {raw[:8].hex()}…)")
                    continue
                if r[0] == "beacon":
                    b = r[3]
                    if b and b[0] == 0x01 and len(b) >= 14:
                        iv = int.from_bytes(b[10:14], "big")
                        print(f"   balise réseau : Network ID {b[2:10].hex()}"
                              f"{' (OK)' if b[2:10] == mesh.netid else ' (≠ !)'}, IV index {iv}, flags 0x{b[1]:02x}")
                        if iv != mesh.iv:
                            mesh.iv = iv
                    continue
                if want(r):
                    return r
                extra = f" [{describe(r[3])}]" if r[0] == "access" and r[3][:2] in (b"\x82\x04", b"\x82\x4e", b"\x82\x60") else ""
                print(f"   {time.strftime('%H:%M:%S')} reçu {r[0]} 0x{(r[1] or 0):04X} -> 0x{(r[2] or 0):04X} : {r[3].hex()}{extra}")
            return None

        await recv(2.0, lambda r: False)          # balise réseau envoyée à la connexion -> IV index

        # Filtre du proxy. "reject" : liste de rejet vide = tout transmettre.
        # "accept" : liste d'autorisation contenant notre adresse (certains proxys ignorent Set Filter Type).
        if args.filter == "reject":
            cfgs = [b"\x00\x01"]
        else:
            cfgs = [b"\x00\x00", b"\x01" + b"".join(a.to_bytes(2, "big") for a in [src] + args.filter_add)]
        for c in cfgs:
            await client.write_gatt_char(PROXY_IN, mesh.proxy_cfg(c), response=False); save()
            r = await recv(3, lambda r: r[0] == "proxycfg")
            print(f"filtre proxy ({args.filter}, {c.hex()}) :", f"statut {r[3].hex()}" if r else "pas de réponse")

        tid = int.from_bytes(os.urandom(1), "big")

        async def req(name, params=b"", label=None, with_tid=False, timeout=4):
            """Envoie un message et attend le statut correspondant ; renvoie le dict décodé ou None."""
            nonlocal tid
            op, st = OP[name]
            if with_tid:
                tid = (tid + 1) & 0xFF
                params = params[:args.tid_pos(name, params)] + bytes([tid]) + params[args.tid_pos(name, params):]
            await client.write_gatt_char(PROXY_IN, mesh.access_pdu(args.dst, op + params), response=False); save()
            r = await recv(timeout, lambda r: r[0] == "access" and r[1] == args.dst and r[3][:2] == st)
            print(f"{label or name:<16} -> " + (describe(r[3]) if r else "pas de réponse"))
            return parse_status(r[3]) if r else None

        trans = b"" if args.transition is None else bytes([transition(args.transition), 0])

        async def set_onoff(v, label):
            return await req("onoff_set", bytes([v]), label, with_tid=True)

        async def set_light(v, label):
            return await req("light_set", v.to_bytes(2, "little") + trans, label, with_tid=True)

        async def set_ctl(light, kelvin, label):
            return await req("ctl_set", light.to_bytes(2, "little") + kelvin.to_bytes(2, "little")
                             + (0).to_bytes(2, "little", signed=True) + trans, label, with_tid=True)

        # Commandes "Nordlux" : l'app (MeshElementControl.setOnOffVirtual / setColorTemperatureVirtual)
        # détourne Light CTL Set : ON = température 10000, OFF = 15000 (lightness 0, transition 0) ;
        # luminosité = lightness en POURCENTAGE (0-100) + température = 800 + teinte en % (0-100), transition 400 ms ;
        # délai = roomNum*5 ms (1 pour un appareil seul) -> 1 pas de 5 ms.
        async def nx_ctl(light_pct, temp, trans_byte, label):
            params = light_pct.to_bytes(2, "little") + temp.to_bytes(2, "little") + (0).to_bytes(2, "little") \
                + bytes([trans_byte, 0x01])
            return await req("ctl_set", params, label, with_tid=True)

        if args.cmd in ("nx-on", "nx-off", "nx-bri"):
            if args.cmd == "nx-on":
                await nx_ctl(0, 10000, 0x00, "nx allumer")
            elif args.cmd == "nx-off":
                await nx_ctl(0, 15000, 0x00, "nx éteindre")
            else:
                await nx_ctl(max(0, min(100, round(args.value))), 800 + max(0, min(100, args.cct_pct)),
                             transition(400), f"nx luminosité {args.value:g} %, blanc {args.cct_pct} %")
            if args.listen:
                print(f"écoute du trafic mesh pendant {args.listen:.0f} s…")
                await recv(args.listen, lambda r: False)
            return

        onoff = await req("onoff_get", label="état")
        initial_on = onoff["on"] if onoff else None

        if args.cmd == "on":
            await set_onoff(1, "allumer")
        elif args.cmd == "off":
            await set_onoff(0, "éteindre")
        elif args.cmd == "test":
            await set_onoff(1, "allumer"); await asyncio.sleep(3)
            await set_onoff(0, "éteindre"); await asyncio.sleep(3)
            if initial_on is not None:
                await set_onoff(int(initial_on), "restauration")
        elif args.cmd == "status":
            await req("light_get", label="luminosité")
            await req("light_last_get", label="dernière lum.")
            await req("light_range_get", label="plage lum.")
            await req("ctl_get", label="CTL", timeout=3)
            await req("ctl_range_get", label="plage temp. (K)", timeout=3)
        elif args.cmd == "bri":
            await set_light(round(args.value * 65535 / 100), f"luminosité {args.value:g} %")
        elif args.cmd == "cct":
            rng = await req("ctl_range_get", label="plage temp. (K)", timeout=3)
            cur = await req("ctl_get", label="CTL actuel", timeout=3)
            if not cur:
                print("Pas de réponse CTL : cette ampoule ne gère pas la température de couleur.")
            else:
                k = int(args.value)
                if rng and rng.get("min") and rng.get("max"):
                    k = max(rng["min"], min(rng["max"], k))
                await set_ctl(cur["lightness"], k, f"température {k} K")
        elif args.cmd == "test-bri":
            # Niveau à restaurer : Lightness Last si l'ampoule le fournit, sinon niveau actuel
            # (si allumée) ou niveau repris à l'allumage (si éteinte).
            last = await req("light_last_get", label="dernière lum.", timeout=2)
            level = last["last"] if last and last["last"] else None
            if level is None:
                if not initial_on:
                    await set_onoff(1, "allumer (lecture)")
                cur = await req("light_get", label="niveau à restaurer")
                level = cur["lightness"] if cur and cur["lightness"] else None
            for p in (100, 50, 20, 5):
                await set_light(round(p * 65535 / 100), f"luminosité {p} %"); await asyncio.sleep(2.5)
            if level:
                await set_light(level, f"restaure {pct(level)}")
            if initial_on is False:
                await set_onoff(0, "restaure OFF")
    finally:
        save()
        if client and client.is_connected:
            await client.disconnect()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["get", "on", "off", "test", "status", "bri", "cct", "test-bri",
                                    "nx-on", "nx-off", "nx-bri", "selftest"])
    ap.add_argument("--cct-pct", type=int, default=100,
                    help="nx-bri : teinte en %% (l'app transmet 800 + pourcentage) ; 100 par défaut")
    ap.add_argument("value", nargs="?", type=float, help="bri : pourcentage 0–100 ; cct : kelvins")
    ap.add_argument("--mac")
    ap.add_argument("--dst", type=lambda s: int(s, 0), help="adresse unicast du nœud (cf. mesh_find_node.py)")
    ap.add_argument("--transition", type=int, help="durée de transition en ms (bri/cct)")
    ap.add_argument("--listen", type=float, default=0, help="après une commande nx-*, écouter le trafic mesh N s")
    ap.add_argument("--filter-add", type=lambda s: [int(x, 0) for x in s.split(",")], default=[],
                    help="adresses supplémentaires pour la liste d'autorisation (ex. 0xC000,0x2005)")
    ap.add_argument("--filter", choices=["reject", "accept"], default="accept",
                    help="configuration du filtre du proxy (accept = liste d'autorisation avec notre adresse)")
    a = ap.parse_args()
    # position du TID dans les paramètres : après OnOff (1 o), Lightness (2 o) ou CTL (6 o)
    a.tid_pos = lambda name, params: {"onoff_set": 1, "light_set": 2, "ctl_set": 6}[name]
    if a.cmd in ("bri", "cct", "nx-bri") and a.value is None:
        ap.error(f"{a.cmd} attend une valeur")
    if a.cmd == "selftest":
        print("vecteurs de la spec Mesh :", "OK" if selftest() else "ÉCHEC")
        sys.exit(0)
    if not a.mac or a.dst is None:
        ap.error("--mac et --dst obligatoires")
    asyncio.run(run(a))
