"""Ajout d'une ampoule Nordlux Smart au réseau mesh SANS l'app.

MÉTHODE NORDLUX (ampoules PHY6222 réinitialisées, commande `nx-add`) — v2/bleMeshSilicon/net/InformationConfigOfDevices2,
request/ConfigNodeRequest : après réinitialisation, l'ampoule rejoint seule un réseau d'usine (Mesh Proxy 0x1828, Node
Identity d'un autre réseau) et ses données fabricant 0x6E78 indiquent « clés non configurées » (octets 7–10 = 0000).
L'app écrit alors en clair, sur le service 4d124bf0 (caractéristique da3c026f, réponses JSON sur 3db871af), 6 messages
de 18 octets : « CMD » 01 21 00 00 <adresse actuelle, 2 o tels qu'annoncés> 08 + 8 octets :
  1 : 01 NetKey[0..6]     2 : 02 NetKey[7..13]    3 : 03 64 NetKey[14..15] <nouvelle adresse LE> <n° de pièce> 64
  4 : 04 AppKey[0..6]     5 : 05 AppKey[7..13]    6 : 06 00 AppKey[14..15] <adresse de publication LE (C000)> 00 00
L'ampoule se reconfigure seule (liaisons, abonnements). Aucune devKey n'est échangée.

MÉTHODE STANDARD (commande `provision`, appareils annonçant 0x1827) : provisioning PB-GATT puis configuration,
en reproduisant l'app Android (ble_mesh/silicon/ProvisioningModel + ConfigurationLightOperation).

Étapes reproduites :
  1. provisioning sans OOB (service 0x1827) : NetKey, IV index, adresse unicast -> devKey propre au nœud ;
  2. configuration avec la devKey : GATT Proxy activé, Relay activé, AppKey Add (index 0), puis pour les
     modèles SIG 0x1000/0x1300/0x1303/0x1306 et les modèles vendeur : App Bind + abonnement au groupe C000.
     Calé sur une Candle DIM configurée par l'app et relue avec read-config : pas de publication
     (option --publish pour la publication C000 TTL 5 demandée par le code de l'app), relais 0x01 ;
  3. signal de fin de l'app : Light CTL Set « virtuel » lightness 101, température 900.

Une ampoule ajoutée ainsi est pilotable localement (Home Assistant, mesh_onoff.py) mais inconnue de l'app et du cloud.
Pour la rendre à l'app : réinitialisation (3 allumages/extinctions), puis ajout normal dans l'app.

Clés : mesh/mesh_keys.json (nordlux_mesh_keys.py). Adresse source 0x7F01 et SEQ : mesh/local_state.json
(partagés avec mesh_onoff.py). Nœuds ajoutés, avec leur devKey : mesh/provisioned.json (SECRET, ne pas publier).

Usage :
  python mesh_provision.py scan                                    # ampoules Nordlux (état des clés) et appareils 0x1827
  python mesh_provision.py nx-add --mac AA:BB:CC:DD:EE:FF [--addr 0x7E00] [--room-num 1] [--name Salon]
  python mesh_provision.py provision --mac AA:BB:CC:DD:EE:FF [--addr 0x7E00] [--name Salon] [--proxy MAC_BRIDGE]
  python mesh_provision.py configure --mac MAC_PROXY --dst 0x7E00  # (re)configuration d'un nœud de provisioned.json
  python mesh_provision.py read-config --mac MAC_PROXY --dst 0x2005  # lecture seule (devKey du cloud ou de provisioned.json)
  python mesh_provision.py selftest                                # tests hors radio
"""
import argparse, asyncio, importlib.util, json, os, struct, sys, time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

ROOT = Path(__file__).resolve().parent.parent
MESH_DIR = ROOT / "mesh"
# Cœur mesh partagé avec l'intégration Home Assistant (ha-nordlux-mesh) : copie locale nx_mesh.py si présente.
_MESH_PY = Path(__file__).resolve().parent / "nx_mesh.py"
if not _MESH_PY.exists():
    _MESH_PY = ROOT / "ha/custom_components/nordlux_mesh/mesh.py"
_spec = importlib.util.spec_from_file_location("nx_mesh", _MESH_PY)
nx = importlib.util.module_from_spec(_spec)
sys.modules["nx_mesh"] = nx
_spec.loader.exec_module(nx)

PROV_SERVICE = "00001827-0000-1000-8000-00805f9b34fb"
PROV_IN = "00002adb-0000-1000-8000-00805f9b34fb"
PROV_OUT = "00002adc-0000-1000-8000-00805f9b34fb"
PROXY_SERVICE, PROXY_IN, PROXY_OUT = nx.PROXY_SERVICE, nx.PROXY_IN, nx.PROXY_OUT
NX_SERVICE = "4d124bf0-fee0-44bd-947f-e668f1228a9d"
NX_WRITE = "da3c026f-4f76-48e5-ab29-be11daa3604c"
NX_NOTIFY = "3db871af-558c-40ea-bb4f-f9991217a72f"
NX_COMPANY = 0x6E78  # 28280, données fabricant des ampoules Nordlux/Yankon

GROUP = 0xC000                      # « default group » de la maison (toutes les pièces publient ici)
ADDR_RANGE = range(0x7E00, 0x7F00)  # plage réservée aux nœuds ajoutés hors de l'app
SIG_TARGETS = (0x1000, 0x1300, 0x1303, 0x1306)  # OnOff, Lightness, CTL, CTL Temperature (serveurs)
# Relay Retransmit : le code de l'app demande 3 retransmissions / 20 ms pour le PHY6222, mais une Candle DIM
# configurée par l'app relue le 26/11/2026 indique 0x01 (1 retransmission, 10 ms) : on reproduit l'état réel.
RELAY_RETRANSMIT = 0x01

PROV_FAIL = {1: "PDU invalide", 2: "format invalide", 3: "PDU inattendu", 4: "échec de confirmation",
             5: "ressources insuffisantes", 6: "échec de déchiffrement", 7: "erreur inattendue",
             8: "adresse impossible à attribuer"}
CFG_STATUS = {0: "OK", 1: "adresse invalide", 2: "modèle invalide", 3: "AppKey index invalide",
              4: "NetKey index invalide", 5: "ressources insuffisantes", 6: "clé déjà enregistrée",
              7: "publication invalide", 8: "non abonnable", 0x0C: "impossible à mettre à jour",
              0x0D: "non pris en charge"}


class ProvError(Exception):
    pass


# ------------------------------------------------------------------ couche proxy (SAR)
def sar_split(msg_type: int, data: bytes, chunk: int) -> list[bytes]:
    """Découpe un message proxy en écritures GATT de `chunk` octets (en-tête SAR compris)."""
    if len(data) + 1 <= chunk:
        return [bytes([msg_type]) + data]
    parts = [data[i:i + chunk - 1] for i in range(0, len(data), chunk - 1)]
    return [bytes([(0x40 if i == 0 else 0xC0 if i == len(parts) - 1 else 0x80) | msg_type]) + p
            for i, p in enumerate(parts)]


class SarRx:
    def __init__(self):
        self.buf, self.type = None, None

    def feed(self, pdu: bytes):
        sar, t = pdu[0] >> 6, pdu[0] & 0x3F
        if sar == 0:
            return t, pdu[1:]
        if sar == 1:
            self.buf, self.type = bytearray(pdu[1:]), t
            return None
        if self.buf is None:
            return None
        self.buf += pdu[1:]
        if sar == 3:
            out, self.buf = (self.type, bytes(self.buf)), None
            return out
        return None


# ------------------------------------------------------------------ provisioning (PB-GATT, sans OOB)
class ProvLink:
    def __init__(self, client, chunk: int):
        self.c, self.chunk, self.q, self.sar = client, chunk, asyncio.Queue(), SarRx()

    async def start(self):
        await self.c.start_notify(PROV_OUT, self._on_notify)

    def _on_notify(self, _h, data):
        r = self.sar.feed(bytes(data))
        if r and r[0] == 0x03:
            self.q.put_nowait(r[1])

    async def send(self, pdu: bytes):
        for part in sar_split(0x03, pdu, self.chunk):
            await self.c.write_gatt_char(PROV_IN, part, response=False)
            await asyncio.sleep(0.02)

    async def expect(self, ptype: int, timeout: float = 20.0) -> bytes:
        try:
            pdu = await asyncio.wait_for(self.q.get(), timeout)
        except asyncio.TimeoutError:
            raise ProvError(f"pas de réponse de l'ampoule (PDU {ptype:#04x} attendu)") from None
        if pdu[0] == 0x09:
            code = pdu[1] if len(pdu) > 1 else -1
            raise ProvError(f"provisioning refusé par l'ampoule : code {code} ({PROV_FAIL.get(code, '?')})")
        if pdu[0] != ptype:
            raise ProvError(f"PDU {pdu[0]:#04x} reçu, {ptype:#04x} attendu")
        return pdu[1:]


def prov_confirmation(conf_key: bytes, rand: bytes, auth: bytes = bytes(16)) -> bytes:
    return nx._cmac(conf_key, rand + auth)


def prov_session(secret: bytes, conf_salt: bytes, rand_p: bytes, rand_d: bytes):
    """Clé et nonce de session, devKey (Mesh Profile §5.4.2.5)."""
    salt = nx.s1(conf_salt + rand_p + rand_d)
    return (nx.k1(secret, salt, b"prsk"), nx.k1(secret, salt, b"prsn")[-13:], nx.k1(secret, salt, b"prdk"))


def prov_data(netkey: bytes, iv: int, addr: int, key_index: int = 0, flags: int = 0) -> bytes:
    return netkey + key_index.to_bytes(2, "big") + bytes([flags]) + iv.to_bytes(4, "big") + addr.to_bytes(2, "big")


async def provision(link: ProvLink, netkey: bytes, iv: int, addr: int, attention: int = 5):
    invite = bytes([attention])
    await link.send(b"\x00" + invite)
    caps = await link.expect(0x01)
    n_el, algs, pk_type, static_oob = caps[0], int.from_bytes(caps[1:3], "big"), caps[3], caps[4]
    print(f"  capacités : {n_el} élément(s), algorithmes 0x{algs:04x}, clé publique OOB {pk_type}, "
          f"OOB statique {static_oob}, sortie {caps[5]}/{caps[6:8].hex()}, entrée {caps[8]}/{caps[9:11].hex()}")
    if not algs & 0x0001:
        raise ProvError("l'ampoule ne propose pas FIPS P-256")
    start = bytes([0x00, 0x00, 0x00, 0x00, 0x00])  # P-256/CMAC, pas de clé OOB, pas d'authentification OOB
    await link.send(b"\x02" + start)

    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    pub = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
    await link.send(b"\x03" + pub)
    dev_pub = await link.expect(0x03)
    if len(dev_pub) != 64:
        raise ProvError("clé publique de l'ampoule invalide")
    dpk = ec.EllipticCurvePublicNumbers(int.from_bytes(dev_pub[:32], "big"), int.from_bytes(dev_pub[32:], "big"),
                                        ec.SECP256R1()).public_key()
    secret = priv.exchange(ec.ECDH(), dpk)

    conf_salt = nx.s1(invite + caps + start + pub + dev_pub)
    conf_key = nx.k1(secret, conf_salt, b"prck")
    rand_p = os.urandom(16)
    await link.send(b"\x05" + prov_confirmation(conf_key, rand_p))
    conf_d = await link.expect(0x05)
    await link.send(b"\x06" + rand_p)
    rand_d = await link.expect(0x06)
    if prov_confirmation(conf_key, rand_d) != conf_d:
        raise ProvError("confirmation de l'ampoule incorrecte")
    sess_key, sess_nonce, devkey = prov_session(secret, conf_salt, rand_p, rand_d)
    enc = AESCCM(sess_key, tag_length=8).encrypt(sess_nonce, prov_data(netkey, iv, addr), None)
    await link.send(b"\x07" + enc)
    await link.expect(0x08, timeout=30)
    return devkey, n_el


# ------------------------------------------------------------------ messages de configuration (devKey)
class CfgNetwork(nx.MeshNetwork):
    """MeshNetwork + clé de nœud (AKF=0), segmentation et réassemblage."""

    def dev_pdus(self, dst: int, access: bytes, devkey: bytes, ttl: int = 5) -> list[bytes]:
        seq0 = self._seq_alloc()
        nonce = (b"\x02\x00" + seq0.to_bytes(3, "big") + self.src.to_bytes(2, "big")
                 + dst.to_bytes(2, "big") + self.iv.to_bytes(4, "big"))
        upper = AESCCM(devkey, tag_length=4).encrypt(nonce, access, None)
        if len(upper) <= 15:
            return [b"\x00" + self._net(0, ttl, dst, b"\x00" + upper, seq0)]
        segs = [upper[i:i + 12] for i in range(0, len(upper), 12)]
        out = []
        for o, seg in enumerate(segs):
            hdr = ((seq0 & 0x1FFF) << 10) | (o << 5) | (len(segs) - 1)  # SZMIC 0
            seq = seq0 if o == 0 else self._seq_alloc()
            out.append(b"\x00" + self._net(0, ttl, dst, b"\x80" + hdr.to_bytes(3, "big") + seg, seq))
        return out

    def seg_ack_pdu(self, dst: int, seqzero: int, block: int, ttl: int = 5) -> bytes:
        payload = b"\x00" + (seqzero << 2).to_bytes(2, "big") + block.to_bytes(4, "big")
        return b"\x00" + self._net(1, ttl, dst, payload, self._seq_alloc())

    def decode_net(self, pdu: bytes):
        """PDU réseau -> dict(src, dst, seq, ctl, tr) ; None si autre type ou autre réseau."""
        if not pdu or (pdu[0] & 0x3F) != 0x00 or len(pdu) < 15:
            return None
        body = pdu[1:]
        if (body[0] & 0x7F) != self.nid:
            return None
        iv = self.iv if (body[0] >> 7) == (self.iv & 1) else self.iv - 1
        iv4 = iv.to_bytes(4, "big")
        hdr = nx._xor(body[1:7], nx.aes_ecb(self.pk, b"\x00" * 5 + iv4 + body[7:14])[:6])
        ctl = hdr[0] >> 7
        nonce = bytes([0x00, hdr[0]]) + hdr[1:4] + hdr[4:6] + b"\x00\x00" + iv4
        try:
            plain = AESCCM(self.ek, tag_length=8 if ctl else 4).decrypt(nonce, body[7:], None)
        except Exception:  # noqa: BLE001
            return None
        return {"src": int.from_bytes(hdr[4:6], "big"), "dst": int.from_bytes(plain[:2], "big"),
                "seq": int.from_bytes(hdr[1:4], "big"), "ctl": ctl, "tr": plain[2:], "iv": iv}

    def open_upper(self, m: dict, upper: bytes, seq_auth: int, akf: int, szmic: int, key: bytes) -> bytes | None:
        first = b"\x01" if akf else b"\x02"
        nonce = (first + bytes([szmic << 7]) + seq_auth.to_bytes(3, "big") + m["src"].to_bytes(2, "big")
                 + m["dst"].to_bytes(2, "big") + m["iv"].to_bytes(4, "big"))
        try:
            return AESCCM(key, tag_length=8 if szmic else 4).decrypt(nonce, upper, None)
        except Exception:  # noqa: BLE001
            return None


class Reassembler:
    def __init__(self):
        self.sessions = {}

    def feed(self, m: dict):
        """Segment reçu -> (complet, données de session)."""
        tr = m["tr"]
        h = int.from_bytes(tr[1:4], "big")
        szmic, seqzero, sego, segn = h >> 23, (h >> 10) & 0x1FFF, (h >> 5) & 0x1F, h & 0x1F
        seq_auth = (m["seq"] & ~0x1FFF) | seqzero
        if seq_auth > m["seq"]:
            seq_auth -= 0x2000
        key = (m["src"], seq_auth)
        s = self.sessions.setdefault(key, {"segs": {}, "segn": segn, "akf": (tr[0] >> 6) & 1, "szmic": szmic,
                                           "seqzero": seqzero, "seq_auth": seq_auth, "done": False})
        s["segs"][sego] = tr[4:]
        complete = len(s["segs"]) == segn + 1
        return complete, s


def model_bytes(model) -> bytes:
    if isinstance(model, tuple):  # (company, id) : modèle vendeur
        return model[0].to_bytes(2, "little") + model[1].to_bytes(2, "little")
    return model.to_bytes(2, "little")


def model_name(model) -> str:
    return f"{model[0]:04X}:{model[1]:04X}" if isinstance(model, tuple) else f"{model:04X}"


def parse_composition(data: bytes) -> dict:
    d = data[1:]  # page
    cid, pid, vid, crpl, feat = struct.unpack("<HHHHH", d[:10])
    i, elements = 10, []
    while i + 4 <= len(d):
        loc, ns, nv = struct.unpack("<HBB", d[i:i + 4])
        i += 4
        sig = [int.from_bytes(d[i + 2 * k:i + 2 * k + 2], "little") for k in range(ns)]
        i += 2 * ns
        ven = [(int.from_bytes(d[i + 4 * k:i + 4 * k + 2], "little"), int.from_bytes(d[i + 4 * k + 2:i + 4 * k + 4], "little"))
               for k in range(nv)]
        i += 4 * nv
        elements.append({"loc": loc, "sig": sig, "vendor": ven})
    return {"cid": cid, "pid": pid, "vid": vid, "crpl": crpl, "features": feat, "elements": elements}


class ConfigClient:
    def __init__(self, client, net: CfgNetwork, devkey: bytes, dst: int, save, appkey: bytes):
        self.c, self.net, self.devkey, self.dst, self.save, self.appkey = client, net, devkey, dst, save, appkey
        self.q, self.rx = asyncio.Queue(), Reassembler()

    async def open(self):
        await self.c.start_notify(PROXY_OUT, lambda _h, d: self.q.put_nowait(bytes(d)))
        await self._drain(1.5)
        for cfg in (b"\x00\x00", b"\x01" + self.net.src.to_bytes(2, "big")):  # liste d'autorisation + notre adresse
            await self._write(self.net.proxy_cfg_pdu(cfg))
        await self._drain(0.5)

    async def _write(self, pdu: bytes):
        await self.c.write_gatt_char(PROXY_IN, pdu, response=False)
        self.save()

    async def _drain(self, timeout: float):
        end = time.monotonic() + timeout
        while (left := end - time.monotonic()) > 0:
            try:
                raw = await asyncio.wait_for(self.q.get(), left)
            except asyncio.TimeoutError:
                return
            if raw and (raw[0] & 0x3F) == 0x01 and len(raw) >= 15 and raw[1] == 0x01:
                self.net.iv = int.from_bytes(raw[11:15], "big")

    async def _receive(self, timeout: float):
        """Messages d'accès reçus du nœud, déchiffrés (devKey ou AppKey)."""
        end = time.monotonic() + timeout
        while (left := end - time.monotonic()) > 0:
            try:
                raw = await asyncio.wait_for(self.q.get(), left)
            except asyncio.TimeoutError:
                return
            m = self.net.decode_net(raw)
            if not m or m["dst"] != self.net.src or not (self.dst <= m["src"] < self.dst + 16):
                continue
            tr = m["tr"]
            if m["ctl"]:
                continue  # acquittement de segments : on se fie au statut
            akf = (tr[0] >> 6) & 1
            key = self.appkey if akf else self.devkey
            if tr[0] & 0x80:
                complete, s = self.rx.feed(m)
                if complete and not s["done"]:
                    s["done"] = True
                    await self._write(self.net.seg_ack_pdu(m["src"], s["seqzero"], (1 << (s["segn"] + 1)) - 1))
                    upper = b"".join(s["segs"][i] for i in range(s["segn"] + 1))
                    acc = self.net.open_upper(m, upper, s["seq_auth"], s["akf"], s["szmic"], key)
                    if acc is not None:
                        yield m["src"], acc
                elif complete:
                    await self._write(self.net.seg_ack_pdu(m["src"], s["seqzero"], (1 << (s["segn"] + 1)) - 1))
            else:
                acc = self.net.open_upper(m, tr[1:], m["seq"], akf, 0, key)
                if acc is not None:
                    yield m["src"], acc

    async def request(self, access: bytes, status_op: bytes, label: str, timeout: float = 6.0, retries: int = 3) -> bytes:
        for attempt in range(1, retries + 1):
            for pdu in self.net.dev_pdus(self.dst, access, self.devkey):
                await self._write(pdu)
                await asyncio.sleep(0.05)
            async for _src, acc in self._receive(timeout):
                if acc.startswith(status_op):
                    return acc[len(status_op):]
            print(f"   {label} : pas de réponse (essai {attempt}/{retries})")
        raise ProvError(f"{label} : aucune réponse du nœud")

    async def send_app(self, access: bytes):
        await self._write(self.net.access_pdu(self.dst, access))


def check(label: str, status: int, ok=(0,)):
    txt = CFG_STATUS.get(status, f"0x{status:02x}")
    print(f"   {label:<38} {txt}")
    if status not in ok:
        raise ProvError(f"{label} : {txt}")


async def read_config(cc: ConfigClient) -> dict:
    comp = parse_composition(await cc.request(b"\x80\x08\x00", b"\x02", "Composition Data Get"))
    print(f"  composition : CID 0x{comp['cid']:04X} PID 0x{comp['pid']:04X} VID 0x{comp['vid']:04X} "
          f"CRPL {comp['crpl']} fonctions 0x{comp['features']:04x}")
    proxy = await cc.request(b"\x80\x12", b"\x80\x14", "GATT Proxy Get")
    relay = await cc.request(b"\x80\x26", b"\x80\x28", "Relay Get")
    print(f"  GATT Proxy {proxy[0]} ; Relay {relay[0]} (retransmission 0x{relay[1]:02x})")
    for idx, el in enumerate(comp["elements"]):
        addr = cc.dst + idx
        print(f"  élément {idx} (0x{addr:04X}, emplacement 0x{el['loc']:04X})")
        for model in el["sig"] + el["vendor"]:
            vendor = isinstance(model, tuple)
            mb = model_bytes(model)
            st = await cc.request((b"\x80\x4D" if vendor else b"\x80\x4B") + addr.to_bytes(2, "little") + mb,
                                  b"\x80\x4E" if vendor else b"\x80\x4C", f"App Get {model_name(model)}")
            apps = st[1 + 2 + len(mb):].hex() if st[0] == 0 else f"statut {st[0]}"
            st = await cc.request((b"\x80\x2B" if vendor else b"\x80\x29") + addr.to_bytes(2, "little") + mb,
                                  b"\x80\x2C" if vendor else b"\x80\x2A", f"Sub Get {model_name(model)}")
            subs = [f"{int.from_bytes(st[i:i + 2], 'little'):04X}" for i in range(3 + len(mb), len(st), 2)] if st[0] == 0 else f"statut {st[0]}"
            st = await cc.request(b"\x80\x18" + addr.to_bytes(2, "little") + mb, b"\x80\x19",
                                  f"Pub Get {model_name(model)}")
            pub = f"{int.from_bytes(st[3:5], 'little'):04X} TTL {st[7]}" if st[0] == 0 else f"statut {st[0]}"
            print(f"    modèle {model_name(model):<10} AppKeys [{apps}]  abonnements {subs}  publication {pub}")
    return comp


async def configure(cc: ConfigClient, comp: dict | None = None, publish: bool = False) -> dict:
    """Configuration de l'app. La publication vers C000 est demandée par l'app, mais absente d'une ampoule
    configurée par l'app (relue le 26/11/2026) : elle n'est faite qu'avec publish=True."""
    if comp is None:
        comp = parse_composition(await cc.request(b"\x80\x08\x00", b"\x02", "Composition Data Get"))
    print(f"  composition : CID 0x{comp['cid']:04X} PID 0x{comp['pid']:04X} VID 0x{comp['vid']:04X}, "
          f"{len(comp['elements'])} élément(s)")
    st = await cc.request(b"\x00" + b"\x00\x00\x00" + cc.appkey, b"\x80\x03", "AppKey Add")
    check("AppKey Add (index 0)", st[0], ok=(0, 6))
    st = await cc.request(b"\x80\x13\x01", b"\x80\x14", "GATT Proxy Set")
    print(f"   {'GATT Proxy Set 1':<38} état {st[0]}")
    st = await cc.request(b"\x80\x27\x01" + bytes([RELAY_RETRANSMIT]), b"\x80\x28", "Relay Set")
    print(f"   {'Relay Set 1':<38} état {st[0]}, retransmission 0x{st[1]:02x}")
    for idx, el in enumerate(comp["elements"]):
        addr = cc.dst + idx
        a2 = addr.to_bytes(2, "little")
        models = [m for m in el["sig"] if m in SIG_TARGETS] + el["vendor"]
        for model in models:
            vendor, mb, name = isinstance(model, tuple), model_bytes(model), model_name(model)
            st = await cc.request(b"\x80\x3D" + a2 + b"\x00\x00" + mb, b"\x80\x3E", f"App Bind {name}")
            check(f"App Bind {name} (élément {idx})", st[0])
            st = await cc.request(b"\x80\x1B" + a2 + GROUP.to_bytes(2, "little") + mb, b"\x80\x1F", f"Sub Add {name}")
            check(f"Abonnement C000 {name}", st[0])
            if publish and not vendor:
                st = await cc.request(b"\x03" + a2 + GROUP.to_bytes(2, "little") + b"\x00\x00" + bytes([5, 0, 0]) + mb,
                                      b"\x80\x19", f"Pub Set {name}")
                check(f"Publication C000 TTL 5 {name}", st[0])
    # Signal de fin de configuration de l'app : CTL Set lightness 101, temp 900, 400 ms, délai 5 ms
    await cc.send_app(nx.nx_ctl_access(101, 900, nx.transition_byte(400), int.from_bytes(os.urandom(1), "big"), 1))
    print("   signal de fin (CTL 101 / 900) envoyé")
    return comp


# ------------------------------------------------------------------ méthode Nordlux (service 4d124bf0)
def parse_nx_mfr(d: bytes) -> dict | None:
    """Données fabricant 0x6E78 (DeviceDescriptionUtil) : type, version, état des clés, adresse actuelle."""
    if d is None or len(d) < 24 or (sum(b if b < 128 else b - 256 for b in d[:23]) & 0xFF) != d[23]:
        return None
    return {"beacon": d[0:4][::-1].decode("ascii", "replace"), "chip": d[5], "version": f"{d[6]}.{d[19]}",
            "spec_netkey": d[7:9][::-1].hex(), "spec_appkey": d[9:11][::-1].hex(),
            "configured": d[7:9] != b"\x00\x00" and d[9:11] != b"\x00\x00",
            "addr_raw": d[17:19], "addr": int.from_bytes(d[17:19], "little"), "room": d[22]}


def nx_config_messages(cur_addr_raw: bytes, netkey: bytes, appkey: bytes, new_addr: int,
                       room_num: int = 1, pub_addr: int = GROUP) -> list[bytes]:
    """Les 6 écritures de l'app (ConfigNodeRequest.getResult, opcode 0x21)."""
    head = b"CMD\x01\x21\x00\x00" + cur_addr_raw + b"\x08"
    bodies = [
        b"\x01" + netkey[0:7],
        b"\x02" + netkey[7:14],
        b"\x03\x64" + netkey[14:16] + new_addr.to_bytes(2, "little") + bytes([room_num & 0xFF, 0x64]),
        b"\x04" + appkey[0:7],
        b"\x05" + appkey[7:14],
        b"\x06\x00" + appkey[14:16] + pub_addr.to_bytes(2, "little") + b"\x00\x00",
    ]
    return [head + b for b in bodies]


def node_identity_addr(netkey: bytes, service_data: bytes) -> int | None:
    """Node Identity (type 01) -> adresse unicast si elle appartient à notre réseau."""
    if not service_data or service_data[0] != 0x01 or len(service_data) < 17:
        return None
    ik = nx.k1(netkey, nx.s1(b"nkik"), b"id128\x01")
    h, rnd = service_data[1:9], service_data[9:17]
    for a in range(1, 0x8000):
        if nx.aes_ecb(ik, b"\x00" * 6 + rnd + a.to_bytes(2, "big"))[8:] == h:
            return a
    return None


async def nx_observe(mac: str, seconds: float = 12):
    """Dernières données fabricant et service 0x1828 vues pour `mac`."""
    from bleak import BleakScanner
    seen = {"mfr": None, "proxy": None, "rssi": None}

    def cb(d, adv):
        if d.address.upper() == mac:
            seen["rssi"] = adv.rssi
            if NX_COMPANY in adv.manufacturer_data:
                seen["mfr"] = parse_nx_mfr(adv.manufacturer_data[NX_COMPANY])
            if PROXY_SERVICE in adv.service_data:
                seen["proxy"] = adv.service_data[PROXY_SERVICE]

    async with BleakScanner(cb):
        await asyncio.sleep(seconds)
    return seen


async def cmd_nx_add(args):
    keys, netkey, appkey, iv = load_keys()
    nodes = load_provisioned()
    mac = args.mac.upper()
    print(f"Observation de {mac}…")
    seen = await nx_observe(mac)
    info = seen["mfr"]
    if info is None:
        raise ProvError(f"{mac} : pas de données fabricant Nordlux valides (ampoule hors de portée ?)")
    print(f"  {info['beacon']} v{info['version']}, clés {'configurées' if info['configured'] else 'NON configurées'} "
          f"(net {info['spec_netkey']}, app {info['spec_appkey']}), adresse actuelle 0x{info['addr']:04X}, RSSI {seen['rssi']}")
    if info["configured"] and not args.force:
        raise ProvError("l'ampoule a déjà des clés : réinitialisez-la d'abord (ou --force)")
    addr = int(args.addr, 0) if args.addr else pick_address(keys, nodes)
    msgs = nx_config_messages(info["addr_raw"], netkey, appkey, addr, args.room_num)
    print(f"Configuration Nordlux -> adresse 0x{addr:04X}, pièce n° {args.room_num}, publication 0x{GROUP:04X}")
    client = await connect(mac, NX_SERVICE)
    try:
        def on_notify(_h, data):
            print(f"   réponse : {bytes(data).decode('utf-8', 'replace')}")
        try:
            await client.start_notify(NX_NOTIFY, on_notify)
        except Exception as e:  # noqa: BLE001 - les réponses ne sont qu'informatives
            print(f"   (réponses de l'ampoule indisponibles : {e})")
        for i, m in enumerate(msgs, 1):
            await client.write_gatt_char(NX_WRITE, m, response=True)
            print(f"   message {i}/6 envoyé")
            await asyncio.sleep(0.3)
        await asyncio.sleep(3)
    finally:
        try:
            await client.disconnect()
        except Exception:  # noqa: BLE001
            pass
    node = {"mac": mac, "name": args.name or mac.replace(":", "").lower(), "unicast": addr, "elements": 1,
            "method": "nordlux-gatt", "room_num": args.room_num, "provisioned": time.strftime("%Y-%m-%d %H:%M:%S")}
    nodes = [nd for nd in nodes if nd["mac"] != mac] + [node]
    save_provisioned(nodes)
    print("Vérification (annonces de l'ampoule)…")
    await asyncio.sleep(3)
    seen = await nx_observe(mac, 15)
    info = seen["mfr"]
    if info:
        print(f"  clés {'configurées' if info['configured'] else 'NON configurées'} (net {info['spec_netkey']}, "
              f"app {info['spec_appkey']}), adresse annoncée 0x{info['addr']:04X}")
    ident = node_identity_addr(netkey, seen["proxy"]) if seen["proxy"] else None
    print(f"  Node Identity : {f'notre réseau, adresse 0x{ident:04X}' if ident else 'non résolue avec notre NetKey'}")
    if ident == addr or (info and info["configured"] and info["addr"] == addr):
        print(f"\nTerminé. Ligne pour Home Assistant : {node['name']} = 0x{addr:04X}")
    else:
        print("\nÉtat final incertain : vérifier avec mesh_find_node.py, puis tester nx-on/nx-off.")


NX_RESET_ACCESS = bytes([0xE1, 0x11, 0x11, 0x0A, 0x00])  # opcode vendeur E1 + société 0x1111, message 0A 00


async def cmd_nx_reset(args):
    """Réinitialisation à distance, comme la suppression dans l'app pour les ampoules v18+ (MyUtil.isFastAddMeshDevice) :
    MeshVendorModelControl.resetFastDevice -> message vendeur 0xE1 (modèle 0x3333, société 0x1111), données 0A 00,
    chiffré avec l'AppKey et envoyé à l'élément 0 du nœud, via n'importe quel proxy du réseau."""
    keys, netkey, appkey, iv = load_keys()
    dst = int(args.dst, 0)
    net, save = make_net(netkey, appkey, iv)
    client = await connect(args.mac.upper(), PROXY_SERVICE)
    try:
        cc = ConfigClient(client, net, bytes(16), dst, save, appkey)
        await cc.open()
        for _ in range(args.repeat):
            await cc.send_app(NX_RESET_ACCESS)
            await asyncio.sleep(0.3)
        print(f"Réinitialisation envoyée à 0x{dst:04X} ({args.repeat} fois) via {args.mac.upper()}")
        await asyncio.sleep(1)
    finally:
        save()
        await client.disconnect()


# ------------------------------------------------------------------ commandes
def load_keys():
    keys = json.loads((MESH_DIR / "mesh_keys.json").read_text(encoding="utf-8"))[0]
    return keys, bytes.fromhex(keys["netKey"]), bytes.fromhex(keys["appKeyValue"]), int(keys.get("ivIndex") or 0)


def load_provisioned() -> list[dict]:
    f = MESH_DIR / "provisioned.json"
    return json.loads(f.read_text(encoding="utf-8")) if f.exists() else []


def save_provisioned(nodes: list[dict]):
    (MESH_DIR / "provisioned.json").write_text(json.dumps(nodes, indent=2, ensure_ascii=False), encoding="utf-8")


def make_net(netkey, appkey, iv):
    state_f = MESH_DIR / "local_state.json"
    state = json.loads(state_f.read_text()) if state_f.exists() else {"src": "0x7F01", "seq": 1}
    box = {"seq": int(state["seq"])}

    def alloc():
        s = box["seq"]
        box["seq"] += 1
        return s

    def save():
        state["seq"] = box["seq"]
        state_f.write_text(json.dumps(state, indent=2))

    net = CfgNetwork(netkey, appkey, iv, int(state["src"], 16), alloc)
    return net, save


async def connect(mac: str, service: str, attempts: int = 5, scan_timeout: float = 20):
    from bleak import BleakClient, BleakScanner
    dev = await BleakScanner.find_device_by_address(mac, timeout=scan_timeout)
    if not dev:
        raise ProvError(f"{mac} introuvable")
    for attempt in range(1, attempts + 1):
        client = BleakClient(dev, timeout=20, winrt={"use_cached_services": False})
        try:
            await client.connect()
        except Exception as e:  # noqa: BLE001
            print(f"  connexion {attempt}/{attempts} à {mac} échouée : {e!r}")
            await asyncio.sleep(1.5)
            continue
        if client.services.get_service(service) is None:
            await client.disconnect()
            print(f"  {mac} : service {service[4:8]} absent (essai {attempt}/{attempts})")
            await asyncio.sleep(2)
            continue
        print(f"  connecté à {mac} (MTU {client.mtu_size})")
        return client
    raise ProvError(f"pas de connexion utilisable à {mac} (service {service[4:8]})")


async def cmd_scan(_args):
    from bleak import BleakScanner
    _keys, netkey, _appkey, _iv = load_keys()
    # Les ampoules alternent deux annonces (données fabricant / Mesh Proxy) : on cumule par adresse.
    acc: dict[str, dict] = {}

    def cb(d, adv):
        e = acc.setdefault(d.address.upper(), {})
        e["rssi"] = adv.rssi
        if NX_COMPANY in adv.manufacturer_data:
            e["mfr"] = parse_nx_mfr(adv.manufacturer_data[NX_COMPANY])
        if PROXY_SERVICE in adv.service_data:
            e["proxy"] = adv.service_data[PROXY_SERVICE]

    async with BleakScanner(cb):
        await asyncio.sleep(15)
    print("Ampoules Nordlux (données fabricant 0x6E78) :")
    for mac, e in acc.items():
        info = e.get("mfr")
        if info is None:
            continue
        ident = node_identity_addr(netkey, e.get("proxy"))
        print(f"  {mac}  RSSI {e['rssi']:4}  {info['beacon']} v{info['version']}  clés "
              f"{'configurées' if info['configured'] else 'NON configurées'}  adresse 0x{info['addr']:04X}"
              + (f"  (notre réseau : 0x{ident:04X})" if ident else ""))
    found = await BleakScanner.discover(timeout=8, return_adv=True)
    print("Appareils non provisionnés (service standard 0x1827) :")
    n = 0
    for dev, adv in found.values():
        sd = adv.service_data.get(PROV_SERVICE)
        if sd is None and PROV_SERVICE not in adv.service_uuids:
            continue
        n += 1
        uuid = sd[:16].hex() if sd else "?"
        print(f"{dev.address}  RSSI {adv.rssi:4}  nom {adv.local_name or dev.name or '-':<16} UUID {uuid}"
              f"  OOB {sd[16:18].hex() if sd and len(sd) >= 18 else '?'}")
    print(f"{n} appareil(s) non provisionné(s) à portée.")


def pick_address(keys, nodes, n_el: int = 1) -> int:
    used = set()
    for d in keys.get("devices") or []:
        try:
            used.add(int(str(d.get("unicast")), 16))
        except (TypeError, ValueError):
            pass
    for nd in nodes:
        used.update(range(nd["unicast"], nd["unicast"] + nd.get("elements", 1)))
    for a in ADDR_RANGE:
        if all(x not in used for x in range(a, a + n_el)):
            return a
    raise ProvError("plus d'adresse libre dans 0x7E00–0x7EFF")


async def cmd_provision(args):
    keys, netkey, appkey, iv = load_keys()
    nodes = load_provisioned()
    mac = args.mac.upper()
    if any(nd["mac"] == mac for nd in nodes) and not args.force:
        raise ProvError(f"{mac} figure déjà dans provisioned.json (--force pour recommencer)")
    addr = int(args.addr, 0) if args.addr else pick_address(keys, nodes)
    print(f"Provisioning de {mac} -> adresse 0x{addr:04X} (réseau {nx.k3(netkey).hex()}, IV {iv})")
    client = await connect(mac, PROV_SERVICE)
    try:
        link = ProvLink(client, args.chunk)
        await link.start()
        devkey, n_el = await provision(link, netkey, iv, addr, args.attention)
    finally:
        try:
            await client.disconnect()
        except Exception:  # noqa: BLE001
            pass
    node = {"mac": mac, "name": args.name or mac.replace(":", "").lower(), "unicast": addr, "elements": n_el,
            "deviceKey": devkey.hex(), "provisioned": time.strftime("%Y-%m-%d %H:%M:%S"), "configured": False}
    nodes = [nd for nd in nodes if nd["mac"] != mac] + [node]
    save_provisioned(nodes)  # devKey enregistrée AVANT la configuration : sans elle, le nœud est inconfigurable
    print(f"Provisioning terminé : 0x{addr:04X}, {n_el} élément(s), devKey enregistrée dans mesh/provisioned.json")
    await asyncio.sleep(3)  # l'ampoule passe du service 0x1827 au service Mesh Proxy 0x1828
    await do_configure(node, nodes, [mac] + ([args.proxy.upper()] if args.proxy else []), args.publish)


async def do_configure(node: dict, nodes: list[dict], proxies: list[str], publish: bool = False):
    keys, netkey, appkey, iv = load_keys()
    net, save = make_net(netkey, appkey, iv)
    last = None
    for mac in proxies:
        try:
            client = await connect(mac, PROXY_SERVICE)
        except ProvError as e:
            last = e
            print(f"  {e}")
            continue
        try:
            cc = ConfigClient(client, net, bytes.fromhex(node["deviceKey"]), node["unicast"], save, appkey)
            await cc.open()
            print(f"Configuration de 0x{node['unicast']:04X} via {mac} (src 0x{net.src:04X})")
            comp = await configure(cc, publish=publish)
            node.update(configured=True, cid=comp["cid"], pid=comp["pid"], vid=comp["vid"],
                        elements=len(comp["elements"]))
            save_provisioned(nodes)
            print(f"\nTerminé. Ligne pour Home Assistant : {node['name']} = 0x{node['unicast']:04X}")
            return
        finally:
            save()
            try:
                await client.disconnect()
            except Exception:  # noqa: BLE001
                pass
    raise ProvError(f"configuration impossible : {last}")


async def cmd_configure(args):
    nodes = load_provisioned()
    dst = int(args.dst, 0)
    node = next((nd for nd in nodes if nd["unicast"] == dst), None)
    if node is None:
        raise ProvError(f"0x{dst:04X} absent de mesh/provisioned.json (devKey inconnue)")
    await do_configure(node, nodes, [args.mac.upper()], args.publish)


async def cmd_read_config(args):
    keys, netkey, appkey, iv = load_keys()
    dst = int(args.dst, 0)
    devkey = next((bytes.fromhex(nd["deviceKey"]) for nd in load_provisioned() if nd["unicast"] == dst), None)
    if devkey is None:
        for d in keys.get("devices") or []:
            try:
                if int(str(d.get("unicast")), 16) == dst and d.get("deviceKey"):
                    devkey = bytes.fromhex(d["deviceKey"])
            except ValueError:
                pass
    if devkey is None:
        raise ProvError(f"devKey de 0x{dst:04X} inconnue")
    net, save = make_net(netkey, appkey, iv)
    client = await connect(args.mac.upper(), PROXY_SERVICE)
    try:
        cc = ConfigClient(client, net, devkey, dst, save, appkey)
        await cc.open()
        print(f"Lecture de la configuration de 0x{dst:04X} (src 0x{net.src:04X}, lecture seule)")
        await read_config(cc)
    finally:
        save()
        await client.disconnect()


def cmd_selftest(_args):
    ok = nx.selftest()
    print("vecteurs k1..k4 de la spécification :", "OK" if ok else "ÉCHEC")
    # SAR : découpe puis réassemblage
    data = os.urandom(65)
    rx, got = SarRx(), None
    for p in sar_split(0x03, data, 20):
        got = rx.feed(p) or got
    ok_sar = got == (0x03, data)
    print("SAR proxy :", "OK" if ok_sar else "ÉCHEC")
    # Provisioning : les deux côtés calculent la même confirmation / la même session
    a, b = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    sa, sb = a.exchange(ec.ECDH(), b.public_key()), b.exchange(ec.ECDH(), a.public_key())
    salt = nx.s1(b"inputs")
    rp, rd = os.urandom(16), os.urandom(16)
    ok_prov = (prov_confirmation(nx.k1(sa, salt, b"prck"), rp) == prov_confirmation(nx.k1(sb, salt, b"prck"), rp)
               and prov_session(sa, salt, rp, rd) == prov_session(sb, salt, rp, rd))
    print("ECDH / confirmation / session :", "OK" if ok_prov else "ÉCHEC")
    # Segmentation devKey : émission puis réassemblage et déchiffrement (réseau fictif, src = dst)
    seq = {"v": 100}

    def alloc():
        seq["v"] += 1
        return seq["v"]

    net = CfgNetwork(os.urandom(16), os.urandom(16), 0, 0x7F01, alloc)
    devkey, msg = os.urandom(16), b"\x00\x00\x00\x00" + os.urandom(16)  # AppKey Add : 20 o -> 2 segments
    pdus = net.dev_pdus(0x7F01, msg, devkey)
    rx2, out = Reassembler(), None
    for p in pdus:
        m = net.decode_net(p)
        complete, s = rx2.feed(m)
        if complete:
            out = net.open_upper(m, b"".join(s["segs"][i] for i in range(s["segn"] + 1)), s["seq_auth"], 0, 0, devkey)
    ok_seg = len(pdus) == 2 and out == msg
    one = net.dev_pdus(0x7F01, b"\x80\x08\x00", devkey)
    m = net.decode_net(one[0])
    ok_one = len(one) == 1 and net.open_upper(m, m["tr"][1:], m["seq"], 0, 0, devkey) == b"\x80\x08\x00"
    print("segmentation / devKey :", "OK" if ok_seg and ok_one else "ÉCHEC")
    comp = parse_composition(bytes.fromhex("00" "0405" "1262" "0a00" "1e00" "0700"
                                           "0000" "05" "01" "0000" "0010" "0013" "0313" "0613" "33331111"))
    ok_comp = comp["elements"][0]["sig"] == [0, 0x1000, 0x1300, 0x1303, 0x1306] and comp["elements"][0]["vendor"] == [(0x3333, 0x1111)]
    print("lecture Composition Data :", "OK" if ok_comp else "ÉCHEC")
    # Données fabricant d'une Candle DIM réinitialisée (26/11/2026), MAC remplacée par 11:22:33:44:55:66
    info = parse_nx_mfr(bytes.fromhex("3236303000041b00000000665544332211f03a0300000079"))
    ok_mfr = (info is not None and info["beacon"] == "0062" and info["version"] == "27.3" and not info["configured"]
              and info["addr"] == 0x3AF0 and info["addr_raw"] == b"\xf0\x3a")
    msgs = nx_config_messages(b"\xf0\x3a", bytes(range(16)), bytes(range(16, 32)), 0x7E00, 1)
    ok_msgs = (len(msgs) == 6 and all(len(m) == 18 and m.startswith(b"CMD\x01\x21\x00\x00\xf0\x3a\x08") for m in msgs)
               and msgs[2][10:] == bytes([3, 0x64, 14, 15, 0x00, 0x7E, 1, 0x64])
               and msgs[5][10:] == bytes([6, 0, 30, 31, 0x00, 0xC0, 0, 0]))
    print("données fabricant / messages Nordlux :", "OK" if ok_mfr and ok_msgs else "ÉCHEC")
    sys.exit(0 if all((ok, ok_sar, ok_prov, ok_seg, ok_one, ok_comp, ok_mfr, ok_msgs)) else 1)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("scan")
    p = sub.add_parser("nx-add")
    p.add_argument("--mac", required=True)
    p.add_argument("--addr", help="adresse unicast (défaut : première libre de 0x7E00–0x7EFF)")
    p.add_argument("--room-num", type=int, default=1, help="numéro de pièce (serialNum de la pièce dans l'app, défaut 1)")
    p.add_argument("--name")
    p.add_argument("--force", action="store_true")
    p = sub.add_parser("nx-reset")
    p.add_argument("--mac", required=True, help="proxy mesh (l'ampoule elle-même ou le bridge)")
    p.add_argument("--dst", required=True)
    p.add_argument("--repeat", type=int, default=2)
    p = sub.add_parser("provision")
    p.add_argument("--mac", required=True)
    p.add_argument("--addr", help="adresse unicast (défaut : première libre de 0x7E00–0x7EFF)")
    p.add_argument("--name")
    p.add_argument("--proxy", help="proxy de secours pour la configuration (ex. le bridge)")
    p.add_argument("--attention", type=int, default=5, help="durée d'identification demandée à l'ampoule (s)")
    p.add_argument("--chunk", type=int, default=20, help="taille des écritures GATT (défaut 20)")
    p.add_argument("--force", action="store_true")
    p.add_argument("--publish", action="store_true", help="publication des modèles SIG vers C000 (TTL 5)")
    p = sub.add_parser("configure")
    p.add_argument("--mac", required=True)
    p.add_argument("--dst", required=True)
    p.add_argument("--publish", action="store_true")
    p = sub.add_parser("read-config")
    p.add_argument("--mac", required=True)
    p.add_argument("--dst", required=True)
    sub.add_parser("selftest")
    args = ap.parse_args()
    if args.cmd == "selftest":
        cmd_selftest(args)
        return
    fn = {"scan": cmd_scan, "nx-add": cmd_nx_add, "nx-reset": cmd_nx_reset, "provision": cmd_provision, "configure": cmd_configure, "read-config": cmd_read_config}[args.cmd]
    try:
        asyncio.run(fn(args))
    except ProvError as e:
        sys.exit(f"ERREUR : {e}")


if __name__ == "__main__":
    main()
