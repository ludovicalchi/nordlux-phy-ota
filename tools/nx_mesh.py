"""Cœur Bluetooth Mesh pour les ampoules Nordlux Smart (PHY6222), sans dépendance à Home Assistant.

Repris de tools/mesh_onoff.py (validé sur une Candle DIM le 21/11/2026) :
  - dérivation de clés k1..k4, chiffrement AES-CCM réseau / application, obfuscation ;
  - Proxy PDU (0x2ADD écriture, 0x2ADE notification), filtre en liste d'autorisation ;
  - commandes Nordlux : Light CTL Set détourné (ON = temp 10000, OFF = 15000,
    luminosité = lightness en % et température = 800 + teinte en %).
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.cmac import CMAC

_LOGGER = logging.getLogger(__name__)

PROXY_SERVICE = "00001828-0000-1000-8000-00805f9b34fb"
PROXY_IN = "00002add-0000-1000-8000-00805f9b34fb"
PROXY_OUT = "00002ade-0000-1000-8000-00805f9b34fb"

OP_CTL_GET = b"\x82\x5d"
OP_CTL_SET = b"\x82\x5e"
OP_CTL_STATUS = b"\x82\x60"

NX_TEMP_ON = 10000
NX_TEMP_OFF = 15000
# Opcode vendeur 0xE1, société 0x1111 (modèle 0x3333), données 0A 00 = réinitialisation
NX_RESET_ACCESS = bytes([0xE1, 0x11, 0x11, 0x0A, 0x00])


# ------------------------------------------------------------------ crypto
def _cmac(key: bytes, msg: bytes) -> bytes:
    c = CMAC(algorithms.AES(key))
    c.update(msg)
    return c.finalize()


def aes_ecb(key: bytes, block: bytes) -> bytes:
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return e.update(block) + e.finalize()


def s1(m: bytes) -> bytes:
    return _cmac(bytes(16), m)


def k1(n: bytes, salt: bytes, p: bytes) -> bytes:
    return _cmac(_cmac(salt, n), p)


def k2(n: bytes, p: bytes = b"\x00") -> tuple[int, bytes, bytes]:
    t = _cmac(s1(b"smk2"), n)
    t1 = _cmac(t, p + b"\x01")
    t2 = _cmac(t, t1 + p + b"\x02")
    t3 = _cmac(t, t2 + p + b"\x03")
    return t1[15] & 0x7F, t2, t3


def k3(n: bytes) -> bytes:
    return k1(n, s1(b"smk3"), b"id64\x01")[-8:]


def k4(n: bytes) -> int:
    return _cmac(_cmac(s1(b"smk4"), n), b"id6\x01")[-1] & 0x3F


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def selftest() -> bool:
    """Vecteurs de la spécification Mesh Profile (§8.1)."""
    n = bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00")
    nid, ek, pk = k2(n)
    return (nid == 0x7F and ek.hex() == "9f589181a0f50de73c8070c7a6d27f46"
            and pk.hex() == "4c715bd4a64b938f99b453351653124f"
            and k3(n).hex() == "ff046958233db014"
            and k4(bytes.fromhex("3216d1509884b533248541792b877f98")) == 0x38)


def transition_byte(ms: int) -> int:
    """Encodage Generic Default Transition Time (pas de 100 ms, 1 s, 10 s ou 10 min)."""
    for res, step in ((0, 100), (1, 1000), (2, 10000), (3, 600000)):
        n = round(ms / step)
        if n <= 0x3E:
            return (res << 6) | n
    return 0xFE


# ------------------------------------------------------------------ réseau
class MeshNetwork:
    """Construction / décodage des PDU pour un couple NetKey/AppKey."""

    def __init__(self, netkey: bytes, appkey: bytes, iv_index: int, src: int,
                 seq_alloc: Callable[[], int]) -> None:
        self.nid, self.ek, self.pk = k2(netkey)
        self.network_id = k3(netkey)
        self.appkey = appkey
        self.aid = k4(appkey)
        self.iv = iv_index
        self.src = src
        self._seq_alloc = seq_alloc

    def _net(self, ctl: int, ttl: int, dst: int, transport: bytes, seq: int, proxy: bool = False) -> bytes:
        ctl_ttl = (ctl << 7) | ttl
        iv4, seq3, src2 = self.iv.to_bytes(4, "big"), seq.to_bytes(3, "big"), self.src.to_bytes(2, "big")
        nonce = bytes([0x03 if proxy else 0x00, 0x00 if proxy else ctl_ttl]) + seq3 + src2 + b"\x00\x00" + iv4
        enc = AESCCM(self.ek, tag_length=8 if ctl else 4).encrypt(nonce, dst.to_bytes(2, "big") + transport, None)
        pecb = aes_ecb(self.pk, b"\x00" * 5 + iv4 + enc[:7])
        return bytes([((self.iv & 1) << 7) | self.nid]) + _xor(bytes([ctl_ttl]) + seq3 + src2, pecb[:6]) + enc

    def access_pdu(self, dst: int, access: bytes, ttl: int = 5) -> bytes:
        seq = self._seq_alloc()
        nonce = (b"\x01\x00" + seq.to_bytes(3, "big") + self.src.to_bytes(2, "big")
                 + dst.to_bytes(2, "big") + self.iv.to_bytes(4, "big"))
        upper = AESCCM(self.appkey, tag_length=4).encrypt(nonce, access, None)
        if len(upper) > 15:
            raise ValueError("message trop long pour un PDU non segmenté")
        return b"\x00" + self._net(0, ttl, dst, bytes([0x40 | self.aid]) + upper, seq)

    def proxy_cfg_pdu(self, payload: bytes) -> bytes:
        return b"\x02" + self._net(1, 0, 0x0000, payload, self._seq_alloc(), proxy=True)

    def decode(self, pdu: bytes) -> tuple[str, int | None, int | None, bytes] | None:
        """Renvoie (type, src, dst, données) : type parmi beacon, proxycfg, control, access, …"""
        if not pdu:
            return None
        kind, body = pdu[0] & 0x3F, pdu[1:]
        if kind == 0x01:
            return ("beacon", None, None, body)
        if kind not in (0x00, 0x02) or len(body) < 14 or (body[0] & 0x7F) != self.nid:
            return None
        iv = self.iv if (body[0] >> 7) == (self.iv & 1) else self.iv - 1
        iv4 = iv.to_bytes(4, "big")
        hdr = _xor(body[1:7], aes_ecb(self.pk, b"\x00" * 5 + iv4 + body[7:14])[:6])
        ctl, seq3, src = hdr[0] >> 7, hdr[1:4], int.from_bytes(hdr[4:6], "big")
        proxy = kind == 0x02
        nonce = bytes([0x03 if proxy else 0x00, 0x00 if proxy else hdr[0]]) + seq3 + hdr[4:6] + b"\x00\x00" + iv4
        try:
            plain = AESCCM(self.ek, tag_length=8 if ctl else 4).decrypt(nonce, body[7:], None)
        except Exception:  # noqa: BLE001 - autre réseau / PDU corrompu
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
        except Exception:  # noqa: BLE001
            return None


def nx_ctl_access(lightness_pct: int, temperature: int, transition: int, tid: int, delay_steps: int = 1) -> bytes:
    """Light CTL Set au format de l'app Nordlux (lightness = %, temp = code ou 800 + teinte %)."""
    return (OP_CTL_SET + lightness_pct.to_bytes(2, "little") + temperature.to_bytes(2, "little")
            + (0).to_bytes(2, "little") + bytes([tid & 0xFF, transition, delay_steps]))


# ------------------------------------------------------------------ lien proxy
class ProxyLink:
    """Connexion GATT à un proxy mesh. `connect` est fourni par l'appelant (bleak ou HA)."""

    def __init__(self, network: MeshNetwork, connect: Callable[[], Awaitable[object]],
                 extra_filter: list[int] | None = None) -> None:
        self.net = network
        self._connect = connect
        self._client = None
        self._queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._extra_filter = extra_filter or []
        self._tid = int(time.time()) & 0xFF

    @property
    def connected(self) -> bool:
        return self._client is not None and getattr(self._client, "is_connected", False)

    def next_tid(self) -> int:
        self._tid = (self._tid + 1) & 0xFF
        return self._tid

    async def open(self) -> None:
        if self.connected:
            return
        self._queue = asyncio.Queue()
        client = await self._connect()
        try:
            await client.start_notify(PROXY_OUT, lambda _h, d: self._queue.put_nowait(bytes(d)))
            self._client = client
            await self._drain(1.0)  # balise réseau éventuelle -> IV index
            # Filtre : liste d'autorisation contenant notre adresse (+ adresses demandées)
            await self._write(self.net.proxy_cfg_pdu(b"\x00\x00"))
            addrs = [self.net.src] + self._extra_filter
            await self._write(self.net.proxy_cfg_pdu(b"\x01" + b"".join(a.to_bytes(2, "big") for a in addrs)))
            await self._drain(0.5)
        except Exception:
            # Échec dès l'ouverture : souvent un cache GATT périmé (l'ampoule peut réorganiser ses
            # handles, par ex. Mesh Proxy passé de 0x42 à 0xF1) -> on oublie le cache.
            self._client = None
            await self._release(client, clear_cache=True)
            raise

    async def close(self, clear_cache: bool = False) -> None:
        """Ferme la connexion ; `clear_cache` force une nouvelle découverte des services la prochaine fois."""
        client, self._client = self._client, None
        if client is not None:
            await self._release(client, clear_cache)

    @staticmethod
    async def _release(client, clear_cache: bool) -> None:
        if clear_cache and hasattr(client, "clear_cache"):
            try:
                await client.clear_cache()
            except Exception:  # noqa: BLE001
                pass
        try:
            await client.disconnect()
        except Exception:  # noqa: BLE001
            pass

    async def _write(self, pdu: bytes) -> None:
        await self._client.write_gatt_char(PROXY_IN, pdu, response=False)

    def _handle(self, raw: bytes):
        r = self.net.decode(raw)
        if r and r[0] == "beacon":
            b = r[3]
            if len(b) >= 14 and b[0] == 0x01 and b[2:10] == self.net.network_id:
                iv = int.from_bytes(b[10:14], "big")
                if iv != self.net.iv:
                    _LOGGER.info("IV index mis à jour par la balise réseau : %s -> %s", self.net.iv, iv)
                    self.net.iv = iv
        return r

    async def _drain(self, timeout: float) -> None:
        end = time.monotonic() + timeout
        while (left := end - time.monotonic()) > 0:
            try:
                raw = await asyncio.wait_for(self._queue.get(), left)
            except asyncio.TimeoutError:
                return
            self._handle(raw)

    async def send(self, dst: int, access: bytes, expect: bytes | None = None, timeout: float = 3.0) -> bytes | None:
        """Envoie un message d'accès ; si `expect` (opcode de statut) est donné, attend la réponse."""
        await self.open()
        await self._write(self.net.access_pdu(dst, access))
        if expect is None:
            return None
        end = time.monotonic() + timeout
        while (left := end - time.monotonic()) > 0:
            try:
                raw = await asyncio.wait_for(self._queue.get(), left)
            except asyncio.TimeoutError:
                break
            r = self._handle(raw)
            if r and r[0] == "access" and r[1] == dst and r[3][: len(expect)] == expect:
                return r[3][len(expect):]
        return None

    # Commandes Nordlux -------------------------------------------------
    async def nx_on(self, dst: int) -> bytes | None:
        return await self.send(dst, nx_ctl_access(0, NX_TEMP_ON, 0x00, self.next_tid()), OP_CTL_STATUS)

    async def nx_off(self, dst: int) -> bytes | None:
        return await self.send(dst, nx_ctl_access(0, NX_TEMP_OFF, 0x00, self.next_tid()), OP_CTL_STATUS)

    async def nx_brightness(self, dst: int, pct: int, cct_pct: int = 100, transition_ms: int = 400) -> bytes | None:
        pct = max(0, min(100, int(pct)))
        temp = 800 + max(0, min(100, int(cct_pct)))
        return await self.send(dst, nx_ctl_access(pct, temp, transition_byte(transition_ms), self.next_tid()),
                               OP_CTL_STATUS)

    async def nx_reset(self, dst: int, repeat: int = 2) -> None:
        """Réinitialisation à distance (suppression dans l'app, firmware ≥ 18) : message vendeur sans réponse.
        Testé le 26/11/2026 : l'ampoule clignote et revient en « clés non configurées »."""
        for _ in range(repeat):
            await self.send(dst, NX_RESET_ACCESS)
            await asyncio.sleep(0.3)

    async def ctl_get(self, dst: int) -> bytes | None:
        """Lecture (sans effet sur la lumière) : utile pour vérifier la liaison."""
        return await self.send(dst, OP_CTL_GET, OP_CTL_STATUS)
