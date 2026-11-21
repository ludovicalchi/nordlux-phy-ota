"""OTA Phyplus PHY62xx par BLE (bleak), réimplémentation du SDK com.phy.ota.sdk embarqué
dans l'app Nordlux Smart v2.6.2. Cible : ampoule bloquée dans le bootloader OTA
(service 5833ff01-9b8b-5191-6142-22a4536ef123).

Protocole (cf. apk/src/sources/com/phy/ota/sdk/{OTAUtils,ble/BleCallBack,util/BleUtils,beans/*}.java) :
  ff02 (write) : 01 <nb_partitions> 00                         -> notif ff03 00 81
                 02 <idx> <flash LE32> <run LE32> <len LE32> <crc16 LE16>  -> 00 84
  ff04 (write without response) : blocs de 16 paquets de (MTU-3) octets
                 après chaque bloc -> 00 87 ; fin de partition -> 00 85 ; fin d'OTA -> 00 83
                 68 87 = erreur de bloc -> on renvoie le bloc
  ff02 : 04 (ou 04 01 avec réponse si MTU > 23) = reboot   -> 00 8a
CRC16 : poly 0xA001 réfléchi, init 0 (CRC-16/ARC) sur les données de la partition.

Usage :
  python phy_ota.py firmware/xxx.hex16 --dry-run            # analyse seule, aucune radio
  python phy_ota.py firmware/xxx.hex16 --mac AA:BB:CC:DD:EE:FF
"""
import argparse, asyncio, datetime, sys, time
from dataclasses import dataclass
from pathlib import Path

SVC = "5833ff01-9b8b-5191-6142-22a4536ef123"
CMD = "5833ff02-9b8b-5191-6142-22a4536ef123"
NTF = "5833ff03-9b8b-5191-6142-22a4536ef123"
DATA = "5833ff04-9b8b-5191-6142-22a4536ef123"
FLASH_LO, FLASH_HI = 0x11000000, 0x1107FFFF
PKTS_PER_BLOCK = 16

R_START, R_PART, R_BLOCK, R_PART_DONE, R_OTA_DONE, R_REBOOT, R_BLOCK_ERR = (
    b"\x00\x81", b"\x00\x84", b"\x00\x87", b"\x00\x85", b"\x00\x83", b"\x00\x8a", b"\x68\x87")


# ---------------------------------------------------------------- image
@dataclass
class Partition:
    addr: int
    data: bytes

    @property
    def in_flash(self):
        return FLASH_LO <= self.addr <= FLASH_HI


def crc16(data: bytes) -> int:
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xA001 if c & 1 else c >> 1
    return c


def parse_hex(path: Path):
    """Même découpage que FirmWareFile.analyzeFile : une partition par enregistrement 04,
    données des enregistrements suivants concaténées, adresse = ELA(16) + offset du 1er enregistrement."""
    parts, buf, addr_str, have, warnings = [], bytearray(), "", False, []
    expected = None
    for ln, line in enumerate(path.read_text().splitlines(), 1):
        t = line.strip()
        if not t:
            continue
        if not t.startswith(":"):
            raise ValueError(f"ligne {ln} : pas un enregistrement Intel HEX")
        raw = bytes.fromhex(t[1:])
        if sum(raw) & 0xFF:
            raise ValueError(f"ligne {ln} : somme de contrôle Intel HEX invalide")
        n, rtype = raw[0], t[7:9]
        if rtype == "04":
            if buf:
                parts.append(Partition(int(addr_str, 16), bytes(buf)))
            addr_str, buf, have, expected = t[9:13], bytearray(), False, None
        elif rtype in ("05", "01"):
            break
        else:
            off = int(t[3:7], 16)
            if not have:
                addr_str += t[3:7]
                have = True
            elif expected is not None and off != expected:
                warnings.append(f"ligne {ln} : trou/saut d'adresse dans la partition {len(parts)} "
                                f"(attendu 0x{expected:04X}, lu 0x{off:04X}) — concaténé comme le fait l'app")
            buf += raw[4:4 + n]
            expected = (off + n) & 0xFFFF
    if buf:
        parts.append(Partition(int(addr_str, 16), bytes(buf)))
    return parts, warnings


def plan(parts, hexe16=False):
    """Calcule (flash_addr, commande 02) par partition, comme BleCallBack/BleUtils."""
    out, flash_acc = [], 0
    for i, p in enumerate(parts):
        fa = p.addr if p.in_flash else flash_acc
        tail = p.data[-4:] if hexe16 else crc16(p.data).to_bytes(2, "little")
        cmd = bytes([0x02, i]) + fa.to_bytes(4, "little") + p.addr.to_bytes(4, "little") \
            + len(p.data).to_bytes(4, "little") + tail
        out.append((fa, cmd))
        if not p.in_flash:
            flash_acc += len(p.data) + (4 if hexe16 else 8)
    return out


def blocks_of(data: bytes, chunk: int):
    pkts = [data[k:k + chunk] for k in range(0, len(data), chunk)]
    return [pkts[k:k + PKTS_PER_BLOCK] for k in range(0, len(pkts), PKTS_PER_BLOCK)]


# ---------------------------------------------------------------- BLE
class OTAError(Exception):
    pass


class Session:
    def __init__(self, client, log):
        self.c, self.log = client, log
        self.q = asyncio.Queue()
        self.disconnected = asyncio.Event()

    def on_notify(self, _h, data):
        self.q.put_nowait(bytes(data))

    async def cmd(self, payload: bytes, response=True):
        self.log(f"TX ff02 {payload.hex(' ')}")
        await self.c.write_gatt_char(CMD, payload, response=response)

    async def notif_or_none(self, timeout):
        """Comme notif() mais renvoie None sur simple délai dépassé (déconnexion = erreur)."""
        try:
            return await self.notif(timeout)
        except OTAError as e:
            if self.disconnected.is_set():
                raise
            if "pas de notification" in str(e):
                return None
            raise

    async def notif(self, timeout):
        get = asyncio.ensure_future(self.q.get())
        disc = asyncio.ensure_future(self.disconnected.wait())
        done, _ = await asyncio.wait({get, disc}, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
        for f in (get, disc):
            if f not in done:
                f.cancel()
        if get in done:
            v = get.result()
            self.log(f"RX ff03 {v.hex(' ')}")
            return v
        if disc in done:
            raise OTAError("déconnecté par l'ampoule")
        raise OTAError(f"pas de notification en {timeout:.0f} s")

    async def expect(self, want: bytes, timeout):
        v = await self.notif(timeout)
        if v != want:
            raise OTAError(f"réponse inattendue {v.hex(' ')} (attendu {want.hex(' ')})")


async def connect(args, log):
    from bleak import BleakClient, BleakScanner
    for attempt in range(1, args.connect_retries + 1):
        log(f"Recherche de {args.mac} (essai {attempt}/{args.connect_retries})…")
        try:
            dev = await BleakScanner.find_device_by_address(args.mac, timeout=args.scan_timeout)
        except Exception as e:
            if type(e).__name__ == "BleakBluetoothNotAvailableError":
                raise OTAError(f"Bluetooth du PC indisponible : {e.args[0] if e.args else e}")
            raise
        if not dev:
            log("  non trouvée.")
            continue
        log(f"  trouvée : {dev.name}")
        sess_holder = {}
        on_disc = lambda _c: sess_holder.get("s") and sess_holder["s"].disconnected.set()
        try:
            client = BleakClient(dev, timeout=20, disconnected_callback=on_disc,
                                 winrt={"use_cached_services": False})
        except TypeError:  # option winrt absente de cette version de bleak
            client = BleakClient(dev, timeout=20, disconnected_callback=on_disc)
        try:
            await client.connect()
            return client, sess_holder
        except Exception as e:  # connexions qui échouent souvent (cf. 0x3E dans la trace)
            log(f"  connexion échouée : {e!r}")
            await asyncio.sleep(1.0)
    raise OTAError("impossible de se connecter à l'ampoule")


async def run_ota(args, parts, hexe16, log):
    client, holder = await connect(args, log)
    s = Session(client, log)
    holder["s"] = s
    try:
        svc = client.services.get_service(SVC)
        if not svc or not all(svc.get_characteristic(u) for u in (CMD, NTF, DATA)):
            raise OTAError("service OTA Phyplus absent : l'ampoule n'est pas en mode bootloader")
        mtu = client.mtu_size
        chunk = args.chunk or min(mtu - 3, 20)
        quick = mtu > 23
        if chunk > mtu - 3:
            raise OTAError(f"--chunk {chunk} > MTU-3 ({mtu - 3})")
        # Taille de bloc côté bootloader : 16 paquets (modèle "pkt") ou 16*(MTU-3) octets (modèle "mtu").
        # Identiques si chunk == MTU-3 ; sinon détectées sur le premier bloc.
        model = args.block_model if args.block_model != "auto" else ("pkt" if chunk == mtu - 3 else None)
        log(f"Connectée. MTU={mtu}, paquets de {chunk} o, mode rapide={quick}, modèle de bloc={model or 'à détecter'}")
        await client.start_notify(NTF, s.on_notify)
        await asyncio.sleep(0.3)

        total = sum(len(p.data) for p in parts)
        sent, t0 = 0, time.monotonic()

        async def send_range(data, a, b):
            for k in range(a, b, chunk):
                if s.disconnected.is_set():
                    raise OTAError("déconnecté par l'ampoule")
                await client.write_gatt_char(DATA, data[k:min(k + chunk, b)], response=False)
                if args.delay:
                    await asyncio.sleep(args.delay)

        await s.cmd(bytes([0x01, len(parts), 0x00]))
        await s.expect(R_START, args.timeout)

        ota_done = False
        for i, (p, (fa, pcmd)) in enumerate(zip(parts, plan(parts, hexe16))):
            log(f"Partition {i}/{len(parts) - 1} : run 0x{p.addr:08X} flash 0x{fa:08X} {len(p.data)} o")
            await s.cmd(pcmd)
            await s.expect(R_PART, args.part_timeout)
            data, L = p.data, len(p.data)
            off, err, part_done = 0, 0, False
            while off < L:
                if model is None:  # détection sur le tout premier bloc
                    end1 = min(off + PKTS_PER_BLOCK * chunk, L)
                    await send_range(data, off, end1)
                    log(f"  détection : {end1 - off} o envoyés (16 paquets), attente {args.probe_wait:.0f} s…")
                    v = await s.notif_or_none(args.probe_wait)
                    if v is not None:
                        model, end = "pkt", end1
                    else:
                        end = min(off + PKTS_PER_BLOCK * (mtu - 3), L)
                        log(f"  pas d'acquittement ; complément jusqu'à {end - off} o (16*(MTU-3))")
                        await send_range(data, end1, end)
                        v = await s.notif(args.timeout)
                        model = "mtu"
                    log(f"  modèle de bloc détecté : {model} (réponse {v.hex(' ')})")
                else:
                    bs = PKTS_PER_BLOCK * (chunk if model == "pkt" else mtu - 3)
                    end = min(off + bs, L)
                    await send_range(data, off, end)
                    v = await s.notif(args.timeout)
                last = end == L
                if v == R_BLOCK:
                    sent += end - off
                    off, err = end, 0
                    pct = 100 * sent / total
                    rate = sent / max(time.monotonic() - t0, 1e-3) / 1024
                    print(f"\r  {pct:5.1f} %  ({sent}/{total} o, {rate:.1f} Ko/s)", end="", flush=True)
                elif v == R_BLOCK_ERR:
                    err += 1
                    log(f"  bloc à l'offset {off} rejeté (68 87), renvoi {err}/{args.retries}")
                    if err > args.retries:
                        raise OTAError("trop d'erreurs sur un bloc")
                elif v == R_PART_DONE and last:
                    sent += end - off
                    off, part_done = end, True
                elif v == R_OTA_DONE and last and i == len(parts) - 1:
                    sent += end - off
                    off, part_done, ota_done = end, True, True
                else:
                    raise OTAError(f"réponse inattendue {v.hex(' ')} à l'offset {off}/{L}")
            print()
            if not part_done:
                await s.expect(R_PART_DONE, args.part_timeout)
        if not ota_done:
            v = await s.notif(args.part_timeout)
            if v != R_OTA_DONE:
                raise OTAError(f"fin d'OTA non confirmée ({v.hex(' ')})")
        log(f"OTA terminée en {time.monotonic() - t0:.0f} s (00 83).")

        if args.no_reboot:
            log("--no-reboot : l'ampoule reste en bootloader.")
            return
        await s.cmd(b"\x04\x01" if quick else b"\x04", response=quick)
        try:
            v = await s.notif(10)
            log("Reboot confirmé (00 8a)." if v == R_REBOOT else f"Réponse au reboot : {v.hex(' ')}")
        except OTAError as e:
            log(f"Après reboot : {e} (normal si l'ampoule redémarre).")
    finally:
        if client.is_connected:
            await client.disconnect()


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("hexfile", type=Path)
    ap.add_argument("--mac", help="adresse BLE de l'ampoule EN MODE OTA (nom nxXXXXv1, service 5833ff01)")
    ap.add_argument("--dry-run", action="store_true", help="analyse l'image et affiche les commandes, sans BLE")
    ap.add_argument("--mtu", type=int, default=240, help="MTU supposé pour --dry-run")
    ap.add_argument("--chunk", type=int, help="taille de paquet (défaut 20 : validé le 21/11/2026 ; 197 et 237 bloquent le bootloader)")
    ap.add_argument("--block-model", choices=["auto", "pkt", "mtu"], default="mtu",
                    help="taille de bloc du bootloader : 16 paquets (pkt) ou 16*(MTU-3) octets (mtu)")
    ap.add_argument("--probe-wait", type=float, default=2.5, help="attente lors de la détection du modèle (s)")
    ap.add_argument("--delay", type=float, default=0.01, help="pause entre paquets en s (défaut 0.01)")
    ap.add_argument("--timeout", type=float, default=8, help="attente d'un acquittement de bloc (s)")
    ap.add_argument("--part-timeout", type=float, default=20, help="attente 0084/0085/0083 (effacement flash) (s)")
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--connect-retries", type=int, default=10)
    ap.add_argument("--scan-timeout", type=float, default=15)
    ap.add_argument("--no-reboot", action="store_true")
    args = ap.parse_args()

    hexe16 = args.hexfile.name.endswith("hexe16")
    parts, warnings = parse_hex(args.hexfile)
    total = sum(len(p.data) for p in parts)
    print(f"{args.hexfile.name} : {len(parts)} partitions, {total} o, format {'hexe16' if hexe16 else 'hex'}")
    for w in warnings:
        print("  !", w)
    for i, (p, (fa, cmd)) in enumerate(zip(parts, plan(parts, hexe16))):
        print(f"  [{i}] run 0x{p.addr:08X} flash 0x{fa:08X} {len(p.data):7d} o "
              f"{'flash' if p.in_flash else 'hors flash'}  cmd {cmd.hex(' ')}")
    if args.dry_run:
        chunk = args.chunk or (args.mtu - 3)
        nb = sum(len(blocks_of(p.data, chunk)) for p in parts)
        print(f"Commande de départ : 01 {len(parts):02x} 00 ; {nb} blocs de {PKTS_PER_BLOCK}x{chunk} o (MTU {args.mtu})")
        print(f"1er paquet : {blocks_of(parts[0].data, chunk)[0][0][:24].hex(' ')} …")
        return

    if not args.mac:
        ap.error("--mac est obligatoire hors --dry-run")
    logdir = args.hexfile.resolve().parent
    logf = (logdir / f"ota_log_{datetime.datetime.now():%Y%m%d_%H%M%S}.txt").open("w", encoding="utf-8")

    def log(msg):
        line = f"{datetime.datetime.now():%H:%M:%S.%f}"[:-3] + " " + msg
        print(line)
        logf.write(line + "\n")
        logf.flush()

    try:
        asyncio.run(run_ota(args, parts, hexe16, log))
    except OTAError as e:
        log(f"ÉCHEC : {e}")
        log("L'ampoule reste en bootloader ; on peut relancer le script.")
        sys.exit(1)
    finally:
        logf.close()


if __name__ == "__main__":
    main()
