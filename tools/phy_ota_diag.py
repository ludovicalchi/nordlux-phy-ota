"""Diagnostic du bootloader OTA PHY62xx : envoie 01/02 puis les données paquet par paquet,
en vérifiant après chaque paquet que l'ampoule répond (lecture du CCCD de ff03) et
en guettant les notifications. N'envoie jamais de commande de reboot.

Usage : python phy_ota_diag.py <fichier.hex16> --mac AA:BB:CC:DD:EE:FF [--chunk 20] [--max-bytes 3792]
"""
import argparse, asyncio, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from phy_ota import parse_hex, plan, SVC, CMD, NTF, DATA  # noqa: E402


async def main(a):
    from bleak import BleakClient, BleakScanner
    parts, _ = parse_hex(a.hexfile)
    _, pcmd = plan(parts)[0]
    dev = await BleakScanner.find_device_by_address(a.mac, timeout=15)
    if not dev:
        sys.exit("ampoule non trouvée")
    disc = asyncio.Event()
    for attempt in range(10):
        try:
            client = BleakClient(dev, timeout=20, disconnected_callback=lambda _c: disc.set())
            await client.connect()
            break
        except Exception as e:
            print("connexion échouée :", repr(e)); await asyncio.sleep(1)
    else:
        sys.exit("pas de connexion")
    t0 = time.monotonic()
    ts = lambda: f"{time.monotonic() - t0:7.3f}s"
    q = asyncio.Queue()
    ntf_char = client.services.get_characteristic(NTF)
    cccd = next(d for d in ntf_char.descriptors if d.uuid.startswith("00002902"))
    print(ts(), f"connectée, MTU={client.mtu_size}, CCCD handle={cccd.handle}")
    await client.start_notify(NTF, lambda _h, d: q.put_nowait(bytes(d)))
    await asyncio.sleep(0.3)

    async def ntf(timeout):
        try:
            return await asyncio.wait_for(q.get(), timeout)
        except asyncio.TimeoutError:
            return None

    async def alive():
        try:
            v = await asyncio.wait_for(client.read_gatt_descriptor(cccd.handle), 3)
            return bytes(v).hex()
        except Exception as e:
            return f"ÉCHEC ({type(e).__name__})"

    print(ts(), "vivante avant tout :", await alive())
    await client.write_gatt_char(CMD, bytes([1, len(parts), 0]), response=True)
    print(ts(), "01 -> ", (await ntf(3) or b"").hex(" "))
    await client.write_gatt_char(CMD, pcmd, response=True)
    print(ts(), "02 -> ", (await ntf(5) or b"").hex(" "))
    print(ts(), "vivante après 02 :", await alive())

    data = parts[0].data[:a.max_bytes]
    n = 0
    for k in range(0, len(data), a.chunk):
        pkt = data[k:k + a.chunk]
        await client.write_gatt_char(DATA, pkt, response=a.with_response)
        n += 1
        v = await ntf(a.wait)
        st = await alive() if (n <= 3 or n % a.check_every == 0 or v) else "-"
        if v or n <= 3 or n % a.check_every == 0:
            print(ts(), f"paquet {n:3d} ({k + len(pkt):5d} o) notif={v.hex(' ') if v else '-'} vivante={st}")
        if v or st.startswith("ÉCHEC") or disc.is_set():
            break
    else:
        print(ts(), "fin des données de test ; attente 5 s d'une notification…")
        v = await ntf(5)
        print(ts(), "notif :", v.hex(" ") if v else "-", "| vivante :", await alive())
    print(ts(), "déconnectée par l'ampoule" if disc.is_set() else "toujours connectée")
    if client.is_connected:
        await client.disconnect()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("hexfile", type=Path)
    ap.add_argument("--mac", required=True, help="adresse BLE de l'ampoule en mode OTA")
    ap.add_argument("--chunk", type=int, default=20)
    ap.add_argument("--max-bytes", type=int, default=3792)
    ap.add_argument("--wait", type=float, default=0.05, help="attente de notification après chaque paquet")
    ap.add_argument("--check-every", type=int, default=16)
    ap.add_argument("--with-response", action="store_true")
    asyncio.run(main(ap.parse_args()))
