"""Écoute les annonces Mesh Proxy (service 0x1828) et, avec la NetKey de mesh/mesh_keys.json :
  - vérifie les Network ID annoncés (type 0x00) : appartenance au réseau ;
  - résout les Node Identity (type 0x01) : retrouve l'adresse unicast du nœud.
Utile pour un appareil supprimé de l'app (absent du cloud) mais encore provisionné.
Écoute seule : rien n'est envoyé aux appareils.

Node Identity (Mesh Profile §7.2.2.2.3) :
  IdentityKey = k1(NetKey, s1("nkik"), "id128" || 0x01)
  Hash        = e(IdentityKey, 0x00*6 || Random || Address)[8:16]

Usage : python mesh_find_node.py [--mac AA:BB:CC:DD:EE:FF] [--scan 15] [--keys mesh/mesh_keys.json]
"""
import argparse, asyncio, json, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mesh_onoff import aes_ecb, k1, k3, s1  # noqa: E402

UUID_1828 = "00001828-0000-1000-8000-00805f9b34fb"


def resolve(identity_key, hsh, rnd):
    for addr in range(1, 0x8000):
        if aes_ecb(identity_key, b"\x00" * 6 + rnd + addr.to_bytes(2, "big"))[8:] == hsh:
            return addr
    return None


async def scan(seconds, only):
    from bleak import BleakScanner
    seen = {}

    def cb(d, adv):
        if only and d.address.upper() != only:
            return
        sd = adv.service_data.get(UUID_1828)
        if sd is None and UUID_1828 not in adv.service_uuids:
            return
        e = seen.setdefault(d.address, {"rssi": adv.rssi, "sd": set()})
        e["rssi"] = adv.rssi
        if sd:
            e["sd"].add(bytes(sd))
    async with BleakScanner(cb, scanning_mode="active"):
        await asyncio.sleep(seconds)
    return seen


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mac", help="limiter à une adresse BLE")
    ap.add_argument("--scan", type=float, default=15)
    ap.add_argument("--keys", type=Path, default=Path(__file__).resolve().parent.parent / "mesh" / "mesh_keys.json")
    a = ap.parse_args()

    nets = []
    for h in json.loads(a.keys.read_text(encoding="utf-8")):
        nk = bytes.fromhex(h["netKey"])
        nets.append((h.get("houseName") or h.get("houseId"), k3(nk), k1(nk, s1(b"nkik"), b"id128\x01")))
    for name, nid, _ in nets:
        print(f"Réseau « {name} » : Network ID {nid.hex()}")

    seen = asyncio.run(scan(a.scan, a.mac.upper() if a.mac else None))
    if not seen:
        print("Aucun proxy mesh entendu.")
        return
    for addr, e in sorted(seen.items()):
        out = []
        for sd in e["sd"]:
            if sd[0] == 0x00 and len(sd) >= 9:
                m = [n for n, nid, _ in nets if nid == sd[1:9]]
                out.append(f"Network ID {sd[1:9].hex()} " + (f"= « {m[0]} »" if m else "(réseau inconnu)"))
            elif sd[0] == 0x01 and len(sd) >= 17:
                for name, _, ik in nets:
                    u = resolve(ik, sd[1:9], sd[9:17])
                    if u:
                        out.append(f"Node Identity → unicast 0x{u:04X} dans « {name} »")
                        break
                else:
                    out.append("Node Identity non résolue (autre réseau ?)")
            else:
                out.append(f"données 0x1828 {sd.hex()}")
        print(f"{addr}  RSSI {e['rssi']:4}  " + ("; ".join(sorted(set(out))) or "0x1828 sans service data"))


if __name__ == "__main__":
    main()
