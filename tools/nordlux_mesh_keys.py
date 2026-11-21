"""Récupère la configuration Bluetooth Mesh (NetKey, AppKey, IV index, adresses, DevKeys…)
du compte Nordlux Smart via l'API Yankon, comme le fait l'app à la synchronisation.

Identifiants : NORDLUX_USER / NORDLUX_PASSWORD (environnement), plus les clés de l'API
NORDLUX_ACCESS_KEY_ID / NORDLUX_SECRET_KEY (voir README).
Sortie : mesh/house_<houseId>.json (réponse complète, contient des secrets) + mesh/mesh_keys.json (résumé).
L'écran n'affiche que des clés masquées.

Endpoints (sources décompilées) :
  - smartLight/api/account/emailLogin       (UserAuthApi, form cipher=)  -> token, accountId, lastHouse
  - smartLight/api/sync/syncHouse           (HouseApi, JSON {"cipher"}, sans houseList = lecture) -> houseList
  - smartLight/api/house/getHouseInfo       (SyncDataApi, JSON {"cipher"}) -> netKey, appKeyValue, ivIndex,
                                              sequenceNum, meshJson, deviceList[nodeJson, pubAddress…]
"""
import json, os, sys, uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import requests  # noqa: E402
from nordlux_fetch_fw import (APP, HOST, ACCESS_KEY_ID, SECRET_KEY, aes_cipher,  # noqa: E402
                              decode_response, headers, redact)

OUT = Path(__file__).resolve().parent.parent / "mesh"


def mask(v):
    if not isinstance(v, str) or len(v) < 8:
        return v
    return f"{v[:4]}…({len(v)} car.)"


def post_form(s, path, payload):
    r = s.post(HOST + path, data={"cipher": aes_cipher(json.dumps(payload))}, headers=headers(), timeout=30)
    return decode_response(r)


def post_json(s, path, payload):
    r = s.post(HOST + path, json={"cipher": aes_cipher(json.dumps(payload))}, headers=headers(), timeout=30)
    return decode_response(r)


def main():
    if len(ACCESS_KEY_ID) != 32 or len(SECRET_KEY) != 16:
        sys.exit("NORDLUX_ACCESS_KEY_ID / NORDLUX_SECRET_KEY absentes : voir le README (« Clés de l'API »).")
    user, pwd = os.environ.get("NORDLUX_USER"), os.environ.get("NORDLUX_PASSWORD")
    if not user or not pwd:
        sys.exit("NORDLUX_USER / NORDLUX_PASSWORD absentes de l'environnement.")
    s, uniq = requests.Session(), uuid.uuid4().hex

    j = post_form(s, "smartLight/api/account/emailLogin",
                  dict(APP, email=user, password=pwd, pushToken="123456", languages="en", uniqueIndication=uniq))
    if not j.get("isSuccess"):
        sys.exit("Échec de connexion : " + json.dumps(redact(j), ensure_ascii=False))
    d = j["data"]
    token, account = d["token"], d["accountId"]
    auth = dict(APP, token=token, accountId=account, uniqueIndication=uniq)
    print("Connexion OK.")

    # Lecture seule : comme SyncDataUntil.syncHouse(type=0) au premier passage,
    # sans houseList ni syncTime -> le serveur renvoie les maisons, rien n'est modifié.
    houses = []
    j = post_json(s, "smartLight/api/sync/syncHouse", dict(auth))
    if j.get("isSuccess"):
        for h in (j.get("data") or {}).get("houseList") or []:
            hid = h.get("houseId")
            if hid and hid not in houses:
                houses.append(hid)
    else:
        print("syncHouse :", json.dumps(redact(j), ensure_ascii=False)[:300])
    if d.get("lastHouse") and d["lastHouse"] not in houses:
        houses.append(d["lastHouse"])
    print(f"Maisons trouvées : {len(houses)}")
    if not houses:
        sys.exit(1)

    OUT.mkdir(exist_ok=True)
    summary = []
    for hid in houses:
        j = post_json(s, "smartLight/api/house/getHouseInfo", dict(auth, houseId=hid))
        if not j.get("isSuccess"):
            print(f"getHouseInfo({mask(hid)}) :", json.dumps(redact(j), ensure_ascii=False)[:300])
            continue
        h = j.get("data") or {}
        (OUT / f"house_{hid}.json").write_text(json.dumps(h, indent=2, ensure_ascii=False), encoding="utf-8")
        devs = []
        for dv in h.get("deviceList") or []:
            node = {}
            try:
                node = json.loads(dv.get("nodeJson") or "{}")
            except ValueError:
                pass
            devs.append({
                "name": dv.get("deviceName"), "mac": dv.get("deviceMac") or dv.get("bleMacAddress"),
                "beacon": dv.get("firmwareTypeBeacon"), "typeCode": dv.get("deviceTypeCode"),
                "version": dv.get("deviceVer"), "platform": dv.get("platformCode"),
                "unicast": node.get("unicastAddress"), "pubAddress": dv.get("pubAddress"),
                "deviceKey": node.get("deviceKey"), "appKeyIndex": dv.get("appKey"),
                "appKeyValue": dv.get("appKeyValue"), "meshUUID": dv.get("meshUUID") or node.get("UUID"),
            })
        summary.append({
            "houseId": hid, "houseName": h.get("houseName"),
            "netKey": h.get("netKey"), "netKeyIndex": h.get("netKeyIndex"),
            "appKeyIndex": h.get("appKey"), "appKeyValue": h.get("appKeyValue"),
            "ivIndex": h.get("ivIndex"), "sequenceNum": h.get("sequenceNum"),
            "provisionerAddress": h.get("address"), "minAddress": h.get("minAddress"),
            "maxAddress": h.get("maxAddress"), "pubAddress": h.get("pubAddress"),
            "hasMeshJson": bool(h.get("meshJson")), "devices": devs,
        })
        print(f"\nMaison « {h.get('houseName')} » : {len(devs)} appareil(s)")
        print(f"  NetKey   {mask(h.get('netKey'))} (index {h.get('netKeyIndex')})")
        print(f"  AppKey   {mask(h.get('appKeyValue'))} (index {h.get('appKey')})")
        print(f"  IV index {h.get('ivIndex')}  seq {h.get('sequenceNum')}  adresse provisioner {h.get('address')}"
              f"  plage {h.get('minAddress')}–{h.get('maxAddress')}  meshJson {'oui' if h.get('meshJson') else 'non'}")
        for dv in devs:
            print(f"   - {dv['name']!s:28} mac {dv['mac']!s:14} unicast {dv['unicast']!s:6} "
                  f"{dv['beacon']!s:12} v{dv['version']}  devKey {mask(dv['deviceKey'])}")
    (OUT / "mesh_keys.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nEnregistré dans {OUT} (contient les clés en clair, ne pas publier).")


if __name__ == "__main__":
    main()
