"""Récupère l'image OTA d'une ampoule Nordlux Smart (PHY62xx) via l'API cloud Yankon,
en reproduisant le comportement de l'app Android v2.6.2 (com.nx.smbt5.a.android).

Identifiants lus dans les variables d'environnement NORDLUX_USER / NORDLUX_PASSWORD,
clés applicatives dans NORDLUX_ACCESS_KEY_ID / NORDLUX_SECRET_KEY (voir README).
Ni le mot de passe ni le jeton de session ne sont affichés ou écrits sur disque.

Référence (sources décompilées dans apk/src/sources) :
  - wifi/ykutils/SecurityUtil.java : clés, en-têtes authorization/sign
  - wifi/ykutils/CryptoUtil.java   : AES-128-ECB/PKCS5 -> hex majuscule (champ "cipher")
  - wifi/restful/api/app/account/UserAuthApi.java : POST smartLight/api/account/emailLogin (form cipher=)
  - v2/netWork/api/DeviceApi.java  : POST smartLight/api/ota/getOTAInfo (JSON {"cipher": ...})

Usage : python nordlux_fetch_fw.py [--beacon nx00626222] [--out firmware]
"""
import argparse, base64, datetime, hashlib, json, os, sys, uuid
from pathlib import Path

import requests
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HOST = "https://api.yankon-xm.com/"
# Clés applicatives de l'app (non publiées ici) : voir README, section « Clés de l'API ».
ACCESS_KEY_ID = os.environ.get("NORDLUX_ACCESS_KEY_ID", "")
SECRET_KEY = os.environ.get("NORDLUX_SECRET_KEY", "")
APP = {"appCode": "nordlux", "version": "v2.0.0", "appVersion": "v2.6.2", "buildVersion": 137,
       "mobileSystemType": "android", "mobileSystemVersion": "14",
       "mobileBrand": "generic", "mobileModel": "generic"}
UA = "okhttp/4.9.0"


def aes_cipher(plain: str) -> str:
    padder = padding.PKCS7(128).padder()
    data = padder.update(plain.encode()) + padder.finalize()
    enc = Cipher(algorithms.AES(SECRET_KEY.encode()), modes.ECB()).encryptor()
    return (enc.update(data) + enc.finalize()).hex().upper()


def aes_decipher(hexstr: str) -> str:
    dec = Cipher(algorithms.AES(SECRET_KEY.encode()), modes.ECB()).decryptor()
    data = dec.update(bytes.fromhex(hexstr)) + dec.finalize()
    unpad = padding.PKCS7(128).unpadder()
    return (unpad.update(data) + unpad.finalize()).decode()


def headers(utc=False):
    now = datetime.datetime.now(datetime.timezone.utc) if utc else datetime.datetime.now()
    t = now.strftime("%Y%m%d%H%M%S")
    return {"authorization": base64.b64encode(f"{ACCESS_KEY_ID}:{t}".encode()).decode(),
            "sign": hashlib.md5(f"{ACCESS_KEY_ID}{SECRET_KEY}{t}".encode()).hexdigest().upper(),
            "User-Agent": UA}


def decode_response(r):
    try:
        j = r.json()
    except ValueError:
        sys.exit(f"Réponse non JSON (HTTP {r.status_code}) : {r.text[:300]}")
    if isinstance(j, dict) and isinstance(j.get("cipher"), str):
        j = json.loads(aes_decipher(j["cipher"]))
    return j


def redact(obj):
    if isinstance(obj, dict):
        return {k: ("<masqué>" if k.lower() in ("token", "password", "accountid", "userid", "email", "nickname")
                    else redact(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    return obj


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--beacon", action="append", help="deviceTypeBeacon (défaut : nx00626222 = Candle DIM)")
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent.parent / "firmware"))
    args = ap.parse_args()
    beacons = args.beacon or ["nx00626222"]

    if len(ACCESS_KEY_ID) != 32 or len(SECRET_KEY) != 16:
        sys.exit("NORDLUX_ACCESS_KEY_ID (32 car.) / NORDLUX_SECRET_KEY (16 car.) absentes : voir le README.")
    user, pwd = os.environ.get("NORDLUX_USER"), os.environ.get("NORDLUX_PASSWORD")
    if not user or not pwd:
        sys.exit("NORDLUX_USER / NORDLUX_PASSWORD absentes de l'environnement.")

    s = requests.Session()
    uniq = uuid.uuid4().hex

    # 1. Connexion
    login = dict(APP, email=user, password=pwd, pushToken="123456", languages="en", uniqueIndication=uniq)
    r = s.post(HOST + "smartLight/api/account/emailLogin", data={"cipher": aes_cipher(json.dumps(login))},
               headers=headers(), timeout=20)
    j = decode_response(r)
    if not j.get("isSuccess"):
        print("Échec de connexion :", json.dumps(redact(j), ensure_ascii=False))
        sys.exit(1)
    d = j.get("data") or {}
    token, account_id = d.get("token"), d.get("accountId")
    if not token:
        sys.exit("Connexion OK mais pas de jeton dans la réponse.")
    print("Connexion OK.")

    # 2. getOTAInfo
    req = dict(APP, token=token, accountId=account_id, uniqueIndication=uniq, languageCode="en",
               deviceList=[{"deviceTypeBeacon": b} for b in beacons])
    r = s.post(HOST + "smartLight/api/ota/getOTAInfo", json={"cipher": aes_cipher(json.dumps(req))},
               headers=headers(), timeout=20)
    j = decode_response(r)
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    (out / "getOTAInfo_response.json").write_text(json.dumps(redact(j), indent=2, ensure_ascii=False), encoding="utf-8")
    print("Réponse getOTAInfo :", json.dumps(redact(j), indent=2, ensure_ascii=False))
    if not j.get("isSuccess"):
        sys.exit(1)
    items = (j.get("data") or {}).get("deviceList") or []

    # 3. Téléchargement + MD5
    got = 0
    for it in items:
        url, name, md5 = it.get("lastVersionURL"), it.get("lastVersionFileName"), it.get("lastVersionMD5")
        if not url:
            continue
        name = Path(name or url.split("?")[0].rsplit("/", 1)[-1]).name
        r = requests.get(url, headers={"User-Agent": UA}, timeout=60)
        r.raise_for_status()
        h = hashlib.md5(r.content).hexdigest()
        dest = out / name
        dest.write_bytes(r.content)
        ok = (md5 or "").lower() == h
        print(f"{it.get('deviceTypeBeacon')} v{it.get('lastVersion')} -> {dest} ({len(r.content)} o) "
              f"MD5 {h} {'OK' if ok else 'DIFFÉRENT de ' + str(md5)}")
        got += 1
    if not got:
        sys.exit("Aucune URL de firmware dans la réponse.")


if __name__ == "__main__":
    main()
