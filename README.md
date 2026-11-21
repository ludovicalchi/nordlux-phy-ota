# nordlux-phy-ota

Récupération par Bluetooth d'une ampoule **Nordlux Smart Light** (puce Phyplus **PHY6222**) restée bloquée dans son bootloader OTA après une mise à jour ratée depuis l'app Nordlux. Testé avec succès le 21/11/2026 sur une « Candle DIM » (`nx0062`), firmware v27.3, depuis Windows 11 (adaptateur Intel, bleak 2.1.1).

> Le firmware n'est pas inclus dans ce dépôt (il appartient à Nordlux/Yankon). Le script `nordlux_fetch_fw.py` le télécharge avec **votre** compte Nordlux, comme le fait l'app.

## Symptôme

- L'ampoule ne répond plus dans l'app après une mise à jour qui a échoué sans message.
- Un scan BLE (nRF Connect, par exemple) montre un appareil nommé `nxXXXXv1` avec :
  - des manufacturer data de Company ID `0x0504` (PHYPLUS Inc), dont le payload commence par la MAC en little-endian ;
  - un seul service hors GAP/GATT, `5833ff01-9b8b-5191-6142-22a4536ef123` (OTA Phyplus), avec les caractéristiques `ff02` (write), `ff03` (notify) et `ff04` (write without response) ;
  - aucun service mesh (ni `0x1827` ni `0x1828`).

L'ampoule tourne alors dans son bootloader : elle est récupérable par radio.

## Pourquoi l'app échoue

Le SDK OTA Phyplus embarqué dans l'app (`com.phy.ota.sdk`) demande un MTU de **200**. Depuis Android 14, Android ignore cette valeur et négocie toujours le maximum ; Windows fait de même. L'ampoule accepte un MTU de **240**, et l'app envoie donc des paquets de données de 237 octets (MTU − 3).

Le bootloader ne supporte pas ces gros paquets : il cesse d'acquitter dès le premier bloc et l'app abandonne sans message. Constaté :

| Taille de paquet | Résultat |
|---|---|
| 237 o (comportement de l'app avec un MTU de 240) | aucun acquittement ; le lien radio meurt (trace HCI Android) |
| 197 o | aucun acquittement |
| **20 o** | **OK** : flashage complet en 217 s, sans aucune erreur de bloc |

Le bootloader compte ses blocs **en octets** : 16 × (MTU − 3), soit 3 792 o avec un MTU de 240, quelle que soit la taille des paquets.

## Prérequis

- Python 3.10+ avec `bleak`, `requests`, `cryptography` : `pip install bleak requests cryptography`.
- Un PC avec Bluetooth LE (testé sous Windows 11 ; macOS et Linux devraient fonctionner avec bleak).
- L'app Nordlux et nRF Connect fermées : l'ampoule n'accepte qu'une connexion à la fois.
- Le PC à 1–2 m de l'ampoule.

## Procédure

### 1. Trouver l'ampoule en mode OTA

Notez la MAC de l'appareil `nxXXXXv1` qui expose le service `5833ff01…`, puis cherchez son `firmwareBeacon` dans le [tableau ci-dessous](#modèles-phy6222-plateforme-2). Le code à 4 chiffres du nom correspond au début du beacon : `nx0062v1` → `nx00626222`.

### 2. Télécharger le firmware

```powershell
$env:NORDLUX_USER = "vous@example.com"
$env:NORDLUX_PASSWORD = "…"
$env:NORDLUX_ACCESS_KEY_ID = "…"   # voir « Clés de l'API »
$env:NORDLUX_SECRET_KEY = "…"
python tools/nordlux_fetch_fw.py --beacon nx00626222
```

Le fichier (`<id>.hex16`) est écrit dans `firmware/` après vérification du MD5 fourni par le serveur. Le mot de passe et le jeton de session ne sont jamais affichés.

### 3. Vérifier l'image (sans radio)

```bash
python tools/phy_ota.py firmware/<id>.hex16 --dry-run
```

Le script affiche les partitions et les commandes qui seront envoyées. Pour la Candle DIM v27.3 : 10 partitions, 122 724 o, 7 partitions en flash (0x1101B000…) et 3 en SRAM (0x1FFFxxxx).

### 4. Flasher

```bash
python tools/phy_ota.py firmware/<id>.hex16 --mac AA:BB:CC:DD:EE:FF
```

Réglages par défaut : paquets de 20 o, blocs de 16 × (MTU − 3) o, pause de 10 ms entre paquets, 10 essais de connexion, reboot à la fin. Tout est journalisé dans `firmware/ota_log_*.txt`.

En cas d'échec, l'ampoule reste dans son bootloader et on peut relancer.

### 5. Vérifier

Après le reboot (`00 8a`), l'ampoule annonce son firmware applicatif :
- à la MAC **du mode OTA moins 1** (le SDK ajoute 1 au dernier octet en mode OTA) ;
- avec le service **Mesh Proxy `0x1828`** si elle est toujours provisionnée (elle conserve ses clés mesh), ou `0x1827` si elle doit être réinstallée.

## Protocole OTA Phyplus

Toutes les commandes passent sur `ff02` (écriture avec réponse) et toutes les réponses arrivent en notification sur `ff03`. Les entiers sont en little-endian.

| Étape | Envoi | Réponse attendue |
|---|---|---|
| Début | `01 <nb_partitions> 00` | `00 81` |
| Partition *i* | `02 <i> <flash_addr u32> <run_addr u32> <len u32> <crc16 u16>` | `00 84` |
| Données | blocs de 16 × (MTU − 3) o sur `ff04` (write without response) | `00 87` par bloc |
| Fin de partition | — | `00 85` |
| Fin d'OTA | — | `00 83` |
| Bloc rejeté | (renvoyer le bloc) | `68 87` |
| Reboot | `04 01` (avec réponse, si MTU > 23) ou `04` | `00 8a` |

- **CRC16** : CRC-16/ARC (polynôme réfléchi 0xA001, valeur initiale 0) sur les données de la partition.
- **Adresse flash** : si `run_addr` ∈ [0x11000000, 0x1107FFFF], `flash_addr = run_addr`. Sinon (partitions en SRAM), `flash_addr` est un décalage qui commence à 0 et augmente de `len + 8` après chaque partition hors flash (`len + 4` pour les fichiers `.hexe16`).
- **Format `.hexe16`** : le champ CRC est remplacé par les 4 derniers octets de la partition (non inversés).
- **Image** : fichier Intel HEX. Chaque enregistrement de type `04` ouvre une partition ; les données des enregistrements suivants sont concaténées ; l'adresse vaut ELA(16 bits) + offset du premier enregistrement ; `01` ou `05` termine la lecture.
- Le SDK contient aussi un mode « Security » (commandes 05–08, AES) que l'app Nordlux n'utilise pas pour les ampoules.

## API cloud (firmware)

L'app (v2.6.2, paquet `com.nx.smbt5.a.android`) parle à `https://api.yankon-xm.com/` (Yankon est le fabricant OEM).

- **En-têtes** :
  - `authorization: base64(accessKeyId + ":" + yyyyMMddHHmmss)` ;
  - `sign: MD5(accessKeyId + secretKey + yyyyMMddHHmmss)` en hexadécimal majuscule.
- **Corps** : le JSON de la requête est chiffré en AES-128-ECB/PKCS7 avec `secretKey`, puis encodé en hexadécimal majuscule dans un champ `cipher`.
- **Connexion** : `POST smartLight/api/account/emailLogin`, en formulaire `cipher=…`. Le JSON contient `email`, `password` (en clair à l'intérieur du chiffrement), `pushToken`, `languages`, `uniqueIndication`, `appCode="nordlux"`, `version="v2.0.0"`, etc. La réponse renvoie `data.token` et `data.accountId`.
- **Firmware** : `POST smartLight/api/ota/getOTAInfo`, corps JSON `{"cipher": …}` avec `token`, `accountId`, `languageCode` et `deviceList: [{"deviceTypeBeacon": "nx00626222"}]`. La réponse renvoie `lastVersion`, `lastVersionURL` (URL S3 pré-signée), `lastVersionFileName` et `lastVersionMD5`.

### Clés de l'API

Les clés applicatives (`accessKeyId`, 32 caractères hexadécimaux, et `secretKey`, 16 caractères) sont codées en dur dans l'app et ne sont pas reproduites ici. Pour les retrouver :

1. Récupérez l'APK de l'app installée : `adb shell pm path com.nx.smbt5.a.android`, puis `adb pull <chemin>`.
2. Décompilez-la avec [jadx](https://github.com/skylot/jadx) : `jadx --no-res -d src nordlux.apk`.
3. Lisez `src/sources/com/nx/smbt5/a/android/wifi/ykutils/SecurityUtil.java`, champs `accessKeyId` et `secretKey`.

## Modèles PHY6222 (plateforme 2)

Extrait de `assets/device/device_type.json` (app v2.6.2) :

| firmwareBeacon | typeCode | Modèle |
|---|---|---|
| nx00566222 | 57 | E27 SMD |
| nx00576222 | 58 | E27 DIM |
| nx00586222 | 59 | GU10 Plastic |
| nx00596222 | 60 | GU10 DIM |
| nx00606222 | 61 | GU10 Glass |
| nx00616222 | 62 | E14 Candle |
| nx00626222 | 63 | Candle DIM *(testé)* |
| nx00636222 | 64 | E14 Globe |
| nx00646222 | 65 | LANDON |
| nx00656222 | 66 | E27 A60 Filament |
| nx00666222 | 67 | E27 Globe Filament |
| nx00676222 | 68 | E27 Giant 95 |
| nx00686222 | 69 | E27 Decorative |
| nx00696222 | 70 | Spot |
| nx00706222 | 71 | A60 Colour |
| nx00716222 | 72 | E27 Globe 95 Colour |
| nx00726222 | 73 | GU10 Colour |
| nx00736222 | 74 | DON Downlight Colour |
| nx00746222 | 76 | STRIP |
| nx00756222 | 75 | OJA |
| nx00776222 | 78 | Smart Button |
| nx00786222 | 79 | Indoor Sensor |

Les modèles des plateformes 0 et 1 (MediaTek/Airoha, Silicon Labs) utilisent d'autres procédures OTA, non couvertes ici.

## Outils

| Script | Rôle |
|---|---|
| `tools/phy_ota.py` | Flasheur OTA PHY62xx (bleak), avec `--dry-run`. |
| `tools/phy_ota_diag.py` | Diagnostic : envoie les données paquet par paquet et vérifie que l'ampoule répond (lecture du CCCD) ; n'envoie jamais de reboot. |
| `tools/nordlux_fetch_fw.py` | Connexion au compte Nordlux, appel getOTAInfo, téléchargement avec vérification MD5. |
| `tools/parse_btsnoop.py` | Analyse d'un journal HCI Android (`btsnoop_hci.log`) : connexions, table GATT et chronologie ATT pour une MAC. |
| `tools/nocp.py` | Paquets ACL envoyés et acquittés par le contrôleur (Number of Completed Packets) pour un handle. |
| `tools/dex_strings.py` | Recherche par regex dans les chaînes des fichiers `.dex` d'une APK. |

Pour obtenir une trace HCI sur Android : Options pour les développeurs → Journal HCI Bluetooth = « Activé », couper puis rallumer le Bluetooth, reproduire le problème, puis `adb bugreport out.zip` (fichier `FS/data/misc/bluetooth/logs/btsnoop_hci.log`).

## Avertissement

Projet personnel, non affilié à Nordlux ni à Yankon. À utiliser à vos risques : flasher un mauvais firmware peut rendre l'ampoule inutilisable. Vérifiez toujours le beacon et lancez `--dry-run` d'abord.
