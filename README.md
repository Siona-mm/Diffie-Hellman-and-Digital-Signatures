# Diffie Hellman and Digital Signatures
 
---

## Përmbledhja e Projektit 
Ky aplikacion është një sistem komunikimi klient-server (Console Application) i ndërtuar në mënyrë asinkrone me Python (`asyncio` dhe `websockets`). Projekti demonstron zbatimin praktik të kriptografisë asimetrike dhe simetrike për të krijuar një kanal të sigurt bisede mbi një rrjet të pasigurt.

Sistemi garanton katër shtyllat kryesore të sigurisë:
1. **Konfidencialitetin (Confidentiality):** Përmes enkriptimit simetrik AES-CBC.
2. **Autentikimin (Authentication):** Përmes nënshkrimeve dixhitale RSA-PSS.
3. **Integritetin (Integrity):** Përmes fuksioneve hash SHA-256 dhe padding-ut PKCS7.
4. **Mos-mohimin (Non-Repudiation):** Çdo mesazh i serverit nënshkruhet me çelësin e tij privat.

---

## Staku Teknik & Algoritmet 
Aplikacioni përdor librarinë standarde industriale `cryptography` në Python për të gjitha operacionet:

* **ECDH (Elliptic Curve Diffie-Hellman):** Përdor kurbën standarde `SECP256R1` për marrëveshjen e çelësit të fshehtë.
* **HKDF (HMAC-based Key Derivation Function):** Përdoret me SHA-256 për të derivuar një çelës të pastër 256-bitësh nga sekreti i shkëmbyer.
* **RSA-PSS (2048-bit):** Skema më moderne e nënshkrimit dixhital asimetrik për vërtetimin e identitetit të serverit.
* **AES-CBC (256-bit):** Enkriptimi simetrik për mesazhet e bisedës, i shoqëruar me **PKCS7 Padding** dhe IV (Initialization Vector) të rastësishëm për çdo mesazh.

---

## Setup & Installation (Windows PowerShell)

Ndiqni këto hapa në terminalin tuaj për të konfiguruar mjedisin dhe për të nisur aplikacionet.

### 1. Navigoni te direktoria e projektit tuaj

```powershell
cd C:\path\...\...\...

```

### 2. Krijoni një mjedis virtual

```powershell
python -m venv .venv

```

### 3. Aktivizoni mjedisin virtual

```powershell
& .\.venv\Scripts\Activate.ps1

```

### 4. Instaloni paketat e nevojshme (Dependencies)

```powershell
pip install -r requirements.txt

```

### 5. Nisni Serverin

```powershell
python server.py

```

### 6. Nisni Klientin

```powershell
python client.py

```


### macOS / Linux (Terminal)

### 1. Navigoni te direktoria e projektit tuaj
```bash
cd /path/.../.../...

```


### 2. Krijoni një mjedis virtual
```bash
python3 -m venv .venv

```


### 3. Aktivizoni mjedisin virtual
```bash
source .venv/bin/activate

```


### 4. Instaloni paketat e nevojshme (Dependencies)
```bash
pip install -r requirements.txt

```


### 5. Nisni Serverin
```bash
python3 server.py

```


### 6. Nisni Klientin
```bash
python3 client.py

```

## Rrjedha e Protokollit (Handshake Execution)
Kur klienti lidhet me serverin, ekzekutohen këto faza automatikisht në konsole:

* **Faza 1 (Shkëmbimi i çelësave publikë):** Serveri dërgon çelësin e tij publik RSA dhe çelësin e tij publik ECDH. Klienti gjeneron çiftin e tij të çelësave ECDH dhe ia kthen çelësin e tij publik serverit.
* **Faza 2 (Derivimi i Sekretit):** Të dyja palët llogarisin të pavarura çelësin e përbashkët (Shared Secret) përmes Diffie-Hellman pa dërguar asgjë sekrete në rrjet.
* **Faza 3 (Autentikimi & Mirëseardhja):** Serveri nënshkruan një mesazh mirëseardhjeje me RSA privat dhe e enkripton me AES. Klienti e dekripton, verifikon nënshkrimin RSA me çelësin publik të serverit. Nëse nënshkrimi është valid, kanali konsiderohet i besueshëm.
* **Faza 4 (Komunikimi i Enkriptuar):** Hapen konsolat `Server>` dhe `Client>` ku përdoruesit mund të shkruajnë mesazhe të enkriptuara plotësisht me AES-CBC 256-bit.

---

## Trajtimi i Gabimeve (Error Handling)
Sistemi është i mbrojtur nga rrëzimi (crash) dhe sulmet e jashtme:

* Nëse një mesazh i enkriptuar modifikohet përgjatë rrugës (Sulm i integritetit), standardi **PKCS7** dhe blloku `try-except` te `CryptoUtils.decrypt_message` do ta kapin gabimin në mënyrë elegante pa e thyer programin.
* Nëse nënshkrimi dixhital i serverit dështon, klienti refuzon menjëherë komunikimin duke shfaqur: `✗ Invalid signature - Message rejected!`.

