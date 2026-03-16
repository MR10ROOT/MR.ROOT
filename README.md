# 🔍 MR.ROOT — Mobilny Skaner Sieci
### NetHunter Edition

> Narzędzie do rekonesansu i analizy sieci lokalnej, zaprojektowane do pracy na Kali NetHunter (Android).  
> Napisane w Pythonie, oparte na **nmap** i **NSE (Nmap Scripting Engine)**.

```
  ███╗   ███╗██████╗     ██████╗  ██████╗  ██████╗ ████████╗
  ████╗ ████║██╔══██╗    ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
  ██╔████╔██║██████╔╝    ██████╔╝██║   ██║██║   ██║   ██║
  ██║╚██╔╝██║██╔══██╗    ██╔══██╗██║   ██║██║   ██║   ██║
  ██║ ╚═╝ ██║██║  ██║    ██║  ██║╚██████╔╝╚██████╔╝   ██║
  ╚═╝     ╚═╝╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝
        Mobilny Skaner Sieci | by MR.ROOT | NetHunter Edition
```

---

## ⚠️ Disclaimer / Ostrzeżenie prawne

**To narzędzie zostało stworzone wyłącznie w celach edukacyjnych i do użytku na własnej sieci lub sieci, do której posiadasz pisemną zgodę właściciela.**

Używanie tego oprogramowania do skanowania sieci bez autoryzacji jest **nielegalne** i narusza m.in.:
- Polską ustawę o cyberbezpieczeństwie
- Europejską dyrektywę NIS2
- Przepisy karne Kodeksu karnego (art. 267 KK)

Autor nie ponosi żadnej odpowiedzialności za niewłaściwe użycie tego narzędzia.

---

## 📋 Funkcje

| Komenda | Opis |
|---|---|
| `<IP>` | Głęboki skan portów + detekcja OS |
| `<IP,IP,...>` | Wiele celów naraz |
| `i <IP>` | **Identity Scan** — mDNS, NetBIOS, SMB, UPnP |
| `snmp <IP>` | **SNMP Scan** — lokalizacja, kontakt admina, interfejsy |
| `v <IP>` | **Vuln-Scan NSE** — CVE, Heartbleed, EternalBlue |
| `b <IP>` | **Banner Grabber** — HTTP/HTTPS + raport HTML |
| `h` | Pomoc |
| `q` | Wyjście |

### Szczegóły modułów

**🔎 Identity Scan (`i <IP>`)**
- **mDNS/Zeroconf** (UDP/5353) — wykrywa nazwy `.local` urządzeń Apple, smart TV, drukarek
- **NetBIOS** (UDP/137) — nazwa komputera Windows, workgroup/domena
- **SMB** (TCP/139+445) — OS, lista udostępnionych folderów (null session)
- **UPnP/SSDP** (UDP/1900) — model urządzenia, producent, URL panelu konfiguracyjnego
- Na końcu generuje **Kartę urządzenia** — podsumowanie wszystkich wektorów

**📡 SNMP Scan (`snmp <IP>`)**
- Próbuje community strings: `public`, `private`, `community`, `admin`, `manager`
- Wyciąga: opis systemu, lokalizację, kontakt administratora, listę interfejsów, uruchomione procesy

**🛡️ Vuln-Scan (`v <IP>`)**
- Skrypty NSE: `vuln`, `ssl-heartbleed`, `ssl-poodle`, `smb-vuln-ms17-010`, `http-vuln-cve2017-5638`
- Kolorowe alerty: `⚠ PODATNOŚĆ` dla wykrytych CVE

**🌐 Banner Grabber (`b <IP>`)**
- Skanuje 11 portów HTTP/HTTPS (80, 443, 8008, 8080, 8443...)
- Wyciąga: tytuł strony, wersję serwera, podgląd HTML
- Ignoruje błędy SSL (self-signed certyfikaty IoT)
- Generuje **ciemny raport HTML** z rozwijanym podglądem kodu

---

## 🛠️ Wymagania

- **System:** Kali Linux / Kali NetHunter (Android)
- **Python:** 3.10+
- **nmap:** 7.80+
- **Uprawnienia:** root (wymagane dla skanów UDP i detekcji OS)

---

## 📦 Instalacja

```bash
# 1. Sklonuj repozytorium
git clone https://github.com/TWOJ_LOGIN/mr-root-recon.git
cd mr-root-recon

# 2. Utwórz środowisko wirtualne (opcjonalne, ale zalecane)
python3 -m venv .venv
source .venv/bin/activate

# 3. Zainstaluj zależności Python
pip install -r requirements.txt

# 4. Upewnij się że nmap jest zainstalowany
apt-get install nmap -y

# 5. Uruchom jako root
sudo python recon2.py
```

---

## 🚀 Użycie

```bash
sudo python recon2.py
```

Program automatycznie:
1. Wykrywa aktywny interfejs sieciowy (`wlan0` → `eth0` → `usb0`)
2. Przeprowadza ping sweep całej podsieci
3. Wyświetla listę aktywnych urządzeń z adresami MAC i producentami
4. Przechodzi do trybu interaktywnego

```
[>] Komenda: 192.168.1.1           # deep scan routera
[>] Komenda: i 192.168.1.15        # kto to jest?
[>] Komenda: b 192.168.1.4         # co serwuje na HTTP?
[>] Komenda: snmp 192.168.1.3      # drukarka z domyślnym hasłem?
[>] Komenda: v 192.168.1.1         # czy router ma dziury?
```

### Raporty

Wszystkie wyniki są automatycznie zapisywane:
```
/MR.ROOT/reports/
├── scan_192-168-1-0_24_20260315_210208.txt    ← ping sweep
├── scan_192-168-1-1_20260315_210431.txt       ← deep scan
├── identity_192-168-1-15_20260315_211005.txt  ← identity scan
├── snmp_192-168-1-3_20260315_211230.txt       ← snmp scan
├── vuln_192-168-1-1_20260315_211500.txt       ← vuln scan
└── html/
    └── scan_banner_192-168-1-4_*.html         ← banner grabber (HTML)
```

---

## 📁 Struktura projektu

```
mr-root-recon/
├── recon2.py          # główny skrypt
├── requirements.txt   # zależności Python
├── README.md          # dokumentacja
├── LICENSE            # licencja MIT
└── .gitignore         # wykluczone pliki
```

---

## 🗺️ Roadmap

- [ ] Eksport wyników do JSON
- [ ] Moduł WiFi — skanowanie sieci bezprzewodowych (iwlist / aircrack-ng)
- [ ] Automatyczny raport HTML po ping sweep
- [ ] Tryb cichy (`--quiet`) — tylko wyniki, bez kolorów
- [ ] Integracja z bazą CVE (NVD API)

---

## 📄 Licencja

MIT License — szczegóły w pliku [LICENSE](LICENSE).

---

<p align="center">
  Stworzony z ♥ przez <strong>MR.ROOT</strong> | NetHunter Edition
</p>
