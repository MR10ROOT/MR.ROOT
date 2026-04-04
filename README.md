# 🔍 MR.ROOT — Mobilny Skaner Sieci
### NetHunter Edition v3.0

> Zaawansowane narzędzie do rekonesansu, analizy sieci lokalnej i fuzzingu aplikacji webowych, zaprojektowane do pracy na Kali NetHunter (Android).  
> Napisane w Pythonie, oparte na **nmap**, **NSE** oraz autorskich, wielowątkowych modułach HTTP.

```text
  ███╗   ███╗██████╗     ██████╗  ██████╗  ██████╗ ████████╗
  ████╗ ████║██╔══██╗    ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
  ██╔████╔██║██████╔╝    ██████╔╝██║   ██║██║   ██║   ██║
  ██║╚██╔╝██║██╔══██╗    ██╔══██╗██║   ██║██║   ██║   ██║
  ██║ ╚═╝ ██║██║  ██║    ██║  ██║╚██████╔╝╚██████╔╝   ██║
  ╚═╝     ╚═╝╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝
        Mobilny Skaner Sieci | by MR.ROOT | NetHunter Edition v3.0
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

## 📋 Funkcje i Komendy

Skaner działa w płynnym trybie interaktywnym lub wykonuje pojedyncze zadania z poziomu CLI.

| Komenda | Opis |
|---|---|
| `<IP / IPv6>` | Głęboki skan portów + detekcja OS |
| `<IP,IP,...>` | Wiele celów naraz |
| `<CIDR>` | Skan całej podsieci — IPv4 (`192.168.1.0/24`) lub IPv6 (`fd00::/64`) |
| `sweep` / `sweep <CIDR>` | Szybki Ping Sweep aktywnej (lub podanej) podsieci |
| `i <IP>` | **Identity Scan** — mDNS, NetBIOS, SMB, UPnP |
| `snmp <IP>` | **SNMP Scan** — lokalizacja, kontakt admina, interfejsy |
| `v <IP>` | **Vuln-Scan NSE** — CVE, Heartbleed, Shellshock |
| `b <IP>` | **Banner Grabber** — wielowątkowe skanowanie HTTP/HTTPS + raport HTML |
| `f <IP> [wordlist]` | **Fuzzer Ścieżek** — 124 wbudowane wektory; opcjonalny zewnętrzny plik słownika |
| `h` | Pomoc |
| `q / exit` | Wyjście |

---

## 🔥 Szczegóły głównych modułów

### 🔎 Identity Scan (`i <IP>`)
- **mDNS/Zeroconf** (UDP/5353) — wykrywa nazwy `.local` urządzeń Apple, smart TV, drukarek
- **NetBIOS** (UDP/137) — nazwa komputera Windows, workgroup/domena
- **SMB** (TCP/139+445) — OS, lista udostępnionych folderów (null session)
- **UPnP/SSDP** (UDP/1900) — model urządzenia, producent, URL panelu konfiguracyjnego

### 🚀 Smart Fuzzer (`f <IP> [wordlist]`) *(Przepisano w v3.0!)*
- **124 wbudowane wektory** obejmujące: konfigurację/sekrety (`.env`, `.git/config`), panele admina, API/Swagger/GraphQL, Spring Boot Actuator, diagnostykę (phpinfo, server-status), backupy, pliki instalacyjne, artefakty IIS/Tomcat/macOS i wiele więcej.
- **Zewnętrzny słownik:** `f 192.168.1.1 /usr/share/wordlists/dirb/common.txt` — wczytuje dowolny plik (jeden wpis na linię), pomija komentarze.
- **Baseline Fingerprinting:** Skrypt uczy się wzorca Soft 404/Catch-all serwera i odrzuca fałszywe wyniki na podstawie skrótów MD5 i rozmiaru odpowiedzi.
- **Rate limiting:** `threading.BoundedSemaphore` + 80 ms przerwy między żądaniami — chroni przed blokowaniem IP i przeciążeniem celu.
- Poprawnie identyfikuje chronione zasoby (HTTP 401 i 403).

### 🌐 Banner Grabber (`b <IP>`)
- Wielowątkowo skanuje 11 najpopularniejszych portów HTTP/HTTPS.
- Automatyczna rotacja nagłówków User-Agent w celu ominięcia prostych filtrów.
- Pełna obsługa IPv6 (poprawne formatowanie URL: `http://[fd00::1]:80/`).
- Generuje **ciemny raport HTML** z rozwijanym podglądem kodu przechwyconej strony.

### 🛡️ Vuln-Scan (`v <IP>`)
- Domyślnie skanuje **top-1000 portów** (szybko, przyjazne dla telefonu). Flaga `--full-ports` przełącza na wszystkie 65 535 portów.
- Odpala zestaw skryptów NSE: `vuln`, `ssl-heartbleed`, `ssl-poodle`, `smb-vuln-ms17-010`, `http-shellshock` i inne.
- Kolorowe alerty w terminalu dla błyskawicznej identyfikacji krytycznych luk.

---

## 🛠️ Wymagania

| Element | Wersja |
|---|---|
| System | Kali Linux / Kali NetHunter (Android) |
| Python | 3.10+ |
| nmap | 7.80+ |
| Uprawnienia | root (wymagane dla skanów UDP, detekcji OS i surowych pakietów) |

> **v3.0:** Skrypt wykrywa brak roota przy starcie i wyświetla ostrzeżenie o ograniczonej funkcjonalności — zamiast po cichu zwracać puste wyniki z nmap.

---

## 📦 Instalacja

```bash
# 1. Sklonuj repozytorium
git clone https://github.com/TWOJ_LOGIN/mr-root-recon.git
cd mr-root-recon

# 2. Utwórz środowisko wirtualne (zalecane)
python3 -m venv .venv
source .venv/bin/activate

# 3. Zainstaluj zależności Python
pip install -r requirements.txt

# 4. Upewnij się, że nmap jest zainstalowany w systemie
apt-get install nmap -y

# 5. Nadaj uprawnienia i uruchom jako root
chmod +x recon3.py
sudo python3 recon3.py
```

---

## 🚀 Użycie

### Tryb Interaktywny

Wystarczy uruchomić skrypt bez argumentów. Program automatycznie:

1. Sprawdzi uprawnienia roota i poinformuje o ograniczeniach.
2. Wyświetli ostrzeżenie o trybie SSL (unverified / pentest).
3. Sprawdzi połączenie z internetem (wykrywanie Captive Portal).
4. Wykryje aktywny interfejs sieciowy (IPv4 **i** IPv6).
5. Zaproponuje szybki Ping Sweep w celu odnalezienia sąsiadów w sieci.

```
[MR.ROOT]>> sweep 192.168.1.0/24        # Szybka mapa sieci
[MR.ROOT]>> 192.168.1.1                 # Deep scan routera
[MR.ROOT]>> i 192.168.1.15             # Identity Scan (kto to jest?)
[MR.ROOT]>> b 192.168.1.4              # Banner Grabber
[MR.ROOT]>> f 192.168.1.1              # Fuzzer — wbudowany słownik (124 wpisy)
[MR.ROOT]>> f 192.168.1.1 /usr/share/wordlists/dirb/common.txt  # zewnętrzny słownik
[MR.ROOT]>> fd00::1                    # Deep scan IPv6
```

### Tryb CLI (One-Shot Mode)

Idealny do automatyzacji i pisania skryptów w Bashu.

```bash
# Podstawowe
sudo python3 recon3.py -t 192.168.1.100 -m deep
sudo python3 recon3.py -t 10.0.0.0/24  -m sweep
sudo python3 recon3.py -t 192.168.1.1  -m fuzz

# Fuzzer z zewnętrznym słownikiem
sudo python3 recon3.py -t 192.168.1.1 -m fuzz -w /usr/share/wordlists/dirb/common.txt

# Vuln-scan wszystkich portów (wolno — tylko na urządzeniu stacjonarnym lub ze świadomością)
sudo python3 recon3.py -t 192.168.1.1 -m vuln --full-ports

# Tryb z weryfikacją certyfikatów SSL (nie-pentest)
sudo python3 recon3.py -t 192.168.1.1 -m banner --strict-ssl
```

### Flagi globalne

| Flaga | Opis |
|---|---|
| `-t / --target` | Cel: IP, IPv6, CIDR lub lista oddzielona przecinkami |
| `-m / --mode` | Tryb: `deep`, `identity`, `snmp`, `vuln`, `banner`, `fuzz`, `sweep` |
| `-w / --wordlist` | Plik słownika dla fuzzera |
| `--strict-ssl` | Weryfikuj certyfikaty SSL (domyślnie: unverified / pentest mode) |
| `--full-ports` | Vuln-scan: skanuj wszystkie 65 535 portów zamiast top-1000 |

---

## 📁 Raporty (JSON & HTML)

Wszystkie wyniki są automatycznie strukturyzowane i zapisywane w bezpiecznym katalogu:

```text
/MR.ROOT/reports/
├── sweep_20260402_170916.txt                  ← lista hostów
├── scan_20260402_172208.json                  ← deep scan
├── identity_192-168-1-1_20260402_172221.json  ← identity scan
├── fuzz_192-168-1-1_20260402_180900.json      ← wyniki fuzzera
├── banner_192-168-1-1_20260402_172536.json    ← banner grabber (surowe dane)
└── html/
    └── banner_192-168-1-1_20260402_172536.html ← banner grabber (raport HTML)
```

---

## 🗺️ Roadmap

- [x] Eksport wyników do JSON *(v2.1)*
- [x] Obsługa argumentów z linii komend (CLI) *(v2.1)*
- [x] Inteligentny Fuzzer Ścieżek z baseline fingerprinting *(v2.2)*
- [x] Rozbudowany słownik fuzzera (124 wpisy) + zewnętrzny plik słownika *(v3.0)*
- [x] Obsługa IPv6 (adresy, sieci, URL) *(v3.0)*
- [x] Rate limiting w fuzzerze (semaphore + delay) *(v3.0)*
- [x] Weryfikacja SSL z flagą `--strict-ssl` *(v3.0)*
- [x] Sprawdzenie uprawnień roota przy starcie *(v3.0)*
- [x] Vuln-scan top-1000 domyślnie + flaga `--full-ports` *(v3.0)*
- [x] Globalny timeout skanowania (300 s) + limit 2 równoległych procesów NMAP *(v3.0)*
- [ ] Moduł WiFi — skanowanie sieci bezprzewodowych (iwlist / airodump-ng)
- [ ] Automatyczny raport HTML połączony z widokiem Ping Sweep
- [ ] Tryb cichy (`--quiet`) — tylko wyniki, bez ANSI kolorów
- [ ] Integracja z bazą CVE (NVD API) dla wykrytych banerów

---

## 📄 Licencja

MIT License — szczegóły w pliku `LICENSE`.

<p align="center">
Stworzony z ♥ przez <strong>MR.ROOT</strong> | NetHunter Edition
</p>
