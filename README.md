# MR.ROOT – Mobilny Skaner Sieci

**NetHunter Edition v3.8 REDHUNT-16-BETA | ADB-PENTEST**

Zaawansowane narzędzie do rekonesansu, analizy sieci lokalnej, fuzzingu aplikacji webowych, automatycznego wykrywania podatności SQL Injection oraz **pentestów urządzeń mobilnych Android przez ADB**, zaprojektowane z myślą o pracy na Kali NetHunter (Android).
Napisane w Pythonie, oparte na nmap, NSE, SearchSploit, sqlmap, Frida oraz autorskich, wielowątkowych modułach HTTP.

```
  ███╗   ███╗██████╗     ██████╗  ██████╗  ██████╗ ████████╗
  ████╗ ████║██╔══██╗    ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
  ██╔████╔██║██████╔╝    ██████╔╝██║   ██║██║   ██║   ██║
  ██║╚██╔╝██║██╔══██╗    ██╔══██╗██║   ██║██║   ██║   ██║
  ██║ ╚═╝ ██║██║  ██║    ██║  ██║╚██████╔╝╚██████╔╝   ██║
  ╚═╝     ╚═╝╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝
        NetHunter Edition v3.8 REDHUNT-16-BETA | ADB-PENTEST
```

---

## ⚠️ Zastrzeżenie prawne (Disclaimer)

Narzędzie powstało wyłącznie w celach edukacyjnych oraz do testów na własnych urządzeniach lub po uzyskaniu pisemnej zgody ich właściciela.
Nieautoryzowane skanowanie sieci i urządzeń jest nielegalne i narusza m.in.:

- polską ustawę o cyberbezpieczeństwie,
- europejską dyrektywę NIS2,
- przepisy Kodeksu karnego (art. 267 KK).

Autor nie ponosi odpowiedzialności za niewłaściwe użycie narzędzia.

---

## 📋 Funkcje i komendy (tryb interaktywny)

Skaner działa w trybie interaktywnym lub jako pojedyncze zadanie z linii poleceń (CLI).

| Komenda | Opis |
|---|---|
| `<IP / IPv6>` | Głęboki skan portów + detekcja OS + szukanie exploitów (SearchSploit) |
| `<IP,IP,...>` | Skan wielu wskazanych celów |
| `<CIDR>` | Skan całej podsieci – IPv4 (np. `192.168.1.0/24`) lub IPv6 (np. `fd00::/64`) |
| `sweep [CIDR]` | Szybki ping sweep podsieci z wizualnym oznaczaniem urządzeń mobilnych (📱/💻) |
| `i <IP>` | Identity Scan – mDNS (w tym detekcja iOS/Android), NetBIOS, SMB, UPnP |
| `snmp <IP>` | SNMP Scan – lokalizacja, kontakt admina, interfejsy sieciowe |
| `v <IP>` | Vuln-Scan NSE – CVE, Heartbleed, Shellshock |
| `b <IP>` | Banner Grabber – skanowanie HTTP/HTTPS + audyt nagłówków bezpieczeństwa |
| `f <IP> [słownik]` | Fuzzer ścieżek – 124 wbudowane wektory, opcjonalny zewnętrzny plik słownika |
| `m <IP>` | Mobile Scan – porty ADB/iOS/AirPlay/KDE Connect + mDNS fingerprint |
| `mf <IP>` | Mobile Fuzzer – wyszukiwanie otwartych katalogów Android/iOS (np. `/sdcard/`) |
| `all <IP>` | Full Scan – wszystkie moduły sekwencyjnie (przerwanie fazy: Ctrl+C) |
| `all-net` | Full Scan sieci – ping sweep + automatyczny pełny skan każdego hosta |
| `sql <URL>` | **[v3.5]** SQLMap Auto-Tamper WAF-Bypass – rotacja 6 łańcuchów tamperów 2025/2026 |
| `auto-sql <URL>` | **[v3.5]** Auto-Spider + SQLMap – crawl strony → deduplikacja → masowy atak SQLi |
| `hw <URL>` | **[v3.6]** Headless browser scan – analiza przez Playwright/Chromium |
| `hpp <URL>` | **[v3.6]** HTTP Parameter Pollution test – WAF bypass via fragmentacja |
| `adb` | **[v3.8]** ADB Audit – Device Info, APK Enum, Debug Surface (USB) |
| `adb <package>` | **[v3.8]** ADB Audit + Frida SSL Unpin na wskazanej aplikacji |
| `adb-frida <pkg>` | **[v3.8]** Frida SSL Unpin – push frida-server + inject |
| `adb-dump [sec]` | **[v3.8]** tcpdump capture przez ADB USB (domyślnie 30s) → .pcap |
| `h` | Pomoc |
| `q / exit` | Wyjście |

---

## 🔥 Szczegóły głównych modułów

### 📱 ADB Pentest Module — nowość v3.8

Kompletny moduł do pentestów urządzeń mobilnych Android przez kabel USB (ADB).
Działa z poziomu Kali NetHunter — nie wymaga żadnej instalacji na urządzeniu docelowym poza włączeniem Debugowania USB.

#### `adb` — Device Info + Debug Surface + APK Enumeration

Trójfazowy audit urządzenia:

**Faza 1 — Device Info (`getprop`)**
Zbiera pełną kartę urządzenia: brand, model, codename, Android version, SDK, ABI, kernel, build_type, build_tags, verified_boot state, SELinux mode, ro.debuggable, ro.secure, USB config, ADB TCP port, dostępność root shell (`su`), fingerprint.

**Faza 2 — Debug Surface Analysis**
Automatycznie analizuje zebrane właściwości i generuje listę findings z priorytetami:
- 🔴 **HIGH**: `ro.debuggable=1`, `ro.secure=0`, `build_type=userdebug/eng`, SELinux=Permissive, ADB TCP aktywne przez WiFi
- 🟡 **MED**: `build_tags` bez release-keys, Verified Boot != green, ADB aktywne przez USB
- 🔵 **INFO**: Dostępny root shell

**Faza 3 — APK Enumeration**
Listuje wszystkie zainstalowane aplikacje (user + system) i automatycznie flaguje interesujące z punktu widzenia bezpieczeństwa: bankowość (PKO, mBank, ING, Alior, BLIK), komunikatory E2E (Signal, WhatsApp, Telegram), VPN (NordVPN, Mullvad, Tor), narzędzia root (Magisk), identyfikacja rządowa (mObywatel).

Wynik: raport JSON w `/MR.ROOT/reports/adb_audit_<serial>_<timestamp>.json`

---

#### `adb-frida <package>` — Frida SSL Unpin

Automatyzuje cały proces SSL unpinningu:

1. Push `frida-server` ARM64 na urządzenie (`/data/local/tmp/`)
2. `chmod +x` + uruchomienie przez `su` w tle
3. Weryfikacja procesu (`ps -A | grep frida`)
4. Uruchomienie aplikacji docelowej przez `monkey` jeśli nie działa
5. Inject skryptu SSL Unpin (4 warstwy bypass):
   - **OkHttp3 CertificatePinner** — najpopularniejsza biblioteka HTTP w Androidzie
   - **javax.net.ssl.TrustManager** — natywny Java TLS
   - **Conscrypt TrustManagerImpl** — Android 7+ (używany przez WebView)
   - **Network Security Config** — Android 7+ NSC pinning
6. Zatrzymanie frida-server po wyjściu (Ctrl+C)

Działa w połączeniu z **mitmproxy** lub **Burp Suite** — po instalacji certyfikatu CA w systemowym store (`/system/etc/security/cacerts/`) przechwytuje pełny ruch HTTPS w plaintext.

**Przetestowane:** Samsung Galaxy Tab A9 (SM-X110) — WeChat (`com.tencent.mm`) + Facebook SDK bypass ✅

---

#### `adb-dump [sekundy]` — Traffic Dump

Przechwytuje ruch sieciowy bezpośrednio na urządzeniu:

1. Push statycznego `tcpdump` ARM64 na urządzenie
2. Capture na interfejsie `any` przez podaną liczbę sekund (domyślnie 30)
3. Auto-pull pliku `.pcap` na hosta do katalogu raportów
4. Usunięcie tymczasowych plików z urządzenia

Wynik gotowy do otwarcia w **Wireshark**.

---

#### Wymagania modułu ADB (v3.8)

| Składnik | Jak uzyskać |
|---|---|
| `adb` | `apt install adb` (Kali) / `pkg install android-tools` (Termux) |
| `frida-tools` | `pip install frida-tools --break-system-packages` |
| `frida-server` ARM64 | [github.com/frida/frida/releases](https://github.com/frida/frida/releases) → `frida-server-*-android-arm64.xz` |
| `tcpdump` ARM64 (static) | [github.com/extremecoders-re/tcpdump-android-builds](https://github.com/extremecoders-re/tcpdump-android-builds) |

Ścieżki domyślne (konfigurowalne w kodzie):
```
FRIDA_SERVER_LOCAL  = "/MR.ROOT/frida-server"
TCPDUMP_LOCAL       = "/MR.ROOT/tcpdump"
```

Wersja `frida-server` **musi być identyczna** z wersją `frida-tools`:
```bash
frida --version        # np. 17.9.1
# Pobierz frida-server-17.9.1-android-arm64.xz
```

---

#### Przykładowy flow — pełny pentest mobilny

```bash
# 1. Podłącz urządzenie docelowe przez USB
adb devices
# → cmtokbayqkpbofbi   device

# 2. Uruchom MR.ROOT
python3 recon3-8.py

# 3. Pełny audit (device info + debug surface + APK enum)
[MR.ROOT]>> adb

# 4. SSL Unpin na konkretnej aplikacji
[MR.ROOT]>> adb-frida com.tencent.mm

# 5. W osobnym terminalu — przechwytywanie ruchu
mitmproxy --listen-host 0.0.0.0 --listen-port 8082

# 6. Capture ruchu do pcap
[MR.ROOT]>> adb-dump 60
```

---

### 🛡️ Moduły STEALTH / WAF-Bypass — nowość v3.6

**Smart Delay + Jitter:**
- Losowe opóźnienia między żądaniami (`JITTER_MIN`/`JITTER_MAX`: 0.3–1.8 s) zamiast stałego interwału.
- Utrudnia heurystyczną detekcję przez WAF/IPS.

**Zaawansowana rotacja nagłówków (`_smart_headers()`):**
- Rozszerzony pool nagłówków: `Accept-Language`, `Referer`, `Sec-Ch-Ua` (Client Hints), `X-Forwarded-For`.
- Losowa rotacja przy każdym żądaniu.

**WAF-Bypass via fragmentacja:**
- `hpp <URL>` — HTTP Parameter Pollution przez `_hpp_url()`.
- `_send_chunked()` — Chunked Transfer Encoding przez raw socket.

**Detekcja Rate Limiting + Cooldown:**
- Per-IP state machine (`_RL_STATE`) — cooldown jednego celu nie blokuje pozostałych.
- Automatyczne rozpoznanie kodów 403/429/503 → wstrzymanie skanowania (domyślnie 300 s).

**Headless browser scan (`hw <URL>`):**
- Integracja z Playwright/Chromium — analiza stron renderowanych przez JavaScript.
- Wymaga: `pip install playwright && playwright install chromium`.

---

### 💉 Moduły SQL Injection (sql, auto-sql) — nowość v3.5

**`sql <URL>`** – SQLMap Auto-Tamper WAF-Bypass:
- Automatycznie rotuje 6 najskuteczniejszych łańcuchów tamperów skonstruowanych pod nowoczesne WAF (2025/2026).
- Uruchamia `sqlmap --level=5 --risk=3 --batch --random-agent`.
- **[v3.7]** Flaga `--resume` → wznawia poprzednią sesję SQLMap (`--no-flush-session`).
- Wykrywa podatność **na żywo** przez parsowanie stdout — zatrzymuje się przy pierwszym potwierdzeniu.
- Po sukcesie wyświetla gotową komendę `--dump-all` z najlepszym tamperem.

**`auto-sql <URL>`** – Auto-Spider + masowy SQLi:
- Pobiera kod źródłowy strony i wyciąga wszystkie linki `href`.
- **Deduplikuje wektory ataku** po sygnaturze `(ścieżka_pliku, zestaw_parametrów_GET)`.
- Wyświetla tabelę unikalnych endpointów przed atakiem.
- Wywołuje `sql_scan()` sekwencyjnie na każdym znalezionym parametryzowanym URL.

---

### 📱 Moduły mobilne sieciowe (m, mf) — nowość v3.4

- **Mobile Scan** – dedukuje typ urządzenia przez skanowanie portów: ADB (5555), Apple Lockdown (62078), KDE Connect (1714–1764), AirDroid (8888), AirPlay (7000) + mDNS.
- **Mobile Fuzzer** – generuje słownik ścieżek mobilnych (`/sdcard/`, `/DCIM/`, `/WhatsApp/Media/` itd.) i skanuje serwery HTTP w poszukiwaniu niezabezpieczonych plików.

---

### 🚀 Smart Fuzzer (f \<IP\> [słownik])

- **124 wbudowane wektory:** sekrety (`.env`, `.git/config`), API/Swagger/GraphQL, Spring Boot Actuator, backupy i pliki instalacyjne.
- **Baseline fingerprinting** – uczy się wzorca Soft 404/Catch-all serwera i odrzuca fałszywe wyniki.
- **Rate limiting** – `threading.BoundedSemaphore` + Smart Delay z jitterem.

---

## 🛠️ Wymagania

| Składnik | Wersja / Uwagi |
|---|---|
| System | Kali Linux / Kali NetHunter (Android) |
| Python | 3.10+ |
| Narzędzia | `nmap` 7.80+, `exploitdb` (SearchSploit), `sqlmap`, `adb` |
| Uprawnienia | root (wymagane do skanów UDP, detekcji OS, ADB su) |
| Opcjonalnie | `playwright` + Chromium (tylko dla komendy `hw`) |
| Opcjonalnie | `frida-tools` + `frida-server` ARM64 (dla `adb-frida`) |
| Opcjonalnie | `tcpdump` ARM64 static (dla `adb-dump`) |

> **NetHunter Chroot Fix** – skrypt posiada trzy wbudowane mechanizmy wykrywania interfejsów sieciowych (fallbacki), co rozwiązuje problem braku domyślnej bramy w środowisku chroot na Androidzie.

---

## 📦 Instalacja

```bash
# 1. Sklonuj repozytorium
git clone https://github.com/MR10ROOT/MR.ROOT.git
cd MR.ROOT

# 2. Utwórz środowisko wirtualne (zalecane)
python3 -m venv venv
source venv/bin/activate

# 3. Zainstaluj zależności Pythona
pip install -r requirements.txt

# 4. Zainstaluj narzędzia systemowe
apt install nmap exploitdb sqlmap adb -y

# 5. (Opcjonalnie) Playwright dla komendy hw
pip install playwright && playwright install chromium

# 6. (Opcjonalnie) Frida dla modułu ADB
pip install frida-tools --break-system-packages
# Pobierz frida-server ARM64 z github.com/frida/frida/releases
# Umieść jako /MR.ROOT/frida-server i nadaj chmod +x

# 7. Nadaj uprawnienia i uruchom jako root
chmod +x recon3-8.py
sudo python3 recon3-8.py
```

---

## 🚀 Użycie (tryb CLI / one-shot)

```bash
# Podstawowe skany sieciowe
sudo python3 recon3-8.py -t 192.168.1.100 -m deep
sudo python3 recon3-8.py -t 10.0.0.0/24  -m sweep
sudo python3 recon3-8.py -t 192.168.1.1  -m mobile

# Pełny skan sieci
sudo python3 recon3-8.py -m all-net

# Fuzzer z zewnętrznym słownikiem
sudo python3 recon3-8.py -t 192.168.1.1 -m fuzz -w /usr/share/wordlists/dirb/common.txt

# SQL Injection
sudo python3 recon3-8.py -t "http://cel/page.php?id=1" -m sql
sudo python3 recon3-8.py -t "http://cel/page.php?id=1" -m sql --resume
sudo python3 recon3-8.py -t "http://cel/index.php" -m auto-sql

# Headless browser scan
sudo python3 recon3-8.py -t "http://cel/" -m hw

# HTTP Parameter Pollution
sudo python3 recon3-8.py -t "http://cel/page.php?id=1" -m hpp

# [v3.8] ADB Pentest — audit urządzenia USB
sudo python3 recon3-8.py -m adb

# [v3.8] ADB + Frida SSL Unpin
sudo python3 recon3-8.py -m adb-frida -t com.example.app

# [v3.8] ADB Traffic Dump (60 sekund)
sudo python3 recon3-8.py -m adb-dump -t 60
```

---

## 📁 Raporty (JSON i HTML)

Wszystkie wyniki są automatycznie zapisywane w katalogu `/MR.ROOT/reports/`:

```
/MR.ROOT/reports/
├── netscan_20260426_070000.json
├── sweep_20260426_070000.txt
├── scan_20260426_070000.json
├── identity_192-168-101-1_20260426_070000.json
├── mobile_192-168-101-43_20260426_070000.json
├── fuzz_192-168-101-43_20260426_070000.json
├── banner_192-168-101-1_20260426_070000.json
├── sqlmap_http___cel_page_20260426_070000.json
├── adb_audit_cmtokbayqkpbofbi_20260426_070000.json   ← [v3.8] ADB Audit
├── traffic_cmtokbayqkpbofbi_20260426_070000.pcap      ← [v3.8] tcpdump capture
└── html/
    └── banner_192-168-101-1_20260426_070000.html
```

---

## 🗺️ Roadmap

- [x] Tryb Full Scan (`all` / `-m all`) — wszystkie moduły sekwencyjnie (v3.1)
- [x] Zbieranie statystyk do końcowego raportu JSON (v3.1)
- [x] Integracja z SearchSploit (Exploit-DB) (v3.2)
- [x] Analizator nagłówków HTTP (HSTS, CSP, Info-leak) (v3.2)
- [x] Omijanie ograniczeń routingu NetHunter chroot (v3.3)
- [x] Oznaczanie urządzeń mobilnych (📱/💻) w ping sweep (v3.4)
- [x] Moduły Mobile Scan (`m`) i Mobile Fuzzer (`mf`) (v3.4)
- [x] Masowy audyt `all-net` z możliwością pominięcia hosta (v3.4)
- [x] SQLMap Auto-Tamper WAF-Bypass (`sql`) (v3.5)
- [x] Auto-Spider + masowy SQLi (`auto-sql`) (v3.5)
- [x] Smart Delay + Jitter — anty-WAF/IPS (v3.6)
- [x] Zaawansowana rotacja nagłówków — Client Hints, X-Forwarded-For (v3.6)
- [x] WAF-Bypass via HTTP Parameter Pollution + Chunked Transfer (v3.6)
- [x] Detekcja Rate Limiting + per-IP Cooldown state machine (v3.6)
- [x] Headless browser scan via Playwright/Chromium (`hw`) (v3.6)
- [x] Per-IP rate limiting — cooldown jednego celu nie blokuje innych (v3.7)
- [x] Flaga `--resume` dla SQLMap (v3.7)
- [x] `NamedTemporaryFile` w Mobile Fuzzer (v3.7)
- [x] **ADB Device Info + Debug Surface Analysis** (v3.8)
- [x] **ADB APK Enumeration z flagowaniem interesujących pakietów** (v3.8)
- [x] **Frida SSL Unpin przez ADB USB** (OkHttp3 + TrustManager + Conscrypt + NSC) (v3.8)
- [x] **Traffic Dump przez ADB USB** — tcpdump → .pcap → Wireshark (v3.8)
- [ ] Moduł WiFi — skanowanie sieci bezprzewodowych (`iwlist` / `airodump-ng`)
- [ ] Tryb cichy (`--quiet`) — tylko wyniki, bez kolorów ANSI
- [ ] Eksport raportów do HTML dla modułu ADB

---

## 📄 Licencja

MIT License – szczegóły w pliku `LICENSE`.

---

<p align="center">
Stworzony z ♥ przez <strong>MR.ROOT</strong> | NetHunter Edition v3.8 REDHUNT-16-BETA | ADB-PENTEST
</p>
