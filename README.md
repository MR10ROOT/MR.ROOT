# MR.ROOT – Mobilny Skaner Sieci

**NetHunter Edition v3.5 REDHUNT-16-BETA**

Zaawansowane narzędzie do rekonesansu, analizy sieci lokalnej, fuzzingu aplikacji webowych oraz automatycznego wykrywania podatności SQL Injection, zaprojektowane z myślą o pracy na Kali NetHunter (Android).
Napisane w Pythonie, oparte na nmap, NSE, SearchSploit, sqlmap oraz autorskich, wielowątkowych modułach HTTP.

```
  ███╗   ███╗██████╗     ██████╗  ██████╗  ██████╗ ████████╗
  ████╗ ████║██╔══██╗    ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
  ██╔████╔██║██████╔╝    ██████╔╝██║   ██║██║   ██║   ██║
  ██║╚██╔╝██║██╔══██╗    ██╔══██╗██║   ██║██║   ██║   ██║
  ██║ ╚═╝ ██║██║  ██║    ██║  ██║╚██████╔╝╚██████╔╝   ██║
  ╚═╝     ╚═╝╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝
```

---

## ⚠️ Zastrzeżenie prawne (Disclaimer)

Narzędzie powstało wyłącznie w celach edukacyjnych oraz do testów we własnej sieci lub po uzyskaniu pisemnej zgody jej właściciela.
Nieautoryzowane skanowanie sieci jest nielegalne i narusza m.in.:

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
| `h` | Pomoc |
| `q / exit` | Wyjście |

---

## 🔥 Szczegóły głównych modułów

### 💉 Moduły SQL Injection (sql, auto-sql) — nowość v3.5

**`sql <URL>`** – SQLMap Auto-Tamper WAF-Bypass:
- Automatycznie rotuje 6 najskuteczniejszych łańcuchów tamperów skonstruowanych pod nowoczesne WAF (2025/2026).
- Uruchamia `sqlmap --level=5 --risk=3 --batch --random-agent --flush-session`.
- Wykrywa podatność **na żywo** przez parsowanie stdout — zatrzymuje się przy pierwszym potwierdzeniu.
- Po sukcesie wyświetla gotową komendę `--dump-all` z najlepszym tamperem.
- Zapisuje raport JSON z timestampem do katalogu raportów.

**`auto-sql <URL>`** – Auto-Spider + masowy SQLi:
- Pobiera kod źródłowy strony i wyciąga wszystkie linki `href` przez wyrażenia regularne.
- **Deduplikuje wektory ataku** po sygnaturze `(ścieżka_pliku, zestaw_parametrów_GET)` — `?id=1` i `?id=99` traktowane jako jeden wektor.
- Wyświetla tabelę unikalnych endpointów przed atakiem.
- Wywołuje `sql_scan()` sekwencyjnie na każdym znalezionym parametryzowanym adresie URL.
- Zero zewnętrznych zależności — używa wyłącznie `re` i `urllib.parse` ze standardowej biblioteki Pythona.

> **Przykład użycia:** `auto-sql http://192.168.101.44/index.php` — skrypt sam znajdzie wszystkie linki typu `product.php?id=5`, odrzuci duplikaty i automatycznie przeprowadzi atak SQLi.

---

### 📱 Moduły mobilne (m, mf) — nowość v3.4

- **Mobile Scan** – dedukuje typ urządzenia poprzez skanowanie specyficznych portów:
  Android ADB (5555), Apple Lockdown (62078), KDE Connect (1714–1764), AirDroid (8888), AirPlay (7000).
  Dodatkowo analizuje rekordy ZeroConf/mDNS pod kątem usług Apple i Google Cast.
- **Mobile Fuzzer** – generuje na bieżąco specjalistyczny słownik ścieżek mobilnych (`/sdcard/`, `/DCIM/`, `/WhatsApp/Media/` itd.) i skanuje serwery HTTP w poszukiwaniu niezabezpieczonych plików użytkownika.

### 🤖 Automatyzacja (all, all-net) — nowość v3.1–v3.4

- **Full Scan (`all`)** – uruchamia sekwencyjnie 6 modułów: Deep, Identity, SNMP, Banner, Fuzzer, Vuln.
  Ctrl+C w trakcie fazy bezpiecznie ją pomija i przechodzi do następnej.
- **Network Scan (`all-net`)** – „bomba dywanowa": wykonuje ping sweep, pyta o zgodę, a następnie uruchamia Full Scan dla każdego hosta w sieci. Na koniec generuje zbiorczy plik JSON ze statystykami.

### 🚀 Smart Fuzzer (f \<IP\> [słownik])

- **124 wbudowane wektory:** sekrety (`.env`, `.git/config`), API/Swagger/GraphQL, Spring Boot Actuator, backupy i pliki instalacyjne.
- **Baseline fingerprinting** – skrypt uczy się wzorca Soft 404/Catch-all serwera i odrzuca fałszywe wyniki na podstawie skrótów MD5 i rozmiaru odpowiedzi.
- **Rate limiting** – `threading.BoundedSemaphore` + 80 ms przerwy między żądaniami, co chroni przed blokowaniem IP.

### 🌐 Banner Grabber i Deep Scan

- **Analizator nagłówków bezpieczeństwa** – Banner Grabber bada brakujące nagłówki (HSTS, CSP, X-Frame-Options) i ostrzega o wyciekach informacji (np. `Server: SimpleHTTP`) w konsoli oraz w raporcie HTML.
- **Integracja z Exploit-DB** – Deep Scan automatycznie przeszukuje systemową bazę `searchsploit` dla każdej wykrytej usługi z konkretną wersją oprogramowania i podaje identyfikatory EDB-ID znalezionych exploitów.

---

## 🛠️ Wymagania

| Składnik | Wersja / Uwagi |
|---|---|
| System | Kali Linux / Kali NetHunter (Android) |
| Python | 3.10+ |
| Narzędzia | `nmap` 7.80+, `exploitdb` (SearchSploit), `sqlmap` |
| Uprawnienia | root (wymagane do skanów UDP, detekcji OS i surowych pakietów) |

> **NetHunter Chroot Fix** – skrypt posiada trzy wbudowane mechanizmy wykrywania interfejsów sieciowych (fallbacki), co rozwiązuje problem braku domyślnej bramy w środowisku chroot na Androidzie. Omija też wirtualne interfejsy systemowe (`ccmni`, `dummy`, `rmnet`).

---

## 📦 Instalacja

```bash
# 1. Sklonuj repozytorium
git clone https://github.com/TWOJ_LOGIN/mr-root-recon.git
cd mr-root-recon

# 2. Utwórz środowisko wirtualne (zalecane)
python3 -m venv .venv
source .venv/bin/activate

# 3. Zainstaluj zależności Pythona
pip install -r requirements.txt

# 4. Zainstaluj nmap, exploitdb i sqlmap w systemie
apt-get install nmap exploitdb sqlmap -y

# 5. Nadaj uprawnienia i uruchom jako root
chmod +x recon3-4-3.py
sudo python3 recon3-4-3.py
```

---

## 🚀 Użycie (tryb CLI / one-shot)

Idealny do automatyzacji i skryptów w Bashu.

```bash
# Podstawowe skany
sudo python3 recon3-4-3.py -t 192.168.1.100 -m deep
sudo python3 recon3-4-3.py -t 10.0.0.0/24  -m sweep
sudo python3 recon3-4-3.py -t 192.168.1.1  -m mobile

# Pełny skan całej infrastruktury (automatyczny)
sudo python3 recon3-4-3.py -m all-net

# Fuzzer z zewnętrznym słownikiem
sudo python3 recon3-4-3.py -t 192.168.1.1 -m fuzz -w /usr/share/wordlists/dirb/common.txt

# SQL Injection – pojedynczy URL z WAF-bypass
sudo python3 recon3-4-3.py -t "http://cel/page.php?id=1" -m sql

# SQL Injection – automatyczny spider + masowy atak
sudo python3 recon3-4-3.py -t "http://cel/index.php" -m auto-sql

# Skanowanie podatności na wszystkich portach
sudo python3 recon3-4-3.py -t 192.168.1.1 -m vuln --full-ports

# Tryb z weryfikacją certyfikatów SSL
sudo python3 recon3-4-3.py -t 192.168.1.1 -m banner --strict-ssl
```

---

## 📁 Raporty (JSON i HTML)

Wszystkie wyniki są automatycznie zapisywane w katalogu:

```
/MR.ROOT/reports/
├── netscan_20260404_175304.json                      # master raport z all-net
├── sweep_20260404_170916.txt                         # lista hostów
├── scan_20260404_172208.json                         # deep scan
├── identity_192-168-101-1_20260404_172221.json       # identity scan
├── mobile_192-168-101-43_20260404_172031.json        # skan mobilny
├── fuzz_192-168-101-43_20260404_180900.json          # wyniki fuzzera
├── banner_192-168-101-1_20260404_172536.json         # banner grabber (surowe dane)
├── sqlmap_http___cel_page_20260404_183012.json       # wynik sql_scan
└── html/
    └── banner_192-168-101-1_20260404_172536.html     # raport HTML z audytem nagłówków
```

---

## 🗺️ Roadmap

- [x] Tryb Full Scan (`all` / `-m all`) – wszystkie moduły sekwencyjnie (v3.1)
- [x] Zbieranie statystyk do końcowego raportu JSON (v3.1)
- [x] Integracja z SearchSploit (Exploit-DB) dla wykrytych usług (v3.2)
- [x] Analizator nagłówków HTTP (HSTS, CSP, Info-leak) (v3.2)
- [x] Omijanie ograniczeń routingu NetHunter chroot (v3.3)
- [x] Oznaczanie urządzeń mobilnych (📱/💻) w ping sweep (v3.4)
- [x] Moduły Mobile Scan (`m`) i Mobile Fuzzer (`mf`) (v3.4)
- [x] Masowy audyt `all-net` z możliwością pominięcia hosta przez Ctrl+C (v3.4)
- [x] SQLMap Auto-Tamper WAF-Bypass (`sql`) – rotacja 6 łańcuchów (v3.5)
- [x] Auto-Spider + masowy SQLi (`auto-sql`) – crawl → deduplikacja → atak (v3.5)
- [ ] Moduł WiFi – skanowanie sieci bezprzewodowych (`iwlist` / `airodump-ng`)
- [ ] Tryb cichy (`--quiet`) – tylko wyniki, bez kolorów ANSI

---

## 📄 Licencja

MIT License – szczegóły w pliku `LICENSE`.

---

<p align="center">
Stworzony z ♥ przez <strong>MR.ROOT</strong> | NetHunter Edition v3.5 REDHUNT-16-BETA
</p>
