# 🔍 MR.ROOT — Mobilny Skaner Sieci
### NetHunter Edition v2.2

> Zaawansowane narzędzie do rekonesansu, analizy sieci lokalnej i fuzzingu aplikacji webowych, zaprojektowane do pracy na Kali NetHunter (Android).  
> Napisane w Pythonie, oparte na **nmap**, **NSE** oraz autorskich, wielowątkowych modułach HTTP.

```text
  ███╗   ███╗██████╗     ██████╗  ██████╗  ██████╗ ████████╗
  ████╗ ████║██╔══██╗    ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
  ██╔████╔██║██████╔╝    ██████╔╝██║   ██║██║   ██║   ██║
  ██║╚██╔╝██║██╔══██╗    ██╔══██╗██║   ██║██║   ██║   ██║
  ██║ ╚═╝ ██║██║  ██║    ██║  ██║╚██████╔╝╚██████╔╝   ██║
  ╚═╝     ╚═╝╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝
        Mobilny Skaner Sieci | by MR.ROOT | NetHunter Edition v2.2

```
## ⚠️ Disclaimer / Ostrzeżenie prawne
**To narzędzie zostało stworzone wyłącznie w celach edukacyjnych i do użytku na własnej sieci lub sieci, do której posiadasz pisemną zgodę właściciela.**
Używanie tego oprogramowania do skanowania sieci bez autoryzacji jest **nielegalne** i narusza m.in.:
 * Polską ustawę o cyberbezpieczeństwie
 * Europejską dyrektywę NIS2
 * Przepisy karne Kodeksu karnego (art. 267 KK)
Autor nie ponosi żadnej odpowiedzialności za niewłaściwe użycie tego narzędzia.
## 📋 Funkcje i Komendy
Skaner może działać w płynnym trybie interaktywnym lub wykonywać pojedyncze strzały z poziomu CLI.
| Komenda | Opis |
|---|---|
| <IP> | Głęboki skan portów + detekcja OS |
| <IP,IP,...> | Wiele celów naraz |
| <CIDR> | Skan całej podsieci (np. 192.168.1.0/24) |
| sweep / sweep <CIDR> | Szybki Ping Sweep aktywnej (lub podanej) podsieci |
| i <IP> | **Identity Scan** — mDNS, NetBIOS, SMB, UPnP |
| snmp <IP> | **SNMP Scan** — lokalizacja, kontakt admina, interfejsy |
| v <IP> | **Vuln-Scan NSE** — CVE, Heartbleed, Shellshock |
| b <IP> | **Banner Grabber** — Wielowątkowe skanowanie HTTP/HTTPS + raport HTML |
| f <IP> | **Fuzzer Ścieżek** — Szukanie ukrytych plików (z filtrowaniem fałszywych alarmów) |
| h | Pomoc |
| q / exit | Wyjście |
### 🔥 Szczegóły głównych modułów
**🔎 Identity Scan (i <IP>)**
 * **mDNS/Zeroconf** (UDP/5353) — wykrywa nazwy .local urządzeń Apple, smart TV, drukarek
 * **NetBIOS** (UDP/137) — nazwa komputera Windows, workgroup/domena
 * **SMB** (TCP/139+445) — OS, lista udostępnionych folderów (null session)
 * **UPnP/SSDP** (UDP/1900) — model urządzenia, producent, URL panelu konfiguracyjnego
**🚀 Smart Fuzzer (f <IP>)** *(Nowość v2.2!)*
 * Błyskawicznie sprawdza najczęstsze wektory ataku (/.env, /.git/config, /backup.zip, /wp-admin/ itp.).
 * **Baseline Fingerprinting:** Skrypt uczy się wzorca strony błędu na danym serwerze (tzw. Soft 404 / Catch-all) i odrzuca fałszywe wyniki na podstawie skrótów MD5 i rozmiaru odpowiedzi.
 * Prawidłowo identyfikuje chronione zasoby (kody HTTP 401 i 403).
**🌐 Banner Grabber (b <IP>)**
 * Wielowątkowo skanuje 11 najpopularniejszych portów HTTP/HTTPS.
 * Automatyczna rotacja nagłówków User-Agent w celu ominięcia prostych filtrów.
 * Ignoruje błędy SSL (częste przy self-signed certyfikatach w IoT).
 * Generuje **ciemny raport HTML** z rozwijanym podglądem kodu przechwyconej strony.
**🛡️ Vuln-Scan (v <IP>)**
 * Odpala zestaw skryptów Nmap Scripting Engine: m.in. vuln, ssl-heartbleed, smb-vuln-ms17-010.
 * Kolorowe alerty w terminalu dla błyskawicznej identyfikacji krytycznych luk.
## 🛠️ Wymagania
 * **System:** Kali Linux / Kali NetHunter (Android)
 * **Python:** 3.10+
 * **nmap:** 7.80+
 * **Uprawnienia:** root (wymagane dla skanów UDP, detekcji OS i surowych pakietów)
## 📦 Instalacja
```bash
# 1. Sklonuj repozytorium
git clone [https://github.com/TWOJ_LOGIN/mr-root-recon.git](https://github.com/TWOJ_LOGIN/mr-root-recon.git)
cd mr-root-recon

# 2. Utwórz środowisko wirtualne (zalecane)
python3 -m venv .venv
source .venv/bin/activate

# 3. Zainstaluj zależności Python
pip install -r requirements.txt

# 4. Upewnij się, że nmap jest zainstalowany w systemie
apt-get install nmap -y

# 5. Nadaj uprawnienia i uruchom jako root
chmod +x recon2.py
sudo python3 recon2.py

```
## 🚀 Użycie
### Tryb Interaktywny
Wystarczy uruchomić skrypt bez argumentów. Program automatycznie:
 1. Sprawdzi połączenie z internetem (wykrywanie Captive Portal).
 2. Wykryje aktywny interfejs sieciowy.
 3. Zaproponuje zrobienie szybkiego "Ping Sweep" w celu odnalezienia sąsiadów w sieci.
<!-- end list -->
```
[MR.ROOT]>> sweep 192.168.1.0/24  # Szybka mapa sieci
[MR.ROOT]>> 192.168.1.1           # Deep scan routera
[MR.ROOT]>> i 192.168.1.15        # Identity Scan (kto to jest?)
[MR.ROOT]>> b 192.168.1.4         # Banner Grabber
[MR.ROOT]>> f 192.168.1.1         # Fuzzer ukrytych ścieżek

```
### Tryb CLI (One-Shot Mode)
Idealny do automatyzacji i pisania skryptów w Bashu. Wykonuje jedno zadanie i kończy działanie.
```bash
sudo python3 recon2.py -t 192.168.1.100 -m deep
sudo python3 recon2.py -t 10.0.0.0/24 -m sweep
sudo python3 recon2.py -t 192.168.1.1 -m fuzz

```
## 📁 Raporty (JSON & HTML)
Wszystkie wyniki są automatycznie strukturyzowane i zapisywane w bezpiecznym katalogu, gotowe do przeglądania na urządzeniu mobilnym:
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
## 🗺️ Roadmap
 * [x] Eksport wyników do JSON *(Dodano w v2.1)*
 * [x] Obsługa argumentów z linii komend (CLI) *(Dodano w v2.1)*
 * [x] Inteligentny Fuzzer Ścieżek *(Dodano w v2.2)*
 * [ ] Moduł WiFi — skanowanie sieci bezprzewodowych (iwlist / airodump-ng)
 * [ ] Automatyczny raport HTML połączony z widokiem Ping Sweep
 * [ ] Tryb cichy (--quiet) — tylko wyniki, bez ANSI kolorów
 * [ ] Integracja z bazą CVE (NVD API) dla wykrytych banerów
## 📄 Licencja
MIT License — szczegóły w pliku LICENSE.
<p align="center">
Stworzony z ♥ przez <strong>MR.ROOT</strong> | NetHunter Edition
</p>
```

```
