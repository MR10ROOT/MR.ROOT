MR.ROOT — Mobilny Skaner Sieci
NetHunter Edition v3.4
Zaawansowane narzędzie do rekonesansu, analizy sieci lokalnej i fuzzingu aplikacji webowych, zaprojektowane do pracy na Kali NetHunter (Android).
Napisane w Pythonie, oparte na nmap, NSE, SearchSploit oraz autorskich, wielowątkowych modułach HTTP.
  ███╗   ███╗██████╗     ██████╗  ██████╗  ██████╗ ████████╗
  ████╗ ████║██╔══██╗    ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
  ██╔████╔██║██████╔╝    ██████╔╝██║   ██║██║   ██║   ██║
  ██║╚██╔╝██║██╔══██╗    ██╔══██╗██║   ██║██║   ██║   ██║
  ██║ ╚═╝ ██║██║  ██║    ██║  ██║╚██████╔╝╚██████╔╝   ██║
  ╚═╝     ╚═╝╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝
        Mobilny Skaner Sieci | by MR.ROOT | NetHunter Edition v3.4
        ⚠️ Disclaimer / Ostrzeżenie prawne
To narzędzie zostało stworzone wyłącznie w celach edukacyjnych i do użytku na własnej sieci lub sieci, do której posiadasz pisemną zgodę właściciela.
Używanie tego oprogramowania do skanowania sieci bez autoryzacji jest nielegalne i narusza m.in.:
Polską ustawę o cyberbezpieczeństwie
Europejską dyrektywę NIS2
Przepisy karne Kodeksu karnego (art. 267 KK)
Autor nie ponosi żadnej odpowiedzialności za niewłaściwe użycie tego narzędzia.
📋 Funkcje i Komendy
Skaner działa w płynnym trybie interaktywnym lub wykonuje pojedyncze zadania z poziomu CLI.
Komenda Opis
<IP / IPv6> Głęboki skan portów + detekcja OS + szukanie exploitów (SearchSploit)
<IP,IP,...> Wiele celów naraz
<CIDR> Skan całej podsieci — IPv4 (192.168.1.0/24) lub IPv6 (fd00::/64)
sweep [CIDR] Szybki Ping Sweep podsieci z wizualnym flagowaniem urządzeń mobilnych (📱/💻)
i <IP> Identity Scan — mDNS (w tym detekcja iOS/Android), NetBIOS, SMB, UPnP
snmp <IP> SNMP Scan — lokalizacja, kontakt admina, interfejsy
v <IP> Vuln-Scan NSE — CVE, Heartbleed, Shellshock
b <IP> Banner Grabber — skanowanie HTTP/HTTPS + audyt nagłówków bezpieczeństwa
f <IP> [word] Fuzzer Ścieżek — 124 wbudowane wektory; opcjonalny zewnętrzny plik słownika
m <IP> Mobile Scan — porty ADB/iOS/AirPlay/KDE Connect + mDNS fingerprint
mf <IP> Mobile Fuzzer — szukanie otwartych katalogów Android/iOS (np. /sdcard/)
all <IP> Full Scan — wszystkie moduły sekwencyjnie (możliwość pomijania: Ctrl+C)
all-net Full Scan Sieci — sweep + zautomatyzowany full_scan każdego wykrytego hosta
h Pomoc
q / exit Wyjście
🔥 Szczegóły głównych modułów
📱 Moduły Mobilne (m / mf) (Nowość v3.4!)
Mobile Scan: Dedukuje rodzaj urządzenia, skanując specyficzne porty (Android ADB 5555, Apple Lockdown 62078, KDE Connect 1714-1764, AirDroid 8888, AirPlay 7000). Dodatkowo rozbija rekordy ZeroConf/mDNS w poszukiwaniu śladów usług Apple i Google Cast.
Mobile Fuzzer: Generuje "w locie" specjalistyczny słownik ścieżek mobilnych (/sdcard/, /DCIM/, /WhatsApp/Media/) i skanuje serwery HTTP w poszukiwaniu niezabezpieczonych plików użytkownika.
🤖 Automatyzacja (all / all-net) (Nowość v3.1 - v3.4!)
Full Scan (all): Uruchamia sekwencyjnie wszystkie 6 modułów skanera (Deep, Identity, SNMP, Banner, Fuzzer, Vuln). Naciśnięcie Ctrl+C w trakcie trwania fazy bezpiecznie ją pomija i przechodzi do następnej.
Network Scan (all-net): Prawdziwa "bomba dywanowa". Wykonuje Ping Sweep, pyta o zgodę, a następnie uruchamia Full Scan dla każdego hosta w sieci. Na koniec generuje potężny, zbiorczy plik Master JSON ze statystykami.
🚀 Smart Fuzzer (f <IP> [wordlist])
124 wbudowane wektory obejmujące: sekrety (.env, .git/config), API/Swagger/GraphQL, Spring Boot Actuator, backupy i pliki instalacyjne.
Baseline Fingerprinting: Skrypt uczy się wzorca Soft 404/Catch-all serwera i odrzuca fałszywe wyniki na podstawie skrótów MD5 i rozmiaru odpowiedzi.
Rate limiting: threading.BoundedSemaphore + 80 ms przerwy między żądaniami — chroni przed blokowaniem IP.
🌐 Banner Grabber i Deep Scan
Analizator Nagłówków Bezpieczeństwa: Banner Grabber automatycznie bada brakujące nagłówki (HSTS, CSP, X-Frame-Options) i ostrzega o wyciekach informacji (Info-disclosure) typu Server: SimpleHTTP w konsoli oraz raporcie HTML.
Integracja z Exploit-DB: Deep Scan automatycznie odpytuje systemową bazę searchsploit dla każdej wykrytej usługi z konkretną wersją oprogramowania i podaje EDB-ID znalezionych exploitów.
🛠️ Wymagania
Element Wersja
System Kali Linux / Kali NetHunter (Android)
Python 3.10+
Narzędzia nmap 7.80+, exploitdb (SearchSploit)
Uprawnienia root (wymagane dla skanów UDP, detekcji OS i surowych pakietów)
NetHunter Chroot Fix: Skrypt posiada wbudowane 3 mechanizmy (fallbacki) wykrywania interfejsów sieciowych, co rozwiązuje problem braku domyślnej bramy (default route) w środowisku chroot na Androidzie. Omija też wirtualne interfejsy systemowe (ccmni, dummy, rmnet).
📦 Instalacja
# 1. Sklonuj repozytorium
git clone https://github.com/TWOJ_LOGIN/mr-root-recon.git
cd mr-root-recon

# 2. Utwórz środowisko wirtualne (zalecane)
python3 -m venv .venv
source .venv/bin/activate

# 3. Zainstaluj zależności Python🚀 Użycie (Tryb CLI / One-Shot)
Idealny do automatyzacji i pisania skryptów w Bashu.
pip install -r requirements.txt

# 4. Upewnij się, że nmap i exploitdb są zainstalowane w systemie
apt-get install nmap exploitdb -y

# 5. Nadaj uprawnienia i uruchom jako root
chmod +x recon3.py
sudo python3 recon3.py
🚀 Użycie (Tryb CLI / One-Shot)
Idealny do automatyzacji i pisania skryptów w Bashu.
# Podstawowe
sudo python3 recon3.py -t 192.168.1.100 -m deep
sudo python3 recon3.py -t 10.0.0.0/24  -m sweep
sudo python3 recon3.py -t 192.168.1.1  -m mobile

# Full scan całej infrastruktury z automatu
sudo python3 recon3.py -m all-net

# Fuzzer z zewnętrznym słownikiem
sudo python3 recon3.py -t 192.168.1.1 -m fuzz -w /usr/share/wordlists/dirb/common.txt

# Vuln-scan wszystkich portów (wolno — tylko ze świadomością obciążenia)
sudo python3 recon3.py -t 192.168.1.1 -m vuln --full-ports

# Tryb z weryfikacją certyfikatów SSL (nie-pentest)
sudo python3 recon3.py -t 192.168.1.1 -m banner --strict-ssl
📁 Raporty (JSON & HTML)
Wszystkie wyniki są automatycznie strukturyzowane i zapisywane w bezpiecznym katalogu:
/MR.ROOT/reports/
├── netscan_20260404_175304.json               ← raport master z audytu all-net
├── sweep_20260404_170916.txt                  ← lista hostów
├── scan_20260404_172208.json                  ← deep scan
├── identity_192-168-101-1_20260404_172221.json ← identity scan
├── mobile_192-168-101-43_20260404_172031.json ← skan mobilny (ADB/AirPlay itp.)
├── fuzz_192-168-101-43_20260404_180900.json   ← wyniki fuzzera
├── banner_192-168-101-1_20260404_172536.json  ← banner grabber (surowe dane)
└── html/
    └── banner_192-168-101-1_20260404_172536.html ← banner grabber (ciemny raport HTML z sekcją Security Headers)

    🗺️ Roadmap
[x] Tryb Full Scan (all / -m all) — wszystkie moduły sekwencyjnie (v3.1)
[x] Zbieranie statystyk do końcowego raportu Master JSON (v3.1)
[x] Integracja z searchsploit (Exploit-DB) dla wykrytych usług (v3.2)
[x] Analizator nagłówków HTTP (HSTS, CSP, Info-leak) (v3.2)
[x] Omijanie ograniczeń routingu NetHunter chroot (v3.3)
[x] Flagowanie urządzeń mobilnych 📱/💻 w Ping Sweep (v3.4)
[x] Moduł Mobile Scan (m) i Mobile Fuzzer (mf) (v3.4)
[x] Masowy audyt all-net z graceful graceful exit (Ctrl+C na hosta) (v3.4)
[ ] Moduł WiFi — skanowanie sieci bezprzewodowych (iwlist / airodump-ng)
[ ] Tryb cichy (--quiet) — tylko wyniki, bez ANSI kolorów
📄 Licencja
MIT License — szczegóły w pliku LICENSE.
<p align="center">
Stworzony z ♥ przez <strong>MR.ROOT</strong> | NetHunter Edition
</p>
