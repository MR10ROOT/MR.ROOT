#!/usr/bin/env python3
"""
MR.ROOT Scanner v3.0 — NetHunter Edition
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
from concurrent.futures import ThreadPoolExecutor, as_completed, wait

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
FUZZ_DELAY   = 0.08    # sekundy przerwy między żądaniami fuzzera
SCAN_TIMEOUT = 300     # globalny timeout (sekundy) dla run_scan
MAX_PARALLEL_NMAP = 2  # [POPRAWA 7] max równoległych procesów NMAP

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

# [POPRAWA 3] Rozbudowany słownik fuzzera (~100 wpisów)
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
    "/trace.axd", "/elmah.axd",            # ASP.NET
    "/.DS_Store",                            # macOS artefakt
    "/web.config", "/applicationHost.config",  # IIS
    "/WEB-INF/web.xml",                      # Java/Tomcat
    "/.well-known/",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 14; 23049PCD8G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "MR.ROOT-Recon/3.0 (Educational Network Scanner)"
]

VULN_SCRIPTS = [
    "vuln", "ssl-heartbleed", "ssl-poodle", "ssl-dh-params",
    "smb-vuln-ms17-010", "smb-vuln-ms08-067",
    "http-vuln-cve2017-5638", "http-shellshock"
]

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
{C.DIM}        Mobilny Skaner Sieci | by MR.ROOT | NetHunter Edition v3.0{C.RESET}
"""

HELP_TEXT = f"""
{c(C.CYAN+C.BOLD, "═══ KOMENDY INTERAKTYWNE ═══")}
  {c(C.GREEN, "<IP / IPv6>")}       Deep Scan — porty, OS, HTTP
  {c(C.GREEN, "<IP,IP,...>")}       Wiele celów naraz
  {c(C.GREEN, "<CIDR>")}           Skan podsieci (np. 192.168.1.0/24 lub fd00::/64)
  {c(C.GREEN, "i <IP>")}           Identity Scan — mDNS, NetBIOS, SMB, UPnP
  {c(C.GREEN, "snmp <IP>")}        SNMP Scan — community brute + info
  {c(C.GREEN, "v <IP>")}           Vuln-Scan NSE — CVE, Heartbleed, EternalBlue
  {c(C.GREEN, "b <IP>")}           Banner Grabber — HTTP/HTTPS + raport HTML
  {c(C.GREEN, "f <IP> [wordlist]")} Fuzzer Ścieżek — ukryte pliki (opcj. plik słownika)
  {c(C.GREEN, "sweep")}            Ping Sweep aktywnej podsieci
  {c(C.GREEN, "sweep <CIDR>")}     Ping Sweep podanej podsieci
  {c(C.GREEN, "h")}                Ta pomoc
  {c(C.GREEN, "q / exit")}         Wyjście
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

# [POPRAWA 2] Walidacja IPv4 i IPv6
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

# [POPRAWA 1] SSL context — weryfikacja jeśli STRICT_SSL, unverified w trybie pentest
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
# NETWORK & ENVIRONMENT
# =========================
def detect_interface():
    """Wykrywa aktywny interfejs sieciowy; zwraca IPv4 i opcjonalnie IPv6."""
    iface = ip4 = net4 = ip6 = None
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"],
            stderr=subprocess.DEVNULL, text=True
        )
        for line in out.splitlines():
            parts = line.split()
            if "dev" in parts:
                iface = parts[parts.index("dev") + 1]

                # IPv4
                addr4 = subprocess.check_output(
                    ["ip", "-4", "addr", "show", iface],
                    stderr=subprocess.DEVNULL, text=True
                )
                for iline in addr4.splitlines():
                    iline = iline.strip()
                    if iline.startswith("inet "):
                        cidr = iline.split()[1]
                        ip4  = cidr.split("/")[0]
                        net4 = str(ipaddress.IPv4Network(cidr, strict=False))

                # [POPRAWA 2] IPv6 (link-local pomijamy — bierzemy global/unique-local)
                try:
                    addr6 = subprocess.check_output(
                        ["ip", "-6", "addr", "show", iface],
                        stderr=subprocess.DEVNULL, text=True
                    )
                    for iline in addr6.splitlines():
                        iline = iline.strip()
                        if iline.startswith("inet6 "):
                            cidr6 = iline.split()[1]
                            candidate = ipaddress.ip_interface(cidr6).ip
                            if not candidate.is_link_local:
                                ip6 = str(candidate)
                                break
                except Exception:
                    pass

                break
    except Exception:
        pass
    return iface, ip4, net4, ip6

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

# [POPRAWA 2] parse_targets obsługuje IPv6 i sieci IPv6
def parse_targets(inp):
    out = []
    for token in inp.split(","):
        token = token.strip()
        if not token:
            continue
        # Spróbuj jako sieć (CIDR) — IPv4 lub IPv6
        try:
            net = ipaddress.ip_network(token, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                out.extend([str(h) for h in net.hosts()])
            else:
                # Dla IPv6 ograniczamy do max 256 hostów (unikamy /48 itp.)
                hosts = list(net.hosts())
                if len(hosts) > 256:
                    log("warn", f"Sieć IPv6 ma {len(hosts)} hostów — ograniczono do 256.")
                    hosts = hosts[:256]
                out.extend([str(h) for h in hosts])
            continue
        except ValueError:
            pass
        # Spróbuj jako adres IP (v4 lub v6)
        if validate_ip(token):
            out.append(token)
    return list(dict.fromkeys(out))  # deduplikacja z zachowaniem kolejności

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
    # [POPRAWA 2] Sortowanie działa dla obu wersji IP
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
            alive.append({"ip": host, "hostname": hostname, "mac": mac, "vendor": vendor})
            print(f"  {c(C.GREEN, '●')} {c(C.WHITE+C.BOLD, host):<42} {c(C.DIM, hostname or '—'):<35} {c(C.YELLOW, mac)} {c(C.CYAN, vendor)}")

    print()
    log("ok", f"Aktywnych hostów: {c(C.GREEN+C.BOLD, str(len(alive)))}")

    ts = now()
    txt_file = f"{REPORT_DIR}/sweep_{ts}.txt"
    with open(txt_file, "w") as f:
        f.write(f"Ping Sweep: {target_net} — {ts}\n\n")
        for h in alive:
            f.write(f"{h['ip']:<42} {h['hostname']:<35} {h['mac']} {h['vendor']}\n")
    log("ok", f"Raport: {txt_file}")
    return alive

# =========================
# BANNER GRABBER
# =========================
def fetch_single_banner(ip, port, proto):
    # Dla IPv6 URL wymaga nawiasów: http://[::1]:80/
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

        return {
            "url": url, "port": port, "proto": proto, "status": res.status,
            "server": res.headers.get("Server", ""),
            "powered_by": res.headers.get("X-Powered-By", ""),
            "title": title, "body": body[:1500], "success": True
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
        rows += f"""
<div class="entry">
  <div class="url"><a href="{r['url']}" target="_blank">{r['url']}</a><span class="badge" style="color:{sc}">{r['status']}</span></div>
  <div class="meta">Server: <b>{r['server'] or '—'}</b> &nbsp;|&nbsp; X-Powered-By: <b>{r['powered_by'] or '—'}</b></div>
  <div class="title">Title: {r['title'] or '—'}</div>
  <details><summary>Body preview</summary><pre>{body_esc}</pre></details>
</div>"""
    html = f"""<!DOCTYPE html><html lang="pl"><head><meta charset="UTF-8"><title>Banner Grabber — {ip}</title>
<style>body{{background:#0d0d0d;color:#ccc;font-family:monospace;padding:24px;max-width:1100px;margin:auto}}
h1{{color:#0f0;border-bottom:1px solid #333;padding-bottom:8px}} a{{color:#0af;text-decoration:none}} a:hover{{text-decoration:underline}}
.entry{{border:1px solid #2a2a2a;border-radius:6px;margin:12px 0;padding:12px;background:#111}} .url{{font-size:1.05em;margin-bottom:6px}}
.badge{{margin-left:10px;font-weight:bold;font-size:.9em}} .meta{{color:#777;font-size:.88em;margin-bottom:4px}} .title{{color:#0f0;font-size:.9em}}
pre{{background:#0a0a0a;padding:10px;overflow:auto;max-height:220px;font-size:.78em;border-radius:4px;border:1px solid #222;white-space:pre-wrap;word-break:break-all}}
details summary{{cursor:pointer;color:#0af;font-size:.88em;margin-top:6px;user-select:none}} details summary:hover{{color:#fff}}</style></head>
<body><h1>🌐 Banner Grabber — {ip}</h1>
<p style="color:#555">Wygenerowano: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Portów: {len(BANNER_PORTS)} | Wyników: {len(results)}</p>
{rows}</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

# =========================
# FUZZER — z rate limitingiem i zewnętrznym słownikiem
# =========================

# [POPRAWA 4] Semafor Rate Limiter dla fuzzera
_FUZZ_SEMAPHORE = threading.BoundedSemaphore(10)  # max 10 równoległych żądań

def _get_baseline(base_url):
    """Pobiera wzorzec catch-all — odpytuje losowy nieistniejący URL."""
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
    """Pobiera URL z rate limitingiem i filtruje catch-all przez baseline."""
    with _FUZZ_SEMAPHORE:
        time.sleep(FUZZ_DELAY)  # [POPRAWA 4] rate limiting
        ua = random.choice(USER_AGENTS)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": ua})
            ctx = get_ssl_ctx()
            res = urllib.request.urlopen(req, timeout=3, context=ctx)
            body = res.read(2048)
            body_hash = hashlib.md5(body).hexdigest()
            body_len  = len(body)

            if baseline_hash and body_hash == baseline_hash:
                return {"url": url, "success": False, "reason": "catch-all"}

            if baseline_len and abs(body_len - baseline_len) < 50:
                return {"url": url, "success": False, "reason": "similar-length"}

            return {
                "url": url, "status": res.status,
                "length": body_len, "hash": body_hash, "success": True
            }
        except HTTPError as e:
            if e.code in [401, 403]:
                return {"url": url, "status": e.code, "length": 0, "success": True}
            return {"url": url, "status": e.code, "success": False}
        except Exception:
            return {"url": url, "success": False}

def _load_wordlist(path):
    """Wczytuje zewnętrzny plik słownika (jeden wpis na linię)."""
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

    # [POPRAWA 3] Opcjonalny zewnętrzny słownik
    paths = _load_wordlist(wordlist_file) if wordlist_file else FUZZ_PATHS
    log("info", f"Słownik: {len(paths)} ścieżek | Delay: {FUZZ_DELAY*1000:.0f} ms")

    # [POPRAWA 2] IPv6 wymaga nawiasów w URL
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
# IDENTITY SCAN
# =========================
def identity_scan(ip):
    log("scan", f"Identity Scan: {c(C.WHITE+C.BOLD, ip)}")
    nm  = nmap.PortScanner()
    res = {"ip": ip, "hostname": None, "mdns": None, "netbios": None, "smb": None, "upnp": None}

    try:
        res["hostname"] = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass

    for proto, port, script, name in [
        ("UDP", 5353, "dns-service-discovery", "mDNS"),
        ("UDP", 137,  "nbstat",               "NetBIOS"),
        ("UDP", 1900, "upnp-info",            "UPnP")
    ]:
        log("info", f"{name} ({proto}/{port})...")
        try:
            nm.scan(hosts=ip, arguments=f"-sU -p {port} --script {script} -T4 --host-timeout 20s")
            if ip in nm.all_hosts():
                res[name.lower()] = (
                    nm[ip].get("udp", {}).get(port, {}).get("script", {}).get(script)
                    or "brak danych"
                )
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

    # [POPRAWA 5] Domyślnie top-1000; -p- tylko z --full-ports
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
    print(div)

    result = {
        "ip": ip, "hostname": hostname, "os": os_name,
        "ports": ports, "http": http_info, "timestamp": now()
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
    """
    [POPRAWA 7] Limit MAX_PARALLEL_NMAP równoległych procesów NMAP.
    [POPRAWA 8] Globalny timeout SCAN_TIMEOUT sekund dla całości.
    """
    results = []
    with ThreadPoolExecutor(max_workers=MAX_PARALLEL_NMAP) as ex:
        future_to_ip = {ex.submit(deep_scan, ip): ip for ip in targets}

        done, not_done = wait(future_to_ip.keys(), timeout=SCAN_TIMEOUT)

        # [POPRAWA 8] Anuluj tych co nie zdążyli
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
# CLI / MAIN ROUTING
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

    # "f <IP> [wordlist]" — opcjonalny plik słownika jako trzeci element
    if lower.startswith("f "):
        parts = raw[2:].strip().split(None, 1)
        ip_arg = parts[0]
        wl_arg = parts[1] if len(parts) > 1 else None
        if validate_ip(ip_arg):
            return "fuzz", ip_arg, wl_arg
        return "unknown", f"Nieprawidłowy IP: {ip_arg}", None

    for prefix, cmd_type in [
        ("i ",    "identity"),
        ("snmp ", "snmp"),
        ("v ",    "vuln"),
        ("b ",    "banner"),
    ]:
        if lower.startswith(prefix):
            arg = raw[len(prefix):].strip()
            if validate_ip(arg):
                return cmd_type, arg, None
            return "unknown", f"Nieprawidłowy IP: {arg}", None

    targets = parse_targets(raw)
    if targets:
        return "deep", targets, None
    return "unknown", "Nieprawidłowy input — wpisz h po pomoc", None

def main():
    global STRICT_SSL, FULL_PORTS

    parser = argparse.ArgumentParser(description="MR.ROOT Scanner v3.0")
    parser.add_argument("-t", "--target",
        help="Cel skanowania (IP, IPv6, CIDR lub lista np. 192.168.1.1,192.168.1.2)")
    parser.add_argument("-m", "--mode",
        choices=["deep", "identity", "snmp", "vuln", "banner", "fuzz", "sweep"],
        help="Tryb skanowania")
    parser.add_argument("-w", "--wordlist",
        help="Zewnętrzny plik słownika dla fuzzera")
    # [POPRAWA 1] --strict-ssl
    parser.add_argument("--strict-ssl", action="store_true",
        help="Włącz weryfikację certyfikatów SSL (domyślnie: unverified / pentest mode)")
    # [POPRAWA 5] --full-ports
    parser.add_argument("--full-ports", action="store_true",
        help="Vuln-scan: skanuj wszystkie 65535 portów zamiast top-1000 (wolno na telefonie)")
    args = parser.parse_args()

    STRICT_SSL = args.strict_ssl
    FULL_PORTS = args.full_ports

    print(BANNER)

    # [POPRAWA 6] Sprawdzenie uprawnień roota
    if os.geteuid() != 0:
        log("warn", f"{c(C.YELLOW+C.BOLD, 'Nie jesteś root!')} Niektóre skany (OS detection, UDP, -sU, -O) wymagają sudo.")
        log("warn", "Uruchom: sudo python3 recon3.py — dla pełnej funkcjonalności.")
    else:
        log("ok", f"Uprawnienia: {c(C.GREEN+C.BOLD, 'root')} — wszystkie skany dostępne.")

    # [POPRAWA 1] Ostrzeżenie SSL przy starcie
    if not STRICT_SSL:
        log("warn", f"{c(C.YELLOW, 'SSL:')} tryb unverified (pentest). Dodaj {c(C.WHITE, '--strict-ssl')} dla weryfikacji certyfikatów.")

    log("ok", f"Katalog raportów: {c(C.DIM, REPORT_DIR)}")
    check_captive_portal()

    # Tryb CLI bez interakcji (One-Shot Mode)
    if args.target and args.mode:
        log("info", f"Uruchamianie z linii komend: Tryb={args.mode}, Cel={args.target}")
        if   args.mode == "sweep":    ping_sweep(args.target)
        elif args.mode == "deep":     run_scan(parse_targets(args.target))
        elif args.mode == "identity": identity_scan(args.target)
        elif args.mode == "snmp":     snmp_scan(args.target)
        elif args.mode == "vuln":     vuln_scan(args.target)
        elif args.mode == "banner":   banner_grabber(args.target)
        elif args.mode == "fuzz":     fuzz_scan(args.target, args.wordlist)
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
        elif cmd_type == "unknown":  log("err", arg)

if __name__ == "__main__":
    main()
