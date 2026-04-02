#!/usr/bin/env python3
"""
MR.ROOT Scanner v2.0 — NetHunter Edition
Autor: MR.ROOT | Kali NetHunter
TYLKO do użytku na własnej sieci lub za pisemną zgodą właściciela.
"""

import nmap
import os
import sys
import json
import datetime
import ipaddress
import socket
import ssl
import urllib.request
import subprocess
from concurrent.futures import ThreadPoolExecutor

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
# CONFIG
# =========================
def _detect_base_dir():
    """Wykrywa pierwszy zapisywalny katalog bazowy."""
    for candidate in ["/MR.ROOT", os.path.expanduser("~/MR.ROOT"), "/sdcard/MR.ROOT", "/tmp/MR.ROOT"]:
        try:
            os.makedirs(candidate, exist_ok=True)
            test = os.path.join(candidate, ".write_test")
            with open(test, "w") as f:
                f.write("ok")
            os.remove(test)
            return candidate
        except:
            continue
    return "/tmp/MR.ROOT"

BASE_DIR   = _detect_base_dir()
REPORT_DIR = f"{BASE_DIR}/reports"
HTML_DIR   = f"{REPORT_DIR}/html"
CACHE_FILE = f"{BASE_DIR}/cache.json"

NMAP_FAST  = "-T4 --max-retries 2 --host-timeout 30s --max-rtt-timeout 500ms"
NMAP_DEEP  = "-T4 --max-retries 3 --host-timeout 120s"
MAX_THREADS = 5

SNMP_COMMUNITIES = ["public", "private", "community", "admin", "manager", "cisco", "snmp"]
BANNER_PORTS     = [80, 443, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 3000, 5000]

VULN_SCRIPTS = [
    "vuln",
    "ssl-heartbleed",
    "ssl-poodle",
    "ssl-dh-params",
    "smb-vuln-ms17-010",
    "smb-vuln-ms08-067",
    "http-vuln-cve2017-5638",
    "http-shellshock",
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
{C.DIM}        Mobilny Skaner Sieci | by MR.ROOT | NetHunter Edition v2.0{C.RESET}
"""

HELP_TEXT = f"""
{c(C.CYAN+C.BOLD, "═══ KOMENDY ═══")}
  {c(C.GREEN, "<IP>")}              Deep Scan — porty, OS, HTTP
  {c(C.GREEN, "<IP,IP,...>")}       Wiele celów naraz
  {c(C.GREEN, "<CIDR>")}           Skan podsieci (np. 192.168.1.0/24)
  {c(C.GREEN, "i <IP>")}           Identity Scan — mDNS, NetBIOS, SMB, UPnP
  {c(C.GREEN, "snmp <IP>")}        SNMP Scan — community brute + info
  {c(C.GREEN, "v <IP>")}           Vuln-Scan NSE — CVE, Heartbleed, EternalBlue
  {c(C.GREEN, "b <IP>")}           Banner Grabber — HTTP/HTTPS + raport HTML
  {c(C.GREEN, "sweep")}            Ping Sweep aktywnej podsieci
  {c(C.GREEN, "sweep <CIDR>")}     Ping Sweep podanej podsieci
  {c(C.GREEN, "h")}                Ta pomoc
  {c(C.GREEN, "q / exit")}         Wyjście
{c(C.DIM, f"  Raporty: {REPORT_DIR}")}
"""

# =========================
# LOGGING
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

# =========================
# CACHE
# =========================
def load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE) as f:
                return json.load(f)
        except:
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
# UTILS
# =========================
def now():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def validate_ip(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except:
        return False

def parse_targets(inp):
    out = []
    for token in inp.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            net = ipaddress.IPv4Network(token, strict=False)
            out.extend([str(h) for h in net.hosts()])
        except:
            if validate_ip(token):
                out.append(token)
    return list(set(out))

def ip_to_filename(ip):
    return ip.replace(".", "-")

# =========================
# NETWORK INTERFACE DETECT
# =========================
def detect_interface():
    """Zwraca (interfejs, IP, sieć/CIDR) aktywnego połączenia."""
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"],
            stderr=subprocess.DEVNULL, text=True)
        for line in out.splitlines():
            parts = line.split()
            if "dev" in parts:
                iface = parts[parts.index("dev") + 1]
                addr_out = subprocess.check_output(
                    ["ip", "-4", "addr", "show", iface],
                    stderr=subprocess.DEVNULL, text=True)
                for iline in addr_out.splitlines():
                    iline = iline.strip()
                    if iline.startswith("inet "):
                        cidr = iline.split()[1]
                        ip   = cidr.split("/")[0]
                        net  = str(ipaddress.IPv4Network(cidr, strict=False))
                        return iface, ip, net
    except:
        pass
    return None, None, None

# =========================
# PING SWEEP
# =========================
def ping_sweep(network=None):
    iface, my_ip, detected_net = detect_interface()
    target_net = network or detected_net

    if not target_net:
        log("err", "Nie można wykryć sieci. Podaj CIDR: sweep 192.168.1.0/24")
        return []

    if iface:
        log("info", f"Interfejs: {c(C.GREEN, iface)} | IP: {c(C.GREEN, my_ip)} | Sieć: {c(C.GREEN, target_net)}")

    log("scan", f"Ping sweep → {c(C.WHITE+C.BOLD, target_net)} ...")

    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target_net, arguments="-sn -T4 --max-rtt-timeout 300ms")
    except Exception as e:
        log("err", f"Ping sweep error: {e}")
        return []

    alive = []
    print()
    for host in sorted(nm.all_hosts(), key=lambda x: ipaddress.IPv4Address(x)):
        if nm[host].state() == "up":
            try:
                hostname = socket.gethostbyaddr(host)[0]
            except:
                hostname = ""
            addrs  = nm[host].get("addresses", {})
            mac    = addrs.get("mac", "??:??:??:??:??:??")
            vendor = nm[host].get("vendor", {}).get(mac, "")
            alive.append({"ip": host, "hostname": hostname, "mac": mac, "vendor": vendor})
            print(f"  {c(C.GREEN, '●')} {c(C.WHITE+C.BOLD, host):<18} "
                  f"{c(C.DIM, hostname or '—'):<35} "
                  f"{c(C.YELLOW, mac)} {c(C.CYAN, vendor)}")

    print()
    log("ok", f"Aktywnych hostów: {c(C.GREEN+C.BOLD, str(len(alive)))}")

    # Zapis
    ts = now()
    txt_file = f"{REPORT_DIR}/sweep_{ts}.txt"
    with open(txt_file, "w") as f:
        f.write(f"Ping Sweep: {target_net} — {ts}\n\n")
        for h in alive:
            f.write(f"{h['ip']:<18} {h['hostname']:<35} {h['mac']} {h['vendor']}\n")
    log("ok", f"Raport: {txt_file}")

    return alive

# =========================
# HTTP GRAB (wewnętrzny)
# =========================
def grab_http_basic(ip):
    results = []
    for proto in ["http", "https"]:
        try:
            url = f"{proto}://{ip}"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            ctx = ssl._create_unverified_context()
            res = urllib.request.urlopen(req, timeout=5, context=ctx)
            body = res.read(1024).decode("utf-8", errors="ignore")
            results.append({
                "url":    url,
                "status": res.status,
                "server": res.headers.get("Server", ""),
                "body":   body[:300],
            })
        except:
            continue
    return results

# =========================
# BANNER GRABBER (b <IP>)
# =========================
def banner_grabber(ip):
    log("scan", f"Banner Grabber: {c(C.WHITE+C.BOLD, ip)}")

    results = []
    for port in BANNER_PORTS:
        for proto in ["http", "https"]:
            try:
                url = f"{proto}://{ip}:{port}"
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                ctx = ssl._create_unverified_context()
                res = urllib.request.urlopen(req, timeout=4, context=ctx)
                body = res.read(4096).decode("utf-8", errors="ignore")

                title = ""
                bl = body.lower()
                if "<title>" in bl and "</title>" in bl:
                    s = bl.index("<title>") + 7
                    e = bl.index("</title>")
                    title = body[s:e].strip()

                entry = {
                    "url":        url,
                    "port":       port,
                    "proto":      proto,
                    "status":     res.status,
                    "server":     res.headers.get("Server", ""),
                    "powered_by": res.headers.get("X-Powered-By", ""),
                    "title":      title,
                    "body":       body[:1500],
                }
                results.append(entry)

                sc = C.GREEN if res.status < 400 else C.YELLOW
                log("ok", f"  {c(sc, str(res.status))} {c(C.WHITE, url):<45} "
                    f"{c(C.DIM, entry['server']):<25} {c(C.CYAN, title[:50])}")
            except:
                continue

    if not results:
        log("warn", "Brak odpowiedzi HTTP na żadnym porcie")
        return []

    ts = now()
    safe_ip = ip_to_filename(ip)

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
  <div class="url">
    <a href="{r['url']}" target="_blank">{r['url']}</a>
    <span class="badge" style="color:{sc}">{r['status']}</span>
  </div>
  <div class="meta">
    Server: <b>{r['server'] or '—'}</b> &nbsp;|&nbsp;
    X-Powered-By: <b>{r['powered_by'] or '—'}</b>
  </div>
  <div class="title">Title: {r['title'] or '—'}</div>
  <details><summary>Body preview</summary><pre>{body_esc}</pre></details>
</div>"""

    html = f"""<!DOCTYPE html>
<html lang="pl"><head><meta charset="UTF-8">
<title>Banner Grabber — {ip}</title>
<style>
  body{{background:#0d0d0d;color:#ccc;font-family:monospace;padding:24px;max-width:1100px;margin:auto}}
  h1{{color:#0f0;border-bottom:1px solid #333;padding-bottom:8px}}
  a{{color:#0af;text-decoration:none}} a:hover{{text-decoration:underline}}
  .entry{{border:1px solid #2a2a2a;border-radius:6px;margin:12px 0;padding:12px;background:#111}}
  .url{{font-size:1.05em;margin-bottom:6px}}
  .badge{{margin-left:10px;font-weight:bold;font-size:.9em}}
  .meta{{color:#777;font-size:.88em;margin-bottom:4px}}
  .title{{color:#0f0;font-size:.9em}}
  pre{{background:#0a0a0a;padding:10px;overflow:auto;max-height:220px;font-size:.78em;
       border-radius:4px;border:1px solid #222;white-space:pre-wrap;word-break:break-all}}
  details summary{{cursor:pointer;color:#0af;font-size:.88em;margin-top:6px;user-select:none}}
  details summary:hover{{color:#fff}}
</style></head>
<body>
<h1>🌐 Banner Grabber — {ip}</h1>
<p style="color:#555">Wygenerowano: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
 | Portów przeskanowanych: {len(BANNER_PORTS)} | Wyników: {len(results)}</p>
{rows}
</body></html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

# =========================
# IDENTITY SCAN (i <IP>)
# =========================
def identity_scan(ip):
    log("scan", f"Identity Scan: {c(C.WHITE+C.BOLD, ip)}")

    nm  = nmap.PortScanner()
    res = {"ip": ip, "hostname": None, "mdns": None, "netbios": None, "smb": None, "upnp": None}

    # Reverse DNS
    try:
        res["hostname"] = socket.gethostbyaddr(ip)[0]
    except:
        pass

    # mDNS (UDP/5353)
    log("info", "mDNS/Zeroconf (UDP/5353)...")
    try:
        nm.scan(hosts=ip, arguments="-sU -p 5353 --script dns-service-discovery -T4 --host-timeout 20s")
        if ip in nm.all_hosts():
            scripts = nm[ip].get("udp", {}).get(5353, {}).get("script", {})
            res["mdns"] = scripts.get("dns-service-discovery") or "brak danych"
    except Exception as e:
        res["mdns"] = f"error: {e}"

    # NetBIOS (UDP/137)
    log("info", "NetBIOS (UDP/137)...")
    try:
        nm.scan(hosts=ip, arguments="-sU -p 137 --script nbstat -T4 --host-timeout 20s")
        if ip in nm.all_hosts():
            scripts = nm[ip].get("udp", {}).get(137, {}).get("script", {})
            res["netbios"] = scripts.get("nbstat") or "brak danych"
    except Exception as e:
        res["netbios"] = f"error: {e}"

    # SMB (TCP/139,445)
    log("info", "SMB (TCP/139,445)...")
    try:
        nm.scan(hosts=ip, arguments="-p 139,445 --script smb-os-discovery,smb-enum-shares -T4 --host-timeout 30s")
        if ip in nm.all_hosts():
            tcp = nm[ip].get("tcp", {})
            for port in [445, 139]:
                if port in tcp:
                    scripts = tcp[port].get("script", {})
                    res["smb"] = {
                        "os_discovery": scripts.get("smb-os-discovery", ""),
                        "shares":       scripts.get("smb-enum-shares", ""),
                    }
                    break
    except Exception as e:
        res["smb"] = {"error": str(e)}

    # UPnP/SSDP (UDP/1900)
    log("info", "UPnP/SSDP (UDP/1900)...")
    try:
        nm.scan(hosts=ip, arguments="-sU -p 1900 --script upnp-info -T4 --host-timeout 20s")
        if ip in nm.all_hosts():
            scripts = nm[ip].get("udp", {}).get(1900, {}).get("script", {})
            res["upnp"] = scripts.get("upnp-info") or "brak danych"
    except Exception as e:
        res["upnp"] = f"error: {e}"

    # Wydruk karty
    div = c(C.CYAN+C.BOLD, "═" * 50)
    print(f"\n{div}")
    print(c(C.CYAN+C.BOLD, f"  KARTA URZĄDZENIA: {ip}"))
    print(div)
    _card_row("Hostname", res["hostname"])
    _card_row("mDNS",     res["mdns"],    C.GREEN)
    _card_row("NetBIOS",  res["netbios"], C.GREEN)
    if res["smb"]:
        smb = res["smb"]
        _card_row("SMB OS",   smb.get("os_discovery"), C.YELLOW)
        _card_row("SMB Share",smb.get("shares"),        C.YELLOW)
    _card_row("UPnP",     res["upnp"],    C.CYAN)
    print(div + "\n")

    # Zapis
    ts  = now()
    out = f"{REPORT_DIR}/identity_{ip_to_filename(ip)}_{ts}.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, ensure_ascii=False)
    log("ok", f"Raport: {out}")

    return res

def _card_row(label, value, color=C.WHITE):
    if not value:
        return
    val_str = str(value).strip()
    if not val_str or val_str in ["brak danych", "None"]:
        return
    lines = val_str.splitlines()
    print(c(C.DIM, f"  {label:<10}:") + " " + c(color, lines[0][:110]))
    for line in lines[1:8]:
        print(c(color, f"              {line[:110]}"))
    if len(lines) > 8:
        print(c(C.DIM, f"              ... (+{len(lines)-8} linii)"))

# =========================
# SNMP SCAN (snmp <IP>)
# =========================
def snmp_scan(ip):
    log("scan", f"SNMP Scan: {c(C.WHITE+C.BOLD, ip)}")
    log("info",  f"Próbuję community strings: {c(C.DIM, ', '.join(SNMP_COMMUNITIES))}")

    nm = nmap.PortScanner()
    res = {"ip": ip, "community": None, "data": {}}
    found_community = None
    snmp_data = {}

    for community in SNMP_COMMUNITIES:
        log("info", f"  → community: {c(C.YELLOW, community)}")
        try:
            nm.scan(
                hosts=ip,
                arguments=(
                    f"-sU -p 161 "
                    f"--script snmp-info,snmp-interfaces,snmp-processes,snmp-sysdescr "
                    f"--script-args snmp.community={community} "
                    f"-T4 --host-timeout 20s"
                )
            )
            if ip not in nm.all_hosts():
                continue
            udp = nm[ip].get("udp", {})
            if 161 not in udp:
                continue
            port_info = udp[161]
            if port_info.get("state") not in ["open", "open|filtered"]:
                continue
            scripts = port_info.get("script", {})
            if scripts:
                found_community = community
                snmp_data = scripts
                log("ok", f"Community string działa: {c(C.GREEN+C.BOLD, community)}")
                break
        except Exception as e:
            log("err", f"SNMP error ({community}): {e}")
            continue

    if not found_community:
        log("warn", "SNMP niedostępny lub żadna community string nie zadziałała")
        return res

    res["community"] = found_community
    res["data"]      = snmp_data

    # Wydruk
    div = c(C.CYAN+C.BOLD, "═" * 55)
    print(f"\n{div}")
    print(c(C.CYAN+C.BOLD, f"  SNMP INFO: {ip}  [community: {found_community}]"))
    print(div)
    for key, val in snmp_data.items():
        print(c(C.GREEN+C.BOLD, f"\n  [{key}]"))
        lines = str(val).splitlines()
        for line in lines[:20]:
            print(c(C.WHITE, f"    {line}"))
        if len(lines) > 20:
            print(c(C.DIM, f"    ... (+{len(lines)-20} linii)"))
    print(f"\n{div}\n")

    ts  = now()
    out = f"{REPORT_DIR}/snmp_{ip_to_filename(ip)}_{ts}.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, ensure_ascii=False)
    log("ok", f"Raport: {out}")

    return res

# =========================
# VULN SCAN (v <IP>)
# =========================
def vuln_scan(ip):
    log("scan", f"Vuln-Scan NSE: {c(C.WHITE+C.BOLD, ip)}")
    log("warn", "Może potrwać kilka minut...")

    nm  = nmap.PortScanner()
    res = {"ip": ip, "vulns": []}

    try:
        nm.scan(
            hosts=ip,
            arguments=(
                f"-sV -p- "
                f"--script {','.join(VULN_SCRIPTS)} "
                f"{NMAP_DEEP}"
            )
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
            svc     = host[proto][port]
            scripts = svc.get("script", {})
            for script_name, output in scripts.items():
                if not output:
                    continue
                if "VULNERABLE" in output.upper():
                    vuln_found.append({"port": port, "script": script_name, "output": output})
                    print(c(C.RED+C.BOLD, f"\n  ⚠  PODATNOŚĆ [{script_name}] PORT {port}"))
                    for line in output.splitlines()[:10]:
                        print(c(C.YELLOW, f"     {line}"))
                else:
                    # Pokaż skróconą informację dla innych skryptów
                    first_line = output.splitlines()[0][:100] if output else ""
                    print(c(C.DIM, f"  [{script_name}:{port}] {first_line}"))

    print()
    if not vuln_found:
        log("ok", "Brak wykrytych podatności NSE")
    else:
        log("vuln", f"Wykryto {c(C.RED+C.BOLD, str(len(vuln_found)))} podatności!")

    res["vulns"] = vuln_found

    ts  = now()
    out = f"{REPORT_DIR}/vuln_{ip_to_filename(ip)}_{ts}.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, ensure_ascii=False)
    log("ok", f"Raport: {out}")

    return res

# =========================
# DEEP SCAN (core)
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
        log("warn", f"{ip} — host niedostępny (down)")
        return {"ip": ip, "status": "down"}

    host = nm[ip]

    os_name = "unknown"
    if host.get("osmatch"):
        os_name = host["osmatch"][0]["name"]

    ports = []
    for proto in host.all_protocols():
        for port in sorted(host[proto]):
            svc = host[proto][port]
            if svc["state"] == "open":
                ports.append({
                    "port":    port,
                    "proto":   proto,
                    "service": svc.get("name", ""),
                    "product": svc.get("product", ""),
                    "version": svc.get("version", ""),
                })

    http_info = grab_http_basic(ip)

    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except:
        hostname = None

    # Wydruk
    div = c(C.CYAN+C.BOLD, "─" * 55)
    print(f"\n{div}")
    print(c(C.CYAN+C.BOLD, f"  {ip}"))
    print(div)
    print(c(C.WHITE,  f"  OS       : {os_name}"))
    print(c(C.WHITE,  f"  Hostname : {hostname or '—'}"))
    print(c(C.WHITE,  f"  Porty    :"))
    for p in ports:
        ver = f"{p['product']} {p['version']}".strip()
        print(f"    {c(C.GREEN, f\"{p['port']}/{p['proto']}\"):<22}"
              f"{c(C.CYAN, p['service']):<16} {c(C.DIM, ver)}")
    for h in http_info:
        sc = C.GREEN if h["status"] < 400 else C.YELLOW
        print(f"    {c(C.YELLOW, '→ HTTP')} {h['url']} "
              f"[{c(sc, str(h['status']))}] {c(C.DIM, h['server'])}")
    print(div)

    result = {
        "ip":        ip,
        "hostname":  hostname,
        "os":        os_name,
        "ports":     ports,
        "http":      http_info,
        "timestamp": now(),
    }

    CACHE[cache_key] = result
    return result

# =========================
# SAVE DEEP SCAN OUTPUT
# =========================
def save_deep_outputs(results):
    ts = now()

    json_file = f"{REPORT_DIR}/scan_{ts}.json"
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    txt_file = f"{REPORT_DIR}/scan_{ts}.txt"
    with open(txt_file, "w", encoding="utf-8") as f:
        for r in results:
            f.write(f"\n=== {r['ip']} ===\n")
            f.write(f"OS      : {r.get('os', '?')}\n")
            f.write(f"Hostname: {r.get('hostname') or '—'}\n")
            for p in r.get("ports", []):
                f.write(f"PORT {p['port']}/{p['proto']:<5} {p['service']:<15} "
                        f"{p['product']} {p['version']}\n")

    html_file = f"{HTML_DIR}/scan_{ts}.html"
    with open(html_file, "w", encoding="utf-8") as f:
        f.write("""<!DOCTYPE html><html lang="pl"><head><meta charset="UTF-8">
<title>MR.ROOT Scan</title>
<style>
  body{background:#0d0d0d;color:#ccc;font-family:monospace;padding:24px;max-width:900px;margin:auto}
  h1{color:#0f0} h2{color:#0af;border-bottom:1px solid #222;padding-bottom:4px}
  .os{color:#ff0} .port{color:#0af} .http{color:#fa0} .dim{color:#555}
</style></head><body>""")
        f.write(f"<h1>MR.ROOT Deep Scan — {ts}</h1>")
        for r in results:
            f.write(f"<h2>{r['ip']}</h2>")
            f.write(f"<p class='os'>OS: {r.get('os')}</p>")
            f.write(f"<p class='dim'>Hostname: {r.get('hostname') or '—'}</p>")
            for p in r.get("ports", []):
                f.write(f"<div class='port'>PORT {p['port']}/{p['proto']} "
                        f"→ {p['service']} <span class='dim'>{p['product']} {p['version']}</span></div>")
            for h in r.get("http", []):
                f.write(f"<div class='http'>→ HTTP {h['url']} [{h['status']}] {h['server']}</div>")
        f.write("</body></html>")

    print()
    log("ok", "Zapisano:")
    print(f"   {json_file}")
    print(f"   {txt_file}")
    print(f"   {html_file}")

# =========================
# PARALLEL DEEP SCAN
# =========================
def run_scan(targets):
    results = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
        futures = [ex.submit(deep_scan, ip) for ip in targets]
        for fut in futures:
            try:
                results.append(fut.result())
            except Exception as e:
                log("err", str(e))
    save_cache(CACHE)
    save_deep_outputs(results)

# =========================
# CLI COMMAND PARSER
# =========================
def parse_command(raw):
    """
    Zwraca (typ, arg):
      deep     → arg = lista IP
      identity → arg = IP
      snmp     → arg = IP
      vuln     → arg = IP
      banner   → arg = IP
      sweep    → arg = CIDR | None
      help | quit | unknown
    """
    raw   = raw.strip()
    lower = raw.lower()

    if lower in ["q", "exit", "quit"]:
        return "quit", None
    if lower in ["h", "help", "?"]:
        return "help", None
    if lower == "sweep":
        return "sweep", None
    if lower.startswith("sweep "):
        return "sweep", raw[6:].strip()

    for prefix, cmd_type in [
        ("i ",    "identity"),
        ("snmp ", "snmp"),
        ("v ",    "vuln"),
        ("b ",    "banner"),
    ]:
        if lower.startswith(prefix):
            arg = raw[len(prefix):].strip()
            if validate_ip(arg):
                return cmd_type, arg
            return "unknown", f"Nieprawidłowy IP: {arg}"

    targets = parse_targets(raw)
    if targets:
        return "deep", targets
    return "unknown", "Nieprawidłowy input — wpisz h po pomoc"

# =========================
# MAIN
# =========================
def main():
    print(BANNER)
    log("ok", f"Katalog raportów: {c(C.DIM, REPORT_DIR)}")

    # Auto-detect i opcjonalny ping sweep przy starcie
    iface, my_ip, net = detect_interface()
    if iface:
        log("info", f"Interfejs: {c(C.GREEN, iface)} | IP: {c(C.GREEN, my_ip)} | Sieć: {c(C.GREEN, net)}")
        try:
            ans = input(c(C.YELLOW, f"\n[?] Wykonać ping sweep {net}? [T/n]: ")).strip().lower()
        except (KeyboardInterrupt, EOFError):
            ans = "n"
        if ans in ["", "t", "y", "tak", "yes"]:
            ping_sweep(net)
    else:
        log("warn", "Nie wykryto aktywnego interfejsu sieciowego")

    print(HELP_TEXT)

    while True:
        try:
            raw = input(c(C.GREEN+C.BOLD, "[MR.ROOT]>> ")).strip()
        except (KeyboardInterrupt, EOFError):
            print()
            log("info", "Zamykanie...")
            save_cache(CACHE)
            sys.exit(0)

        if not raw:
            continue

        cmd_type, arg = parse_command(raw)

        if   cmd_type == "quit":
            save_cache(CACHE)
            log("info", "Żegnaj.")
            sys.exit(0)
        elif cmd_type == "help":
            print(HELP_TEXT)
        elif cmd_type == "sweep":
            ping_sweep(arg)
        elif cmd_type == "deep":
            run_scan(arg)
        elif cmd_type == "identity":
            identity_scan(arg)
        elif cmd_type == "snmp":
            snmp_scan(arg)
        elif cmd_type == "vuln":
            vuln_scan(arg)
        elif cmd_type == "banner":
            banner_grabber(arg)
        elif cmd_type == "unknown":
            log("err", arg)

if __name__ == "__main__":
    main()
