#!/usr/bin/env python3

import nmap
import os
import json
import datetime
import ipaddress
import socket
import ssl
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# =========================
# CONFIG
# =========================
BASE_DIR = "/sdcard/MR.ROOT"
REPORT_DIR = f"{BASE_DIR}/reports"
CACHE_FILE = f"{BASE_DIR}/cache.json"

NMAP_ARGS = "-T4 --max-retries 2 --host-timeout 30s --max-rtt-timeout 500ms"
MAX_THREADS = 5

# =========================
# INIT
# =========================
os.makedirs(REPORT_DIR, exist_ok=True)

# =========================
# CACHE
# =========================
def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE) as f:
            return json.load(f)
    return {}

def save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)

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

# =========================
# HTTP INFO
# =========================
def grab_http(ip):
    results = []
    for proto in ["http", "https"]:
        try:
            url = f"{proto}://{ip}"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            ctx = ssl._create_unverified_context()
            res = urllib.request.urlopen(req, timeout=5, context=ctx)

            results.append({
                "url": url,
                "status": res.status,
                "server": res.headers.get("Server")
            })
        except:
            continue
    return results

# =========================
# CORE SCAN
# =========================
def deep_scan(ip):
    if ip in CACHE:
        print(f"[CACHE] {ip}")
        return CACHE[ip]

    print(f"[SCAN] {ip}")

    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip, arguments=f"-F -sV -O {NMAP_ARGS}")
    except Exception as e:
        return {"ip": ip, "error": str(e)}

    if ip not in nm.all_hosts():
        return {"ip": ip, "status": "down"}

    host = nm[ip]

    # OS
    os_name = "unknown"
    if host.get("osmatch"):
        os_name = host["osmatch"][0]["name"]

    # Ports
    ports = []
    for proto in host.all_protocols():
        for port in host[proto]:
            if host[proto][port]["state"] == "open":
                ports.append({
                    "port": port,
                    "service": host[proto][port].get("name"),
                    "product": host[proto][port].get("product"),
                })

    # HTTP
    http_info = grab_http(ip)

    # Reverse DNS
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except:
        hostname = None

    result = {
        "ip": ip,
        "hostname": hostname,
        "os": os_name,
        "ports": ports,
        "http": http_info,
        "timestamp": now()
    }

    CACHE[ip] = result
    return result

# =========================
# SAVE
# =========================
def save_outputs(results):

    ts = now()

    # JSON
    json_file = f"{REPORT_DIR}/scan_{ts}.json"
    with open(json_file, "w") as f:
        json.dump(results, f, indent=2)

    # TXT
    txt_file = f"{REPORT_DIR}/scan_{ts}.txt"
    with open(txt_file, "w") as f:
        for r in results:
            f.write(f"\n=== {r['ip']} ===\n")
            f.write(f"OS: {r.get('os')}\n")
            f.write(f"Hostname: {r.get('hostname')}\n")

            for p in r.get("ports", []):
                f.write(f"PORT {p['port']} → {p['service']} {p['product']}\n")

    # HTML
    html_file = f"{REPORT_DIR}/scan_{ts}.html"
    with open(html_file, "w") as f:
        f.write("<html><body style='background:#111;color:#0f0;font-family:monospace'>")
        for r in results:
            f.write(f"<h2>{r['ip']}</h2>")
            f.write(f"<p>OS: {r.get('os')}</p>")
            for p in r.get("ports", []):
                f.write(f"<div>PORT {p['port']} → {p['service']}</div>")
        f.write("</body></html>")

    print(f"\n[+] Saved:")
    print(json_file)
    print(txt_file)
    print(html_file)

# =========================
# PARALLEL EXEC
# =========================
def run_scan(targets):
    results = []

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
        futures = [ex.submit(deep_scan, ip) for ip in targets]

        for f in futures:
            try:
                results.append(f.result())
            except:
                pass

    save_cache(CACHE)
    save_outputs(results)

# =========================
# CLI
# =========================
def main():
    print("\nMR.ROOT Scanner (Refactored)\n")

    while True:
        cmd = input(">> ").strip()

        if cmd in ["q", "exit"]:
            break

        if not cmd:
            continue

        targets = parse_targets(cmd)

        if not targets:
            print("Invalid input")
            continue

        run_scan(targets)

# =========================
# START
# =========================
if __name__ == "__main__":
    main()