import nmap
import subprocess
import re
import datetime
import ipaddress
import os
import ssl
import urllib.request
import urllib.error

# ============================================================
#  KOLORY ANSI
# ============================================================
class C:
    RESET   = '\033[0m'
    BOLD    = '\033[1m'
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN    = '\033[96m'
    WHITE   = '\033[97m'
    DIM     = '\033[2m'

BANNER = f"""
{C.CYAN}{C.BOLD}
  ███╗   ███╗██████╗     ██████╗  ██████╗  ██████╗ ████████╗
  ████╗ ████║██╔══██╗    ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
  ██╔████╔██║██████╔╝    ██████╔╝██║   ██║██║   ██║   ██║   
  ██║╚██╔╝██║██╔══██╗    ██╔══██╗██║   ██║██║   ██║   ██║   
  ██║ ╚═╝ ██║██║  ██║    ██║  ██║╚██████╔╝╚██████╔╝   ██║   
  ╚═╝     ╚═╝╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   
{C.DIM}        Mobilny Skaner Sieci | by MR.ROOT | NetHunter Edition{C.RESET}
"""

HELP_TEXT = f"""
{C.CYAN}{'='*60}{C.RESET}
{C.BOLD}  DOSTĘPNE KOMENDY:{C.RESET}

  {C.WHITE}── ROZPOZNANIE ──────────────────────────────────{C.RESET}
  {C.GREEN}<IP>{C.RESET}           → Głęboki skan portów + OS
  {C.GREEN}<IP,IP,...>{C.RESET}    → Wiele celów naraz

  {C.WHITE}── WYWIAD / TOŻSAMOŚĆ ──────────────────────────{C.RESET}
  {C.CYAN}i <IP>{C.RESET}         → Identity Scan (mDNS + SMB + UPnP)
  {C.BLUE}snmp <IP>{C.RESET}      → SNMP Scan UDP/161 (drukarki, switche)

  {C.WHITE}── PODATNOŚCI ──────────────────────────────────{C.RESET}
  {C.YELLOW}v <IP>{C.RESET}         → Vuln-Scan NSE (CVE, Heartbleed, EternalBlue)
  {C.MAGENTA}b <IP>{C.RESET}         → Banner Grabber HTTP/HTTPS + raport HTML

  {C.WHITE}── INNE ────────────────────────────────────────{C.RESET}
  {C.DIM}h{C.RESET}              → Pokaż tę pomoc
  {C.RED}q / Enter{C.RESET}      → Wyjście
{C.CYAN}{'='*60}{C.RESET}
"""

# ============================================================
#  KATALOGI RAPORTÓW
# ============================================================
REPORT_DIR      = "/MR.ROOT/reports"
REPORT_DIR_HTML = "/MR.ROOT/reports/html"

def init_report_dirs():
    os.makedirs(REPORT_DIR, exist_ok=True)
    os.makedirs(REPORT_DIR_HTML, exist_ok=True)

def _strip_ansi(text: str) -> str:
    return re.sub(r'\033\[[0-9;]*m', '', text)

def save_report(content: str, ip_label: str, subdir: str = REPORT_DIR, ext: str = "txt"):
    timestamp  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_label = ip_label.replace("/", "_").replace(".", "-")
    filename   = f"{subdir}/scan_{safe_label}_{timestamp}.{ext}"
    clean      = _strip_ansi(content) if ext == "txt" else content
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(clean)
        print(f"{C.DIM}[*] Raport zapisany: {filename}{C.RESET}")
        return filename
    except Exception as e:
        print(f"{C.RED}[!] Błąd zapisu raportu: {e}{C.RESET}")
        return None

# ============================================================
#  WALIDACJA IP
# ============================================================
def validate_ip(ip_str: str) -> bool:
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except ipaddress.AddressValueError:
        return False

def parse_ip_list(user_input: str) -> list:
    results = []
    for token in user_input.split(','):
        token = token.strip()
        if not token:
            continue
        try:
            net   = ipaddress.IPv4Network(token, strict=False)
            hosts = list(net.hosts())
            if len(hosts) > 254:
                print(f"{C.YELLOW}[!] Zakres {token} ma {len(hosts)} hostów — za dużo. Podaj konkretne IP.{C.RESET}")
                continue
            results.extend(str(h) for h in hosts)
        except ValueError:
            if validate_ip(token):
                results.append(token)
            else:
                print(f"{C.RED}[!] Niepoprawny adres: '{token}' — pomijam.{C.RESET}")
    return results

# ============================================================
#  WYKRYCIE INTERFEJSU
# ============================================================
def get_network_info():
    for iface in ['wlan0', 'eth0', 'usb0']:
        try:
            output = subprocess.check_output(
                ["ip", "-4", "addr", "show", iface],
                stderr=subprocess.DEVNULL
            ).decode('utf-8')
            match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', output)
            if match:
                ip     = match.group(1)
                cidr   = match.group(2)
                subnet = ".".join(ip.split('.')[:-1]) + ".0/" + cidr
                return ip, subnet, iface
        except Exception:
            continue
    return "127.0.0.1", "127.0.0.0/24", "lo"

# ============================================================
#  PING SWEEP
# ============================================================
def scan_network(network_target: str) -> list:
    print(f"\n{C.BLUE}[*] Rozpoczynam szybkie skanowanie sieci: {C.BOLD}{network_target}{C.RESET}")
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=network_target, arguments='-sn --min-parallelism 50')
    except nmap.PortScannerError as e:
        print(f"{C.RED}[!] Błąd skanera nmap: {e}{C.RESET}")
        return []

    live_hosts = nm.all_hosts()
    print(f"{C.GREEN}[*] Zakończono. Znaleziono {C.BOLD}{len(live_hosts)}{C.RESET}{C.GREEN} aktywnych urządzeń.{C.RESET}\n")
    print(C.CYAN + "=" * 50 + C.RESET)

    report_lines = [f"=== Ping Sweep: {network_target} | {datetime.datetime.now()} ===\n"]
    for host in live_hosts:
        print(f"\n{C.GREEN}[+] Adres IP:   {C.BOLD}{host}{C.RESET}")
        report_lines.append(f"[+] Adres IP:   {host}")
        if 'mac' in nm[host]['addresses']:
            mac    = nm[host]['addresses']['mac']
            vendor = nm[host].get('vendor', {}).get(mac, '')
            print(f"    Adres MAC:  {C.YELLOW}{mac}{C.RESET}")
            report_lines.append(f"    Adres MAC:  {mac}")
            if vendor:
                print(f"    Producent:  {C.MAGENTA}{vendor}{C.RESET}")
                report_lines.append(f"    Producent:  {vendor}")
        else:
            print(f"    Adres MAC:  {C.DIM}Nieznany (może to być Twoje urządzenie){C.RESET}")
            report_lines.append("    Adres MAC:  Nieznany")
        print(C.DIM + "-" * 50 + C.RESET)
        report_lines.append("-" * 50)

    save_report("\n".join(report_lines), network_target)
    return live_hosts

# ============================================================
#  GŁĘBOKI SKAN PORTÓW
# ============================================================
def deep_scan(ip_address: str):
    print(f"\n{C.CYAN}{'='*60}{C.RESET}")
    print(f"{C.BOLD}{C.MAGENTA}[*] GŁĘBOKIE SKANOWANIE → {ip_address}{C.RESET}")
    print(f"{C.DIM}    Porty: top-100 | Usługi: TAK | Detekcja OS: TAK{C.RESET}")
    print(f"{C.CYAN}{'='*60}{C.RESET}")

    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip_address, arguments='-F -sV -O -T4 --open')
    except Exception as e:
        print(f"{C.RED}[!] Błąd skanera: {e}{C.RESET}")
        return

    if ip_address not in nm.all_hosts():
        print(f"{C.RED}[-] Host {ip_address} nie odpowiedział — możliwy firewall.{C.RESET}")
        return

    report_lines = [f"=== Deep Scan: {ip_address} | {datetime.datetime.now()} ===\n"]

    os_matches = nm[ip_address].get('osmatch', [])
    if os_matches:
        best    = os_matches[0]
        os_name = best.get('name', 'Nieznany')
        os_acc  = best.get('accuracy', '?')
        print(f"\n{C.BOLD}[OS]{C.RESET} {C.YELLOW}{os_name}{C.RESET} {C.DIM}(pewność: {os_acc}%){C.RESET}")
        report_lines.append(f"[OS] {os_name} (pewność: {os_acc}%)")
    else:
        print(f"\n{C.DIM}[OS] Nie udało się określić systemu operacyjnego.{C.RESET}")
        report_lines.append("[OS] Nieznany")

    for proto in nm[ip_address].all_protocols():
        print(f"\n{C.BOLD}{C.BLUE}--- Protokół: {proto.upper()} ---{C.RESET}")
        report_lines.append(f"\n--- Protokół: {proto.upper()} ---")
        ports = sorted(nm[ip_address][proto].keys())
        if not ports:
            print(f"  {C.DIM}Brak otwartych portów.{C.RESET}")
            continue
        for port in ports:
            data         = nm[ip_address][proto][port]
            state        = data['state']
            name         = data.get('name', '')
            product      = data.get('product', '')
            version      = data.get('version', '')
            extrainfo    = data.get('extrainfo', '')
            service_info = " ".join(filter(None, [name, product, version, extrainfo]))
            color = C.GREEN if state == 'open' else (C.YELLOW if state == 'filtered' else C.RED)
            icon  = '[O]' if state == 'open' else ('[F]' if state == 'filtered' else '[X]')
            print(f"  {color}{C.BOLD}{icon}{C.RESET} Port: {C.BOLD}{port:<6}{C.RESET} Stan: {color}{state:<10}{C.RESET} Usługa: {C.WHITE}{service_info}{C.RESET}")
            report_lines.append(f"  {icon} Port: {port:<6} Stan: {state:<10} Usługa: {service_info}")

    print(f"\n{C.CYAN}{'='*60}{C.RESET}")
    save_report("\n".join(report_lines), ip_address)


# ============================================================
#  IDENTITY SCAN  —  komenda: i <IP>
#  Wektory: mDNS · NetBIOS/SMB · UPnP
# ============================================================

# Porty które otwieramy dla identity scanu:
#   5353/UDP  — mDNS (Multicast DNS, Zeroconf/Bonjour)
#   137/UDP   — NetBIOS Name Service
#   138/UDP   — NetBIOS Datagram
#   139/TCP   — NetBIOS Session / SMB starszy
#   445/TCP   — SMB nowoczesny (Windows, Samba)
#   1900/UDP  — UPnP (SSDP — Simple Service Discovery Protocol)

def _section_header(title: str, color: str = C.CYAN) -> str:
    """Drukuje i zwraca czytelny nagłówek sekcji."""
    line = f"\n{color}{C.BOLD}┌─ {title} {'─' * (50 - len(title))}┐{C.RESET}"
    print(line)
    return _strip_ansi(line)

def _row(label: str, value: str, found: bool = True) -> str:
    """Drukuje i zwraca jeden wiersz danych."""
    if found and value and value != 'Brak danych':
        val_colored = f"{C.WHITE}{C.BOLD}{value}{C.RESET}"
        icon_colored = f"{C.GREEN}✓{C.RESET}"
    else:
        val_colored = f"{C.DIM}Brak danych{C.RESET}"
        icon_colored = f"{C.DIM}·{C.RESET}"
        value = "Brak danych"
    line = f"  {icon_colored} {C.DIM}{label:<22}{C.RESET} {val_colored}"
    print(line)
    return f"  {'OK' if found else ' '} {label:<22} {value}"

def identity_scan(ip_address: str):
    print(f"\n{C.CYAN}{'='*60}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}[*] IDENTITY SCAN → {ip_address}{C.RESET}")
    print(f"{C.DIM}    Wektory: mDNS · NetBIOS · SMB · UPnP{C.RESET}")
    print(f"{C.DIM}    Porty: 137-139/UDP, 445/TCP, 1900/UDP, 5353/UDP{C.RESET}")
    print(f"{C.CYAN}{'='*60}{C.RESET}")

    report_lines = [f"=== Identity Scan: {ip_address} | {datetime.datetime.now()} ===\n"]

    # ── KROK 1: mDNS / Zeroconf / Bonjour ──────────────────
    # Skrypty NSE:
    #   dns-service-discovery  — pyta port 5353 o usługi Bonjour
    #   mdns-service-discovery — szerszy broadcast mDNS (wymaga --script-args)
    # Używamy dns-service-discovery bo działa bez broadcastu (punkt-punkt)

    report_lines.append(_section_header("mDNS / Zeroconf / Bonjour", C.CYAN))

    nm_mdns = nmap.PortScanner()
    mdns_data = {
        'hostname':   'Brak danych',
        'services':   [],
    }
    try:
        nm_mdns.scan(
            hosts=ip_address,
            arguments='-sU -p 5353 --script=dns-service-discovery -T4 --open',
        )
        if ip_address in nm_mdns.all_hosts():
            # Próbujemy wyciągnąć hostname z mDNS
            hostnames = nm_mdns[ip_address].get('hostnames', [])
            for h in hostnames:
                if h.get('name') and h['name'] != ip_address:
                    mdns_data['hostname'] = h['name']
                    break

            # Wyniki skryptów NSE
            try:
                scripts = nm_mdns[ip_address]['udp'][5353].get('script', {})
                for sname, sout in scripts.items():
                    # Parsujemy każdą linię — wyciągamy usługi mDNS
                    for line in sout.strip().splitlines():
                        line = line.strip()
                        if line and not line.startswith('|'):
                            mdns_data['services'].append(line)
            except (KeyError, TypeError):
                pass
    except Exception as e:
        mdns_data['error'] = str(e)

    report_lines.append(_row("Nazwa hosta (.local)", mdns_data['hostname']))
    if mdns_data['services']:
        print(f"  {C.GREEN}✓{C.RESET} {C.DIM}{'Usługi mDNS':<22}{C.RESET}", end='')
        print()
        for svc in mdns_data['services'][:10]:   # max 10 linii
            print(f"      {C.WHITE}{svc}{C.RESET}")
            report_lines.append(f"      {svc}")
    else:
        report_lines.append(_row("Usługi mDNS", "Brak danych"))


    # ── KROK 2: NetBIOS ─────────────────────────────────────
    # Skrypty NSE:
    #   nbstat  — pyta port 137/UDP o tablicę nazw NetBIOS:
    #             zwraca nazwę komputera, grupę roboczą, MAC
    report_lines.append(_section_header("NetBIOS (UDP/137)", C.YELLOW))

    nm_nb = nmap.PortScanner()
    netbios_data = {
        'computer_name': 'Brak danych',
        'workgroup':     'Brak danych',
        'mac':           'Brak danych',
        'raw':           [],
    }
    try:
        nm_nb.scan(
            hosts=ip_address,
            arguments='-sU -p 137 --script=nbstat -T4',
        )
        if ip_address in nm_nb.all_hosts():
            try:
                scripts = nm_nb[ip_address]['udp'][137].get('script', {})
                for sname, sout in scripts.items():
                    for line in sout.strip().splitlines():
                        line = line.strip().lstrip('|_ ')
                        if not line:
                            continue
                        netbios_data['raw'].append(line)
                        # Parsowanie nazwy komputera (NetBIOS name + typ <00>)
                        m = re.match(r'^(.+?)\s+<00>\s+\S+\s+<unique>', line, re.IGNORECASE)
                        if m and netbios_data['computer_name'] == 'Brak danych':
                            netbios_data['computer_name'] = m.group(1).strip()
                        # Parsowanie grupy roboczej / domeny (typ <00> + group)
                        m2 = re.match(r'^(.+?)\s+<00>\s+\S+\s+<group>', line, re.IGNORECASE)
                        if m2 and netbios_data['workgroup'] == 'Brak danych':
                            netbios_data['workgroup'] = m2.group(1).strip()
                        # MAC
                        m3 = re.search(r'MAC Address = ([\dA-Fa-f:]{17})', line)
                        if m3:
                            netbios_data['mac'] = m3.group(1)
            except (KeyError, TypeError):
                pass
    except Exception as e:
        netbios_data['error'] = str(e)

    report_lines.append(_row("Nazwa komputera",  netbios_data['computer_name']))
    report_lines.append(_row("Workgroup / Domena", netbios_data['workgroup']))
    report_lines.append(_row("MAC (NetBIOS)",    netbios_data['mac']))
    if netbios_data['raw']:
        print(f"  {C.DIM}  Surowe dane NetBIOS:{C.RESET}")
        for r in netbios_data['raw'][:8]:
            print(f"      {C.DIM}{r}{C.RESET}")
            report_lines.append(f"      {r}")


    # ── KROK 3: SMB (porty 139 + 445 TCP) ───────────────────
    # Skrypty NSE:
    #   smb-os-discovery   — OS, nazwa, domena, czas serwera
    #   smb-enum-shares    — lista udostępnionych folderów (null session)
    report_lines.append(_section_header("SMB (TCP/139 + 445)", C.MAGENTA))

    nm_smb = nmap.PortScanner()
    smb_data = {
        'os':      'Brak danych',
        'name':    'Brak danych',
        'domain':  'Brak danych',
        'shares':  [],
        'raw_os':  [],
        'raw_sh':  [],
    }
    try:
        nm_smb.scan(
            hosts=ip_address,
            arguments='-p 139,445 --script=smb-os-discovery,smb-enum-shares -T4',
        )
        if ip_address in nm_smb.all_hosts():
            for proto in ['tcp']:
                for port in [139, 445]:
                    try:
                        scripts = nm_smb[ip_address][proto][port].get('script', {})
                    except (KeyError, TypeError):
                        continue

                    # smb-os-discovery
                    if 'smb-os-discovery' in scripts:
                        out = scripts['smb-os-discovery']
                        for line in out.strip().splitlines():
                            line = line.strip().lstrip('|_ ')
                            if not line:
                                continue
                            smb_data['raw_os'].append(line)
                            if 'OS:' in line and smb_data['os'] == 'Brak danych':
                                smb_data['os'] = line.split('OS:', 1)[1].strip()
                            if ('Computer name:' in line or 'NetBIOS computer name:' in line) \
                               and smb_data['name'] == 'Brak danych':
                                smb_data['name'] = line.split(':', 1)[1].strip()
                            if ('Domain name:' in line or 'Workgroup:' in line) \
                               and smb_data['domain'] == 'Brak danych':
                                smb_data['domain'] = line.split(':', 1)[1].strip()

                    # smb-enum-shares
                    if 'smb-enum-shares' in scripts:
                        out = scripts['smb-enum-shares']
                        current_share = None
                        for line in out.strip().splitlines():
                            line = line.strip().lstrip('|_ ')
                            if not line:
                                continue
                            smb_data['raw_sh'].append(line)
                            # Nazwa share'a — linia zaczynająca się od \\
                            if line.startswith('\\\\'):
                                current_share = line
                                smb_data['shares'].append({'name': current_share, 'details': []})
                            elif current_share and smb_data['shares']:
                                smb_data['shares'][-1]['details'].append(line)
    except Exception as e:
        smb_data['error'] = str(e)

    report_lines.append(_row("System operacyjny",   smb_data['os']))
    report_lines.append(_row("Nazwa komputera SMB", smb_data['name']))
    report_lines.append(_row("Domena / Workgroup",  smb_data['domain']))

    if smb_data['shares']:
        print(f"\n  {C.MAGENTA}{C.BOLD}  Udostępnione foldery ({len(smb_data['shares'])}):{C.RESET}")
        report_lines.append(f"\n    Udostępnione foldery ({len(smb_data['shares'])}):")
        for sh in smb_data['shares']:
            print(f"    {C.WHITE}{C.BOLD}{sh['name']}{C.RESET}")
            report_lines.append(f"    {sh['name']}")
            for det in sh['details'][:4]:
                print(f"      {C.DIM}{det}{C.RESET}")
                report_lines.append(f"      {det}")
    else:
        report_lines.append(_row("Udostępnione foldery", "Brak danych"))


    # ── KROK 4: UPnP / SSDP (port 1900 UDP) ─────────────────
    # Skrypt NSE:
    #   upnp-info  — pobiera XML z urządzenia i parsuje:
    #                modelName, manufacturer, friendlyName, deviceType
    report_lines.append(_section_header("UPnP / SSDP (UDP/1900)", C.GREEN))

    nm_upnp = nmap.PortScanner()
    upnp_data = {
        'friendly_name': 'Brak danych',
        'manufacturer':  'Brak danych',
        'model':         'Brak danych',
        'device_type':   'Brak danych',
        'url':           'Brak danych',
        'raw':           [],
    }
    try:
        nm_upnp.scan(
            hosts=ip_address,
            arguments='-sU -p 1900 --script=upnp-info -T4',
        )
        if ip_address in nm_upnp.all_hosts():
            try:
                scripts = nm_upnp[ip_address]['udp'][1900].get('script', {})
                for sname, sout in scripts.items():
                    for line in sout.strip().splitlines():
                        line = line.strip().lstrip('|_ ')
                        if not line:
                            continue
                        upnp_data['raw'].append(line)
                        # Parsowanie pól z XML odpowiedzi UPnP
                        low = line.lower()
                        if 'friendly name:' in low or 'friendlyname:' in low:
                            upnp_data['friendly_name'] = line.split(':', 1)[1].strip()
                        elif 'manufacturer:' in low:
                            upnp_data['manufacturer']  = line.split(':', 1)[1].strip()
                        elif 'model name:' in low or 'modelname:' in low:
                            upnp_data['model']         = line.split(':', 1)[1].strip()
                        elif 'device type:' in low or 'devicetype:' in low:
                            upnp_data['device_type']   = line.split(':', 1)[1].strip()
                        elif line.startswith('http://') or line.startswith('https://'):
                            upnp_data['url']           = line
            except (KeyError, TypeError):
                pass
    except Exception as e:
        upnp_data['error'] = str(e)

    report_lines.append(_row("Nazwa przyjazna",  upnp_data['friendly_name']))
    report_lines.append(_row("Producent",        upnp_data['manufacturer']))
    report_lines.append(_row("Model",            upnp_data['model']))
    report_lines.append(_row("Typ urządzenia",   upnp_data['device_type']))
    report_lines.append(_row("URL konfiguracji", upnp_data['url']))
    if upnp_data['raw']:
        print(f"\n  {C.DIM}  Pełna odpowiedź UPnP:{C.RESET}")
        for r in upnp_data['raw'][:12]:
            print(f"      {C.DIM}{r}{C.RESET}")
            report_lines.append(f"      {r}")

    # ── PODSUMOWANIE ─────────────────────────────────────────
    print(f"\n{C.CYAN}{'='*60}{C.RESET}")
    print(f"{C.BOLD}  KARTA URZĄDZENIA: {C.WHITE}{ip_address}{C.RESET}")
    print(f"{C.CYAN}{'─'*60}{C.RESET}")

    summary_fields = [
        ("Hostname (mDNS)",   mdns_data['hostname']),
        ("Nazwa (NetBIOS)",   netbios_data['computer_name']),
        ("Workgroup",         netbios_data['workgroup']),
        ("OS (SMB)",          smb_data['os']),
        ("Domena (SMB)",      smb_data['domain']),
        ("Model (UPnP)",      upnp_data['model']),
        ("Producent (UPnP)",  upnp_data['manufacturer']),
        ("URL konfig.",       upnp_data['url']),
    ]
    report_lines.append(f"\n=== KARTA URZĄDZENIA: {ip_address} ===")
    for label, value in summary_fields:
        found = value != 'Brak danych'
        if found:
            print(f"  {C.GREEN}●{C.RESET}  {C.DIM}{label:<22}{C.RESET} {C.WHITE}{C.BOLD}{value}{C.RESET}")
        else:
            print(f"  {C.DIM}○  {label:<22} Brak danych{C.RESET}")
        report_lines.append(f"  {'●' if found else '○'}  {label:<22} {value}")

    print(f"{C.CYAN}{'='*60}{C.RESET}")
    save_report("\n".join(report_lines), f"identity_{ip_address}")


# ============================================================
#  SNMP SCAN  —  komenda: snmp <IP>
#  Port: 161/UDP
#  Community strings: public, private, community (domyślne)
#  Skrypty NSE:
#    snmp-sysdescr  — opis systemu (OS, wersja firmware)
#    snmp-info      — sysName, sysLocation, sysContact, uptime
#    snmp-interfaces — lista interfejsów sieciowych
#    snmp-processes  — uruchomione procesy (jeśli dostępne)
# ============================================================
SNMP_COMMUNITY_STRINGS = ['public', 'private', 'community', 'admin', 'manager']

def snmp_scan(ip_address: str):
    print(f"\n{C.CYAN}{'='*60}{C.RESET}")
    print(f"{C.BOLD}{C.BLUE}[*] SNMP SCAN → {ip_address}{C.RESET}")
    print(f"{C.DIM}    Port: 161/UDP | Community strings: {SNMP_COMMUNITY_STRINGS}")
    print(f"    Uwaga: UDP może być wolniejszy od TCP!{C.RESET}")
    print(f"{C.CYAN}{'='*60}{C.RESET}")

    report_lines = [f"=== SNMP Scan: {ip_address} | {datetime.datetime.now()} ===\n"]
    any_data_found = False

    for community in SNMP_COMMUNITY_STRINGS:
        print(f"\n{C.DIM}[*] Próbuję community string: '{community}'...{C.RESET}", end=' ', flush=True)

        nm = nmap.PortScanner()
        try:
            nm.scan(
                hosts=ip_address,
                arguments=(
                    f'-sU -p 161 '
                    f'--script=snmp-sysdescr,snmp-info,snmp-interfaces,snmp-processes '
                    f'--script-args=snmpcommunity={community} '
                    f'-T4 --open'
                ),
            )
        except Exception as e:
            print(f"{C.RED}Błąd: {e}{C.RESET}")
            continue

        if ip_address not in nm.all_hosts():
            print(f"{C.RED}Brak odpowiedzi{C.RESET}")
            continue

        try:
            port_data = nm[ip_address]['udp'][161]
        except (KeyError, TypeError):
            print(f"{C.RED}Port 161 zamknięty/filtrowany{C.RESET}")
            continue

        scripts = port_data.get('script', {})
        if not scripts:
            print(f"{C.YELLOW}Port otwarty, brak danych SNMP{C.RESET}")
            continue

        print(f"{C.GREEN}TRAFIENIE! community='{community}'{C.RESET}")
        any_data_found = True
        report_lines.append(f"\n--- Community string: '{community}' ---")

        # ── snmp-sysdescr ──
        if 'snmp-sysdescr' in scripts:
            report_lines.append(_section_header("System Description", C.BLUE))
            val = scripts['snmp-sysdescr'].strip()
            print(f"  {C.WHITE}{val}{C.RESET}")
            report_lines.append(f"  {val}")

        # ── snmp-info ──
        if 'snmp-info' in scripts:
            report_lines.append(_section_header("SNMP Info", C.CYAN))
            snmp_fields = {
                'sysName':     'Brak danych',
                'sysLocation': 'Brak danych',
                'sysContact':  'Brak danych',
                'sysUpTime':   'Brak danych',
                'sysDescr':    'Brak danych',
            }
            for line in scripts['snmp-info'].strip().splitlines():
                line = line.strip().lstrip('|_ ')
                if not line:
                    continue
                for field in snmp_fields:
                    if field + ':' in line or field.lower() in line.lower():
                        snmp_fields[field] = line.split(':', 1)[1].strip() if ':' in line else line

            report_lines.append(_row("Nazwa systemu",   snmp_fields['sysName']))
            report_lines.append(_row("Lokalizacja",     snmp_fields['sysLocation']))
            report_lines.append(_row("Kontakt (admin)", snmp_fields['sysContact']))
            report_lines.append(_row("Uptime",          snmp_fields['sysUpTime']))

        # ── snmp-interfaces ──
        if 'snmp-interfaces' in scripts:
            report_lines.append(_section_header("Interfejsy sieciowe", C.GREEN))
            iface_lines = [
                l.strip().lstrip('|_ ')
                for l in scripts['snmp-interfaces'].strip().splitlines()
                if l.strip().lstrip('|_ ')
            ]
            # Grupujemy po 3 linie (nazwa, IP, MAC)
            for idx, iline in enumerate(iface_lines[:18]):
                icon = f"{C.GREEN}✓{C.RESET}" if 'up' in iline.lower() else f"{C.DIM}·{C.RESET}"
                print(f"  {icon} {C.WHITE}{iline}{C.RESET}")
                report_lines.append(f"  {iline}")

        # ── snmp-processes ──
        if 'snmp-processes' in scripts:
            report_lines.append(_section_header("Uruchomione procesy (fragment)", C.YELLOW))
            proc_lines = [
                l.strip().lstrip('|_ ')
                for l in scripts['snmp-processes'].strip().splitlines()
                if l.strip().lstrip('|_ ')
            ]
            for pline in proc_lines[:20]:   # max 20 procesów
                print(f"  {C.DIM}{pline}{C.RESET}")
                report_lines.append(f"  {pline}")
            if len(proc_lines) > 20:
                more = len(proc_lines) - 20
                print(f"  {C.DIM}... i {more} więcej (patrz raport){C.RESET}")
                for pline in proc_lines[20:]:
                    report_lines.append(f"  {pline}")

        # Jeśli mamy dane — nie próbujemy kolejnych community strings
        break

    if not any_data_found:
        print(f"\n{C.YELLOW}[-] Brak odpowiedzi SNMP na żadnym ze znanych community strings.")
        print(f"    Urządzenie może nie obsługiwać SNMP lub używać niestandardowego hasła.{C.RESET}")
        report_lines.append("\n[-] Brak odpowiedzi SNMP.")

    print(f"\n{C.CYAN}{'='*60}{C.RESET}")
    save_report("\n".join(report_lines), f"snmp_{ip_address}")


# ============================================================
#  VULN-SCAN (NSE)  —  komenda: v <IP>
# ============================================================
NSE_SCRIPTS = "vuln,http-vuln-cve2017-5638,ssl-heartbleed,ssl-poodle,smb-vuln-ms17-010"

def vuln_scan(ip_address: str):
    print(f"\n{C.CYAN}{'='*60}{C.RESET}")
    print(f"{C.BOLD}{C.RED}[*] VULN-SCAN (NSE) → {ip_address}{C.RESET}")
    print(f"{C.DIM}    Silnik: NSE | Skrypty: vuln, ssl, smb, http-cve")
    print(f"    Uwaga: ten skan może potrwać 2-5 minut!{C.RESET}")
    print(f"{C.CYAN}{'='*60}{C.RESET}")

    nm = nmap.PortScanner()
    try:
        nm.scan(
            hosts=ip_address,
            arguments=f'-sV -T4 --script={NSE_SCRIPTS} --script-timeout 30s'
        )
    except Exception as e:
        print(f"{C.RED}[!] Błąd skanera: {e}{C.RESET}")
        return

    if ip_address not in nm.all_hosts():
        print(f"{C.RED}[-] Host nie odpowiedział.{C.RESET}")
        return

    report_lines = [f"=== Vuln-Scan: {ip_address} | {datetime.datetime.now()} ===\n"]
    found_vulns  = 0

    for proto in nm[ip_address].all_protocols():
        for port in sorted(nm[ip_address][proto].keys()):
            data   = nm[ip_address][proto][port]
            name   = data.get('name', '')
            state  = data['state']
            script = data.get('script', {})
            if not script:
                continue
            port_header = f"\n  Port {port}/{proto} ({name}) [{state}]"
            print(f"{C.BOLD}{C.BLUE}{port_header}{C.RESET}")
            report_lines.append(port_header)
            for script_name, output in script.items():
                if 'VULNERABLE' in output.upper():
                    color = C.RED
                    icon  = '⚠  PODATNOŚĆ'
                    found_vulns += 1
                elif 'ERROR' in output.upper() or 'FAILED' in output.upper():
                    color = C.DIM
                    icon  = '~  INFO'
                else:
                    color = C.GREEN
                    icon  = 'OK'
                print(f"\n    {color}{C.BOLD}[{icon}]{C.RESET} {C.YELLOW}{script_name}{C.RESET}")
                report_lines.append(f"\n    [{icon}] {script_name}")
                for line in output.strip().splitlines():
                    print(f"      {color}{line}{C.RESET}")
                    report_lines.append(f"      {line}")

    if found_vulns == 0:
        print(f"\n{C.GREEN}[OK] Brak wykrytych podatności dla użytych skryptów NSE.{C.RESET}")
        report_lines.append("\n[OK] Brak wykrytych podatności.")
    else:
        print(f"\n{C.RED}{C.BOLD}[!] Wykryto {found_vulns} potencjalnych podatności!{C.RESET}")
        report_lines.append(f"\n[!] Wykryto {found_vulns} potencjalnych podatności!")

    print(f"{C.CYAN}{'='*60}{C.RESET}")
    save_report("\n".join(report_lines), f"vuln_{ip_address}")


# ============================================================
#  BANNER GRABBER HTTP/HTTPS  —  komenda: b <IP>
# ============================================================
HTTP_PORTS  = [80, 8080, 8008, 8888, 3000, 5000, 9090]
HTTPS_PORTS = [443, 8443, 4443, 9443]

def _fetch_http(url: str, timeout: int = 6) -> dict:
    result = {'url': url, 'status': None, 'server': 'Nieznany',
              'title': 'Brak tytułu', 'raw_html': '', 'error': None}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    try:
        req = urllib.request.Request(
            url, headers={'User-Agent': 'Mozilla/5.0 (MR.ROOT NetHunter Scanner)'}
        )
        kw = {'timeout': timeout}
        if url.startswith('https'):
            kw['context'] = ctx
        with urllib.request.urlopen(req, **kw) as resp:
            result['status'] = resp.status
            result['server'] = resp.headers.get('Server', 'Nieznany')
            raw = resp.read(32768)
            enc = resp.headers.get_content_charset('utf-8') or 'utf-8'
            result['raw_html'] = raw.decode(enc, errors='replace')
            m = re.search(r'<title[^>]*>(.*?)</title>', result['raw_html'], re.IGNORECASE | re.DOTALL)
            if m:
                result['title'] = re.sub(r'\s+', ' ', m.group(1)).strip()
    except urllib.error.HTTPError as e:
        result['status'] = e.code
        result['error']  = str(e)
    except Exception as e:
        result['error'] = str(e)
    return result

def _build_html_report(ip: str, findings: list) -> str:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cards = ""
    for f in findings:
        sc = "#2ecc71" if f['status'] and f['status'] < 400 else "#e74c3c"
        sb = f['status'] or "Brak"
        er = f'<tr><td>Błąd</td><td style="color:#e74c3c">{f["error"]}</td></tr>' if f['error'] else ''
        eh = f['raw_html'].replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')[:8000]
        cards += f"""
        <div class="card">
          <div class="card-header">
            <span class="url">{f['url']}</span>
            <span class="badge" style="background:{sc}">HTTP {sb}</span>
          </div>
          <table>
            <tr><td>Tytuł strony</td><td><strong>{f['title']}</strong></td></tr>
            <tr><td>Serwer</td><td>{f['server']}</td></tr>
            {er}
          </table>
          <details>
            <summary>Podgląd HTML (pierwsze 8 000 znaków)</summary>
            <pre class="html-dump">{eh}</pre>
          </details>
        </div>"""
    return f"""<!DOCTYPE html>
<html lang="pl"><head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Banner Grabber — {ip} | MR.ROOT</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:#0d1117;color:#c9d1d9;font-family:'Courier New',monospace;padding:20px}}
    header{{border-bottom:2px solid #30363d;padding-bottom:12px;margin-bottom:20px}}
    header h1{{color:#58a6ff;font-size:1.4em}} header p{{color:#8b949e;font-size:.85em;margin-top:4px}}
    .card{{background:#161b22;border:1px solid #30363d;border-radius:8px;margin-bottom:20px;overflow:hidden}}
    .card-header{{background:#21262d;padding:10px 16px;display:flex;justify-content:space-between;align-items:center}}
    .url{{color:#58a6ff;font-weight:bold;word-break:break-all}}
    .badge{{border-radius:12px;padding:3px 10px;font-size:.8em;font-weight:bold;color:#fff;white-space:nowrap;margin-left:10px}}
    table{{width:100%;border-collapse:collapse;padding:10px}} td{{padding:8px 16px;border-bottom:1px solid #21262d;font-size:.9em}}
    td:first-child{{color:#8b949e;width:140px}} details{{padding:10px 16px 0}}
    summary{{cursor:pointer;color:#8b949e;font-size:.85em;padding:8px 0;user-select:none}}
    summary:hover{{color:#58a6ff}}
    .html-dump{{background:#0d1117;color:#7ee787;padding:12px;border-radius:6px;margin:8px 0 10px;
                font-size:.78em;overflow-x:auto;white-space:pre-wrap;max-height:400px;overflow-y:auto}}
    footer{{margin-top:30px;color:#30363d;font-size:.8em;text-align:center}}
  </style>
</head><body>
  <header><h1>Banner Grabber — {ip}</h1><p>Wygenerowano: {now} | MR.ROOT NetHunter Scanner</p></header>
  {cards if cards else '<p style="color:#8b949e;padding:20px">Brak odpowiedzi HTTP/HTTPS.</p>'}
  <footer>MR.ROOT | NetHunter Edition</footer>
</body></html>"""

def banner_grab(ip_address: str):
    print(f"\n{C.CYAN}{'='*60}{C.RESET}")
    print(f"{C.BOLD}{C.MAGENTA}[*] BANNER GRABBER → {ip_address}{C.RESET}")
    print(f"{C.DIM}    HTTP:  {HTTP_PORTS}\n    HTTPS: {HTTPS_PORTS}{C.RESET}")
    print(f"{C.CYAN}{'='*60}{C.RESET}\n")
    findings = []
    def probe(url):
        print(f"  {C.DIM}→ {url}{C.RESET}", end=' ', flush=True)
        r = _fetch_http(url)
        if r['error'] and r['status'] is None:
            print(f"{C.RED}brak odpowiedzi{C.RESET}")
            return
        findings.append(r)
        color = C.GREEN if r['status'] and r['status'] < 400 else C.YELLOW
        print(f"{color}HTTP {r['status']}{C.RESET}")
        print(f"    {C.WHITE}Tytuł:  {C.BOLD}{r['title']}{C.RESET}")
        print(f"    {C.WHITE}Serwer: {r['server']}{C.RESET}")
        if r['raw_html']:
            prev = r['raw_html'][:120].replace('\n',' ').strip()
            print(f"    {C.DIM}HTML:   {prev}...{C.RESET}")
        print()
    for p in HTTP_PORTS:  probe(f"http://{ip_address}:{p}/")
    for p in HTTPS_PORTS: probe(f"https://{ip_address}:{p}/")
    if not findings:
        print(f"{C.YELLOW}[-] Brak odpowiedzi HTTP/HTTPS na żadnym porcie.{C.RESET}")
        return
    html_content = _build_html_report(ip_address, findings)
    save_report(html_content, f"banner_{ip_address}", subdir=REPORT_DIR_HTML, ext="html")
    print(f"{C.CYAN}{'='*60}{C.RESET}")
    print(f"{C.GREEN}[OK] {len(findings)} aktywnych endpointów. Raport: {REPORT_DIR_HTML}/{C.RESET}")


# ============================================================
#  GŁÓWNA PĘTLA
# ============================================================
if __name__ == "__main__":
    print(BANNER)
    init_report_dirs()

    my_ip, target_subnet, iface = get_network_info()
    print(f"{C.GREEN}[*] Wykryto interfejs: {C.BOLD}{iface}{C.RESET}")
    print(f"{C.GREEN}[*] Twoje IP:          {C.BOLD}{my_ip}{C.RESET}")
    print(f"{C.GREEN}[*] Docelowa podsieć:  {C.BOLD}{target_subnet}{C.RESET}")

    scan_network(target_subnet)
    print(HELP_TEXT)

    while True:
        try:
            raw = input(f"{C.YELLOW}{C.BOLD}[>] Komenda: {C.RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{C.DIM}[*] Przerwano. Do zobaczenia, MR.ROOT!{C.RESET}")
            break

        if not raw or raw.lower() in ('q', 'quit', 'exit'):
            print(f"{C.DIM}[*] Zamykanie programu. Udanych łowów!{C.RESET}")
            break

        if raw.lower() == 'h':
            print(HELP_TEXT)
            continue

        # IDENTITY SCAN: i <IP>
        if raw.lower().startswith('i '):
            ip_part = raw[2:].strip()
            if validate_ip(ip_part):
                identity_scan(ip_part)
            else:
                print(f"{C.RED}[!] Niepoprawny adres IP: '{ip_part}'{C.RESET}")
            continue

        # SNMP SCAN: snmp <IP>
        if raw.lower().startswith('snmp '):
            ip_part = raw[5:].strip()
            if validate_ip(ip_part):
                snmp_scan(ip_part)
            else:
                print(f"{C.RED}[!] Niepoprawny adres IP: '{ip_part}'{C.RESET}")
            continue

        # VULN-SCAN: v <IP>
        if raw.lower().startswith('v '):
            ip_part = raw[2:].strip()
            if validate_ip(ip_part):
                vuln_scan(ip_part)
            else:
                print(f"{C.RED}[!] Niepoprawny adres IP: '{ip_part}'{C.RESET}")
            continue

        # BANNER GRABBER: b <IP>
        if raw.lower().startswith('b '):
            ip_part = raw[2:].strip()
            if validate_ip(ip_part):
                banner_grab(ip_part)
            else:
                print(f"{C.RED}[!] Niepoprawny adres IP: '{ip_part}'{C.RESET}")
            continue

        # DEEP SCAN: <IP> lub <IP,IP,...>
        targets = parse_ip_list(raw)
        if not targets:
            print(f"{C.RED}[!] Nieznana komenda. Wpisz 'h' po pomoc.{C.RESET}")
            continue
        print(f"{C.BLUE}[*] Kolejka skanowania: {C.BOLD}{', '.join(targets)}{C.RESET}")
        for ip in targets:
            deep_scan(ip)
