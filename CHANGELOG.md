# Changelog — MR.ROOT Scanner

All notable changes to this project are documented in this file.  
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [v3.9] — 2026 (current)

### Added
- **`sniff_scan` — Passive Packet Sniffer module**
  - Passive network capture using `scapy` + `tshark`
  - Live pcap analysis with protocol breakdown
  - Auto-save to `/MR.ROOT/reports/` in `.pcap` format
  - Compatible with Wireshark for post-capture analysis

### Changed
- Updated `requirements.txt` — added `scapy` dependency

---

## [v3.8] — 2026

### Added
- **ADB Pentest Module** — full USB-based Android audit
  - `adb` — Device Info (getprop) + Debug Surface Analysis + APK Enumeration
  - `adb-frida <pkg>` — Frida SSL Unpinning (OkHttp3 + TrustManager + Conscrypt + NSC)
  - `adb-dump [sec]` — tcpdump traffic capture via ADB → .pcap
- Frida version pinning to `17.7.1` ARM64
- Tested: Samsung Galaxy Tab A9 (SM-X110) — WeChat + Facebook SDK

---

## [v3.7] — 2026

### Added
- `--resume` flag for SQLMap (resumes previous session via `--no-flush-session`)
- Per-IP rate limiting — cooldown of one target no longer blocks others
- `NamedTemporaryFile` in Mobile Fuzzer

---

## [v3.6] — 2025

### Added
- **Stealth / WAF-Bypass** module
  - Smart Delay + Jitter (0.3–1.8s random intervals)
  - Advanced header rotation (`_smart_headers()`) — Client Hints, X-Forwarded-For
  - HTTP Parameter Pollution via `_hpp_url()` and `_send_chunked()`
  - Rate Limiting detection + per-IP cooldown state machine (default 300s)
- **`hw <URL>`** — Headless browser scan via Playwright/Chromium
- **`hpp <URL>`** — HTTP Parameter Pollution test

---

## [v3.5] — 2025

### Added
- **`sql <URL>`** — SQLMap Auto-Tamper WAF-Bypass (6 tamper chain rotation)
- **`auto-sql <URL>`** — Auto-Spider + deduplicated mass SQLi attack

---

## [v3.4] — 2025

### Added
- **`m <IP>`** — Mobile Scan (port-based device type deduction)
- **`mf <IP>`** — Mobile Fuzzer (Android/iOS path dictionary)
- `📱/💻` visual markers in ping sweep
- `all-net` — mass audit with per-host skip support

---

## [v3.3] — 2025

### Fixed
- NetHunter chroot routing — 3 fallback mechanisms for network interface detection

---

## [v3.2] — 2025

### Added
- SearchSploit (Exploit-DB) integration
- HTTP header security analyzer (HSTS, CSP, info-leak detection)

---

## [v3.1] — 2025

### Added
- Full Scan mode (`all` / `-m all`) — all modules sequentially
- Final JSON report aggregation with scan statistics

---

## [v3.0] — 2025

### Initial public release
- Interactive mode + CLI (`-t`, `-m`)
- Deep port scan (nmap + NSE), OS detection
- CIDR/IPv6 sweep, mDNS/NetBIOS/SMB/UPnP identity scan
- SNMP scan, banner grabber, smart path fuzzer (124 vectors)
