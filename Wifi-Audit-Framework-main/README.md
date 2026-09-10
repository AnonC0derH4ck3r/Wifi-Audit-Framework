# WiFiToolKit — 802.11 Wireless Audit Framework

```
 ██╗    ██╗██╗███████╗██╗    ████████╗ ██████╗  ██████╗ ██╗      ██╗  ██╗██╗████████╗
 ██║    ██║██║██╔════╝██║    ╚══██╔══╝██╔═══██╗██╔═══██╗██║      ██║ ██╔╝██║╚══██╔══╝
 ██║ █╗ ██║██║█████╗  ██║       ██║   ██║   ██║██║   ██║██║      █████╔╝ ██║   ██║   
 ██║███╗██║██║██╔══╝  ██║       ██║   ██║   ██║██║   ██║██║      ██╔═██╗ ██║   ██║   
 ╚███╔███╔╝██║██║     ██║       ██║   ╚██████╔╝╚██████╔╝███████╗ ██║  ██╗██║   ██║   
  ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝ ╚═╝  ╚═╝╚═╝   ╚═╝  
                     [ 802.11 Wireless Audit Framework ]
```

> **Author:** Huzefa Khalil Dayanji — Security Consultant
> **Purpose:** Modular OOP framework for automated 802.11 wireless auditing, interface management, and vulnerability assessment.

---

## ⚠️ Legal Disclaimer

This tool is intended **strictly for authorised penetration testing and security research**. Only use it against networks and devices you own or have explicit written permission to test. Unauthorised use is illegal and unethical. The author assumes no liability for misuse.

---

## Features

- **Access Point Discovery** — Passive beacon frame sniffing with live table output. Extracts BSSID, SSID, channel, **RSSI (dBm)** signal strength, encryption, PMF (MFPC/MFPR), WPS status, DTIM period, group cipher, AKM suite, WPA1 downgrade detection, beacon interval, RRM (802.11k), BSS Transition (802.11v), and TSF uptime. RSSI is colour-coded: 🟢 ≥-50 dBm (excellent/close), 🟡 -70 to -50 dBm (good), 🔴 <-70 dBm (weak/far), and live-updates on re-seen beacons.
- **Connected Client Enumeration** — Identifies associated clients by inspecting data frames, EAPOL (4-way handshake), association responses, deauth, and disassoc frames. Tracks live Connected / Disconnected status per client.
- **Hidden SSID Decloaking (NEW)** — Passive Assoc-Req listener that captures Association Request frames from clients connecting to hidden-SSID networks. Selects a target from discovered APs (option 1) or manual BSSID entry, then displays a live table of decloaked SSIDs, client MACs, vendors, timestamps, and deauth frames — revealing networks that never broadcast their name.
- **Vulnerability Assessment** — Sends directed Probe Requests to a target AP and parses the Probe Response for a deep security profile: PMF state, group cipher, AKM suite, WPA1 downgrade risk, RRM/BSS-Transition support, and full WPS TLV breakdown (version, state, method, UUID-E, device info, setup-lock status).
- **Rogue Access Point — Evil Twin with Selectable Captive Portal (NEW)** — Mirrors `wpf_complete.py` Evil Twin (Phase 3c) verbatim `hostapd`/`dnsmasq`/`iptables`/`mitmproxy`/`Flask` logic. Lets operator choose phishing template (`google` / `microsoft` / `instagram`) from `captive-portal-pages/<name>/index.html`. Includes persistent-internet fixes: `nmcli managed no`, `keepalive` re-assert, captive-probe `204` handling, `bcrypt` patch, and post-login internet guarantee. See [Evil Twin Details](#evil-twin--rogue-ap-details) below.
- **PNL Extractor** — Passively captures directed Probe Requests from nearby devices to reconstruct their Preferred Network List (PNL) — the set of SSIDs a device has previously joined and will auto-associate with.
- **OUI Vendor Lookup** — Resolves AP and client MAC prefixes to vendor names using the IEEE OUI database.
- **Channel Hopper** — Threaded channel hopper supporting 2.4 GHz, 5 GHz, or interleaved dual-band sweeps.
- **Auto Dependency Installer** — Detects and installs missing Python dependencies via APT automatically.
- **Monitor Mode Management** — Switches interface to/from monitor mode via NL80211 (Netlink), with `airmon-ng` as a secondary enforcement fallback for quirky drivers.
- **Clean Shutdown** — Restores NetworkManager, wpa_supplicant, and the interface to managed mode on exit.

---

## Project Structure

```
wifi_toolkit/
├── main.py               # Entry point — arg parsing, interface setup, sniff dispatch (option 5 Evil Twin, option 7 Decloak)
├── config.py             # Constants: channel maps, interface type names, banner
├── ui.py                 # Terminal UI: colours, logging helpers, menu (options 0-7)
├── dependencies.py       # Auto-installer for scapy, pyroute2, tabulate
├── interface_manager.py  # NL80211 interface control: mode, channel, state
├── audit_engine.py       # Core engine: packet parsing, client tracking, live tables, decloak listener
├── evil_twin.py          # Rogue AP module (hostapd/dnsmasq/iptables/mitmproxy/Flask + portal loader + keepalive)
├── captive-portal-pages/ # Selectable phishing templates
│   ├── google/index.html     # Google Sign-in clone (self-contained, {ssid} placeholder)
│   ├── microsoft/index.html  # Microsoft / Azure AD clone (from wpf_complete PORTAL_HTML)
│   └── instagram/index.html  # Instagram Login clone
├── wpf_complete.py       # Standalone full framework (reference for Evil Twin logic)
└── wpf_results.db        # SQLite results (APs, clients, handshakes, credentials, http_traffic)
```

---

## Requirements

- **OS:** Linux (tested on Kali / Ubuntu)
- **Python:** 3.8+
- **Privileges:** Must be run as `root`
- **Hardware:** Wireless adapter with monitor mode support + second adapter recommended for Active Evil Twin; `hostapd`, `dnsmasq`, `iptables`, `iproute2` required for Rogue AP
- **System deps for Evil Twin:** `hostapd`, `dnsmasq`, `iptables`, `iw`, `ip`, `sysctl`, `mitmdump` (mitmproxy), `NetworkManager` (`nmcli`)

### Python Dependencies

Auto-installed if missing:

| Package | Purpose |
|---|---|
| `scapy` | Packet capture and parsing |
| `pyroute2` | NL80211 / Netlink interface control |
| `tabulate` | Live table rendering |
| `flask` | **NEW** — Captive portal web server (required for option 5) |
| `mitmproxy` | **NEW** — Transparent HTTP/S sniffer (`mitmdump`) for Evil Twin (optional but recommended) |

### Optional

| Package | Purpose |
|---|---|
| `rich` | Enhanced terminal UI (gracefully degrades if absent) |
| `aircrack-ng` | Secondary monitor mode enforcement via `airmon-ng` |
| `reaver` (`wash`/`reaver`) | **NEW** — WPS survey + Pixie-Dust/online PIN attacks (option 8): `sudo apt install reaver` |
| `pixiewps` | **NEW** — Optional Pixie-Dust accelerator for option 8: `sudo apt install pixiewps` |
| `dsniff` (`arpspoof`) / `bettercap` | **NEW** — ARP-spoof backend for option 9 (`bettercap` preferred if present) |
| `tcpdump` | **NEW** — Optional pcap capture for option 9 |

---

## Installation

```bash
git clone https://github.com/AnonC0derH4ck3r/wifi-audit-framework.git
cd wifi-audit-framework
```

No manual `pip install` needed — missing dependencies are detected and installed automatically on first run.

For Evil Twin, ensure system deps are present:

```bash
sudo apt update && sudo apt install -y hostapd dnsmasq iptables iproute2 iw mitmproxy
pip install flask mitmproxy  # if not auto-installed
# Fix bcrypt warning that can kill mitmproxy (handled automatically, but manual fix):
pip install --upgrade passlib
# or
pip install bcrypt==4.0.1
```

Optionally, download the IEEE OUI database for vendor resolution:

```bash
mkdir oui_file
wget -O oui_file/ieee-oui.txt https://standards-oui.ieee.org/oui/oui.txt
```

---

## Usage

```bash
sudo python3 main.py
```

On launch you will be prompted to select your wireless interface, then dropped into the interactive menu.

### CLI Arguments

| Argument | Description | Default |
|---|---|---|
| `--iface` | Wireless interface name (e.g. `wlan0`) | Auto-detected |
| `--channels` | Comma-separated channel list (e.g. `1,6,11`) | All channels |
| `--band` | Lock to a band: `2g` or `5g` | Both (interleaved) |
| `--hop-interval` | Seconds between channel hops | `0.05` |
| `--no-hop` | Disable channel hopping | Off |

### Examples

```bash
# Auto interface detection, interactive menu
sudo python3 main.py

# Specific interface, 2.4 GHz only
sudo python3 main.py --iface wlan0 --band 2g

# Specific channels only
sudo python3 main.py --iface wlan0 --channels 1,6,11

# Lock to a single channel (no hopping)
sudo python3 main.py --iface wlan0 --channels 6 --no-hop

# Evil Twin — will prompt for SSID/channel/portal afterwards
sudo python3 main.py --iface wlan0
# then choose 5 → clone existing AP or manual → pick google/microsoft/instagram → AP iface / uplink
```

---

## Menu Options

| Option | Description | Status |
|---|---|---|
| `1` | Discover Access Points (beacon frame scan) | ✅ Active |
| `2` | Enumerate Connected Devices (data frame + EAPOL analysis) | ✅ Active |
| `3` | Vulnerability Assessment (Probe Response deep inspection) | ✅ Active |
| `4` | Deauthentication Attack (broadcast / unicast) | ✅ Active |
| `5` | **Rogue Access Point — Evil Twin + Captive Portal** (selectable `google`/`microsoft`/`instagram`; source: Discovered APs, PNL, or manual) | ✅ **Active** |
| `6` | PNL Extractor (Preferred Network List sniffing) | ✅ Active |
| `7` | **Hidden SSID Decloaking** (passive Assoc-Req listener, target from APs or manual) | ✅ **NEW — Active** |
| `8` | **WPS Brute-Force (Reaver)** (Pixie-Dust → online PIN, wash survey) | ✅ **NEW — Active** |
| `9` | **MITM Attack (ARP Spoof)** (post-association intercept + pcap + cred hints) | ✅ **NEW — Active** |
| `0` | Exit | ✅ Active |

---

## Evil Twin / Rogue AP Details

**Module:** `evil_twin.py` — faithful port of `wpf_complete.py` Evil Twin (Phase 3c). `hostapd` commands are kept **exactly** as in `wpf_complete.py:1940` (`interface`, `driver nl80211`, `ssid`, `hw_mode g`, `channel`, `macaddr_acl 0`, `ignore_broadcast_ssid 0`, `auth_algs 1`, `wmm_enabled 0`, optional `bssid`).

**Flow (option `5`):**
1. **Target selection** — offers three sources: **Discovered APs** (from option 1), **PNL** (from option 6, deduplicated), or **Manual** entry. If Discovered APs exist, shows table with `#`, `SSID`, `BSSID`, `CH`, `Encryption`. If PNL exists, shows deduplicated SSID list (each entry from a unique device). Prompts for BSSID and channel for PNL/manual entries. Handles hidden SSIDs (`<Hidden>`).
2. **Portal selection** — scans `captive-portal-pages/` for subdirs with `index.html` (built-ins: `google`, `microsoft`, `instagram`). Shows table with `Template` / `Style` / `Path`, prompts `1-N`. Template is loaded and `{ssid}` replaced.
3. **Uplink / AP iface** — prompts for uplink (auto-detected via `ip route show default`) and AP interface (defaults to framework iface).
4. **Launch** — writes `/tmp/wpf_hostapd.conf` + `/tmp/wpf_dnsmasq.conf` (`dhcp-range 10.0.0.2-10.0.0.254 12h`, `dhcp-option 3/6 → 10.0.0.1`, `server 8.8.8.8/1.1.1.1`, hijacks `captive.apple.com`, `connectivitycheck.gstatic.com`, `detectportal.firefox.com`, `msftconnecttest.com`, `clients3.google.com` → `10.0.0.1`), sets `10.0.0.1/24` on AP iface, `sysctl net.ipv4.ip_forward=1`, `iptables` NAT/REDIRECT (see below), kills old `hostapd/dnsmasq`, starts `hostapd`, `dnsmasq --no-daemon`, `mitmdump --mode transparent --listen-port 8080 -s /tmp/wpf_mitm_addon.py`, and `Flask` on `:5000` serving the chosen portal for all `host`/`path` (catch-all) and `POST /login` harvesting to `wpf_results.db:credentials` + `captive-portal-creds.log` → `302` to `https://www.google.com/`.

**Iptables (verbatim from `wpf_complete.py` plus persistence fixes):**
* `iptables -F` / `-t nat -F` / `-t mangle -F` / `-X` flush once
* `sysctl -w net.ipv4.ip_forward=1` (+ `conf.all/default.forwarding=1` re-asserted)
* `iptables -P FORWARD ACCEPT` / `-P INPUT ACCEPT`
* `INPUT -i <ap> -p udp/tcp --dport 53/67/68/5000/8080 ACCEPT` (survives `INPUT DROP`)
* `POSTROUTING -s 10.0.0.0/24 -o <uplink> -j MASQUERADE` (+ fallback generic)
* `FORWARD -i <uplink> -o <ap> -m state RELATED,ESTABLISHED ACCEPT` + `FORWARD -i <ap> -o <uplink> ACCEPT` (`-I` so not shadowed)
* `PREROUTING -i <ap> -p tcp --dport 80 ! -d 10.0.0.1 -j REDIRECT --to-port 8080` (to mitmproxy)
* `PREROUTING -i <ap> -p tcp --dport 443 ! -d 10.0.0.1 -j REDIRECT --to-port 8080`
* `PREROUTING -i <ap> -p tcp --dport 80 -d 10.0.0.1 -j REDIRECT --to-port 5000` (to Flask)

**Persistence Fixes (fixes “internet works ~60-180s then stops”):**
* **`nmcli dev set <ap> managed no`** before `hostapd` + restore on `stop()` — prevents NetworkManager reclaiming `10.0.0.1/24` after 60-90s.
* **`bind-dynamic` + `except-interface lo` + `listen-address 10.0.0.1`** in `dnsmasq` + `log-facility=/tmp/wpf_dnsmasq.log` — survives brief IP missing and `systemd-resolved:53` race (auto `systemctl stop systemd-resolved` retry).
* **Keepalive thread every 10s** (`_keepalive_loop`) — re-adds `10.0.0.1/24` if lost, re-asserts `ip_forward=1`, `iptables -C` → re-add if `firewalld/ufw` flushed, auto-restarts `dnsmasq` (max 2) and `mitmproxy` (max 2, patched `bcrypt`), logs `hostapd` death once with `/tmp/wpf_hostapd.log` tail (no spam).
* **Captive-probe `204` handling** — `CAPTIVE_HOSTS` / `CAPTIVE_PATHS` (`generate_204`, `hotspot-detect.html`, `connecttest.txt` etc.) via `_is_captive_probe()`. Unauth probe → portal (triggers OS popup), auth probe (IP in `_authenticated_ips` after `POST /login`) → `204 No Content` with `Cache-Control: no-cache` so OS marks `Connected` and never throttles. Normal GW traffic for auth IP → `302` to Google.
* **`_patch_bcrypt()`** — patches `passlib/handlers/bcrypt.py` `__about__` → `getattr(..., '4.0.1')` for `bcrypt 4.x`, suppresses `PYTHONWARNINGS`, filters `CryptographyDeprecationWarning` — fixes `mitmproxy` crash `module 'bcrypt' has no attribute '__about__'` that blackholed `80/443`.
* **Post-login internet guarantee** — `login()` marks IP auth, checks `mitm_alive`; if `mitm` dead, deletes `REDIRECT` to `8080` and ensures `MASQUERADE` so client still gets direct NAT internet (keepalive will restart `mitm` and re-add `REDIRECT`).

**Logs & Debugging:**
* `cat /tmp/wpf_hostapd.log` / `cat /tmp/wpf_dnsmasq.log` on `hostapd/dnsmasq` exit 1
* `ss -tulpn | grep :53` → free with `systemctl stop systemd-resolved`
* `hostapd -d /tmp/wpf_hostapd.conf` / `dmesg` for driver/channel errors (try channel 1/6/11, remove `bssid` spoof if driver rejects)
* `iptables -t nat -S` / `cat /proc/sys/net/ipv4/ip_forward` for NAT

---

## Hidden SSID Decloaking

**Menu option `7`** — passive listener that decloaks hidden SSIDs by capturing Association Request frames from clients that already know the SSID.

**How it works:**

1. **Target selection** — offers Discovered APs (from option 1, filtered to hidden `<Hidden>` SSIDs) or manual BSSID entry. If an AP is chosen from the list, its BSSID, SSID, and channel are auto-filled. Manual entry prompts for BSSID and channel.
2. **Assoc-Req listener** — sniffs on the target channel for management frames: **Association Request** (`type=0, subtype=0`) and **Reassociation Request** (`type=0, subtype=2`). These frames are sent by clients that already know the SSID — the SSID is embedded in the Information Elements even when the AP never broadcasts it.
3. **SSID extraction** — walks the IE chain for Tag 0 (SSID), decodes the UTF-8 value, and records `(client_mac, ssid, timestamp, deauth_count)`.
4. **Live table** — refreshes on every new Assoc-Req. Columns: `CLIENT MAC`, `VENDOR`, `DELOCAKED SSID`, `TIMESTAMP`, `DEAUTHS`. The `DEAUTHS` column increments if the framework also captures a deauth/disassoc frame from that client during the same session.
5. **Ctrl+C to stop** — returns to menu. Results are saved to `audit.results` row for the target AP.

**Security relevance:**

- Hidden SSIDs provide zero security — any client that has previously joined the network will leak the SSID in Assoc/Reassoc frames.
- An attacker can passively decloak every hidden network in range without sending a single frame.
- The decloaked SSID can then be used to set up an Evil Twin (option 5) targeting clients that auto-connect.

---

## WPS Brute-Force (Reaver)

**Menu option `8`** — module `wps_attack.py`. Pixie-Dust first (fast, few packets), then optional online PIN brute-force (slow, explicit consent).

**How it works:**

1. **Target selection** — WPS-enabled rows from option 1 (beacon WPS flag), else live `wash -i <mon> -s` survey (parsed BSSID/CH/PWR/lock/ESSID), else manual BSSID/channel.
2. **Pixie-Dust** — flags auto-adapted to the installed reaver (`--help` probed: v1.6.6 bare `-K` + `-x` fail-wait + `-5` for 5 GHz channels vs t6x-fork `-K 1`). PIN/PSK parsed live from output.
3. **Online brute-force (opt-in)** — only after a `y/N` prompt; tunable `-d` delay (default 1) and fail-wait (default 5, `-x`/`-T` per build); `-L` ignore-locks only on request. Output teed to `/tmp/wpf_wps_<BSSID>.log` by the framework (+ `.session`, resumable).
4. **Ctrl+C to stop** — reaver terminated, session kept, back to menu.

**If reaver exits instantly (code 1, usage text):** it never attacked — interface/driver problem, not a failed crack. The module now aborts pre-flight when `iw` reports non-monitor mode, streams full reaver output, and prints the reaver log tail. Checklist: `iw dev <mon> info` → `type monitor`; `airmon-ng check kill`; iface UP; target on shown channel and in range.

**If you see `WPS transaction failed (code: 0x03)` looping:** the AP's registrar is NACKing your M2 and restarting — it refuses the transaction. Usual causes: not Pixie-Dust vulnerable (typical on Realtek — the module warns after 3 consecutive 0x03s), WPS locked/rate-limited (check `wash` Lck column or option 3 assessment), or out-of-range flakiness. Hammering rarely helps — stop (Ctrl+C), switch targets (older/Atheros-based APs fare better for Pixie-Dust), and only consider online brute-force against unlocked targets.

**Security relevance:** WPS PIN is brute-forceable (11k effective halves); Pixie-Dust breaks weak RNGs in seconds. Recommend disabling WPS / locking + rate-limiting.

---

## MITM Attack (ARP Spoof)

**Menu option `9`** — module `mitm_attack.py`. Post-association LAN intercept: join the network normally first, then sit between victim ⇄ gateway. Companion to option 5 (which is rogue-AP + captive portal).

**How it works:**

1. **Setup** — prompts for iface, gateway (auto-detected via `ip route`), victim IP, pcap path (`/tmp/wpf_mitm.pcap`), live credential hints on/off.
2. **Spoof** — `bettercap` backend if present, else bidirectional `arpspoof -i <iface> -t <victim> <gateway>` + reverse. `sysctl net.ipv4.ip_forward=1`.
3. **Capture** — `tcpdump -i <iface> -w <pcap> host <victim>` (if installed) + scapy thread flagging transiting HTTP POSTs / basic-auth hosts live.
4. **Ctrl+C to stop** — procs terminated and correct ARP announcements (`arping -U`) sent so victim/gateway heal; capture path + hint count summarized.

**Security relevance:** demonstrates why open/WEP/WPA2-PSK LANs + clear-text HTTP are fatal; validates client isolation / dynamic ARP inspection / HSTS controls.

---

## Output Fields

### Access Point Table

| Field | Description |
|---|---|
| `BSSID` | MAC address of the AP |
| `CH` | Operating channel |
| `RSSI` | Received Signal Strength in dBm (e.g. `-67 dBm`) — 🟢 ≥-50 excellent, 🟡 -70 to -50 good, 🔴 <-70 weak; extracted from `RadioTap.dBm_AntSignal`, live-updates on each beacon from same BSSID |
| `SSID` | Network name (`<Hidden>` if not broadcast) |
| `ENCRYPTION` | Security protocol (Open / WPA / WPA2 / WPA3) |
| `MFPC` | Management Frame Protection Capable |
| `MFPR` | Management Frame Protection Required |
| `WPS` | WPS enabled / disabled |
| `DTIM` | DTIM period (1 = aggressive power-save impact) |
| `GRP CIPHER` | RSN group cipher suite (CCMP / TKIP / WEP) |
| `AKM` | Authentication Key Management (PSK / SAE / 802.1X) |
| `WPA1` | WPA1 IE present alongside RSN (downgrade risk) |
| `BCN INT` | Beacon interval in TUs (non-100 = non-standard, flagged with `*`) |
| `RRM` | 802.11k Radio Resource Management support |
| `BSS-TRANS` | 802.11v BSS Transition / client steering support |
| `UPTIME` | Estimated AP uptime derived from TSF timestamp |

### Client Table

| Field | Description |
|---|---|
| `Access Point` | BSSID of the associated AP |
| `AP Vendor` | AP manufacturer (via OUI lookup) |
| `Connected Client` | Client MAC address |
| `Client Vendor` | Client manufacturer (via OUI lookup) |
| `Status` | `Connected` or `Disconnected` (live tracking) |

### Probe Request Table (PNL Extractor)

| Field | Description |
|---|---|
| `SRC MAC` | MAC address of the probing device |
| `Vendor` | Device manufacturer (via OUI lookup) |
| `SSID (Probed)` | Network name the device is actively seeking |
| `Count` | Number of probe requests seen for this (MAC, SSID) pair |
| `Last Seen` | Timestamp of the most recent probe (`HH:MM:SS`) |

### Evil Twin Captured Credentials

| Field | Description |
|---|---|
| `Portal` | Template used (`google`/`microsoft`/`instagram`) |
| `SSID` | Cloned SSID |
| `Username` | Submitted `username`/`email` |
| `Password` | Submitted `password` |
| `Client IP` | `10.0.0.x` of the victim |
| `Source` | `captive_portal:<portal>:<ip>` or `mitmproxy:<host>` in `wpf_results.db:credentials` + `mitm` `http_traffic` |

Live console also prints `⚡ CREDENTIAL HARVESTED` with `Portal/SSID/User/Password/Client`.

### Hidden SSID Decloak Table

| Field | Description |
|---|---|
| `CLIENT MAC` | MAC address of the client sending the Assoc-Req |
| `VENDOR` | Client manufacturer (via OUI lookup) |
| `DELOCAKED SSID` | The hidden SSID revealed from the Assoc-Req IE |
| `TIMESTAMP` | Time the Assoc-Req was captured (`HH:MM:SS`) |
| `DEAUTHS` | Number of deauth/disassoc frames seen from this client during the session |

---

## How It Works

### Client Detection

Client association is determined through a layered signal approach rather than trusting association responses alone (which can report success even on a wrong password):

1. **Data frames** (`type=2`, `ToDS=1`) — client transmitting to AP proves active association.
2. **EAPOL frames** — 4-way handshake traffic confirms key exchange is in progress.
3. **Association Response** (`subtype=1`) — AP approval signal used as a secondary indicator.
4. **Deauth / Disassoc frames** (`subtype=0x0C` / `0x0A`) — marks client as `Disconnected`.
5. **Subsequent data / EAPOL after deauth** — automatically flips status back to `Connected`.

### Vulnerability Assessment

The assessment is triggered by injecting a crafted directed Probe Request at the target AP (with randomised source MAC, correct Supported Rates, Extended Rates, and HT Capabilities IEs) and then sniffing for the unicast Probe Response the AP sends back. The Probe Response carries the same Information Elements as a Beacon, so the same RSN / Vendor IE parser is reused. Fields extracted include:

- PMF state (MFPC / MFPR bits from RSN Capabilities)
- Group cipher and AKM suite type from the RSN IE
- WPA1 Vendor IE presence (downgrade attack surface)
- RRM (Tag 70, bit 0) and BSS Transition (Tag 127, bit 19)
- Full WPS TLV blob (Tag 221, OUI `00:50:F2:04`): version, configured state, PIN/PBC method, Selected Registrar flag, Setup Locked flag, RF bands, manufacturer, model, serial, device name, UUID-E, and primary device type

### PNL Extraction

Modern 802.11 clients periodically broadcast **directed Probe Requests** — management frames (type=0, subtype=4) carrying a specific SSID in the SSID IE (Tag 0) — to check whether a previously joined network is within range. These frames passively leak the device's **Preferred Network List (PNL)**: every SSID the device has connected to in the past and will auto-associate with if it hears a matching beacon.

Detection pipeline:

1. **Frame filter** — only management frames with subtype `0x04` are processed; everything else is dropped immediately.
2. **Wildcard suppression** — probes with an empty SSID IE (Tag 0, length 0) are discarded. These are undirected broadcast scans that reveal nothing about the PNL.
3. **Unicast source enforcement** — the LSB of the first octet of `addr2` is checked; multicast / broadcast sources are dropped as malformed.
4. **Deduplication by `(src_mac, ssid)` pair** — state is keyed on this tuple via `probe_index` (a dict), giving O(1) lookups. A device probing for multiple SSIDs produces one row per SSID.
5. **In-place update** — repeat probes to the same pair increment `Count` and refresh `Last Seen` without adding a new row.

**Security relevance:**

- **Privacy leak** — reveals SSIDs of networks a device has previously joined (home, office, hotel, etc.).
- **Evil Twin setup** — an attacker can respond to a directed probe with a rogue AP advertising the exact requested SSID, triggering automatic client association.
- **MAC randomisation note** — iOS 14+, Android 10+, and Windows 10+ randomise the source MAC per probe session, limiting persistent device tracking. The SSID content itself is still leaked regardless.

---

## Colour Legend

Output tables use ANSI colours consistently across all views:

| Colour | Meaning |
|---|---|
| 🟢 Green | Secure / expected value |
| 🟡 Yellow | Noteworthy / non-standard, warrants attention |
| 🔴 Red | Insecure / high-risk value |
| 🔵 Cyan | Informational (timestamps, identifiers) |
| Dim | Not present / not applicable |

---

## Changelog — 2026-09-04 RSSI + Evil Twin + Decloak Update

* **AP Discovery: RSSI (dBm) column (NEW)** — `audit_engine.py:427` adds `_extract_rssi()` extracting `RadioTap.dBm_AntSignal` (with `dbm_antsignal`/`Signal` fallbacks and field-scan) into new `RSSI` column between `CH` and `SSID`. Live-updates on re-seen BSSID without duplicate rows. Colour-coded: 🟢 ≥-50 dBm, 🟡 -70 to -50, 🔴 <-70, `?` if NIC/driver doesn't expose it. `ui.py:128` and `main.py:620,868` shifted to `row[3]` for SSID. `table_headers` expanded to 16 columns.
* **New `5` Rogue AP** — `main.py:538` now fully implements Evil Twin (was `coming soon`). Mirrors `wpf_complete.py` Evil Twin verbatim `hostapd` conf generation, adds portal chooser (`evil_twin.py:113`).
* **New `7` Hidden SSID Decloaking** — passive Assoc-Req listener in `audit_engine.py`. Selects target from discovered APs or manual BSSID, captures Assoc/Reassoc frames to extract hidden SSIDs, live table with client MAC, vendor, decloaked SSID, timestamp, and deauth count.
* **Evil Twin PNL source** — option 5 target selection now offers three sources: Discovered APs, PNL (deduplicated), or Manual. PNL entries prompt for BSSID and channel.
* **New `evil_twin.py`** — `EvilTwin` class with `GW 10.0.0.1`, `DHCP 10.0.0.2-254 12h`, `Flask :5000`, `mitm :8080`, `PORTAL_BASE`, `list_portals()`, `_load_portal_template()` (`{ssid}` replace), `_patch_bcrypt()`, keepalive.
* **New `captive-portal-pages/`** — `google/index.html`, `microsoft/index.html` (from `wpf_complete.py:1014`), `instagram/index.html` — self-contained, `POST /login` with `username`/`password` + hidden `ssid`, inline CSS/JS, no external deps.
* **Fix persistent internet** — `nmcli managed no`, `keepalive` 10s, `bind-dynamic`, `204` for auth probes, `bcrypt` patch, post-login direct NAT fallback — fixes "works 60-180s then no internet" and "no internet after login".
* **Fix spam** — keepalive now tracks `_keepalive_handled` pids, auto-restarts `dnsmasq`/`mitmproxy` max 2, logs once to `/tmp/wpf_hostapd.log`/`/tmp/wpf_dnsmasq.log`, filters `bcrypt` noise.
* **Docs** — this README updated to reflect `RSSI`, `5`/`7` active, new structure, new deps, Evil Twin + Decloak details, and troubleshooting.
