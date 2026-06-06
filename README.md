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

This tool is intended **strictly for authorized penetration testing and security research**. Only use it against networks and devices you own or have explicit written permission to test. Unauthorized use is illegal and unethical. The author assumes no liability for misuse.

---

## Features

- **Access Point Discovery** — Passive beacon frame sniffing with live table output. Extracts BSSID, SSID, channel, encryption, PMF (MFPC/MFPR), WPS status, DTIM period, group cipher, AKM suite, WPA1 downgrade detection, beacon interval, RRM (802.11k), BSS Transition (802.11v), and TSF uptime.
- **Connected Client Enumeration** — Identifies associated clients by inspecting data frames, EAPOL (4-way handshake), association responses, deauth, and disassoc frames. Tracks live Connected / Disconnected status per client.
- **OUI Vendor Lookup** — Resolves AP and client MAC prefixes to vendor names using the IEEE OUI database.
- **Channel Hopper** — Threaded channel hopper supporting 2.4 GHz, 5 GHz, or interleaved dual-band sweeps.
- **Auto Dependency Installer** — Detects and installs missing Python dependencies via APT automatically.
- **Monitor Mode Management** — Switches interface to/from monitor mode via NL80211 (Netlink), with `airmon-ng` as a secondary enforcement fallback for quirky drivers.
- **Clean Shutdown** — Restores NetworkManager, wpa_supplicant, and the interface to managed mode on exit.

---

## Project Structure

```
wifi_toolkit/
├── main.py               # Entry point — arg parsing, interface setup, sniff dispatch
├── config.py             # Constants: channel maps, interface type names, banner
├── ui.py                 # Terminal UI: colours, logging helpers, menu
├── dependencies.py       # Auto-installer for scapy, pyroute2, tabulate
├── interface_manager.py  # NL80211 interface control: mode, channel, state
└── audit_engine.py       # Core engine: packet parsing, client tracking, live tables
```

---

## Requirements

- **OS:** Linux (tested on Kali / Ubuntu)
- **Python:** 3.8+
- **Privileges:** Must be run as `root`
- **Hardware:** Wireless adapter with monitor mode support

### Python Dependencies
Auto-installed if missing:

| Package | Purpose |
|---|---|
| `scapy` | Packet capture and parsing |
| `pyroute2` | NL80211 / Netlink interface control |
| `tabulate` | Live table rendering |

### Optional
| Package | Purpose |
|---|---|
| `rich` | Enhanced terminal UI (gracefully degrades if absent) |
| `aircrack-ng` | Secondary monitor mode enforcement via `airmon-ng` |

---

## Installation

```bash
git clone https://github.com/AnonC0derH4ck3r/wifi-audit-framework.git
cd wifi-audit-framework
```

No manual `pip install` needed — missing dependencies are detected and installed automatically on first run.

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

On launch, you will be prompted to select your wireless interface and choose a menu option.

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
# Scan with auto interface detection (interactive menu)
sudo python3 main.py

# Scan on a specific interface, 2.4 GHz only
sudo python3 main.py --iface wlan0 --band 2g

# Scan specific channels only
sudo python3 main.py --iface wlan0 --channels 1,6,11

# Lock to a single channel (no hopping)
sudo python3 main.py --iface wlan0 --channels 6 --no-hop
```

---

## Menu Options

| Option | Description |
|---|---|
| `1` | Discover Access Points (beacon frame scan) |
| `2` | Enumerate Connected Devices (data frame + EAPOL analysis) |
| `3` | Vulnerability Assessment *(coming soon)* |
| `4` | Deauthentication Attack *(coming soon)* |
| `5` | Rogue Access Point *(coming soon)* |
| `6` | PNL Extract *(coming soon)* |
| `0` | Exit |

---

## Output Fields

### Access Point Table

| Field | Description |
|---|---|
| `BSSID` | MAC address of the AP |
| `CH` | Operating channel |
| `SSID` | Network name (`<Hidden>` if not broadcast) |
| `ENCRYPTION` | Security protocol (Open / WPA2 / WPA3 etc.) |
| `MFPC` | Management Frame Protection Capable |
| `MFPR` | Management Frame Protection Required |
| `WPS` | WPS enabled/disabled |
| `DTIM` | DTIM period (1 = aggressive power save impact) |
| `GRP CIPHER` | RSN group cipher suite (CCMP / TKIP / WEP) |
| `AKM` | Authentication Key Management (PSK / SAE / 802.1X) |
| `WPA1` | WPA1 IE present alongside RSN (downgrade risk) |
| `BCN INT` | Beacon interval (non-100 = non-standard) |
| `RRM` | 802.11k Radio Resource Management support |
| `BSS-TRANS` | 802.11v BSS Transition (client steering) |
| `UPTIME` | Estimated AP uptime derived from TSF timestamp |

### Client Table

| Field | Description |
|---|---|
| `Access Point` | BSSID of the associated AP |
| `AP Vendor` | AP manufacturer (via OUI lookup) |
| `Connected Client` | Client MAC address |
| `Client Vendor` | Client manufacturer (via OUI lookup) |
| `Status` | `Connected` or `Disconnected` (live tracking) |

---

## How Client Detection Works

Client association is determined through a layered signal approach rather than trusting association responses alone (which can report success even on wrong passwords):

1. **Data frames** (`type=2`, `ToDS=1`) — client transmitting to AP proves active association.
2. **EAPOL frames** — 4-way handshake traffic confirms key exchange.
3. **Association Response** (`subtype=1`) — AP approval signal.
4. **Deauth / Disassoc frames** (`subtype=0x0C` / `0x0A`) — marks client as `Disconnected`.
5. **Subsequent data/EAPOL** after deauth — automatically flips status back to `Connected`.

---
