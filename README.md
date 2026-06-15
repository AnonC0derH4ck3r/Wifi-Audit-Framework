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

- **Access Point Discovery** — Passive beacon frame sniffing with live table output. Extracts BSSID, SSID, channel, encryption, PMF (MFPC/MFPR), WPS status, DTIM period, group cipher, AKM suite, WPA1 downgrade detection, beacon interval, RRM (802.11k), BSS Transition (802.11v), and TSF uptime.
- **Connected Client Enumeration** — Identifies associated clients by inspecting data frames, EAPOL (4-way handshake), association responses, deauth, and disassoc frames. Tracks live Connected / Disconnected status per client.
- **Vulnerability Assessment** — Sends directed Probe Requests to a target AP and parses the Probe Response for a deep security profile: PMF state, group cipher, AKM suite, WPA1 downgrade risk, RRM/BSS-Transition support, and full WPS TLV breakdown (version, state, method, UUID-E, device info, setup-lock status).
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
```

---

## Menu Options

| Option | Description |
|---|---|
| `1` | Discover Access Points (beacon frame scan) |
| `2` | Enumerate Connected Devices (data frame + EAPOL analysis) |
| `3` | Vulnerability Assessment (Probe Response deep inspection) |
| `4` | Deauthentication Attack *(coming soon)* |
| `5` | Rogue Access Point *(coming soon)* |
| `6` | PNL Extractor (Preferred Network List sniffing) |
| `0` | Exit |

---

## Output Fields

### Access Point Table

| Field | Description |
|---|---|
| `BSSID` | MAC address of the AP |
| `CH` | Operating channel |
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
