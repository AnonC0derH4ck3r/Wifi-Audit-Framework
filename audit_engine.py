import os
import re
import time
import difflib
import threading
from pathlib import Path
from typing import List, Tuple, Any, Dict

from scapy.all import Dot11, Dot11Elt, Dot11Beacon, RadioTap, Dot11Deauth
from scapy.layers.eap import EAPOL
from tabulate import tabulate

from ui import UI
from interface_manager import InterfaceManager

# -----------------------------------------------------------------------------
# AUDIT ENGINE
# -----------------------------------------------------------------------------

class WirelessAuditEngine:
    """The core sniffer and packet processor."""

    def __init__(self, interface: str):
        self.interface      = interface
        self.seen_bssids    = set()
        self.results        = []
        self.client_results = []
        self.probe_results = []
        self.probe_index   = {}
        self.probe_first_seen: dict = {}  # (src_mac, ssid) -> "HH:MM:SS" first observed
        self.seen_clients   = set()
        # tracks current status per client mac: "Connected" | "Disconnected"
        self.client_status  = {}
        # For timeout-based disconnect: last transmitted-packet timestamp per client (monotonic).
        # ANY packet transmitted by the client refreshes this (data/mgmt/ctrl where client is transmitter).
        self.client_last_seen: dict = {}  # last ANY transmitted packet from client
        self.client_last_any: dict = {}   # alias of client_last_seen (kept for compat)
        self.client_timeout = 15  # seconds — no packet for this long → Disconnected
        self._client_monitor_stop = threading.Event()
        self._client_monitor_thread = None
        self._start_client_timeout_monitor()
        # Deauth display — single-line live counter (no per-packet newlines)
        self._deauth_counts: dict = {}  # (tx, rx) -> count
        self._deauth_lock = threading.Lock()
        # View gating — only the active feature may draw to the screen.
        # Prevents background threads (e.g. client timeout) from overwriting
        # another feature's table (e.g. vuln assessment). Data still updates.
        self.current_view: str = "menu"  # "aps"|"clients"|"vuln"|"probes"|"decloak"|"deauth"|"rogue"|"menu"
        self._render_lock = threading.Lock()
        # Passive-discovery timestamps per BSSID (wall clock for display)
        self.ap_first_seen: dict = {}  # bssid -> "HH:MM:SS" first beacon observed
        self.ap_last_seen: dict = {}   # bssid -> "HH:MM:SS" most recent beacon
        # Per-client extended state (passive): RSSI, wall-clock first/last seen,
        # and activity counters. Core 5-col client row layout is unchanged.
        self.client_first_seen: dict = {}  # client_mac -> "HH:MM:SS"
        self.client_last_wall: dict = {}   # client_mac -> "HH:MM:SS"
        self.client_rssi: dict = {}        # client_mac -> int dBm or None
        self.client_stats: dict = {}       # client_mac -> {"data":n,"eapol":n,"assoc":n,"auth":n}
        # Hidden SSID decloaking — store decloaked results
        self.decloaked = {}  # bssid.lower() -> ssid
        self.decloaked_results = []  # list of [bssid, ssid, client_mac, vendor, frame_type, timestamp, channel]
        self.decloaked_seen = set()  # (bssid, ssid) to avoid duplicates
        # Rogue AP detection — legit baseline + scored candidates
        self.rogue_legit: Dict[str, Any] = {}  # {ssid,bssid,channel,encryption,mfpc,mfpr,uptime_secs}
        self.rogue_results: list = []  # rows: [bssid,ssid,ch,rssi,enc,mfpc,mfpr,uptime,score,risk,reasons]
        self.rogue_index: dict = {}    # bssid.lower() -> idx in rogue_results
        # Latest WPS detail per BSSID from probe-response assessment (passive)
        self.vuln_wps: dict = {}       # bssid.lower() -> {present,version,state,method,...}
        # WPA handshake / EAP / PMKID tracking (passive — parsed, never transmitted)
        self.client_handshake: dict = {}  # client_mac -> {"msgs":set,"complete":bool,"eap":set,"pmkid":bool}
        self.ap_pmkid: dict = {}          # bssid.lower() -> first PMKID hex seen in EAPOL M1
        # BSSID fingerprint conflicts: same BSSID, differing attrs (possible impersonation)
        self.bssid_fp: dict = {}       # bssid.lower() -> {"ch":set,"enc":set,"ssid":set,"mfpc":set}
        self.bssid_conflicts: dict = {}  # bssid.lower() -> evidence string
        self.stop_hopper    = threading.Event()
        self.table_headers  = [
            "BSSID", "CH", "RSSI", "SSID", "ENCRYPTION",
            "MFPC", "MFPR", "WPS", "DTIM",
            "GRP CIPHER", "AKM", "WPA1", "BCN INT", "RRM", "BSS-TRANS", "UPTIME",
            "FREQ", "STD", "FIRST SEEN", "LAST SEEN", "FT",
        ]
        self.oui_map = {}
        # Try multiple locations: project/oui_file, cwd, and alongside script
        candidates = [
            Path(__file__).parent / "oui_file" / "ieee-oui.txt",
            Path("./oui_file/ieee-oui.txt"),
            Path("./ieee-oui.txt"),
            Path("oui_file/ieee-oui.txt"),
            Path("ieee-oui.txt"),
        ]
        oui_path = next((p for p in candidates if p.exists()), None)
        if oui_path and oui_path.exists():
            try:
                with open(oui_path, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        # Handles both hyphen and colon formats, case-insensitive
                        # Example: "A8-BA-69   (hex)                Samsung Electronics Co.,Ltd"
                        m = re.match(r'^\s*([0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)', line)
                        if m:
                            key = m.group(1).upper().replace(":", "-")
                            self.oui_map[key] = m.group(2).strip()
                UI.ok(f"OUI database loaded: {len(self.oui_map)} entries from {oui_path}.")
                # Quick sanity check for known Samsung prefix to warn if file is truncated
                if "A8-BA-69" not in self.oui_map:
                    UI.warn(f"OUI file at {oui_path} loaded but A8-BA-69 not found — file may be truncated or format changed.")
            except Exception as e:
                UI.warn(f"Failed to read OUI file {oui_path}: {e} — vendor names will show as 'Unknown'.")
        else:
            tried = ", ".join(str(p) for p in candidates)
            UI.warn(f"ieee-oui.txt not found (tried {tried}) — vendor names will show as 'Unknown'. Put file at oui_file/ieee-oui.txt")

    # def send_probe_request(self, ssid: str, iface: str):
    #     """
    #     Craft and inject a directed Probe Request for `ssid` on `iface`.

    #     The AP will unicast a Probe Response back, which vuln_assessment()
    #     will pick up and parse.  We use the broadcast destination (ff:ff:...)
    #     and a randomised source so the real NIC MAC doesn't matter.
    #     """
    #     from scapy.all import sendp, RandMAC
    #     import struct

    #     src_mac = RandMAC()

    #     # Supported Rates IE (Tag 1) — standard 802.11b/g rates
    #     # Each byte = rate * 2; the MSB set means "basic rate"
    #     supported_rates = b'\x82\x84\x8b\x96\x0c\x12\x18\x24'

    #     # Extended Supported Rates IE (Tag 50) — 802.11g extras
    #     ext_rates = b'\x30\x48\x60\x6c'

    #     # HT Capabilities IE (Tag 45) — 26-byte minimal placeholder
    #     # Presence of this IE tells the AP we can handle 802.11n,
    #     # which may cause it to include more detail in the Probe Response.
    #     ht_cap = b'\x01\x00' + b'\xff' * 2 + b'\x00' * 22
    #     # it is doing it's job well.
    #     # already sending required params to make the AP being able to trust a probe request
    #     # by setting supported, extended rates, caps
    #     probe = (
    #         RadioTap() /
    #         Dot11(
    #             type=0,          # Management
    #             subtype=4,       # Probe Request
    #             addr1="ff:ff:ff:ff:ff:ff",   # Destination — broadcast
    #             addr2=src_mac,               # Source — us (randomised)
    #             addr3="ff:ff:ff:ff:ff:ff",   # BSSID — broadcast (directed by SSID IE)
    #         ) /
    #         Dot11Elt(ID=0,  info=ssid.encode()) /       # SSID IE (Tag 0)
    #         Dot11Elt(ID=1,  info=supported_rates) /     # Supported Rates (Tag 1)
    #         Dot11Elt(ID=50, info=ext_rates) /           # Extended Rates (Tag 50)
    #         Dot11Elt(ID=45, info=ht_cap)                # HT Capabilities (Tag 45)
    #     )

    #     # Send 3 times — some APs rate-limit or drop the first frame
    #     sendp(probe, iface=iface, count=1, inter=0.1, verbose=False)

    #     UI.ok(f"Probe Request sent for SSID '{ssid}' on {iface}")
    def send_probe_request(self, ssid: str, iface: str, channel: int = None, timeout: float = 3.0) -> bool:
        """
        Craft and inject a directed Probe Request for `ssid` on `iface`.
        The AP will unicast a Probe Response back, which vuln_assessment()
        will pick up and parse.  We use the broadcast destination (ff:ff:...)
        and a randomised source so the real NIC MAC doesn't matter.

        Returns True if a matching Probe Response (type=0, subtype=5) was
        sniffed from the target BSSID within `timeout` seconds, False otherwise.
        """
        from scapy.all import sendp, sniff, RandMAC

        src_mac = RandMAC()
        # Supported Rates IE (Tag 1) — standard 802.11b/g rates
        # Each byte = rate * 2; the MSB set means "basic rate"
        supported_rates = b'\x82\x84\x8b\x96\x0c\x12\x18\x24'
        # Extended Supported Rates IE (Tag 50) — 802.11g extras
        ext_rates = b'\x30\x48\x60\x6c'
        # HT Capabilities IE (Tag 45) — 26-byte minimal placeholder
        ht_cap = b'\x01\x00' + b'\xff' * 2 + b'\x00' * 22

        probe = (
            RadioTap() /
            Dot11(
                type=0,          # Management
                subtype=4,       # Probe Request
                addr1="ff:ff:ff:ff:ff:ff",
                addr2=src_mac,
                addr3="ff:ff:ff:ff:ff:ff",
            ) /
            Dot11Elt(ID=0,  info=ssid.encode()) /
            Dot11Elt(ID=1,  info=supported_rates) /
            Dot11Elt(ID=50, info=ext_rates) /
            Dot11Elt(ID=45, info=ht_cap)
        )

        # --- Set up a short-lived sniff BEFORE sending, so we don't race the AP --- #
        responded = {"flag": False}

        def _watch(pkt):
            if not pkt.haslayer(Dot11):
                return
            d = pkt.getlayer(Dot11)
            if d.type == 0x00 and d.subtype == 0x05 and d.addr2 == ssid_bssid:
                responded["flag"] = True
                return True  # stop_filter truthy → sniff() returns immediately

        # `ssid` here is actually treated as the target SSID for the IE, but the
        # Probe Response is matched by BSSID, not SSID — so the caller must pass
        # the BSSID as `ssid` (as main.py already does: send_probe_request(ssid=a_bssid, ...))
        ssid_bssid = ssid

        sniff_thread = threading.Thread(
            target=lambda: sniff(
                iface=iface,
                prn=_watch,
                store=False,
                timeout=timeout,
                stop_filter=lambda pkt: responded["flag"],
            ),
            daemon=True,
        )
        sniff_thread.start()

        # Send 3 times — some APs rate-limit or drop the first frame
        sendp(probe, iface=iface, count=1, inter=0.1, verbose=False)

        sniff_thread.join(timeout=timeout + 0.5)

        if responded["flag"]:
            UI.ok(f"Probe Request sent for SSID '{ssid}' on {iface} — AP responded.")
        else:
            UI.warn(f"Probe Request sent for SSID '{ssid}' on {iface} — no response received.")

        return responded["flag"]

    def _lookup_oui(self, mac: str) -> str:
        if not mac:
            return "Unknown"
        oui_key = mac.upper().replace(":", "-")[:8]
        return self.oui_map.get(oui_key, "Unknown")

    def set_view(self, name: str):
        """Set the active UI view. Only this view may draw to the screen."""
        try:
            self.current_view = name
        except Exception:
            pass

    def _can_render(self, view: str) -> bool:
        """Background threads must call this before any clear/print."""
        try:
            return self.current_view == view
        except Exception:
            return False

    def _update_row_status(self, client_mac: str):
        """Patch the Status field (index 4) in the existing row for this client."""
        for row in self.client_results:
            if row[2] == client_mac:   # index 2 = client_mac
                row[4] = self.client_status[client_mac]
                if len(row) > 7:
                    row[7] = self.client_last_wall.get(client_mac, row[7])
                break

    def _note_client_activity(self, mac: str, rssi=None, kind: str = None):
        """Passive per-client metadata: wall-clock first/last seen, RSSI and
        activity counters (data/eapol/assoc/auth). Never changes status or
        creates rows — purely observational."""
        if not mac:
            return
        try:
            now_wall = time.strftime("%H:%M:%S")
            if mac not in self.client_first_seen:
                self.client_first_seen[mac] = now_wall
            self.client_last_wall[mac] = now_wall
            if isinstance(rssi, int):
                self.client_rssi[mac] = rssi
            if kind:
                stats = self.client_stats.setdefault(
                    mac, {"data": 0, "eapol": 0, "assoc": 0, "auth": 0})
                if kind in stats:
                    stats[kind] += 1
            for row in self.client_results:
                if row[2] == mac:
                    while len(row) < 8:
                        row.append("?")
                    row[5] = f"{self.client_rssi[mac]} dBm" if isinstance(
                        self.client_rssi.get(mac), int) else "?"
                    row[6] = self.client_first_seen.get(mac, row[6])
                    row[7] = self.client_last_wall.get(mac, row[7])
                    break
        except Exception:
            pass

    def _mark_connected(self, client_mac: str, ap_mac: str, rssi=None, kind: str = None):
        """Mark an existing client Connected, or add them if first seen via assoc/EAPOL."""
        now = time.monotonic()
        self.client_last_seen[client_mac] = now
        self.client_last_any[client_mac] = now
        self._note_client_activity(client_mac, rssi=rssi, kind=kind)
        if client_mac in self.seen_clients:
            if self.client_status.get(client_mac) != "Connected":
                self.client_status[client_mac] = "Connected"
                self._update_row_status(client_mac)
        else:
            # Seen assoc/EAPOL before any data frame — add the row now
            ap_vendor     = self._lookup_oui(ap_mac)
            client_vendor = self._lookup_oui(client_mac)
            self.client_status[client_mac] = "Connected"
            now_wall = time.strftime("%H:%M:%S")
            first = self.client_first_seen.get(client_mac, now_wall)
            rssi_s = f"{rssi} dBm" if isinstance(rssi, int) else "?"
            row = [ap_mac, ap_vendor, client_mac, client_vendor, "Connected",
                   rssi_s, first, now_wall]
            self.client_results.append(row)
            self.seen_clients.add(client_mac)

    def _touch_client(self, mac: str):
        """Refresh last-seen timestamp; if it was Disconnected, flip to Connected."""
        now = time.monotonic()
        self.client_last_seen[mac] = now
        self.client_last_any[mac] = now
        if self.client_status.get(mac) == "Disconnected":
            self.client_status[mac] = "Connected"
            self._update_row_status(mac)
            self.render_client_table()

    def _touch_any(self, mac: str):
        """Refresh timestamp on any transmitted packet — Disconnected flips back to Connected."""
        now = time.monotonic()
        self.client_last_seen[mac] = now
        self.client_last_any[mac] = now
        if self.client_status.get(mac) == "Disconnected":
            if mac in self.seen_clients:
                self.client_status[mac] = "Connected"
                self._update_row_status(mac)
                self.render_client_table()

    def _start_client_timeout_monitor(self):
        if self._client_monitor_thread and self._client_monitor_thread.is_alive():
            return
        self._client_monitor_stop.clear()
        self._client_monitor_thread = threading.Thread(target=self._client_timeout_loop, daemon=True)
        self._client_monitor_thread.start()

    def _client_timeout_loop(self):
        """Two-state: Connected while client transmitted any packet within 15s, else Disconnected."""
        while not self._client_monitor_stop.is_set():
            now = time.monotonic()
            for mac in list(self.seen_clients):
                status = self.client_status.get(mac)
                last = self.client_last_seen.get(mac, self.client_last_any.get(mac, 0))
                if status == "Connected" and now - last >= self.client_timeout:
                    # No packet at all for 15s → Disconnected (Deauth/Disassoc also forces this elsewhere)
                    self.client_status[mac] = "Disconnected"
                    self._update_row_status(mac)
                    self.render_client_table()
            time.sleep(1)

    # ── Hidden SSID Decloaking ────────────────────────────────────────────────
    def hidden_decloak(self, pkt, target_bssid: str):
        """
        Passive hidden-SSID decloaker — listens ONLY for Association Requests (0,0)
        as requested (Probe-req are unreliable). If the Assoc Req is directed to
        target_bssid and contains a non-empty SSID IE (ID 0), the hidden SSID is
        recovered. Called via sniff(prn=lambda p: engine.hidden_decloak(p, target_bssid)).
        """
        if not target_bssid:
            return
        target_bssid = target_bssid.lower()
        if not pkt.haslayer(Dot11):
            return
        dot11 = pkt.getlayer(Dot11)
        if dot11.type != 0:
            return
        # Only Association Request (0,0) — per user request, ignore Probe/Reassoc
        if dot11.subtype != 0:
            return

        # For Assoc Req, addr1 must be the hidden AP's BSSID, addr2 is the client
        if not dot11.addr1 or dot11.addr1.lower() != target_bssid:
            return
        client_mac = dot11.addr2

        if not client_mac or not self.is_unicast(client_mac):
            return

        # Walk IEs to find SSID (ID 0)
        ssid = None
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:
                raw = bytes(elt.info) if elt.info else b""
                if raw:  # skip empty (wildcard) and hidden beacon's empty
                    try:
                        ssid = raw.decode("utf-8", errors="replace").strip()
                    except Exception:
                        try:
                            ssid = raw.decode("utf-8", "ignore").strip()
                        except Exception:
                            ssid = None
                    # Filter out placeholders and non-printable
                    if ssid and ssid not in ("<Hidden>", "<hidden>", "<Malformed>") and len(ssid) >= 1:
                        # Basic sanity: SSID 1-32 bytes, printable
                        if 1 <= len(ssid) <= 32 and all(32 <= ord(c) <= 126 or c in " -_." for c in ssid):
                            break
                        else:
                            # Still accept it but clean
                            break
                ssid = None
                break
            try:
                elt = elt.payload.getlayer(Dot11Elt)
            except Exception:
                break

        if not ssid:
            return

        # Deduplicate by (bssid, ssid)
        key = (target_bssid, ssid)
        if key in self.decloaked_seen:
            return
        self.decloaked_seen.add(key)
        self.decloaked[target_bssid] = ssid

        # Try to update the original beacon results entry so UI no longer shows <Hidden>
        for row in self.results:
            if row[0].lower() == target_bssid and str(row[3]).strip().lower() in ("<hidden>", "<malformed>", "", "<hidden>"):
                row[3] = ssid
                break

        # Record decloaked event — only Assoc-Req per user request.
        # Channel is captured passively from the RadioTap frequency (best effort).
        now = time.strftime("%H:%M:%S")
        frame_type = "Assoc-Req"
        vendor = self._lookup_oui(client_mac)
        channel = "?"
        try:
            if pkt.haslayer(RadioTap) and pkt[RadioTap].Channel:
                freq = int(pkt[RadioTap].Channel)
                channel = (freq - 2407) // 5 if freq < 5000 else (freq - 5000) // 5
        except Exception:
            channel = "?"
        self.decloaked_results.append([target_bssid, ssid, client_mac, vendor, frame_type, now, channel])

        # Live feedback
        UI.ok(f"Decloaked {UI.YELLOW}{ssid}{UI.RESET} from {UI.CYAN}{target_bssid}{UI.RESET} via {frame_type} by {UI.GREEN}{client_mac}{UI.RESET} ({vendor})")
        self.render_decloaked_table(target_bssid)

    def render_decloaked_table(self, target_bssid: str = None):
        """Render decloaked SSIDs live table."""
        if not self._can_render("decloak"):
            return
        if not self.decloaked_results:
            return
        # Filter by target if given
        rows = [r for r in self.decloaked_results if not target_bssid or r[0].lower() == target_bssid.lower()]
        display_rows = []
        for r in rows:
            row = list(r) + ["?"] * (7 - len(r))
            bssid, ssid, client_mac, vendor, ftype, ts, ch = row[0:7]
            display_rows.append([
                f"{UI.GREEN}{bssid}{UI.RESET}",
                f"{UI.YELLOW}{ssid}{UI.RESET}",
                f"{UI.CYAN}{client_mac}{UI.RESET}",
                f"{UI.DIM}{vendor}{UI.RESET}",
                f"{UI.BLUE}{ftype}{UI.RESET}",
                f"{UI.DIM}{ts}{UI.RESET}",
                f"{UI.CYAN}{ch}{UI.RESET}",
            ])
        with self._render_lock:
            os.system('clear')
            UI.print_banner()
            if target_bssid:
                print(f"{UI.BOLD}Decloaked Hidden SSID for {UI.YELLOW}{target_bssid}{UI.RESET}{UI.BOLD}:{UI.RESET}  {UI.GREEN}{self.decloaked.get(target_bssid.lower(), '—')}{UI.RESET}\n")
            print(tabulate(display_rows, headers=["BSSID (Hidden AP)", "Decloaked SSID", "Client MAC", "Client Vendor", "Frame", "Time", "CH"], tablefmt="pretty"))
            print(f"\n{UI.DIM}Listening for Association Requests that leak SSID — press CTRL+C to stop.{UI.RESET}\n")

    # ── Rogue AP detection ──────────────────────────────────────────────────
    def start_rogue_watch(self, legit_ssid: str, legit_bssid: str, legit_channel=None,
                          legit_encryption=None, legit_mfpc=None, legit_mfpr=None,
                          legit_uptime_secs=None, legit_vendor=None, legit_rssi=None):
        """Set the legitimate AP baseline and reset rogue candidates."""
        try:
            vendor = legit_vendor or self._lookup_oui(str(legit_bssid or ""))
        except Exception:
            vendor = "Unknown"
        self.rogue_legit = {
            "ssid": str(legit_ssid or "").strip(),
            "bssid": str(legit_bssid or "").strip().lower(),
            "channel": str(legit_channel).strip() if legit_channel not in (None, "") else "?",
            "encryption": str(legit_encryption or "?"),
            "mfpc": str(legit_mfpc) if legit_mfpc not in (None, "") else "?",
            "mfpr": str(legit_mfpr) if legit_mfpr not in (None, "") else "?",
            "uptime_secs": legit_uptime_secs,
            "vendor": vendor,
            "rssi": legit_rssi if isinstance(legit_rssi, int) else None,
        }
        self.rogue_results = []
        self.rogue_index = {}

    @staticmethod
    def _rogue_ssid_match(ssid: str, legit_ssid: str):
        """Same-or-similar SSID check (BSSID is deliberately ignored).

        Returns (matched: bool, kind: str, ratio: float).
        kind: 'exact' | 'similar'. Similarity covers typosquatting
        ('Starbucks' vs 'Starbuckz'), extra suffixes ('Corp' vs 'Corp_Free'),
        and case/spacing variants.
        """
        a = str(ssid or "").strip()
        b = str(legit_ssid or "").strip()
        if not a or not b:
            return False, "", 0.0
        placeholders = {"<hidden>", "<malformed>", "<wildcard>", ""}
        if a.lower() in placeholders or b.lower() in placeholders:
            return False, "", 0.0
        if a.lower() == b.lower():
            return True, "exact", 1.0
        al, bl = a.lower(), b.lower()
        # Substring / affix tricks: "Corp" vs "Corp_Free", "Corp " vs "Corp"
        if al in bl or bl in al:
            ratio = difflib.SequenceMatcher(None, al, bl).ratio()
            return True, "similar", ratio
        ratio = difflib.SequenceMatcher(None, al, bl).ratio()
        if ratio >= 0.80:
            return True, "similar", ratio
        # Single-char typo on short names can dip below 0.80 — catch edit distance 1
        if abs(len(al) - len(bl)) <= 1 and len(al) >= 4:
            diffs = sum(1 for x, y in zip(al, bl) if x != y) + abs(len(al) - len(bl))
            if diffs <= 1:
                return True, "similar", ratio
        return False, "", ratio

    @staticmethod
    def _rogue_uptime_secs(uptime) -> Any:
        """Parse 'Xd Xh Xm Xs' (or raw TSF microseconds) into seconds."""
        if uptime is None or uptime == "?":
            return None
        if isinstance(uptime, (int, float)):
            # Assume raw TSF microseconds if huge, else seconds
            try:
                v = float(uptime)
                return int(v // 1_000_000) if v > 1_000_000_000 else int(v)
            except Exception:
                return None
        try:
            m = re.search(r"(?:(\d+)\s*d)?\s*(?:(\d+)\s*h)?\s*(?:(\d+)\s*m)?\s*(?:(\d+)\s*s)?",
                          str(uptime))
            if not m or not m.group(0).strip():
                return None
            d = int(m.group(1) or 0)
            h = int(m.group(2) or 0)
            mi = int(m.group(3) or 0)
            s = int(m.group(4) or 0)
            total = d * 86400 + h * 3600 + mi * 60 + s
            # All-zero parse of a non-empty string means unparseable
            if total == 0 and str(uptime).strip() not in ("0d 0h 0m 0s", "0"):
                # Could still be a genuine fresh AP (<1s) — treat as 0
                return 0
            return total
        except Exception:
            return None

    def _score_rogue(self, ssid_kind: str, ssid_ratio: float, enc: str,
                     mfpc, mfpr, channel, uptime_secs, rssi, suspect_vendor=None) -> Tuple[int, str, list]:
        """Correlate rogue probability 0-100 from SSID, encryption, MFPC/MFPR,
        channel, uptime, vendor and signal vs the legit baseline.
        Returns (score, risk, reasons). Wording stays at 'suspect' level —
        never claims definitive spoofing without adequate evidence."""
        score = 0
        reasons = []
        legit = self.rogue_legit or {}
        legit_enc = str(legit.get("encryption") or "?")
        legit_mfpc = str(legit.get("mfpc") or "?")
        legit_mfpr = str(legit.get("mfpr") or "?")
        legit_ch = str(legit.get("channel") or "?")
        legit_up = legit.get("uptime_secs")

        # 1. SSID — strongest signal (BSSID differs by construction)
        if ssid_kind == "exact":
            score += 35
            reasons.append("Same SSID, different BSSID")
        elif ssid_kind == "similar":
            score += 22
            reasons.append(f"Similar SSID (~{ssid_ratio:.0%})")

        # 2. Encryption — Open rogue impersonating secured legit is the classic evil twin
        enc_l = str(enc or "?").lower()
        leg_l = legit_enc.lower()
        rogue_open = "open" in enc_l
        legit_open = "open" in leg_l or leg_l.strip() == "?"
        if rogue_open and not legit_open:
            score += 30
            reasons.append(f"Open (legit: {legit_enc})")
        elif rogue_open and legit_open:
            score += 8
            reasons.append("Open like legit — check BSSID/vendor")
        elif not rogue_open and not legit_open and enc_l != leg_l and "?" not in (enc_l, leg_l):
            score += 10
            reasons.append(f"Enc differs ({enc} vs {legit_enc})")

        # 3. PMF (MFPC/MFPR) — legit with protected mgmt frames, rogue without
        try:
            mfpc_s, mfpr_s = str(mfpc), str(mfpr)
            if legit_mfpc == "1" and mfpc_s == "0":
                score += 15
                reasons.append("PMF stripped (MFPC 1->0)")
            elif legit_mfpr == "1" and mfpr_s == "0":
                score += 12
                reasons.append("PMF required->off (MFPR 1->0)")
            elif legit_mfpc in ("1",) and mfpc_s == "?":
                score += 5
                reasons.append("PMF unknown on suspect")
        except Exception:
            pass

        # 4. Channel — rogues usually broadcast from a different radio/channel
        try:
            if str(channel) != "?" and legit_ch != "?":
                if str(channel).strip() != str(legit_ch).strip():
                    score += 10
                    reasons.append(f"Other channel (CH {channel} vs {legit_ch})")
        except Exception:
            pass

        # 5. Uptime — a minutes-old AP cloning a days-old enterprise AP is suspect
        try:
            if uptime_secs is not None:
                if uptime_secs < 3600:
                    score += 15
                    reasons.append("Fresh uptime (<1h)")
                elif isinstance(legit_up, (int, float)) and legit_up and legit_up > 86400 \
                        and uptime_secs < legit_up / 10:
                    score += 10
                    reasons.append("Much younger than legit")
        except Exception:
            pass

        # 6. Signal — attacker box nearby is often louder than the real AP.
        # Flag potential signal-based impersonation when the suspect is
        # significantly stronger than the legit baseline (indicator only).
        try:
            legit_rssi = legit.get("rssi")
            if isinstance(rssi, int) and isinstance(legit_rssi, int) \
                    and rssi >= legit_rssi + 10:
                score += 8
                reasons.append(f"Stronger than legit ({rssi} vs {legit_rssi} dBm) — possible signal impersonation")
            elif isinstance(rssi, int) and rssi >= -45:
                score += 5
                reasons.append(f"Very strong ({rssi} dBm)")
        except Exception:
            pass

        # 7. Vendor — same SSID from an unexpected vendor is a classic tell
        try:
            legit_vendor = str(legit.get("vendor") or "Unknown")
            sus_vendor = str(suspect_vendor or "Unknown")
            if sus_vendor != "Unknown" and legit_vendor != "Unknown" \
                    and sus_vendor.lower() != legit_vendor.lower():
                score += 8
                reasons.append(f"Unexpected vendor ({sus_vendor} vs {legit_vendor})")
        except Exception:
            pass

        score = max(0, min(100, int(score)))
        risk = "HIGH" if score >= 70 else ("MEDIUM" if score >= 40 else "LOW")
        if not reasons:
            reasons.append("Weak signals only")
        return score, risk, reasons

    def rogue_watch(self, pkt):
        """Beacon handler — flag APs with same/similar SSID but other BSSID.

        Call via sniff(prn=audit.rogue_watch). Channel hopping is done by the
        caller's hopper thread; this handler never changes channels itself.
        """
        legit = self.rogue_legit or {}
        legit_ssid = str(legit.get("ssid") or "").strip()
        legit_bssid = str(legit.get("bssid") or "").strip().lower()
        if not legit_ssid or not legit_bssid:
            return
        if not pkt.haslayer(Dot11):
            return
        dot11 = pkt.getlayer(Dot11)
        if dot11.type != 0 or dot11.subtype != 0x08:  # beacons only
            return
        bssid = str(dot11.addr2 or "").strip().lower()
        if not bssid or bssid == legit_bssid:
            return  # the real AP itself — never a suspect

        stats = {}
        try:
            stats = pkt.getlayer(Dot11Beacon).network_stats()
        except Exception:
            stats = {}
        ssid = stats.get("ssid") or ""
        if not ssid:
            return
        matched, kind, ratio = self._rogue_ssid_match(ssid, legit_ssid)
        if not matched:
            return

        encryption = ", ".join(sorted(stats.get("crypto", {"Open"}))) if stats.get("crypto") else "Open"
        channel = stats.get("channel")
        if not channel:
            try:
                if pkt.haslayer(RadioTap) and pkt[RadioTap].Channel:
                    freq = pkt[RadioTap].Channel
                    channel = (freq - 2407) // 5 if freq < 5000 else (freq - 5000) // 5
            except Exception:
                channel = "?"
        if not channel:
            channel = "?"
        mfpc, mfpr = self._extract_pmf(pkt)
        rssi = self._extract_rssi(pkt)
        try:
            suspect_vendor = self._lookup_oui(bssid)
        except Exception:
            suspect_vendor = "Unknown"
        uptime_str = None
        uptime_secs = None
        try:
            if pkt.haslayer(Dot11Beacon) and pkt[Dot11Beacon].timestamp is not None:
                tsf = int(pkt[Dot11Beacon].timestamp)
                total = tsf // 1_000_000
                uptime_str = f"{total // 86400}d {(total % 86400) // 3600}h {(total % 3600) // 60}m {total % 60}s"
                uptime_secs = total
        except Exception:
            pass
        if uptime_str is None:
            uptime_str = "?"

        score, risk, reasons = self._score_rogue(kind, ratio, encryption, mfpc, mfpr,
                                                 channel, uptime_secs, rssi,
                                                 suspect_vendor=suspect_vendor)
        key = bssid
        if key in self.rogue_index:
            idx = self.rogue_index[key]
            row = self.rogue_results[idx]
            # Refresh live fields, keep the highest score seen with its evidence
            row[3] = rssi
            row[7] = uptime_str
            if score >= row[8]:
                row[4], row[5], row[6] = encryption, mfpc, mfpr
                row[8], row[9], row[10] = score, risk, "; ".join(reasons)
            row[2] = channel
        else:
            row = [bssid, ssid, channel, rssi,
                   encryption, mfpc, mfpr, uptime_str, score, risk, "; ".join(reasons)]
            self.rogue_index[key] = len(self.rogue_results)
            self.rogue_results.append(row)
        try:
            self.render_rogue_table()
        except Exception:
            pass

    def render_rogue_table(self):
        """Live rogue-candidate table (gated to the rogue view)."""
        if not self._can_render("rogue"):
            return
        legit = self.rogue_legit or {}
        rows = sorted(self.rogue_results, key=lambda r: r[8], reverse=True)
        display = []
        for r in rows:
            bssid, ssid, ch, rssi, enc, mfpc, mfpr, uptime, score, risk, reasons = r
            rssi_s = "?" if rssi is None else f"{rssi} dBm"
            if risk == "HIGH":
                risk_s = f"{UI.RED}{risk}{UI.RESET}"
            elif risk == "MEDIUM":
                risk_s = f"{UI.YELLOW}{risk}{UI.RESET}"
            else:
                risk_s = f"{UI.DIM}{risk}{UI.RESET}"
            enc_s = f"{UI.RED}{enc}{UI.RESET}" if "open" in str(enc).lower() else f"{UI.GREEN}{enc}{UI.RESET}"
            display.append([
                f"{UI.GREEN}{bssid}{UI.RESET}",
                f"{UI.YELLOW}{ssid}{UI.RESET}",
                f"{UI.CYAN}{ch}{UI.RESET}",
                f"{UI.DIM}{rssi_s}{UI.RESET}",
                enc_s,
                f"{mfpc}/{mfpr}",
                f"{UI.DIM}{uptime}{UI.RESET}",
                f"{UI.BOLD}{score}{UI.RESET}",
                risk_s,
            ])
        with self._render_lock:
            os.system("clear")
            UI.print_banner()
            print(f"  {UI.DIM}Legit:{UI.RESET} {UI.YELLOW}{legit.get('ssid', '?')}{UI.RESET} / "
                  f"{UI.CYAN}{legit.get('bssid', '?')}{UI.RESET}  CH {UI.CYAN}{legit.get('channel', '?')}{UI.RESET}  "
                  f"ENC {UI.GREEN}{legit.get('encryption', '?')}{UI.RESET}  "
                  f"PMF {UI.DIM}{legit.get('mfpc', '?')}/{legit.get('mfpr', '?')}{UI.RESET}\n")
            if display:
                print(tabulate(display,
                               headers=["Suspect BSSID", "SSID", "CH", "RSSI", "Encryption",
                                        "MFPC/MFPR", "Uptime", "Score", "Risk"],
                               tablefmt="pretty"))
                highs = [r for r in rows if r[9] == "HIGH"]
                if highs:
                    print(f"\n  {UI.RED}{UI.BOLD}** Potential Evil Twin detected **{UI.RESET} "
                          f"{UI.DIM}({len(highs)} HIGH suspect(s) closely resemble(s) the legit AP){UI.RESET}")
                    for h in highs[:3]:
                        print(f"  {UI.RED}!{UI.RESET} {UI.CYAN}{h[0]}{UI.RESET} "
                              f"({UI.YELLOW}{h[1]}{UI.RESET} CH {h[2]} {h[4]}): {h[10]}")
            else:
                print(f"  {UI.DIM}No rogue candidates yet — listening...{UI.RESET}")
            try:
                conflicts = list((self.bssid_conflicts or {}).items())
            except Exception:
                conflicts = []
            if conflicts:
                print(f"\n  {UI.YELLOW}{UI.BOLD}Possible BSSID impersonation{UI.RESET} "
                      f"{UI.DIM}(same BSSID, conflicting beacons — verify, do not assume spoofing){UI.RESET}")
                for bssid, ev in conflicts[:5]:
                    print(f"  {UI.YELLOW}?{UI.RESET} {UI.CYAN}{bssid}{UI.RESET}: {ev}")
            print(f"\n  {UI.DIM}Same/similar SSID, different BSSID. Open + fresh uptime + PMF stripped = HIGH. Press CTRL+C to stop.{UI.RESET}\n")

    def _extract_pmf(self, pkt) -> Tuple[Any, Any]:
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 48:  # RSN IE
                data = bytes(elt.info)
                try:
                    # Skip version (2) + group cipher (4)
                    off = 6
                    p_count = int.from_bytes(data[off:off+2], "little")
                    off += 2 + (p_count * 4)
                    a_count = int.from_bytes(data[off:off+2], "little")
                    off += 2 + (a_count * 4)
                    rsn_caps = int.from_bytes(data[off:off+2], "little")
                    return (rsn_caps >> 7) & 1, (rsn_caps >> 6) & 1
                except:
                    break
            elt = elt.payload.getlayer(Dot11Elt)
        return "?", "?"

    def is_unicast(self, mac):
        first_byte = int(mac.split(':')[0], 16)
        return (first_byte & 1) == 0  # LSB = 0 → unicast

    @staticmethod
    def _channel_to_freq(channel) -> str:
        """Map a Wi-Fi channel number to a frequency string like '2412 MHz'."""
        try:
            ch = int(channel)
        except (TypeError, ValueError):
            return "?"
        try:
            from config import Config
            freq = Config._2GHZ.get(ch) or Config._5GHZ.get(ch)
        except Exception:
            freq = None
        if not freq:
            # Formula fallback for 2.4 GHz (ch 14 handled explicitly)
            if ch == 14:
                freq = 2484
            elif 1 <= ch <= 13:
                freq = 2407 + 5 * ch
            else:
                return "?"
        return f"{freq} MHz"

    def _extract_rssi(self, pkt) -> Any:
        """Extract RSSI (dBm) from RadioTap — returns int (e.g. -67) or None."""
        try:
            if pkt.haslayer(RadioTap):
                rt = pkt.getlayer(RadioTap)
                # Most reliable: dBm_AntSignal (present on Linux/mac80211)
                for attr in ("dBm_AntSignal", "dbm_antsignal", "dBm_AntennaSignal"):
                    try:
                        val = rt.getfieldval(attr)
                        if isinstance(val, int):
                            return val
                    except Exception:
                        pass
                    try:
                        if hasattr(rt, attr):
                            v = getattr(rt, attr)
                            if isinstance(v, int):
                                return v
                    except Exception:
                        pass
                # Fallback: generic 'Signal' / 'signal' field (some drivers)
                for attr in ("Signal", "signal", "RSSI"):
                    try:
                        val = rt.getfieldval(attr)
                        if isinstance(val, int):
                            return val
                    except Exception:
                        pass
                # Last resort — scan fields dict for anything containing signal/dbm/rssi
                try:
                    for k, v in dict(rt.fields).items():
                        lk = k.lower()
                        if ("signal" in lk or "dbm" in lk or "rssi" in lk) and isinstance(v, int):
                            return v
                except Exception:
                    pass
                # Scapy may store as rt.dBm_AntSignal directly with None check
                try:
                    if hasattr(rt, "dBm_AntSignal") and rt.dBm_AntSignal is not None:
                        return int(rt.dBm_AntSignal)
                except Exception:
                    pass
        except Exception:
            pass
        return None

    # this will scan for beacon frames
    def _note_bssid_fp(self, bssid: str, ssid=None, channel=None,
                       encryption=None, mfpc=None):
        """Track per-BSSID beacon fingerprints. Flags possible BSSID
        impersonation when ONE BSSID advertises conflicting attributes
        (channels / SSIDs / security) — cautious 'possible' wording only."""
        if not bssid:
            return
        try:
            key = str(bssid).lower()
            fp = self.bssid_fp.setdefault(
                key, {"ch": set(), "enc": set(), "ssid": set(), "mfpc": set()})
            if channel not in (None, "", "?"):
                fp["ch"].add(str(channel).strip())
            if encryption not in (None, "", "?"):
                fp["enc"].add(str(encryption).strip())
            if ssid not in (None, "") and str(ssid).strip().lower() \
                    not in ("<hidden>", "<malformed>", ""):
                fp["ssid"].add(str(ssid).strip())
            if mfpc not in (None, "", "?"):
                fp["mfpc"].add(str(mfpc).strip())
            conflicts = []
            if len(fp["ch"]) > 1:
                conflicts.append(f"channels {sorted(fp['ch'])}")
            if len(fp["ssid"]) > 1:
                conflicts.append(f"SSIDs {sorted(fp['ssid'])}")
            if len(fp["enc"]) > 1:
                conflicts.append(f"security {sorted(fp['enc'])}")
            if conflicts:
                self.bssid_conflicts[key] = ("Same BSSID seen with " + "; ".join(conflicts)
                                             + " — possible impersonation; verify against inventory")
            elif key in self.bssid_conflicts and not conflicts:
                pass  # keep first evidence once flagged
        except Exception:
            pass

    def beacon_frame(self, pkt):
        if not pkt.haslayer(Dot11) or pkt.subtype != 0x08:  # Beacon only
            return

        bssid = pkt[Dot11].addr2
        # Extract RSSI early so we can update existing rows with live signal
        rssi = self._extract_rssi(pkt)
        if bssid in self.seen_bssids:
            # Update RSSI + last-seen live even though we don't add a duplicate row
            for _row in self.results:
                if _row[0] == bssid:
                    _row[2] = rssi  # column 2 = RSSI after header insertion
                    if len(_row) > 19:
                        _row[19] = time.strftime("%H:%M:%S")
                    # Fingerprint the NEW packet (not the stored row) so channel /
                    # SSID / security conflicts on a reused BSSID surface here.
                    try:
                        try:
                            _stats = pkt.getlayer(Dot11Beacon).network_stats()
                        except Exception:
                            _stats = {}
                        _nssid = _stats.get("ssid")
                        _nch = _stats.get("channel")
                        if not _nch:
                            try:
                                if pkt.haslayer(RadioTap) and pkt[RadioTap].Channel:
                                    _f = pkt[RadioTap].Channel
                                    _nch = (_f - 2407) // 5 if _f < 5000 else (_f - 5000) // 5
                            except Exception:
                                _nch = None
                        _nenc = ", ".join(sorted(_stats.get("crypto", {"Open"}))) \
                            if _stats.get("crypto") else "Open"
                        try:
                            _nmfpc, _ = self._extract_pmf(pkt)
                        except Exception:
                            _nmfpc = None
                        self._note_bssid_fp(
                            bssid,
                            _nssid or (_row[3] if len(_row) > 3 else None),
                            _nch or (_row[1] if len(_row) > 1 else None),
                            _nenc or (_row[4] if len(_row) > 4 else None),
                            _nmfpc if _nmfpc not in (None, "") else (_row[5] if len(_row) > 5 else None))
                    except Exception:
                        pass
                    break
            self.ap_last_seen[bssid] = time.strftime("%H:%M:%S")
            # Re-render so user sees signal fluctuations without duplicate rows
            try:
                self.render_live_table()
            except Exception:
                pass
            return

        stats = {}
        try:
            stats = pkt[Dot11Beacon].network_stats()
        except:
            pass

        # ssid       = stats.get('ssid', '<Hidden>')
        ssid = stats.get('ssid') or ('<Malformed>' if 'ssid' in stats else '<Hidden>')
        # encryption = stats.get('crypto', 'Open')
        encryption = ', '.join(sorted(stats.get('crypto', {'Open'}))) if stats.get('crypto') else 'Open'

        # Channel resolution
        channel = stats.get('channel')
        if not channel and pkt.haslayer(RadioTap):
            freq = pkt[RadioTap].Channel
            if freq:
                channel = (freq - 2407) // 5 if freq < 5000 else (freq - 5000) // 5

        mfpc, mfpr   = self._extract_pmf(pkt)
        wps          = False
        dtim_period  = None
        group_cipher = None   # RSN group cipher suite (last byte = suite type)
        akm_suite    = None   # RSN AKM suite type
        has_wpa1     = False  # Vendor IE WPA1 (00:50:F2:01) alongside RSN = downgrade risk
        beacon_int   = None   # Non-standard beacon interval flags misconfigured AP
        has_rrm      = False  # 802.11k Radio Resource Management
        bss_trans    = False  # 802.11v BSS Transition (client steering capable)
        has_ht       = False  # 802.11n (HT Capabilities, Tag 45)
        has_vht      = False  # 802.11ac (VHT Capabilities, Tag 191)
        has_he       = False  # 802.11ax (HE ext IDs 35/36 under Element ID 255)
        has_eht      = False  # 802.11be (EHT ext IDs, where detectable)
        has_mobdom   = False  # 802.11r hint (Mobility Domain IE, Tag 54)
        tsf          = None
        tsf_uptime   = None

        # Beacon interval lives in fixed params (Dot11Beacon), not an IE
        if pkt.haslayer(Dot11Beacon):
            beacon_int = pkt[Dot11Beacon].beacon_interval
            tsf        = pkt[Dot11Beacon].timestamp # raw microseconds (u64)
            if tsf is not None:
                total_secs  = tsf // 1_000_000
                days        = total_secs // 86400
                hours       = (total_secs % 86400) // 3600
                minutes     = (total_secs % 3600) // 60
                seconds     = total_secs % 60
                # tsf_uptime  = f"{days}d {hours:02}:{minutes:02}:{seconds:02}"
                tsf_uptime  = f"{days}d {hours}h {minutes}m {seconds}s"

        elt = pkt.getlayer(Dot11Elt)
        while elt:

            # TIM — Tag 5
            if elt.ID == 5 and elt.info and len(elt.info) >= 2:
                dtim_period = elt.info[1]

            # RSN IE — Tag 48: extract group cipher + AKM suite
            if elt.ID == 48:
                data = bytes(elt.info)
                try:
                    off = 2  # skip RSN version
                    group_cipher = data[off + 3]  # last byte of group cipher suite = suite type
                    off += 4
                    p_count = int.from_bytes(data[off:off+2], "little")
                    off += 2 + (p_count * 4)
                    a_count = int.from_bytes(data[off:off+2], "little")
                    off += 2
                    akm_suite = data[off + 3]  # last byte of first AKM suite = suite type
                except:
                    pass

            # Vendor IE — Tag 221
            if elt.ID == 221 and elt.info and len(elt.info) >= 4:
                if elt.info[:4] == b'\x00\x50\xf2\x04':  # WPS
                    wps = True
                if elt.info[:4] == b'\x00\x50\xf2\x01':  # WPA1 IE — downgrade risk if RSN also present
                    has_wpa1 = True

            # RM Enabled Capabilities — Tag 70: bit 0 = Neighbor Report (802.11k)
            if elt.ID == 70 and elt.info:
                has_rrm = bool(elt.info[0] & 0x01)

            # Extended Capabilities — Tag 127: bit 19 = BSS Transition (802.11v)
            if elt.ID == 127 and elt.info and len(elt.info) >= 3:
                bss_trans = bool(elt.info[2] & 0x08)

            # PHY generations — best-effort, where detectable in IEs
            if elt.ID == 45:    # HT Capabilities → 802.11n
                has_ht = True
            elif elt.ID == 191:  # VHT Capabilities → 802.11ac
                has_vht = True
            elif elt.ID == 54:   # Mobility Domain → 802.11r (Fast Transition)
                has_mobdom = True
            elif elt.ID == 255 and elt.info and len(elt.info) >= 1:
                try:
                    ext_id = elt.info[0]
                    if ext_id in (35, 36):       # HE Capabilities / HE Operation → 802.11ax
                        has_he = True
                    elif ext_id in (108, 109, 110, 113):  # EHT Capabilities/Operation → 802.11be
                        has_eht = True
                except Exception:
                    pass

            elt = elt.payload.getlayer(Dot11Elt)

        # Capability string: most modern generation advertised (best effort)
        if has_eht:
            std = "BE?"
        elif has_he:
            std = "AX"
        elif has_vht:
            std = "AC"
        elif has_ht:
            std = "N"
        else:
            std = "A/B/G"
        freq = self._channel_to_freq(channel)
        now_wall = time.strftime("%H:%M:%S")
        self.ap_first_seen[bssid] = now_wall
        self.ap_last_seen[bssid] = now_wall

        # no need to add Beacon
        row = [
            bssid, channel or "?", rssi, ssid, encryption,
            mfpc, mfpr, wps, dtim_period,
            group_cipher, akm_suite, has_wpa1,
            beacon_int, has_rrm, bss_trans, tsf_uptime,
            freq, std, now_wall, now_wall, has_mobdom,
        ]
        # I'll have to change the indexs if I do this
        # rathern remove "Beacon" in render_live_table instead
        # row = [
        #     bssid, channel or "?", ssid, encryption,
        #     mfpc, mfpr, wps, dtim_period,
        #     group_cipher, akm_suite, has_wpa1,
        #     beacon_int, has_rrm, bss_trans, tsf_uptime,
        # ]
        self.results.append(row)
        self.seen_bssids.add(bssid)
        try:
            self._note_bssid_fp(bssid, ssid, channel or "?", encryption, mfpc)
        except Exception:
            pass
        self.render_live_table()

    # ── WPA handshake / EAP / PMKID parsing (passive helpers) ──────────────
    _EAP_METHODS = {1: "Identity", 3: "NAK", 4: "MD5", 13: "TLS", 18: "SIM",
                    21: "TTLS", 23: "AKA", 25: "PEAP", 43: "FAST", 50: "AKA'",
                    52: "PWD", 55: "TEAP"}

    @staticmethod
    def _eapol_raw(pkt):
        """Raw bytes of the EAPOL layer, or None."""
        try:
            raw = bytes(pkt.getlayer(EAPOL))
            return raw if len(raw) >= 4 else None
        except Exception:
            return None

    @classmethod
    def _eapol_msgnum(cls, key_info: int):
        """Map RSN key-info bits to WPA handshake message 1-4 (or None).

        Key-info (big-endian): bit7 Ack, bit8 MIC, bit6 Install, bit9 Secure.
        M1=(Ack,MIC)=(1,0)  M2=(0,1)+!Secure+!Install
        M3=(1,1)+Install    M4=(0,1)+Secure.
        """
        try:
            ack = (key_info >> 7) & 1
            mic = (key_info >> 8) & 1
            install = (key_info >> 6) & 1
            secure = (key_info >> 9) & 1
            if ack and not mic:
                return 1
            if mic and not ack and not secure and not install:
                return 2
            if ack and mic and install:
                return 3
            if mic and not ack and secure:
                return 4
        except Exception:
            pass
        return None

    @classmethod
    def _parse_eapol(cls, pkt):
        """Parse an EAPOL frame. Returns dict with kind 'key'|'eap'|'other'.

        key  -> {"msg": 1-4|None, "pmkid": hex|None}
        eap  -> {"code": int, "method": str|None}
        Pure parsing — no I/O, no state changes.
        """
        raw = cls._eapol_raw(pkt)
        if not raw:
            return {"kind": "other"}
        try:
            etype = raw[1]
            if etype == 3 and len(raw) >= 7:  # Key frame
                key_info = int.from_bytes(raw[5:7], "big")
                out = {"kind": "key", "msg": cls._eapol_msgnum(key_info), "pmkid": None}
                # Key-data starts after the 95-byte fixed key descriptor
                if len(raw) >= 99:
                    try:
                        kd_len = int.from_bytes(raw[97:99], "big")
                        kd = raw[99:99 + kd_len] if kd_len else b""
                        i = kd.find(b"\x00\x0f\xac\x04")  # PMKID KDE selector (OUI + type)
                        if i >= 0 and len(kd) >= i + 4 + 16:
                            out["pmkid"] = kd[i + 4:i + 20].hex()
                    except Exception:
                        pass
                return out
            if etype == 0 and len(raw) >= 9:  # EAP packet
                code = raw[4]
                method = None
                if code in (1, 2) and len(raw) >= 9:
                    method = cls._EAP_METHODS.get(raw[8], f"Type-{raw[8]}")
                return {"kind": "eap", "code": code, "method": method}
        except Exception:
            pass
        return {"kind": "other"}

    @staticmethod
    def _rsn_pmkid_count(info: bytes) -> int:
        """PMKID count from an RSN IE body (Tag 48 info bytes). 0 if absent."""
        try:
            data = bytes(info)
            off = 2 + 4  # version + group suite
            if len(data) < off + 2:
                return 0
            p_count = int.from_bytes(data[off:off + 2], "little")
            off += 2 + p_count * 4
            if len(data) < off + 2:
                return 0
            a_count = int.from_bytes(data[off:off + 2], "little")
            off += 2 + a_count * 4 + 2  # akm suites + capabilities
            if len(data) < off + 2:
                return 0
            return int.from_bytes(data[off:off + 2], "little")
        except Exception:
            return 0

    def _hs_state(self, mac: str) -> dict:
        """Per-client handshake record (created on demand)."""
        st = self.client_handshake.get(mac)
        if st is None:
            st = {"msgs": set(), "complete": False, "eap": set(), "pmkid": False}
            self.client_handshake[mac] = st
        return st

    @staticmethod
    def _hs_label(st: dict) -> str:
        """Compact handshake/EAP label for tables, e.g. '4/4|PEAP', '2/4+PMKID'."""
        try:
            msgs = sorted(m for m in st.get("msgs", set()) if m in (1, 2, 3, 4))
            hs = "4/4" if st.get("complete") else (f"{len(msgs)}/4" if msgs else "--")
            eap = ",".join(sorted(st.get("eap", set())))
            label = hs + (f"|{eap}" if eap else "")
            if st.get("pmkid"):
                label += "+PMKID"
            return label
        except Exception:
            return "--"

    # this will extract/enumerate connected clients
    # will only look for data frames.
    # i thought management frame's subtype 0x01 (association response)
    # status code could be used to identify connected clients (checking status_code == 0)
    # however, even though i intentionally provided wrong password
    # it still set the status_code to 0 in the association response
    # so i/we can't really trust association responses
    # hence, only inspect the data frames (subtypes = Data, QoS Data, )
    # we need to switch channels to be on that radio frequency
    # the target AP is residing on
    def data_frames(self, pkt, s_bssid, iface, channel):
        if not s_bssid:
            return
        InterfaceManager.set_channel(iface, channel)

        if not pkt.haslayer(Dot11):
            return

        dot11 = pkt.getlayer(Dot11)

        # ── Presence heartbeat: any transmitted packet keeps client Connected ──
        # Any frame from a known client proves it is still present and refreshes
        # the 15s timer. A Disconnected client seen transmitting becomes Connected.
        # Passive metadata (RSSI / wall-clock seen) is refreshed for any src.
        try:
            pkt_rssi = self._extract_rssi(pkt)
            src = (dot11.addr2 or "").lower()
            if src and src in (m.lower() for m in self.seen_clients):
                now_hb = time.monotonic()
                self.client_last_seen[src] = now_hb
                self.client_last_any[src] = now_hb
                self._note_client_activity(src, rssi=pkt_rssi if isinstance(pkt_rssi, int) else None)
                if self.client_status.get(src) == "Disconnected":
                    self.client_status[src] = "Connected"
                    self._update_row_status(src)
                    self.render_client_table()
        except Exception:
            pass

        # ------------------------------------------------------------------ #
        #  DEAUTH — type 0 (management), subtype 12 (0x0C)                    #
        #  Flag the client as Disconnected whether AP or client sent it.       #
        #  addr1 = destination, addr2 = source                                 #
        # ------------------------------------------------------------------ #
        if dot11.type == 0x00 and dot11.subtype == 0x0C:
            # AP → Client deauth  (addr1=client, addr2=bssid)
            if dot11.addr2 == s_bssid and dot11.addr1 and self.is_unicast(dot11.addr1):
                target = dot11.addr1
            # Client → AP deauth  (addr1=bssid, addr2=client)
            elif dot11.addr1 == s_bssid and dot11.addr2 and self.is_unicast(dot11.addr2):
                target = dot11.addr2
            else:
                target = None

            if target and target in self.client_status:
                self.client_status[target] = "Disconnected"
                self._update_row_status(target)
                self.render_client_table()
            return

        # ------------------------------------------------------------------ #
        #  DISASSOC — type 0 (management), subtype 10 (0x0A)                  #
        #  Same logic as deauth — also marks client as Disconnected.          #
        # ------------------------------------------------------------------ #
        if dot11.type == 0x00 and dot11.subtype == 0x0A:
            # AP → Client disassoc  (addr1=client, addr2=bssid)
            if dot11.addr2 == s_bssid and dot11.addr1 and self.is_unicast(dot11.addr1):
                target = dot11.addr1
            # Client → AP disassoc  (addr1=bssid, addr2=client)
            elif dot11.addr1 == s_bssid and dot11.addr2 and self.is_unicast(dot11.addr2):
                target = dot11.addr2
            else:
                target = None

            if target and target in self.client_status:
                self.client_status[target] = "Disconnected"
                self._update_row_status(target)
                self.render_client_table()
            return

        # ------------------------------------------------------------------ #
        #  RECONNECT SIGNALS — mark Disconnected clients as Connected again   #
        #                                                                      #
        #  1. Association Response (mgmt subtype 1) — AP approves client      #
        #  2. EAPOL — 4-way handshake, key exchange after association         #
        #  3. Data frames — actual traffic = definitely connected              #
        #  (Authentication frames, subtype 11, are counted as activity        #
        #  evidence only — they never change connection state.)                #
        # ------------------------------------------------------------------ #

        # 0. Authentication activity (type 0, subtype 11) — passive counter only
        if dot11.type == 0x00 and dot11.subtype == 0x0B:
            try:
                if dot11.addr1 == s_bssid and dot11.addr2 and self.is_unicast(dot11.addr2):
                    if dot11.addr2 in self.seen_clients:
                        self._note_client_activity(dot11.addr2, kind="auth")
                elif dot11.addr2 == s_bssid and dot11.addr1 and self.is_unicast(dot11.addr1):
                    if dot11.addr1 in self.seen_clients:
                        self._note_client_activity(dot11.addr1, kind="auth")
            except Exception:
                pass
            return

        # 0b. Association Request (type 0, subtype 0) — passive activity +
        # PMKID-exposure check. Never creates rows or changes state.
        if dot11.type == 0x00 and dot11.subtype == 0x00:
            try:
                if dot11.addr1 == s_bssid and dot11.addr2 and self.is_unicast(dot11.addr2):
                    cli = dot11.addr2
                    elt = pkt.getlayer(Dot11Elt)
                    while elt:
                        try:
                            if elt.ID == 48 and self._rsn_pmkid_count(bytes(elt.info)) > 0:
                                self._hs_state(cli)["pmkid"] = True
                                break
                            elt = elt.payload.getlayer(Dot11Elt)
                        except Exception:
                            break
                    if cli in self.seen_clients:
                        self._note_client_activity(cli, kind="assoc")
            except Exception:
                pass
            return

        # 1. Association Response: type 0, subtype 1
        #    addr1=client (destination), addr2=bssid (source)
        if dot11.type == 0x00 and dot11.subtype == 0x01:
            if dot11.addr2 == s_bssid and dot11.addr1 and self.is_unicast(dot11.addr1):
                try:
                    ar_rssi = self._extract_rssi(pkt)
                except Exception:
                    ar_rssi = None
                self._mark_connected(dot11.addr1, s_bssid,
                                     rssi=ar_rssi if isinstance(ar_rssi, int) else None,
                                     kind="assoc")
                self.render_client_table()
            return

        # 2. EAPOL frames ride inside Dot11 data frames (type 2).
        #    Type 3 (Key)  → handshake message tracking + PMKID + Connected.
        #    Type 0 (EAP)  → EAP-method observation only (never changes state).
        if pkt.haslayer(EAPOL) and dot11.type == 0x02:
            try:
                eo_rssi = self._extract_rssi(pkt)
            except Exception:
                eo_rssi = None
            eo_rssi = eo_rssi if isinstance(eo_rssi, int) else None
            parsed = self._parse_eapol(pkt)
            cli = None
            try:
                # Client → AP
                if dot11.addr1 == s_bssid and dot11.addr2 and self.is_unicast(dot11.addr2):
                    cli = dot11.addr2
                # AP → Client
                elif dot11.addr2 == s_bssid and dot11.addr1 and self.is_unicast(dot11.addr1):
                    cli = dot11.addr1
            except Exception:
                cli = None
            if parsed.get("kind") == "eap":
                # Passive EAP-method observation (enterprise assessment data)
                try:
                    if cli and parsed.get("method"):
                        self._hs_state(cli)["eap"].add(parsed["method"])
                        if cli in self.seen_clients:
                            self._note_client_activity(cli)
                except Exception:
                    pass
                return
            if cli:
                # Key frame: track handshake progress + PMKID exposure
                try:
                    if parsed.get("kind") == "key":
                        st = self._hs_state(cli)
                        if parsed.get("msg") in (1, 2, 3, 4):
                            st["msgs"].add(parsed["msg"])
                            if {1, 2, 3, 4} <= st["msgs"]:
                                st["complete"] = True
                        # M1 AP→client carrying a PMKID enables offline PMKID attacks
                        if parsed.get("msg") == 1 and parsed.get("pmkid") \
                                and dot11.addr2 == s_bssid:
                            st["pmkid"] = True
                            self.ap_pmkid.setdefault(s_bssid.lower(), parsed["pmkid"])
                except Exception:
                    pass
            # Client → AP
            if dot11.addr1 == s_bssid and dot11.addr2 and self.is_unicast(dot11.addr2):
                self._mark_connected(dot11.addr2, s_bssid, rssi=eo_rssi, kind="eapol")
                self.render_client_table()
            # AP → Client
            elif dot11.addr2 == s_bssid and dot11.addr1 and self.is_unicast(dot11.addr1):
                self._mark_connected(dot11.addr1, s_bssid, rssi=eo_rssi, kind="eapol")
                self.render_client_table()
            return

        # 3. Regular data frames — type 2
        # type2 = data frame
        # https://mrncciew.com/2014/11/03/cwap-data-frame-address-fields/
        if dot11.type == 0x02:
            fc_type = dot11.type
            fc_subtype = dot11.subtype
            # to-destination
            to_ds = dot11.FCfield & 0x01 # 1st bit (bit 0)
            # from-destination
            from_ds = dot11.FCfield & 0x02 # 2nd bit (bit 1)

            ap_mac     = None
            client_mac = None

            # as per https://mrncciew.com/wp-content/uploads/2014/11/cwap-data-address-01.png?w=768&h=266
            # 1. Client to AP
            if to_ds == 1 and from_ds == 0 and dot11.addr1 == s_bssid:
                # print("[+] Client to AP (Associated)")
                # UI.info("[+] Client to AP (Associated)")
                # we extract the connected clients
                # by readin the Address2 field (which is the transmitting address)
                # client_mac = dot11.addr2
                # client_mac = dot11.addr2 if int(dot11.addr2.split(':')[0], 16) % 2 == 0 else None
                client_mac = dot11.addr2 if dot11.addr2 and self.is_unicast(dot11.addr2) else None
                # client_mac = dot11.addr2
                ap_mac = dot11.addr1
                # we also need to first check if it's a unicast mac
                # extract the 1st octet of a mac
                # convert it into 8 bit binary
                # check if last bit is 0 (unicast)
                # also check for ff:ff:ff:ff:ff:ff (exclusion)
                # delimeter (:)
                # f_octet = str(client_mac).split(":")[0]
                # c_mac_type = type(client_mac)
                # if client_mac in self.seen_clients:
                #     return
                # will show a proper table
                # UI.info(f"[+] Client:- {client_mac} - AP:- {ap_mac}")

            # i'll not check this at all, as i found nothing
            # elif to_ds == 0 and from_ds == 1:
                # vice-versa for previos if
                # client_mac = dot11.addr1
                # ap_mac = dot11.addr2
                # print("")
                # UI.info("[+] AP to Client")
                # UI.info(f"[+] Client:- {client_mac} - AP:- {ap_mac}")

            if not ap_mac or not client_mac:
                return

            # Any data frame transmitted by the client = client is Connected.
            # Any transmitted packet refreshes the 15s timer.
            try:
                data_rssi = self._extract_rssi(pkt)
            except Exception:
                data_rssi = None
            data_rssi = data_rssi if isinstance(data_rssi, int) else None
            # New client — add row for the first time
            if client_mac not in self.seen_clients:
                ap_vendor     = self._lookup_oui(ap_mac)
                client_vendor = self._lookup_oui(client_mac)
                self.client_status[client_mac] = "Connected"
                now_ts = time.monotonic()
                self.client_last_seen[client_mac] = now_ts
                self.client_last_any[client_mac] = now_ts
                self._note_client_activity(client_mac, rssi=data_rssi, kind="data")
                now_wall = time.strftime("%H:%M:%S")
                first = self.client_first_seen.get(client_mac, now_wall)
                rssi_s = f"{data_rssi} dBm" if isinstance(data_rssi, int) else "?"
                row = [ap_mac, ap_vendor, client_mac, client_vendor, "Connected",
                       rssi_s, first, now_wall]
                self.client_results.append(row)
                self.seen_clients.add(client_mac)
            else:
                # Known client — refresh timestamp, ensure Connected
                now_ts = time.monotonic()
                self.client_last_seen[client_mac] = now_ts
                self.client_last_any[client_mac] = now_ts
                self._note_client_activity(client_mac, rssi=data_rssi, kind="data")
                if self.client_status.get(client_mac) != "Connected":
                    self.client_status[client_mac] = "Connected"
                    self._update_row_status(client_mac)

            self.render_client_table()

    # now it's time to code the vulnerability assessment engine.
    def vuln_assessment(self, pkt, s_bssid, iface, channel):
        # in this case, we'll get the following information
        # 1. Management Frame Protection Capable/Required
        # 2. WPS Extension Information Element
        # 3. Encryption Analysis
        # 4. Group Cipher
        # 5. AKM Suite
        # 6. WPA1 presence
        # 7. RRM and BSS Transition presence
        if not s_bssid:
            return
        InterfaceManager.set_channel(iface, channel)

        if not pkt.haslayer(Dot11):
            return

        dot11 = pkt.getlayer(Dot11)

        # We only care about Probe Responses here (type=0 management, subtype=5)
        # A Probe Response is unicast back to whichever client sent the Probe Request,
        # so addr2 (source) will be the AP's BSSID.
        if not (dot11.type == 0x00 and dot11.subtype == 0x05):
            return

        # Only process responses from the AP we are targeting
        if dot11.addr2 != s_bssid:
            return

        # ------------------------------------------------------------------ #
        #  Pull security fields from the Probe Response                        #
        #  Same IE layout as a Beacon frame, so we reuse the same parser       #
        #  logic that already exists in beacon_frame().                        #
        # ------------------------------------------------------------------ #

        # --- PMF (MFPC / MFPR) from RSN IE -------------------------------- #
        mfpc, mfpr = self._extract_pmf(pkt)

        # --- Walk every Information Element -------------------------------- #
        encryption   = "Open"
        group_cipher = None
        akm_suite    = None
        has_wpa1     = False
        has_rrm      = False
        bss_trans    = False
        wps_present  = False

        # WPS detail fields
        wps_version       = None   # WPS Version (0x104A)
        wps_state         = None   # WPS State: 0x01=Unconfigured, 0x02=Configured (0x1044)
        wps_config_error  = None   # Config Error code (0x1009)
        wps_dev_pass_id   = None   # Device Password ID — tells us the WPS method (0x1012)
                                   #   0x0000 = PIN (default)
                                   #   0x0004 = PBC (push-button)
                                   #   0x0005 = Registrar-specified PIN
                                   #   0x0007 = NFC
        wps_selected_reg  = None   # Selected Registrar flag (0x1041) — True if button was pressed
        wps_rf_bands      = None   # RF Bands bitmap (0x103C): 0x01=2.4GHz, 0x02=5GHz
        wps_manufacturer  = None   # Device Manufacturer string (0x1021)
        wps_model_name    = None   # Device Model Name (0x1023)
        wps_model_number  = None   # Device Model Number (0x1024)
        wps_serial        = None   # Serial Number (0x1042)
        wps_dev_name      = None   # Device Name (0x1011)
        wps_uuid_e        = None   # UUID-E (0x1047) — 16-byte unique AP identity
        wps_primary_type  = None   # Primary Device Type (0x1054) — category:sub-category
        wps_response_type = None   # Response Type (0x103B): 0x03=AP
        wps_setup_locked  = None   # AP Setup Locked (0x1057) — True = WPS is locked out

        elt = pkt.getlayer(Dot11Elt)
        while elt:

            # RSN IE (Tag 48) — WPA2/WPA3 encryption details
            if elt.ID == 48:
                data = bytes(elt.info)
                try:
                    off = 2  # skip RSN version (2 bytes)
                    group_cipher = data[off + 3]  # suite type byte of group cipher
                    off += 4
                    p_count = int.from_bytes(data[off:off+2], "little")
                    off += 2 + (p_count * 4)
                    a_count = int.from_bytes(data[off:off+2], "little")
                    off += 2
                    akm_suite = data[off + 3]  # suite type byte of first AKM
                except:
                    pass
                # presence of RSN IE means at least WPA2
                encryption = "WPA2"

            # Vendor IE (Tag 221) — WPA1 and WPS both live here
            if elt.ID == 221 and elt.info and len(elt.info) >= 4:

                # WPA1 IE: OUI 00:50:F2, Type 0x01
                # If both RSN IE and WPA1 IE are present, the AP advertises a
                # WPA1 fallback — a potential downgrade attack vector.
                if elt.info[:4] == b'\x00\x50\xf2\x01':
                    has_wpa1 = True
                    if encryption == "Open":
                        encryption = "WPA"

                # WPS IE: OUI 00:50:F2, Type 0x04
                # The WPS IE is a TLV blob (2-byte Type + 2-byte Length + Value).
                # All multi-byte fields inside are big-endian.
                if elt.info[:4] == b'\x00\x50\xf2\x04':
                    wps_present = True
                    payload = bytes(elt.info[4:])  # skip the 4-byte OUI+Type header
                    idx = 0
                    while idx + 4 <= len(payload):
                        attr_type = int.from_bytes(payload[idx:idx+2],   "big")
                        attr_len  = int.from_bytes(payload[idx+2:idx+4], "big")
                        idx += 4
                        if idx + attr_len > len(payload):
                            break  # truncated IE — bail out safely
                        attr_val = payload[idx:idx+attr_len]
                        idx += attr_len

                        if attr_type == 0x104A:  # Version
                            # One byte: major nibble | minor nibble
                            wps_version = f"{attr_val[0] >> 4}.{attr_val[0] & 0x0F}" if attr_val else None

                        elif attr_type == 0x1044:  # Wi-Fi Protected Setup State
                            if attr_val:
                                wps_state = "Unconfigured" if attr_val[0] == 0x01 else "Configured"

                        elif attr_type == 0x1009:  # Config Error
                            if len(attr_val) >= 2:
                                wps_config_error = int.from_bytes(attr_val, "big")

                        elif attr_type == 0x1012:  # Device Password ID — the WPS method
                            if len(attr_val) >= 2:
                                dpid = int.from_bytes(attr_val, "big")
                                # Human-readable WPS method
                                _dpid_map = {
                                    0x0000: "PIN (default)",
                                    0x0004: "PBC (Push-Button)",
                                    0x0005: "Registrar PIN",
                                    0x0007: "NFC Token",
                                }
                                wps_dev_pass_id = _dpid_map.get(dpid, f"Unknown (0x{dpid:04x})")

                        elif attr_type == 0x1041:  # Selected Registrar
                            # 0x01 = button has been pressed, WPS session is active
                            wps_selected_reg = bool(attr_val[0]) if attr_val else None

                        elif attr_type == 0x103C:  # RF Bands
                            if attr_val:
                                bands = []
                                if attr_val[0] & 0x01:
                                    bands.append("2.4 GHz")
                                if attr_val[0] & 0x02:
                                    bands.append("5 GHz")
                                wps_rf_bands = ", ".join(bands) if bands else f"0x{attr_val[0]:02x}"

                        elif attr_type == 0x1021:  # Manufacturer
                            wps_manufacturer = attr_val.decode("utf-8", errors="replace").rstrip("\x00")

                        elif attr_type == 0x1023:  # Model Name
                            wps_model_name = attr_val.decode("utf-8", errors="replace").rstrip("\x00")

                        elif attr_type == 0x1024:  # Model Number
                            wps_model_number = attr_val.decode("utf-8", errors="replace").rstrip("\x00")

                        elif attr_type == 0x1042:  # Serial Number
                            wps_serial = attr_val.decode("utf-8", errors="replace").rstrip("\x00")

                        elif attr_type == 0x1011:  # Device Name
                            wps_dev_name = attr_val.decode("utf-8", errors="replace").rstrip("\x00")

                        elif attr_type == 0x1047:  # UUID-E (16 bytes)
                            # Format as standard 8-4-4-4-12 UUID string
                            if len(attr_val) == 16:
                                h = attr_val.hex()
                                wps_uuid_e = f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

                        elif attr_type == 0x1054:  # Primary Device Type (8 bytes)
                            # Bytes 0-1: category, bytes 6-7: sub-category (both big-endian)
                            if len(attr_val) == 8:
                                cat     = int.from_bytes(attr_val[0:2], "big")
                                sub_cat = int.from_bytes(attr_val[6:8], "big")
                                wps_primary_type = f"cat={cat}, sub={sub_cat}"

                        elif attr_type == 0x103B:  # Response Type
                            # 0x00=Enrollee Info, 0x01=Enrollee Open, 0x02=Registrar, 0x03=AP
                            if attr_val:
                                _rtype_map = {
                                    0x00: "Enrollee Info", 0x01: "Enrollee Open",
                                    0x02: "Registrar",     0x03: "AP",
                                }
                                wps_response_type = _rtype_map.get(attr_val[0], f"0x{attr_val[0]:02x}")

                        elif attr_type == 0x1057:  # AP Setup Locked
                            # 0x01 = locked (too many failed PIN attempts)
                            wps_setup_locked = bool(attr_val[0]) if attr_val else None

            # RM Enabled Capabilities IE (Tag 70): bit 0 = Neighbor Report (802.11k)
            if elt.ID == 70 and elt.info:
                has_rrm = bool(elt.info[0] & 0x01)

            # Extended Capabilities IE (Tag 127): bit 19 = BSS Transition (802.11v)
            if elt.ID == 127 and elt.info and len(elt.info) >= 3:
                bss_trans = bool(elt.info[2] & 0x08)

            elt = elt.payload.getlayer(Dot11Elt)

        # ------------------------------------------------------------------ #
        #  Render vulnerability assessment as a styled tabulate table          #
        #  Same colour logic as render_live_table()                            #
        # ------------------------------------------------------------------ #

        GROUP_CIPHER_MAP = {
            0x00: "None",    0x01: "WEP-40",      0x02: "TKIP",
            0x04: "CCMP",    0x05: "WEP-104",      0x06: "AES-128-CMAC",
        }

        AKM_MAP = {
            0x01: "802.1X",     # Enterprise
            0x02: "PSK",        # WPA2-Personal
            0x03: "FT-802.1X",
            0x04: "FT-PSK",
            0x06: "PSK-SHA256",
            0x08: "SAE",        # WPA3-Personal
            0x12: "OWE",        # WPA3-Enhanced Open
        }

        # --- PMF styling -------------------------------------------------- #
        mfpc_s = f"{UI.GREEN}{mfpc}{UI.RESET}" if str(mfpc) == "1" else f"{UI.RED}{mfpc}{UI.RESET}"
        mfpr_s = f"{UI.GREEN}{mfpr}{UI.RESET}" if str(mfpr) == "1" else f"{UI.RED}{mfpr}{UI.RESET}"

        # --- Group Cipher styling ----------------------------------------- #
        gc_name = GROUP_CIPHER_MAP.get(group_cipher, f"0x{group_cipher:02x}" if group_cipher is not None else "?")
        if group_cipher in (0x02, 0x01, 0x05):  # TKIP, WEP-40, WEP-104
            gc_s = f"{UI.RED}{gc_name}{UI.RESET}"
        elif group_cipher == 0x04:               # CCMP
            gc_s = f"{UI.GREEN}{gc_name}{UI.RESET}"
        else:
            gc_s = f"{UI.DIM}{gc_name}{UI.RESET}"

        # --- AKM styling -------------------------------------------------- #
        akm_name = AKM_MAP.get(akm_suite, f"0x{akm_suite:02x}" if akm_suite is not None else "?")
        if akm_suite in (0x08, 0x01, 0x03, 0x12):  # SAE, 802.1X, FT-802.1X, OWE
            akm_s = f"{UI.GREEN}{akm_name}{UI.RESET}"
        elif akm_suite in (0x02, 0x04, 0x06):       # PSK variants
            akm_s = f"{UI.YELLOW}{akm_name}{UI.RESET}"
        else:
            akm_s = f"{UI.DIM}{akm_name}{UI.RESET}"

        # --- WPA1 styling ------------------------------------------------- #
        wpa1_s = f"{UI.RED}Yes{UI.RESET}" if has_wpa1 else f"{UI.GREEN}No{UI.RESET}"

        # --- RRM / BSS-Trans styling --------------------------------------- #
        rrm_s  = f"{UI.YELLOW}Yes{UI.RESET}" if has_rrm   else f"{UI.DIM}No{UI.RESET}"
        bsst_s = f"{UI.YELLOW}Yes{UI.RESET}" if bss_trans else f"{UI.DIM}No{UI.RESET}"

        # --- WPS styling -------------------------------------------------- #
        if not wps_present:
            wps_present_s  = f"{UI.DIM}No{UI.RESET}"
            wps_version_s  = f"{UI.DIM}N/A{UI.RESET}"
            wps_state_s    = f"{UI.DIM}N/A{UI.RESET}"
            wps_method_s   = f"{UI.DIM}N/A{UI.RESET}"
            wps_selreg_s   = f"{UI.DIM}N/A{UI.RESET}"
            wps_locked_s   = f"{UI.DIM}N/A{UI.RESET}"
            wps_cfgerr_s   = f"{UI.DIM}N/A{UI.RESET}"
            wps_bands_s    = f"{UI.DIM}N/A{UI.RESET}"
            wps_rtype_s    = f"{UI.DIM}N/A{UI.RESET}"
            wps_mfr_s      = f"{UI.DIM}N/A{UI.RESET}"
            wps_mname_s    = f"{UI.DIM}N/A{UI.RESET}"
            wps_mnum_s     = f"{UI.DIM}N/A{UI.RESET}"
            wps_serial_s   = f"{UI.DIM}N/A{UI.RESET}"
            wps_devname_s  = f"{UI.DIM}N/A{UI.RESET}"
            wps_primtype_s = f"{UI.DIM}N/A{UI.RESET}"
            wps_uuid_s     = f"{UI.DIM}N/A{UI.RESET}"
        else:
            wps_present_s  = f"{UI.GREEN}Yes{UI.RESET}"
            wps_version_s  = f"{UI.CYAN}{wps_version}{UI.RESET}"         if wps_version       else f"{UI.DIM}?{UI.RESET}"
            wps_state_s    = f"{UI.YELLOW}{wps_state}{UI.RESET}"         if wps_state         else f"{UI.DIM}?{UI.RESET}"
            wps_method_s   = f"{UI.RED}{wps_dev_pass_id}{UI.RESET}"      if wps_dev_pass_id   else f"{UI.DIM}?{UI.RESET}"
            wps_selreg_s   = f"{UI.RED}Yes{UI.RESET}"                    if wps_selected_reg  else f"{UI.DIM}No{UI.RESET}"
            wps_locked_s   = f"{UI.RED}Yes{UI.RESET}"                    if wps_setup_locked  else f"{UI.GREEN}No{UI.RESET}"
            wps_cfgerr_s   = f"{UI.YELLOW}{wps_config_error}{UI.RESET}"  if wps_config_error  else f"{UI.DIM}?{UI.RESET}"
            wps_bands_s    = f"{UI.CYAN}{wps_rf_bands}{UI.RESET}"        if wps_rf_bands      else f"{UI.DIM}?{UI.RESET}"
            wps_rtype_s    = f"{UI.CYAN}{wps_response_type}{UI.RESET}"   if wps_response_type else f"{UI.DIM}?{UI.RESET}"
            wps_mfr_s      = f"{UI.CYAN}{wps_manufacturer}{UI.RESET}"    if wps_manufacturer  else f"{UI.DIM}?{UI.RESET}"
            wps_mname_s    = f"{UI.CYAN}{wps_model_name}{UI.RESET}"      if wps_model_name    else f"{UI.DIM}?{UI.RESET}"
            wps_mnum_s     = f"{UI.CYAN}{wps_model_number}{UI.RESET}"    if wps_model_number  else f"{UI.DIM}?{UI.RESET}"
            wps_serial_s   = f"{UI.CYAN}{wps_serial}{UI.RESET}"          if wps_serial        else f"{UI.DIM}?{UI.RESET}"
            wps_devname_s  = f"{UI.CYAN}{wps_dev_name}{UI.RESET}"        if wps_dev_name      else f"{UI.DIM}?{UI.RESET}"
            wps_primtype_s = f"{UI.CYAN}{wps_primary_type}{UI.RESET}"    if wps_primary_type  else f"{UI.DIM}?{UI.RESET}"
            wps_uuid_s     = f"{UI.CYAN}{wps_uuid_e}{UI.RESET}"          if wps_uuid_e        else f"{UI.DIM}?{UI.RESET}"

        # --- Security table ----------------------------------------------- #
        sec_rows = [
            ["BSSID",        s_bssid],
            ["Encryption",   encryption],
            ["MFPC",         mfpc_s],
            ["MFPR",         mfpr_s],
            ["Group Cipher", gc_s],
            ["AKM Suite",    akm_s],
            ["WPA1 IE",      wpa1_s],
            ["RRM",          rrm_s],
            ["BSS-Trans",    bsst_s],
        ]

        # --- WPS table ---------------------------------------------------- #
        wps_rows = [
            ["Present",        wps_present_s],
            ["Version",        wps_version_s],
            ["State",          wps_state_s],
            ["Method",         wps_method_s],
            ["Selected Reg.",  wps_selreg_s],
            ["Setup Locked",   wps_locked_s],
            ["Config Error",   wps_cfgerr_s],
            ["RF Bands",       wps_bands_s],
            ["Response Type",  wps_rtype_s],
            ["Manufacturer",   wps_mfr_s],
            ["Model Name",     wps_mname_s],
            ["Model Number",   wps_mnum_s],
            ["Serial",         wps_serial_s],
            ["Device Name",    wps_devname_s],
            ["Primary Type",   wps_primtype_s],
            ["UUID-E",         wps_uuid_s],
        ]

        # Persist the latest WPS detail per BSSID for structured posture findings.
        # Purely observational — no packets are sent here.
        try:
            self.vuln_wps[str(s_bssid).lower()] = {
                "present": bool(wps_present),
                "version": wps_version,
                "state": wps_state,
                "method": wps_dev_pass_id,
                "selected_registrar": bool(wps_selected_reg),
                "locked": bool(wps_setup_locked),
                "manufacturer": wps_manufacturer,
                "model_name": wps_model_name,
            }
        except Exception:
            pass

        if not self._can_render("vuln"):
            return
        with self._render_lock:
            os.system('clear')
            UI.print_banner()
            print(tabulate(sec_rows, headers=["Field", "Value"], tablefmt="pretty"))
            print()
            print(tabulate(wps_rows, headers=["WPS Field", "Value"], tablefmt="pretty"))

    def probe_request(self, pkt):
        """Packet handler — call via scapy sniff(prn=engine.probe_request)."""
        if not pkt.haslayer(Dot11):
            return

        dot11 = pkt[Dot11]

        # Management frame (type 0), subtype 4 = Probe Request
        if dot11.type != 0x00 or dot11.subtype != 0x04:
            return

        src_mac = dot11.addr2
        if not src_mac or not self.is_unicast(src_mac):
            return

        # Walk IEs to find SSID (Tag 0) — skip wildcard (empty) probes
        ssid = None
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:
                raw = bytes(elt.info)
                if raw:  # empty = wildcard broadcast probe, ignore
                    try:
                        ssid = raw.decode("utf-8", errors="replace")
                    except Exception:
                        ssid = raw.hex()
                break
            elt = elt.payload.getlayer(Dot11Elt)

        if not ssid:
            return

        now = time.strftime("%H:%M:%S")
        key = (src_mac, ssid)

        if key in self.probe_index:
            # Already seen — bump count and refresh last-observed timestamp
            idx = self.probe_index[key]
            self.probe_results[idx][3] += 1
            self.probe_results[idx][4] = now
        else:
            # First time — add new row and remember first observation
            vendor = self._lookup_oui(src_mac)
            row = [src_mac, vendor, ssid, 1, now]
            self.probe_index[key] = len(self.probe_results)
            self.probe_results.append(row)
            self.probe_first_seen[key] = now

        self.render_probe_table()

    @staticmethod
    def _probe_notes(ssid: str, count: int) -> str:
        """Classify a probed SSID: previously configured / repeated / hidden."""
        try:
            n = int(count)
        except (TypeError, ValueError):
            n = 0
        s = str(ssid or "")
        if not s or s.strip().lower() in ("<hidden>", "<wildcard>", "<malformed>", "") \
                or s.strip().startswith("<"):
            return "Hidden/placeholder"
        if n >= 3:
            return "Repeatedly probed (saved?)"
        if n >= 2:
            return "Previously configured?"
        return "Seen once"

    # # this will be a deathentication attack module
    # def deauth_frame(self, iface:str, channel: int, transmitter_mac: str, receiver_mac: str) -> bool:

    #     # we don't need Dot11Deauth separately, as we'll use the Dot11
    #     # and give type=0; subtype=12 (for a valid deauth frame)
    #     from scapy.all import sendp, Dot11Deauth

    #     # need to switch the channel to the AP's channel
    #     # to be able to operate on the same frequency
    #     import subprocess
    #     channel_str = str(channel)
    #     channel_switch = subprocess.run(["sudo", "iw", "dev", iface, "set", "channel", channel_str], 
    #         capture_output=True,
    #         text=True
    #     )

    #     if channel_switch.returncode != 0:
    #         print(f"[!] Unable to switch the channel: {channel_switch.stderr}")
    #         import sys; sys.exit(1)

    #     # set the RadioTap header
    #     radio_tap = RadioTap()

    #     # 802.11 Frame Header
    #     # type=0 (Management Frame)
    #     # subtype=12 (0x0C) Deauthentication Frame
    #     # addr1: Receiver address (target)
    #     # addr2: Transmitter address (Access Point or Client)
    #     # addr3: BSSID (Access Point MAC)
    #     dot11 = Dot11(type=0, subtype=12, addr1=receiver_mac, addr2=transmitter_mac, addr3=transmitter_mac)

    #     # Set the reason code to 1 (unspecified reason)
    #     # writing it in \x01\x00 instead of \x00\x01 due to little-endian (LSB)
    #     # so \0x1\x00 won't be seen as 256 in decimal representation
    #     # rather it'd be interpreter as \x00\x01 by the devices
    #     # as the ieee 802.11 this bit is in little-endian format
    #     # so it'd be seen as 1 not 256 !!!!
    #     reason_code = b"\x01\x00"

    #     # structure the frame
    #     deauth_frame = radio_tap / dot11 / reason_code

    #     # Send the frame
    #     print(f"Sending raw deauth frames with reason code 1...")
    #     sendp(deauth_frame, iface=iface, inter=0.1, count=100, verbose=0)

    def deauth_frame(self, iface: str, transmitter_mac: str, receiver_mac: str,
                     mgmt_subtype: int = 12) -> bool:
        """Send one spoofed disruption frame (ACTIVE — call only after explicit
        user authorization). mgmt_subtype 12 = Deauthentication (default),
        10 = Disassociation. Returns nothing meaningful (kept for compatibility)."""

        # we don't need Dot11Deauth separately, as we'll use the Dot11
        # and give type=0; subtype=12 (for a valid deauth frame)
        # from scapy.all import sendp, Dot11,  Dot11, Dot11Deauth
        from scapy.all import Dot11, Dot11Deauth, Dot11Disas, RadioTap, sendp
        try:
            mgmt_subtype = int(mgmt_subtype)
        except (TypeError, ValueError):
            mgmt_subtype = 12
        if mgmt_subtype not in (10, 12):
            mgmt_subtype = 12
        is_disassoc = (mgmt_subtype == 10)

        # need to switch the channel to the AP's channel
        # to be able to operate on the same frequency
        # This thing will be in main.py
        # I don't want it to keep changing channel continuosly every time this function get's called.
        # Change only once.
        # import subprocess
        # channel_str = str(channel)
        # channel_switch = subprocess.run(["sudo", "iw", "dev", iface, "set", "channel", channel_str], 
        #     capture_output=True,
        #     text=True
        # )

        # if channel_switch.returncode != 0:
        #     print(f"[!] Unable to switch the channel: {channel_switch.stderr}")
        #     import sys; sys.exit(1)

        # set the RadioTap header
        # radio = RadioTap()

        # # 802.11 Frame Header
        # # type=0 (Management Frame)
        # # subtype=12 (0x0C) Deauthentication Frame
        # # addr1: Receiver address (target)
        # # addr2: Transmitter address (Access Point or Client)
        # # addr3: BSSID (Access Point MAC)
        # dot11 = Dot11(addr1=receiver_mac, addr2=transmitter_mac, addr3=transmitter_mac)

        # # Set the reason code to 1 (unspecified reason)
        # # writing it in \x01\x00 instead of \x00\x01 due to little-endian (LSB)
        # # so \0x1\x00 won't be seen as 256 in decimal representation
        # # rather it'd be interpreter as \x00\x01 by the devices
        # # as the ieee 802.11 this bit is in little-endian format
        # # so it'd be seen as 1 not 256 !!!!
        # # changed from using raw bytes to Dot11Deauth with reason code 1 or 7
        # deauth = Dot11Deauth(reason=7)

        # lemme try this way !!!
        packet = (
            RadioTap() /
            Dot11(
                type=0,
                subtype=mgmt_subtype,
                addr1=receiver_mac,
                addr2=transmitter_mac,
                addr3=transmitter_mac,
            ) /
            (Dot11Disas(reason=8) if is_disassoc else Dot11Deauth(reason=7))
        )

        # structure the frame
        # packet = radio / dot11 / deauth

        # Send the frame
        # changing the verbose to 0, so it doesn't look creepy !!!
        sendp(packet, iface=iface, inter=0.1, count=1, verbose=0)

        # Single-line live counter — overwrites the same line, no newlines.
        # Gated to deauth view so a lingering thread can't scribble over menu/other tables.
        try:
            key = (str(transmitter_mac), str(receiver_mac), mgmt_subtype)
            with self._deauth_lock:
                count = self._deauth_counts.get(key, 0) + 1
                self._deauth_counts[key] = count
            if self._can_render("deauth"):
                tag = "DISASSOC" if is_disassoc else "DEAUTH"
                print(
                    f"\r  {UI.RED}[{tag}]{UI.RESET} "
                    f"{UI.CYAN}{transmitter_mac}{UI.RESET} -> "
                    f"{UI.YELLOW}{receiver_mac}{UI.RESET} - "
                    f"Count {UI.GREEN}{count}{UI.RESET}  ",
                    end="",
                    flush=True,
                )
        except Exception:
            pass

    def reset_deauth_counters(self):
        """Clear deauth counts so a new attack starts from Count 1."""
        try:
            with self._deauth_lock:
                self._deauth_counts.clear()
        except Exception:
            pass

    def end_deauth_line(self):
        """End the single-line counter so the next UI starts on a fresh line."""
        try:
            print()
        except Exception:
            pass

    def render_probe_table(self):
        if not self._can_render("probes"):
            return
        display_rows = []
        for r in self.probe_results:
            src_mac, vendor, ssid, count, last_seen = r
            first_seen = self.probe_first_seen.get((src_mac, ssid), last_seen)
            notes = self._probe_notes(ssid, count)
            display_rows.append([
                f"{UI.CYAN}{src_mac}{UI.RESET}",
                f"{UI.DIM}{vendor}{UI.RESET}",
                f"{UI.YELLOW}{ssid}{UI.RESET}",
                f"{UI.GREEN}{count}{UI.RESET}",
                f"{UI.DIM}{first_seen}{UI.RESET}",
                f"{UI.DIM}{last_seen}{UI.RESET}",
                f"{UI.DIM}{notes}{UI.RESET}",
            ])

        with self._render_lock:
            os.system('clear')
            UI.print_banner()
            print(tabulate(
                display_rows,
                headers=["SRC MAC", "Vendor", "SSID (Probed)", "Count", "First Seen", "Last Seen", "Notes"],
                tablefmt="pretty",
            ))
            print(f"\n  {UI.DIM}Listening for directed Probe Requests — press CTRL+C to stop.{UI.RESET}\n")

    def render_client_table(self):
        if not self._can_render("clients"):
            return
        STATUS_COLOR = {
            "Connected":    UI.GREEN,
            "Disconnected": UI.RED,
        }
        display_rows = []
        for r in self.client_results:
            # Rows are [ap, ap_vendor, client, vendor, status, rssi, first, last];
            # older 5-col rows are padded defensively.
            row = list(r) + ["?"] * (8 - len(r))
            ap_mac, ap_vendor, client_mac, client_vendor, status = row[0:5]
            rssi_s, first_s, last_s = row[5], row[6], row[7]

            # skip if ap or client is None
            if not ap_mac or not client_mac:
                continue

            color = STATUS_COLOR.get(status, UI.DIM)
            try:
                hs_s = self._hs_label(self.client_handshake.get(client_mac, {}))
            except Exception:
                hs_s = "--"
            display_rows.append([
                f"{UI.GREEN}{ap_mac}{UI.RESET}",
                f"{UI.GREEN}{ap_vendor}{UI.RESET}",
                f"{UI.GREEN}{client_mac}{UI.RESET}",
                f"{UI.GREEN}{client_vendor}{UI.RESET}",
                f"{color}{status}{UI.RESET}",
                f"{UI.DIM}{rssi_s}{UI.RESET}",
                f"{UI.DIM}{first_s}{UI.RESET}",
                f"{UI.DIM}{last_s}{UI.RESET}",
                f"{UI.DIM}{hs_s}{UI.RESET}",
            ])
        with self._render_lock:
            os.system('clear')
            UI.print_banner()
            print(tabulate(display_rows, headers=["Access Point", "AP Vendor", "Connected Client", "Client Vendor", "Status", "RSSI", "First Seen", "Last Seen", "HS/EAP"], tablefmt="pretty"))

    def render_live_table(self):
        if not self._can_render("aps"):
            return
        # UI.info("I'm getting executed.")
        GROUP_CIPHER_MAP = {
            0x00: "None",    0x01: "WEP-40",      0x02: "TKIP",
            0x04: "CCMP",    0x05: "WEP-104",      0x06: "AES-128-CMAC",
        }

        AKM_MAP = {
            0x01: "802.1X",     # Enterprise
            0x02: "PSK",        # WPA2-Personal
            0x03: "FT-802.1X",
            0x04: "FT-PSK",
            0x06: "PSK-SHA256",
            0x08: "SAE",        # WPA3-Personal
            0x12: "OWE",        # WPA3-Enhanced Open
        }

        display_rows = []
        for r in self.results:
            styled = list(r)

            # RSSI — index 2 (NEW)
            rssi = r[2]
            if rssi is None:
                styled[2] = f"{UI.DIM}?{UI.RESET}"
            elif isinstance(rssi, int):
                if rssi >= -50:
                    styled[2] = f"{UI.GREEN}{rssi} dBm{UI.RESET}"
                elif rssi >= -70:
                    styled[2] = f"{UI.YELLOW}{rssi} dBm{UI.RESET}"
                else:
                    styled[2] = f"{UI.RED}{rssi} dBm{UI.RESET}"
            else:
                styled[2] = f"{UI.DIM}{rssi}{UI.RESET}"

            # DTIM — index 8
            dtim = r[8]
            if dtim is None:
                styled[8] = f"{UI.DIM}?{UI.RESET}"
            elif dtim == 1:
                styled[8] = f"{UI.RED}{dtim}{UI.RESET}"
            elif dtim == 2:
                styled[8] = f"{UI.YELLOW}{dtim}{UI.RESET}"
            else:
                styled[8] = f"{UI.GREEN}{dtim}{UI.RESET}"

            # WPS — index 7
            styled[7] = f"{UI.GREEN}Enabled{UI.RESET}" if r[7] else f"{UI.RED}Disabled{UI.RESET}"

            # PMF — index 5 (MFPC), 6 (MFPR)
            styled[5] = f"{UI.GREEN}{r[5]}{UI.RESET}" if str(r[5]) == "1" else f"{UI.RED}{r[5]}{UI.RESET}"
            styled[6] = f"{UI.GREEN}{r[6]}{UI.RESET}" if str(r[6]) == "1" else f"{UI.RED}{r[6]}{UI.RESET}"

            # Group Cipher — index 9
            gc      = r[9]
            gc_name = GROUP_CIPHER_MAP.get(gc, f"0x{gc:02x}" if gc is not None else "?")
            if gc in (0x02, 0x01, 0x05):  # TKIP, WEP-40, WEP-104
                styled[9] = f"{UI.RED}{gc_name}{UI.RESET}"
            elif gc == 0x04:              # CCMP
                styled[9] = f"{UI.GREEN}{gc_name}{UI.RESET}"
            else:
                styled[9] = f"{UI.DIM}{gc_name}{UI.RESET}"

            # AKM Suite — index 10
            akm      = r[10]
            akm_name = AKM_MAP.get(akm, f"0x{akm:02x}" if akm is not None else "?")
            if akm in (0x08, 0x01, 0x03, 0x12):  # SAE, 802.1X, FT-802.1X, OWE
                styled[10] = f"{UI.GREEN}{akm_name}{UI.RESET}"
            elif akm in (0x02, 0x04, 0x06):       # PSK variants
                styled[10] = f"{UI.YELLOW}{akm_name}{UI.RESET}"
            else:
                styled[10] = f"{UI.DIM}{akm_name}{UI.RESET}"

            # WPA1 IE — index 11
            styled[11] = f"{UI.RED}Yes{UI.RESET}" if r[11] else f"{UI.GREEN}No{UI.RESET}"

            # Beacon Interval — index 12
            bi = r[12]
            if bi is None:
                styled[12] = f"{UI.DIM}?{UI.RESET}"
            elif bi == 100:
                styled[12] = f"{UI.GREEN}{bi}{UI.RESET}"
            else:
                styled[12] = f"{UI.YELLOW}{bi}*{UI.RESET}"  # * = non-standard

            # RRM (802.11k) — index 13
            styled[13] = f"{UI.YELLOW}Yes{UI.RESET}" if r[13] else f"{UI.DIM}No{UI.RESET}"

            # BSS Transition (802.11v) — index 14
            styled[14] = f"{UI.YELLOW}Yes{UI.RESET}" if r[14] else f"{UI.DIM}No{UI.RESET}"
            tsf = r[15]
            styled[15] = f"{UI.DIM}?{UI.RESET}" if tsf is None else f"{UI.CYAN}{tsf}{UI.RESET}"

            # Appended passive-discovery columns (indices 16+) — plain styling.
            # Older rows (if any) may be shorter; pad defensively.
            while len(styled) < len(self.table_headers):
                styled.append("?")
            try:
                styled[16] = f"{UI.DIM}{r[16]}{UI.RESET}"  # FREQ
                styled[17] = f"{UI.CYAN}{r[17]}{UI.RESET}" if r[17] not in ("?", None) else f"{UI.DIM}?{UI.RESET}"  # STD
                styled[18] = f"{UI.DIM}{r[18]}{UI.RESET}"  # FIRST SEEN
                styled[19] = f"{UI.DIM}{r[19]}{UI.RESET}"  # LAST SEEN
                styled[20] = f"{UI.YELLOW}Yes{UI.RESET}" if r[20] else f"{UI.DIM}No{UI.RESET}"  # FT (11r)
            except (IndexError, TypeError):
                pass

            display_rows.append(styled)

        with self._render_lock:
            os.system('clear')
            UI.print_banner()
            print(tabulate(display_rows, headers=self.table_headers, tablefmt="pretty"))

    def hopper_loop(self, channels: List[int], interval: float):
        idx = 0
        while not self.stop_hopper.is_set():
            chan = channels[idx % len(channels)]
            try:
                InterfaceManager.set_channel(self.interface, chan)
            except:
                pass
            idx += 1
            time.sleep(interval)
