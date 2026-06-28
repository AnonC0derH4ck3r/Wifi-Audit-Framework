import os
import re
import time
import threading
from pathlib import Path
from typing import List, Tuple, Any

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
        self.seen_clients   = set()
        # tracks current status per client mac: "Connected" | "Disconnected"
        self.client_status  = {}
        self.stop_hopper    = threading.Event()
        self.table_headers  = [
            "BSSID", "CH", "SSID", "ENCRYPTION",
            "MFPC", "MFPR", "WPS", "DTIM",
            "GRP CIPHER", "AKM", "WPA1", "BCN INT", "RRM", "BSS-TRANS", "UPTIME",
        ]
        self.oui_map = {}
        oui_path = Path("./ieee-oui.txt")
        if oui_path.exists():
            with open(oui_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    m = re.match(r'^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)', line)
                    if m:
                        self.oui_map[m.group(1).upper()] = m.group(2).strip()
            UI.ok(f"OUI database loaded: {len(self.oui_map)} entries.")
        else:
            UI.warn("ieee-oui.txt not found — vendor names will show as 'Unknown'.")

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

    def _update_row_status(self, client_mac: str):
        """Patch the Status field (index 4) in the existing row for this client."""
        for row in self.client_results:
            if row[2] == client_mac:   # index 2 = client_mac
                row[4] = self.client_status[client_mac]
                break

    def _mark_connected(self, client_mac: str, ap_mac: str):
        """Mark an existing client Connected, or add them if first seen via assoc/EAPOL."""
        if client_mac in self.seen_clients:
            if self.client_status.get(client_mac) != "Connected":
                self.client_status[client_mac] = "Connected"
                self._update_row_status(client_mac)
        else:
            # Seen assoc/EAPOL before any data frame — add the row now
            ap_vendor     = self._lookup_oui(ap_mac)
            client_vendor = self._lookup_oui(client_mac)
            self.client_status[client_mac] = "Connected"
            row = [ap_mac, ap_vendor, client_mac, client_vendor, "Connected"]
            self.client_results.append(row)
            self.seen_clients.add(client_mac)

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

    # this will scan for beacon frames
    def beacon_frame(self, pkt):
        if not pkt.haslayer(Dot11) or pkt.subtype != 0x08:  # Beacon only
            return

        bssid = pkt[Dot11].addr2
        if bssid in self.seen_bssids:
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

            elt = elt.payload.getlayer(Dot11Elt)

        # no need to add Beacon
        row = [
            bssid, channel or "?", ssid, encryption,
            mfpc, mfpr, wps, dtim_period,
            group_cipher, akm_suite, has_wpa1,
            beacon_int, has_rrm, bss_trans, tsf_uptime,
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
        self.render_live_table()

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
        # ------------------------------------------------------------------ #

        # 1. Association Response: type 0, subtype 1
        #    addr1=client (destination), addr2=bssid (source)
        if dot11.type == 0x00 and dot11.subtype == 0x01:
            if dot11.addr2 == s_bssid and dot11.addr1 and self.is_unicast(dot11.addr1):
                self._mark_connected(dot11.addr1, s_bssid)
                self.render_client_table()
            return

        # 2. EAPOL frames ride inside Dot11 data frames (type 2)
        #    Check for EAPOL layer regardless of subtype
        if pkt.haslayer(EAPOL) and dot11.type == 0x02:
            # Client → AP
            if dot11.addr1 == s_bssid and dot11.addr2 and self.is_unicast(dot11.addr2):
                self._mark_connected(dot11.addr2, s_bssid)
                self.render_client_table()
            # AP → Client
            elif dot11.addr2 == s_bssid and dot11.addr1 and self.is_unicast(dot11.addr1):
                self._mark_connected(dot11.addr1, s_bssid)
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

            # New client — add row for the first time
            if client_mac not in self.seen_clients:
                ap_vendor     = self._lookup_oui(ap_mac)
                client_vendor = self._lookup_oui(client_mac)
                self.client_status[client_mac] = "Connected"
                # row = [
                #     "Beacon", bssid, channel or "?", ssid, encryption,
                #     mfpc, mfpr, wps, dtim_period,
                #     group_cipher, akm_suite, has_wpa1,
                #     beacon_int, has_rrm, bss_trans,
                # ]
                row = [ap_mac, ap_vendor, client_mac, client_vendor, "Connected"]
                self.client_results.append(row)
                self.seen_clients.add(client_mac)

            # Already known — if they were Disconnected, data frames prove they're back
            elif self.client_status.get(client_mac) == "Disconnected":
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
            # Already seen — bump count and refresh timestamp
            idx = self.probe_index[key]
            self.probe_results[idx][3] += 1
            self.probe_results[idx][4] = now
        else:
            # First time — add new row
            vendor = self._lookup_oui(src_mac)
            row = [src_mac, vendor, ssid, 1, now]
            self.probe_index[key] = len(self.probe_results)
            self.probe_results.append(row)

        self.render_probe_table()

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

    def deauth_frame(self, iface:str, transmitter_mac: str, receiver_mac: str) -> bool:

        # we don't need Dot11Deauth separately, as we'll use the Dot11
        # and give type=0; subtype=12 (for a valid deauth frame)
        # from scapy.all import sendp, Dot11,  Dot11, Dot11Deauth
        from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp

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
                subtype=12,
                addr1=receiver_mac,
                addr2=transmitter_mac,
                addr3=transmitter_mac,
            ) /
            Dot11Deauth(reason=7)
        )

        # structure the frame
        # packet = radio / dot11 / deauth

        # Send the frame
        print(f"Sending raw deauth frames with reason code 1...")
        # print(type(iface), iface)
        # print(type(packet), packet.summary())
        # changing the verbose to 0, so it doesn't look creepy !!!
        sendp(packet, iface=iface, inter=0.1, count=1, verbose=0)

    def render_probe_table(self):
        display_rows = []
        for r in self.probe_results:
            src_mac, vendor, ssid, count, last_seen = r
            display_rows.append([
                f"{UI.CYAN}{src_mac}{UI.RESET}",
                f"{UI.DIM}{vendor}{UI.RESET}",
                f"{UI.YELLOW}{ssid}{UI.RESET}",
                f"{UI.GREEN}{count}{UI.RESET}",
                f"{UI.DIM}{last_seen}{UI.RESET}",
            ])

        os.system('clear')
        UI.print_banner()
        print(tabulate(
            display_rows,
            headers=["SRC MAC", "Vendor", "SSID (Probed)", "Count", "Last Seen"],
            tablefmt="pretty",
        ))
        print(f"\n  {UI.DIM}Listening for directed Probe Requests — press CTRL+C to stop.{UI.RESET}\n")

    def render_client_table(self):
        STATUS_COLOR = {
            "Connected":    UI.GREEN,
            "Disconnected": UI.RED,
        }
        display_rows = []
        for r in self.client_results:
            ap_mac, ap_vendor, client_mac, client_vendor, status = r

            # skip if ap or client is None
            if not ap_mac or not client_mac:
                continue

            color = STATUS_COLOR.get(status, UI.DIM)
            display_rows.append([
                f"{UI.GREEN}{ap_mac}{UI.RESET}",
                f"{UI.GREEN}{ap_vendor}{UI.RESET}",
                f"{UI.GREEN}{client_mac}{UI.RESET}",
                f"{UI.GREEN}{client_vendor}{UI.RESET}",
                f"{color}{status}{UI.RESET}",
            ])
        os.system('clear')
        UI.print_banner()
        print(tabulate(display_rows, headers=["Access Point", "AP Vendor", "Connected Client", "Client Vendor", "Status"], tablefmt="pretty"))

    def render_live_table(self):
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

            # DTIM — index 8
            # r[0] = None
            dtim = r[7]
            if dtim is None:
                styled[7] = f"{UI.DIM}?{UI.RESET}"
            elif dtim == 1:
                styled[7] = f"{UI.RED}{dtim}{UI.RESET}"
            elif dtim == 2:
                styled[7] = f"{UI.YELLOW}{dtim}{UI.RESET}"
            else:
                styled[7] = f"{UI.GREEN}{dtim}{UI.RESET}"

            # WPS — index 7
            styled[6] = f"{UI.GREEN}Enabled{UI.RESET}" if r[6] else f"{UI.RED}Disabled{UI.RESET}"

            # PMF — index 5 (MFPC), 6 (MFPR)
            styled[4] = f"{UI.GREEN}{r[4]}{UI.RESET}" if str(r[4]) == "1" else f"{UI.RED}{r[4]}{UI.RESET}"
            styled[5] = f"{UI.GREEN}{r[5]}{UI.RESET}" if str(r[5]) == "1" else f"{UI.RED}{r[5]}{UI.RESET}"

            # Group Cipher — index 9
            gc      = r[8]
            gc_name = GROUP_CIPHER_MAP.get(gc, f"0x{gc:02x}" if gc is not None else "?")
            if gc in (0x02, 0x01, 0x05):  # TKIP, WEP-40, WEP-104
                styled[8] = f"{UI.RED}{gc_name}{UI.RESET}"
            elif gc == 0x04:              # CCMP
                styled[8] = f"{UI.GREEN}{gc_name}{UI.RESET}"
            else:
                styled[8] = f"{UI.DIM}{gc_name}{UI.RESET}"

            # AKM Suite — index 10
            akm      = r[9]
            akm_name = AKM_MAP.get(akm, f"0x{akm:02x}" if akm is not None else "?")
            if akm in (0x08, 0x01, 0x03, 0x12):  # SAE, 802.1X, FT-802.1X, OWE
                styled[9] = f"{UI.GREEN}{akm_name}{UI.RESET}"
            elif akm in (0x02, 0x04, 0x06):       # PSK variants
                styled[9] = f"{UI.YELLOW}{akm_name}{UI.RESET}"
            else:
                styled[9] = f"{UI.DIM}{akm_name}{UI.RESET}"

            # WPA1 IE — index 11
            styled[10] = f"{UI.RED}Yes{UI.RESET}" if r[10] else f"{UI.GREEN}No{UI.RESET}"

            # Beacon Interval — index 12
            bi = r[11]
            if bi is None:
                styled[11] = f"{UI.DIM}?{UI.RESET}"
            elif bi == 100:
                styled[11] = f"{UI.GREEN}{bi}{UI.RESET}"
            else:
                styled[11] = f"{UI.YELLOW}{bi}*{UI.RESET}"  # * = non-standard

            # RRM (802.11k) — index 13
            styled[12] = f"{UI.YELLOW}Yes{UI.RESET}" if r[12] else f"{UI.DIM}No{UI.RESET}"

            # BSS Transition (802.11v) — index 14
            styled[13] = f"{UI.YELLOW}Yes{UI.RESET}" if r[13] else f"{UI.DIM}No{UI.RESET}"
            tsf = r[14]
            styled[14] = f"{UI.DIM}?{UI.RESET}" if tsf is None else f"{UI.CYAN}{tsf}{UI.RESET}"

            display_rows.append(styled)

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
