import subprocess

from pyroute2 import IPRoute, IW, NL80211
from pyroute2.netlink.nl80211 import nl80211cmd, NL80211_CMD_GET_INTERFACE, NL80211_CMD_SET_INTERFACE, NL80211_CMD_SET_CHANNEL
from pyroute2.netlink import NLM_F_REQUEST, NLM_F_ACK, NLM_F_DUMP, NetlinkError

from config import Config
from ui import UI

# -----------------------------------------------------------------------------
# WIRELESS HARDWARE CONTROLLER (NL80211)
# -----------------------------------------------------------------------------

class InterfaceManager:
    """Low-level interface manipulation using Netlink/nl80211."""

    @staticmethod
    def get_info(iw, ifname: str) -> dict:
        msg = nl80211cmd()
        msg['cmd'] = NL80211_CMD_GET_INTERFACE
        responses = iw.nlm_request(msg, msg_type=iw.prid, msg_flags=NLM_F_REQUEST | NLM_F_DUMP)

        for resp in responses:
            if resp.get_attr('NL80211_ATTR_IFNAME') == ifname:
                iftype = resp.get_attr('NL80211_ATTR_IFTYPE')
                return {
                    'ifindex':    resp.get_attr('NL80211_ATTR_IFINDEX'),
                    'wiphy':      resp.get_attr('NL80211_ATTR_WIPHY'),
                    'current':    Config.IFTYPE_NAMES.get(iftype, f'Unknown ({iftype})'),
                    'iftype_raw': iftype
                }
        raise RuntimeError(f"Interface {ifname} not found.")

    @staticmethod
    def set_state(ifname: str, state: str):
        """State: 'up' or 'down'"""
        with IPRoute() as ip:
            idx = ip.link_lookup(ifname=ifname)[0]
            ip.link('set', index=idx, state=state)

    @classmethod
    def set_mode(cls, ifname: str, mode_idx: int):
        """Mode 2 = Managed, 6 = Monitor"""
        # we need to check if we are switching to monitor mode
        # kill the NetworkManager and wpa_supplicant
        # these two processess often interfere with monitor mode
        # this also solves the Network is down issue throwed by scapy
        # as these process may automatically switch the interface back to managed mode (which they expect)
        # if the interface behaves abnormally (monitor mode)
        if mode_idx == 6:
            # attempt to kill the NetworkManager
            subprocess.run(["systemctl", "stop", "NetworkManager"], capture_output=True)
            # attempt to kill the wpa_supplicant
            subprocess.run(["systemctl", "stop", "wpa_supplicant"], capture_output=True)
        with NL80211() as iw:
            iw.bind()
            info = cls.get_info(iw, ifname)
            msg = nl80211cmd()
            msg['cmd'] = NL80211_CMD_SET_INTERFACE
            msg['attrs'] = [['NL80211_ATTR_IFINDEX', info['ifindex']], ['NL80211_ATTR_IFTYPE', mode_idx]]
            try:
                iw.nlm_request(msg, msg_type=iw.prid, msg_flags=NLM_F_REQUEST | NLM_F_ACK)
            except NetlinkError:
                UI.error(f"Failed to switch {ifname} to mode {mode_idx}")

        # if switching to monitor mode, also invoke airmon-ng as a secondary enforcement
        # this is useful when nl80211 succeeds structurally but the driver doesn't fully
        # honour the mode switch (e.g. ath9k, rtl88xx quirks)
        if mode_idx == 6:
            try:
                result = subprocess.run(
                    ["airmon-ng", "start", ifname],
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    UI.ok(f"airmon-ng: monitor mode enforced on {ifname}.")
                else:
                    UI.warn(f"airmon-ng exited with code {result.returncode} — it may not be installed or the interface name changed.")
            except FileNotFoundError:
                # airmon-ng is not installed — non-fatal, nl80211 path already attempted above
                UI.warn("airmon-ng not found — skipping secondary monitor mode enforcement.")
            except Exception as e:
                UI.error(f"airmon-ng invocation failed: {e}")

    @classmethod
    def set_channel(cls, ifname: str, channel: int):
        freq = Config._2GHZ.get(channel) or Config._5GHZ.get(channel)
        if not freq:
            return

        with NL80211() as iw:
            iw.bind()
            info = cls.get_info(iw, ifname)
            msg = nl80211cmd()
            msg['cmd'] = NL80211_CMD_SET_CHANNEL
            msg['attrs'] = [
                ['NL80211_ATTR_IFINDEX',       info['ifindex']],
                ['NL80211_ATTR_WIPHY_FREQ',    freq],
                ['NL80211_ATTR_CHANNEL_WIDTH', 1],  # 20MHz
                ['NL80211_ATTR_CENTER_FREQ1',  freq]
            ]
            iw.nlm_request(msg, msg_type=iw.prid, msg_flags=NLM_F_REQUEST | NLM_F_ACK)
