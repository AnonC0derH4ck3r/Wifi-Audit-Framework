"""Passive wireless security-posture assessment.

Builds structured findings (CRITICAL / HIGH / MEDIUM / LOW / INFO) from
already-captured AP data — beacons, probe responses and scan context.
Never transmits. Never claims a vulnerability without captured evidence:
every finding carries the evidence it was derived from.
"""

from typing import Any, Dict, List

from ui import UI
from tabulate import tabulate

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

_SEV_COLOR = None  # resolved lazily so unit tests can stub UI


def _color(sev: str, text: str) -> str:
    if sev in ("CRITICAL", "HIGH"):
        return f"{UI.RED}{text}{UI.RESET}"
    if sev == "MEDIUM":
        return f"{UI.YELLOW}{text}{UI.RESET}"
    if sev == "LOW":
        return f"{UI.CYAN}{text}{UI.RESET}"
    return f"{UI.DIM}{text}{UI.RESET}"


def _mk(findings: List[Dict[str, Any]], fid: str, name: str, severity: str,
        description: str, evidence: str, remediation: str) -> None:
    findings.append({
        "id": fid,
        "name": name,
        "severity": severity,
        "description": description,
        "evidence": evidence or "n/a",
        "remediation": remediation,
    })


def _is_open(encryption: str) -> bool:
    return "open" in str(encryption or "").lower()


def assess_ap(ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Assess one AP's captured configuration.

    `ctx` keys (all optional): ssid, bssid, channel, freq, encryption,
    group_cipher (int|None), akm (int|None), has_wpa1 (bool), mfpc, mfpr,
    wps (bool), wps_version, wps_state, wps_method, wps_locked,
    wps_selected_registrar, has_rrm, bss_trans, has_mobdom (11r),
    std, hidden (bool), beacon_int, vendor, same_channel_neighbors (int),
    ssid_dup_count (int), ssid_dup_open (bool).
    """
    f: List[Dict[str, Any]] = []
    enc = str(ctx.get("encryption") or "?")
    enc_l = enc.lower()
    akm = ctx.get("akm")
    grp = ctx.get("group_cipher")
    has_wpa1 = bool(ctx.get("has_wpa1"))
    mfpc = str(ctx.get("mfpc", "?"))
    mfpr = str(ctx.get("mfpr", "?"))
    ssid = str(ctx.get("ssid") or "?")
    bssid = str(ctx.get("bssid") or "?")

    # ── Encryption / authentication ──────────────────────────────────
    if _is_open(enc):
        _mk(f, "OPEN-NETWORK", "Open network (no encryption)", "CRITICAL",
            "Anyone in range can capture all traffic; evil-twin impersonation is trivial.",
            f"Encryption: {enc}",
            "Enable WPA3-SAE (or WPA2-PSK/AES minimum); never carry sensitive data over this network.")
    else:
        if "wep" in enc_l or grp in (1, 5):
            _mk(f, "WEP-IN-USE", "WEP encryption in use", "CRITICAL",
                "WEP is broken in minutes with public tools; keys offer no real protection.",
                f"Encryption: {enc}; group cipher: {grp}",
                "Disable WEP; migrate to WPA3-SAE (or WPA2-AES).")
        if has_wpa1 and "wpa2" not in enc_l and "wpa3" not in enc_l and "sae" not in enc_l:
            _mk(f, "WPA1-ONLY", "WPA-only (TKIP) network", "HIGH",
                "Original WPA relies on TKIP/RC4 with known weaknesses.",
                f"Encryption: {enc}; WPA1 IE present",
                "Move to WPA2-AES minimum; disable TKIP and WPA-only mode.")
        if grp == 2 or "tkip" in enc_l:
            _mk(f, "TKIP-IN-USE", "TKIP cipher configured", "HIGH",
                "TKIP is deprecated and vulnerable to packet injection/recovery attacks.",
                f"Group cipher: TKIP ({grp}); encryption: {enc}",
                "Use CCMP-128 (AES) group cipher; disable TKIP.")
        if has_wpa1 and ("wpa2" in enc_l or akm == 2):
            _mk(f, "WPA-MIXED-MODE", "WPA/WPA2 mixed mode", "MEDIUM",
                "Mixed mode keeps TKIP-era clients working but allows downgrade pressure.",
                f"Encryption: {enc}; WPA1 IE + RSN both present",
                "Run WPA2-AES-only (or WPA3 transition mode) once legacy clients are gone.")
        if akm == 0x02 and grp == 4 and not has_wpa1 and "tkip" not in enc_l:
            _mk(f, "WPA2-PSK-OK", "WPA2-Personal with CCMP", "INFO",
                "Sound baseline personal-network configuration.",
                f"Encryption: {enc}; AKM: PSK",
                "Prefer a long random passphrase; consider WPA3-SAE transition.")
        if akm == 0x08 or "sae" in enc_l or "wpa3" in enc_l:
            _mk(f, "WPA3-SAE", "WPA3-SAE in use", "INFO",
                "Modern personal authentication resistant to offline dictionary attacks.",
                f"Encryption: {enc}; AKM: SAE",
                "Keep PMF required; disable WPA3-transition downgrade where possible.")
        if akm == 0x12 or "owe" in enc_l:
            _mk(f, "OWE", "Opportunistic Wireless Encryption", "INFO",
                "Enhanced Open: per-client encryption without a passphrase (still no authentication).",
                f"Encryption: {enc}",
                "Fine for guest use; do not treat as authenticated access.")
        if akm == 0x01 or "802.1x" in enc_l or "enterprise" in enc_l:
            _mk(f, "ENTERPRISE-AUTH", "WPA-Enterprise (802.1X/EAP)", "INFO",
                "Enterprise authentication observed. Risk concentrates on client-side "
                "trust: cert validation disabled, server identity not checked, weak EAP methods.",
                f"Encryption: {enc}; AKM: 802.1X",
                "Enforce server-certificate validation and expected server names on all "
                "managed clients; prefer EAP-TLS; review RADIUS server certificates.")

    # ── Management-frame protection (802.11w) ────────────────────────
    if not _is_open(enc):
        if mfpc == "0" and mfpr == "0":
            _mk(f, "PMF-DISABLED", "PMF/802.11w disabled", "HIGH",
                "Unprotected deauthentication/disassociation frames allow spoofed disconnect attacks.",
                f"MFPC={mfpc} MFPR={mfpr}",
                "Set PMF to required (802.11w=2) on AP and clients.")
        elif mfpc == "1" and mfpr == "0":
            _mk(f, "PMF-OPTIONAL", "PMF optional, not required", "LOW",
                "Capable clients negotiate protection, but attackers can target non-PMF clients.",
                f"MFPC={mfpc} MFPR={mfpr}",
                "Move to PMF required once all clients support it.")
        elif mfpc == "1" and mfpr == "1":
            _mk(f, "PMF-REQUIRED", "PMF required", "INFO",
                "Management frames are protected for capable clients.",
                f"MFPC={mfpc} MFPR={mfpr}",
                "No action; keep required.")
        else:
            _mk(f, "PMF-UNKNOWN", "PMF state not observed", "INFO",
                "RSN capabilities were not captured, so 802.11w posture is unknown.",
                f"MFPC={mfpc} MFPR={mfpr}",
                "Re-run the assessment closer/longer to capture the RSN IE.")

    # ── WPS ──────────────────────────────────────────────────────────
    if ctx.get("wps"):
        details = []
        if ctx.get("wps_version"):
            details.append(f"v{ctx['wps_version']}")
        if ctx.get("wps_state"):
            details.append(str(ctx["wps_state"]))
        if ctx.get("wps_method") not in (None, "", "?"):
            details.append(f"method {ctx['wps_method']}")
        ev = "; ".join(details) if details else "WPS IE present in beacon"
        if ctx.get("wps_locked"):
            _mk(f, "WPS-LOCKED", "WPS locked / rate-limited", "MEDIUM",
                "AP reports WPS setup-locked — often a sign of lockout after guessing, "
                "or a hardened default. Locked today does not mean safe tomorrow.",
                ev, "Leave WPS disabled entirely; if needed, verify lockout resets and PIN is strong.")
        else:
            _mk(f, "WPS-ENABLED", "WPS enabled", "HIGH",
                "WPS PIN is brute-forceable (and Pixie-Dust may recover it offline) on many implementations.",
                ev, "Disable WPS (PBC and PIN). If business-critical, monitor lockout counters.")
        if ctx.get("wps_selected_registrar"):
            _mk(f, "WPS-SESS-ACTIVE", "WPS registrar session flagged", "MEDIUM",
                "Selected-registrar flag suggests a WPS session was recently active.",
                "Selected Registrar = Yes",
                "Investigate who initiated it; keep WPS disabled.")
    else:
        _mk(f, "WPS-DISABLED", "WPS not observed", "INFO",
            "No WPS information element was captured.",
            "Beacon scan",
            "Keep WPS disabled.")

    # ── Modern Wi-Fi features ────────────────────────────────────────
    feats = []
    if ctx.get("has_mobdom"):
        feats.append("802.11r (Fast Transition)")
    if ctx.get("has_rrm"):
        feats.append("802.11k (RRM)")
    if ctx.get("bss_trans"):
        feats.append("802.11v (BSS Transition)")
    std = str(ctx.get("std") or "")
    if "AX" in std:
        feats.append("802.11ax (HE)")
    if "BE" in std:
        feats.append("802.11be (EHT, tentative)")
    elif "AC" in std:
        feats.append("802.11ac (VHT)")
    elif std.strip() == "N":
        feats.append("802.11n (HT)")
    if feats:
        _mk(f, "MODERN-FEATURES", "Modern Wi-Fi features observed", "INFO",
            "Capability advertisement seen in beacons.",
            "; ".join(feats),
            "No action; prefer WPA3/PMF-required to match modern hardware.")
    else:
        _mk(f, "LEGACY-PHY", "Legacy 802.11a/b/g only", "LOW",
            "No 11n/ac/ax capability elements were captured; Tx rates and efficiency suffer.",
            f"STDADB: {std or '?'}",
            "Prefer modern AP hardware; this alone is not a vulnerability.")

    # ── PMKID exposure ────────────────────────────────────────────────
    if ctx.get("pmkid_observed"):
        _mk(f, "PMKID-IN-M1", "PMKID exposed in EAPOL Message 1", "HIGH",
            "This AP includes a PMKID in handshake Message 1, enabling offline "
            "PMKID-cracking attacks that never need a full handshake or client.",
            f"PMKID: {str(ctx['pmkid_observed'])[:32]}... (BSSID {bssid})",
            "Use a long random PSK (20+ chars); monitor for M1-harvesting; prefer WPA3-SAE.")
    if ctx.get("bssid_conflict"):
        _mk(f, "BSSID-CONFLICT", "Possible BSSID impersonation", "MEDIUM",
            "The same BSSID was observed with conflicting characteristics. This may be "
            "a second radio, a reconfigured AP — or an impersonator. Do not assume spoofing.",
            str(ctx["bssid_conflict"])[:100],
            "Compare against the approved-AP inventory (location, hardware, config); "
            "investigate unknown devices physically.")

    # ── Other posture checks ─────────────────────────────────────────
    if ctx.get("hidden"):
        _mk(f, "HIDDEN-SSID", "Hidden (non-broadcast) SSID", "LOW",
            "Hiding the SSID provides no security — clients probe for it anyway — "
            "and hurts roaming/debugging.",
            f"SSID: {ssid}",
            "Broadcast the SSID; rely on WPA3/PMF instead of obscurity.")
    dup = int(ctx.get("ssid_dup_count") or 0)
    if dup > 0:
        if ctx.get("ssid_dup_open"):
            _mk(f, "DUP-SSID-OPEN", "Same SSID on an Open AP nearby", "HIGH",
                "A second AP advertises this SSID without encryption — possible evil twin.",
                f"{dup} other BSSID(s) share SSID '{ssid}'; at least one is Open",
                "Verify against the approved-AP inventory; run Rogue AP Detection (option 10).")
        else:
            _mk(f, "DUP-SSID", "Duplicate SSID nearby", "MEDIUM",
                "Multiple BSSIDs advertise the same SSID. May be legitimate multi-AP "
                "roaming — or a rogue. Do not assume either way.",
                f"{dup} other BSSID(s) share SSID '{ssid}'",
                "Compare against the approved BSSID/channel/vendor inventory; investigate unknowns.")
    vendor = str(ctx.get("vendor") or "Unknown")
    if vendor == "Unknown":
        _mk(f, "UNKNOWN-VENDOR", "BSSID OUI not in database", "INFO",
            "Vendor could not be resolved — locally-administered, new, or truncated OUI file.",
            f"BSSID: {bssid}",
            "Check the BSSID against the hardware inventory.")
    bi = ctx.get("beacon_int")
    try:
        if bi is not None and int(bi) != 100:
            _mk(f, "BEACON-INT", "Non-standard beacon interval", "LOW",
                "Unusual beacon interval can indicate misconfiguration or soft-AP software.",
                f"Beacon interval: {bi} TU (standard: 100)",
                "Confirm the value is intentional.")
    except (TypeError, ValueError):
        pass
    try:
        neigh = int(ctx.get("same_channel_neighbors") or 0)
        if neigh >= 5:
            _mk(f, "CROWDED-CHANNEL", "Crowded channel", "INFO",
                "Many neighboring APs share this channel; expect contention, not a vulnerability.",
                f"{neigh} APs on CH {ctx.get('channel')}",
                "Prefer 5 GHz / cleaner channels where possible.")
    except (TypeError, ValueError):
        pass

    if not f:
        _mk(f, "NO-DATA", "Insufficient capture", "INFO",
            "Too little traffic was captured to assess this AP.",
            f"BSSID: {bssid}",
            "Re-run the assessment longer and closer to the AP.")
    f.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 9))
    return f


def assess_from_engine(engine, bssid: str) -> List[Dict[str, Any]]:
    """Build the assessment context for one BSSID from engine scan state
    (passive discovery rows + probe-response WPS detail + neighborhood) and
    return structured findings. Returns [] if the BSSID is unknown."""
    try:
        target = str(bssid).lower()
        row = next((r for r in (getattr(engine, "results", []) or [])
                    if str(r[0]).lower() == target), None)
        if row is None:
            return []
        ssid = str(row[3]) if len(row) > 3 else "?"
        hidden = ssid.strip().lower() in ("<hidden>", "<malformed>", "") \
            or ssid.strip().startswith("<")
        same_ch = 0
        dup = 0
        dup_open = False
        try:
            ch = str(row[1])
            for r in getattr(engine, "results", []) or []:
                if str(r[0]).lower() == target:
                    continue
                if len(r) > 1 and str(r[1]) == ch:
                    same_ch += 1
                if len(r) > 3 and str(r[3]).strip().lower() == ssid.strip().lower() \
                        and ssid.strip().lower() not in ("<hidden>", "<malformed>", ""):
                    dup += 1
                    if len(r) > 4 and "open" in str(r[4]).lower():
                        dup_open = True
        except Exception:
            pass
        try:
            vendor = engine._lookup_oui(str(row[0]))
        except Exception:
            vendor = "Unknown"
        try:
            pmkid = (getattr(engine, "ap_pmkid", {}) or {}).get(target)
        except Exception:
            pmkid = None
        try:
            conflict = (getattr(engine, "bssid_conflicts", {}) or {}).get(target)
        except Exception:
            conflict = None
        wps_det = {}
        try:
            wps_det = (getattr(engine, "vuln_wps", {}) or {}).get(target, {})
        except Exception:
            wps_det = {}
        ctx: Dict[str, Any] = {
            "ssid": ssid,
            "bssid": str(row[0]),
            "channel": row[1] if len(row) > 1 else "?",
            "freq": row[16] if len(row) > 16 else "?",
            "encryption": row[4] if len(row) > 4 else "?",
            "group_cipher": row[9] if len(row) > 9 else None,
            "akm": row[10] if len(row) > 10 else None,
            "has_wpa1": row[11] if len(row) > 11 else False,
            "mfpc": row[5] if len(row) > 5 else "?",
            "mfpr": row[6] if len(row) > 6 else "?",
            "wps": row[7] if len(row) > 7 else False,
            "wps_version": wps_det.get("version"),
            "wps_state": wps_det.get("state"),
            "wps_method": wps_det.get("method"),
            "wps_locked": wps_det.get("locked", False),
            "wps_selected_registrar": wps_det.get("selected_registrar", False),
            "has_rrm": row[13] if len(row) > 13 else False,
            "bss_trans": row[14] if len(row) > 14 else False,
            "has_mobdom": row[20] if len(row) > 20 else False,
            "std": row[17] if len(row) > 17 else "",
            "hidden": hidden,
            "beacon_int": row[12] if len(row) > 12 else None,
            "vendor": vendor,
            "same_channel_neighbors": same_ch,
            "ssid_dup_count": dup,
            "ssid_dup_open": dup_open,
            "pmkid_observed": pmkid,
            "bssid_conflict": conflict,
        }
        return assess_ap(ctx)
    except Exception:
        return []


def render_findings(findings: List[Dict[str, Any]], title: str = "Security Posture Findings") -> None:
    """Print findings ordered CRITICAL → INFO. Display-only; never transmits."""
    print(f"\n  {UI.BOLD}{title}{UI.RESET} ({len(findings)} finding(s))\n")
    rows = []
    for x in findings:
        rows.append([
            _color(x["severity"], x["severity"]),
            f"{UI.BOLD}{x['name']}{UI.RESET}\n{UI.DIM}{x['description'][:100]}{UI.RESET}",
            f"{UI.DIM}{str(x['evidence'])[:60]}{UI.RESET}",
            f"{str(x['remediation'])[:70]}",
        ])
    print(tabulate(rows, headers=["Severity", "Finding", "Evidence", "Remediation"], tablefmt="pretty"))
    print()
