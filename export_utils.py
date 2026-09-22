"""Excel export helper — saves every scan to a timestamped .xlsx file.

Filename format (as requested, no overwrite / no data loss):
    <scan-name>-{date}-{time}.xlsx
e.g. discover-aps-2026-02-14-10-30-05.xlsx

- date = YYYY-MM-DD, time = HH-MM-SS in IST (Asia/Kolkata, UTC+5:30)
  (colons replaced so it is Windows-safe).
- Each call creates a NEW file, never appends/overwrites.
- ANSI colour codes from terminal tables are stripped.
- openpyxl is required (see dependencies.py). If missing, export is
  skipped with a warning instead of crashing the scan.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Sequence, Tuple, Any

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# IST (Asia/Kolkata, UTC+5:30) — fixed offset, no DST, so this is exact.
# All report filenames + exported_at stamps use IST regardless of the
# machine's system timezone.
_IST = timezone(timedelta(hours=5, minutes=30))


def now_ist() -> datetime:
    """Current time in IST, returned naive (no tzinfo) for formatting."""
    return datetime.now(_IST).replace(tzinfo=None)


def clean_cell(value: Any) -> Any:
    """Make a value Excel-safe: strip ANSI, convert None/bool."""
    if value is None:
        return "?"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (int, float)):
        return value
    s = str(value)
    s = _ANSI_RE.sub("", s)
    return s.strip() if s.strip() != "" else "?"


def build_filename(scan_name: str, out_dir: str | Path = "scans") -> Path:
    """Build <scan-name>-{date}-{time}.xlsx path (parent NOT created).

    The {date}-{time} stamp is IST (Asia/Kolkata).
    """
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", str(scan_name).strip() or "scan")
    now = now_ist()
    date_part = now.strftime("%Y-%m-%d")
    time_part = now.strftime("%H-%M-%S")
    return Path(out_dir) / f"{safe}-{date_part}-{time_part}.xlsx"


def save_scan_excel(
    scan_name: str,
    sheets: Dict[str, Tuple[Sequence[str], Sequence[Sequence[Any]]]],
    out_dir: str | Path = "scans",
    meta: Dict[str, Any] | None = None,
) -> str | None:
    """Save scan findings to a timestamped .xlsx file.

    Args:
        scan_name: e.g. "discover-aps", "clients", "vuln-assessment",
            "pnl", "decloak", "rogue-detection".
        sheets: {sheet_title: (headers, rows)} — rows are lists/tuples.
        out_dir: folder for reports (created if missing).
        meta: optional {key: value} written to a "Meta" sheet
            (interface, target, timestamp...).

    Returns:
        File path as str, or None if openpyxl is missing / write failed.
    """
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment
        from openpyxl.utils import get_column_letter
    except ImportError:
        try:
            from ui import UI
            UI.warn("openpyxl not installed — skipping Excel export "
                    "(pip install openpyxl / apt install python3-openpyxl).")
        except Exception:
            pass
        return None

    out_path = build_filename(scan_name, out_dir)
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    # Guarantee no overwrite/data-loss: if a file with the same
    # second-resolution timestamp already exists (e.g. two scans in the
    # same second), append -1, -2, ...  Filename pattern stays
    # <scan-name>-{date}-{time}.xlsx with an optional numeric suffix.
    try:
        if out_path.exists():
            stem = out_path.stem  # e.g. discover-aps-2026-02-14-10-30-05
            suffix = out_path.suffix  # .xlsx
            n = 1
            while True:
                candidate = out_path.parent / f"{stem}-{n}{suffix}"
                if not candidate.exists():
                    out_path = candidate
                    break
                n += 1
    except Exception:
        pass

    try:
        wb = Workbook()
        # Remove default sheet; we add our own (or a placeholder).
        wb.remove(wb.active)

        header_font = Font(bold=True, color="FFFFFF")
        header_fill = PatternFill(start_color="1F4E78", end_color="1F4E78",
                                  fill_type="solid")
        header_align = Alignment(horizontal="center", vertical="center",
                                 wrap_text=True)

        if not sheets:
            ws = wb.create_sheet("Empty")
            ws["A1"] = "No findings captured in this scan."
        else:
            for title, (headers, rows) in sheets.items():
                safe_title = re.sub(r"[:\\/?*\[\]]", "-", str(title))[:31] or "Sheet"
                ws = wb.create_sheet(safe_title)
                clean_headers = [clean_cell(h) for h in (headers or [])]
                for c, h in enumerate(clean_headers, start=1):
                    cell = ws.cell(row=1, column=c, value=h)
                    cell.font = header_font
                    cell.fill = header_fill
                    cell.alignment = header_align
                for r_idx, row in enumerate(rows or [], start=2):
                    try:
                        for c_idx in range(len(clean_headers)):
                            try:
                                v = row[c_idx]
                            except (IndexError, TypeError):
                                v = "?"
                            ws.cell(row=r_idx, column=c_idx + 1,
                                    value=clean_cell(v))
                    except Exception:
                        continue
                # Freeze header, autofilter, autosize.
                try:
                    ws.freeze_panes = "A2"
                    if clean_headers:
                        ws.auto_filter.ref = (
                            f"A1:{get_column_letter(len(clean_headers))}"
                            f"{max(1, (len(list(rows or []))) + 1)}"
                        )
                    for c_idx, h in enumerate(clean_headers, start=1):
                        max_len = len(str(h))
                        for row in (rows or []):
                            try:
                                max_len = max(max_len, len(str(clean_cell(row[c_idx - 1]))))
                            except Exception:
                                pass
                        ws.column_dimensions[get_column_letter(c_idx)].width = min(50, max(12, max_len + 2))
                except Exception:
                    pass

        # Meta sheet — scan context for forensics.
        try:
            ws = wb.create_sheet("Meta")
            ws["A1"] = "Field"
            ws["B1"] = "Value"
            for c in ("A1", "B1"):
                ws[c].font = header_font
                ws[c].fill = header_fill
                ws[c].alignment = header_align
            meta = dict(meta or {})
            meta.setdefault("scan", scan_name)
            meta.setdefault("exported_at", now_ist().strftime("%Y-%m-%d %H:%M:%S") + " IST")
            for i, (k, v) in enumerate(meta.items(), start=2):
                ws.cell(row=i, column=1, value=clean_cell(k))
                ws.cell(row=i, column=2, value=clean_cell(v))
            ws.column_dimensions["A"].width = 22
            ws.column_dimensions["B"].width = 60
        except Exception:
            pass

        wb.save(str(out_path))
        return str(out_path)
    except Exception as e:
        try:
            from ui import UI
            UI.warn(f"Excel export failed: {e}")
        except Exception:
            pass
        return None


# ── Convenience wrappers (thin, so main.py stays readable) ──────────────

def export_aps(results: List[list], headers: Sequence[str],
               out_dir: str | Path = "scans", **meta) -> str | None:
    return save_scan_excel("discover-aps", {"APs": (list(headers), list(results or []))},
                           out_dir=out_dir, meta=meta)


def export_clients(rows: List[list], out_dir: str | Path = "scans", **meta) -> str | None:
    headers = ["Access Point", "AP Vendor", "Connected Client",
               "Client Vendor", "Status", "RSSI", "First Seen", "Last Seen"]
    return save_scan_excel("clients", {"Clients": (headers, list(rows or []))},
                           out_dir=out_dir, meta=meta)


def export_probes(rows: List[list], first_seen: Dict | None = None,
                  out_dir: str | Path = "scans", **meta) -> str | None:
    from typing import Any as _Any  # local alias, no-op
    headers = ["SRC MAC", "Vendor", "SSID (Probed)", "Count",
               "First Seen", "Last Seen", "Notes"]
    # Lazy import to avoid circulars in unit tests.
    try:
        from audit_engine import WirelessAuditEngine
        _notes = WirelessAuditEngine._probe_notes
    except Exception:
        def _notes(ssid, count):  # type: ignore
            return ""
    out_rows: List[list] = []
    for r in (rows or []):
        try:
            src, vendor, ssid, count, last = r[0], r[1], r[2], r[3], r[4]
            first = (first_seen or {}).get((src, ssid), last) if first_seen is not None else last
            out_rows.append([src, vendor, ssid, count, first, last, _notes(ssid, count)])
        except Exception:
            continue
    return save_scan_excel("pnl", {"Probed SSIDs": (headers, out_rows)},
                           out_dir=out_dir, meta=meta)


def export_decloaked(rows: List[list], out_dir: str | Path = "scans", **meta) -> str | None:
    headers = ["BSSID (Hidden AP)", "Decloaked SSID", "Client MAC",
               "Client Vendor", "Frame", "Time", "CH"]
    return save_scan_excel("decloak", {"Decloaked": (headers, list(rows or []))},
                           out_dir=out_dir, meta=meta)


def export_rogue(rows: List[list], legit: Dict | None = None,
                 out_dir: str | Path = "scans", **meta) -> str | None:
    headers = ["Suspect BSSID", "SSID", "CH", "RSSI", "Encryption",
               "MFPC", "MFPR", "Uptime", "Score", "Risk", "Reasons"]
    sheets: Dict[str, Tuple[Sequence[str], Sequence[Sequence[Any]]]] = {
        "Rogue Candidates": (headers, list(rows or []))
    }
    if legit:
        sheets["Legit Baseline"] = (
            ["Field", "Value"],
            [[k, v] for k, v in dict(legit).items()],
        )
    return save_scan_excel("rogue-detection", sheets, out_dir=out_dir, meta=meta)


def sanitize_project_name(name: str | None) -> str:
    """Make a project/engagement name filesystem-safe for a directory name.

    Keeps letters, digits, dot, underscore, dash; everything else becomes
    '-'. Returns "" if nothing usable remains (caller falls back to a
    default like audit-<date>-<time>).
    """
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", str(name or "").strip()).strip("-.")
    return safe[:64]


def export_vuln(findings: List[Dict[str, Any]], bssid: str = "",
                out_dir: str | Path = "scans", **meta) -> str | None:
    headers = ["Severity", "ID", "Finding", "Description", "Evidence", "Remediation"]
    rows = [[f.get("severity", "?"), f.get("id", "?"), f.get("name", "?"),
             f.get("description", "?"), f.get("evidence", "?"),
             f.get("remediation", "?")] for f in (findings or [])]
    meta = {"target_bssid": bssid, **(meta or {})}
    return save_scan_excel("vuln-assessment", {"Findings": (headers, rows)},
                           out_dir=out_dir, meta=meta)


def export_deauth(counts: Dict | None,
                  out_dir: str | Path = "scans", **meta) -> str | None:
    """Report a deauth/disassoc run (option 4).

    `counts` is WirelessAuditEngine._deauth_counts:
    {(tx, rx, subtype, reason): frames_sent}. Unicast pairs count 2.
    """
    try:
        from audit_engine import WirelessAuditEngine as _Eng
        _rname = _Eng.reason_name
    except Exception:
        def _rname(code):  # type: ignore
            return f"Reason {code}"
    rows: List[list] = []
    total = 0
    for (tx, rx, st, rs), c in (dict(counts or {})).items():
        try:
            n = int(c)
        except Exception:
            continue
        total += n
        try:
            fname = "Disassociation" if int(st) == 10 else "Deauthentication"
        except Exception:
            fname = str(st)
        try:
            rlabel = f"{rs} ({_rname(rs)})"
        except Exception:
            rlabel = str(rs)
        rows.append([tx, rx, fname, rlabel, n])
    headers = ["Transmitter", "Receiver", "Frame", "Reason", "Frames Sent"]
    meta = {"total_frames_sent": total, **(meta or {})}
    return save_scan_excel("deauth", {"Frames": (headers, rows)},
                           out_dir=out_dir, meta=meta)


def export_eviltwin(config: Dict[str, Any] | None,
                    creds: List[Dict[str, Any]] | None = None,
                    db_path: str | Path | None = None,
                    out_dir: str | Path = "scans", **meta) -> str | None:
    """Report an evil-twin run (option 5): config + captured credentials.

    `creds` = EvilTwin._creds ({portal, ssid, username, password, ip, ts}).
    If empty, falls back to the sqlite credentials table at `db_path`
    (filtered to the twin SSID when known).
    """
    cfg_rows = [[k, v] for k, v in dict(config or {}).items()]
    sheets: Dict[str, Tuple[Sequence[str], Sequence[Sequence[Any]]]] = {
        "Config": (["Setting", "Value"], cfg_rows),
    }
    merged: List[list] = []
    seen = set()

    def _add(ssid, user, pw, src, ip, ts):
        try:
            key = (str(user), str(pw), str(ts))
        except Exception:
            return
        if key in seen:
            return
        seen.add(key)
        merged.append([ssid, user, pw, src, ip, ts])

    for c in (creds or []):
        try:
            if isinstance(c, dict):
                _add(c.get("ssid", "?"), c.get("username", "?"),
                     c.get("password", "?"),
                     c.get("portal") or c.get("source", "?"),
                     c.get("ip", "?"), c.get("ts", "?"))
            elif isinstance(c, (list, tuple)) and len(c) >= 4:
                _add(c[0], c[1], c[2], c[3],
                     c[4] if len(c) > 4 else "?",
                     c[5] if len(c) > 5 else "?")
        except Exception:
            continue
    # SQLite fallback — same DB the portal writes to.
    try:
        if db_path and Path(db_path).exists():
            import sqlite3
            ssid_f = (config or {}).get("ssid")
            con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            try:
                q = "SELECT ssid, username, password, source, ts FROM credentials"
                qargs: tuple = ()
                if ssid_f:
                    q += " WHERE ssid = ?"
                    qargs = (ssid_f,)
                for (s, u, p, src, ts) in con.execute(q, qargs).fetchall():
                    _add(s, u, p, src, "?", ts)
            finally:
                try:
                    con.close()
                except Exception:
                    pass
    except Exception:
        pass
    sheets["Credentials"] = (
        ["SSID", "Username", "Password", "Source/Portal", "Client IP", "Timestamp"],
        merged,
    )
    meta = {"credentials_captured": len(merged), **(meta or {})}
    return save_scan_excel("evil-twin", sheets, out_dir=out_dir, meta=meta)


def export_wps(result: Dict[str, Any] | None,
               out_dir: str | Path = "scans", **meta) -> str | None:
    """Report a WPS assessment (option 8).

    `result` is WPSAttack.run()'s dict: {bssid, pin, psk, log, ...}.
    """
    r = dict(result or {})
    rows = [[k, v] for k, v in r.items()]
    m = {"target_bssid": r.get("bssid", "?"),
         "pin_recovered": bool(r.get("pin")),
         "psk_recovered": bool(r.get("psk")),
         **(meta or {})}
    return save_scan_excel("wps-assessment", {"Result": (["Field", "Value"], rows)},
                           out_dir=out_dir, meta=m)


def export_mitm(result: Dict[str, Any] | None,
                out_dir: str | Path = "scans", **meta) -> str | None:
    """Report a MITM session (option 9).

    `result` is MITMAttack.run()'s dict:
    {ok, backend, capture, creds:[{host, preview}]}.
    """
    r = dict(result or {})
    sess_rows = [[k, v] for k, v in r.items() if k != "creds"]
    crows: List[list] = []
    for c in (r.get("creds") or []):
        try:
            crows.append([c.get("host", "?"), c.get("preview", "?")])
        except Exception:
            continue
    sheets: Dict[str, Tuple[Sequence[str], Sequence[Sequence[Any]]]] = {
        "Session": (["Field", "Value"], sess_rows),
        "Credential Hints": (["Host", "Preview"], crows),
    }
    m = {"credential_hints": len(crows), **(meta or {})}
    return save_scan_excel("mitm", sheets, out_dir=out_dir, meta=m)
