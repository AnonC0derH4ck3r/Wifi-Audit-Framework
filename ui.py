# --- Optional External Dependency: Rich (Fallbacks provided) ---
try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import SpinnerColumn, Progress
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False

from tabulate import tabulate
from config import Config

# -----------------------------------------------------------------------------
# TERMINAL UI UTILITIES
# -----------------------------------------------------------------------------

class UI:
    """Handles professional CLI aesthetics and logging."""
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    CYAN   = '\033[96m'
    BLUE   = '\033[94m'
    MAGENTA= '\033[95m'
    RESET  = '\033[0m'
    BOLD   = '\033[1m'
    DIM    = '\033[2m'

    # ── decorative helpers ────────────────────────────────────────────────────

    @staticmethod
    def section(title: str):
        """Print a prominent section divider with a centred title."""
        width   = 72
        bar     = "─" * width
        padding = (width - len(title) - 2) // 2
        left    = "─" * padding
        right   = "─" * (width - padding - len(title) - 2)
        print(f"\n{UI.CYAN}{UI.BOLD}┌{bar}┐{UI.RESET}")
        print(f"{UI.CYAN}{UI.BOLD}│{left} {title} {right}│{UI.RESET}")
        print(f"{UI.CYAN}{UI.BOLD}└{bar}┘{UI.RESET}\n")

    @staticmethod
    def divider():
        """Print a thin horizontal rule."""
        print(f"{UI.DIM}{'─' * 74}{UI.RESET}")

    # ── banner ────────────────────────────────────────────────────────────────

    @staticmethod
    def print_banner():
        if RICH_AVAILABLE:
            console.print(Config.BANNER, style="bold cyan")
        else:
            print(f"{UI.CYAN}{UI.BOLD}{Config.BANNER}{UI.RESET}")

    # ── log helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def info(msg):  print(f"{UI.CYAN}[*]{UI.RESET} {msg}")
    @staticmethod
    def ok(msg):    print(f"{UI.GREEN}[+]{UI.RESET} {msg}")
    @staticmethod
    def warn(msg):  print(f"{UI.YELLOW}[!]{UI.RESET} {msg}")
    @staticmethod
    def error(msg): print(f"{UI.RED}[-]{UI.RESET} {msg}")

    # ── menu ──────────────────────────────────────────────────────────────────

    @staticmethod
    def show_menu() -> int:
        menu_rows = [
            ["1", "Discover Access Points",    "Scan nearby APs (required first step)"],
            ["2", "Enumerate Connected Devices","List clients associated with a target AP"],
            ["3", "Vulnerability Assessment",  "Analyse security posture of a target AP"],
            ["4", "Deauthentication Attack",   "Forcibly disconnect clients from an AP"],
            ["5", "Rogue Access Point",        "Stand up an evil-twin AP"],
            ["6", "PNL Extract",               "Pull Preferred Network List from probes"],
            ["0", "Exit",                      "Quit the framework"],
        ]

        UI.section("Main Menu")
        print(tabulate(
            menu_rows,
            headers=[
                f"{UI.BOLD}#{UI.RESET}",
                f"{UI.BOLD}Option{UI.RESET}",
                f"{UI.BOLD}Description{UI.RESET}",
            ],
            tablefmt="rounded_outline",
        ))
        print(f"\n{UI.DIM}  v1.0.0  │  Author: Huzefa Khalil{UI.RESET}\n")

        while True:
            try:
                choice = input(f"{UI.BOLD}  ❯ Enter choice [0-6]: {UI.RESET}").strip()
                if choice in {"1", "2", "3", "4", "5", "6", "0"}:
                    return int(choice)
                UI.warn(f"Invalid option '{choice}'. Choose 0–6.")
            except (KeyboardInterrupt, EOFError, ValueError):
                return 0

    # ── AP selection (used by options 2 & 3) ─────────────────────────────────

    @staticmethod
    def select_ap_from_results(results: list, table_headers: list) -> tuple:
        """
        Display the already-scanned APs in a numbered table and let the user
        pick one by serial number.  Returns (bssid, channel) of the chosen AP.

        `results`      – list of raw rows stored in WirelessAuditEngine.results
        `table_headers`– the column headers used in render_live_table()
        """
        if not results:
            # Caller should have checked this, but guard anyway
            UI.error("No AP data found. Run option 1 (Discover Access Points) first.")
            return None, None

        # Build a lightweight display table: #  BSSID  CH  SSID  ENCRYPTION
        display_rows = []
        for idx, row in enumerate(results, start=1):
            bssid      = row[0]
            channel    = row[1]
            ssid       = row[2]
            encryption = row[3]
            display_rows.append([
                f"{UI.BOLD}{idx}{UI.RESET}",
                f"{UI.GREEN}{bssid}{UI.RESET}",
                f"{UI.CYAN}{channel}{UI.RESET}",
                f"{UI.YELLOW}{ssid}{UI.RESET}",
                encryption,
            ])

        UI.section("Discovered Access Points")
        print(tabulate(
            display_rows,
            headers=[
                f"{UI.BOLD}#{UI.RESET}",
                f"{UI.BOLD}BSSID{UI.RESET}",
                f"{UI.BOLD}CH{UI.RESET}",
                f"{UI.BOLD}SSID{UI.RESET}",
                f"{UI.BOLD}Encryption{UI.RESET}",
            ],
            tablefmt="rounded_outline",
        ))
        print()

        while True:
            try:
                raw = input(f"{UI.BOLD}  ❯ Select target AP [1-{len(results)}]: {UI.RESET}").strip()
                sel = int(raw)
                if 1 <= sel <= len(results):
                    chosen  = results[sel - 1]
                    bssid   = chosen[0]
                    channel = chosen[1]
                    UI.ok(f"Target selected → BSSID: {UI.GREEN}{bssid}{UI.RESET}  Channel: {UI.CYAN}{channel}{UI.RESET}")
                    return bssid, channel
                UI.warn(f"Enter a number between 1 and {len(results)}.")
            except (ValueError, KeyboardInterrupt):
                print()
                UI.info("Selection cancelled.")
                return None, None
