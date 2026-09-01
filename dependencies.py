import os
import sys
import importlib.util
import subprocess

from ui import UI

# -----------------------------------------------------------------------------
# SYSTEM & DEPENDENCY MANAGER
# -----------------------------------------------------------------------------

class DependencyManager:
    """Handles module verification and auto-installation via APT."""
    REQUIRED = [('scapy', 'scapy'), ('pyroute2', 'pyroute2'), ('tabulate', 'tabulate')]

    @classmethod
    def check_and_fix(cls):
        missing = [pkg for pkg, imp in cls.REQUIRED if not cls._is_installed(imp)]
        if not missing:
            return

        UI.warn(f"Missing dependencies: {', '.join(missing)}")
        for pkg, imp in cls.REQUIRED:
            if not cls._is_installed(imp):
                if not cls._install(pkg):
                    UI.error(f"Fatal: Failed to install {pkg}.")
                    sys.exit(1)

        UI.ok("Environment repaired. Restarting script...")
        os.execv(sys.executable, [sys.executable] + sys.argv)

    @staticmethod
    def _is_installed(name):
        return importlib.util.find_spec(name) is not None

    @staticmethod
    def _install(pkg):
        UI.info(f"Attempting installation of python3-{pkg}...")
        res = subprocess.run(['apt', 'install', '-y', f'python3-{pkg}'], capture_output=True, text=True)
        return res.returncode == 0
