"""Build the wheel, install it into a clean virtual environment and run it.

    python scripts/package_check.py

Catches what tests against the source tree cannot: a data file missing from the package, a
broken entry point, an accidental runtime dependency.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import venv
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NEEDED = ["mcpguard/dashboard.html", "mcpguard/py.typed", "mcpguard/data/iocs.json",
          "mcpguard/data/injection_model.json", "mcpguard/data/confusables.json", "mcpguard/data/advisories.json"]


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, capture_output=True, text=True, encoding="utf-8", **kw)


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        dist = Path(tmp) / "dist"
        run([sys.executable, "-m", "pip", "wheel", "--no-deps", "-q", "-w", str(dist), str(ROOT)])
        wheel = next(dist.glob("mcpguard-*.whl"))
        names = set(zipfile.ZipFile(wheel).namelist())
        missing = [n for n in NEEDED if n not in names]
        if missing:
            print(f"wheel is missing: {', '.join(missing)}")
            return 1
        env = Path(tmp) / "venv"
        venv.create(env, with_pip=True)
        bin_dir = env / ("Scripts" if sys.platform == "win32" else "bin")
        run([str(bin_dir / "python"), "-m", "pip", "install", "-q", "--no-index", str(wheel)])
        exe = str(bin_dir / "mcpguard")
        version = run([exe, "--version"], cwd=tmp).stdout.strip()
        test = subprocess.run([exe, "selftest"], cwd=tmp, capture_output=True, text=True, encoding="utf-8",
                              check=False)
        print(f"{wheel.name}: installs with no dependencies; {version}")
        print(test.stdout.strip().splitlines()[-1])
        return test.returncode


if __name__ == "__main__":
    sys.exit(main())
