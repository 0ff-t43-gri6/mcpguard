"""Run every quality check the project uses, then print a summary.

    python scripts/check.py           # lint, types, security lint, dead code, tests + coverage
    python scripts/check.py --full    # also a clean-install package check, the large property
                                      # campaign and a dependency audit
    python scripts/check.py --fast    # skip tests

Exits non-zero if any check fails. Works on Windows, macOS and Linux.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable

DEV_REQUIREMENTS = ["pytest>=8", "pytest-cov", "ruff>=0.6", "mypy>=1.10", "hypothesis>=6.100",
                    "tomli-w>=1.0", "bandit", "vulture", "pip-audit"]


# Fail the tests on any text I/O that relies on the platform encoding (not UTF-8 on Windows).
ENC = {"PYTHONWARNDEFAULTENCODING": "1"}


def _importable(module: str) -> bool:
    return subprocess.run([PY, "-c", f"import {module}"], capture_output=True, check=False).returncode == 0


def checks(full: bool, fast: bool) -> list[tuple[str, list[str], dict]]:
    out = [
        ("ruff (lint)", [PY, "-m", "ruff", "check", "src", "tests", "scripts"], {}),
        ("mypy (types)", [PY, "-m", "mypy", "src"], {}),
        # mypy only checks the branches for the platform it runs on; check the other two as well,
        # so Windows-only code is checked on Linux and the other way round.
        *[(f"mypy ({name})", [PY, "-m", "mypy", "--platform", plat, "src"], {})
          for name, plat in (("as Windows", "win32"), ("as macOS", "darwin"), ("as Linux", "linux"))
          if plat != sys.platform],
        ("bandit (security lint)", [PY, "-m", "bandit", "-q", "-r", "src", "-c", "pyproject.toml"], {}),
        ("vulture (dead code)", [PY, "-m", "vulture", "src", "scripts/vulture_whitelist.py",
                                 "--min-confidence", "60"], {}),
    ]
    if not fast:
        if _importable("pytest_cov"):
            out.append(("pytest + coverage", [PY, "-m", "pytest", "-q", "--cov", "--cov-report=term"], ENC))
        else:
            out.append(("pytest (no coverage: pytest-cov missing)", [PY, "-m", "pytest", "-q"], ENC))
    if full:
        out.append(("package (build, clean install, self-test)", [PY, "scripts/package_check.py"], ENC))
        out.append(("property campaign", [PY, "-m", "pytest", "-q", "tests/test_properties.py", "-p", "no:randomly"],
                    {"HYPOTHESIS_PROFILE": "campaign"}))
        reqs = ROOT / ".dev-requirements.txt"
        reqs.write_text("\n".join(DEV_REQUIREMENTS) + "\n", encoding="utf-8")
        out.append(("pip-audit (dependencies)", [PY, "-m", "pip_audit", "--progress-spinner", "off",
                                                 "-r", str(reqs)], {}))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--full", action="store_true", help="add the property campaign and dependency audit")
    ap.add_argument("--fast", action="store_true", help="skip the test suite")
    ap.add_argument("--install", action="store_true",
                    help='first run: pip install -e ".[dev]" into this Python')
    a = ap.parse_args()

    if a.install:
        print(f'== installing dev tools into {PY}', flush=True)
        code = subprocess.run([PY, "-m", "pip", "install", "-e", ".[dev]"], cwd=ROOT, check=False).returncode
        if code:
            print("pip install failed; see the output above.")
            return code

    results = []
    for name, cmd, env in checks(a.full, a.fast):
        tool = cmd[2] if cmd[1] == "-m" else cmd[1]
        is_script = tool.endswith(".py")  # our own scripts need no installed tool
        if not is_script and (shutil.which(PY) is None or not _importable(tool.split(".")[0])):
            results.append((name, "missing", 0.0))
            print(f"\n== {name}: not installed")
            continue
        print(f"\n== {name}", flush=True)
        start = time.perf_counter()
        code = subprocess.run(cmd, cwd=ROOT, env={**os.environ, **env}, check=False).returncode
        results.append((name, "ok" if code == 0 else "FAILED", time.perf_counter() - start))
    (ROOT / ".dev-requirements.txt").unlink(missing_ok=True)

    print("\nSummary")
    width = max(len(n) for n, _, _ in results)
    for name, status, secs in results:
        print(f"  {name:<{width}}  {status:<8} {secs:6.1f}s")
    failed = [n for n, s, _ in results if s != "ok"]
    print(f"\n{'All checks passed.' if not failed else 'Failed: ' + ', '.join(failed)}")
    if any(s == "missing" for _, s, _ in results):
        print(f'\nSome tools are not installed in this Python ({PY}).\n'
              'Install them once with:  python scripts/check.py --install\n'
              '(or: python -m pip install -e ".[dev]")')
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
