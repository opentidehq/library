from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "scripts" / "opentide_run.py"


def test_wrapper_is_a_thin_cli_passthrough() -> None:
    source = WRAPPER.read_text(encoding="utf-8")
    assert "_load_objects_sequential" not in source
    assert "_load_objects_parallel" not in source
    assert "from opentide.cli import main" in source


def test_wrapper_help_runs_against_installed_opentide() -> None:
    result = subprocess.run(
        [sys.executable, str(WRAPPER), "--help"],
        check=False,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert result.returncode == 0, result.stderr
    assert "Usage" in result.stdout or "usage" in result.stdout.lower()
