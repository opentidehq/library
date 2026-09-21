from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import patch_opentide_threat_lists as patch  # noqa: E402

SAMPLE = """\
class ThreatBody(TideModel):
    severity: str = VocabField(True)
    impact: str = VocabField(True)
    leverage: str = VocabField(True)
    surface: list[str] = VocabField(True)
"""

ALREADY_LISTS = SAMPLE.replace(
    "impact: str = VocabField(True)", "impact: list[str] = VocabField(True)"
).replace("leverage: str = VocabField(True)", "leverage: list[str] = VocabField(True)")


def test_patch_threat_source_rewrites_str_fields() -> None:
    patched, changed = patch.patch_threat_source(SAMPLE)
    assert changed is True
    assert "impact: list[str] = VocabField(True)" in patched
    assert "leverage: list[str] = VocabField(True)" in patched
    assert "impact: str = VocabField(True)" not in patched
    assert "leverage: str = VocabField(True)" not in patched
    assert "surface: list[str] = VocabField(True)" in patched


def test_patch_threat_source_is_noop_when_already_lists() -> None:
    patched, changed = patch.patch_threat_source(ALREADY_LISTS)
    assert changed is False
    assert patched == ALREADY_LISTS


def test_patch_file_writes_once(tmp_path: Path) -> None:
    target = tmp_path / "threat.py"
    target.write_text(SAMPLE, encoding="utf-8")
    assert patch.patch_file(target) is True
    assert "impact: list[str] = VocabField(True)" in target.read_text(encoding="utf-8")
    assert patch.patch_file(target) is False
