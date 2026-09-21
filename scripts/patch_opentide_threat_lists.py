#!/usr/bin/env python3
"""Patch installed opentide ThreatBody.impact/leverage to list[str].

``threat-1.0`` requires YAML lists of vocab tokens (specifications#12).
Released opentide through 0.3.0 still types those fields as ``str``
(opentide#189), so ``opentide validate --strict`` rejects this catalogue.

This rewrites the installed ``opentide.models.threat`` source in place and
is a no-op once the engine already uses ``list[str]``. Remove the CI step
and this script when that release is the PyPI default.
"""

from __future__ import annotations

from pathlib import Path

IMPACT_STR = "impact: str = VocabField(True)"
IMPACT_LIST = "impact: list[str] = VocabField(True)"
LEVERAGE_STR = "leverage: str = VocabField(True)"
LEVERAGE_LIST = "leverage: list[str] = VocabField(True)"


def threat_model_path() -> Path:
    import opentide.models.threat as threat

    return Path(threat.__file__)


def patch_threat_source(source: str) -> tuple[str, bool]:
    patched = source.replace(IMPACT_STR, IMPACT_LIST).replace(LEVERAGE_STR, LEVERAGE_LIST)
    return patched, patched != source


def patch_file(path: Path) -> bool:
    original = path.read_text(encoding="utf-8")
    patched, changed = patch_threat_source(original)
    if changed:
        path.write_text(patched, encoding="utf-8")
    return changed


def main() -> int:
    path = threat_model_path()
    if patch_file(path):
        print(f"patched {path} (opentide#189 list[str] workaround)")
    else:
        print(f"no patch needed for {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
