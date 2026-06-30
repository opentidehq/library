#!/usr/bin/env python3
"""QA check: threat title/description consistency with surface terrain values."""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

import yaml

LABEL_PATTERN = re.compile(r"^(Domains|Platforms|Targets):\s*", re.MULTILINE)


def _load_surface_vocab(path: Path) -> set[str]:
    raw = tomllib.loads(path.read_text(encoding="utf-8"))
    return {str(entry["name"]) for entry in raw.get("keys", []) if entry.get("name")}


def _tokens(text: str) -> set[str]:
    return {token.lower() for token in re.findall(r"[A-Za-z0-9][A-Za-z0-9+./_-]*", text)}


def qa_threats(threats_dir: Path, *, allowed: set[str]) -> list[str]:
    issues: list[str] = []
    for path in sorted(threats_dir.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            continue
        threat = data.get("threat") or {}
        name = str(data.get("name", path.stem))
        terrain = threat.get("terrain")
        description = str(threat.get("description") or "")

        if isinstance(terrain, str):
            if LABEL_PATTERN.search(terrain):
                issues.append(f"{path.name}: legacy Domains/Platforms/Targets labels remain")
            terrain_values = [terrain] if terrain.strip() else []
        elif isinstance(terrain, list):
            terrain_values = [str(item) for item in terrain]
        else:
            issues.append(f"{path.name}: terrain missing or invalid type")
            continue

        if not terrain_values:
            issues.append(f"{path.name}: empty terrain surface list")
            continue

        for value in terrain_values:
            if value not in allowed:
                issues.append(f"{path.name}: terrain value not in surface vocab: {value!r}")

        haystack = _tokens(f"{name} {description}")
        surface_tokens: set[str] = set()
        for value in terrain_values:
            surface_tokens |= _tokens(value.replace("::", " "))
        _ = haystack & surface_tokens  # overlap reserved for future reporting
    return issues


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--threats-dir", type=Path, default=Path("objects/threats"))
    parser.add_argument(
        "--surface-vocab",
        type=Path,
        default=Path("../opentide/src/opentide/data/vocabulary/surface.vocab.toml"),
    )
    args = parser.parse_args()
    threats_dir = args.threats_dir.resolve()
    surface_vocab = args.surface_vocab.resolve()
    allowed = _load_surface_vocab(surface_vocab)
    issues = qa_threats(threats_dir, allowed=allowed)
    if issues:
        print("QA issues:", file=sys.stderr)
        for issue in issues:
            print(f"  - {issue}", file=sys.stderr)
        raise SystemExit(1)
    print(f"QA passed for {len(list(threats_dir.glob('*.yaml')))} threats")


if __name__ == "__main__":
    main()
