#!/usr/bin/env python3
"""Rename object YAML files to dash-case slugs derived from the name field."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import yaml


def slugify(name: str) -> str:
    """Match opentide.documentation.markdown.links.slugify."""
    slug = re.sub(r"[^A-Za-z0-9]+", "-", name.strip()).strip("-").lower()
    return slug or "object"

FAMILIES = ("threats", "objectives", "rules")


def _load_name(path: Path) -> tuple[str, str]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected mapping in {path}")
    name = str(data.get("name") or path.stem)
    uuid = str((data.get("metadata") or {}).get("uuid") or "")
    return name, uuid


def _target_slug(name: str, uuid: str, used: set[str]) -> str:
    base = slugify(name)
    if base not in used:
        return base
    suffix = uuid.replace("-", "")[:8] if uuid else "collision"
    candidate = f"{base}-{suffix}"
    if candidate not in used:
        return candidate
    raise RuntimeError(f"Could not resolve slug collision for {name!r} ({uuid})")


def plan_renames(objects_root: Path) -> list[tuple[Path, Path]]:
    plans: list[tuple[Path, Path]] = []
    for family in FAMILIES:
        family_dir = objects_root / family
        if not family_dir.is_dir():
            continue
        used: set[str] = set()
        pending: list[tuple[Path, str, str]] = []
        for path in sorted(family_dir.glob("*.yaml")):
            name, uuid = _load_name(path)
            pending.append((path, name, uuid))
        for path, name, uuid in pending:
            slug = _target_slug(name, uuid, used)
            used.add(slug)
            target = path.parent / f"{slug}.yaml"
            if path != target:
                plans.append((path, target))
    return plans


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    objects_root = args.root / "objects"
    plans = plan_renames(objects_root)
    collisions = [p for p in plans if "-" in p[1].stem and p[1].stem.count("-") > slugify(_load_name(p[0])[0]).count("-")]
    print(f"Planned renames: {len(plans)}")
    for src, dst in plans:
        print(f"  {src.relative_to(args.root)} -> {dst.name}")
    if args.dry_run:
        return
    for src, dst in plans:
        if dst.exists() and dst != src:
            raise FileExistsError(f"Target already exists: {dst}")
        src.rename(dst)
    print("Done.")


if __name__ == "__main__":
    main()
