#!/usr/bin/env python3
"""One-off ShareTide → OpenTide Library content migration."""

from __future__ import annotations

import argparse
import copy
import shutil
from pathlib import Path
from typing import Any

import yaml
from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import LiteralScalarString

from opentide.documentation.markdown.links import slugify

SOURCE_MAP = {
    "Objects/Threat Vectors": "objects/threats",
    "Objects/Detection Objectives": "objects/objectives",
    "Objects/Detection Rules": "objects/rules",
}

SCHEMA_MAP = {
    "tvm::2.0": "threat::1.0",
    "tvm::2.1": "threat::1.0",
    "dom::1.0": "objective::1.0",
    "mdr::2.0": "rule::1.0",
    "mdr::2.1": "rule::1.0",
}

THREAT_EXTRA_KEYS = frozenset({"domains", "targets", "cve", "misp", "platforms", "surface"})


def _load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected mapping in {path}")
    return data


def _format_extra_value(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(str(item).strip() for item in value if item is not None and str(item).strip())
    if value is None:
        return ""
    return str(value).strip()


def _wrap_literal_scalars(value: Any) -> Any:
    if isinstance(value, str):
        if "\n" in value:
            return LiteralScalarString(value.rstrip("\n"))
        return value
    if isinstance(value, dict):
        return {key: _wrap_literal_scalars(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_wrap_literal_scalars(item) for item in value]
    return value


_yaml_writer = YAML()
_yaml_writer.default_flow_style = False
_yaml_writer.width = 4096
_yaml_writer.indent(mapping=2, sequence=4, offset=2)


def _dump_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        _yaml_writer.dump(_wrap_literal_scalars(data), handle)


def _scalar_list_to_string(value: Any) -> str:
    if isinstance(value, list):
        parts = [str(item).strip() for item in value if item is not None and str(item).strip()]
        return "; ".join(parts) if parts else ""
    if value is None:
        return ""
    return str(value).strip()


def _flatten_actors(actors: Any) -> list[str] | None:
    if not actors:
        return None
    if not isinstance(actors, list):
        return None
    flat: list[str] = []
    for item in actors:
        if isinstance(item, str):
            flat.append(item.split("#", 1)[0].strip())
        elif isinstance(item, dict) and "name" in item:
            flat.append(str(item["name"]).split("#", 1)[0].strip())
    return flat or None


def _fold_extra_threat_fields(threat: dict[str, Any]) -> None:
    extras: list[str] = []
    for key in THREAT_EXTRA_KEYS:
        if key not in threat:
            continue
        value = threat.pop(key)
        formatted = _format_extra_value(value)
        if formatted:
            label = key.replace("_", " ").title()
            extras.append(f"{label}: {formatted}")
    if extras:
        terrain = str(threat.get("terrain") or "").rstrip()
        suffix = "\n".join(extras)
        threat["terrain"] = f"{terrain}\n\n{suffix}".strip() if terrain else suffix


def _migrate_threat(data: dict[str, Any]) -> dict[str, Any]:
    metadata = data.setdefault("metadata", {})
    schema = metadata.get("schema", "")
    metadata["schema"] = SCHEMA_MAP.get(schema, "threat::1.0")

    threat = data.get("threat")
    if isinstance(threat, dict):
        if "actors" in threat:
            threat["actors"] = _flatten_actors(threat["actors"])
        for field in ("impact", "leverage"):
            if field in threat:
                threat[field] = _scalar_list_to_string(threat[field])
        _fold_extra_threat_fields(threat)
    return data


def _migrate_objective(data: dict[str, Any]) -> dict[str, Any]:
    metadata = data.setdefault("metadata", {})
    schema = metadata.get("schema", "")
    metadata["schema"] = SCHEMA_MAP.get(schema, "objective::1.0")

    objective = data.get("objective")
    if isinstance(objective, dict):
        if "att&ck" in objective:
            objective["attack"] = objective.pop("att&ck")
        composition = objective.get("composition")
        if composition and "composition" not in data:
            data["composition"] = copy.deepcopy(composition)

    return data


def _build_signal_to_objective_map(source: Path) -> dict[str, str]:
    mapping: dict[str, str] = {}
    obj_dir = source / "Objects/Detection Objectives"
    for path in obj_dir.glob("*.yaml"):
        data = _load_yaml(path)
        objective_uuid = data.get("metadata", {}).get("uuid")
        if not objective_uuid:
            continue
        signals = (data.get("objective") or {}).get("signals") or []
        if isinstance(signals, list):
            for signal in signals:
                if isinstance(signal, dict) and signal.get("uuid"):
                    mapping[str(signal["uuid"])] = str(objective_uuid)
    return mapping


def _extract_techniques(data: dict[str, Any]) -> list[str]:
    techniques: list[str] = []
    configs = data.get("configurations")
    if isinstance(configs, dict):
        for block in configs.values():
            if not isinstance(block, dict):
                continue
            alert = block.get("alert")
            if isinstance(alert, dict):
                for tech in alert.get("techniques") or []:
                    if tech not in techniques:
                        techniques.append(str(tech))
    return techniques


def _migrate_rule_platform(name: str, platform: str, block: dict[str, Any]) -> dict[str, Any]:
    from opentide.loading.platform_loader import load_platform_config

    migrated = dict(block)
    migrated.pop("schema", None)
    migrated.pop("threshold", None)
    migrated.setdefault("enabled", True)
    migrated.setdefault("name", name)
    try:
        cfg = load_platform_config(platform, migrated)
        return cfg.model_dump(by_alias=True, exclude_none=True)
    except Exception:
        return migrated


def _migrate_rule(data: dict[str, Any], signal_objective_map: dict[str, str]) -> dict[str, Any]:
    metadata = data.setdefault("metadata", {})
    schema = metadata.get("schema", "")
    metadata["schema"] = SCHEMA_MAP.get(schema, "rule::1.0")

    name = str(data.get("name", "rule"))
    response = data.get("response") if isinstance(data.get("response"), dict) else {}
    data.setdefault("status", "STAGING")
    data.setdefault("severity", response.get("alert_severity", "Informational"))
    data.setdefault("techniques", _extract_techniques(data))

    if isinstance(data.get("configurations"), dict):
        configs: dict[str, Any] = {}
        for platform, block in data["configurations"].items():
            if isinstance(block, dict):
                configs[platform] = _migrate_rule_platform(name, platform, block)
        data["configurations"] = configs

    dm = data.get("detection_model")
    if isinstance(dm, str):
        dm = dm.strip()
        if dm.startswith("#"):
            data.pop("detection_model", None)
        elif dm in signal_objective_map:
            data["detection_model"] = signal_objective_map[dm]

    return data


def _migrate_file(data: dict[str, Any], family: str, signal_objective_map: dict[str, str]) -> dict[str, Any]:
    if family == "threats":
        return _migrate_threat(data)
    if family == "objectives":
        return _migrate_objective(data)
    return _migrate_rule(data, signal_objective_map)


def _object_output_path(out_dir: Path, data: dict[str, Any], used: set[str]) -> Path:
    name = str(data.get("name") or "object")
    uuid = str((data.get("metadata") or {}).get("uuid") or "")
    base = slugify(name)
    slug = base
    if slug in used:
        suffix = uuid.replace("-", "")[:8] if uuid else "collision"
        slug = f"{base}-{suffix}"
    used.add(slug)
    return out_dir / f"{slug}.yaml"


def migrate(source: Path, dest: Path, *, dry_run: bool = False) -> dict[str, int]:
    counts = {"threats": 0, "objectives": 0, "rules": 0}
    signal_objective_map = _build_signal_to_objective_map(source)
    for src_rel, dest_rel in SOURCE_MAP.items():
        family = Path(dest_rel).name
        src_dir = source / src_rel
        out_dir = dest / dest_rel
        if not src_dir.is_dir():
            raise FileNotFoundError(src_dir)
        if out_dir.exists() and not dry_run:
            shutil.rmtree(out_dir)
        used_slugs: set[str] = set()
        for src_file in sorted(src_dir.glob("*.yaml")):
            migrated = _migrate_file(_load_yaml(src_file), family, signal_objective_map)
            out_path = _object_output_path(out_dir, migrated, used_slugs)
            if not dry_run:
                _dump_yaml(out_path, migrated)
            counts[family] += 1
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("../ShareTide"))
    parser.add_argument("--dest", type=Path, default=Path("."))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    source = args.source.resolve()
    dest = args.dest.resolve()
    counts = migrate(source, dest, dry_run=args.dry_run)
    total = sum(counts.values())
    print(f"Migrated {total} objects: {counts}")


if __name__ == "__main__":
    main()
