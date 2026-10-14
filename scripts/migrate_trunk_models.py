#!/usr/bin/env python3
"""Migrate catalogue YAML to trunk opentide threat::1.0 / objective::1.0 shapes.

Transforms (OpenTideHQ/library#7):

- ``threat.actors`` strings -> ``{name: ...}`` objects
- semicolon-packed ``threat.impact`` / ``threat.leverage`` -> YAML lists
- ``signals.entities`` kept as scoped ``<Stage>::<Key>`` values, validated
  against the engine's ``signal.entities`` vocabulary (opentide#509 /
  specifications RFC 0005 capitalised the stage ids to Host/Network/Cloud)
- ``signals.severity`` validated against ``alert_severity::1.0``

Does not coerce actors in the engine. Does not collapse packed fields to a
single token. Semicolon-packed strings are not a valid ``list[string]`` encoding.

Signal severity is pinned to ``alert_severity::1.0`` (see
``src/opentide/data/pins/objective.toml`` -> ``objective.signals.severity``),
whose values are Informational/Low/Medium/High/Critical. The NCSC long names
(``severity::1.0``) are the THREAT severity vocabulary, a different field, and
must never be written onto a signal.
"""

from __future__ import annotations

import argparse
import copy
import sys
from pathlib import Path
from typing import Any, Mapping

import yaml
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.scalarstring import LiteralScalarString

REPO_ROOT = Path(__file__).resolve().parents[1]

# Fallback stage ids used only when the engine vocabulary cannot be located
# (``--no-vocab`` or no installed opentide). The authoritative source is the
# ``[[stages]]`` table of ``signal.entities.vocab.toml``; see load_vocab_stages.
DEFAULT_ENTITY_STAGES: tuple[str, ...] = ("Host", "Network", "Cloud")

# The NCSC incident-categorisation names. These are the THREAT ``severity::1.0``
# vocabulary (``threat.severity``), NOT the signal severity vocabulary. Kept for
# the threat-severity invariant; never applied to ``objective.signals.severity``.
NCSC_SEVERITY = frozenset(
    {
        "Localised incident",
        "Moderate incident",
        "Substantial incident",
        "Significant incident",
        "Highly significant incident",
        "National cyber emergency",
    }
)

_yaml = YAML()
_yaml.default_flow_style = False
_yaml.width = 4096
_yaml.indent(mapping=2, sequence=4, offset=2)


class MigrationError(ValueError):
    """Raised when a catalogue object cannot be migrated safely."""


def split_packed_tokens(value: Any, *, field: str) -> list[str]:
    """Split a semicolon-packed string (or pass through a list) into vocab tokens.

    Empty tokens after split are dropped. Order is preserved. Adjacent duplicates
    are removed so ``A; A`` becomes ``[A]``. Non-adjacent duplicates are kept
    (they are a data issue the caller can reject via *allowed*).
    """
    if value is None:
        raise MigrationError(f"{field} is missing")
    if isinstance(value, list):
        tokens: list[str] = []
        for item in value:
            if not isinstance(item, str):
                raise MigrationError(f"{field} list items must be strings, got {type(item).__name__}")
            stripped = item.strip()
            if not stripped:
                continue
            if ";" in stripped:
                raise MigrationError(
                    f"{field} list item still contains a semicolon: {stripped!r}"
                )
            tokens.append(stripped)
        if not tokens:
            raise MigrationError(f"{field} list is empty")
        return _drop_adjacent_duplicates(tokens)
    if isinstance(value, str):
        tokens = [part.strip() for part in value.split(";") if part.strip()]
        if not tokens:
            raise MigrationError(f"{field} is empty")
        return _drop_adjacent_duplicates(tokens)
    raise MigrationError(f"{field} must be a string or list of strings, got {type(value).__name__}")


def _drop_adjacent_duplicates(tokens: list[str]) -> list[str]:
    out: list[str] = []
    for token in tokens:
        if out and out[-1] == token:
            continue
        out.append(token)
    return out


def assert_allowed(tokens: list[str], *, field: str, allowed: set[str] | None) -> None:
    if allowed is None:
        return
    unknown = [token for token in tokens if token not in allowed]
    if unknown:
        raise MigrationError(f"{field} tokens not in vocabulary: {', '.join(unknown)}")


def wrap_actors(value: Any) -> list[dict[str, Any]] | None:
    """Convert actor strings to ``{name: ...}`` objects; keep existing objects."""
    if value is None:
        return None
    if not isinstance(value, list):
        raise MigrationError(f"threat.actors must be a list, got {type(value).__name__}")
    wrapped: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if isinstance(item, str):
            name = item.strip()
            if not name:
                raise MigrationError(f"threat.actors[{index}] is empty")
            wrapped.append({"name": name})
            continue
        if isinstance(item, Mapping):
            name = item.get("name")
            if not isinstance(name, str) or not name.strip():
                raise MigrationError(f"threat.actors[{index}] object is missing name")
            entry = dict(item)
            entry["name"] = name.strip()
            wrapped.append(entry)
            continue
        raise MigrationError(
            f"threat.actors[{index}] must be a string or mapping, got {type(item).__name__}"
        )
    return wrapped


def validate_scoped_entity(value: str, *, stages: tuple[str, ...]) -> str:
    """Validate a ``<Stage>::<Key>`` entity and return it unchanged.

    opentide 0.14.0 (issue #509, specifications RFC 0005) requires signal
    entities to carry their capitalised stage id (``Host``/``Network``/``Cloud``):
    the prefix is what tells two stages' identically-named keys apart. A bare,
    unscoped entity (the pre-0.14.0 shape) is a regression and is rejected.
    """
    if not isinstance(value, str):
        raise MigrationError(f"entity must be a string, got {type(value).__name__}")
    stripped = value.strip()
    if not stripped:
        raise MigrationError("entity is empty")
    stage, sep, key = stripped.partition("::")
    if not sep:
        raise MigrationError(
            f"entity {value!r} is not scoped; expected '<Stage>::<Key>' with a stage of "
            f"{', '.join(stages)}"
        )
    if "::" in key:
        raise MigrationError(f"entity {value!r} contains more than one '::'")
    stage = stage.strip()
    key = key.strip()
    if not key:
        raise MigrationError(f"entity {value!r} has an empty key after the stage prefix")
    if stage not in stages:
        raise MigrationError(
            f"entity {value!r} uses an unknown stage {stage!r} (expected {', '.join(stages)})"
        )
    return f"{stage}::{key}"


def validate_entities(values: Any, *, stages: tuple[str, ...]) -> list[str]:
    """Validate a signal's scoped entity list and return it unchanged.

    Duplicates are collapsed (preserving order of first appearance) so that a
    re-run is idempotent against already-deduplicated catalogue content.
    """
    if values is None:
        raise MigrationError("signals.entities is missing")
    if not isinstance(values, list) or not values:
        raise MigrationError("signals.entities must be a non-empty list")
    validated: list[str] = []
    seen: set[str] = set()
    for item in values:
        if not isinstance(item, str):
            raise MigrationError(f"entity must be a string, got {type(item).__name__}")
        name = validate_scoped_entity(item, stages=stages)
        if name in seen:
            continue
        seen.add(name)
        validated.append(name)
    return validated


def validate_signal_severity(value: Any, *, allowed: set[str] | None) -> str:
    """Validate a signal severity against ``alert_severity::1.0`` and return it unchanged.

    ``objective.signals.severity`` is pinned to ``alert_severity::1.0``
    (Informational/Low/Medium/High/Critical), not to the NCSC threat
    ``severity::1.0`` long names. An NCSC long name on a signal is the
    wrong-vocabulary defect this migration previously introduced; it is now
    rejected rather than written.
    """
    if not isinstance(value, str) or not value.strip():
        raise MigrationError("signals.severity is missing or empty")
    current = value.strip()
    if current in NCSC_SEVERITY:
        raise MigrationError(
            f"signals.severity {current!r} is an NCSC threat-severity (severity::1.0) name; "
            f"objective.signals.severity is pinned to alert_severity::1.0"
        )
    if allowed is not None and current not in allowed:
        raise MigrationError(
            f"signals.severity {current!r} is not in the alert_severity vocabulary"
        )
    return current


def migrate_threat_payload(
    data: dict[str, Any],
    *,
    allowed_impact: set[str] | None = None,
    allowed_leverage: set[str] | None = None,
) -> dict[str, Any]:
    """Return a migrated threat object (does not mutate *data*)."""
    migrated = copy.deepcopy(data)
    threat = migrated.get("threat")
    if not isinstance(threat, dict):
        raise MigrationError("threat block is missing")

    if "actors" in threat:
        threat["actors"] = wrap_actors(threat.get("actors"))

    if "impact" in threat:
        tokens = split_packed_tokens(threat.get("impact"), field="threat.impact")
        assert_allowed(tokens, field="threat.impact", allowed=allowed_impact)
        threat["impact"] = tokens
    if "leverage" in threat:
        tokens = split_packed_tokens(threat.get("leverage"), field="threat.leverage")
        assert_allowed(tokens, field="threat.leverage", allowed=allowed_leverage)
        threat["leverage"] = tokens

    migrated["threat"] = threat
    return migrated


def migrate_objective_payload(
    data: dict[str, Any],
    *,
    allowed_signal_severity: set[str] | None = None,
    entity_stages: tuple[str, ...] = DEFAULT_ENTITY_STAGES,
) -> dict[str, Any]:
    """Return a migrated objective object (does not mutate *data*).

    *allowed_signal_severity* is the set of valid ``alert_severity`` names when
    the caller wants severity membership checked. *entity_stages* is the set of
    valid capitalised stage ids for scoped entities.
    """
    migrated = copy.deepcopy(data)
    objective = migrated.get("objective")
    if not isinstance(objective, dict):
        raise MigrationError("objective block is missing")
    signals = objective.get("signals")
    if not isinstance(signals, list) or not signals:
        raise MigrationError("objective.signals must be a non-empty list")

    for index, signal in enumerate(signals):
        if not isinstance(signal, dict):
            raise MigrationError(f"objective.signals[{index}] must be a mapping")
        signal["severity"] = validate_signal_severity(
            signal.get("severity"), allowed=allowed_signal_severity
        )
        signal["entities"] = validate_entities(signal.get("entities"), stages=entity_stages)

    migrated["objective"] = objective
    return migrated


def _wrap_literal(value: Any) -> Any:
    if isinstance(value, str) and "\n" in value:
        return LiteralScalarString(value.rstrip("\n"))
    if isinstance(value, dict):
        mapping = CommentedMap()
        for key, item in value.items():
            mapping[key] = _wrap_literal(item)
        return mapping
    if isinstance(value, list):
        seq = CommentedSeq()
        for item in value:
            seq.append(_wrap_literal(item))
        return seq
    return value


def dump_yaml(path: Path, data: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        _yaml.dump(_wrap_literal(data), handle)


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise MigrationError(f"{path}: YAML root must be a mapping")
    return data


def _load_vocab_toml(path: Path) -> dict[str, Any]:
    import tomllib

    if not path.is_file():
        raise MigrationError(f"vocabulary file not found: {path}")
    return tomllib.loads(path.read_text(encoding="utf-8"))


def load_vocab_names(path: Path) -> set[str]:
    raw = _load_vocab_toml(path)
    names: set[str] = set()
    for entry in raw.get("keys", []):
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if isinstance(name, str) and name.strip():
            names.add(name.strip())
    return names


def load_vocab_stages(path: Path) -> tuple[str, ...]:
    """Return the ``[[stages]]`` ids of a vocabulary file, in file order.

    Used for ``signal.entities.vocab.toml`` so the valid stage prefixes
    (Host/Network/Cloud) are derived from the engine rather than hardcoded.
    """
    raw = _load_vocab_toml(path)
    stages: list[str] = []
    for entry in raw.get("stages", []):
        if not isinstance(entry, dict):
            continue
        stage_id = entry.get("id")
        if isinstance(stage_id, str) and stage_id.strip():
            stages.append(stage_id.strip())
    return tuple(stages)


def default_vocab_dir() -> Path | None:
    try:
        import opentide

        candidate = Path(opentide.__file__).resolve().parent / "data" / "vocabulary"
        if candidate.is_dir():
            return candidate
    except ImportError:
        pass
    sibling = REPO_ROOT.parent / "opentide" / "src" / "opentide" / "data" / "vocabulary"
    if sibling.is_dir():
        return sibling
    return None


def migrate_tree(
    *,
    threats_dir: Path,
    objectives_dir: Path,
    dry_run: bool = False,
    vocab_dir: Path | None = None,
) -> dict[str, int]:
    allowed_impact: set[str] | None = None
    allowed_leverage: set[str] | None = None
    allowed_signal_severity: set[str] | None = None
    entity_stages: tuple[str, ...] = DEFAULT_ENTITY_STAGES
    if vocab_dir is not None:
        allowed_impact = load_vocab_names(vocab_dir / "impact.vocab.toml")
        allowed_leverage = load_vocab_names(vocab_dir / "leverage.vocab.toml")
        allowed_signal_severity = load_vocab_names(vocab_dir / "alert_severity.vocab.toml")
        derived_stages = load_vocab_stages(vocab_dir / "signal.entities.vocab.toml")
        if derived_stages:
            entity_stages = derived_stages

    counts = {"threats": 0, "objectives": 0, "unchanged": 0, "written": 0}
    errors: list[str] = []

    for path in sorted(threats_dir.glob("*.yaml")):
        original = load_yaml_mapping(path)
        try:
            migrated = migrate_threat_payload(
                original,
                allowed_impact=allowed_impact,
                allowed_leverage=allowed_leverage,
            )
        except MigrationError as exc:
            errors.append(f"{path.name}: {exc}")
            continue
        counts["threats"] += 1
        if migrated == original:
            counts["unchanged"] += 1
            continue
        if not dry_run:
            dump_yaml(path, migrated)
        counts["written"] += 1

    for path in sorted(objectives_dir.glob("*.yaml")):
        original = load_yaml_mapping(path)
        try:
            migrated = migrate_objective_payload(
                original,
                allowed_signal_severity=allowed_signal_severity,
                entity_stages=entity_stages,
            )
        except MigrationError as exc:
            errors.append(f"{path.name}: {exc}")
            continue
        counts["objectives"] += 1
        if migrated == original:
            counts["unchanged"] += 1
            continue
        if not dry_run:
            dump_yaml(path, migrated)
        counts["written"] += 1

    if errors:
        print("Migration errors:", file=sys.stderr)
        for row in errors:
            print(f"  - {row}", file=sys.stderr)
        raise SystemExit(1)
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--threats-dir", type=Path, default=REPO_ROOT / "objects" / "threats")
    parser.add_argument(
        "--objectives-dir", type=Path, default=REPO_ROOT / "objects" / "objectives"
    )
    parser.add_argument(
        "--vocab-dir",
        type=Path,
        default=None,
        help="Directory of *.vocab.toml files (defaults to installed opentide data)",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--no-vocab",
        action="store_true",
        help="Skip vocabulary membership checks",
    )
    args = parser.parse_args()

    vocab_dir = None if args.no_vocab else (args.vocab_dir or default_vocab_dir())
    if not args.no_vocab and vocab_dir is None:
        raise SystemExit(
            "Could not locate opentide vocabulary files. Pass --vocab-dir or install opentide."
        )

    counts = migrate_tree(
        threats_dir=args.threats_dir.resolve(),
        objectives_dir=args.objectives_dir.resolve(),
        dry_run=args.dry_run,
        vocab_dir=None if args.no_vocab else vocab_dir.resolve(),
    )
    mode = "dry-run" if args.dry_run else "wrote"
    print(
        f"Migrated {counts['threats']} threats and {counts['objectives']} objectives "
        f"({mode} {counts['written']}, unchanged {counts['unchanged']})"
    )


if __name__ == "__main__":
    main()
