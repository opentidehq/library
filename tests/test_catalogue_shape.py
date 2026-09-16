"""Catalogue invariants for trunk opentide threat::1.0 / objective::1.0."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import migrate_trunk_models as migrate  # noqa: E402

THREATS_DIR = ROOT / "objects" / "threats"
OBJECTIVES_DIR = ROOT / "objects" / "objectives"
RULES_DIR = ROOT / "objects" / "rules"

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
SCOPED_ACTOR_RE = re.compile(r"^(att&ck|misp)::.+$")
FILENAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*\.yaml$")


def _load(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict), path
    return data


def _iter_yaml(directory: Path) -> list[tuple[Path, dict[str, Any]]]:
    return [(path, _load(path)) for path in sorted(directory.glob("*.yaml"))]


def _vocab_names(filename: str) -> set[str] | None:
    vocab_dir = migrate.default_vocab_dir()
    if vocab_dir is None:
        return None
    path = vocab_dir / filename
    if not path.is_file():
        return None
    return migrate.load_vocab_names(path)


@pytest.fixture(scope="module")
def threats() -> list[tuple[Path, dict[str, Any]]]:
    files = _iter_yaml(THREATS_DIR)
    assert files, "no threat objects"
    return files


@pytest.fixture(scope="module")
def objectives() -> list[tuple[Path, dict[str, Any]]]:
    files = _iter_yaml(OBJECTIVES_DIR)
    assert files, "no objective objects"
    return files


@pytest.fixture(scope="module")
def rules() -> list[tuple[Path, dict[str, Any]]]:
    files = _iter_yaml(RULES_DIR)
    assert files, "no rule objects"
    return files


def test_filenames_are_dash_case(
    threats: list[tuple[Path, dict[str, Any]]],
    objectives: list[tuple[Path, dict[str, Any]]],
    rules: list[tuple[Path, dict[str, Any]]],
) -> None:
    for path, _ in (*threats, *objectives, *rules):
        assert FILENAME_RE.match(path.name), path.name


def test_object_uuids_unique_and_well_formed(
    threats: list[tuple[Path, dict[str, Any]]],
    objectives: list[tuple[Path, dict[str, Any]]],
    rules: list[tuple[Path, dict[str, Any]]],
) -> None:
    seen: dict[str, Path] = {}
    for path, data in (*threats, *objectives, *rules):
        uuid = data.get("metadata", {}).get("uuid")
        assert isinstance(uuid, str) and UUID_RE.match(uuid), path
        assert uuid not in seen, f"duplicate uuid {uuid}: {path} and {seen[uuid]}"
        seen[uuid] = path


def test_schema_identifiers(
    threats: list[tuple[Path, dict[str, Any]]],
    objectives: list[tuple[Path, dict[str, Any]]],
    rules: list[tuple[Path, dict[str, Any]]],
) -> None:
    for path, data in threats:
        assert data["metadata"]["schema"] == "threat::1.0", path
        assert data["metadata"]["tlp"] == "clear", path
    for path, data in objectives:
        assert data["metadata"]["schema"] == "objective::1.0", path
        assert data["metadata"]["tlp"] == "clear", path
    for path, data in rules:
        assert data["metadata"]["schema"] == "rule::1.0", path
        assert data["metadata"]["tlp"] == "clear", path


def test_threat_actors_are_named_objects(threats: list[tuple[Path, dict[str, Any]]]) -> None:
    objects_with_actors = 0
    for path, data in threats:
        actors = data["threat"].get("actors")
        if actors is None:
            continue
        objects_with_actors += 1
        assert isinstance(actors, list) and actors, path
        for actor in actors:
            assert isinstance(actor, dict), f"{path}: actor {actor!r} is not an object"
            assert set(actor) >= {"name"}
            assert isinstance(actor["name"], str) and SCOPED_ACTOR_RE.match(actor["name"]), (
                f"{path}: {actor['name']!r}"
            )
            assert not isinstance(actor.get("name"), list)
    assert objects_with_actors >= 144


def test_threat_impact_and_leverage_are_vocab_lists(
    threats: list[tuple[Path, dict[str, Any]]],
) -> None:
    impact_vocab = _vocab_names("impact.vocab.toml")
    leverage_vocab = _vocab_names("leverage.vocab.toml")
    packed = 0
    for path, data in threats:
        threat = data["threat"]
        for field in ("impact", "leverage"):
            value = threat.get(field)
            assert isinstance(value, list) and value, f"{path}: {field} must be a non-empty list"
            assert all(isinstance(item, str) and item.strip() for item in value), path
            assert all(";" not in item for item in value), f"{path}: packed token in {field}"
        if impact_vocab is not None:
            unknown = [item for item in threat["impact"] if item not in impact_vocab]
            assert not unknown, f"{path}: unknown impact {unknown}"
        if leverage_vocab is not None:
            unknown = [item for item in threat["leverage"] if item not in leverage_vocab]
            assert not unknown, f"{path}: unknown leverage {unknown}"
        packed += int(len(threat["impact"]) > 1) + int(len(threat["leverage"]) > 1)
    assert packed >= 200, "expected the historical semicolon-packed fields to become multi-token lists"


def test_threat_criticality_is_in_vocab(threats: list[tuple[Path, dict[str, Any]]]) -> None:
    allowed = _vocab_names("criticality.vocab.toml")
    if allowed is None:
        pytest.skip("opentide criticality vocab not available")
    for path, data in threats:
        assert data.get("criticality") in allowed, path


def test_threat_severity_is_ncsc(threats: list[tuple[Path, dict[str, Any]]]) -> None:
    for path, data in threats:
        assert data["threat"]["severity"] in migrate.NCSC_SEVERITY, path


def test_threat_surface_is_non_empty_list(threats: list[tuple[Path, dict[str, Any]]]) -> None:
    for path, data in threats:
        surface = data["threat"].get("surface")
        assert isinstance(surface, list) and surface, path
        assert all(isinstance(item, str) and item.strip() for item in surface), path


def test_objective_signals_use_ncsc_severity_and_bare_entities(
    objectives: list[tuple[Path, dict[str, Any]]],
) -> None:
    entity_vocab = _vocab_names("signal.entities.vocab.toml")
    signal_count = 0
    for path, data in objectives:
        signals = data["objective"]["signals"]
        assert isinstance(signals, list) and signals, path
        for signal in signals:
            signal_count += 1
            assert signal["severity"] in migrate.NCSC_SEVERITY, path
            entities = signal.get("entities")
            assert isinstance(entities, list) and entities, path
            for entity in entities:
                assert isinstance(entity, str) and entity.strip(), path
                assert "::" not in entity, f"{path}: staged entity {entity!r}"
                if entity_vocab is not None:
                    assert entity in entity_vocab, f"{path}: unknown entity {entity!r}"
            assert len(entities) == len(set(entities)), f"{path}: duplicate entities"
    assert signal_count >= 11


def test_objective_threat_references_exist(
    threats: list[tuple[Path, dict[str, Any]]],
    objectives: list[tuple[Path, dict[str, Any]]],
) -> None:
    threat_ids = {data["metadata"]["uuid"] for _, data in threats}
    for path, data in objectives:
        refs = data["objective"].get("threats") or []
        for ref in refs:
            assert ref in threat_ids, f"{path}: threat {ref} is not in the catalogue"


def test_rules_point_at_objectives(
    objectives: list[tuple[Path, dict[str, Any]]],
    rules: list[tuple[Path, dict[str, Any]]],
) -> None:
    objective_ids = {data["metadata"]["uuid"] for _, data in objectives}
    signal_ids: set[str] = set()
    for _, data in objectives:
        for signal in data["objective"]["signals"]:
            signal_ids.add(signal["uuid"])
    for path, data in rules:
        model = data.get("detection_model")
        assert isinstance(model, str) and UUID_RE.match(model), (
            f"{path}: detection_model missing or not a UUID"
        )
        assert model in objective_ids, f"{path}: detection_model is not an objective uuid"
        assert model not in signal_ids, f"{path}: detection_model must not be a signal uuid"


def test_powershell_rule_links_the_powershell_objective(
    objectives: list[tuple[Path, dict[str, Any]]],
    rules: list[tuple[Path, dict[str, Any]]],
) -> None:
    by_name = {path.name: data for path, data in rules}
    rule = by_name["rba-rr-win-base64-encoded-powershell-payload.yaml"]
    objective = next(
        data
        for path, data in objectives
        if path.name == "powershell-encoded-payload-to-start-new-process.yaml"
    )
    assert rule["detection_model"] == objective["metadata"]["uuid"]


def test_migrated_catalogue_is_idempotent(
    threats: list[tuple[Path, dict[str, Any]]],
    objectives: list[tuple[Path, dict[str, Any]]],
) -> None:
    for path, data in threats:
        again = migrate.migrate_threat_payload(data)
        assert again == data, path
    for path, data in objectives:
        again = migrate.migrate_objective_payload(data)
        assert again == data, path


def test_objects_have_required_identity_fields(
    threats: list[tuple[Path, dict[str, Any]]],
    objectives: list[tuple[Path, dict[str, Any]]],
    rules: list[tuple[Path, dict[str, Any]]],
) -> None:
    for path, data in (*threats, *objectives, *rules):
        assert isinstance(data.get("name"), str) and data["name"].strip(), path
        metadata = data["metadata"]
        assert isinstance(metadata.get("version"), int) or (
            isinstance(metadata.get("version"), str) and str(metadata["version"]).strip()
        ), path
        org = metadata.get("organisation")
        if org is not None:
            assert isinstance(org, dict) and UUID_RE.match(str(org.get("uuid", ""))), path


def test_no_legacy_packed_or_string_actors_remain(
    threats: list[tuple[Path, dict[str, Any]]],
    objectives: list[tuple[Path, dict[str, Any]]],
) -> None:
    for path, data in threats:
        for actor in data["threat"].get("actors") or []:
            assert not isinstance(actor, str), path
        for field in ("impact", "leverage"):
            assert not isinstance(data["threat"][field], str), path
    for path, data in objectives:
        for signal in data["objective"]["signals"]:
            assert signal["severity"] not in migrate.SIGNAL_SEVERITY_MAP, path
            assert all("::" not in entity for entity in signal["entities"]), path
