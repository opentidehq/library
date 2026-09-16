from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import migrate_trunk_models as migrate  # noqa: E402


ALLOWED_IMPACT = {"Data Breach", "Nuisance", "Impairement", "Reputational Damages"}
ALLOWED_LEVERAGE = {"Tampering", "Elevation of privilege", "Dwelling"}
ALLOWED_ENTITIES = {"Process", "Account", "IP Address", "Resource"}


def test_split_packed_tokens_skips_blank_list_items() -> None:
    assert migrate.split_packed_tokens(["Data Breach", "  ", "Nuisance"], field="impact") == [
        "Data Breach",
        "Nuisance",
    ]


def test_migrate_tree_uses_vocab_dir_and_reports_objective_errors(tmp_path: Path) -> None:
    vocab = tmp_path / "vocab"
    vocab.mkdir()
    (vocab / "impact.vocab.toml").write_text('[[keys]]\nname = "Data Breach"\n', encoding="utf-8")
    (vocab / "leverage.vocab.toml").write_text('[[keys]]\nname = "Tampering"\n', encoding="utf-8")
    (vocab / "signal.entities.vocab.toml").write_text('[[keys]]\nname = "Process"\n', encoding="utf-8")
    threats = tmp_path / "threats"
    objectives = tmp_path / "objectives"
    threats.mkdir()
    objectives.mkdir()
    (threats / "ok.yaml").write_text(
        "name: Ok\nthreat:\n  impact: Data Breach\n  leverage: Tampering\n",
        encoding="utf-8",
    )
    (objectives / "bad.yaml").write_text("name: Bad\nobjective:\n  signals: []\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        migrate.migrate_tree(
            threats_dir=threats,
            objectives_dir=objectives,
            vocab_dir=vocab,
        )
    written = yaml.safe_load((threats / "ok.yaml").read_text(encoding="utf-8"))
    assert written["threat"]["impact"] == ["Data Breach"]


def test_main_with_vocab_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    vocab = tmp_path / "vocab"
    vocab.mkdir()
    (vocab / "impact.vocab.toml").write_text('[[keys]]\nname = "Data Breach"\n', encoding="utf-8")
    (vocab / "leverage.vocab.toml").write_text('[[keys]]\nname = "Tampering"\n', encoding="utf-8")
    (vocab / "signal.entities.vocab.toml").write_text('[[keys]]\nname = "Process"\n', encoding="utf-8")
    threats = tmp_path / "threats"
    objectives = tmp_path / "objectives"
    threats.mkdir()
    objectives.mkdir()
    (threats / "ok.yaml").write_text(
        "name: Ok\nthreat:\n  impact: Data Breach\n  leverage: Tampering\n",
        encoding="utf-8",
    )
    (objectives / "ok.yaml").write_text(
        "name: Ok\nobjective:\n  signals:\n    - severity: High\n      entities:\n        - host::Process\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "migrate_trunk_models.py",
            "--threats-dir",
            str(threats),
            "--objectives-dir",
            str(objectives),
            "--vocab-dir",
            str(vocab),
        ],
    )
    migrate.main()
    out = capsys.readouterr().out
    assert "wrote 2" in out


def test_main_errors_when_vocab_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["migrate_trunk_models.py"])
    monkeypatch.setattr(migrate, "default_vocab_dir", lambda: None)
    with pytest.raises(SystemExit, match="Could not locate"):
        migrate.main()


def test_split_packed_tokens_trims_and_drops_empties() -> None:
    assert migrate.split_packed_tokens("  Data Breach ; ; Nuisance  ;", field="impact") == [
        "Data Breach",
        "Nuisance",
    ]


def test_split_packed_tokens_single_token() -> None:
    assert migrate.split_packed_tokens("Data Breach", field="impact") == ["Data Breach"]


def test_split_packed_tokens_already_list() -> None:
    assert migrate.split_packed_tokens(["Tampering", "Dwelling"], field="leverage") == [
        "Tampering",
        "Dwelling",
    ]


def test_split_packed_tokens_rejects_semicolon_inside_list_item() -> None:
    with pytest.raises(migrate.MigrationError, match="semicolon"):
        migrate.split_packed_tokens(["Tampering; Dwelling"], field="leverage")


def test_split_packed_tokens_rejects_empty_and_wrong_types() -> None:
    with pytest.raises(migrate.MigrationError, match="missing"):
        migrate.split_packed_tokens(None, field="impact")
    with pytest.raises(migrate.MigrationError, match="empty"):
        migrate.split_packed_tokens("   ;  ", field="impact")
    with pytest.raises(migrate.MigrationError, match="empty"):
        migrate.split_packed_tokens([], field="impact")
    with pytest.raises(migrate.MigrationError, match="list items must be strings"):
        migrate.split_packed_tokens([1], field="impact")
    with pytest.raises(migrate.MigrationError, match="must be a string or list"):
        migrate.split_packed_tokens({"a": 1}, field="impact")


def test_split_packed_tokens_drops_adjacent_duplicates_only() -> None:
    assert migrate.split_packed_tokens("A; A; B; A", field="impact") == ["A", "B", "A"]


def test_assert_allowed_rejects_unknown_tokens() -> None:
    with pytest.raises(migrate.MigrationError, match="not in vocabulary"):
        migrate.assert_allowed(["Nope"], field="impact", allowed=ALLOWED_IMPACT)
    migrate.assert_allowed(["Data Breach"], field="impact", allowed=ALLOWED_IMPACT)
    migrate.assert_allowed(["Anything"], field="impact", allowed=None)


def test_wrap_actors_strings_and_existing_objects() -> None:
    assert migrate.wrap_actors(["att&ck::G0125", "misp::abc"]) == [
        {"name": "att&ck::G0125"},
        {"name": "misp::abc"},
    ]
    assert migrate.wrap_actors(
        [{"name": "  att&ck::G0007  ", "sighting": "seen in 2024"}]
    ) == [{"name": "att&ck::G0007", "sighting": "seen in 2024"}]


def test_wrap_actors_none_and_errors() -> None:
    assert migrate.wrap_actors(None) is None
    assert migrate.wrap_actors([]) == []
    with pytest.raises(migrate.MigrationError, match="must be a list"):
        migrate.wrap_actors("att&ck::G0125")
    with pytest.raises(migrate.MigrationError, match="empty"):
        migrate.wrap_actors(["  "])
    with pytest.raises(migrate.MigrationError, match="missing name"):
        migrate.wrap_actors([{"sighting": "x"}])
    with pytest.raises(migrate.MigrationError, match="string or mapping"):
        migrate.wrap_actors([1])


def test_strip_entity_stage_and_unknown_prefix() -> None:
    assert migrate.strip_entity_stage("host::Process") == "Process"
    assert migrate.strip_entity_stage("network::IP Address") == "IP Address"
    assert migrate.strip_entity_stage("cloud::Account") == "Account"
    assert migrate.strip_entity_stage("Process") == "Process"
    with pytest.raises(migrate.MigrationError, match="still contains '::'"):
        migrate.strip_entity_stage("host::Process::Child")
    with pytest.raises(migrate.MigrationError, match="unknown stage prefix"):
        migrate.strip_entity_stage("identity::Account")
    with pytest.raises(migrate.MigrationError, match="empty name"):
        migrate.strip_entity_stage("host::")
    with pytest.raises(migrate.MigrationError, match="empty"):
        migrate.strip_entity_stage("   ")
    with pytest.raises(migrate.MigrationError, match="must be a string"):
        migrate.strip_entity_stage(1)  # type: ignore[arg-type]


def test_strip_entities_dedupes_after_stage_drop() -> None:
    assert migrate.strip_entities(["host::Account", "cloud::Account", "network::IP Address"]) == [
        "Account",
        "IP Address",
    ]


def test_strip_entities_errors() -> None:
    with pytest.raises(migrate.MigrationError, match="missing"):
        migrate.strip_entities(None)
    with pytest.raises(migrate.MigrationError, match="non-empty list"):
        migrate.strip_entities([])
    with pytest.raises(migrate.MigrationError, match="must be a string"):
        migrate.strip_entities([{"name": "Process"}])


def test_map_signal_severity_alert_and_ncsc() -> None:
    assert migrate.map_signal_severity("Medium") == "Moderate incident"
    assert migrate.map_signal_severity("  High  ") == "Substantial incident"
    assert migrate.map_signal_severity("Critical") == "Significant incident"
    assert migrate.map_signal_severity("Substantial incident") == "Substantial incident"
    assert migrate.map_signal_severity("Localised incident") == "Localised incident"
    with pytest.raises(migrate.MigrationError, match="not an alert label"):
        migrate.map_signal_severity("Low")
    with pytest.raises(migrate.MigrationError, match="missing"):
        migrate.map_signal_severity(None)
    with pytest.raises(migrate.MigrationError, match="missing"):
        migrate.map_signal_severity("  ")


def test_migrate_threat_payload_full_shape_and_uuid_preserved() -> None:
    original = {
        "name": "Example",
        "metadata": {"uuid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "schema": "threat::1.0"},
        "threat": {
            "actors": ["att&ck::G0125"],
            "impact": "Data Breach; Nuisance",
            "leverage": "Tampering; Elevation of privilege",
            "terrain": "Windows estate",
            "surface": ["Windows"],
        },
    }
    migrated = migrate.migrate_threat_payload(
        original, allowed_impact=ALLOWED_IMPACT, allowed_leverage=ALLOWED_LEVERAGE
    )
    assert original["threat"]["actors"] == ["att&ck::G0125"]
    assert migrated["metadata"]["uuid"] == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    assert migrated["threat"]["actors"] == [{"name": "att&ck::G0125"}]
    assert migrated["threat"]["impact"] == ["Data Breach", "Nuisance"]
    assert migrated["threat"]["leverage"] == ["Tampering", "Elevation of privilege"]
    assert migrated["threat"]["terrain"] == "Windows estate"


def test_migrate_threat_payload_without_actors_still_splits_fields() -> None:
    migrated = migrate.migrate_threat_payload(
        {"threat": {"impact": "Data Breach", "leverage": "Tampering"}},
        allowed_impact=ALLOWED_IMPACT,
        allowed_leverage=ALLOWED_LEVERAGE,
    )
    assert "actors" not in migrated["threat"]
    assert migrated["threat"]["impact"] == ["Data Breach"]
    assert migrated["threat"]["leverage"] == ["Tampering"]


def test_migrate_threat_payload_actors_only() -> None:
    migrated = migrate.migrate_threat_payload({"threat": {"actors": ["att&ck::G0125"]}})
    assert migrated["threat"]["actors"] == [{"name": "att&ck::G0125"}]
    assert "impact" not in migrated["threat"]
    assert "leverage" not in migrated["threat"]


def test_migrate_threat_payload_idempotent_and_rejects_unknown_vocab() -> None:
    first = migrate.migrate_threat_payload(
        {
            "threat": {
                "actors": [{"name": "att&ck::G0007"}],
                "impact": ["Data Breach"],
                "leverage": ["Tampering"],
            }
        },
        allowed_impact=ALLOWED_IMPACT,
        allowed_leverage=ALLOWED_LEVERAGE,
    )
    second = migrate.migrate_threat_payload(
        first, allowed_impact=ALLOWED_IMPACT, allowed_leverage=ALLOWED_LEVERAGE
    )
    assert first == second
    with pytest.raises(migrate.MigrationError, match="not in vocabulary"):
        migrate.migrate_threat_payload(
            {"threat": {"impact": "Not A Real Impact", "leverage": "Tampering"}},
            allowed_impact=ALLOWED_IMPACT,
            allowed_leverage=ALLOWED_LEVERAGE,
        )
    with pytest.raises(migrate.MigrationError, match="missing"):
        migrate.migrate_threat_payload({"name": "no threat block"})


def test_migrate_objective_payload_maps_signals() -> None:
    original = {
        "metadata": {"uuid": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"},
        "objective": {
            "signals": [
                {
                    "name": "sig",
                    "uuid": "cccccccc-cccc-cccc-cccc-cccccccccccc",
                    "severity": "High",
                    "entities": ["host::Process", "network::IP Address"],
                }
            ]
        },
    }
    migrated = migrate.migrate_objective_payload(original, allowed_entities=ALLOWED_ENTITIES)
    assert original["objective"]["signals"][0]["severity"] == "High"
    assert migrated["objective"]["signals"][0]["severity"] == "Substantial incident"
    assert migrated["objective"]["signals"][0]["entities"] == ["Process", "IP Address"]
    assert migrated["metadata"]["uuid"] == "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    again = migrate.migrate_objective_payload(migrated, allowed_entities=ALLOWED_ENTITIES)
    assert again == migrated


def test_migrate_objective_payload_errors() -> None:
    with pytest.raises(migrate.MigrationError, match="missing"):
        migrate.migrate_objective_payload({})
    with pytest.raises(migrate.MigrationError, match="non-empty list"):
        migrate.migrate_objective_payload({"objective": {"signals": []}})
    with pytest.raises(migrate.MigrationError, match="must be a mapping"):
        migrate.migrate_objective_payload({"objective": {"signals": ["nope"]}})
    with pytest.raises(migrate.MigrationError, match="not in vocabulary"):
        migrate.migrate_objective_payload(
            {
                "objective": {
                    "signals": [
                        {
                            "severity": "High",
                            "entities": ["host::NotAThing"],
                        }
                    ]
                }
            },
            allowed_entities=ALLOWED_ENTITIES,
        )


def test_migrate_tree_writes_and_is_idempotent(tmp_path: Path) -> None:
    threats = tmp_path / "threats"
    objectives = tmp_path / "objectives"
    threats.mkdir()
    objectives.mkdir()
    (threats / "example.yaml").write_text(
        "name: Example\n"
        "metadata:\n"
        "  uuid: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\n"
        "threat:\n"
        "  actors:\n"
        "    - att&ck::G0125\n"
        "  impact: Data Breach; Nuisance\n"
        "  leverage: Tampering\n",
        encoding="utf-8",
    )
    (objectives / "detect.yaml").write_text(
        "name: Detect\n"
        "metadata:\n"
        "  uuid: bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb\n"
        "objective:\n"
        "  signals:\n"
        "    - name: s\n"
        "      uuid: cccccccc-cccc-cccc-cccc-cccccccccccc\n"
        "      severity: Critical\n"
        "      entities:\n"
        "        - cloud::Resource\n",
        encoding="utf-8",
    )

    first = migrate.migrate_tree(
        threats_dir=threats,
        objectives_dir=objectives,
        dry_run=True,
        vocab_dir=None,
    )
    assert first["written"] == 2
    raw_threat = yaml.safe_load((threats / "example.yaml").read_text(encoding="utf-8"))
    assert raw_threat["threat"]["actors"] == ["att&ck::G0125"]

    written = migrate.migrate_tree(
        threats_dir=threats,
        objectives_dir=objectives,
        dry_run=False,
        vocab_dir=None,
    )
    assert written["written"] == 2
    threat = yaml.safe_load((threats / "example.yaml").read_text(encoding="utf-8"))
    objective = yaml.safe_load((objectives / "detect.yaml").read_text(encoding="utf-8"))
    assert threat["threat"]["actors"] == [{"name": "att&ck::G0125"}]
    assert threat["threat"]["impact"] == ["Data Breach", "Nuisance"]
    assert threat["metadata"]["uuid"] == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    assert objective["objective"]["signals"][0]["severity"] == "Significant incident"
    assert objective["objective"]["signals"][0]["entities"] == ["Resource"]

    second = migrate.migrate_tree(
        threats_dir=threats,
        objectives_dir=objectives,
        dry_run=False,
        vocab_dir=None,
    )
    assert second["unchanged"] == 2
    assert second["written"] == 0


def test_migrate_tree_reports_errors(tmp_path: Path) -> None:
    threats = tmp_path / "threats"
    objectives = tmp_path / "objectives"
    threats.mkdir()
    objectives.mkdir()
    (threats / "bad.yaml").write_text("name: Bad\nthreat:\n  actors: att&ck::G0125\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        migrate.migrate_tree(
            threats_dir=threats,
            objectives_dir=objectives,
            vocab_dir=None,
        )


def test_default_vocab_dir_falls_back_to_sibling(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sibling = tmp_path / "opentide" / "src" / "opentide" / "data" / "vocabulary"
    sibling.mkdir(parents=True)
    monkeypatch.setattr(migrate, "REPO_ROOT", tmp_path / "library")

    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):  # type: ignore[no-untyped-def]
        if name == "opentide" or name.startswith("opentide."):
            raise ImportError("hidden")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert migrate.default_vocab_dir() == sibling


def test_default_vocab_dir_returns_none_when_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(migrate, "REPO_ROOT", tmp_path / "library")
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):  # type: ignore[no-untyped-def]
        if name == "opentide" or name.startswith("opentide."):
            raise ImportError("hidden")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert migrate.default_vocab_dir() is None


def test_default_vocab_dir_skips_installed_package_without_vocab(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import sys
    import types

    fake = types.SimpleNamespace(__file__=str(tmp_path / "site" / "opentide" / "__init__.py"))
    monkeypatch.setitem(sys.modules, "opentide", fake)
    monkeypatch.setattr(migrate, "REPO_ROOT", tmp_path / "library")
    assert migrate.default_vocab_dir() is None


def test_default_vocab_dir_finds_installed_opentide() -> None:
    vocab_dir = migrate.default_vocab_dir()
    assert vocab_dir is not None
    assert (vocab_dir / "impact.vocab.toml").is_file()
    names = migrate.load_vocab_names(vocab_dir / "impact.vocab.toml")
    assert "Data Breach" in names
    assert "Impairement" in names


def test_load_vocab_names(tmp_path: Path) -> None:
    path = tmp_path / "impact.vocab.toml"
    path.write_text(
        'name = "Impact"\n[[keys]]\nname = "Data Breach"\n[[keys]]\nname = "Nuisance"\n'
        '[[keys]]\nname = "  Impairement  "\n[[keys]]\nid = "no-name"\n',
        encoding="utf-8",
    )
    assert migrate.load_vocab_names(path) == {"Data Breach", "Nuisance", "Impairement"}
    with pytest.raises(migrate.MigrationError, match="vocabulary file not found"):
        migrate.load_vocab_names(tmp_path / "missing.vocab.toml")
    skip_non_maps = tmp_path / "mixed.vocab.toml"
    skip_non_maps.write_text(
        'keys = ["nope"]\n',
        encoding="utf-8",
    )
    assert migrate.load_vocab_names(skip_non_maps) == set()


def test_migrate_tree_errors_when_vocab_file_missing(tmp_path: Path) -> None:
    threats = tmp_path / "threats"
    objectives = tmp_path / "objectives"
    threats.mkdir()
    objectives.mkdir()
    (threats / "ok.yaml").write_text(
        "name: Ok\nthreat:\n  impact: Data Breach\n  leverage: Tampering\n",
        encoding="utf-8",
    )
    with pytest.raises(migrate.MigrationError, match="vocabulary file not found"):
        migrate.migrate_tree(
            threats_dir=threats,
            objectives_dir=objectives,
            vocab_dir=tmp_path / "empty-vocab",
        )


def test_load_yaml_mapping_rejects_non_mapping(tmp_path: Path) -> None:
    path = tmp_path / "list.yaml"
    path.write_text("- just a list\n", encoding="utf-8")
    with pytest.raises(migrate.MigrationError, match="mapping"):
        migrate.load_yaml_mapping(path)


def test_migrate_cli_dry_run(tmp_path: Path) -> None:
    threats = tmp_path / "threats"
    objectives = tmp_path / "objectives"
    threats.mkdir()
    objectives.mkdir()
    (threats / "example.yaml").write_text(
        "name: Example\nthreat:\n  impact: Data Breach\n  leverage: Tampering\n",
        encoding="utf-8",
    )
    (objectives / "detect.yaml").write_text(
        "name: Detect\nobjective:\n  signals:\n    - severity: High\n      entities:\n        - host::Process\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "migrate_trunk_models.py"),
            "--threats-dir",
            str(threats),
            "--objectives-dir",
            str(objectives),
            "--no-vocab",
            "--dry-run",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "dry-run 2" in result.stdout
    raw = yaml.safe_load((threats / "example.yaml").read_text(encoding="utf-8"))
    assert raw["threat"]["impact"] == "Data Breach"


def test_dump_yaml_roundtrip_literals(tmp_path: Path) -> None:
    path = tmp_path / "out.yaml"
    migrate.dump_yaml(
        path,
        {
            "name": "Example",
            "threat": {
                "terrain": "line one\nline two\n",
                "impact": ["Data Breach"],
                "actors": [{"name": "att&ck::G0125"}],
            },
        },
    )
    text = path.read_text(encoding="utf-8")
    assert "terrain: |-" in text or "terrain: |" in text
    loaded = yaml.safe_load(text)
    assert loaded["threat"]["impact"] == ["Data Breach"]
    assert loaded["threat"]["actors"][0]["name"] == "att&ck::G0125"


def test_dump_yaml_wraps_nested_lists_and_maps(tmp_path: Path) -> None:
    path = tmp_path / "nested.yaml"
    migrate.dump_yaml(
        path,
        {
            "objective": {
                "signals": [
                    {
                        "name": "sig",
                        "description": "line a\nline b\n",
                        "entities": ["Process", "Account"],
                    }
                ]
            }
        },
    )
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert loaded["objective"]["signals"][0]["entities"] == ["Process", "Account"]
    assert "line a" in loaded["objective"]["signals"][0]["description"]
