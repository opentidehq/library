# Contributing to OpenTide Library

Thank you for contributing `TLP:CLEAR` detection objects to the public catalogue.

## Before you open a PR

1. Install the released engine (and pytest for catalogue tests):

   ```bash
   python -m venv .venv && source .venv/bin/activate
   pip install -r requirements-dev.txt
   export OPENTIDE_REPO_ROOT=$PWD
   ```

   `pip install opentide` is enough if you only need the CLI. Use `pip install -e ../opentide[cli]` only when testing unreleased engine changes.

2. Add or edit YAML under `objects/threats/`, `objects/objectives/`, or `objects/rules/` using schema identifiers `threat::1.0`, `objective::1.0`, and `rule::1.0`.

   **Filenames:** use dash-case slugs aligned with the object `name` (lowercase, hyphens — same rules as `opentide` doc paths via `slugify()`). Keep `name` human-readable; only the filename is slugified. Append a short UUID suffix if two objects slugify to the same stem.

3. Validate and refresh docs:

   ```bash
   pytest --cov=migrate_trunk_models --cov-fail-under=98
   python scripts/patch_opentide_threat_lists.py
   opentide generate schemas
   opentide generate templates
   opentide validate --strict
   opentide generate docs --output docs --flavor github
   ```

   `scripts/opentide_run.py` is a thin passthrough around the same CLI.

   Released `opentide` through 0.3.0 still types `threat.impact` / `threat.leverage` as `str` ([opentide#189](https://github.com/OpenTideHQ/opentide/issues/189)). After `pip install opentide`, run `python scripts/patch_opentide_threat_lists.py` so `opentide validate --strict` accepts the YAML lists required by `threat-1.0`. Do not collapse those fields back to semicolon-packed strings. The patch is a no-op once the engine ships `list[str]`.

4. Commit object YAML and updated `docs/` together.

## Content policy

- Only **public** information (`TLP:CLEAR`).
- Preserve existing UUIDs when editing objects; do not regenerate identifiers.
- Rules must reference a valid objective UUID in `detection_model` (not signal UUIDs).
- Follow top-down modelling: threats → objectives → rules.

## Licensing

By contributing, you agree that your objects are licensed under [CC-BY-SA 4.0](LICENSE).

## Migration reference

This catalogue was migrated from ShareTide. For field transforms, layout mapping, and lessons learned, see [sharetide-to-library.md](https://github.com/OpenTideHQ/opentide/blob/development/docs/usage/migration/sharetide-to-library.md) in the opentide documentation.
