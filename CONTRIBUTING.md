# Contributing to OpenTide Library

Thank you for contributing `TLP:CLEAR` detection objects to the public catalogue.

## Before you open a PR

1. Install the local engine (until PyPI publish):

   ```bash
   python -m venv .venv && source .venv/bin/activate
   pip install -e ../opentide
   export OPENTIDE_REPO_ROOT=$PWD
   ```

2. Add or edit YAML under `objects/threats/`, `objects/objectives/`, or `objects/rules/` using schema identifiers `threat::1.0`, `objective::1.0`, and `rule::1.0`.

   **Filenames:** use dash-case slugs aligned with the object `name` (lowercase, hyphens — same rules as `opentide` doc paths via `slugify()`). Keep `name` human-readable; only the filename is slugified. Append a short UUID suffix if two objects slugify to the same stem.

3. Validate and refresh docs:

   ```bash
   python scripts/opentide_run.py generate schemas
   python scripts/opentide_run.py generate templates
   python scripts/opentide_run.py validate --strict
   python scripts/opentide_run.py generate docs --output docs --flavor github
   ```

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
