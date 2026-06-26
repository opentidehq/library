# OpenTide Library — Agent Guide

Public TLP:CLEAR detection object catalogue for the OpenTide community.

**Organisation:** OpenTideHQ

## Quick start

```bash
pip install -e ../opentide   # until PyPI publish
opentide generate
opentide validate --strict
opentide generate docs --output docs
```

## Object layout

- `objects/threats/` — threat vectors (`threat::1.0`)
- `objects/objectives/` — detection objectives (`objective::1.0`)
- `objects/rules/` — MDR rules (`rule::1.0`)
- Object YAML **filenames** use dash-case slugs derived from the `name` field (via `slugify()`); the `name` value itself stays human-readable.
- `docs/` — generated object documentation (committed)
- `.opentide/schemas/` — generated JSON schemas (from `opentide generate`; do not hand-edit)

## Guardrails

- Only edit YAML under `objects/` unless explicitly asked.
- Do not modify generated `.opentide/schemas/` or templates.
- Preserve existing object UUIDs.
- Run `opentide validate --strict` before proposing changes.

## MCP

Configured in `.cursor/mcp.json` via `opentide setup mcp --cursor`.
