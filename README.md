# OpenTide Library

Public registry of published detection objects for the [OpenTide](https://github.com/OpenTideHQ/opentide) detection-as-code framework.

The Library hosts versioned **threat vectors**, **detection objectives**, and **MDR rules** that teams can browse, reference, and import into their own repositories. Content conforms to the normative schemas in [OpenTideHQ/specifications](https://github.com/OpenTideHQ/specifications) and is validated with the `opentide` engine.

## Object families

| Object | Path | Schema identifier | Role |
|--------|------|-------------------|------|
| Threat | `objects/threats/` | `threat::1.0` | Threat vector (TVM) definitions |
| Objective | `objects/objectives/` | `objective::1.0` | Detection objectives and signals |
| Rule | `objects/rules/` | `rule::1.0` | MDR rules with platform configurations |

Each YAML file includes a top-level `name` and a `metadata` block (`schema`, `version`, `uuid`, `tlp`, and related fields). See the [specifications](https://github.com/OpenTideHQ/specifications) for normative field definitions.

## Relationship to OpenTide

```text
specifications  →  schemas and object specs (source of truth)
opentide        →  validate, generate, deploy (engine)
library         →  published objects (this repository)
website         →  browse and render library content (coming soon)
```

- **Client repositories** hold private detection content under `objects/` and index it locally via the OpenTide workspace registry.
- **This repository** is the curated, public catalogue of objects published by OpenTide and contributors.
- **`opentide`** validates library objects the same way it validates client content.

## Layout (planned)

```text
objects/
  threats/
  objectives/
  rules/
manifest.json          # catalogue index for discovery and tooling
```

A bundled manifest (mirroring the [skills catalogue](https://github.com/OpenTideHQ/skills) pattern) will list published objects for offline browse and future `opentide library` commands.

## Contributing

Contribution guidelines and publishing workflow will be documented here as the catalogue grows. Objects must pass `opentide validate --strict` against the schema revisions declared in each file's `metadata.schema`.

## Related projects

| Project | Description |
|---------|-------------|
| [opentide](https://github.com/OpenTideHQ/opentide) | DetectionOps engine (PyPI package) |
| [specifications](https://github.com/OpenTideHQ/specifications) | Normative schemas and metadata specs |
| [skills](https://github.com/OpenTideHQ/skills) | Agent skills for detection engineering |
| [website](https://github.com/OpenTideHQ/website) | OpenTide documentation and public surfaces |

## License

Licensing for published objects will be stated per object (`metadata` / TLP). Repository terms will be added before the first public catalogue release.
