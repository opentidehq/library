#!/usr/bin/env python3
"""Invoke opentide CLI with sequential registry YAML loading.

ProcessPoolExecutor can fail on macOS when forking after the engine is imported;
CI on Linux is unaffected but this wrapper is safe everywhere.
"""

from __future__ import annotations

import opentide.registry.builder as registry_builder

registry_builder.RegistryBuilder._load_objects_parallel = (  # type: ignore[method-assign]
    registry_builder.RegistryBuilder._load_objects_sequential
)

from opentide.cli import main

if __name__ == "__main__":
    main()
