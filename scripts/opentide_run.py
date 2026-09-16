#!/usr/bin/env python3
"""Invoke the installed opentide CLI.

opentide 0.1.5+ loads the object registry sequentially, so the old
ProcessPoolExecutor macOS workaround is no longer required.
"""

from __future__ import annotations

from opentide.cli import main

if __name__ == "__main__":
    main()
