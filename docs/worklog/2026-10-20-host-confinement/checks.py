#!/usr/bin/env python3
"""Run parent root-test and scoped-format helpers against standalone nixvm."""

import argparse
from pathlib import Path
import sys


def configure(tools: Path):
    sys.path.insert(0, str(tools.resolve()))
    import format as formatting
    import layout
    import test

    packages, owner = layout.packages, layout.owner
    layout.packages = lambda root: packages(root) if (root / "package.json").exists() else ([], [])
    layout.owner = lambda path, directories: owner(path, directories) or ("." if "." in directories else None)
    swept = formatting.swept
    formatting.swept = lambda root: swept(root) if (root / formatting.SWEPT).exists() else swept(tools.resolve().parent)
    return {"test": test.main, "format": formatting.main}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tools", type=Path, required=True, help="parent checkout's tools directory")
    parser.add_argument("action", choices=("test", "format"))
    options, arguments = parser.parse_known_args()
    return configure(options.tools)[options.action](arguments)


if __name__ == "__main__":
    raise SystemExit(main())
