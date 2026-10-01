#!/usr/bin/env python3
"""Keep the locked Rust dependency license inventory in sync with Cargo."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = (
    ROOT / "rust/spqr_bridge/Cargo.toml",
    ROOT / "third_party/spqr/Cargo.toml",
)
INVENTORY = ROOT / "docs/RUST-DEPENDENCIES.md"


def render():
    packages = {}
    for manifest in MANIFESTS:
        command = (
            "cargo", "metadata", "--manifest-path", str(manifest),
            "--locked", "--format-version", "1",
        )
        metadata = json.loads(subprocess.check_output(command, text=True))
        for package in metadata["packages"]:
            license_name = package.get("license") or package.get("license_file")
            if not license_name:
                raise ValueError(
                    f"missing license metadata: {package['name']} {package['version']}"
                )
            key = (package["name"], package["version"])
            if key in packages and packages[key] != license_name:
                raise ValueError(f"conflicting license metadata: {key}")
            packages[key] = license_name

    lines = [
        "# Locked Rust dependencies",
        "",
        "This inventory is generated from both Cargo lockfiles by",
        "`python3 ci/check-rust-licenses.py --write`. It includes packages used",
        "for building and testing and packages for other supported targets; it",
        "does not claim that every entry is linked into the executable.",
        "",
        "The expressions below are the packages' own license metadata. Their",
        "source packages carry the complete notices. A binary release must also",
        "provide the exact corresponding source and preserve applicable notices;",
        "this inventory alone is not a binary redistribution package.",
        "",
        f"Packages: {len(packages)}.",
        "",
        "| Package | Version | Declared license |",
        "| --- | --- | --- |",
    ]
    for (name, version), license_name in sorted(packages.items()):
        lines.append(f"| `{name}` | `{version}` | `{license_name}` |")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args()
    content = render()
    if args.write:
        INVENTORY.write_text(content)
        print(f"wrote {INVENTORY}")
    elif not INVENTORY.exists() or INVENTORY.read_text() != content:
        raise SystemExit("Rust dependency license inventory is out of date")
    else:
        print("Rust dependency license inventory is current")


if __name__ == "__main__":
    main()
