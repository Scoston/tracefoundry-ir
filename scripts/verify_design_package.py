"""Confirm the historical design package remains byte-for-byte intact."""

import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1] / "docs" / "design"
manifest = json.loads((root / "FILE_HASHES.json").read_text())
for name, expected in manifest["files"].items():
    path = (root / name).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError("Unsafe manifest path")
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise ValueError(f"Historical design artifact changed: {name}")
print(json.dumps({"historical_package_files_verified": len(manifest["files"])}))
