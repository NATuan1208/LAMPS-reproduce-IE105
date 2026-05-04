"""
Build a set of MD5 hashes from D1 dataset (Setup.py content) for dedup against D2.

Usage:
    cd <LAMPS root>
    python scripts/build_d1_hashes.py

Output:
    scripts/d1_hashes.json  — list of MD5 hex strings
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import subprocess
import sys
from pathlib import Path

LAMPS_ROOT = Path(__file__).parent.parent
LAMPS_JSS = LAMPS_ROOT / "tmp_lamps_jss"
D1_BLOB_HASH = "f8e282b33eb1f8b55dbac68df39340eab3d4e8cd"
OUTPUT = Path(__file__).parent / "d1_hashes.json"


def _read_d1_via_git() -> str:
    result = subprocess.run(
        ["git", "cat-file", "blob", D1_BLOB_HASH],
        cwd=LAMPS_JSS,
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git cat-file failed: {result.stderr.decode()}")
    return result.stdout.decode("utf-8", errors="ignore")


def build_hashes() -> None:
    print("Reading D1 CSV via git cat-file...")
    raw = _read_d1_via_git()

    reader = csv.DictReader(io.StringIO(raw))
    d1_hashes: set[str] = set()

    for row in reader:
        content = row.get("Setup.py", "")
        if content:
            h = hashlib.md5(content.encode("utf-8", errors="ignore")).hexdigest()
            d1_hashes.add(h)

    OUTPUT.write_text(json.dumps(sorted(d1_hashes), indent=2), encoding="utf-8")
    print(f"D1 hashes saved: {len(d1_hashes)} unique entries -> {OUTPUT}")


if __name__ == "__main__":
    build_hashes()
