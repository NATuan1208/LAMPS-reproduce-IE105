"""
Supplement D2 malicious files from pypi_malregistry when DataDog gives < 140 packages.

pypi_malregistry format: {package}/{version}/{package}-{version}.tar.gz (no encryption).

Prerequisites:
    git clone --depth 1 https://github.com/lxyeternal/pypi_malregistry.git

Usage:
    cd <LAMPS root>
    python scripts/supplement_malregistry.py [--need N] [--skip-packages pkg1,pkg2]

Output:
    Appends to scripts/extracted_malicious/ and scripts/datadog_raw_metadata.json
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import subprocess
import tarfile
import zipfile
from pathlib import Path

LAMPS_ROOT = Path(__file__).parent.parent
MALREG_REPO = LAMPS_ROOT / "pypi_malregistry"
SCRIPTS_DIR = Path(__file__).parent

EXTRACTED_DIR = SCRIPTS_DIR / "extracted_malicious"
METADATA_FILE = SCRIPTS_DIR / "datadog_raw_metadata.json"
D1_HASHES_FILE = SCRIPTS_DIR / "d1_hashes.json"

SKIP_DIRS = {"test", "tests", "doc", "docs", "example", "examples", "__pycache__"}
SKIP_FILES = {"conftest.py"}
MIN_CONTENT_LEN = 50


def _load_d1_hashes() -> set[str]:
    if D1_HASHES_FILE.exists():
        return set(json.loads(D1_HASHES_FILE.read_text(encoding="utf-8")))
    return set()


def _should_skip(py_name: str, py_parts: list[str], content: str, d1_hashes: set[str]) -> bool:
    lower_parts = [p.lower() for p in py_parts]
    if any(d in SKIP_DIRS for d in lower_parts):
        return True
    if py_name in SKIP_FILES:
        return True
    if len(content.strip()) < MIN_CONTENT_LEN:
        return True
    h = hashlib.md5(content.encode("utf-8", errors="ignore")).hexdigest()
    if py_name != "setup.py" and h in d1_hashes:
        return True
    return False


def _extract_from_tar(tar_path: Path, pkg_name: str, d1_hashes: set[str]) -> list[dict]:
    records = []
    try:
        with tarfile.open(tar_path) as tf:
            for member in tf.getmembers():
                name = member.name
                if not name.endswith(".py"):
                    continue
                py_parts = name.replace("\\", "/").split("/")
                py_name = py_parts[-1]
                fobj = tf.extractfile(member)
                if fobj is None:
                    continue
                try:
                    content = fobj.read().decode("utf-8", errors="ignore")
                except Exception:
                    continue
                if _should_skip(py_name, py_parts, content, d1_hashes):
                    continue
                h = hashlib.md5(content.encode("utf-8", errors="ignore")).hexdigest()
                records.append({
                    "original_path": name,
                    "content": content,
                    "package": pkg_name,
                    "category": "malregistry",
                    "content_hash": h[:8],
                    "char_count": len(content),
                    "line_count": content.count("\n") + 1,
                    "source": "pypi_malregistry",
                })
    except Exception as e:
        print(f"  [WARN] tar open failed for {tar_path.name}: {e}")
    return records


def _extract_from_whl(whl_path: Path, pkg_name: str, d1_hashes: set[str]) -> list[dict]:
    records = []
    try:
        with zipfile.ZipFile(whl_path) as zf:
            for info in zf.infolist():
                name = info.filename
                if not name.endswith(".py"):
                    continue
                py_parts = name.replace("\\", "/").split("/")
                py_name = py_parts[-1]
                try:
                    content = zf.read(info).decode("utf-8", errors="ignore")
                except Exception:
                    continue
                if _should_skip(py_name, py_parts, content, d1_hashes):
                    continue
                h = hashlib.md5(content.encode("utf-8", errors="ignore")).hexdigest()
                records.append({
                    "original_path": name,
                    "content": content,
                    "package": pkg_name,
                    "category": "malregistry",
                    "content_hash": h[:8],
                    "char_count": len(content),
                    "line_count": content.count("\n") + 1,
                    "source": "pypi_malregistry",
                })
    except Exception as e:
        print(f"  [WARN] whl open failed for {whl_path.name}: {e}")
    return records


def supplement(need: int, skip_packages: set[str]) -> None:
    if not MALREG_REPO.exists():
        raise FileNotFoundError(
            f"pypi_malregistry not found at {MALREG_REPO}\n"
            "  Clone with: git clone --depth 1 https://github.com/lxyeternal/pypi_malregistry.git"
        )

    d1_hashes = _load_d1_hashes()
    EXTRACTED_DIR.mkdir(parents=True, exist_ok=True)

    # Load existing metadata to append to
    existing: list[dict] = []
    if METADATA_FILE.exists():
        existing = json.loads(METADATA_FILE.read_text(encoding="utf-8"))

    existing_pkgs = {r["package"] for r in existing} | skip_packages
    print(f"Packages already in dataset: {len(existing_pkgs)}")
    print(f"Need {need} more from pypi_malregistry")

    new_records: list[dict] = []
    added_pkgs = 0

    for pkg_dir in sorted(MALREG_REPO.iterdir()):
        if added_pkgs >= need:
            break
        if not pkg_dir.is_dir() or pkg_dir.name.startswith("."):
            continue
        pkg_name = pkg_dir.name
        if pkg_name in existing_pkgs:
            continue

        pkg_records: list[dict] = []

        # Find archives in version subdirs
        for version_dir in pkg_dir.iterdir():
            if not version_dir.is_dir():
                continue
            for archive in version_dir.iterdir():
                if archive.name.endswith(".tar.gz") or archive.suffix == ".tgz":
                    pkg_records.extend(_extract_from_tar(archive, pkg_name, d1_hashes))
                elif archive.suffix == ".whl":
                    pkg_records.extend(_extract_from_whl(archive, pkg_name, d1_hashes))
            if pkg_records:
                break  # one version is enough

        if not pkg_records:
            continue

        safe_pkg = pkg_name.replace("-", "_").replace(".", "_")[:40]
        for idx, rec in enumerate(pkg_records):
            filename = f"{safe_pkg}_{idx:03d}_{rec['content_hash']}.py"
            out_path = EXTRACTED_DIR / filename
            out_path.write_text(rec["content"], encoding="utf-8", errors="ignore")
            rec["filename"] = filename
            del rec["content"]

        new_records.extend(pkg_records)
        existing_pkgs.add(pkg_name)
        added_pkgs += 1
        print(f"  {pkg_name}: {len(pkg_records)} files")

    all_records = existing + new_records
    METADATA_FILE.write_text(json.dumps(all_records, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\n=== SUPPLEMENT COMPLETE ===")
    print(f"  New packages added : {added_pkgs}")
    print(f"  New .py files added: {len(new_records)}")
    print(f"  Total records      : {len(all_records)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Supplement D2 from pypi_malregistry.")
    parser.add_argument("--need", type=int, default=100, help="Number of additional packages to add")
    parser.add_argument("--skip-packages", type=str, default="", help="Comma-separated package names to skip")
    args = parser.parse_args()
    skip = set(s.strip() for s in args.skip_packages.split(",") if s.strip())
    supplement(args.need, skip)


if __name__ == "__main__":
    main()
