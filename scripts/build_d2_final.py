"""
Assemble the final D2 dataset from labeled malicious files + existing benign files.

Reads scripts/labeled_metadata.json (output of codebert_label.py),
keeps only files with label_int == 1 from packages that have >= 1 malicious file,
then rebuilds D2_dataset/malicious/ and D2_dataset/metadata.json.
The benign set (D2_dataset/benign/) is NOT modified.

Usage:
    cd <LAMPS root>
    python scripts/build_d2_final.py [--dry-run]

Output:
    D2_dataset/malicious/    replaced with new content-labeled malicious files
    D2_dataset/metadata.json rebuilt with correct label_int values
"""
from __future__ import annotations

import argparse
import json
import shutil
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

LAMPS_ROOT = Path(__file__).parent.parent
SCRIPTS_DIR = Path(__file__).parent

LABELED_METADATA = SCRIPTS_DIR / "labeled_metadata.json"
EXTRACTED_DIR = SCRIPTS_DIR / "extracted_malicious"

D2_ROOT = LAMPS_ROOT / "D2_dataset"
D2_MALICIOUS = D2_ROOT / "malicious"
D2_BENIGN = D2_ROOT / "benign"
D2_METADATA = D2_ROOT / "metadata.json"

# Targets from paper
TARGET_MAL_FILES_MIN = 250
TARGET_MAL_FILES_MAX = 300
TARGET_PACKAGES_MIN = 120
TARGET_PACKAGES_MAX = 160


def _load_labeled() -> list[dict]:
    if not LABELED_METADATA.exists():
        raise FileNotFoundError(f"Labeled metadata not found: {LABELED_METADATA}\n  Run codebert_label.py first.")
    return json.loads(LABELED_METADATA.read_text(encoding="utf-8"))


def _load_benign_metadata() -> list[dict]:
    """Load existing benign file metadata from D2_dataset/metadata.json."""
    if not D2_METADATA.exists():
        return []
    meta = json.loads(D2_METADATA.read_text(encoding="utf-8"))
    return [f for f in meta.get("files", []) if f.get("label_int") == 0]


def build_d2(dry_run: bool = False) -> None:
    labeled = _load_labeled()

    # Check no pending reviews
    pending = [r for r in labeled if r.get("label_int") == -1]
    if pending:
        print(f"[WARN] {len(pending)} files still have label_int=-1 (manual review pending).")
        print("  These will be EXCLUDED from the final dataset.")
        labeled = [r for r in labeled if r.get("label_int") != -1]

    # Group malicious files by package
    pkgs: dict[str, list[dict]] = defaultdict(list)
    for rec in labeled:
        pkgs[rec["package"]].append(rec)

    # Keep only packages with >= 1 malicious file
    valid_malicious_files: list[dict] = []
    dropped_pkgs: list[str] = []
    for pkg_name, files in pkgs.items():
        has_mal = any(f["label_int"] == 1 for f in files)
        if has_mal:
            # Include ALL files from valid packages (both 0 and 1 labels within package context)
            # But only add label=1 files to D2 malicious set
            valid_malicious_files.extend(f for f in files if f["label_int"] == 1)
        else:
            dropped_pkgs.append(pkg_name)

    valid_pkgs = set(r["package"] for r in valid_malicious_files)

    print(f"\n=== D2 BUILD SUMMARY ===")
    print(f"  Malicious files  : {len(valid_malicious_files)}")
    print(f"  Malicious packages: {len(valid_pkgs)}")
    print(f"  Dropped packages : {len(dropped_pkgs)} (no confirmed malicious file)")

    # Warnings if outside target range
    if len(valid_malicious_files) < TARGET_MAL_FILES_MIN:
        print(f"  [WARN] Only {len(valid_malicious_files)} malicious files — below target {TARGET_MAL_FILES_MIN}.")
        print(f"         Consider running supplement_malregistry.py.")
    if len(valid_pkgs) < TARGET_PACKAGES_MIN:
        print(f"  [WARN] Only {len(valid_pkgs)} malicious packages — below target {TARGET_PACKAGES_MIN}.")

    benign_files = _load_benign_metadata()
    print(f"  Benign files     : {len(benign_files)} (unchanged)")

    if dry_run:
        print("\n[DRY RUN] No files written.")
        return

    # Backup old malicious dir
    backup_dir = D2_ROOT / "_malicious_backup"
    if D2_MALICIOUS.exists():
        if backup_dir.exists():
            shutil.rmtree(backup_dir)
        shutil.copytree(D2_MALICIOUS, backup_dir)
        print(f"\n  Backed up old malicious/ -> {backup_dir.name}")
        shutil.rmtree(D2_MALICIOUS)

    D2_MALICIOUS.mkdir(parents=True, exist_ok=True)

    # Copy malicious files into D2_dataset/malicious/
    new_malicious_entries: list[dict] = []
    for rec in valid_malicious_files:
        src = EXTRACTED_DIR / rec["filename"]
        if not src.exists():
            print(f"  [WARN] Source file missing: {src}")
            continue
        dst = D2_MALICIOUS / rec["filename"]
        shutil.copy2(src, dst)
        new_malicious_entries.append({
            "filename": rec["filename"],
            "package": rec["package"],
            "label": "malicious",
            "label_int": 1,
            "filepath": str(dst.relative_to(LAMPS_ROOT)).replace("\\", "/"),
            "char_count": rec.get("char_count", 0),
            "line_count": rec.get("line_count", 0),
            "approx_tokens": rec.get("char_count", 0) // 4,
            "source": rec.get("source", "datadog"),
            "malicious_prob": rec.get("malicious_prob"),
        })

    # Rebuild metadata.json
    all_files = new_malicious_entries + benign_files
    metadata = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "D2 reconstructed v2 — content-based labeling (DataDog primary)",
        "stats": {
            "total_files": len(all_files),
            "malicious_files": len(new_malicious_entries),
            "benign_files": len(benign_files),
            "malicious_packages": len(valid_pkgs),
        },
        "files": all_files,
    }
    D2_METADATA.write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\n  D2_dataset/malicious/ : {len(new_malicious_entries)} files written")
    print(f"  D2_dataset/benign/    : {len(benign_files)} files (untouched)")
    print(f"  D2_dataset/metadata.json rebuilt")
    print(f"\n  Run evaluation:")
    print(f"    python evaluation/run_d2_protocol.py --model_id KevinPhamH/codebert-finetuned --output outputs/d2_metrics_v2.json")


def main() -> None:
    parser = argparse.ArgumentParser(description="Assemble final D2 dataset.")
    parser.add_argument("--dry-run", action="store_true", help="Preview without writing files")
    args = parser.parse_args()
    build_d2(dry_run=args.dry_run)


if __name__ == "__main__":
    main()
