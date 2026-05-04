"""
Extract Python source files from DataDog malicious-software-packages-dataset.

Streams each package ZIP via `git cat-file blob` — no full working-tree checkout needed.
DataDog ZIPs are encrypted with password "infected". Inside may be raw .py files,
a wheel (.whl), or a tarball (.tar.gz); all are handled via nested extraction.

Prerequisites:
    git clone --depth 1 --filter=blob:none --sparse \
        https://github.com/DataDog/malicious-software-packages-dataset.git
    cd malicious-software-packages-dataset
    git sparse-checkout set samples/pypi
    git checkout

Usage:
    cd <LAMPS root>
    python scripts/extract_datadog.py [--max-packages N] [--output-dir PATH]

Output:
    scripts/extracted_malicious/     flat directory of extracted .py files
    scripts/datadog_raw_metadata.json  per-file metadata (no content embedded)
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
DATADOG_REPO = LAMPS_ROOT / "malicious-software-packages-dataset"

SCRIPTS_DIR = Path(__file__).parent
DEFAULT_OUTPUT = SCRIPTS_DIR / "extracted_malicious"
DEFAULT_METADATA = SCRIPTS_DIR / "datadog_raw_metadata.json"
D1_HASHES_FILE = SCRIPTS_DIR / "d1_hashes.json"

ZIP_PASSWORD = b"infected"
SKIP_DIRS = {"test", "tests", "doc", "docs", "example", "examples", "__pycache__"}
SKIP_FILES = {"conftest.py"}
MIN_CONTENT_LEN = 50


def _load_d1_hashes() -> set[str]:
    if D1_HASHES_FILE.exists():
        return set(json.loads(D1_HASHES_FILE.read_text(encoding="utf-8")))
    print("[WARN] d1_hashes.json not found — dedup disabled")
    return set()


def _git_ls_tree_blobs(repo: Path, tree_path: str) -> list[tuple[str, str, str]]:
    """Return list of (blob_hash, file_path, pkg_name) for all ZIPs under tree_path."""
    result = subprocess.run(
        ["git", "ls-tree", "-r", "HEAD", tree_path],
        cwd=repo,
        capture_output=True,
        text=True,
    )
    entries = []
    for line in result.stdout.splitlines():
        # Format: <mode> blob <hash>\t<path>
        parts = line.split("\t", 1)
        if len(parts) != 2:
            continue
        meta, path = parts
        if not path.endswith(".zip"):
            continue
        blob_hash = meta.split()[2]
        # pkg_name is the directory immediately under the category dir
        # path: samples/pypi/<category>/<pkg_name>/[version/]<file>.zip
        path_parts = path.split("/")
        if len(path_parts) >= 4:
            pkg_name = path_parts[3]
        else:
            pkg_name = path_parts[-1]
        entries.append((blob_hash, path, pkg_name))
    return entries


def _stream_blob(repo: Path, blob_hash: str) -> bytes:
    """Stream a git blob as bytes."""
    result = subprocess.run(
        ["git", "cat-file", "blob", blob_hash],
        cwd=repo,
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git cat-file failed for {blob_hash}: {result.stderr.decode()}")
    return result.stdout


def _should_skip(py_name: str, py_parts: list[str], content: str, d1_hashes: set[str]) -> tuple[bool, str]:
    lower_parts = [p.lower() for p in py_parts]
    if any(d in SKIP_DIRS for d in lower_parts):
        return True, "test/doc dir"
    if py_name in SKIP_FILES:
        return True, "conftest"
    if len(content.strip()) < MIN_CONTENT_LEN:
        return True, "too short"
    h = hashlib.md5(content.encode("utf-8", errors="ignore")).hexdigest()
    if py_name != "setup.py" and h in d1_hashes:
        return True, "dup with D1"
    return False, ""


def _collect_from_zipobj(zf: zipfile.ZipFile, pkg_name: str, category: str, d1_hashes: set[str]) -> list[dict]:
    """Collect .py file records from an already-open ZipFile (decrypted)."""
    records = []
    for info in zf.infolist():
        name = info.filename
        if not name.endswith(".py"):
            continue
        py_parts = name.replace("\\", "/").split("/")
        py_name = py_parts[-1]
        try:
            raw = zf.read(info)
            content = raw.decode("utf-8", errors="ignore")
        except Exception:
            continue
        skip, _ = _should_skip(py_name, py_parts, content, d1_hashes)
        if skip:
            continue
        h = hashlib.md5(content.encode("utf-8", errors="ignore")).hexdigest()
        records.append({
            "original_path": name,
            "content": content,
            "package": pkg_name,
            "category": category,
            "content_hash": h[:8],
            "char_count": len(content),
            "line_count": content.count("\n") + 1,
            "source": "datadog",
        })
    return records


def _extract_from_zip_bytes(zip_bytes: bytes, pkg_name: str, category: str, d1_hashes: set[str]) -> list[dict]:
    """Decrypt outer ZIP, then handle nested .whl / .tar.gz / raw .py files."""
    records: list[dict] = []

    try:
        outer = zipfile.ZipFile(io.BytesIO(zip_bytes))
        outer.setpassword(ZIP_PASSWORD)
    except Exception as e:
        raise RuntimeError(f"Cannot open outer ZIP: {e}")

    # Collect .py files directly inside and any nested archives
    nested_whl: list[bytes] = []
    nested_tar: list[bytes] = []

    for info in outer.infolist():
        name = info.filename
        try:
            data = outer.read(info)
        except Exception:
            continue

        if name.endswith(".py"):
            py_parts = name.replace("\\", "/").split("/")
            py_name = py_parts[-1]
            try:
                content = data.decode("utf-8", errors="ignore")
            except Exception:
                continue
            skip, _ = _should_skip(py_name, py_parts, content, d1_hashes)
            if skip:
                continue
            h = hashlib.md5(content.encode("utf-8", errors="ignore")).hexdigest()
            records.append({
                "original_path": name,
                "content": content,
                "package": pkg_name,
                "category": category,
                "content_hash": h[:8],
                "char_count": len(content),
                "line_count": content.count("\n") + 1,
                "source": "datadog",
            })
        elif name.endswith(".whl"):
            nested_whl.append(data)
        elif name.endswith(".tar.gz") or name.endswith(".tgz"):
            nested_tar.append(data)

    outer.close()

    # Expand nested wheels
    for whl_bytes in nested_whl:
        try:
            whl = zipfile.ZipFile(io.BytesIO(whl_bytes))
            records.extend(_collect_from_zipobj(whl, pkg_name, category, d1_hashes))
            whl.close()
        except Exception as e:
            print(f"    [WARN] whl expand failed: {e}")

    # Expand nested tarballs
    for tar_bytes in nested_tar:
        try:
            tf = tarfile.open(fileobj=io.BytesIO(tar_bytes))
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
                skip, _ = _should_skip(py_name, py_parts, content, d1_hashes)
                if skip:
                    continue
                h = hashlib.md5(content.encode("utf-8", errors="ignore")).hexdigest()
                records.append({
                    "original_path": name,
                    "content": content,
                    "package": pkg_name,
                    "category": category,
                    "content_hash": h[:8],
                    "char_count": len(content),
                    "line_count": content.count("\n") + 1,
                    "source": "datadog",
                })
            tf.close()
        except Exception as e:
            print(f"    [WARN] tar expand failed: {e}")

    return records


def extract_all(
    repo: Path,
    output_dir: Path,
    metadata_path: Path,
    max_packages: int = 300,
    max_files_per_package: int = 30,
    categories: list[str] | None = None,
) -> list[dict]:
    if not repo.exists():
        raise FileNotFoundError(
            f"DataDog repo not found at {repo}\n"
            "  Clone with:\n"
            "    git clone --depth 1 --filter=blob:none --sparse \\\n"
            "        https://github.com/DataDog/malicious-software-packages-dataset.git\n"
            "    cd malicious-software-packages-dataset\n"
            "    git sparse-checkout set samples/pypi\n"
            "    git checkout"
        )

    if categories is None:
        # Default: malicious_intent only. compromised_lib packages (litellm, telnyx etc.)
        # have thousands of legit files per package — not suitable for bulk extraction.
        categories = ["malicious_intent"]

    d1_hashes = _load_d1_hashes()
    output_dir.mkdir(parents=True, exist_ok=True)

    all_records: list[dict] = []
    seen_packages: set[str] = set()
    pkg_count = 0

    for category in categories:
        tree_path = f"samples/pypi/{category}/"
        blobs = _git_ls_tree_blobs(repo, tree_path)
        print(f"\n[{category}] {len(blobs)} ZIP entries")

        for blob_hash, zip_path, pkg_name in blobs:
            if pkg_name in seen_packages:
                continue  # only process one version per package
            if pkg_count >= max_packages:
                print(f"  [INFO] Reached max_packages={max_packages}, stopping.")
                break

            try:
                zip_bytes = _stream_blob(repo, blob_hash)
                pkg_records = _extract_from_zip_bytes(zip_bytes, pkg_name, category, d1_hashes)
            except Exception as e:
                print(f"  [ERROR] {pkg_name}: {e}")
                seen_packages.add(pkg_name)
                continue

            seen_packages.add(pkg_name)

            # Cap files per package to avoid bloating from large packages
            if len(pkg_records) > max_files_per_package:
                pkg_records = pkg_records[:max_files_per_package]

            if pkg_records:
                safe_pkg = pkg_name.replace("-", "_").replace(".", "_")[:40]
                for idx, rec in enumerate(pkg_records):
                    filename = f"{safe_pkg}_{idx:03d}_{rec['content_hash']}.py"
                    out_path = output_dir / filename
                    out_path.write_text(rec["content"], encoding="utf-8", errors="ignore")
                    rec["filename"] = filename
                    del rec["content"]

                all_records.extend(pkg_records)
                pkg_count += 1
                print(f"  {pkg_name}: {len(pkg_records)} .py files")
            else:
                print(f"  {pkg_name}: 0 .py files")

    metadata_path.write_text(
        json.dumps(all_records, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"\n=== DATADOG EXTRACTION COMPLETE ===")
    print(f"  Valid packages (>= 1 .py file): {pkg_count}")
    print(f"  Total .py files extracted     : {len(all_records)}")
    print(f"  Metadata saved                : {metadata_path}")
    return all_records


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract .py files from DataDog dataset ZIPs via git cat-file.")
    parser.add_argument("--datadog-repo", type=Path, default=DATADOG_REPO)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--metadata", type=Path, default=DEFAULT_METADATA)
    parser.add_argument("--max-packages", type=int, default=300)
    parser.add_argument("--max-files-per-package", type=int, default=30)
    parser.add_argument(
        "--categories",
        type=str,
        default="malicious_intent",
        help="Comma-separated categories: malicious_intent,compromised_lib (default: malicious_intent)",
    )
    args = parser.parse_args()
    cats = [c.strip() for c in args.categories.split(",") if c.strip()]
    extract_all(args.datadog_repo, args.output_dir, args.metadata, args.max_packages, args.max_files_per_package, cats)


if __name__ == "__main__":
    main()
