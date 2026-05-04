from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Optional, Tuple

from packaging.utils import canonicalize_name
from pydantic import BaseModel, Field

try:
    from crewai.tools import BaseTool
except ImportError:  # pragma: no cover
    from crewai_tools import BaseTool


class PyPIDownloaderInput(BaseModel):
    package: str = Field(
        ...,
        description="Package spec, e.g. 'requests' or 'requests==2.31.0'.",
    )
    download_dir: Optional[str] = Field(
        default=None,
        description="Optional destination directory. If omitted, uses env or default workspace path.",
    )


class PyPIDownloaderTool(BaseTool):
    name: str = "pypi_downloader"
    description: str = (
        "Download a PyPI package archive using pip and return structured JSON with "
        "resolved name, version, archive path, and URL."
    )
    args_schema: type[BaseModel] = PyPIDownloaderInput

    def _run(self, package: str, download_dir: Optional[str] = None) -> str:
        run_id = uuid.uuid4().hex
        resolved_spec = package.strip()
        package_name, requested_version = self._parse_package_spec(package)

        base_download_dir = Path(
            download_dir or os.getenv("LAMPS_DOWNLOAD_DIR", "artifacts/pypi_downloads")
        ).resolve()
        run_download_dir = base_download_dir / f"run_{run_id[:8]}"
        run_download_dir.mkdir(parents=True, exist_ok=True)

        timeout_seconds = int(os.getenv("PIP_DOWNLOAD_TIMEOUT", "180"))
        cmd = [
            sys.executable,
            "-m",
            "pip",
            "download",
            package.strip(),
            "--no-deps",
            "--disable-pip-version-check",
            "--dest",
            str(run_download_dir),
        ]

        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )

        if completed.returncode != 0:
            stderr = completed.stderr.strip() or "pip download failed without stderr."
            raise RuntimeError(f"Failed to download package '{package}': {stderr}")

        artifacts = [p for p in run_download_dir.iterdir() if p.is_file()]
        if not artifacts:
            raise RuntimeError(f"No package archive was downloaded for '{package}'.")

        archive_path = max(artifacts, key=lambda p: p.stat().st_mtime).resolve()
        inferred_name, inferred_version = self._infer_from_filename(archive_path.name)

        resolved_name = canonicalize_name(package_name or inferred_name)
        resolved_version = requested_version or inferred_version

        if not resolved_name or not resolved_version:
            raise RuntimeError(
                "Could not resolve package name/version after download. "
                f"package='{package}', archive='{archive_path.name}'"
            )

        payload = {
            "name": resolved_name,
            "version": resolved_version,
            "archive_path": str(archive_path),
            "url": self._build_pypi_url(resolved_name, resolved_version),
            "resolved_spec": resolved_spec,
            "provenance": {
                "retrieved_at_utc": datetime.now(timezone.utc).isoformat(),
                "source": "pip_download",
                "archive_sha256": self._sha256_file(archive_path),
                "run_id": run_id,
            },
        }
        return json.dumps(payload, ensure_ascii=False)

    @staticmethod
    def _build_pypi_url(name: str, version: str) -> str:
        return f"https://pypi.org/project/{name}/{version}/"

    @staticmethod
    def _parse_package_spec(package: str) -> Tuple[str, Optional[str]]:
        pattern = r"^\s*([A-Za-z0-9_.-]+)\s*(?:==\s*([A-Za-z0-9_.-]+))?\s*$"
        match = re.match(pattern, package)
        if not match:
            raise ValueError(
                "Invalid package spec. Expected 'name' or 'name==version', "
                f"got '{package}'."
            )

        name = canonicalize_name(match.group(1))
        version = match.group(2)
        return name, version

    @staticmethod
    def _infer_from_filename(filename: str) -> Tuple[str, str]:
        if filename.endswith(".whl"):
            stem = filename[:-4]
            parts = stem.split("-")
            if len(parts) < 2:
                raise ValueError(f"Cannot infer package/version from wheel filename '{filename}'.")
            return canonicalize_name(parts[0]), parts[1]

        stem = filename
        for ext in (".tar.gz", ".tar.bz2", ".tar.xz", ".zip", ".tgz"):
            if stem.endswith(ext):
                stem = stem[: -len(ext)]
                break

        if "-" not in stem:
            raise ValueError(f"Cannot infer package/version from archive filename '{filename}'.")

        name_part, version_part = stem.rsplit("-", 1)
        return canonicalize_name(name_part), version_part

    @staticmethod
    def _sha256_file(path: Path) -> str:
        hasher = hashlib.sha256()
        with path.open("rb") as f:
            while True:
                block = f.read(8192)
                if not block:
                    break
                hasher.update(block)
        return hasher.hexdigest()
