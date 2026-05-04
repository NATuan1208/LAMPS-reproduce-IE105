from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field

try:
    from crewai.tools import BaseTool
except ImportError:  # pragma: no cover
    from crewai_tools import BaseTool


class PythonFileReaderInput(BaseModel):
    file_path: str = Field(..., description="Absolute path to a Python file.")


class PythonFileReaderTool(BaseTool):
    name: str = "python_file_reader"
    description: str = "Read and return source code content of a .py file for classifier analysis."
    args_schema: type[BaseModel] = PythonFileReaderInput

    def _run(self, file_path: str) -> str:
        path = Path(file_path).resolve()
        if path.suffix != ".py":
            raise ValueError(f"Only .py files are allowed, got '{path}'.")

        allowed_root = Path(os.getenv("LAMPS_ALLOWED_READ_ROOT", ".")).resolve()
        if not self._is_relative_to(path, allowed_root):
            raise ValueError(f"Refusing to read file outside allowed root '{allowed_root}': {path}")

        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"Python file not found: {path}")

        max_bytes = int(os.getenv("LAMPS_MAX_FILE_BYTES", str(2 * 1024 * 1024)))
        if path.stat().st_size > max_bytes:
            raise ValueError(f"File is too large to read safely ({path.stat().st_size} bytes): {path}")

        try:
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return path.read_text(encoding="latin-1")

    @staticmethod
    def _is_relative_to(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False
