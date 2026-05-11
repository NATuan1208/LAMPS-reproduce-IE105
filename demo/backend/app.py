"""LAMPS Demo — FastAPI backend."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .scanner import PACKAGES, load_model, scan_package

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

FRONTEND = Path(__file__).parent.parent / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Loading CodeBERT model — please wait (~20s)...")
    await asyncio.to_thread(load_model)
    logger.info("Model ready. Open http://localhost:8000")
    yield


app = FastAPI(title="LAMPS Demo", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory=str(FRONTEND)), name="static")


class ScanRequest(BaseModel):
    package_id: str
    strategy: str = "head"


@app.get("/")
async def root():
    return FileResponse(FRONTEND / "index.html")


@app.get("/packages")
async def list_packages():
    return [
        {
            "id": pid,
            "display_name": info["display_name"],
            "type": info["type"],
            "description": info["description"],
            "strategy_demo": info["strategy_demo"],
        }
        for pid, info in PACKAGES.items()
    ]


@app.post("/scan")
async def scan(req: ScanRequest):
    if req.package_id not in PACKAGES:
        raise HTTPException(404, f"Unknown package: {req.package_id}")
    if req.strategy not in ("head", "head_tail"):
        raise HTTPException(400, "strategy must be 'head' or 'head_tail'")
    return await asyncio.to_thread(scan_package, req.package_id, req.strategy)
