"""FastAPI application entry point.

Run with:  uvicorn app.main:app --reload
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

import app.tools  # noqa: F401  importing the package registers every tool
from app.api.routes import router
from app.config import ROOT, settings

app = FastAPI(title=settings.app_name, version=settings.version)

app.mount("/static", StaticFiles(directory=str(ROOT / "app" / "static")), name="static")
app.include_router(router)


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
