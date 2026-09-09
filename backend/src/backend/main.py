from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn

from backend.api.router import api_router
from backend.api.v1.endpoints.search import router as search_router
from backend.config import get_settings

settings = get_settings()

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = PACKAGE_DIR.parent.parent

TEMPLATES_DIR = PROJECT_DIR / "templates" if (PROJECT_DIR / "templates").exists() else PACKAGE_DIR / "templates"
STATIC_DIR = PROJECT_DIR / "static" if (PROJECT_DIR / "static").exists() else PACKAGE_DIR / "static"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Startup logic (e.g., database connection pool initialization)
    yield
    # Shutdown logic (e.g., closing connections)


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        openapi_url=f"{settings.API_V1_STR}/openapi.json",
        docs_url=f"{settings.API_V1_STR}/docs",
        redoc_url=f"{settings.API_V1_STR}/redoc",
        lifespan=lifespan,
    )

    # Enable CORS for local dev / client integration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount static assets directory
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # Mount API routers under versioned prefix (/api/v1) and convenience alias (/api)
    app.include_router(api_router, prefix=settings.API_V1_STR)
    app.include_router(search_router, prefix="/api", tags=["Search"])

    @app.get("/", response_class=HTMLResponse, tags=["Frontend"])
    async def home(request: Request):
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={"request": request},
        )

    @app.get("/terms", response_class=HTMLResponse, tags=["Legal"])
    async def terms():
        return HTMLResponse(
            "<!DOCTYPE html><html lang='en'><head><title>Terms of Service</title><style>body{background:#0b0e14;color:#f0f6fc;font-family:sans-serif;padding:40px;line-height:1.6;max-width:700px;margin:0 auto;}</style></head><body><h1>Terms of Service</h1><p>This intelligence search interface is provided for authorized security research and verification purposes only. Unauthorized automated harvesting is prohibited.</p><p><a href='/' style='color:#388bfd;'>&larr; Back to Search</a></p></body></html>"
        )

    @app.get("/privacy", response_class=HTMLResponse, tags=["Legal"])
    async def privacy():
        return HTMLResponse(
            "<!DOCTYPE html><html lang='en'><head><title>Privacy Policy</title><style>body{background:#0b0e14;color:#f0f6fc;font-family:sans-serif;padding:40px;line-height:1.6;max-width:700px;margin:0 auto;}</style></head><body><h1>Privacy Policy</h1><p>We respect individual privacy rights. Search queries are processed in accordance with public threat intelligence indices and are not permanently logged.</p><p><a href='/' style='color:#388bfd;'>&larr; Back to Search</a></p></body></html>"
        )

    @app.get("/opt-out", response_class=HTMLResponse, tags=["Legal"])
    async def opt_out():
        return HTMLResponse(
            "<!DOCTYPE html><html lang='en'><head><title>Opt-Out Request</title><style>body{background:#0b0e14;color:#f0f6fc;font-family:sans-serif;padding:40px;line-height:1.6;max-width:700px;margin:0 auto;}</style></head><body><h1>Opt-Out Request</h1><p>To request suppression of an identifier from public search indexing, please submit an identity verification request.</p><p><a href='/' style='color:#388bfd;'>&larr; Back to Search</a></p></body></html>"
        )

    return app


app = create_app()


def start() -> None:
    """Entrypoint to run the server via uv run backend"""
    uvicorn.run(
        "backend.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
    )


if __name__ == "__main__":
    start()
