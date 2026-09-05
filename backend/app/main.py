from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config.settings import settings
from app.routes.health_routes import router as health_router
from app.routes.email_routes import router as email_router

from app.routes.case_routes import (
    router as case_router,
)

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "AI-Powered Email Threat Detection "
        "and Forensic Intelligence Platform"
    ),
)

# Frontend development ke liye CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(
    email_router,
    prefix=settings.api_prefix,
    tags=["Email Analysis"],
)

app.include_router(
    health_router,
    prefix=settings.api_prefix,
    tags=["Health"],
)

app.include_router(
    case_router,
    prefix=settings.api_prefix,
    tags=["Cases"],
)


@app.get("/")
def root():
    return {
        "project": "TraceX",
        "message": "Backend is running",
        "docs": "/docs",
    }