from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config.settings import settings
from app.routes.health_routes import router as health_router
from app.routes.email_routes import router as email_router

from app.routes.case_routes import (
    router as case_router,
)

from app.routes.report_routes import (
    router as report_router,
)

from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

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

app.include_router(
    report_router,
    prefix=settings.api_prefix,
    tags=["Reports"],
)

limiter = Limiter(
    key_func=get_remote_address
)

app.state.limiter = limiter

app.add_middleware(
    SlowAPIMiddleware
)

from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

app.add_exception_handler(
    RateLimitExceeded,
    _rate_limit_exceeded_handler,
)


@app.get("/")
def root():
    return {
        "project": "TraceX",
        "message": "Backend is running",
        "docs": "/docs",
    }