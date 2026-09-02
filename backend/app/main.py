from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config.settings import settings
from app.routes.health_routes import router as health_router


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
    health_router,
    prefix=settings.api_prefix,
    tags=["Health"],
)


@app.get("/")
def root():
    return {
        "project": "TraceX",
        "message": "Backend is running",
        "docs": "/docs",
    }