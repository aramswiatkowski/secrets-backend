from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.routers import auth, me, credits, community, webhooks, admin
from app.db import init_db

app = FastAPI(
    title="Secrets of Decoupage PWA API",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def _startup():
    init_db()

@app.get("/health")
def health():
    return {"ok": True}

app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(me.router, prefix="/me", tags=["me"])
app.include_router(credits.router, prefix="/credits", tags=["credits"])
app.include_router(community.router, prefix="/community", tags=["community"])
app.include_router(webhooks.router, prefix="/webhooks", tags=["webhooks"])
app.include_router(admin.router, prefix="/admin", tags=["admin"])
