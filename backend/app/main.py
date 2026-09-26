"""
SecureMailScope — FastAPI application entry point.

Configures CORS, mounts routers, and serves the API.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import analysis, export, sessions

app = FastAPI(
    title="SecureMailScope",
    description="Passive Email Cryptographic Forensics — API",
    version="0.1.0",
)

# CORS — allow Next.js dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount routers
app.include_router(analysis.router)
app.include_router(sessions.router)
app.include_router(export.router)


@app.get("/")
async def root():
    return {
        "name": "SecureMailScope",
        "version": "0.1.0",
        "description": "Passive Email Cryptographic Forensics",
    }


@app.get("/health")
async def health():
    return {"status": "ok"}
