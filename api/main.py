#!/usr/bin/env python3
"""
Signsley Python Backend - pyhanko 0.31
Digital Signature Verification Service

Main FastAPI application entry point.
"""

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import os
from pathlib import Path

# Import routers
from routers.verify_pades import router as pades_router
from routers.verify_cades import router as cades_router  
from routers.verify_xades import router as xades_router
from utils.logging_config import setup_logging

# Initialize logging
setup_logging()

# Initialize FastAPI app
app = FastAPI(
    title="Signsley - Digital Signature Verification",
    description="Professional digital signature verification service supporting PAdES, CAdES, and XAdES formats using pyhanko 0.31",
    version="4.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(pades_router, prefix="/api", tags=["PAdES Verification"])
app.include_router(cades_router, prefix="/api", tags=["CAdES Verification"])
app.include_router(xades_router, prefix="/api", tags=["XAdES Verification"])

# Health check endpoint
@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": "4.1.0",
        "backend": "Python FastAPI + pyhanko 0.31"
    }

# Serve static files (frontend)
static_path = Path(__file__).parent.parent
if (static_path / "index.html").exists():
    app.mount("/", StaticFiles(directory=str(static_path), html=True), name="static")
else:
    # Development: serve a simple message
    @app.get("/", response_class=HTMLResponse)
    async def read_root():
        return """
        <!DOCTYPE html>
        <html>
        <head><title>Signsley API</title></head>
        <body>
            <h1>Signsley Python Backend</h1>
            <p>API Documentation: <a href="/api/docs">/api/docs</a></p>
            <p>Frontend files should be placed in the parent directory.</p>
        </body>
        </html>
        """

if __name__ == "__main__":
    # For development
    uvicorn.run(
        "main:app", 
        host="0.0.0.0", 
        port=8000, 
        reload=True,
        log_level="info"
    )