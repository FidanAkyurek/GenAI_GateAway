from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import time

# İleride yazacağımız controller (router) dosyasını import edeceğiz
from app.controllers import security_controller

app = FastAPI(
    title="GenAI Security Gateway",
    description="Multi-layered security proxy for Generative AI systems.",
    version="1.0.0"
)

# CORS ayarları (Farklı arayüzlerden, örn: Dashboard, erişim için)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Controller'ı (Router) uygulamaya dahil etme (Şimdilik yorum satırında)
app.include_router(security_controller.router, prefix="/api/v1")

@app.get("/api/v1/health", tags=["Health"])
async def health_check():
    """Sistemin çalışıp çalışmadığını kontrol eder."""
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "message": "GenAI Security Gateway is running."
    }

@app.get("/", tags=["Root"])
async def root():
    return {"message": "Welcome to GenAI Security Gateway API. Visit /docs for details."}