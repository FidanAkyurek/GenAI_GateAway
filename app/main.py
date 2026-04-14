from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
import time
import logging
from typing import Optional
from contextlib import asynccontextmanager
from dotenv import load_dotenv

# .env dosyasını yükle (projenin kök dizininde olmalı)
load_dotenv()

from app.controllers import security_controller
from app.services.database_manager import DatabaseManager
from app.services.layer2_deberta import Layer2DeBERTa

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)
logger = logging.getLogger(__name__)


# ── Uygulama başlarken / kapanırken çalışacak işlemler ────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # STARTUP
    logger.info("🚀 GenAI Security Gateway başlatılıyor...")

    # 1. Veritabanını başlat (tablo oluştur)
    await DatabaseManager.initialize()

    # 2. DeBERTa modelini ön yükle (ilk istekte yavaşlık olmasın)
    logger.info("⏳ DeBERTa modeli yükleniyor (ilk seferinde birkaç dakika sürebilir)...")
    Layer2DeBERTa.load_model()

    logger.info("✅ Sistem hazır!")
    yield

    # SHUTDOWN
    logger.info("🛑 GenAI Security Gateway kapatılıyor...")


# ── FastAPI Uygulaması ─────────────────────────────────────────────────────────
app = FastAPI(
    title="GenAI Security Gateway",
    description="""
## Üretken Yapay Zeka Sistemleri İçin Çok Katmanlı Akıllı Güvenlik Ağ Geçidi

Kullanıcılar ile yapay zeka modelleri arasında konumlanan, 3 katmanlı güvenlik proxy'si.

### Katmanlar:
- **Katman 1 (Refleks):** Regex blacklist + PII maskeleme — `<5ms`
- **Katman 2 (Zeka):** DeBERTa AI prompt injection tespiti — `~100ms`
- **Katman 3 (Bilgelik):** GPT-4o-mini LLM Judge — `~500ms` (sadece gri bölge)

### Geliştirici: Funda Bozburun & Fidan Akyürek | İstanbul Topkapı Üniversitesi
    """,
    version="1.0.0",
    lifespan=lifespan,
)

# ── CORS (Dashboard ve harici istemciler için) ─────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Router'ı dahil et ──────────────────────────────────────────────────────────
app.include_router(security_controller.router, prefix="/api/v1")


# ── Kök & Health Endpoint'leri ─────────────────────────────────────────────────
@app.get("/", tags=["Root"])
async def root():
    return {
        "message": "GenAI Security Gateway çalışıyor.",
        "docs": "/docs",
        "health": "/api/v1/health"
    }


@app.get("/api/v1/health", tags=["Health"])
async def health_check():
    """Sistemin ve modellerin çalışıp çalışmadığını kontrol eder."""
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "model_loaded": Layer2DeBERTa._classifier is not None,
        "message": "GenAI Security Gateway is running."
    }


# ── Log Listeleme Endpoint'i ───────────────────────────────────────────────────
@app.get("/api/v1/logs", tags=["Logs"])
async def get_logs(
    limit: int = Query(default=50, ge=1, le=500, description="Kaç kayıt dönsün"),
    action: Optional[str] = Query(default=None, description="ALLOW veya BLOCK"),
    category: Optional[str] = Query(default=None, description="Safe, Injection, Blacklist, PII..."),
):
    """
    Güvenlik log kayıtlarını filtreli olarak listeler.
    Örnek: /api/v1/logs?limit=20&action=BLOCK&category=Injection
    """
    logs = await DatabaseManager.get_logs(
        limit=limit,
        action_filter=action,
        category_filter=category,
    )
    return {"count": len(logs), "logs": logs}


# ── İstatistik Endpoint'i ──────────────────────────────────────────────────────
@app.get("/api/v1/stats", tags=["Logs"])
async def get_stats():
    """Dashboard için özet istatistikler: toplam istek, engellenen, ortalama gecikme."""
    stats = await DatabaseManager.get_stats()
    return stats


# ── Feedback Endpoint'i ────────────────────────────────────────────────────────
@app.post("/api/v1/feedback", tags=["Feedback"])
async def submit_feedback(log_id: str, correct_label: str):
    """
    Yanlış engellemelerin (False Positive) raporlanması için kullanılır.
    Örnek: { "log_id": "abc-123", "correct_label": "safe" }
    """
    success = await DatabaseManager.save_feedback(log_id, correct_label)
    return {"success": success, "message": f"Feedback kaydedildi: {log_id} → {correct_label}"}