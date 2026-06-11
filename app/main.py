from fastapi import FastAPI, Query, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
import time
import logging
import os
from typing import Optional
from contextlib import asynccontextmanager
from dotenv import load_dotenv

# .env dosyasını yükle (projenin kök dizininde olmalı)
load_dotenv()

from app.controllers import security_controller, auth_controller, admin_controller
from app.services.database_manager import DatabaseManager
from app.config_manager import ConfigManager, RulesConfig
from app.services.layer2_deberta import Layer2DeBERTa

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)
logger = logging.getLogger(__name__)

# Graceful shutdown flag
_shutdown_event = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _shutdown_event
    _shutdown_event = False
    logger.info("🚀 GenAI Security Gateway başlatılıyor...")
    try:
        Layer2DeBERTa.load_model()
        await DatabaseManager.initialize()
        logger.info("✅ Sistem hazır!")
    except Exception as e:
        logger.error(f"❌ Başlatma hatası: {e}", exc_info=True)
        raise

    yield

    _shutdown_event = True
    logger.info("🛑 GenAI Security Gateway kapatılıyor...")
    try:
        # Database bağlantılarını düzgün kapat
        await DatabaseManager.close()
        logger.info("✅ Veritabanı bağlantıları kapatıldı")
    except Exception as e:
        logger.error(f"❌ Kapatılırken hata: {e}", exc_info=True)
    logger.info("✅ Sistem tamamen kapatıldı")


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
    lifespan=lifespan
)

# ── CORS (Dashboard ve harici istemciler için) ─────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Session Middleware (OAuth için zorunlu) ────────────────────────────────────
app.add_middleware(SessionMiddleware, secret_key=os.getenv("JWT_SECRET", "super-secret-oauth-session-key"))


# ── Router'ı dahil et ──────────────────────────────────────────────────────────
app.include_router(security_controller.router, prefix="/api/v1")
app.include_router(auth_controller.router, prefix="/api/v1/auth")
app.include_router(admin_controller.router, prefix="/api/v1/admin")



@app.get("/api/v1/health", tags=["Health"])
async def health_check():
    """Sistemin ve modellerin çalışıp çalışmadığını kontrol eder."""
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "model_loaded": False,  # Layer 2 disabled to avoid crashes
        "message": "GenAI Security Gateway is running."
    }


# ── Kullanıcıya Özel Endpoint'ler ──────────────────────────────────────────────
@app.get("/api/v1/user/stats", tags=["User"])
async def get_user_stats(payload: dict = Depends(auth_controller.verify_token)):
    """Giriş yapmış kullanıcının kendi istatistiklerini döner."""
    username = payload.get("sub")
    stats = await DatabaseManager.get_stats(user_id=username)
    return stats


@app.get("/api/v1/user/logs", tags=["User"])
async def get_user_logs(
    limit: int = Query(default=50, ge=1, le=500),
    action: Optional[str] = Query(default=None),
    category: Optional[str] = Query(default=None),
    payload: dict = Depends(auth_controller.verify_token)
):
    """Giriş yapmış kullanıcının kendi log kayıtlarını döner."""
    username = payload.get("sub")
    logs = await DatabaseManager.get_logs(
        limit=limit,
        action_filter=action,
        category_filter=category,
        user_id=username
    )
    return {"count": len(logs), "logs": logs}


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

# ── Ayarlar (Kurallar) Endpoint'leri ───────────────────────────────────────────
@app.get("/api/v1/rules", tags=["Rules"])
async def get_rules():
    """Mevcut güvenlik ayarlarını getirir."""
    return ConfigManager.load_config()

@app.post("/api/v1/rules", tags=["Rules"])
async def update_rules(config: RulesConfig):
    """Güvenlik ayarlarını günceller."""
    success = ConfigManager.save_config(config)
    if success:
        return {"success": True, "message": "Ayarlar güncellendi."}
    return {"success": False, "message": "Ayarlar kaydedilemedi."}

@app.post("/api/v1/start-frontend", tags=["System"])
async def start_frontend():
    """Streamlit frontend'ini arka planda başlatır."""
    import subprocess
    import socket
    try:
        # Check if already running on port 8501
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('localhost', 8501)) == 0:
                return {"success": True, "message": "Frontend zaten çalışıyor.", "url": "http://localhost:8501"}
        
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        venv_python = os.path.join(base_dir, ".venv", "Scripts", "python.exe")
        app_script = os.path.join(base_dir, "streamlit_app.py")
        
        # Start in background without blocking
        subprocess.Popen(
            [venv_python, "-m", "streamlit", "run", app_script], 
            cwd=base_dir,
            creationflags=subprocess.CREATE_NEW_CONSOLE if os.name == 'nt' else 0
        )
        return {"success": True, "message": "Frontend başlatıldı.", "url": "http://localhost:8501"}
    except Exception as e:
        logger.error(f"Frontend başlatılamadı: {e}")
        return {"success": False, "message": f"Hata: {e}"}

# ── Frontend (Dashboard) ───────────────────────────────────────────────────────
# Kök path'e index.html serve et
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
# Alternative path
app.mount("/dashboard", StaticFiles(directory="frontend", html=True), name="dashboard")
