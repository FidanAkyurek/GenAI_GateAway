import time
import uuid
import logging
from datetime import datetime
from fastapi import APIRouter, HTTPException, Query, Depends
from app.models.schemas import PromptRequest, PromptResponse
from app.services.layer1_regex import Layer1Regex
# from app.services.layer2_deberta import Layer2DeBERTa  # Disable DeBERTa to avoid MKL crash
from app.services.layer3_llm_judge import Layer3LLMJudge
from app.services.database_manager import DatabaseManager
from app.config_manager import ConfigManager
from app.controllers.auth_controller import verify_admin

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/analyze", response_model=PromptResponse, tags=["Security Analysis"])
async def analyze_prompt(request: PromptRequest):
    """
    Kullanıcıdan gelen prompt'u 3 katmanlı güvenlik analizinden (Fail-Fast) geçirir.

    - Katman 1 (Refleks): Regex blacklist + PII maskeleme — <5ms
    - Katman 2 (Zeka): DeBERTa AI prompt injection tespiti — ~100ms
    - Katman 3 (Bilgelik): GPT-4o-mini LLM Judge (sadece gri bölgede) — ~500ms
    """
    start_time = time.time()
    log_id = str(uuid.uuid4())
    ai_score = 0.0
    stopped_at_layer = "None"

    # Başlangıçta metni orijinal haliyle işleme al
    processed_text = request.text

    # Config ayarlarını çek
    config = ConfigManager.load_config()

    # ══════════════════════════════════════════════════════════
    # KATMAN 1: REFLEKS (Regex & DLP - PII Maskeleme)
    # ══════════════════════════════════════════════════════════
    if config.layer_regex:
        regex_result = Layer1Regex.scan(processed_text, config.blacklist)

        if regex_result.is_blocked:
            stopped_at_layer = "Layer1"
            latency = int((time.time() - start_time) * 1000)
            await DatabaseManager.log_security_event(
                log_id=log_id, user_id=request.user_id,
                masked_prompt=processed_text, action="BLOCK",
                category="Blacklist", stopped_at_layer=stopped_at_layer,
                ai_score=0.0, latency_ms=latency
            )
            logger.warning(f"🚫 BLOCK [Layer1/Blacklist] user={request.user_id} | {latency}ms")
            return PromptResponse(
                log_id=log_id, status="BLOCK", category="Blacklist",
                reason="Yasaklı kelime tespit edildi.",
                latency_ms=latency
            )

        # PII varsa maskele, güvenli metin ile devam et
        if regex_result.has_pii:
            processed_text = regex_result.processed_text
            logger.info(f"🔒 PII maskelendi, işlem devam ediyor | user={request.user_id}")
    else:
        # Regex motoru kapalı ise, sadece dummy result oluştur (Loglama için Pii=False varsayarız)
        from app.services.layer1_regex import Layer1Result
        regex_result = Layer1Result(is_blocked=False, has_pii=False, processed_text=processed_text)

    # ══════════════════════════════════════════════════════════
    # KATMAN 2: ZEKA (DeBERTa AI Modeli)
    # ══════════════════════════════════════════════════════════
    # Optimize edilmiş eşik değerleri (Dashboard'dan gelir)
    THRESHOLD_HIGH = config.ai_threshold
    THRESHOLD_LOW  = 0.35   # Bu skoru aşan → LLM Judge'a gönder

    if config.layer_deberta:
        # DeBERTa model disabled due to MKL crash on Windows
        ai_score = 0.0  # Placeholder - Layer2DeBERTa.predict_score(processed_text)
        logger.info(f"🤖 DeBERTa skoru (disabled): {ai_score} | user={request.user_id}")

        if ai_score > THRESHOLD_HIGH:
            stopped_at_layer = "Layer2"
            latency = int((time.time() - start_time) * 1000)
            await DatabaseManager.log_security_event(
                log_id=log_id, user_id=request.user_id,
                masked_prompt=processed_text, action="BLOCK",
                category="Injection", stopped_at_layer=stopped_at_layer,
                ai_score=ai_score, latency_ms=latency
            )
            logger.warning(f"🚫 BLOCK [Layer2/Injection] score={ai_score} | {latency}ms")
            return PromptResponse(
                log_id=log_id, status="BLOCK", category="Injection",
                reason=f"Saldırı girişimi tespit edildi. (AI Skoru: {ai_score:.2f})",
                latency_ms=latency
            )
    else:
        ai_score = 0.0

    # ══════════════════════════════════════════════════════════
    # KATMAN 3: BİLGELİK (LLM Yargıç)
    # DeBERTa disabled olduğu için, tüm mesajlara Layer 3 uygulanır
    # Fail-Fast: Layer 1 geçtiyse Layer 3 kontrol eder
    # ══════════════════════════════════════════════════════════
    if config.layer_llm:
        llm_verdict = await Layer3LLMJudge.evaluate(processed_text)
        logger.info(f"⚖️ LLM Yargıç kararı: {llm_verdict} | user={request.user_id}")

        if llm_verdict == "UNSAFE":
            stopped_at_layer = "Layer3"
            latency = int((time.time() - start_time) * 1000)
            await DatabaseManager.log_security_event(
                log_id=log_id, user_id=request.user_id,
                masked_prompt=processed_text, action="BLOCK",
                category="Policy Violation", stopped_at_layer=stopped_at_layer,
                ai_score=ai_score, latency_ms=latency
            )
            logger.warning(f"🚫 BLOCK [Layer3/PolicyViolation] | {latency}ms")
            return PromptResponse(
                log_id=log_id, status="BLOCK", category="Policy Violation",
                reason="LLM Yargıç karmaşık bir manipülasyon (Jailbreak) tespit etti.",
                latency_ms=latency
            )

    # ══════════════════════════════════════════════════════════
    # GÜVENLİ İSTEK — Tüm katmanlardan geçti
    # ══════════════════════════════════════════════════════════
    stopped_at_layer = "None"
    category = "DLP" if regex_result.has_pii else "Safe"
    latency = int((time.time() - start_time) * 1000)

    await DatabaseManager.log_security_event(
        log_id=log_id, user_id=request.user_id,
        masked_prompt=processed_text, action="ALLOW",
        category=category, stopped_at_layer=stopped_at_layer,
        ai_score=ai_score, latency_ms=latency
    )
    logger.info(f"✅ ALLOW [{category}] | {latency}ms")

    return PromptResponse(
        log_id=log_id, status="ALLOW", category=category,
        processed_text=processed_text,
        latency_ms=latency
    )


# ══════════════════════════════════════════════════════════════════════════════
# 🔐 ADMIN CONFIGURATION ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/config", tags=["Admin Config"])
async def get_config():
    """
    Tüm sistemin konfigürasyonunu döndür.
    
    Returns:
    - layer_regex: Layer 1 (DLP) aktif mi?
    - layer_deberta: Layer 2 (AI Injection Detection) aktif mi?
    - layer_llm: Layer 3 (LLM Judge) aktif mi?
    - ai_threshold: AI threshold değeri (0.30 - 0.95)
    - blacklist: Yasaklı kelimeler listesi
    """
    config = ConfigManager.load_config()
    logger.info(f"📖 Config getirilerek görüntülendi")
    return config.model_dump()


@router.put("/config/blacklist", tags=["Admin Config"])
async def update_blacklist(
    operation: str = Query(..., description="'add' veya 'remove'"),
    word: str = Query(...)
):
    """
    Blacklist'e kelime ekle/sil.
    
    Query Parameters:
    - operation: 'add' (ekle) veya 'remove' (sil)
    - word: Eklenecek/silinecek kelime
    
    Örnek:
    - PUT /api/v1/config/blacklist?operation=add&word=bomba
    - PUT /api/v1/config/blacklist?operation=remove&word=bomba
    """
    if operation not in ["add", "remove"]:
        raise HTTPException(
            status_code=400,
            detail="operation 'add' veya 'remove' olmalı"
        )

    config = ConfigManager.load_config()

    if operation == "add":
        if word.lower() in [w.lower() for w in config.blacklist]:
            raise HTTPException(
                status_code=400,
                detail=f"'{word}' zaten blacklist'te var"
            )
        config.blacklist.append(word)
        logger.warning(f"➕ Blacklist'e kelime eklendi: {word}")
    else:  # remove
        if word not in config.blacklist:
            raise HTTPException(
                status_code=404,
                detail=f"'{word}' blacklist'te bulunamadı"
            )
        config.blacklist.remove(word)
        logger.warning(f"➖ Blacklist'ten kelime silindi: {word}")

    success = ConfigManager.save_config(config)
    if not success:
        raise HTTPException(
            status_code=500,
            detail="Config kaydedilemedi"
        )

    return {
        "message": f"Blacklist başarıyla güncellendi",
        "operation": operation,
        "word": word,
        "blacklist": config.blacklist
    }


@router.put("/config/threshold", tags=["Admin Config"])
async def update_threshold(
    threshold: float = Query(...)
):
    """
    DeBERTa AI threshold değerini güncelle.
    
    Query Parameters:
    - threshold: Yeni threshold değeri (0.30 - 0.95 arası olmalı)
    
    Örnek:
    - PUT /api/v1/config/threshold?threshold=0.70

    ℹ️ Threshold değeri ne kadar yüksek olursa, sistem o kadar katı olur.
    - 0.30: Çok hassas (yanlış pozitif çok olur)
    - 0.75: Dengeli (default)
    - 0.95: Çok katı (saldırı kaçabilir)
    """
    if not (0.30 <= threshold <= 0.95):
        raise HTTPException(
            status_code=400,
            detail="Threshold değeri 0.30 ile 0.95 arasında olmalı"
        )

    config = ConfigManager.load_config()
    old_threshold = config.ai_threshold
    config.ai_threshold = threshold

    success = ConfigManager.save_config(config)
    if not success:
        raise HTTPException(
            status_code=500,
            detail="Config kaydedilemedi"
        )

    logger.warning(f"📊 AI Threshold güncellendi: {old_threshold:.2f} → {threshold:.2f}")

    return {
        "message": "Threshold başarıyla güncellendi",
        "old_threshold": old_threshold,
        "new_threshold": threshold
    }


@router.put("/config/layers", tags=["Admin Config"])
async def update_layers(
    layer1: bool = Query(None, description="Layer 1 (DLP) aktif mi?"),
    layer2: bool = Query(None, description="Layer 2 (DeBERTa) aktif mi?"),
    layer3: bool = Query(None, description="Layer 3 (LLM Judge) aktif mi?")
):
    """
    Güvenlik katmanlarını açıp kapatma.
    
    Query Parameters (opsiyonel, null ise değişmez):
    - layer1: Layer 1 (DLP/Regex) açık mı? (true/false)
    - layer2: Layer 2 (DeBERTa AI) açık mı? (true/false)
    - layer3: Layer 3 (LLM Judge) açık mı? (true/false)
    
    Örnek:
    - PUT /api/v1/config/layers?layer1=true&layer2=true&layer3=false
    
    ⚠️ Tüm layer'ları kapatmak güvenlik açığı yaratır!
    """
    if layer1 is None and layer2 is None and layer3 is None:
        raise HTTPException(
            status_code=400,
            detail="En az bir layer parametresi gerekli"
        )

    config = ConfigManager.load_config()

    # Eski değerleri kaydet (log için)
    old_state = {
        "layer_regex": config.layer_regex,
        "layer_deberta": config.layer_deberta,
        "layer_llm": config.layer_llm
    }

    # Yeni değerleri ata
    if layer1 is not None:
        config.layer_regex = layer1
    if layer2 is not None:
        config.layer_deberta = layer2
    if layer3 is not None:
        config.layer_llm = layer3

    success = ConfigManager.save_config(config)
    if not success:
        raise HTTPException(
            status_code=500,
            detail="Config kaydedilemedi"
        )

    logger.warning(
        f"🔄 Layer'lar güncellendi | "
        f"L1: {old_state['layer_regex']}→{config.layer_regex}, "
        f"L2: {old_state['layer_deberta']}→{config.layer_deberta}, "
        f"L3: {old_state['layer_llm']}→{config.layer_llm}"
    )

    return {
        "message": "Layer konfigürasyonu başarıyla güncellendi",
        "previous_state": old_state,
        "new_state": {
            "layer_regex": config.layer_regex,
            "layer_deberta": config.layer_deberta,
            "layer_llm": config.layer_llm
        }
    }


@router.post("/feedback", tags=["Feedback"])
async def submit_feedback(
    log_id: str = Query(...),
    feedback_type: str = Query(..., description="'false_positive' veya 'false_negative'")
):
    """
    Yanlış pozitif / yanlış negatif bildirimi.
    
    Query Parameters:
    - log_id: Geri bildirim verilen log kaydının ID'si
    - feedback_type: 'false_positive' (yanlış engelleme) veya 'false_negative' (yanlış izin)
    
    Örnek:
    - POST /api/v1/feedback?log_id=abc-123&feedback_type=false_positive
    
    💾 Geri bildirimler kalıcı olarak kaydedilir ve analiz için kullanılabilir.
    """
    if feedback_type not in ["false_positive", "false_negative"]:
        raise HTTPException(
            status_code=400,
            detail="feedback_type 'false_positive' veya 'false_negative' olmalı"
        )

    # Geri bildirimi veritabanına kaydet
    try:
        await DatabaseManager.log_feedback(
            log_id=log_id,
            feedback_type=feedback_type
        )
        logger.info(f"📢 Feedback kaydedildi | log_id={log_id}, type={feedback_type}")
        return {
            "message": "Geri bildiriminiz başarıyla kaydedildi. Teşekkürler!",
            "log_id": log_id,
            "feedback_type": feedback_type
        }
    except Exception as e:
        logger.error(f"❌ Feedback kaydetme hatası: {e}")
        raise HTTPException(
            status_code=500,
            detail="Geri bildirim kaydedilemedi"
        )


# ══════════════════════════════════════════════════════════════════════════════
# 📊 LOG VE İSTATİSTİK ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/logs", tags=["Logs"])
async def get_logs(
    limit: int = Query(50, ge=1, le=500),
    action: str = Query(None, description="'BLOCK' veya 'ALLOW'"),
    category: str = Query(None, description="'Safe', 'Injection', 'PII', 'Blacklist', 'Policy Violation'")
):
    """
    Filtrelenmiş log kayıtlarını döndür.
    
    Query Parameters:
    - limit: Kaç kayıt döndürülecek (1-500, default: 50)
    - action: 'BLOCK' (engellenenler) veya 'ALLOW' (izin verilenler)
    - category: Güvenlik kategorisi filtrelemesi
    
    Örnek:
    - GET /api/v1/logs?limit=100&action=BLOCK&category=Injection
    """
    logs = await DatabaseManager.get_logs(
        limit=limit,
        action_filter=action,
        category_filter=category
    )
    logger.info(f"📖 Log listesi getirildi | action={action}, category={category}, count={len(logs)}")
    return {"logs": logs, "count": len(logs)}


@router.get("/stats", tags=["Statistics"])
async def get_stats():
    """
    Dashboard için özet istatistikler.
    
    Returns:
    - total_requests: Toplam istek sayısı
    - blocked: Engellenen istek sayısı
    - allowed: İzin verilen istek sayısı
    - avg_latency_ms: Ortalama yanıt süresi (ms)
    """
    stats = await DatabaseManager.get_stats()
    logger.info(f"📊 İstatistikler getirildi | {stats}")
    return stats


@router.get("/health", tags=["Health"])
async def health_check():
    """
    Sistem sağlık kontrolü.
    
    Returns:
    - status: 'ok' veya 'error'
    - model_loaded: DeBERTa modeli yüklü mü?
    - db_connected: Veritabanı bağlı mı?
    """
    try:
        # DeBERTa modeli disabled - return false
        model_ready = False  # Layer2DeBERTa._model is not None
        
        # DB kontrol et
        db_ok = await DatabaseManager.get_stats() is not None
        
        return {
            "status": "ok" if db_ok else "degraded",
            "model_loaded": model_ready,
            "db_connected": db_ok,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"❌ Health check hatası: {e}")
        return {
            "status": "error",
            "detail": str(e)
        }