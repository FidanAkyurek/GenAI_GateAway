import time
import uuid
import logging
from fastapi import APIRouter
from app.models.schemas import PromptRequest, PromptResponse
from app.services.layer1_regex import Layer1Regex
from app.services.layer2_deberta import Layer2DeBERTa
from app.services.layer3_llm_judge import Layer3LLMJudge
from app.services.database_manager import DatabaseManager

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

    # ══════════════════════════════════════════════════════════
    # KATMAN 1: REFLEKS (Regex & DLP - PII Maskeleme)
    # ══════════════════════════════════════════════════════════
    regex_result = Layer1Regex.scan(processed_text)

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

    # ══════════════════════════════════════════════════════════
    # KATMAN 2: ZEKA (DeBERTa AI Modeli)
    # ══════════════════════════════════════════════════════════
    # Optimize edilmiş eşik değerleri (JailbreakBench test sonuçlarına göre)
    # Tezdeki hedef: TPR>%95, FPR<%2
    THRESHOLD_HIGH = 0.75   # Bu skoru aşan → direkt BLOCK (eski: 0.90)
    THRESHOLD_LOW  = 0.35   # Bu skoru aşan → LLM Judge'a gönder (eski: 0.50)

    ai_score = Layer2DeBERTa.predict_score(processed_text)
    logger.info(f"🤖 DeBERTa skoru: {ai_score} | user={request.user_id}")

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

    # ══════════════════════════════════════════════════════════
    # KATMAN 3: BİLGELİK (LLM Yargıç)
    # Sadece gri bölgede (0.50 < skor ≤ 0.90) devreye girer
    # ══════════════════════════════════════════════════════════
    if THRESHOLD_LOW < ai_score <= THRESHOLD_HIGH:
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