from fastapi import APIRouter
from app.models.schemas import PromptRequest, PromptResponse
import time
from app.services.layer1_regex import Layer1Regex
from app.services.layer2_deberta import Layer2DeBERTa
from app.services.layer3_llm_judge import Layer3LLMJudge

router = APIRouter()

@router.post("/analyze", response_model=PromptResponse, tags=["Security Analysis"])
async def analyze_prompt(request: PromptRequest):
    """
    Kullanıcıdan gelen prompt'u alır ve 3 katmanlı güvenlik analizinden (Fail-Fast) geçirir.
    """
    start_time = time.time()
    
    # Başlangıçta metni orijinal haliyle işleme alıyoruz
    processed_text = request.text

    # ==========================================
    # KATMAN 1: REFLEKS (Regex & DLP - PII Maskeleme) [cite: 687, 688]
    
    regex_result = Layer1Regex.scan(processed_text)
    if regex_result.is_blocked:
       # log_threat("Layer1", "Blacklist Keyword", request.user_id) [cite: 692]
       return PromptResponse(
            status="BLOCK",
            category="Blacklist",
            reason="Yasaklı kelime tespit edildi.",
            latency_ms=int((time.time() - start_time) * 1000)
        )
    if regex_result.has_pii:
        processed_text = Layer1Regex.mask_pii(processed_text) 

    # ==========================================
    # KATMAN 2: ZEKA (DeBERTa AI Modeli) [cite: 696]
    
    ai_score = Layer2DeBERTa.predict_score(processed_text) 
    THRESHOLD_HIGH = 0.90
    THRESHOLD_LOW = 0.50
    
    if ai_score > THRESHOLD_HIGH: 
    #     # log_threat("Layer2", "AI Injection Detection", request.user_id) [cite: 702]
        
        return PromptResponse(
            status="BLOCK",
             category="Injection",
            reason="Saldırı girişimi tespit edildi.", 
            latency_ms=int((time.time() - start_time) * 1000)
     )

    # ==========================================
    # KATMAN 3: BİLGELİK (LLM Yargıç) [cite: 704]
    # Sadece skor gri alanda ise (Örn: 0.50 ile 0.90 arası) devreye girer [cite: 708]

    if THRESHOLD_LOW < ai_score <= THRESHOLD_HIGH:
        llm_verdict = await Layer3LLMJudge.evaluate(processed_text)
        
        if llm_verdict == "UNSAFE":
            # log_threat("Layer3", "Complex Policy Violation", request.user_id)
            return PromptResponse(
                status="BLOCK",
                category="Policy Violation",
                reason="LLM Yargıç karmaşık bir manipülasyon (Jailbreak) tespit etti.",
                latency_ms=int((time.time() - start_time) * 1000)
            )

    # ==========================================
    # GÜVENLİ İSTEK (Tüm katmanlardan geçtiyse) [cite: 712]
    # ==========================================
    # log_to_db("ALLOW", "Safe", request.user_id)
    
    # Katmanlar tamamlanana kadar API'nin çökmemesi için geçici başarılı yanıt
    return PromptResponse(
        status="ALLOW",
        category="Safe",
        processed_text=processed_text,
        latency_ms=int((time.time() - start_time) * 1000)
    )