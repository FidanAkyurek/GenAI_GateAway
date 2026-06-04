import os
import logging
from google import genai
from google.genai import types

logger = logging.getLogger(__name__)

class LLMProxy:
    """
    GenAI Security Gateway - LLM Yönlendirici Servisi (Gemini Altyapısı)
    Güvenli (ALLOW) olan istekleri Gemini'ye iletir ve cevabı alır.
    """
    _client = None

    @classmethod
    def get_client(cls):
        if cls._client is None:
            api_key = os.getenv("GEMINI_API_KEY")
            if not api_key:
                logger.error("GEMINI_API_KEY bulunamadı!")
                return None
            cls._client = genai.Client(api_key=api_key)
        return cls._client

    @classmethod
    async def generate_response(cls, prompt: str, history: list = None) -> str:
        """
        Kullanıcıdan gelen güvenli isteği ve sohbet geçmişini Gemini'ye yollar ve cevabını asenkron döner.
        """
        client = cls.get_client()
        if not client:
            return "Sistem Hatası: GEMINI_API_KEY yapılandırılmamış. Lütfen .env dosyasını kontrol edin."

        try:
            logger.info("🤖 İstek yapay zekaya (Gemini) yönlendiriliyor...")
            
            contents = []
            if history:
                for msg in history:
                    role = "user" if msg.get("role") == "user" else "model"
                    contents.append(types.Content(role=role, parts=[types.Part.from_text(text=msg.get("content", ""))]))
            
            contents.append(types.Content(role="user", parts=[types.Part.from_text(text=prompt)]))
            
            response = await client.aio.models.generate_content(
                model='gemini-flash-latest',
                contents=contents
            )
            
            llm_text = response.text.strip() if response.text else "Yapay zeka boş bir yanıt döndü."
            logger.info("✅ Yapay zekadan (Gemini) cevap başarıyla alındı.")
            return llm_text
            
        except Exception as e:
            logger.error(f"❌ LLM Proxy (Gemini) Hatası: {e}")
            error_msg = str(e)
            if "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg:
                return "⏱️ **Hız Sınırı Aşıldı (Rate Limit):** Google Gemini API'sine çok sık veya art arda istek attınız. Lütfen yaklaşık 1 dakika bekleyip sorunuzu tekrar gönderin."
            return f"Yapay zekaya erişirken bir hata oluştu: {error_msg}"
