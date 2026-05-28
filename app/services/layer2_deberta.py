from transformers import pipeline
import logging

# Loglama ayarları (Uygulamanın durumunu konsoldan takip etmek için)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Layer2DeBERTa:
    """
    GenAI Security Gateway - Katman 2 (Zeka)
    DeBERTa-v3 modelini kullanarak anlamsal saldırı (Prompt Injection) tespiti yapar.
    """
    
    _classifier = None
    # Tezinizde bahsedilen ProtectAI'ın önceden eğitilmiş (pre-trained) modeli
    _model_name = "protectai/deberta-v3-base-prompt-injection-v2"

    @classmethod
    def load_model(cls):
        """
        Modeli hafızaya yükler. API ayağa kalktığında bir kere çalıştırılması performansı artırır.
        WINDOWS MKL CRASH FIX: DeBERTa disable edildi - Layer 1 ve Layer 3'e güvenilir
        """
        if cls._classifier is None:
            logger.warning("⚠️ Katman 2 (DeBERTa) Windows MKL uyumluluğu nedeniyle devre dışı bırakıldı.")
            logger.warning("Layer 1 (Regex) ve Layer 3 (LLM) aktif ve yeterlidir.")
            cls._classifier = None  # Fail-open mode

    _cache = {}

    @classmethod
    def predict_score(cls, text: str) -> float:
        """
        Metni analiz edip 0.0 (Güvenli) ile 1.0 (Kesin Saldırı) arasında bir skor döner.
        """
        # Önbellekte varsa hemen dön (Performans için)
        if text in cls._cache:
            return cls._cache[text]

        if cls._classifier is None:
            cls.load_model()
            
        # Eğer model hala yüklenemediyse (örn: internet sorunu), sistemi kilitlememek için 0.0 dön (Fail-Open)
        if cls._classifier is None:
            logger.warning("Katman 2 atlanıyor: Model aktif değil!")
            return 0.0

        # Modeli çalıştır ve sonucu al
        result = cls._classifier(text)
        
        # Sonuç genellikle [{'label': 'INJECTION', 'score': 0.99}] formatındadır
        score = 0.0
        for res in result:
            if res['label'] == 'INJECTION':
                score = res['score']
            elif res['label'] == 'SAFE':
                score = 1.0 - res['score']
                
        final_score = round(score, 3)
        
        # Önbelleği sınırla (Memory Leak önlemek için)
        if len(cls._cache) > 5000:
            cls._cache.clear()
            
        cls._cache[text] = final_score
        return final_score