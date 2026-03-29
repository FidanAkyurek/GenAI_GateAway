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
        """
        if cls._classifier is None:
            try:
                logger.info(f"Yapay Zeka Modeli Yükleniyor: {cls._model_name}...")
                # truncation=True ve max_length=512 ile donanım optimizasyonu sağlanır
                cls._classifier = pipeline(
                    "text-classification", 
                    model=cls._model_name, 
                    truncation=True, 
                    max_length=512
                )
                logger.info("Katman 2 (DeBERTa) Modeli başarıyla yüklendi.")
            except Exception as e:
                logger.error(f"Model yüklenirken hata oluştu: {e}")
                cls._classifier = None

    @classmethod
    def predict_score(cls, text: str) -> float:
        """
        Metni analiz edip 0.0 (Güvenli) ile 1.0 (Kesin Saldırı) arasında bir skor döner.
        """
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
                
        return round(score, 3)