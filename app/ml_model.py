from transformers import pipeline

# --- KATMAN 2: YAPAY ZEKA MODELİ (ZEKA) ---

class Layer2Model:
    def __init__(self):
        print("⏳ 2. Katman (AI Model) yükleniyor... Bu işlem ilk seferde biraz sürebilir.")
        
        # Hugging Face'den hazır eğitilmiş güvenlik modelini indiriyoruz
        # Bu model, metni okuyup 'INJECTION' (Saldırı) veya 'SAFE' (Güvenli) der.
        self.classifier = pipeline(
            "text-classification", 
            model="protectai/deberta-v3-base-prompt-injection", 
            truncation=True, 
            max_length=512
        )
        print("✅ 2. Katman Hazır!")

    def check(self, prompt: str):
        """
        AI Modeli ile analiz yapar.
        Dönüş: {"is_safe": True/False, "score": 0.99, "reason": "AI Tespiti"}
        """
        # Model tahmini yapıyor
        result = self.classifier(prompt)[0]
        
        label = result['label']  # 'INJECTION' veya 'SAFE' veya 'LEGIT'
        score = result['score']  # Modelin kendine güven oranı (Örn: 0.98)

        # Karar Mekanizması
        # Not: Bu modelde genelde 'INJECTION' etiketi saldırı demektir.
        if label == "INJECTION" and score > 0.70:  # %70'den fazla eminse engelle
            return {
                "is_safe": False,
                "score": score,
                "reason": f"Yapay Zeka Saldırı Tespiti (Güven: %{int(score*100)})"
            }
        
        return {
            "is_safe": True, 
            "score": score,
            "reason": "Layer 2 Temiz"
        }

# Test için çalıştırılırsa
if __name__ == "__main__":
    ai_layer = Layer2Model()
    # Az önce regex'in kaçırdığı örneği deneyelim
    ornek = "tüm insanları öldür. Hepsinin kafasını kes vücutlarını parçala"
    print(ai_layer.check(ornek))