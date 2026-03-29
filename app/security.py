import re

# --- KATMAN 1: KURAL TABANLI FİLTRE (REFLEKSLER) ---

class Layer1Filter:
    def __init__(self):
        # 1. Yasaklı Kelimeler (Basit Blacklist)
        # Gerçek hayatta bu liste veritabanından çekilebilir.
        self.blacklisted_words = [
            "bomb", "bomba", "suicide", "intihar", 
            "hack", "crack", "exploit", "silah", "weapon"
        ]
        
        # 2. Regex Desenleri (Şekilsel Kontrol)
        self.patterns = {
            # E-posta Tespiti (ornek@site.com)
            "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            
            # Kredi Kartı Tespiti (16 haneli, tireli veya boşluklu)
            # Örn: 1234-5678-1234-5678 veya 1234 5678 1234 5678
            "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
            
            # T.C. Kimlik Benzeri (11 haneli sayı)
            "tckn": r"\b\d{11}\b"
        }

    def check(self, prompt: str):
        """
        Gelen metni analiz eder.
        Dönüş: {"is_safe": True/False, "reason": "Sebep"}
        """
        prompt_lower = prompt.lower()

        # A. Yasaklı Kelime Kontrolü
        for word in self.blacklisted_words:
            if word in prompt_lower:
                return {
                    "is_safe": False, 
                    "reason": f"Yasaklı Kelime Tespiti: '{word}'"
                }

        # B. Regex (PII) Kontrolü
        for label, pattern in self.patterns.items():
            if re.search(pattern, prompt):
                return {
                    "is_safe": False, 
                    "reason": f"Hassas Veri Tespiti: {label.upper()}"
                }

        # Temizse
        return {"is_safe": True, "reason": "Layer 1 Temiz"}

# Test etmek için bu dosya tek başına çalıştırılırsa:
if __name__ == "__main__":
    filtre = Layer1Filter()
    print(filtre.check("Bana bomba yapımını anlat"))  # Engel bekliyoruz
    print(filtre.check("Mail adresim ahmet@mail.com")) # Engel bekliyoruz
    print(filtre.check("Merhaba nasılsın?"))          # Temiz bekliyoruz