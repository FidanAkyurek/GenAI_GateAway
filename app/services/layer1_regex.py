import re
from typing import Tuple

class Layer1Regex:
    """
    GenAI Security Gateway - Katman 1 (Refleks)
    Yasaklı kelimeleri tespit eder ve Hassas Verileri (PII) maskeler.
    """
    
    # Yasaklı kelimeler (Blacklist) - İleride veritabanından veya panelden çekilecek şekilde güncellenebilir
    BLACKLIST = ["bomba", "intihar", "hack", "sql_injection", "bypass", "malware", "keylogger"]

    # PII (Hassas Veri) Regex Desenleri
    # T.C. Kimlik No: 11 haneli sayı
    TC_PATTERN = re.compile(r'\b[1-9][0-9]{10}\b')
    # Kredi Kartı: 16 haneli (boşluklu veya tireli olabilir)
    CC_PATTERN = re.compile(r'\b(?:\d[ -]*?){13,16}\b')
    # E-posta Adresi
    EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')

    @classmethod
    def scan(cls, text: str) -> Tuple[bool, bool, str]:
        """
        Metni yasaklı kelimeler ve PII açısından tarar.
        Dönüş formatı: (is_blocked, has_pii, processed_text)
        """
        is_blocked = False
        has_pii = False
        processed_text = text

        # 1. Blacklist (Yasaklı Kelime) Kontrolü
        text_lower = text.lower()
        for word in cls.BLACKLIST:
            if word in text_lower:
                is_blocked = True
                # Fail-Fast: Yasaklı kelime bulunduysa maskeleme yapmaya gerek yok, doğrudan engelle
                return is_blocked, has_pii, processed_text

        # 2. PII Kontrolü ve Maskeleme (DLP - Data Loss Prevention)
        if not is_blocked:
            # Maskeleme Yardımcı Fonksiyonları
            def mask_tc(match):
                tc = match.group(0)
                return f"{tc[:2]}*******{tc[-2:]}" # Örn: 11*******22

            def mask_cc(match):
                cc = match.group(0)
                # Sadece son 4 hane kalsın
                clean_cc = re.sub(r'[- ]', '', cc)
                return f"****-****-****-{clean_cc[-4:]}"

            def mask_email(match):
                email = match.group(0)
                parts = email.split('@')
                if len(parts[0]) > 2:
                    return f"{parts[0][:2]}***@{parts[1]}"
                return f"***@{parts[1]}"

            # Desenleri metin üzerinde ara ve maskele
            if cls.TC_PATTERN.search(processed_text):
                has_pii = True
                processed_text = cls.TC_PATTERN.sub(mask_tc, processed_text)

            if cls.CC_PATTERN.search(processed_text):
                has_pii = True
                processed_text = cls.CC_PATTERN.sub(mask_cc, processed_text)
                
            if cls.EMAIL_PATTERN.search(processed_text):
                has_pii = True
                processed_text = cls.EMAIL_PATTERN.sub(mask_email, processed_text)

        return is_blocked, has_pii, processed_text