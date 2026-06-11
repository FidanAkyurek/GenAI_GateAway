import re
from dataclasses import dataclass


@dataclass
class Layer1Result:
    """
    Layer1Regex.scan() metodunun dönüş tipi.
    Controller'dan regex_result.is_blocked şeklinde erişilebilir.
    """
    is_blocked: bool
    has_pii: bool
    processed_text: str
    detected_entities: list[str] = None


class Layer1Regex:
    """
    GenAI Security Gateway - Katman 1 (Refleks)
    Yasaklı kelimeleri tespit eder ve Hassas Verileri (PII) maskeler.
    Hedef: <5ms gecikme ile hızlı ön eleme.
    """

    # Yasaklı kelimeler (Blacklist) - Dashboard'dan dinamik olarak yönetilebilir
    from app.services.core_blacklist import CORE_BLACKLIST
    # Yasaklı kelimeler (Blacklist) - 1300+ kelimelik dışarıdan yüklenen çekirdek liste
    BLACKLIST = CORE_BLACKLIST

    # PII (Hassas Veri) Regex Desenleri
    # T.C. Kimlik No: 11 haneli, 0 ile başlamaz
    TC_PATTERN = re.compile(r'\b[1-9][0-9]{10}\b')
    # Kredi Kartı: 16 haneli (boşluklu veya tireli olabilir)
    CC_PATTERN = re.compile(r'\b(?:\d[ -]*?){13,16}\b')
    # E-posta Adresi
    EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
    # Telefon Numarası (Türkiye formatı)
    PHONE_PATTERN = re.compile(r'\b(?:\+90|0090|0)?[- ]?5\d{2}[- ]?\d{3}[- ]?\d{2}[- ]?\d{2}\b')
    # IBAN
    IBAN_PATTERN = re.compile(r'\bTR\d{2}[0-9A-Z]{22}\b', re.IGNORECASE)

    @classmethod
    def scan(cls, text: str, dynamic_blacklist: list = None) -> Layer1Result:
        """
        Metni yasaklı kelimeler ve PII açısından tarar.
        Dönüş: Layer1Result(is_blocked, has_pii, processed_text, detected_entities)
        """
        is_blocked = False
        has_pii = False
        processed_text = text
        detected_entities = []

        # 1. Blacklist (Yasaklı Kelime) Kontrolü
        text_lower = text.lower()
        # Kritik Güvenlik Yaması: Çekirdek liste ile Dashboard'dan gelen dinamik listeyi birleştir
        words_to_check = cls.BLACKLIST + (dynamic_blacklist if dynamic_blacklist is not None else [])
        
        for word in words_to_check:
            if word.lower() in text_lower:
                is_blocked = True
                # Fail-Fast: Yasaklı kelime → hemen engelle, maskelemeye gerek yok
                return Layer1Result(is_blocked=True, has_pii=False, processed_text=text, detected_entities=[f"Kara Liste: {word}"])

        # 2. PII Kontrolü ve Maskeleme (DLP - Data Loss Prevention)
        def mask_tc(match):
            tc = match.group(0)
            return f"{tc[:2]}*******{tc[-2:]}"  # Örn: 12*******34

        def mask_cc(match):
            cc = match.group(0)
            clean_cc = re.sub(r'[- ]', '', cc)
            return f"****-****-****-{clean_cc[-4:]}"

        def mask_email(match):
            email = match.group(0)
            parts = email.split('@')
            if len(parts[0]) > 2:
                return f"{parts[0][:2]}***@{parts[1]}"
            return f"***@{parts[1]}"

        def mask_phone(match):
            return "***-***-****"

        def mask_iban(match):
            iban = match.group(0)
            return f"{iban[:4]}****{iban[-4:]}"

        # Desenleri sırayla ara ve maskele
        if cls.TC_PATTERN.search(processed_text):
            has_pii = True
            processed_text = cls.TC_PATTERN.sub(mask_tc, processed_text)
            detected_entities.append("T.C. Kimlik No")

        if cls.CC_PATTERN.search(processed_text):
            has_pii = True
            processed_text = cls.CC_PATTERN.sub(mask_cc, processed_text)
            detected_entities.append("Kredi Kartı")

        if cls.EMAIL_PATTERN.search(processed_text):
            has_pii = True
            processed_text = cls.EMAIL_PATTERN.sub(mask_email, processed_text)
            detected_entities.append("E-posta Adresi")

        if cls.PHONE_PATTERN.search(processed_text):
            has_pii = True
            processed_text = cls.PHONE_PATTERN.sub(mask_phone, processed_text)
            detected_entities.append("Telefon Numarası")

        if cls.IBAN_PATTERN.search(processed_text):
            has_pii = True
            processed_text = cls.IBAN_PATTERN.sub(mask_iban, processed_text)
            detected_entities.append("IBAN")

        return Layer1Result(is_blocked=False, has_pii=has_pii, processed_text=processed_text, detected_entities=detected_entities)