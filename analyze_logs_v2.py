import sqlite3
import json
import re

conn = sqlite3.connect(r'C:\Users\user\Downloads\GenAI_GateAway-main\GenAI_GateAway-main\genai_gateway.db')
c = conn.cursor()

# Tüm logları oku
c.execute("SELECT log_id, masked_prompt, action, category, stopped_at_layer FROM security_logs ORDER BY created_at")
logs = c.fetchall()

print(f"TOPLAM LOG SAYISI: {len(logs)}\n")

# PII desenleri
pii_patterns = [
    r'\d{11}',  # TC kimlik
    r'\d{4}[\-\s]?\d{4}[\-\s]?\d{4}[\-\s]?\d{4}',  # Kredi kartı
    r'TR\d{2}\d{5}.*\d{13}',  # IBAN
    r'\*+',  # Maskelenmiş veriler
    r'@.*\.com',  # Email
    r'sk-proj-',  # API Key
]

# Zararlı kelimeler (Blacklist)
blacklist_words = [
    'bomba', 'intihar', 'hack', 'sql_injection', 'bypass',
    'ölüm', 'saldırı', 'uyuşturucu', 'malware', 'ransomware', 'keylogger',
    'hacking', 'atm', 'antivirus', 'exploit', 'dan'
]

# Jailbreak/Injection desenleri - WORD BOUNDARIES ile
injection_patterns = [
    r'\b(ignore|bypass|disable|pretend|act\s+as|override|without\s+restriction)\b',
    r'\b(DAN|Unrestricted|without\s+ethical|safety\s+guideline)\b',
]

# SQL Injection desenleri
sql_patterns = [
    r'\b(DROP|DELETE|INSERT|UPDATE|SELECT)\b.*\bTABLE\b',
    r'(;|--)',  # Sadece SQL-spesifik karakterler (noktalı virgül ve comment)
    r'\b(WHERE\s+1\s*=\s*1)\b',
]

def categorize_log(text):
    text_lower = text.lower() if text else ""
    
    # 1. PII kontrol
    for pattern in pii_patterns:
        if re.search(pattern, text or "", re.IGNORECASE):
            return "PII"
    
    # 2. SQL Injection kontrol
    for pattern in sql_patterns:
        if re.search(pattern, text or "", re.IGNORECASE):
            return "Injection"
    
    # 3. Blacklist kelimeler
    for word in blacklist_words:
        if word.lower() in text_lower:
            return "Blacklist"
    
    # 4. Jailbreak/Injection - FIXED
    for pattern in injection_patterns:
        if re.search(pattern, text or "", re.IGNORECASE):
            return "Injection"
    
    # 5. Güvenli
    return "Safe"

def should_block(category):
    return category in ["Blacklist", "PII", "Injection"]

# Analiz
errors = []
for log_id, text, action, category, layer in logs:
    correct_category = categorize_log(text)
    expected_action = "BLOCK" if should_block(correct_category) else "ALLOW"
    
    if category != correct_category or action != expected_action:
        errors.append({
            'log_id': log_id,
            'text': text[:60],
            'current_category': category,
            'correct_category': correct_category,
            'current_action': action,
            'correct_action': expected_action,
        })

print(f"Yanlis siniflandirilmis loglar: {len(errors)}")

if errors:
    print("\nILK 10 HATA:\n")
    for err in errors[:10]:
        print(f"ID: {err['log_id'][:8]}")
        print(f"Text: {err['text']}")
        print(f"Yanlis: {err['current_action']} ({err['current_category']}) -> Dogru: {err['correct_action']} ({err['correct_category']})")
        print()
    
    # JSON'a kaydet
    with open(r'C:\Users\user\Downloads\GenAI_GateAway-main\GenAI_GateAway-main\corrections_needed.json', 'w') as f:
        json.dump(errors, f, indent=2)
    
    print(f"Toplam {len(errors)} hata corrections_needed.json'a kaydedildi")
else:
    print("Tum loglar dogru!")

conn.close()
