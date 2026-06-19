"""
GenAI Security Gateway - Analyze Logs Yardımcı Aracı

Bu araç 'analyze_logs.py', geliştirme sürecinde verileri analiz etmek, logları incelemek
veya sistemdeki hataları ayıklamak (debug) amacıyla yazılmış yardımcı bir betiktir.
"""
import sqlite3
import re

conn = sqlite3.connect(r'C:\Users\user\Downloads\GenAI_GateAway-main\GenAI_GateAway-main\genai_gateway.db')
c = conn.cursor()

# Tüm logları oku
c.execute("SELECT log_id, masked_prompt, action, category, stopped_at_layer FROM security_logs ORDER BY created_at")
logs = c.fetchall()

print(f"TOPLAM LOG SAYISI: {len(logs)}\n")

# Analiz kategorileri
correct_logs = []
incorrect_logs = []

# PII desenleri (Kişisel Bilgiler)
pii_patterns = [
    r'\d{11}',  # TC kimlik (11 digit)
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

# Jailbreak/Injection desenleri (word boundaries ile)
injection_patterns = [
    r'\b(ignore|bypass|disable|pretend|act\s+as|override|without\s+restriction)\b',
    r'\b(DAN|Unrestricted|without\s+ethical|safety\s+guideline)\b',
]

# SQL Injection desenleri
sql_patterns = [
    r'(DROP|DELETE|INSERT|UPDATE|SELECT).*TABLE',
    r"('|\"|;|--|\*)",
    r'(WHERE\s+1\s*=\s*1)',
]

def categorize_log(text):
    """Logu otomatik olarak doğru kategorize et"""
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
    
    # 4. Jailbreak/Injection
    for pattern in injection_patterns:
        if re.search(pattern, text or "", re.IGNORECASE):
            return "Injection"
    
    # 5. Güvenli
    return "Safe"

def should_block(category):
    """Kategori bazında bloklanması gerekip gerekmediğini kontrol et"""
    return category in ["Blacklist", "PII", "Injection"]

print("\n" + "=" * 100)
print("LOG ANALIZI VE DOGRULAMA")
print("=" * 100)

errors_found = 0
corrections = []

for idx, (log_id, text, action, category, stopped_layer) in enumerate(logs, 1):
    # Her logu otomatik kategorize et
    correct_category = categorize_log(text)
    should_be_blocked = should_block(correct_category)
    
    # Beklenen action (BLOCK/ALLOW)
    expected_action = "BLOCK" if should_be_blocked else "ALLOW"
    
    # Hata kontrol
    is_correct = (category == correct_category and action == expected_action)
    
    if not is_correct:
        errors_found += 1
        error_info = {
            'log_id': log_id,
            'text': text[:60],
            'current_category': category,
            'correct_category': correct_category,
            'current_action': action,
            'correct_action': expected_action,
        }
        corrections.append(error_info)
        
        print(f"\nHATA #{errors_found} (Log #{idx})")
        print(f"   ID: {log_id}")
        print(f"   Text: {text[:70]}")
        print(f"   Su anda: {action} | {category}")
        print(f"   Olmasi gereken: {expected_action} | {correct_category}")
    else:
        correct_logs.append(log_id)

print("\n" + "=" * 100)
print("OZETI")
print("=" * 100)
print(f"Dogru siniflandirilmis loglar: {len(correct_logs)}")
print(f"Yanlis siniflandirilmis loglar: {errors_found}")
print(f"Dogruluk orani: {len(correct_logs)/len(logs)*100:.1f}%")

print("\n" + "=" * 100)
print("DUZELTILEBSI GEREKEN LOGLAR")
print("=" * 100)

for corr in corrections[:20]:  # İlk 20 hatayı göster
    print(f"\nID: {corr['log_id'][:8]}")
    print(f"Text: {corr['text']}")
    print(f"Yanlış: {corr['current_action']} ({corr['current_category']}) → Doğru: {corr['correct_action']} ({corr['correct_category']})")

if errors_found > 20:
    print(f"\n... ve {errors_found - 20} hata daha")

# Tüm hatayı JSON olarak kaydet (veritabanı güncellemesi için)
import json
with open(r'C:\Users\user\Downloads\GenAI_GateAway-main\GenAI_GateAway-main\corrections_needed.json', 'w', encoding='utf-8') as f:
    json.dump(corrections, f, indent=2, ensure_ascii=False)

print(f"\nHatalar 'corrections_needed.json' dosyasina kaydedildi")

conn.close()
