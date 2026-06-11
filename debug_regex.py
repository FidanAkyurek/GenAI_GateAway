import re

text = "Türkiye'nin başkenti neresidir?"

# Test all patterns
injection_patterns = [
    r'\b(ignore|bypass|disable|pretend|act\s+as|override|without\s+restriction)\b',
    r'\b(DAN|Unrestricted|without\s+ethical|safety\s+guideline)\b',
]

sql_patterns = [
    r'(DROP|DELETE|INSERT|UPDATE|SELECT).*TABLE',
    r"('|\"|;|--|\*)",
    r'(WHERE\s+1\s*=\s*1)',
]

pii_patterns = [
    r'\d{11}',  # TC kimlik
    r'\d{4}[\-\s]?\d{4}[\-\s]?\d{4}[\-\s]?\d{4}',  # Kredi kartı
    r'TR\d{2}\d{5}.*\d{13}',  # IBAN
    r'\*+',  # Maskelenmiş veriler
    r'@.*\.com',  # Email
    r'sk-proj-',  # API Key
]

blacklist_words = [
    'bomba', 'intihar', 'hack', 'sql_injection', 'bypass',
    'ölüm', 'saldırı', 'uyuşturucu', 'malware', 'ransomware', 'keylogger',
    'hacking', 'atm', 'antivirus', 'exploit', 'dan'
]

print(f"Text: {text}\n")

# Check each pattern type
print("PII kontrol:")
for pattern in pii_patterns:
    if re.search(pattern, text, re.IGNORECASE):
        print(f"  MATCH: {pattern}")
        match = re.search(pattern, text, re.IGNORECASE)
        print(f"  Matched: '{match.group()}'")

print("\nSQL Injection kontrol:")
for pattern in sql_patterns:
    if re.search(pattern, text, re.IGNORECASE):
        print(f"  MATCH: {pattern}")
        match = re.search(pattern, text, re.IGNORECASE)
        print(f"  Matched: '{match.group()}'")

print("\nBlacklist kontrol:")
text_lower = text.lower()
for word in blacklist_words:
    if word.lower() in text_lower:
        print(f"  MATCH: {word}")

print("\nInjection/Jailbreak kontrol:")
for pattern in injection_patterns:
    match = re.search(pattern, text, re.IGNORECASE)
    if match:
        print(f"  MATCH: {pattern}")
        print(f"  Matched: '{match.group()}'")
    else:
        print(f"  NO MATCH: {pattern}")

print("\n" + "="*50)
print("SONUÇ: Bu text Safe'dir (Injection degil)")
