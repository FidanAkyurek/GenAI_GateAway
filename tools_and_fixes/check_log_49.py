"""
GenAI Security Gateway - Check Log 49 Yardımcı Aracı

Bu araç 'check_log_49.py', geliştirme sürecinde verileri analiz etmek, logları incelemek
veya sistemdeki hataları ayıklamak (debug) amacıyla yazılmış yardımcı bir betiktir.
"""
import sqlite3

conn = sqlite3.connect('genai_gateway.db')
c = conn.cursor()

c.execute("SELECT log_id, masked_prompt, action, category FROM security_logs WHERE log_id LIKE '%49f8699a%'")
row = c.fetchone()

if row:
    log_id, text, action, category = row
    print(f"ID: {log_id}")
    print(f"Text: {text}")
    print(f"Action: {action}")
    print(f"Category: {category}")
    
    if action == "ALLOW" and category == "Safe":
        print("\n✓ DOGRU SINIFLANDIRILDI!")
    else:
        print(f"\n✗ YANLIS! Olmasi gereken: ALLOW (Safe)")
else:
    print("Log bulunamadi")

conn.close()
