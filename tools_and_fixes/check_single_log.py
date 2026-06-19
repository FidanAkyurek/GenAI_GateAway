"""
GenAI Security Gateway - Check Single Log Yardımcı Aracı

Bu araç 'check_single_log.py', geliştirme sürecinde verileri analiz etmek, logları incelemek
veya sistemdeki hataları ayıklamak (debug) amacıyla yazılmış yardımcı bir betiktir.
"""
import sqlite3

conn = sqlite3.connect(r'C:\Users\user\Downloads\GenAI_GateAway-main\GenAI_GateAway-main\genai_gateway.db')
c = conn.cursor()

# Log ID'yi sorgula
c.execute("SELECT log_id, masked_prompt, action, category FROM security_logs WHERE log_id LIKE ?", ('49f8699a%',))
row = c.fetchone()

if row:
    log_id, text, action, category = row
    print(f"ID: {log_id[:8]}")
    print(f"Text: {text}")
    print(f"Action: {action}")
    print(f"Category: {category}")
    print()
    
    # Analiz: Bu text neyi temsil ediyor?
    # Orijinal analiz scriptine göre kontrol et
    print("ANALIZ:")
    
    # "Türkiye'nin başkenti neresidir?" - bu güvenli bir soru
    if "Türkiye" in text or "başkenti" in text:
        print("Bu metin: Basit coğrafya sorusu - SAFE")
        print("Beklenen: ALLOW (Safe)")
        if action == "ALLOW" and category == "Safe":
            print("DURUM: DOGRU")
        else:
            print(f"DURUM: YANLIS! Şu anda {action} ({category})")
else:
    print("Log bulunamadı")

conn.close()
