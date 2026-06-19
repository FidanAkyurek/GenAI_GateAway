"""
GenAI Security Gateway - Apply Fixes Yardımcı Aracı

Bu araç 'apply_fixes.py', geliştirme sürecinde verileri analiz etmek, logları incelemek
veya sistemdeki hataları ayıklamak (debug) amacıyla yazılmış yardımcı bir betiktir.
"""
import sqlite3
import json

conn = sqlite3.connect('genai_gateway.db')
c = conn.cursor()

# corrections_needed.json'ı oku
try:
    with open('corrections_needed.json', 'r') as f:
        corrections = json.load(f)
    print(f"Toplam {len(corrections)} hata bulundu. Düzeltiliyor...\n")
    
    for correction in corrections:
        log_id = correction['log_id']
        correct_action = correction['correct_action']
        correct_category = correction['correct_category']
        
        c.execute(
            "UPDATE security_logs SET action=?, category=? WHERE log_id=?",
            (correct_action, correct_category, log_id)
        )
    
    conn.commit()
    print(f"✓ Tüm {len(corrections)} log güncellendi!")
    print("\nVerifikasyon tamamlandi.")
    
except Exception as e:
    print(f"Hata: {e}")
    conn.rollback()

conn.close()
