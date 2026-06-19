"""
GenAI Security Gateway - Fix Specific Log Yardımcı Aracı

Bu araç 'fix_specific_log.py', geliştirme sürecinde verileri analiz etmek, logları incelemek
veya sistemdeki hataları ayıklamak (debug) amacıyla yazılmış yardımcı bir betiktir.
"""
import sqlite3

conn = sqlite3.connect('genai_gateway.db')
c = conn.cursor()

# fix_logs.py'nin korepsiyondan sonraki durumu sorgulayal
c.execute("SELECT log_id, masked_prompt, action, category FROM security_logs WHERE action='BLOCK' AND category='Injection' LIMIT 20")
results = c.fetchall()

print(f"Toplam Injection olarak blok edilen (ilk 20):")
for log_id, text, action, cat in results[:5]:
    print(f"\n{log_id[:8]}: {text}")
    
# Şimdi 49f8699a'yı doğrudan güncelleyelim
print("\n\n=== SPESIFIK LOG 49f8699a GÜNCELLEMESİ ===")

c.execute("UPDATE security_logs SET action='ALLOW', category='Safe' WHERE log_id LIKE '%49f8699a%'")
conn.commit()

c.execute("SELECT action, category FROM security_logs WHERE log_id LIKE '%49f8699a%'")
updated = c.fetchone()
if updated:
    print(f"✓ Güncellendi: Action={updated[0]}, Category={updated[1]}")

conn.close()
