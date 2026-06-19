"""
GenAI Security Gateway - Check Logs Yardımcı Aracı

Bu araç 'check_logs.py', geliştirme sürecinde verileri analiz etmek, logları incelemek
veya sistemdeki hataları ayıklamak (debug) amacıyla yazılmış yardımcı bir betiktir.
"""
import sqlite3

conn = sqlite3.connect(r'c:\Users\user\Downloads\GenAI_GateAway-main\GenAI_GateAway-main\genai_gateway.db')
c = conn.cursor()

print("=== LOGLAR NEDİR? ===\n")

# Tüm loglar özeti
c.execute("SELECT COUNT(*), action FROM security_logs GROUP BY action")
print("Toplam istatistikler:")
for row in c.fetchall():
    print(f"  {row[1]}: {row[0]}")

print("\n=== BLOKLANAN LOGLAR (NEDEN BLOKLANDI?) ===\n")

# Bloklanan loglar - kategori göre
c.execute("SELECT action, category, COUNT(*) FROM security_logs GROUP BY action, category")
for row in c.fetchall():
    print(f"  {row[0]:5s} | {row[1]:15s} | {row[2]} log")

print("\n=== BLOKLANAN LOGLAR ÖRNEKLERİ ===\n")

# Bloklanan 10 log - neden bloklı olduğunu göster
c.execute("""
    SELECT log_id, masked_prompt, category, stopped_at_layer 
    FROM security_logs 
    WHERE action = 'BLOCK' 
    LIMIT 10
""")

for row in c.fetchall():
    text = row[1][:50] if row[1] else "N/A"
    print(f"ID: {row[0][:8]} | Text: {text}")
    print(f"  → Kategori: {row[2]} (Durdu: {row[3]})\n")

conn.close()
