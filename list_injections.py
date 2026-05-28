import sqlite3

conn = sqlite3.connect('genai_gateway.db')
c = conn.cursor()

# Tüm Injection olarak kategorize edilen logları listele
c.execute("SELECT log_id, masked_prompt, action, category FROM security_logs WHERE category='Injection' LIMIT 20")
rows = c.fetchall()

print(f"Veritabanında Injection olarak flaglanmış loglar:\n")
for log_id, text, action, cat in rows:
    print(f"ID: {log_id[:8]}")
    print(f"Text: {text[:70]}")
    print(f"DB Status: {action} ({cat})\n")

conn.close()
