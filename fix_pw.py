import sqlite3
conn = sqlite3.connect('genai_gateway.db')
conn.execute("UPDATE users SET password_hash = '$2b$12$P3p11jHbxMkXCgSYbZu5UOPUTT5JyD56Kw7O2T4fFV4Vftswxxacq' WHERE username = 'super_admin_fidan'")
conn.commit()
conn.close()
