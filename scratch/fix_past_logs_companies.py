import asyncio
import asyncpg

async def fix():
    conn = await asyncpg.connect(
        user="postgres",
        password="Fa226021",
        database="genai_gateway",
        host="localhost",
        port=5432
    )
    
    # company_id NULL olan logları çek
    rows = await conn.fetch("SELECT DISTINCT user_id FROM security_logs WHERE company_id IS NULL")
    print("Düzeltilecek kullanıcı logları:", [r['user_id'] for r in rows])
    
    updated_count = 0
    for row in rows:
        user_id = row['user_id']
        # kullanıcının company_id'sini bul
        user_row = await conn.fetchrow("SELECT company_id FROM users WHERE username = $1", user_id)
        if user_row and user_row['company_id']:
            company_id = user_row['company_id']
            # update et
            res = await conn.execute("UPDATE security_logs SET company_id = $1 WHERE user_id = $2 AND company_id IS NULL", company_id, user_id)
            print(f"User '{user_id}' için loglar company_id={company_id} olarak güncellendi. Sonuç: {res}")
            updated_count += 1
            
    await conn.close()
    print(f"Toplam {updated_count} kullanıcının geçmiş logları düzeltildi.")

if __name__ == "__main__":
    asyncio.run(fix())
