import asyncio
import asyncpg

async def read_logs():
    conn = await asyncpg.connect(
        user="postgres",
        password="Fa226021",
        database="genai_gateway",
        host="localhost",
        port=5432
    )
    rows = await conn.fetch("SELECT log_id, user_id, company_id, action, category, masked_prompt FROM security_logs ORDER BY created_at DESC LIMIT 15")
    print("Son 15 Güvenlik Logu ve Şirket ID'leri:")
    for row in rows:
        print(f"User: {row['user_id']} | CompanyID: {row['company_id']} | Action: {row['action']} | Category: {row['category']} | Prompt: {row['masked_prompt']}")
    await conn.close()

if __name__ == "__main__":
    asyncio.run(read_logs())
