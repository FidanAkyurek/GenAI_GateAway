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
    rows = await conn.fetch("SELECT log_id, user_id, masked_prompt, action, category, stopped_at_layer, ai_confidence_score, latency_ms, company_id, created_at FROM security_logs ORDER BY created_at DESC LIMIT 20")
    print("Son 20 Güvenlik Logu:")
    for row in rows:
        print(f"[{row['created_at']}] User: {row['user_id']} | Action: {row['action']} | Category: {row['category']} | Layer: {row['stopped_at_layer']} | Score: {row['ai_confidence_score']} | Prompt: {row['masked_prompt']}")
    await conn.close()

if __name__ == "__main__":
    asyncio.run(read_logs())
