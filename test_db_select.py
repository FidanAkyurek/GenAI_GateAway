import asyncio
import os
import asyncpg

async def test():
    conn = await asyncpg.connect(
        user="postgres",
        password="Fa226021",
        database="genai_gateway",
        host="localhost",
        port=5432
    )
    # let's just see if get_users_by_company logic works.
    company_id = 1
    rows = await conn.fetch("SELECT id, username, email, role, full_name, created_at FROM users WHERE company_id = $1 ORDER BY role", company_id)
    print("Users for company 1:")
    for row in rows:
        print(dict(row))

    await conn.close()

if __name__ == "__main__":
    asyncio.run(test())
