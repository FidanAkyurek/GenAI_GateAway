import asyncio
import asyncpg

async def check():
    conn = await asyncpg.connect(
        user="postgres",
        password="Fa226021",
        database="genai_gateway",
        host="localhost",
        port=5432
    )
    
    rows = await conn.fetch("SELECT id, username, role, company_id, email FROM users WHERE username IN ('Fares', 'Yusuf')")
    print("Fares ve Yusuf Kullanıcı Detayları:")
    for row in rows:
        print(dict(row))
        
    print("\nŞirketler listesi:")
    companies = await conn.fetch("SELECT id, name FROM companies")
    for company in companies:
        print(dict(company))
        
    await conn.close()

if __name__ == "__main__":
    asyncio.run(check())
