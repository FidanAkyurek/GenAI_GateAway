"""
GenAI Security Gateway - Test Pg Test Betiği

Bu test dosyası 'test_pg.py', sistemin belirli bir bileşenini test etmek amacıyla oluşturulmuştur.
Genel amacı ilgili uç noktaların (endpoint) veya fonksiyonların doğru çalışıp çalışmadığını doğrulamaktır.
"""
import asyncio
import asyncpg
import os

async def test_pg():
    try:
        conn = await asyncpg.connect(
            user="postgres",
            password="Fa226021",
            database="postgres",
            host="localhost",
            port=5432
        )
        print("Connected to PostgreSQL successfully!")
        
        # Create database if it doesn't exist
        try:
            await conn.execute("CREATE DATABASE genai_gateway")
            print("Database genai_gateway created!")
        except Exception as e:
            print(f"DB might already exist: {e}")
            
        await conn.close()
    except Exception as e:
        print(f"Failed to connect to PostgreSQL: {e}")

if __name__ == "__main__":
    asyncio.run(test_pg())
