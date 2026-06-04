import asyncio
from dotenv import load_dotenv
load_dotenv()
from app.services.database_manager import DatabaseManager

async def test():
    await DatabaseManager.initialize()
    users = await DatabaseManager.get_users_by_company(1)
    stats = await DatabaseManager.get_stats(1)
    print("Users for company 1:")
    print(users)
    print("Stats for company 1:")
    print(stats)
    
    users = await DatabaseManager.get_users_by_company(3) # Let's assume baykar is 3
    print("Users for company 3:")
    print(users)

    await DatabaseManager.close()

if __name__ == "__main__":
    asyncio.run(test())
