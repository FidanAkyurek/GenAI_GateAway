import asyncio
from app.services.database_manager import DatabaseManager

async def test():
    print(await DatabaseManager.get_user_by_username('super_admin_fidan'))

if __name__ == "__main__":
    asyncio.run(test())
