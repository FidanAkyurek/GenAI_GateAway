import asyncio
from dotenv import load_dotenv
load_dotenv()

from app.services.database_manager import DatabaseManager
from app.controllers.auth_controller import get_password_hash

async def test():
    await DatabaseManager.initialize()
    pwd = get_password_hash("testpwd")
    success = await DatabaseManager.create_user(
        username="test_ömer",
        password_hash=pwd,
        email="test_ömer",
        role="company_admin",
        company_id=1
    )
    if not success:
        print("FAILED to create user")

if __name__ == "__main__":
    asyncio.run(test())
