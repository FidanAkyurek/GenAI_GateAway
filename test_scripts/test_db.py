"""
GenAI Security Gateway - Test Db Test Betiği

Bu test dosyası 'test_db.py', sistemin belirli bir bileşenini test etmek amacıyla oluşturulmuştur.
Genel amacı ilgili uç noktaların (endpoint) veya fonksiyonların doğru çalışıp çalışmadığını doğrulamaktır.
"""
import asyncio
from app.services.database_manager import DatabaseManager

async def test():
    print(await DatabaseManager.get_user_by_username('super_admin_fidan'))

if __name__ == "__main__":
    asyncio.run(test())
