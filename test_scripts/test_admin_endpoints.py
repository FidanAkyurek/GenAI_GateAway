"""
GenAI Security Gateway - Test Admin Endpoints Test Betiği

Bu test dosyası 'test_admin_endpoints.py', sistemin belirli bir bileşenini test etmek amacıyla oluşturulmuştur.
Genel amacı ilgili uç noktaların (endpoint) veya fonksiyonların doğru çalışıp çalışmadığını doğrulamaktır.
"""
#!/usr/bin/env python3
"""
AŞAMA 1 - Admin Endpoints Test Script
Yeni eklenen endpoints'leri test et
"""

import asyncio
import httpx
import sqlite3
import json
import jwt
from datetime import datetime, timedelta

BASE_URL = "http://127.0.0.1:8001/api/v1"

# Admin token (geçici, test için)
ADMIN_TOKEN = None


def make_admin_user():
    """Admin user'ı veritabanında oluştur"""
    try:
        conn = sqlite3.connect("genai_gateway.db")
        cursor = conn.cursor()
        
        # Admin user'ı sil (varsa)
        cursor.execute("DELETE FROM users WHERE username = 'admin_test'")
        
        # Yeni admin user ekle (şifre hash'i bcrypt'in fake hash'i)
        # Note: Gerçek durumda hash edilmelidir, test için basit password kullanıyoruz
        cursor.execute("""
            INSERT INTO users (username, password_hash, email, phone, full_name, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
        """, (
            "admin_test",
            "$2b$12$fake.admin.password.hash123456789",  # Fake hash
            "admin@test.com",
            "1234567890",
            "Admin Test",
            "admin"
        ))
        
        conn.commit()
        conn.close()
        print("✓ Admin test user oluşturuldu")
        return True
    except Exception as e:
        print(f"✗ Admin user oluşturulurken hata: {e}")
        return False


async def get_admin_token():
    """Admin token al (mock token)"""
    global ADMIN_TOKEN
    
    # Basit bir JWT token oluştur (test için)
    from datetime import datetime, timedelta
    
    SECRET_KEY = "super-secret-genai-key"
    payload = {
        "sub": "admin_test",
        "role": "admin",
        "exp": datetime.utcnow() + timedelta(hours=24)
    }
    ADMIN_TOKEN = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    print(f"✓ Mock admin token oluşturuldu: {ADMIN_TOKEN[:30]}...")
    return True


async def test_get_config():
    """GET /config endpoint'ini test et"""
    print("\n" + "="*60)
    print("TEST 1: GET /config")
    print("="*60)
    
    async with httpx.AsyncClient() as client:
        headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
        res = await client.get(f"{BASE_URL}/config", headers=headers)
        
        print(f"Status: {res.status_code}")
        if res.status_code == 200:
            config = res.json()
            print(f"✓ Config başarıyla getirildi")
            print(f"  - Layer 1: {config.get('layer_regex')}")
            print(f"  - Layer 2: {config.get('layer_deberta')}")
            print(f"  - Layer 3: {config.get('layer_llm')}")
            print(f"  - AI Threshold: {config.get('ai_threshold')}")
            print(f"  - Blacklist ({len(config.get('blacklist', []))} kelime):")
            for word in config.get('blacklist', [])[:3]:
                print(f"    • {word}")
            return config
        else:
            print(f"✗ Hata: {res.status_code}")
            print(f"  Detay: {res.text}")
            return None


async def test_add_blacklist(word="test_word_xyz"):
    """PUT /config/blacklist?operation=add endpoint'ini test et"""
    print("\n" + "="*60)
    print(f"TEST 2: PUT /config/blacklist?operation=add&word={word}")
    print("="*60)
    
    async with httpx.AsyncClient() as client:
        headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
        res = await client.put(
            f"{BASE_URL}/config/blacklist",
            headers=headers,
            params={"operation": "add", "word": word}
        )
        
        print(f"Status: {res.status_code}")
        if res.status_code == 200:
            data = res.json()
            print(f"✓ Blacklist'e kelime eklendi: {word}")
            print(f"  - Toplam blacklist kelime: {len(data.get('blacklist', []))}")
            return data
        else:
            print(f"✗ Hata: {res.status_code}")
            print(f"  Detay: {res.text}")
            return None


async def test_update_threshold(threshold=0.70):
    """PUT /config/threshold endpoint'ini test et"""
    print("\n" + "="*60)
    print(f"TEST 3: PUT /config/threshold?threshold={threshold}")
    print("="*60)
    
    async with httpx.AsyncClient() as client:
        headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
        res = await client.put(
            f"{BASE_URL}/config/threshold",
            headers=headers,
            params={"threshold": threshold}
        )
        
        print(f"Status: {res.status_code}")
        if res.status_code == 200:
            data = res.json()
            print(f"✓ Threshold başarıyla güncellendi")
            print(f"  - Eski: {data.get('old_threshold')}")
            print(f"  - Yeni: {data.get('new_threshold')}")
            return data
        else:
            print(f"✗ Hata: {res.status_code}")
            print(f"  Detay: {res.text}")
            return None


async def test_toggle_layers():
    """PUT /config/layers endpoint'ini test et"""
    print("\n" + "="*60)
    print("TEST 4: PUT /config/layers?layer1=true&layer2=false&layer3=true")
    print("="*60)
    
    async with httpx.AsyncClient() as client:
        headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
        res = await client.put(
            f"{BASE_URL}/config/layers",
            headers=headers,
            params={"layer1": True, "layer2": False, "layer3": True}
        )
        
        print(f"Status: {res.status_code}")
        if res.status_code == 200:
            data = res.json()
            print(f"✓ Layer'lar başarıyla güncellendi")
            print(f"  - Eski state: {data.get('previous_state')}")
            print(f"  - Yeni state: {data.get('new_state')}")
            return data
        else:
            print(f"✗ Hata: {res.status_code}")
            print(f"  Detay: {res.text}")
            return None


async def test_submit_feedback(log_id="test-log-123"):
    """POST /feedback endpoint'ini test et"""
    print("\n" + "="*60)
    print(f"TEST 5: POST /feedback?log_id={log_id}&feedback_type=false_positive")
    print("="*60)
    
    async with httpx.AsyncClient() as client:
        res = await client.post(
            f"{BASE_URL}/feedback",
            params={"log_id": log_id, "feedback_type": "false_positive"}
        )
        
        print(f"Status: {res.status_code}")
        if res.status_code == 200:
            data = res.json()
            print(f"✓ Feedback başarıyla kaydedildi")
            print(f"  - Log ID: {data.get('log_id')}")
            print(f"  - Type: {data.get('feedback_type')}")
            return data
        else:
            print(f"✗ Hata: {res.status_code}")
            print(f"  Detay: {res.text}")
            return None


async def test_remove_blacklist(word="test_word_xyz"):
    """PUT /config/blacklist?operation=remove endpoint'ini test et"""
    print("\n" + "="*60)
    print(f"TEST 6: PUT /config/blacklist?operation=remove&word={word}")
    print("="*60)
    
    async with httpx.AsyncClient() as client:
        headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
        res = await client.put(
            f"{BASE_URL}/config/blacklist",
            headers=headers,
            params={"operation": "remove", "word": word}
        )
        
        print(f"Status: {res.status_code}")
        if res.status_code == 200:
            data = res.json()
            print(f"✓ Blacklist'ten kelime silindi: {word}")
            print(f"  - Toplam blacklist kelime: {len(data.get('blacklist', []))}")
            return data
        else:
            print(f"✗ Hata: {res.status_code}")
            print(f"  Detay: {res.text}")
            return None


async def main():
    print("\n")
    print("╔════════════════════════════════════════════════════════╗")
    print("║   GenAI Gateway - AŞAMA 1 Admin Endpoints TEST        ║")
    print("╚════════════════════════════════════════════════════════╝")
    
    # Admin token al
    await get_admin_token()
    
    # Testleri çalıştır
    await test_get_config()
    await test_add_blacklist("dangerous_word")
    await test_update_threshold(0.65)
    await test_toggle_layers()
    await test_submit_feedback("test-log-456")
    await test_remove_blacklist("dangerous_word")
    
    # Sonuç
    print("\n" + "="*60)
    print("✅ TÜM TESTLER TAMAMLANDI")
    print("="*60 + "\n")


if __name__ == "__main__":
    # Admin user oluştur
    make_admin_user()
    
    # Testleri çalıştır
    asyncio.run(main())

