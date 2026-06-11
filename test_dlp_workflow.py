import asyncio
import httpx

API_URL = "http://127.0.0.1:8001/api/v1"

async def test_dlp_flow():
    async with httpx.AsyncClient() as client:
        # 1. Normal prompt (PII içermeyen)
        print("--- TEST 1: Normal Prompt ---")
        res1 = await client.post(f"{API_URL}/analyze", json={
            "text": "Python'da list ve tuple farkı nedir?",
            "user_id": "test_user_dlp",
            "is_test": True
        })
        if res1.status_code == 200:
            data = res1.json()
            print(f"Status: {data.get('status')}")
            print(f"Category: {data.get('category')}")
        else:
            print(f"Error: {res1.status_code} - {res1.text}")

        # 2. Hassas Veri (PII) İçeren Prompt (Durdurulmalı ve DLP_ALERT dönmeli)
        print("\n--- TEST 2: DLP/PII Tespiti (Durdurulmalı) ---")
        res2 = await client.post(f"{API_URL}/analyze", json={
            "text": "Lütfen borcumu sorgula, TCKN: 12345678901 ve Kredi Kartım: 1111222233334444",
            "user_id": "test_user_dlp",
            "is_test": True
        })
        log_id = None
        if res2.status_code == 200:
            data = res2.json()
            log_id = data.get("log_id")
            print(f"Status: {data.get('status')} (Beklenen: DLP_ALERT)")
            print(f"Category: {data.get('category')} (Beklenen: PII)")
            print(f"Maskeli Metin: {data.get('processed_text')}")
            print(f"Tespit Edilenler: {data.get('detected_entities')}")
        else:
            print(f"Error: {res2.status_code} - {res2.text}")

        # 3. Gerekçe Belirterek Gönderme (Bypass - ALLOW dönmeli)
        print("\n--- TEST 3: Gerekçe Belirterek Bypass Gönderim (Red Flag) ---")
        res3 = await client.post(f"{API_URL}/analyze", json={
            "text": "Lütfen borcumu sorgula, TCKN: 12345678901",
            "user_id": "test_user_dlp",
            "is_test": True,
            "bypass_action": "bypass",
            "bypass_justification": "Müşteri finansal doğrulama işlemi için zorunlu gönderim."
        })
        if res3.status_code == 200:
            data = res3.json()
            print(f"Status: {data.get('status')} (Beklenen: ALLOW)")
            print(f"Category: {data.get('category')} (Beklenen: PII_BYPASS)")
            print(f"Bypass Durumu: {data.get('bypass_status')}")
            print(f"Gerekçe: {data.get('justification')}")
        else:
            print(f"Error: {res3.status_code} - {res3.text}")

        # 4. Yöneticiden Onay İsteme (PENDING dönmeli)
        print("\n--- TEST 4: Yöneticiden Onay İsteme ---")
        res4 = await client.post(f"{API_URL}/analyze", json={
            "text": "Borç sorgulamak istiyorum, TCKN: 12345678901",
            "user_id": "test_user_dlp",
            "is_test": True,
            "bypass_action": "request_approval",
            "bypass_justification": "Yıllık denetim raporu hazırlığı için izin talebi."
        })
        pending_log_id = None
        if res4.status_code == 200:
            data = res4.json()
            pending_log_id = data.get("log_id")
            print(f"Status: {data.get('status')} (Beklenen: PENDING)")
            print(f"Category: {data.get('category')} (Beklenen: PII_PENDING)")
            print(f"Bypass Durumu: {data.get('bypass_status')}")
            print(f"Gerekçe: {data.get('justification')}")
        else:
            print(f"Error: {res4.status_code} - {res4.text}")

        # 5. Yöneticinin Talebi Onaylaması (Mock/Admin login token ve onay endpoint'i testi)
        # Login admin and approve
        if pending_log_id:
            print("\n--- TEST 5: Yönetici Onay Endpoint'i ---")
            # First obtain token by logging in as superadmin (or company_admin)
            login_res = await client.post(f"{API_URL}/auth/login", json={
                "username": "superadmin",
                "password": "superadmin123"
            })
            if login_res.status_code == 200:
                token = login_res.json().get("access_token")
                headers = {"Authorization": f"Bearer {token}"}
                
                # Approve the request
                approve_res = await client.post(f"{API_URL}/admin/company/logs/{pending_log_id}/approve", headers=headers)
                if approve_res.status_code == 200:
                    print("Talep başarıyla onaylandı!")
                else:
                    print(f"Onaylama hatası: {approve_res.status_code} - {approve_res.text}")
            else:
                print(f"Login başarısız: {login_res.status_code} - {login_res.text}")

if __name__ == "__main__":
    asyncio.run(test_dlp_flow())
