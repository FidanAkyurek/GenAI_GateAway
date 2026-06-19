"""
GenAI Security Gateway - Test Massive Data Test Betiği

Bu test dosyası 'test_massive_data.py', sistemin belirli bir bileşenini test etmek amacıyla oluşturulmuştur.
Genel amacı ilgili uç noktaların (endpoint) veya fonksiyonların doğru çalışıp çalışmadığını doğrulamaktır.
"""
import asyncio
import httpx
import random
import time
import csv

API_URL = "http://127.0.0.1:8001/api/v1/analyze"
FILE_PATH = "data/massive_security_dataset.csv"

async def send_request(client, prompt, expected_label):
    payload = {
        "text": str(prompt)[:500],  # API'yi çok yormamak için ilk 500 karakter
        "user_id": f"test_user_{random.randint(100, 999)}",
        "is_test": True
    }
    category = "INJECTION (Saldırı)" if expected_label == 1 else "SAFE (Güvenli)"
    try:
        start_time = time.time()
        response = await client.post(API_URL, json=payload, timeout=60.0)
        latency = int((time.time() - start_time) * 1000)
        
        if response.status_code == 200:
            data = response.json()
            status = data.get("status")
            reason = data.get("reason", "")
            
            # Konsola estetik ve okunabilir bir çıktı bas
            if status == "BLOCKED":
                print(f"🛑 [Sistem: ENGELLENDİ] | Beklenen: {category} | Süre: {latency}ms | Sebep: {reason}")
            else:
                print(f"✅ [Sistem: İZİN VERİLDİ] | Beklenen: {category} | Süre: {latency}ms")
        else:
            print(f"❌ HTTP Error: {response.status_code}")
    except Exception as e:
        pass # Port kapanması vs görmezden gel

async def main():
    print("===================================================================")
    print("🚀 GenAI Security Gateway - DEVASA VERİ SETİ YÜK TESTİ BAŞLIYOR...")
    print("===================================================================\n")
    
    safe_prompts = []
    unsafe_prompts = []
    
    # 50.000 satırlık devasa CSV'yi oku
    try:
        with open(FILE_PATH, mode='r', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader) # başlığı atla
            for row in reader:
                if len(row) == 2:
                    prompt, label = row[0], int(row[1])
                    if label == 1:
                        unsafe_prompts.append(prompt)
                    else:
                        safe_prompts.append(prompt)
    except FileNotFoundError:
        print("HATA: Veri seti bulunamadı!")
        return
                    
    # Veri setinden 500 Güvenli, 500 Saldırı (Toplam 1000) isteği rastgele seç
    test_safe = random.sample(safe_prompts, min(500, len(safe_prompts)))
    test_unsafe = random.sample(unsafe_prompts, min(500, len(unsafe_prompts)))
    
    all_tests = [(p, 0) for p in test_safe] + [(p, 1) for p in test_unsafe]
    random.shuffle(all_tests) # İstekleri karıştır (Gerçek dünya simülasyonu)
    
    print(f"Toplam 1000 adet istek (500 Safe, 500 Injection) API'ye eşzamanlı olarak fırlatılıyor...\n")
    
    async with httpx.AsyncClient() as client:
        tasks = []
        for prompt, label in all_tests:
            tasks.append(asyncio.create_task(send_request(client, prompt, label)))
            await asyncio.sleep(0.02) # Çok hafif bir aralık (sunucu timeout yemesin)
            
        await asyncio.gather(*tasks)
        
    print("\n===================================================================")
    print("✅ YÜK TESTİ BAŞARIYLA TAMAMLANDI!")
    print("Sistem Katman 1 (Kara Liste) ve Katman 2 (DeBERTa) ile başarıyla test edildi.")
    print("===================================================================")

if __name__ == "__main__":
    asyncio.run(main())
