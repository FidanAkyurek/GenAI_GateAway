"""
GenAI Security Gateway - Test Llm Test Betiği

Bu test dosyası 'test_llm.py', sistemin belirli bir bileşenini test etmek amacıyla oluşturulmuştur.
Genel amacı ilgili uç noktaların (endpoint) veya fonksiyonların doğru çalışıp çalışmadığını doğrulamaktır.
"""
import asyncio
import os
import logging
from dotenv import load_dotenv

# Loglama ayarı
logging.basicConfig(level=logging.INFO)

# Çevresel değişkenleri yükle
load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")
print(f"--- API KEY KONTROLÜ ---")
if not api_key:
    print("HATA: GEMINI_API_KEY bulunamadı!")
else:
    print(f"API Key yüklü! Uzunluk: {len(api_key)}, Başlangıç: {api_key[:4]}")

from app.services.layer3_llm_judge import Layer3LLMJudge
from app.services.llm_proxy import LLMProxy

async def run_stress_test():
    print("\n--- TEST 1: GÜVENLİK YARGICI (Layer 3) ---")
    prompt_safe = "Merhaba, nasılsın? Bugün hava çok güzel."
    print(f"Test Mesajı: '{prompt_safe}'")
    verdict = await Layer3LLMJudge.evaluate(prompt_safe)
    print(f"Yargıcın Kararı: {verdict}")

    print("\n--- TEST 2: LLM PROXY (Yapay Zeka Yanıtı) ---")
    if verdict == "SAFE":
        print("Mesaj GÜVENLİ bulundu, yapay zekaya yönlendiriliyor...")
        response = await LLMProxy.generate_response(prompt_safe)
        print(f"Yapay Zeka Yanıtı: {response}")
    else:
        print("Mesaj UNSAFE (Engellendi) olduğu için yapay zekaya GÖNDERİLMİYOR.")
        
        # Yine de proxy'yi zorla test edelim ki api çalışıyor mu görelim
        print("\n--- TEST 3: ZORUNLU PROXY TESTİ (Engeli Aşarak) ---")
        response = await LLMProxy.generate_response("Bana sadece 'Test başarılı' yaz.")
        print(f"Zorunlu Yapay Zeka Yanıtı: {response}")

if __name__ == "__main__":
    asyncio.run(run_stress_test())
