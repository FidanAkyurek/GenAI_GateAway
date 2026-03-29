from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from supabase import create_client, Client
import os
from dotenv import load_dotenv

# Katmanları içe aktar
from app.security import Layer1Filter
from app.ml_model import Layer2Model

# 1. Ayarları Yükle
load_dotenv()
url: str = os.environ.get("SUPABASE_URL")
key: str = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)

# Güvenlik katmanını başlat
l1_filter = Layer1Filter()
l2_model = Layer2Model()

app = FastAPI(title="Akıllı Güvenlik Ağ Geçidi")

# Veri Modeli
class PromptRequest(BaseModel):
    text: str
    user_id: str = "anonim"

@app.get("/")
def read_root():
    return {"Durum": "Sistem Aktif", "Katmanlar": ["Regex", "PII"]}

@app.post("/analyze")
def analyze_prompt(request: PromptRequest):
    """
    Gelen isteği analiz eder ve sonucu veritabanına kaydeder.
    """
    # --- 1. KATMAN KONTROLÜ ---
    l1_result = l1_filter.check(request.text)
    
    # Karara göre değişkenleri hazırla
    if l1_result["is_safe"] == False:
        # L1 yakaladıysa hemen engelle, L2'ye gitme
        aksiyon = "ENGEL (L1)"
        kategori = l1_result["reason"]
        skor = 1.0
    else:
        # --- 2. KATMAN KONTROLÜ (Yavaş & Zeki) ---
        # L1 temiz dedi, şimdi dosyayı AI Yargıca (L2) gönderiyoruz
        l2_result = l2_model.check(prompt)
        
        if l2_result["is_safe"] == False:
            aksiyon = "ENGEL (L2)"
            kategori = l2_result["reason"]
            skor = l2_result["score"]
        else:
            aksiyon = "İZİN"
            kategori = "Temiz"
            skor = l2_result["score"]
    # --- LOGLAMA (SUPABASE) ---
    try:
        data = {
            "prompt": request.text,
            "action": aksiyon,
            "category": kategori
        }
        supabase.table("security_logs").insert(data).execute()
    except Exception as e:
        print(f"Loglama Hatası: {e}")

    # Kullanıcıya Cevap Dön
    return {
        "sonuc": aksiyon, 
        "detay": kategori,
        "girdi": request.text
    }