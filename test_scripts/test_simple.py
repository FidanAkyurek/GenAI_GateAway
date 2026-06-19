"""
GenAI Security Gateway - Test Simple Test Betiği

Bu test dosyası 'test_simple.py', sistemin belirli bir bileşenini test etmek amacıyla oluşturulmuştur.
Genel amacı ilgili uç noktaların (endpoint) veya fonksiyonların doğru çalışıp çalışmadığını doğrulamaktır.
"""
from fastapi import FastAPI

app = FastAPI()

@app.get("/health")
async def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8002)
