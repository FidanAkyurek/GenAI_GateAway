"""
GenAI Security Gateway - Test Fastapi Test Betiği

Bu test dosyası 'test_fastapi.py', sistemin belirli bir bileşenini test etmek amacıyla oluşturulmuştur.
Genel amacı ilgili uç noktaların (endpoint) veya fonksiyonların doğru çalışıp çalışmadığını doğrulamaktır.
"""
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

response = client.post("/api/v1/auth/login", json={"username": "super_admin_fidan", "password": "Admin123!"})
print("STATUS:", response.status_code)
print("BODY:", response.text)
