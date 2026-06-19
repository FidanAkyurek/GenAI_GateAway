"""
GenAI Security Gateway - Test Backend Test Betiği

Bu test dosyası 'test_backend.py', sistemin belirli bir bileşenini test etmek amacıyla oluşturulmuştur.
Genel amacı ilgili uç noktaların (endpoint) veya fonksiyonların doğru çalışıp çalışmadığını doğrulamaktır.
"""
import requests
import json

BASE_URL = "http://127.0.0.1:8001"
API_V1 = f"{BASE_URL}/api/v1"

print("=" * 60)
print("BACKEND ENDPOINT TEST")
print("=" * 60 + "\n")

tests = [
    ("GET /api/v1/stats", "GET", f"{API_V1}/stats"),
    ("GET /api/v1/config", "GET", f"{API_V1}/config"),
    ("GET /api/v1/logs", "GET", f"{API_V1}/logs"),
]

passed = 0
failed = 0

for name, method, url in tests:
    try:
        if method == "GET":
            response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            print(f"✓ {name} - Status 200")
            passed += 1
        else:
            print(f"✗ {name} - Status {response.status_code}")
            failed += 1
    except Exception as e:
        print(f"✗ {name} - Error: {e}")
        failed += 1

# Test analyze endpoint
print("\nTEST: POST /api/v1/analyze (Test prompt)")
try:
    response = requests.post(
        f"{API_V1}/analyze",
        json={"prompt": "Merhaba, bugün hava nasıl?"},
        timeout=10
    )
    if response.status_code == 200:
        data = response.json()
        print(f"✓ Analyze endpoint çalışıyor")
        print(f"  - Result: {data.get('result')}")
        print(f"  - Layer1: {data.get('layer1_result')}")
        print(f"  - Layer3: {data.get('layer3_result')}")
        passed += 1
    else:
        print(f"✗ Analyze failed - Status {response.status_code}")
        failed += 1
except Exception as e:
    print(f"✗ Analyze error: {e}")
    failed += 1

print("\n" + "=" * 60)
print(f"SONUÇ: {passed} PASS, {failed} FAIL")
print("=" * 60)
