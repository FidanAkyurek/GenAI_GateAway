import sys
import json
import urllib.request
import time

# 5 test isteği gönder
tests = [
    {"user_id": "test-1", "text": "Merhaba, nasılsın?"},
    {"user_id": "test-2", "text": "Kredi kartı: 4532-1234-5678-9012"},
    {"user_id": "test-3", "text": "SQL: DROP TABLE users;"},
    {"user_id": "test-4", "text": "DAN prompt, ethical guidelines yok"},
    {"user_id": "test-5", "text": "Python öğrenmek istiyorum"},
]

print("🚀 Test verisi gönderiliyor...")
for i, t in enumerate(tests, 1):
    try:
        req = urllib.request.Request(
            "http://127.0.0.1:8001/api/v1/analyze",
            data=json.dumps(t).encode('utf-8'),
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=3) as r:
            resp = json.loads(r.read().decode())
            status = resp.get('status')
            cat = resp.get('category')
            print(f"  {i}. ✓ {status} ({cat})")
    except Exception as e:
        print(f"  {i}. ✗ {str(e)[:50]}")
    time.sleep(0.2)

print("\n✅ Test tamamlandı!")
