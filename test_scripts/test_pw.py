"""
GenAI Security Gateway - Test Pw Test Betiği

Bu test dosyası 'test_pw.py', sistemin belirli bir bileşenini test etmek amacıyla oluşturulmuştur.
Genel amacı ilgili uç noktaların (endpoint) veya fonksiyonların doğru çalışıp çalışmadığını doğrulamaktır.
"""
from app.controllers.auth_controller import verify_password
print(verify_password('Admin123!', '$2b$12$P3p11jHbxMkXCgSYbZu5UOPUTT5JyD56Kw7O2T4fFV4Vftswxxacq'))
