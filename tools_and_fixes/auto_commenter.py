import os
import ast

# Dictionary of file paths to their human-like Turkish documentation
FILE_COMMENTS = {
    "app/controllers/admin_controller.py": '''"""
GenAI Security Gateway - Admin Kontrolcüsü (Admin Controller)

Bu dosya, yönetici (admin) paneli üzerinden yapılan güvenlik konfigürasyonu değişikliklerini,
kullanıcı yönetimini ve kural güncellemelerini işler.
Güvenlik katmanlarını (Layer 1, 2, 3) anlık olarak açıp kapatma veya yapay zeka
hassasiyet eşiğini (threshold) değiştirme işlemleri buradan yönetilir.
Ayrıca sisteme yeni departmanlar ve şirketler ekleme yetkilerine de sahiptir.
"""
''',
    "app/controllers/auth_controller.py": '''"""
GenAI Security Gateway - Kimlik Doğrulama Kontrolcüsü (Auth Controller)

Sisteme giriş yapan kullanıcıların kimlik doğrulamasını (Authentication) ve 
yetkilendirmesini (Authorization) sağlar. 
Kullanıcı giriş yaptığında bir JWT (JSON Web Token) üretilir ve bu token 
diğer tüm korumalı uç noktalarda (endpoints) güvenliği sağlamak için kullanılır.
Ayrıca profil güncelleme ve şifre değiştirme işlemleri de bu dosyada bulunur.
"""
''',
    "app/controllers/file_controller.py": '''"""
GenAI Security Gateway - Dosya Analiz Kontrolcüsü (File Controller)

Sisteme yüklenen dosyaların (PDF, TXT, DOCX vb.) içeriklerini okur ve 
içlerinde güvenlik zafiyeti veya hassas veri (PII) olup olmadığını kontrol eder.
Özellikle büyük dosyaların (örneğin 100 sayfalık bir PDF) güvenli bir şekilde 
ayrıştırılıp (parsing) güvenlik katmanlarından (Layer 1, 2, 3) geçirilmesini sağlar.
"""
''',
    "app/controllers/security_controller.py": '''"""
GenAI Security Gateway - Güvenlik Kontrolcüsü (Security Controller)

Uygulamanın kalbidir. Kullanıcılardan veya dış sistemlerden gelen tüm metin (prompt) 
istekleri ilk olarak bu dosyaya düşer. Gelen istekler sırasıyla:
1. Katman 1 (Regex & Blacklist)
2. Katman 2 (DeBERTa AI Modeli)
3. Katman 3 (LLM Judge)
kontrollerinden geçirilir ve sonuç veritabanına kaydedilir.
Sistem "Fail-Open" veya "Fail-Closed" mantığına göre karar vererek istemciye döner.
"""
''',
    "test_scripts/test_layer1.py": '''"""
GenAI Security Gateway - Katman 1 (Regex & DLP) Test Betiği

Bu test dosyası, Katman 1'in T.C. Kimlik No, Kredi Kartı, Email gibi hassas verileri 
doğru maskeleyip maskelemediğini (DLP) ve yasaklı kelimeleri doğru yakalayıp yakalamadığını kontrol eder.
"""
''',
    "test_scripts/test_layer2.py": '''"""
GenAI Security Gateway - Katman 2 (DeBERTa AI) Test Betiği

Bu test dosyası, yapay zeka modelimizin (DeBERTa) prompt injection (komut enjeksiyonu) 
saldırılarını başarılı bir şekilde tespit edip etmediğini kontrol eder.
"""
''',
    "test_scripts/test_layer3.py": '''"""
GenAI Security Gateway - Katman 3 (LLM Judge) Test Betiği

Bu test dosyası, Gemini modelini kullanan Katman 3 Yargıcının (LLM Judge) bağlamsal
analiz yeteneklerini siber güvenlik senaryolarıyla (Jailbreak vb.) test eder.
"""
''',
    "database_scripts/check_db.py": '''"""
Veritabanı Kontrol Betiği (Database Checker)

Sistemdeki veritabanı (SQLite veya PostgreSQL) tablolarının mevcut olup olmadığını, 
içerisindeki kullanıcıları ve log kayıtlarını basitçe konsola basarak kontrol etmeye yarar.
"""
''',
    "database_scripts/fix_db.py": '''"""
Veritabanı Onarım Betiği (Database Fixer)

Eski veya eksik kalmış veritabanı şemalarını günceller. (Örneğin tablolara sonradan eklenen
'justification' veya 'bypass_status' gibi sütunların eksik olması durumunda tabloyu alter eder).
"""
''',
    "data_generation_scripts/generate_synthetic_massive_dataset.py": '''"""
Sentetik Test Verisi Üretme Betiği

Sistemin yük testlerini yapabilmek ve dashboard üzerinde anlamlı grafikler görebilmek için
rastgele (sentetik) güvenlik logları, promptlar ve kullanıcılar oluşturur.
Çıktı olarak CSV üretir veya doğrudan DB'ye yazar.
"""
''',
    "tools_and_fixes/fix_dashboard.py": '''"""
Dashboard Düzeltme Betiği

Streamlit dashboard'unda yaşanan olası durumları veya veritabanı tutarsızlıklarını onarmak için
kullanılan bir yardımcı araçtır.
"""
'''
}

def add_comments_to_file(filepath, comment):
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return
        
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    # Skip if it already has a prominent GenAI Security Gateway docstring at the top
    if "GenAI Security Gateway -" in content[:500] or "Bu test dosyası" in content[:500]:
        print(f"Already commented: {filepath}")
        return

    # Try to find the best place to insert the docstring (after imports or at the very top)
    try:
        tree = ast.parse(content)
        # If there's an existing docstring, maybe replace it, but for simplicity we just prepend
    except SyntaxError:
        pass
        
    # Standard prepend logic
    new_content = comment + "\n" + content
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(new_content)
        
    print(f"Added comments to {filepath}")

def process_js_frontend():
    js_path = "frontend/app.js"
    if not os.path.exists(js_path):
        return
        
    with open(js_path, "r", encoding="utf-8") as f:
        content = f.read()
        
    if "/* GenAI Security Gateway - Frontend" in content:
        print("Frontend already commented.")
        return
        
    comment = """/*
 * GenAI Security Gateway - Frontend Uygulaması (app.js)
 *
 * Bu JavaScript dosyası, kullanıcıların sisteme giriş yaptığı, prompt gönderdiği
 * ve güvenlik analiz sonuçlarını gördüğü web arayüzünün mantığını (logic) yönetir.
 * 
 * Ana İşlevler:
 * 1. Sunucu ile haberleşme (Fetch API ile REST çağrıları)
 * 2. JWT (JSON Web Token) yönetimi ve LocalStorage'da saklanması
 * 3. Arayüz etkileşimleri (Buton tıklamaları, modal açılıp kapanması)
 * 4. Animasyonlar ve bildirim (toast) mesajları
 */
"""
    with open(js_path, "w", encoding="utf-8") as f:
        f.write(comment + "\n" + content)
    print("Added comments to frontend/app.js")

if __name__ == "__main__":
    import sys
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(base_dir)
    
    for relative_path, docstring in FILE_COMMENTS.items():
        # Correctly join the paths
        full_path = os.path.join(base_dir, relative_path.replace("/", os.sep))
        add_comments_to_file(full_path, docstring)
        
    process_js_frontend()
    print("All configured files processed!")
