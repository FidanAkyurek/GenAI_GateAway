# Proje Uygulama Planı: Etkileşimli Veri Kaybı Önleme (DLP) Uyarı Ekranı

Bu plan, B2B kurumsal müşteriler için geliştirilen **GenAI Security Gateway** projesine bir **Etkileşimli DLP Uyarı Ekranı** entegre etmek için yapılacak değişiklikleri ve tasarımları içerir.

---

## 1. Kullanıcı Arayüzü (UX/UI) Tasarım Esasları

Kullanıcıyı korkutmayan, kurumsal ciddiyeti koruyan ancak güvenlik bilincini artıran bir modal arayüzü kurgulanmıştır.

### Başlık ve Kopyalar (Copywriting)
* **Modal Başlığı:** `🛡️ DLP Güvenlik Uyarısı (KVKK / Kurum Politikası İhlali)`
* **Açıklama Metni:**
  > "Göndermek istediğiniz istek içerisinde KVKK standartlarına veya kurum politikalarına aykırı hassas veriler (örn: **[Tespit Edilen Veri Türleri]**) tespit edilmiştir. Güvenliğiniz için bu istek geçici olarak durdurulmuştur. Lütfen devam etmek için aşağıdaki seçeneklerden birini belirleyin."
* **Tonlama:** Yardımcı, bilgilendirici, kurumsal ve güven verici. Kırmızı renk tonları sadece uyarıyı hissettirmek amacıyla yumuşatılmış biçimde (örneğin arka planda soft kırmızı) kullanılacaktır.

### Görsel Hiyerarşi (Butonlar ve Linkler)
1. **Birincil Aksiyon (Vurgulu Buton - Yeşil/Mavi):** `🧼 Otomatik Maskele ve Gönder` -> En güvenli ve önerilen yoldur.
2. **İkincil Aksiyonlar (Standart Gri/Çerçeveli Butonlar):**
   * `✏️ İstemi Düzenle` (Prompt ekranına geri atar)
   * `❌ İşlemi İptal Et` (İsteği tamamen siler)
3. **Alt Şeffaflık Linkleri (Sade Metin Linkleri):**
   * `📖 Kurum Güvenlik Politikasını İncele` (Harici bilgilendirme linki)
   * `📢 Hatalı Tespit Bildir (False Positive)` (SOC'a raporlama butonu)
4. **İstisna İş Akışı Alanı (Grup Alt Alanı):**
   * **Gerekçe Metin Girişi:** `Bypass Gerekçesi (Maskesiz göndermek için doldurunuz)`
   * **Bypass Gönderim (Kırmızı Çerçeveli Buton):** `🔴 Gerekçe Belirterek Gönder (Red Flag)`
   * **Onay İstem (Mavi Çerçeveli Buton):** `📨 Yöneticiden Onay İste (Pending)`

---

## 2. Planlanan Değişiklikler

### A. Veritabanı Katmanı
#### [MODIFY] [database_manager.py](file:///c:/Users/user/Documents/Bitirme_Kod_Haziran/GenAI_GateAway/app/services/database_manager.py)
* `security_logs` tablosuna aşağıdaki iki yeni kolon eklenecektir:
  * `justification TEXT` (Kullanıcının bypass gerekçesi)
  * `bypass_status TEXT` (Bypass'ın mevcut durumu: örn. `Bypassed (Red Flag)`, `Pending Approval`, `Approved`, `Rejected`)
* SQLite ve PostgreSQL başlatma metotlarına otomatik alter/migration kodları eklenecektir.
* `log_security_event` metoduna bu iki yeni alan parametre olarak eklenecektir.
* Log durumu güncelleme için yeni bir metot (`update_log_status`) eklenecektir.

---

### B. Backend API Katmanı
#### [MODIFY] [schemas.py](file:///c:/Users/user/Documents/Bitirme_Kod_Haziran/GenAI_GateAway/app/models/schemas.py)
* `PromptRequest` modeline `bypass_justification` ve `bypass_action` alanları eklenecektir.
* `PromptResponse` modeline `detected_entities` (tespit edilen veri türleri listesi), `justification` ve `bypass_status` alanları eklenecektir.

#### [MODIFY] [security_controller.py](file:///c:/Users/user/Documents/Bitirme_Kod_Haziran/GenAI_GateAway/app/controllers/security_controller.py)
* DLP tarama sonucunda PII bulunursa ve herhangi bir bypass isteği gelmemişse, istek LLM'e gitmeden durdurulacak ve `status="DLP_ALERT"`, `category="PII"` olarak döndürülecektir.
* `detected_entities` dizisi doldurularak hangi PII türlerinin (örn: TCKN, Kredi Kartı, IBAN) eşleştiği bildirilecektir.
* Kullanıcı `bypass` aksiyonu ile gerekçe gönderdiğinde, bu log veritabanına `justification` ve `bypass_status="Bypassed (Red Flag)"` ile kaydedilecek, istek orijinal haliyle LLM'e iletilerek yanıt alınacaktır.
* Kullanıcı `request_approval` aksiyonu gönderdiğinde, log veritabanına `action="PENDING"` ve `bypass_status="Pending Approval"` ile kaydedilecek, LLM'e gitmeden durdurulacaktır.

#### [MODIFY] [admin_controller.py](file:///c:/Users/user/Documents/Bitirme_Kod_Haziran/GenAI_GateAway/app/controllers/admin_controller.py)
* Yöneticilerin bekleyen talepleri onaylaması/reddetmesi için `/logs/{log_id}/approve` ve `/logs/{log_id}/reject` endpoint'leri eklenecektir.

---

### C. Çalışan Arayüzü (Streamlit Frontend)
#### [MODIFY] [streamlit_app.py](file:///c:/Users/user/Documents/Bitirme_Kod_Haziran/GenAI_GateAway/streamlit_app.py)
* Streamlit 1.58 sürümünün sunduğu native `@st.dialog` dekoratörü kullanılarak **Etkileşimli DLP Uyarı Ekranı** (`show_dlp_warning_dialog`) eklenecektir.
* Kullanıcı prompt gönderdiğinde ve yanıt olarak `DLP_ALERT` döndüğünde bu modal açılacaktır.
* Modal içerisindeki aksiyonlar `st.session_state` güncellemeleriyle ana uygulama akışına bağlanacaktır:
  * **Maskele ve Gönder:** Maskeli metni tekrar `/analyze` endpoint'ine gönderir.
  * **İstemi Düzenle:** Modal kapatılır ve prompt metin kutusu orijinal içerikle doldurulur.
  * **İptal Et:** Modal kapatılır ve prompt metin kutusu sıfırlanır.
  * **Gerekçe Gönder:** Orijinal metni `bypass_justification` parametresiyle tekrar gönderir.
  * **Onay İste:** Orijinal metni `request_approval` parametresiyle göndererek onay sürecini başlatır.

---

### D. SOC Dashboard (Yönetici Arayüzü)
#### [MODIFY] [dashboard.html](file:///c:/Users/user/Documents/Bitirme_Kod_Haziran/GenAI_GateAway/frontend/dashboard.html) ve [app.js](file:///c:/Users/user/Documents/Bitirme_Kod_Haziran/GenAI_GateAway/frontend/app.js)
* SOC Dashboard üzerindeki log detay modalına **Gerekçe** (`Justification`) ve **Bypass Durumu** alanları eklenecektir.
* Eğer istek `PENDING` durumunda ise yöneticinin modal üzerinden talebi doğrudan onaylayıp reddetmesini sağlayan `Onayla` ve `Reddet` butonları eklenecektir.

---

## 3. Doğrulama Planı

### Otomatik Testler
* DLP Alert tespiti ve bypass akışlarını simüle eden bir test script'i (`test_dlp_workflow.py`) yazılıp çalıştırılacaktır.

### Manuel Doğrulama
* Streamlit arayüzünden PII içeren (örn. TCKN) bir prompt gönderilecek, modalın açıldığı görülecektir.
* Modal üzerindeki tüm butonların işlevleri (Maskeleme, Düzenleme, İptal, Gerekçe, SOC Bildirimi, Yönetici Onayı) tek tek test edilecektir.
* SOC Dashboard ekranına girilip Red Flag loglar ve Gerekçeler incelenecek, bekleyen onaylar yönetici panelinden onaylanacaktır.
