# Yapılacaklar Listesi

Bu belge, güvenlik sistemi için yapılacak iyileştirme ve değerlendirme adımlarını özetler. Amaç, modelin doğruluk oranını artırmak, threshold ayarlarını optimize etmek ve sistemin daha güçlü bir değerlendirme sürecine sahip olmasını sağlamaktır.

## 1. Değerlendirme Setini Güçlendirme
- Mevcut test setini artırmak için daha fazla prompt eklemek.
- Safe ve unsafe örnekleri dengeli dağılımlı hale getirmek.
- Zorlayıcı örnekler (hard negatives) eklemek.
- Aynı anlamı farklı cümlelerle ifade eden paraphrase örnekleri eklemek.
- Daha gerçekçi üretim senaryolarına uygun promptlar eklemek.

## 2. Safe / Unsafe Denge Ayarı
- Değerlendirme için 50/50 balance test seti kullanmak.
- Daha gerçek dünya benzeri değerlendirme için 80/20 safe/unsafe oranı kullanmak.
- Daha zor ve saldırgan senaryolar için 40/60 unsafe oranı kullanmak.
- Modelin false positive ve false negative dengesini gözlemlemek.
- Özellikle safe örneklerde yanlış bloklama oranını azaltmaya odaklanmak.

## 3. Threshold Optimizasyonu
- Layer 2 için farklı threshold değerlerini test etmek.
- Başlangıçta 0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85 ve 0.90 değerlerini denemek.
- En iyi F1 skorunu veren threshold değerini seçmek.
- Eğer saldırı tespiti daha kritikse recall yüksek değerleri tercih etmek.
- Eğer yanlış alarm daha problemse daha yüksek threshold kullanmak.
- En dengeli başlangıç değeri olarak 0.55 veya 0.60 önerilmektedir.

## 4. Veri Kalitesini Artırma
- Mevcut veri setlerinde daha fazla “hard negative” safe örnek eklemek.
- Unsafe örnekleri daha çeşitli ve daha gerçekçi senaryolara göre genişletmek.
- Aynı türden örneklerin aşırı tekrar etmesini azaltmak.
- Eğitim ve test setleri arasında veri sızıntısını önlemek.
- Her part dosyasını ayrı ayrı inceleyip dengesizlikleri düzeltmek.

## 5. Model Performansını Ölçme
- Accuracy, precision, recall, F1 ve confusion matrix değerlerini düzenli olarak raporlamak.
- Her katman için ayrı ayrı metrik tutmak.
- Katman 1, katman 2 ve katman 3 için ayrı sonuçlar üretmek.
- Raporları JSON veya CSV olarak saklamak.
- Sonuçları zamanla karşılaştırmak için geçmiş raporlar oluşturmak.

## 6. Layer 3 (LLM Judge) İyileştirme
- Layer 3 için Gemini API anahtarı eklemek ve gerçek değerlendirme yapmak.
- Layer 3’ün gerçek performansını ölçmek için ortam değişkenlerini doğru şekilde yapılandırmak.
- API limitleri ve başarısız istekler için retry/rotation mekanizmasını test etmek.
- Layer 3’ün safe/unsafe kararlarını daha tutarlı hale getirmek için sistem promptunu geliştirmek.

## 7. Sistem Geneli İyileştirme
- Modelin yanlış pozitiflerini azaltmak için daha iyi safe örnekleri eklemek.
- Modelin yanlış negatiflerini azaltmak için daha iyi unsafe örnekleri eklemek.
- Threshold ayarlarını veri tabanlı şekilde optimize etmek.
- Değerlendirme scriptini daha otomatik hale getirmek.
- Her yeni veri eklenmesinde yeniden test çalıştırmak.

## 8. Daha İleri Öneriler
- Veri setini artırmak için dış kaynaklardan ek örnekler almak.
- Promptların farklı dillere veya varyasyonlarına göre test etmek.
- Modelin farklı threshold değerleri için precision-recall eğrisini çizmek.
- Farklı model sürümleriyle karşılaştırma yapmak.
- Sistem performansını hem doğruluk hem de hız açısından birlikte değerlendirmek.

## 9. Öncelik Sırası
1. Test setini büyütmek.
2. Safe/unsafe dengesini iyileştirmek.
3. Threshold değerlerini optimize etmek.
4. Layer 3 için gerçek API desteğini aktif hale getirmek.
5. Raporlama ve otomasyon sürecini güçlendirmek.
