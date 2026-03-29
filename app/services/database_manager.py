import os
import logging
import psycopg2
from datetime import datetime

logger = logging.getLogger(__name__)

class DatabaseManager:
    """
    GenAI Security Gateway - Veritabanı Katmanı
    Tüm analiz sonuçlarını yerel PostgreSQL üzerindeki security_logs tablosuna kaydeder [312].
    """
    
    _connection = None

    @classmethod
    def get_connection(cls):
        """Yerel PostgreSQL veritabanı bağlantısını oluşturur veya mevcut olanı döndürür."""
        if cls._connection is None or cls._connection.closed != 0:
            try:
                cls._connection = psycopg2.connect(
                    host=os.getenv("DB_HOST", "localhost"),
                    port=os.getenv("DB_PORT", "5432"),
                    dbname=os.getenv("DB_NAME", "genai_gateway"),
                    user=os.getenv("DB_USER", "postgres"),
                    password=os.getenv("DB_PASSWORD", "")
                )
                logger.info("Yerel PostgreSQL bağlantısı başarılı.")
            except Exception as e:
                logger.error(f"PostgreSQL bağlantı hatası: {e}")
        return cls._connection

    @classmethod
    def log_security_event(cls, log_id: str, user_id: str, masked_prompt: str, 
                           action: str, category: str, stopped_at_layer: str, 
                           ai_score: float, latency_ms: int):
        """
        Güvenlik olayını (Log) veritabanına yazar [330].
        """
        conn = cls.get_connection()
        if not conn:
            logger.error("Veritabanı bağlantısı kurulamadığı için log atlanıyor.")
            return

        try:
            with conn.cursor() as cursor:
                # ER Diyagramına uygun SQL Insert Sorgusu [453]
                query = """
                    INSERT INTO security_logs 
                    (log_id, user_id, masked_prompt, action, category, stopped_at_layer, ai_confidence_score, latency_ms, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                
                # Değerleri tuple olarak hazırlıyoruz
                values = (
                    log_id, user_id, masked_prompt, action, category, 
                    stopped_at_layer, ai_score, latency_ms, datetime.now()
                )
                
                cursor.execute(query, values)
                conn.commit()
                logger.info(f"Log kaydedildi: {log_id} -> {action} ({category})")
                
        except Exception as e:
            logger.error(f"Veritabanına log yazılırken hata oluştu: {e}")
            if conn:
                conn.rollback() # Hata durumunda işlemi geri al