import os
import logging
import asyncpg
import aiosqlite
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

# SQLite fallback: PostgreSQL yoksa SQLite kullan (geliştirme ortamı için)
USE_SQLITE = os.getenv("USE_SQLITE", "true").lower() == "true"
SQLITE_PATH = os.getenv("SQLITE_PATH", "genai_gateway.db")


class DatabaseManager:
    """
    GenAI Security Gateway - Veritabanı Katmanı
    Tüm analiz sonuçlarını security_logs tablosuna kaydeder.
    PostgreSQL (üretim) veya SQLite (geliştirme) kullanır.
    """

    _pool: Optional[asyncpg.Pool] = None
    _sqlite_initialized: bool = False

    # ─── TABLO OLUŞTURMA SQL ───────────────────────────────────────────────────
    CREATE_TABLE_SQL = """
        CREATE TABLE IF NOT EXISTS security_logs (
            log_id              TEXT PRIMARY KEY,
            user_id             TEXT NOT NULL,
            masked_prompt       TEXT,
            action              TEXT NOT NULL,
            category            TEXT NOT NULL,
            stopped_at_layer    TEXT,
            ai_confidence_score REAL DEFAULT 0.0,
            latency_ms          INTEGER DEFAULT 0,
            created_at          TEXT NOT NULL
        )
    """

    CREATE_USERS_TABLE_SQL = """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            phone TEXT,
            full_name TEXT DEFAULT '',
            profile_photo TEXT,
            role TEXT DEFAULT 'user',
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """

    # ─── PostgreSQL BAĞLANTISI ─────────────────────────────────────────────────
    @classmethod
    async def init_postgres(cls):
        """PostgreSQL bağlantı havuzu oluşturur."""
        try:
            cls._pool = await asyncpg.create_pool(
                host=os.getenv("DB_HOST", "localhost"),
                port=int(os.getenv("DB_PORT", "5432")),
                database=os.getenv("DB_NAME", "genai_gateway"),
                user=os.getenv("DB_USER", "postgres"),
                password=os.getenv("DB_PASSWORD", ""),
                min_size=2,
                max_size=10,
            )
            async with cls._pool.acquire() as conn:
                await conn.execute(cls.CREATE_TABLE_SQL)
                # Note: AUTOINCREMENT is sqlite specific, PostgreSQL uses SERIAL
                pg_create_users = """
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT,
                        phone TEXT,
                        full_name TEXT DEFAULT '',
                        profile_photo TEXT,
                        role TEXT DEFAULT 'user',
                        password_hash TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )
                """
                await conn.execute(pg_create_users)
            logger.info("✅ PostgreSQL bağlantısı ve tablo başarıyla hazırlandı.")
        except Exception as e:
            logger.error(f"❌ PostgreSQL bağlantı hatası: {e}")
            cls._pool = None

    # ─── SQLite BAŞLATMA ───────────────────────────────────────────────────────
    @classmethod
    async def init_sqlite(cls):
        """SQLite veritabanını ve tabloyu oluşturur."""
        try:
            async with aiosqlite.connect(SQLITE_PATH) as db:
                await db.execute(cls.CREATE_TABLE_SQL)
                await db.execute(cls.CREATE_USERS_TABLE_SQL)
                await db.commit()
            cls._sqlite_initialized = True
            logger.info(f"✅ SQLite veritabanı hazırlandı: {SQLITE_PATH}")
        except Exception as e:
            logger.error(f"❌ SQLite başlatma hatası: {e}")

    # ─── GENEL BAŞLATMA ───────────────────────────────────────────────────────
    @classmethod
    async def initialize(cls):
        """Uygulama başlarken çağrılır. DB tipine göre başlatma yapar."""
        if USE_SQLITE:
            await cls.init_sqlite()
        else:
            await cls.init_postgres()

    # ─── LOG KAYDETME ─────────────────────────────────────────────────────────
    @classmethod
    async def log_security_event(
        cls,
        log_id: str,
        user_id: str,
        masked_prompt: str,
        action: str,
        category: str,
        stopped_at_layer: str,
        ai_score: float,
        latency_ms: int,
    ):
        """Güvenlik olayını asenkron olarak veritabanına yazar."""
        created_at = datetime.now().isoformat()

        if USE_SQLITE:
            await cls._log_sqlite(
                log_id, user_id, masked_prompt, action,
                category, stopped_at_layer, ai_score, latency_ms, created_at
            )
        else:
            await cls._log_postgres(
                log_id, user_id, masked_prompt, action,
                category, stopped_at_layer, ai_score, latency_ms, created_at
            )

    @classmethod
    async def _log_sqlite(cls, log_id, user_id, masked_prompt, action,
                          category, stopped_at_layer, ai_score, latency_ms, created_at):
        try:
            async with aiosqlite.connect(SQLITE_PATH) as db:
                await db.execute(
                    """INSERT INTO security_logs
                       (log_id, user_id, masked_prompt, action, category,
                        stopped_at_layer, ai_confidence_score, latency_ms, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (log_id, user_id, masked_prompt, action, category,
                     stopped_at_layer, ai_score, latency_ms, created_at)
                )
                await db.commit()
                logger.info(f"📝 Log kaydedildi → {log_id} | {action} ({category})")
        except Exception as e:
            logger.error(f"❌ SQLite log hatası: {e}")

    @classmethod
    async def _log_postgres(cls, log_id, user_id, masked_prompt, action,
                             category, stopped_at_layer, ai_score, latency_ms, created_at):
        if not cls._pool:
            logger.warning("⚠️ PostgreSQL bağlantısı yok, log atlanıyor.")
            return
        try:
            async with cls._pool.acquire() as conn:
                await conn.execute(
                    """INSERT INTO security_logs
                       (log_id, user_id, masked_prompt, action, category,
                        stopped_at_layer, ai_confidence_score, latency_ms, created_at)
                       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)""",
                    log_id, user_id, masked_prompt, action, category,
                    stopped_at_layer, ai_score, latency_ms, created_at
                )
                logger.info(f"📝 Log kaydedildi → {log_id} | {action} ({category})")
        except Exception as e:
            logger.error(f"❌ PostgreSQL log hatası: {e}")

    # ─── LOG LİSTELEME ────────────────────────────────────────────────────────
    @classmethod
    async def get_logs(cls, limit: int = 50, action_filter: Optional[str] = None,
                       category_filter: Optional[str] = None) -> list:
        """Log kayıtlarını filtreli olarak getirir."""
        if USE_SQLITE:
            return await cls._get_logs_sqlite(limit, action_filter, category_filter)
        else:
            return await cls._get_logs_postgres(limit, action_filter, category_filter)

    @classmethod
    async def _get_logs_sqlite(cls, limit, action_filter, category_filter) -> list:
        try:
            query = "SELECT * FROM security_logs WHERE 1=1"
            params = []
            if action_filter:
                query += " AND action = ?"
                params.append(action_filter.upper())
            if category_filter:
                query += " AND category = ?"
                params.append(category_filter)
            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)

            async with aiosqlite.connect(SQLITE_PATH) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute(query, params) as cursor:
                    rows = await cursor.fetchall()
                    return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"❌ SQLite log okuma hatası: {e}")
            return []

    @classmethod
    async def _get_logs_postgres(cls, limit, action_filter, category_filter) -> list:
        if not cls._pool:
            return []
        try:
            query = "SELECT * FROM security_logs WHERE 1=1"
            params = []
            i = 1
            if action_filter:
                query += f" AND action = ${i}"
                params.append(action_filter.upper())
                i += 1
            if category_filter:
                query += f" AND category = ${i}"
                params.append(category_filter)
                i += 1
            query += f" ORDER BY created_at DESC LIMIT ${i}"
            params.append(limit)

            async with cls._pool.acquire() as conn:
                rows = await conn.fetch(query, *params)
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"❌ PostgreSQL log okuma hatası: {e}")
            return []

    # ─── FEEDBACK KAYDETME ────────────────────────────────────────────────────
    @classmethod
    async def save_feedback(cls, log_id: str, correct_label: str) -> bool:
        """False positive bildirimi için log kaydını günceller."""
        # Şimdilik log'a feedback_label sütunu yok, ileride eklenebilir.
        # Şimdilik sadece logluyoruz.
        logger.info(f"📣 Feedback alındı → log_id={log_id}, correct_label={correct_label}")
        return True

    # ─── İSTATİSTİKLER ────────────────────────────────────────────────────────
    @classmethod
    async def get_stats(cls) -> dict:
        """Dashboard için özet istatistikleri döner."""
        if USE_SQLITE:
            return await cls._get_stats_sqlite()
        return {}

    @classmethod
    async def _get_stats_sqlite(cls) -> dict:
        try:
            async with aiosqlite.connect(SQLITE_PATH) as db:
                async with db.execute("SELECT COUNT(*) FROM security_logs") as c:
                    total = (await c.fetchone())[0]
                async with db.execute("SELECT COUNT(*) FROM security_logs WHERE action='BLOCK'") as c:
                    blocked = (await c.fetchone())[0]
                async with db.execute("SELECT COUNT(*) FROM security_logs WHERE action='ALLOW'") as c:
                    allowed = (await c.fetchone())[0]
                async with db.execute("SELECT AVG(latency_ms) FROM security_logs") as c:
                    avg_latency = (await c.fetchone())[0] or 0
                return {
                    "total_requests": total,
                    "blocked": blocked,
                    "allowed": allowed,
                    "avg_latency_ms": round(avg_latency, 1),
                }
        except Exception as e:
            logger.error(f"❌ Stats hatası: {e}")
            return {}

    # ─── KULLANICI (AUTH) YÖNETİMİ ──────────────────────────────────────────────
    @classmethod
    async def create_user(
        cls, 
        username: str, 
        password_hash: str, 
        email: str = None, 
        phone: str = None, 
        full_name: str = "", 
        role: str = "user"
    ) -> bool:
        """Yeni bir kullanıcı oluşturur."""
        created_at = datetime.now().isoformat()
        if USE_SQLITE:
            try:
                async with aiosqlite.connect(SQLITE_PATH) as db:
                    await db.execute(
                        """INSERT INTO users (username, password_hash, email, phone, full_name, role, created_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (username, password_hash, email, phone, full_name, role, created_at)
                    )
                    await db.commit()
                return True
            except Exception as e:
                logger.error(f"❌ Kullanıcı oluşturma hatası (SQLite): {e}")
                return False
        else:
            if not cls._pool: return False
            try:
                async with cls._pool.acquire() as conn:
                    await conn.execute(
                        """INSERT INTO users (username, password_hash, email, phone, full_name, role, created_at)
                           VALUES ($1, $2, $3, $4, $5, $6, $7)""",
                        username, password_hash, email, phone, full_name, role, created_at
                    )
                return True
            except Exception as e:
                logger.error(f"❌ Kullanıcı oluşturma hatası (PostgreSQL): {e}")
                return False

    @classmethod
    async def get_user_by_username(cls, username: str) -> Optional[dict]:
        """Kullanıcı ismine göre kullanıcı bilgisini getirir."""
        if USE_SQLITE:
            try:
                async with aiosqlite.connect(SQLITE_PATH) as db:
                    db.row_factory = aiosqlite.Row
                    async with db.execute("SELECT * FROM users WHERE username = ?", (username,)) as cursor:
                        row = await cursor.fetchone()
                        return dict(row) if row else None
            except Exception as e:
                logger.error(f"❌ Kullanıcı getirme hatası: {e}")
                return None
        else:
            if not cls._pool: return None
            try:
                async with cls._pool.acquire() as conn:
                    row = await conn.fetchrow("SELECT * FROM users WHERE username = $1", username)
                    return dict(row) if row else None
            except Exception as e:
                logger.error(f"❌ Kullanıcı getirme hatası: {e}")
                return None

    @classmethod
    async def update_user_profile(cls, username: str, update_data: dict) -> bool:
        """Kullanıcı profil verilerini (email, phone, full_name, profile_photo) günceller."""
        if not update_data: return True
        
        sets = []
        values = []
        for i, (k, v) in enumerate(update_data.items()):
            sets.append(f"{k} = {'?' if USE_SQLITE else f'${i+1}'}")
            values.append(v)
            
        values.append(username)
        where_clause = f"username = {'?' if USE_SQLITE else f'${len(values)}'}"
        
        query = f"UPDATE users SET {', '.join(sets)} WHERE {where_clause}"
        
        try:
            if USE_SQLITE:
                async with aiosqlite.connect(SQLITE_PATH) as db:
                    await db.execute(query, tuple(values))
                    await db.commit()
            else:
                async with cls._pool.acquire() as conn:
                    await conn.execute(query, *values)
            return True
        except Exception as e:
            logger.error(f"❌ Profil güncelleme hatası: {e}")
            return False

    @classmethod
    async def update_user_password(cls, username: str, password_hash: str) -> bool:
        """Kullanıcının şifresini günceller."""
        query = "UPDATE users SET password_hash = ? WHERE username = ?" if USE_SQLITE else "UPDATE users SET password_hash = $1 WHERE username = $2"
        try:
            if USE_SQLITE:
                async with aiosqlite.connect(SQLITE_PATH) as db:
                    await db.execute(query, (password_hash, username))
                    await db.commit()
            else:
                async with cls._pool.acquire() as conn:
                    await conn.execute(query, password_hash, username)
            return True
        except Exception as e:
            logger.error(f"❌ Şifre güncelleme hatası: {e}")
            return False