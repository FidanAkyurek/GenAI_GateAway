from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
import uuid

# İstemciden (Client) gelen istek modeli
class PromptRequest(BaseModel):
    text: str = Field(..., description="Analiz edilecek kullanıcı metni")
    user_id: str = Field(..., description="İsteği yapan kullanıcının benzersiz kimliği")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="İstek zamanı")

# API'nin dışarıya döneceği standart yanıt modeli
class PromptResponse(BaseModel):
    log_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="İşlem takip numarası")
    status: str = Field(..., description="'ALLOW' veya 'BLOCK'")
    category: str = Field(default="Safe", description="Tehdit türü (örn: PII, Injection)")
    processed_text: Optional[str] = Field(None, description="Maskelenmiş güvenli metin (DLP çalıştıysa)")
    reason: Optional[str] = Field(None, description="Engellenme sebebi (varsa)")
    latency_ms: Optional[int] = Field(None, description="İşlem süresi")