import os
from pydantic import BaseModel
from typing import List

def _split_csv(v: str) -> List[str]:
    if not v:
        return []
    return [x.strip() for x in v.split(",") if x.strip()]

class Settings(BaseModel):
    # Security
    JWT_SECRET: str = os.getenv("JWT_SECRET", "dev-secret-change-me")
    JWT_ALG: str = os.getenv("JWT_ALG", "HS256")
    JWT_EXPIRES_MIN: int = int(os.getenv("JWT_EXPIRES_MIN", "10080"))  # 7 days

    # CORS
    CORS_ALLOW_ORIGINS: List[str] = _split_csv(os.getenv("CORS_ALLOW_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"))

    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./app.db")

    # Shopify (optional for MVP; wire later)
    SHOPIFY_SHOP_DOMAIN: str = os.getenv("SHOPIFY_SHOP_DOMAIN", "")
    SHOPIFY_ACCESS_TOKEN: str = os.getenv("SHOPIFY_ACCESS_TOKEN", "")
    SHOPIFY_API_VERSION: str = os.getenv("SHOPIFY_API_VERSION", "2024-04")
    SHOPIFY_WEBHOOK_SECRET: str = os.getenv("SHOPIFY_WEBHOOK_SECRET", "")  # used to verify webhooks (HMAC)

    # Business rules
    VIP_DISCOUNT_PERCENT: int = int(os.getenv("VIP_DISCOUNT_PERCENT", "12"))
    VIP_BONUS_MIN_ORDER_GBP: float = float(os.getenv("VIP_BONUS_MIN_ORDER_GBP", "15"))
    VIP_BONUS_CREDITS: int = int(os.getenv("VIP_BONUS_CREDITS", "1"))

    # Moderation
    MODERATION_HIDE_ON_RISK: bool = os.getenv("MODERATION_HIDE_ON_RISK", "true").lower() == "true"

settings = Settings()
