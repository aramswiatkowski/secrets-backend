from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime

# Auth
class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

# Me
class MeOut(BaseModel):
    email: EmailStr
    nickname: Optional[str] = None
    plan: Optional[str] = None
    subscription_status: str = "inactive"
    vip_discount_percent: int

class NicknameIn(BaseModel):
    nickname: str = Field(min_length=2, max_length=24)

# Plans
class PlanOut(BaseModel):
    key: str
    name: str
    price_gbp: float
    includes: List[str]

# Credits
class CreditBalanceOut(BaseModel):
    balance: int

class LedgerItemOut(BaseModel):
    delta: int
    reason: str
    ref_id: Optional[str] = None
    created_at: datetime

class RedeemItemIn(BaseModel):
    size: str  # A4 or A3
    variant_id: Optional[str] = None  # Shopify variant ID (wire later)
    title: Optional[str] = None       # display only

class RedeemIn(BaseModel):
    items: List[RedeemItemIn]
    shipping_required: bool = True

class RedeemOut(BaseModel):
    ok: bool
    credits_used: int
    new_balance: int
    shopify_order_ref: Optional[str] = None

# Community
class PostCreateIn(BaseModel):
    kind: str = Field(pattern="^(question|showcase)$")
    title: Optional[str] = Field(default=None, max_length=120)
    content: str = Field(min_length=1, max_length=4000)
    image_url: Optional[str] = None

class PostOut(BaseModel):
    id: int
    kind: str
    title: Optional[str]
    content: str
    image_url: Optional[str]
    status: str
    risk_flags: Optional[str]
    created_at: datetime
    author_nickname: Optional[str]

# Admin
class AdminSetPlanIn(BaseModel):
    email: EmailStr
    plan: str  # vip_digital | vip_print | pro_studio
    status: str = "active"
