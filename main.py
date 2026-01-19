from __future__ import annotations

import os
import re
import uuid
import json
import base64
import hashlib
import hmac
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status, Body, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm  # <-- CHANGED
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlmodel import SQLModel, Field, Session, create_engine, select

from sqlalchemy import text  # <-- IMPORTANT (for Postgres auto-migration)

import httpx

# Optional web-push support (works if you install pywebpush)
try:
    from pywebpush import webpush, WebPushException
except Exception:
    webpush = None
    WebPushException = Exception

APP_NAME = "Secrets of Decoupage"

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./secrets_app.db")
# Render often provides postgres:// which SQLAlchemy may not accept
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Prefer psycopg (psycopg3) driver on modern Python (e.g., 3.13 on Render)
# to avoid psycopg2 wheel/compile issues.
if DATABASE_URL.split("://", 1)[0] == "postgresql":
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_ME__USE_A_LONG_RANDOM_SECRET")
JWT_ALG = "HS256"
ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "43200"))  # 30 days default

# ---------------- VIP PLANS & CREDITS ----------------

PLAN_FREE = "FREE"
PLAN_VIP_DIGITAL = "VIP_DIGITAL"
PLAN_VIP_PRINT = "VIP_PRINT"
PLAN_PRO = "PRO_STUDIO"

PLAN_DISCOUNT_PERCENT = {
    PLAN_FREE: 0,
    PLAN_VIP_DIGITAL: 10,
    PLAN_VIP_PRINT: 10,
    PLAN_PRO: 12,
}

MONTHLY_CREDITS = {
    PLAN_FREE: 0,
    PLAN_VIP_DIGITAL: 0,
    PLAN_VIP_PRINT: 4,
    PLAN_PRO: 8,
}

# Credit cost rules (as agreed): A4=1, A5=1, Greeting Cards=1, A3=2
CREDIT_COSTS = {
    "A4": 1,
    "A5": 1,
    "GREETING": 1,
    "A3": 2,
}

CREDIT_UNIT_GBP = float(os.getenv("CREDIT_UNIT_GBP", "2.97"))

# Shopify (Admin API) integration
SHOPIFY_SHOP_DOMAIN = (os.getenv("SHOPIFY_SHOP_DOMAIN", "") or "").strip()
SHOPIFY_ADMIN_API_ACCESS_TOKEN = (os.getenv("SHOPIFY_ADMIN_API_ACCESS_TOKEN", "") or "").strip()
SHOPIFY_API_VERSION = (os.getenv("SHOPIFY_API_VERSION", "2026-01") or "2026-01").strip()
SHOPIFY_WEBHOOK_SECRET = (os.getenv("SHOPIFY_WEBHOOK_SECRET", "") or "").strip()

# Optional mapping by SKU (preferred) or by title keywords (fallback)
VIP_DIGITAL_SKU = (os.getenv("VIP_DIGITAL_SKU", "") or "").strip()
VIP_PRINT_SKU = (os.getenv("VIP_PRINT_SKU", "") or "").strip()
PRO_STUDIO_SKU = (os.getenv("PRO_STUDIO_SKU", "") or "").strip()

VIP_DIGITAL_TITLE_KEYWORD = (os.getenv("VIP_DIGITAL_TITLE_KEYWORD", "VIP Digital") or "VIP Digital").strip()
VIP_PRINT_TITLE_KEYWORD = (os.getenv("VIP_PRINT_TITLE_KEYWORD", "VIP Print Pack") or "VIP Print Pack").strip()
PRO_STUDIO_TITLE_KEYWORD = (os.getenv("PRO_STUDIO_TITLE_KEYWORD", "PRO Studio") or "PRO Studio").strip()

VAPID_PUBLIC_KEY = os.getenv("VAPID_PUBLIC_KEY", "")
VAPID_PRIVATE_KEY = os.getenv("VAPID_PRIVATE_KEY", "")
VAPID_SUBJECT = os.getenv("VAPID_SUBJECT", "mailto:support@secretsofdecoupage.com")

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token", auto_error=False)  # <-- CHANGED

engine = create_engine(
    DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)

# ---------------- MODELS ----------------

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    display_name: str = Field(default="", index=True)
    hashed_password: str
    is_admin: bool = False
    plan: str = Field(default=PLAN_FREE, index=True)
    is_vip: bool = False
    credits_balance: int = Field(default=0)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Trick(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str
    body: str
    media_url: Optional[str] = None
    is_vip: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Post(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(index=True, foreign_key="user.id")
    text: str
    image_url: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Comment(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    post_id: int = Field(index=True, foreign_key="post.id")
    user_id: int = Field(index=True, foreign_key="user.id")
    text: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PushSubscription(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: Optional[int] = Field(default=None, index=True, foreign_key="user.id")
    endpoint: str
    p256dh: str
    auth: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------- MODERATION & SUPPORT ----------------

class ModerationItem(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    content_type: str = Field(index=True)  # "post" or "comment"
    content_id: int = Field(index=True)
    status: str = Field(default="approved", index=True)  # approved | hidden | pending
    reports: int = Field(default=0)
    reason: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SupportTicket(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(index=True, foreign_key="user.id")
    subject: str
    message: str
    order_number: Optional[str] = None
    image_url: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CreditLedger(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(index=True, foreign_key="user.id")
    delta: int
    reason: str = Field(default="")
    ref_type: Optional[str] = Field(default=None, index=True)
    ref_id: Optional[str] = Field(default=None, index=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CreditRedemption(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(index=True, foreign_key="user.id")
    credits_used: int
    amount_gbp: float
    code: str = Field(index=True)
    shopify_discount_gid: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ShopifyOrderRecord(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(index=True, foreign_key="user.id")
    shopify_order_id: str = Field(index=True, unique=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# ---------------- HELPERS ----------------

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


def ensure_sqlite_schema():
    """Best-effort schema upgrades for existing SQLite files (Render free instances)."""
    if not DATABASE_URL.startswith("sqlite"):
        return
    try:
        with engine.connect() as conn:
            rows = conn.exec_driver_sql('PRAGMA table_info("user");').fetchall()
            cols = {r[1] for r in rows}  # r[1] = column name

            # Older DBs may miss these columns
            if "display_name" not in cols:
                conn.exec_driver_sql('ALTER TABLE "user" ADD COLUMN display_name VARCHAR;')
                conn.commit()
            if "plan" not in cols:
                conn.exec_driver_sql('ALTER TABLE "user" ADD COLUMN plan VARCHAR;')
                conn.commit()
            if "credits_balance" not in cols:
                conn.exec_driver_sql('ALTER TABLE "user" ADD COLUMN credits_balance INTEGER DEFAULT 0;')
                conn.commit()
            if "is_vip" not in cols:
                conn.exec_driver_sql('ALTER TABLE "user" ADD COLUMN is_vip BOOLEAN DEFAULT 0;')
                conn.commit()
            if "is_admin" not in cols:
                conn.exec_driver_sql('ALTER TABLE "user" ADD COLUMN is_admin BOOLEAN DEFAULT 0;')
                conn.commit()

            # Backfill defaults (SQLite)
            conn.exec_driver_sql('UPDATE "user" SET credits_balance = 0 WHERE credits_balance IS NULL;')
            conn.exec_driver_sql(f'UPDATE "user" SET plan = "{PLAN_FREE}" WHERE plan IS NULL;')
            conn.commit()

    except Exception as e:
        # Don't crash the app if migration fails; tables will still exist.
        print(f"[SCHEMA] ensure_sqlite_schema failed: {e}")


def ensure_postgres_schema():
    """
    Best-effort schema upgrades for existing Postgres DB (Render FREE has no shell).
    Fixes: column "user".plan does not exist (and similar).
    """
    # DATABASE_URL can be normalized to "postgresql+psycopg://..."
    if not DATABASE_URL.startswith("postgresql"):
        return

    try:
        with engine.begin() as conn:
            # Add missing columns safely
            conn.execute(text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS display_name VARCHAR;'))
            conn.execute(text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS plan VARCHAR(32);'))
            conn.execute(text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS credits_balance INTEGER DEFAULT 0;'))
            conn.execute(text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS is_vip BOOLEAN DEFAULT FALSE;'))
            conn.execute(text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE;'))

            # Backfill NULLs so API never crashes on assumptions
            conn.execute(text('UPDATE "user" SET credits_balance = 0 WHERE credits_balance IS NULL;'))
            conn.execute(text('UPDATE "user" SET is_vip = FALSE WHERE is_vip IS NULL;'))
            conn.execute(text('UPDATE "user" SET is_admin = FALSE WHERE is_admin IS NULL;'))

            # Backfill plan:
            # - if is_vip true and plan missing -> VIP_DIGITAL
            # - else -> FREE
            conn.execute(
                text("""
                    UPDATE "user"
                    SET plan = CASE
                        WHEN (is_vip = TRUE) THEN :vip
                        ELSE :free
                    END
                    WHERE plan IS NULL;
                """),
                {"vip": PLAN_VIP_DIGITAL, "free": PLAN_FREE},
            )

    except Exception as e:
        # Don't kill startup if migration has a hiccup
        print(f"[SCHEMA] ensure_postgres_schema failed: {e}")


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)

# --- Content safety (keep community focused on decoupage) ---
_STORE_ISSUE_PATTERNS = [
    r"\border\b", r"\border\s*#?\d+", r"#\d{3,8}",
    r"\bshipping\b", r"\bdelivery\b", r"\btracking\b",
    r"\brefund\b", r"\bchargeback\b", r"\bfraud\b", r"\bscam\b",
    r"\bnot\s+received\b", r"didn'?t\s+arrive", r"\bmissing\b", r"\bdamaged\b",
    r"\betsy\b", r"\bshopify\b", r"\bmy\s+order\b", r"\border\s+number\b",
    r"\bcustomer\s+service\b", r"\bcomplain\b", r"\bcomplaint\b",
]

def _looks_like_store_issue(text: str) -> bool:
    t = (text or "").lower()
    for p in _STORE_ISSUE_PATTERNS:
        try:
            if re.search(p, t):
                return True
        except re.error:
            continue
    return False

def _extract_order_number(text: str) -> Optional[str]:
    t = (text or "")
    m = re.search(r"(?:order\s*#?|#)\s*(\d{3,8})", t, flags=re.I)
    return m.group(1) if m else None


_PROMO_PATTERNS = [
    # links
    r"https?://",
    r"\bwww\.",
    # emails
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
    # phone numbers (very loose)
    r"\+?\d[\d\s().-]{7,}\d",
    # advertising phrases
    r"\bmy\s+(shop|store|etsy|amazon|website)\b",
    r"\bvisit\s+my\b",
    r"\bbuy\s+from\b",
    r"\bselling\s+on\b",
]


def _looks_like_promo_or_contact(text: str) -> bool:
    t = (text or "")
    for p in _PROMO_PATTERNS:
        try:
            if re.search(p, t, flags=re.I):
                return True
        except re.error:
            continue
    return False


def _ensure_moderation(session: Session, content_type: str, content_id: int, status: str = "approved", reason: Optional[str] = None):
    existing = session.exec(
        select(ModerationItem)
        .where(ModerationItem.content_type == content_type)
        .where(ModerationItem.content_id == content_id)
    ).first()
    if existing:
        existing.status = status
        if reason:
            existing.reason = reason
        session.add(existing)
        session.commit()
        return existing

    item = ModerationItem(content_type=content_type, content_id=content_id, status=status, reason=reason)
    session.add(item)
    session.commit()
    return item

def _get_mod_map(session: Session, content_type: str):
    items = session.exec(select(ModerationItem).where(ModerationItem.content_type == content_type)).all()
    return {i.content_id: i for i in items}

def create_access_token(user_id: int) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_MINUTES)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def get_user_from_token(token: str) -> User:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id = int(payload.get("sub"))
    except (JWTError, TypeError, ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    with Session(engine) as session:
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        return user


def current_user(token: str = Depends(oauth2_scheme)) -> User:
    return get_user_from_token(token)


def admin_user(user: User = Depends(current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin only")
    return user


def _display_name_for(user: Optional[User]) -> str:
    if not user:
        return "Member"
    dn = (user.display_name or "").strip()
    return dn if dn else f"Member #{user.id}"


# ---------------- APP ----------------

app = FastAPI(title=f"{APP_NAME} API", version="0.1.0")

# --- Media uploads (MVP) ---
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "./uploads"))
try:
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    # Render free instances can be restrictive; fall back to /tmp
    UPLOAD_DIR = Path("/tmp/uploads")
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "10"))
# Serve uploaded files
app.mount("/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")


# CORS – iPhone/Netlify
def _cors_origins() -> list[str]:
    # Defaults + local dev
    defaults = [
        "https://thesecretsofdecoupagecom.netlify.app",
        "https://thesecretsofdecoupage.com",
        "https://app.thesecretsofdecoupage.com",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]

    env = (os.getenv("CORS_ALLOW_ORIGINS", "") or "").strip()
    extra = [o.strip() for o in env.split(",") if o.strip()] if env else []

    # unique, preserve order
    out: list[str] = []
    for o in defaults + extra:
        if o not in out:
            out.append(o)
    return out


app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    # Create tables first (if DB is empty)
    create_db_and_tables()

    # Best-effort migrations (won't crash app)
    ensure_sqlite_schema()
    ensure_postgres_schema()

    # TEMP BOOTSTRAP (admin+vip + create/reset password)
    # Requires Render env vars:
    #   BOOTSTRAP_EMAIL=aramedultd@gmail.com
    #   BOOTSTRAP_PASSWORD=Aram1971
    bootstrap_email = os.getenv("BOOTSTRAP_EMAIL", "").strip().lower()
    bootstrap_password = os.getenv("BOOTSTRAP_PASSWORD", "")
    bootstrap_display_name = os.getenv("BOOTSTRAP_DISPLAY_NAME", "Admin").strip()

    if bootstrap_email and bootstrap_password:
        with Session(engine) as session:
            u = session.exec(select(User).where(User.email == bootstrap_email)).first()
            if not u:
                u = User(
                    email=bootstrap_email,
                    hashed_password=hash_password(bootstrap_password),
                    display_name=bootstrap_display_name or "Admin",
                    is_admin=True,
                    is_vip=True,
                    plan=PLAN_PRO,
                )
                session.add(u)
                session.commit()
                print(f"[BOOTSTRAP] Created user {bootstrap_email} as admin+vip")
            else:
                u.hashed_password = hash_password(bootstrap_password)
                u.is_admin = True
                u.is_vip = True
                u.plan = PLAN_PRO
                if not (u.display_name or "").strip():
                    u.display_name = bootstrap_display_name or "Admin"
                session.add(u)
                session.commit()
                print(f"[BOOTSTRAP] Updated user {bootstrap_email} password + admin+vip")

    # Ensure every existing user has a non-empty display_name (never expose email publicly)
    try:
        with Session(engine) as session:
            users = session.exec(select(User)).all()
            changed = 0
            for u in users:
                if not (u.display_name or "").strip():
                    u.display_name = f"Member #{u.id}"
                    session.add(u)
                    changed += 1
            if changed:
                session.commit()
                print(f"[SCHEMA] Filled missing display_name for {changed} users")
    except Exception as e:
        print(f"[SCHEMA] Fill display_name failed: {e}")

    # Backfill plans for older databases (when we only had is_vip).
    try:
        with Session(engine) as session:
            users = session.exec(select(User)).all()
            changed = 0
            for u in users:
                if u.is_vip and ((u.plan or "").strip() in ("", PLAN_FREE)):
                    u.plan = PLAN_VIP_DIGITAL
                    session.add(u)
                    changed += 1
                if (not u.is_vip) and ((u.plan or "").strip() == ""):
                    u.plan = PLAN_FREE
                    session.add(u)
                    changed += 1
            if changed:
                session.commit()
                print(f"[SCHEMA] Backfilled plan for {changed} users")
    except Exception as e:
        print(f"[SCHEMA] Backfill plan failed: {e}")


@app.get("/")
def root():
    # makes Render / browser show OK instead of 404
    return {"ok": True, "name": APP_NAME}


@app.get("/health")
def health():
    return {"ok": True, "name": APP_NAME}


# ---------------- AUTH ----------------

class AuthRegister(SQLModel):
    email: str
    password: str
    display_name: str


class AuthLogin(SQLModel):
    username: str  # OAuth2 expects "username"
    password: str


@app.post("/auth/register")
def register(payload: AuthRegister):
    email = payload.email.strip().lower()
    if "@" not in email:
        raise HTTPException(400, "Invalid email")
    if len(payload.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")

    display_name = (payload.display_name or "").strip()
    if len(display_name) < 2:
        raise HTTPException(400, "Display name is required")
    if len(display_name) > 32:
        raise HTTPException(400, "Display name must be 32 characters or less")

    with Session(engine) as session:
        existing = session.exec(select(User).where(User.email == email)).first()
        if existing:
            raise HTTPException(409, "Email already registered")

        user = User(email=email, hashed_password=hash_password(payload.password), display_name=display_name)
        session.add(user)
        session.commit()
        session.refresh(user)

        token = create_access_token(user.id)
        return {"access_token": token, "token_type": "bearer"}


@app.post("/auth/login")
def login(form: AuthLogin):
    email = form.username.strip().lower()
    with Session(engine) as session:
        user = session.exec(select(User).where(User.email == email)).first()
        if not user or not verify_password(form.password, user.hashed_password):
            raise HTTPException(status_code=401, detail="Incorrect email or password")
        token = create_access_token(user.id)
        return {"access_token": token, "token_type": "bearer"}


# ✅ NEW: Swagger "Authorize" needs FORM (x-www-form-urlencoded)
@app.post("/auth/token")
def token(form_data: OAuth2PasswordRequestForm = Depends()):
    return login(AuthLogin(username=form_data.username, password=form_data.password))


@app.get("/me")
def me(user: User = Depends(current_user)):
    plan = (user.plan or PLAN_FREE).strip() or PLAN_FREE
    return {
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "is_admin": user.is_admin,
        "is_vip": user.is_vip,
        "plan": plan,
        "discount_percent": PLAN_DISCOUNT_PERCENT.get(plan, 0),
        "monthly_credits": MONTHLY_CREDITS.get(plan, 0),
        "credits_balance": int(user.credits_balance or 0),
        "credit_costs": CREDIT_COSTS,
    }


class PasswordChange(SQLModel):
    old_password: str
    new_password: str


@app.post("/me/password")
def change_password(payload: PasswordChange, user: User = Depends(current_user)):
    old_pw = (payload.old_password or "").strip()
    new_pw = (payload.new_password or "").strip()
    if not old_pw or not new_pw:
        raise HTTPException(400, "Both old_password and new_password are required")
    if len(new_pw) < 8:
        raise HTTPException(400, "New password must be at least 8 characters")

    with Session(engine) as session:
        u = session.get(User, user.id)
        if not u:
            raise HTTPException(401, "User not found")
        if not verify_password(old_pw, u.hashed_password):
            raise HTTPException(status_code=401, detail="Incorrect current password")
        u.hashed_password = hash_password(new_pw)
        session.add(u)
        session.commit()

    return {"ok": True}


# ---------------- VIP / CREDITS / SHOPIFY ----------------

def _shopify_ready() -> bool:
    return bool(SHOPIFY_SHOP_DOMAIN and SHOPIFY_ADMIN_API_ACCESS_TOKEN)


def _shopify_graphql(query: str, variables: dict | None = None):
    if not _shopify_ready():
        raise HTTPException(status_code=501, detail="Shopify integration not configured")

    url = f"https://{SHOPIFY_SHOP_DOMAIN}/admin/api/{SHOPIFY_API_VERSION}/graphql.json"
    headers = {
        "X-Shopify-Access-Token": SHOPIFY_ADMIN_API_ACCESS_TOKEN,
        "Content-Type": "application/json",
    }
    payload = {"query": query, "variables": variables or {}}
    try:
        with httpx.Client(timeout=20.0) as client:
            r = client.post(url, headers=headers, json=payload)
            r.raise_for_status()
            data = r.json()
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Shopify request failed: {e}")

    if isinstance(data, dict) and data.get("errors"):
        # top-level graphql errors
        raise HTTPException(status_code=502, detail=str(data.get("errors")))
    return data


def _shopify_customer_id_by_email(email: str) -> Optional[str]:
    q = """
    query($q:String!) {
      customers(first: 1, query: $q) {
        nodes { id email }
      }
    }
    """
    data = _shopify_graphql(q, {"q": f"email:{email}"})
    nodes = (((data or {}).get("data") or {}).get("customers") or {}).get("nodes") or []
    if not nodes:
        return None
    return nodes[0].get("id")


def _detect_plan_from_line_items(line_items: list[dict]) -> Optional[str]:
    for li in line_items or []:
        sku = str(li.get("sku") or "").strip()
        title = str(li.get("title") or "").strip()
        t = title.lower()

        if VIP_DIGITAL_SKU and sku == VIP_DIGITAL_SKU:
            return PLAN_VIP_DIGITAL
        if VIP_PRINT_SKU and sku == VIP_PRINT_SKU:
            return PLAN_VIP_PRINT
        if PRO_STUDIO_SKU and sku == PRO_STUDIO_SKU:
            return PLAN_PRO

        if VIP_DIGITAL_TITLE_KEYWORD and VIP_DIGITAL_TITLE_KEYWORD.lower() in t:
            return PLAN_VIP_DIGITAL
        if VIP_PRINT_TITLE_KEYWORD and VIP_PRINT_TITLE_KEYWORD.lower() in t:
            return PLAN_VIP_PRINT
        if PRO_STUDIO_TITLE_KEYWORD and PRO_STUDIO_TITLE_KEYWORD.lower() in t:
            return PLAN_PRO
    return None


def _add_credit_ledger(session: Session, user_id: int, delta: int, reason: str, ref_type: Optional[str] = None, ref_id: Optional[str] = None):
    u = session.get(User, user_id)
    if not u:
        raise HTTPException(404, "User not found")
    u.credits_balance = int(u.credits_balance or 0) + int(delta)
    session.add(u)
    session.add(CreditLedger(user_id=user_id, delta=int(delta), reason=reason, ref_type=ref_type, ref_id=ref_id))


def _apply_plan_and_credits_from_order(session: Session, user: User, shopify_order_id: str, line_items: list[dict]) -> dict:
    # prevent double processing
    exists = session.exec(select(ShopifyOrderRecord).where(ShopifyOrderRecord.shopify_order_id == str(shopify_order_id))).first()
    if exists:
        return {"ok": True, "skipped": True}

    plan = _detect_plan_from_line_items(line_items)
    if not plan:
        # record anyway, so we don't repeatedly parse unknown orders
        session.add(ShopifyOrderRecord(user_id=user.id, shopify_order_id=str(shopify_order_id)))
        session.commit()
        return {"ok": True, "skipped": True, "reason": "No plan matched"}

    user.plan = plan
    user.is_vip = plan != PLAN_FREE
    session.add(user)

    credits_to_add = int(MONTHLY_CREDITS.get(plan, 0))
    if credits_to_add:
        _add_credit_ledger(session, user.id, credits_to_add, reason=f"Monthly credits for {plan}", ref_type="shopify_order", ref_id=str(shopify_order_id))

    session.add(ShopifyOrderRecord(user_id=user.id, shopify_order_id=str(shopify_order_id)))
    session.commit()
    return {"ok": True, "plan": plan, "credits_added": credits_to_add}


class ShopifySyncResult(SQLModel):
    ok: bool
    updated: bool = False
    plan: Optional[str] = None
    credits_added: int = 0
    message: Optional[str] = None


@app.post("/shopify/sync-me", response_model=ShopifySyncResult)
def shopify_sync_me(user: User = Depends(current_user)):
    """Manual sync: checks your Shopify orders by email and updates VIP plan + credits."""
    if not _shopify_ready():
        raise HTTPException(status_code=501, detail="Shopify integration not configured")

    # Pull recent orders for this email
    q = """
    query($q:String!) {
      orders(first: 20, query: $q, sortKey: PROCESSED_AT, reverse: true) {
        nodes {
          id
          name
          processedAt
          email
          lineItems(first: 50) {
            nodes { title sku }
          }
        }
      }
    }
    """

    data = _shopify_graphql(q, {"q": f"email:{user.email}"})
    orders = (((data or {}).get("data") or {}).get("orders") or {}).get("nodes") or []
    if not orders:
        return ShopifySyncResult(ok=True, updated=False, message="No Shopify orders found for this email")

    updated_any = False
    plan = None
    credits_added_total = 0

    with Session(engine) as session:
        db_user = session.get(User, user.id)
        for o in orders:
            oid = o.get("id") or o.get("name")
            # use gid if available, else name
            ref_id = str(oid)
            line_items = ((o.get("lineItems") or {}).get("nodes") or [])

            res = _apply_plan_and_credits_from_order(session, db_user, ref_id, line_items)
            if not res.get("skipped"):
                updated_any = True
                plan = res.get("plan")
                credits_added_total += int(res.get("credits_added") or 0)

    return ShopifySyncResult(ok=True, updated=updated_any, plan=plan, credits_added=credits_added_total)


class RedeemRequest(SQLModel):
    credits: int


@app.post("/credits/redeem-code")
def redeem_credits_code(payload: RedeemRequest, user: User = Depends(current_user)):
    credits = int(payload.credits or 0)
    if credits <= 0:
        raise HTTPException(400, "Credits must be a positive number")

    with Session(engine) as session:
        u = session.get(User, user.id)
        if not u:
            raise HTTPException(401, "User not found")
        if int(u.credits_balance or 0) < credits:
            raise HTTPException(400, "Not enough credits")

        # Create a Shopify discount code (fixed amount) restricted to this customer
        customer_id = _shopify_customer_id_by_email(u.email)
        if not customer_id:
            raise HTTPException(404, "Could not find this email as a Shopify customer")

        amount = round(float(CREDIT_UNIT_GBP) * float(credits), 2)
        code = f"VIP{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc)
        ends = now + timedelta(days=30)

        mutation = """
        mutation discountCodeBasicCreate($basicCodeDiscount: DiscountCodeBasicInput!) {
          discountCodeBasicCreate(basicCodeDiscount: $basicCodeDiscount) {
            codeDiscountNode { id }
            userErrors { field message }
          }
        }
        """

        variables = {
            "basicCodeDiscount": {
                "title": f"VIP Credits {u.email} {now.strftime('%Y-%m-%d')}",
                "code": code,
                "startsAt": now.isoformat(),
                "endsAt": ends.isoformat(),
                "usageLimit": 1,
                "appliesOncePerCustomer": True,
                "customerSelection": {"customers": {"add": [customer_id]}},
                "customerGets": {
                    "items": {"all": True},
                    "value": {"discountAmount": {"amount": str(amount), "appliesOnEachItem": False}},
                },
            }
        }

        resp = _shopify_graphql(mutation, variables)
        out = (((resp or {}).get("data") or {}).get("discountCodeBasicCreate") or {})
        errs = out.get("userErrors") or []
        if errs:
            raise HTTPException(400, f"Shopify error: {errs[0].get('message')}")
        discount_gid = ((out.get("codeDiscountNode") or {}).get("id"))

        # Deduct credits immediately (one-time code)
        _add_credit_ledger(session, u.id, -credits, reason="Redeemed credits for discount code", ref_type="discount_code", ref_id=code)
        session.add(CreditRedemption(user_id=u.id, credits_used=credits, amount_gbp=float(amount), code=code, shopify_discount_gid=discount_gid))
        session.commit()

        return {
            "ok": True,
            "code": code,
            "amount_gbp": amount,
            "expires_at": ends.isoformat(),
            "credits_left": int((session.get(User, u.id).credits_balance) or 0),
        }


@app.post("/webhooks/shopify/orders_paid")
async def shopify_orders_paid(request: Request):
    """Shopify webhook: orders/paid. Verifies HMAC and updates plan/credits."""
    if not SHOPIFY_WEBHOOK_SECRET:
        raise HTTPException(status_code=501, detail="Webhook secret not configured")

    body = await request.body()
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256") or ""

    digest = hmac.new(SHOPIFY_WEBHOOK_SECRET.encode("utf-8"), body, hashlib.sha256).digest()
    computed = base64.b64encode(digest).decode("utf-8")

    if not hmac.compare_digest(computed, hmac_header):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    email = (payload.get("email") or (payload.get("customer") or {}).get("email") or "").strip().lower()
    order_id = payload.get("id") or payload.get("name") or uuid.uuid4().hex
    line_items = payload.get("line_items") or []

    if not email:
        return {"ok": True, "skipped": True, "reason": "No email"}

    with Session(engine) as session:
        u = session.exec(select(User).where(User.email == email)).first()
        if not u:
            # User might register later; nothing to do now.
            return {"ok": True, "skipped": True, "reason": "User not registered in app"}

        res = _apply_plan_and_credits_from_order(session, u, str(order_id), line_items)
        return res


# ---------------- SUPPORT (private) ----------------

class SupportTicketCreate(SQLModel):
    subject: str
    message: str
    order_number: Optional[str] = None
    image_url: Optional[str] = None


@app.post("/support/tickets")
def create_support_ticket(payload: SupportTicketCreate, user: User = Depends(current_user)):
    subj = (payload.subject or "").strip()[:120]
    msg = (payload.message or "").strip()
    if not subj:
        subj = "Support"
    if len(msg) < 3:
        raise HTTPException(400, "Message too short")

    with Session(engine) as session:
        t = SupportTicket(
            user_id=user.id,
            subject=subj,
            message=msg,
            order_number=(payload.order_number or "").strip() or None,
            image_url=(payload.image_url or "").strip() or None,
        )
        session.add(t)
        session.commit()
        session.refresh(t)
        return {"ok": True, "ticket_id": t.id}


@app.get("/admin/support/tickets")
def admin_list_support_tickets(_: User = Depends(admin_user), limit: int = 100):
    with Session(engine) as session:
        tickets = session.exec(select(SupportTicket).order_by(SupportTicket.created_at.desc()).limit(limit)).all()
    return tickets


# ---------------- MEDIA UPLOAD ----------------

ALLOWED_IMAGE_TYPES = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/webp": ".webp",
}

@app.post("/media/upload")
async def upload_media(
    request: Request,
    file: UploadFile = File(...),
    user: User = Depends(current_user),
):
    # Only logged-in users can upload (so we can later limit abuse)
    if file.content_type not in ALLOWED_IMAGE_TYPES:
        raise HTTPException(status_code=400, detail="Only JPG, PNG or WEBP images are allowed")

    data = await file.read()
    if len(data) > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"File too large (max {MAX_UPLOAD_MB} MB)")

    ext = ALLOWED_IMAGE_TYPES[file.content_type]
    filename = f"{uuid.uuid4().hex}{ext}"
    (UPLOAD_DIR / filename).write_bytes(data)

    public_base = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
    if public_base:
        url = f"{public_base}/uploads/{filename}"
    else:
        url = str(request.base_url).rstrip("/") + f"/uploads/{filename}"

    return {"url": url}


# ---------------- SHOPIFY VIP WEBHOOK (optional) ----------------

class VipWebhook(SQLModel):
    email: str
    is_vip: bool = True


@app.post("/webhooks/vip")
def shopify_vip_webhook(payload: VipWebhook, request: Request):
    secret = (os.getenv("VIP_WEBHOOK_SECRET", "") or "").strip()
    if secret:
        if request.headers.get("x-sod-secret", "") != secret:
            raise HTTPException(status_code=401, detail="Unauthorized")

    email = (payload.email or "").strip().lower()
    if "@" not in email:
        raise HTTPException(400, "Invalid email")

    with Session(engine) as session:
        u = session.exec(select(User).where(User.email == email)).first()
        if not u:
            # User must register in the app with the same email first.
            raise HTTPException(404, "User not found (please register in the app first)")
        u.is_vip = bool(payload.is_vip)
        session.add(u)
        session.commit()
    return {"ok": True, "email": email, "is_vip": bool(payload.is_vip)}


class DisplayNameUpdate(SQLModel):
    display_name: str


@app.post("/me/display-name")
def update_display_name(payload: DisplayNameUpdate, user: User = Depends(current_user)):
    display_name = (payload.display_name or "").strip()
    if len(display_name) < 2:
        raise HTTPException(400, "Display name is required")
    if len(display_name) > 32:
        raise HTTPException(400, "Display name must be 32 characters or less")

    with Session(engine) as session:
        db_user = session.get(User, user.id)
        if not db_user:
            raise HTTPException(404, "User not found")
        db_user.display_name = display_name
        session.add(db_user)
        session.commit()
        session.refresh(db_user)
        return {"ok": True, "display_name": db_user.display_name}


# ---------------- TRICKS ----------------

class TrickCreate(SQLModel):
    title: str
    body: str
    media_url: Optional[str] = None
    is_vip: bool = False


@app.get("/tricks")
def list_tricks(
    user: Optional[User] = Depends(lambda token=Depends(oauth2_scheme): get_user_from_token(token) if token else None)
):
    with Session(engine) as session:
        tricks = session.exec(select(Trick).order_by(Trick.created_at.desc())).all()

    out = []
    for t in tricks:
        if t.is_vip and (not user or not user.is_vip):
            continue
        out.append(t)
    return out


@app.post("/tricks")
def create_trick(payload: TrickCreate, _: User = Depends(admin_user)):
    if not payload.title.strip():
        raise HTTPException(400, "Title required")
    with Session(engine) as session:
        t = Trick(
            title=payload.title.strip(),
            body=payload.body.strip(),
            media_url=payload.media_url,
            is_vip=payload.is_vip,
        )
        session.add(t)
        session.commit()
        session.refresh(t)
        return t


@app.delete("/tricks/{trick_id}")
def delete_trick(trick_id: int, _: User = Depends(admin_user)):
    with Session(engine) as session:
        t = session.get(Trick, trick_id)
        if not t:
            raise HTTPException(404, "Not found")
        session.delete(t)
        session.commit()
        return {"ok": True}


# ---------------- COMMUNITY ----------------

class PostCreate(SQLModel):
    text: str
    image_url: Optional[str] = None


class PostOut(SQLModel):
    id: int
    user_id: int
    author_display_name: str
    text: str
    image_url: Optional[str] = None
    created_at: datetime


class CommentOut(SQLModel):
    id: int
    post_id: int
    user_id: int
    author_display_name: str
    text: str
    created_at: datetime


@app.get("/posts")
def list_posts(
    user: Optional[User] = Depends(lambda token=Depends(oauth2_scheme): get_user_from_token(token) if token else None)
):
    with Session(engine) as session:
        posts = session.exec(select(Post).order_by(Post.created_at.desc())).all()
        mods = _get_mod_map(session, "post")

        user_ids = {p.user_id for p in posts}
        name_map = {}
        if user_ids:
            users = session.exec(select(User).where(User.id.in_(list(user_ids)))).all()
            name_map = {u.id: _display_name_for(u) for u in users}

    out: list[PostOut] = []
    for p in posts:
        mi = mods.get(p.id)
        if mi and mi.status != "approved":
            if not user or not user.is_admin:
                continue
        out.append(
            PostOut(
                id=p.id,
                user_id=p.user_id,
                author_display_name=name_map.get(p.user_id, f"Member #{p.user_id}"),
                text=p.text,
                image_url=p.image_url,
                created_at=p.created_at,
            )
        )
    return out


@app.post("/posts")
def create_post(payload: PostCreate, user: User = Depends(current_user)):
    text_val = (payload.text or "").strip()
    if not text_val:
        raise HTTPException(400, "Text required")

    # Route store/order issues to private support (not public)
    if _looks_like_store_issue(text_val):
        with Session(engine) as session:
            t = SupportTicket(
                user_id=user.id,
                subject="Order / Store issue",
                message=text_val,
                order_number=_extract_order_number(text_val),
            )
            session.add(t)
            session.commit()
            session.refresh(t)
        return {"ok": True, "routed": "support", "ticket_id": t.id}

    with Session(engine) as session:
        p = Post(user_id=user.id, text=text_val, image_url=payload.image_url)
        session.add(p)
        session.commit()
        session.refresh(p)

        if _looks_like_promo_or_contact(text_val):
            _ensure_moderation(session, "post", p.id, status="pending", reason="Contains link/contact/promo")
            return {"ok": True, "status": "pending"}
        else:
            _ensure_moderation(session, "post", p.id, status="approved")

        return PostOut(
            id=p.id,
            user_id=p.user_id,
            author_display_name=_display_name_for(user),
            text=p.text,
            image_url=p.image_url,
            created_at=p.created_at,
        )


class CommentCreate(SQLModel):
    text: str


@app.get("/posts/{post_id}/comments")
def list_comments(
    post_id: int,
    user: Optional[User] = Depends(lambda token=Depends(oauth2_scheme): get_user_from_token(token) if token else None),
):
    with Session(engine) as session:
        comments = session.exec(
            select(Comment).where(Comment.post_id == post_id).order_by(Comment.created_at.asc())
        ).all()
        mods = _get_mod_map(session, "comment")

        user_ids = {c.user_id for c in comments}
        name_map = {}
        if user_ids:
            users = session.exec(select(User).where(User.id.in_(list(user_ids)))).all()
            name_map = {u.id: _display_name_for(u) for u in users}

    out: list[CommentOut] = []
    for c in comments:
        mi = mods.get(c.id)
        if mi and mi.status != "approved":
            if not user or not user.is_admin:
                continue
        out.append(
            CommentOut(
                id=c.id,
                post_id=c.post_id,
                user_id=c.user_id,
                author_display_name=name_map.get(c.user_id, f"Member #{c.user_id}"),
                text=c.text,
                created_at=c.created_at,
            )
        )
    return out


@app.post("/posts/{post_id}/comments")
def create_comment(post_id: int, payload: CommentCreate, user: User = Depends(current_user)):
    text_val = (payload.text or "").strip()
    if not text_val:
        raise HTTPException(400, "Text required")

    # Route store/order issues to private support (not public)
    if _looks_like_store_issue(text_val):
        with Session(engine) as session:
            t = SupportTicket(
                user_id=user.id,
                subject="Order / Store issue",
                message=text_val,
                order_number=_extract_order_number(text_val),
            )
            session.add(t)
            session.commit()
            session.refresh(t)
        return {"ok": True, "routed": "support", "ticket_id": t.id}

    # Block links / contact details / advertising (auto-moderation)
    is_promo = _looks_like_promo_or_contact(text_val)

    with Session(engine) as session:
        p = session.get(Post, post_id)
        if not p:
            raise HTTPException(404, "Post not found")

        c = Comment(post_id=post_id, user_id=user.id, text=text_val)
        session.add(c)
        session.commit()
        session.refresh(c)

        if is_promo:
            _ensure_moderation(session, "comment", c.id, status="pending", reason="Contains link/contact/promo")
            return {"ok": True, "status": "pending"}
        else:
            _ensure_moderation(session, "comment", c.id, status="approved")

        return CommentOut(
            id=c.id,
            post_id=c.post_id,
            user_id=c.user_id,
            author_display_name=_display_name_for(user),
            text=c.text,
            created_at=c.created_at,
        )


@app.post("/comments/{comment_id}/report")
def report_comment(comment_id: int, user: User = Depends(current_user)):
    with Session(engine) as session:
        c = session.get(Comment, comment_id)
        if not c:
            raise HTTPException(404, "Comment not found")
        mi = _ensure_moderation(session, "comment", comment_id, status="approved")
        mi.reports += 1
        if mi.reports >= 3:
            mi.status = "hidden"
            mi.reason = "Auto-hidden after reports"
        session.add(mi)
        session.commit()
    return {"ok": True}


@app.get("/admin/moderation/pending")
def admin_list_pending(_: User = Depends(admin_user), limit: int = 200):
    with Session(engine) as session:
        items = session.exec(
            select(ModerationItem)
            .where(ModerationItem.status == "pending")
            .order_by(ModerationItem.created_at.desc())
            .limit(limit)
        ).all()
    return items


class ModerationUpdate(SQLModel):
    status: str  # approved | hidden | pending
    reason: Optional[str] = None


@app.post("/admin/moderation/{content_type}/{content_id}")
def admin_set_moderation(content_type: str, content_id: int, payload: ModerationUpdate, _: User = Depends(admin_user)):
    if content_type not in ("post", "comment"):
        raise HTTPException(400, "Invalid content_type")
    if payload.status not in ("approved", "hidden", "pending"):
        raise HTTPException(400, "Invalid status")
    with Session(engine) as session:
        mi = _ensure_moderation(session, content_type, content_id, status=payload.status, reason=payload.reason)
        session.add(mi)
        session.commit()
    return {"ok": True, "content_type": content_type, "content_id": content_id, "status": payload.status}

# ---------------- ADMIN ----------------

@app.post("/admin/users/{user_id}/vip")
def set_vip(user_id: int, is_vip: bool = Body(...), _: User = Depends(admin_user)):
    with Session(engine) as session:
        u = session.get(User, user_id)
        if not u:
            raise HTTPException(404, "User not found")
        u.is_vip = bool(is_vip)
        session.add(u)
        session.commit()
        return {"ok": True, "user_id": user_id, "is_vip": u.is_vip}


@app.post("/admin/users/{user_id}/admin")
def set_admin(user_id: int, is_admin: bool = Body(...), _: User = Depends(admin_user)):
    with Session(engine) as session:
        u = session.get(User, user_id)
        if not u:
            raise HTTPException(404, "User not found")
        u.is_admin = bool(is_admin)
        session.add(u)
        session.commit()
        return {"ok": True, "user_id": user_id, "is_admin": u.is_admin}


# ---------------- PUSH (optional) ----------------

class PushSubscribe(SQLModel):
    endpoint: str
    p256dh: str
    auth: str


@app.post("/push/subscribe")
def push_subscribe(payload: PushSubscribe, user: User = Depends(current_user)):
    with Session(engine) as session:
        existing = session.exec(
            select(PushSubscription)
            .where(PushSubscription.user_id == user.id)
            .where(PushSubscription.endpoint == payload.endpoint)
        ).first()
        if existing:
            existing.p256dh = payload.p256dh
            existing.auth = payload.auth
            session.add(existing)
            session.commit()
            return {"ok": True, "updated": True}

        sub = PushSubscription(
            user_id=user.id,
            endpoint=payload.endpoint,
            p256dh=payload.p256dh,
            auth=payload.auth,
        )
        session.add(sub)
        session.commit()
        return {"ok": True}


@app.post("/admin/push/broadcast")
def push_broadcast(message: str = Body(..., embed=True), _: User = Depends(admin_user)):
    if webpush is None:
        raise HTTPException(501, "pywebpush not installed")
    if not (VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY):
        raise HTTPException(500, "VAPID keys not configured")

    with Session(engine) as session:
        subs = session.exec(select(PushSubscription)).all()

    sent = 0
    failed = 0
    for s in subs:
        try:
            webpush(
                subscription_info={"endpoint": s.endpoint, "keys": {"p256dh": s.p256dh, "auth": s.auth}},
                data=message,
                vapid_private_key=VAPID_PRIVATE_KEY,
                vapid_claims={"sub": VAPID_SUBJECT},
            )
            sent += 1
        except Exception:
            failed += 1
    return {"ok": True, "sent": sent, "failed": failed}
