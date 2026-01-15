from __future__ import annotations

import os
import re
import uuid
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status, Body, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlmodel import SQLModel, Field, Session, create_engine, select

# Optional web-push support (works if you install pywebpush)
try:
    from pywebpush import webpush, WebPushException
except Exception:
    webpush = None
    WebPushException = Exception

APP_NAME = "Secrets of Decoupage"

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./secrets_app.db")
JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_ME__USE_A_LONG_RANDOM_SECRET")
JWT_ALG = "HS256"
ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "43200"))  # 30 days default

VAPID_PUBLIC_KEY = os.getenv("VAPID_PUBLIC_KEY", "")
VAPID_PRIVATE_KEY = os.getenv("VAPID_PRIVATE_KEY", "")
VAPID_SUBJECT = os.getenv("VAPID_SUBJECT", "mailto:support@secretsofdecoupage.com")

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)

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
    is_vip: bool = False
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
            if "display_name" not in cols:
                conn.exec_driver_sql('ALTER TABLE "user" ADD COLUMN display_name VARCHAR;')
                conn.commit()
    except Exception as e:
        # Don't crash the app if migration fails; tables will still exist.
        print(f"[SCHEMA] ensure_sqlite_schema failed: {e}")


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
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "10"))
# Serve uploaded files
app.mount("/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")


# CORS – iPhone/Netlify
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://bejewelled-unicorn-4e0552.netlify.app",
        "https://app.thesecretsofdecoupage.com",
        "https://thesecretsofdecoupagecom.netlify.app",
        # Local dev (opcjonalnie zostaw)
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        # Jeśli później dodasz własną domenę PWA, dopisz tu:
        # "https://app.secretsofdecoupage.com",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    create_db_and_tables()
    ensure_sqlite_schema()

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
                )
                session.add(u)
                session.commit()
                print(f"[BOOTSTRAP] Created user {bootstrap_email} as admin+vip")
            else:
                u.hashed_password = hash_password(bootstrap_password)
                u.is_admin = True
                u.is_vip = True
                if not (u.display_name or '').strip():
                    u.display_name = bootstrap_display_name or 'Admin'
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


@app.get("/me")
def me(user: User = Depends(current_user)):
    return {"id": user.id, "email": user.email, "display_name": user.display_name, "is_admin": user.is_admin, "is_vip": user.is_vip}



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
    if not payload.text.strip():
        raise HTTPException(400, "Text required")

    with Session(engine) as session:
        p = Post(user_id=user.id, text=payload.text.strip(), image_url=payload.image_url)
        session.add(p)
        session.commit()
        session.refresh(p)

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
    text = (payload.text or "").strip()
    if not text:
        raise HTTPException(400, "Text required")

    # Route store/order issues to private support (not public)
    if _looks_like_store_issue(text):
        with Session(engine) as session:
            t = SupportTicket(
                user_id=user.id,
                subject="Order / Store issue",
                message=text,
                order_number=_extract_order_number(text),
            )
            session.add(t)
            session.commit()
            session.refresh(t)
        return {"ok": True, "routed": "support", "ticket_id": t.id}

    with Session(engine) as session:
        p = session.get(Post, post_id)
        if not p:
            raise HTTPException(404, "Post not found")

        c = Comment(post_id=post_id, user_id=user.id, text=text)
        session.add(c)
        session.commit()
        session.refresh(c)

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
