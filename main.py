from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status, Body
from fastapi.middleware.cors import CORSMiddleware
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
    user_id: int = Field(index=True, foreign_key="user.id")
    endpoint: str
    p256dh: str
    auth: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------- HELPERS ----------------

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


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


# ---------------- APP ----------------

app = FastAPI(title=f"{APP_NAME} API", version="0.1.0")

# CORS – iPhone/Netlify
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://bejewelled-unicorn-4e0552.netlify.app",
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

    # --- TEMP BOOTSTRAP (admin + vip) ---
    # Set BOOTSTRAP_EMAIL on Render (e.g. aramedultd@gmail.com),
    # then register that email once via /auth/register.
    # On startup it will be upgraded to admin+vip automatically.
    bootstrap_email = os.getenv("BOOTSTRAP_EMAIL", "").strip().lower()
    if bootstrap_email:
        with Session(engine) as session:
            u = session.exec(select(User).where(User.email == bootstrap_email)).first()
            if u:
                u.is_admin = True
                u.is_vip = True
                session.add(u)
                session.commit()
    # --- END TEMP BOOTSTRAP ---


@app.get("/health")
def health():
    return {"ok": True, "name": APP_NAME}


# ---------------- AUTH ----------------

class AuthRegister(SQLModel):
    email: str
    password: str


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

    with Session(engine) as session:
        existing = session.exec(select(User).where(User.email == email)).first()
        if existing:
            raise HTTPException(409, "Email already registered")

        user = User(email=email, hashed_password=hash_password(payload.password))
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
    return {"id": user.id, "email": user.email, "is_admin": user.is_admin, "is_vip": user.is_vip}


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


@app.get("/posts")
def list_posts():
    with Session(engine) as session:
        posts = session.exec(select(Post).order_by(Post.created_at.desc())).all()
    return posts


@app.post("/posts")
def create_post(payload: PostCreate, user: User = Depends(current_user)):
    if not payload.text.strip():
        raise HTTPException(400, "Text required")
    with Session(engine) as session:
        p = Post(user_id=user.id, text=payload.text.strip(), image_url=payload.image_url)
        session.add(p)
        session.commit()
        session.refresh(p)
        return p


class CommentCreate(SQLModel):
    text: str


@app.get("/posts/{post_id}/comments")
def list_comments(post_id: int):
    with Session(engine) as session:
        comments = session.exec(
            select(Comment).where(Comment.post_id == post_id).order_by(Comment.created_at.asc())
        ).all()
    return comments


@app.post("/posts/{post_id}/comments")
def create_comment(post_id: int, payload: CommentCreate, user: User = Depends(current_user)):
    if not payload.text.strip():
        raise HTTPException(400, "Text required")
    with Session(engine) as session:
        p = session.get(Post, post_id)
        if not p:
            raise HTTPException(404, "Post not found")
        c = Comment(post_id=post_id, user_id=user.id, text=payload.text.strip())
        session.add(c)
        session.commit()
        session.refresh(c)
        return c


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
