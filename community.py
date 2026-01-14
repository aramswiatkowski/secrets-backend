from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.db import get_db
from app.deps import get_current_user
from app.models import User, Post
from app.schemas import PostCreateIn, PostOut
from app.moderation import assess_risk
from app.core.config import settings

router = APIRouter()

@router.get("/feed", response_model=list[PostOut])
def feed(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    # For MVP: show published posts + user's own hidden posts
    posts = db.query(Post).order_by(desc(Post.created_at)).limit(100).all()
    out = []
    for p in posts:
        if p.status == "published" or p.user_id == user.id:
            author = db.query(User).filter(User.id == p.user_id).first()
            out.append(PostOut(
                id=p.id,
                kind=p.kind,
                title=p.title,
                content=p.content,
                image_url=p.image_url,
                status=p.status,
                risk_flags=p.risk_flags,
                created_at=p.created_at,
                author_nickname=author.nickname if author else None
            ))
    return out

@router.post("/post", response_model=PostOut)
def create_post(data: PostCreateIn, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not user.nickname:
        raise HTTPException(status_code=400, detail="Set your nickname first")

    flags, should_hide = assess_risk((data.title or "") + "\n" + data.content)
    status = "hidden_pending_review" if (settings.MODERATION_HIDE_ON_RISK and should_hide) else "published"
    p = Post(
        user_id=user.id,
        kind=data.kind,
        title=data.title.strip() if data.title else None,
        content=data.content.strip(),
        image_url=data.image_url,
        status=status,
        risk_flags=",".join(flags) if flags else None,
    )
    db.add(p)
    db.commit()
    db.refresh(p)
    return PostOut(
        id=p.id,
        kind=p.kind,
        title=p.title,
        content=p.content,
        image_url=p.image_url,
        status=p.status,
        risk_flags=p.risk_flags,
        created_at=p.created_at,
        author_nickname=user.nickname,
    )
