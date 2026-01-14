from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db import get_db
from app.deps import get_current_user
from app.models import User
from app.schemas import MeOut, NicknameIn
from app.business import current_plan, PLANS
from app.core.config import settings

router = APIRouter()

@router.get("", response_model=MeOut)
def me(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    plan_key, status = current_plan(db, user.id)
    return MeOut(
        email=user.email,
        nickname=user.nickname,
        plan=plan_key,
        subscription_status=status,
        vip_discount_percent=settings.VIP_DISCOUNT_PERCENT,
    )

@router.post("/nickname", response_model=MeOut)
def set_nickname(data: NicknameIn, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    nick = data.nickname.strip()
    if not nick:
        raise HTTPException(status_code=400, detail="Nickname required")
    # uniqueness
    exists = db.query(User).filter(User.nickname == nick).first()
    if exists and exists.id != user.id:
        raise HTTPException(status_code=400, detail="Nickname already taken")
    user.nickname = nick
    db.add(user)
    db.commit()
    plan_key, status = current_plan(db, user.id)
    return MeOut(
        email=user.email,
        nickname=user.nickname,
        plan=plan_key,
        subscription_status=status,
        vip_discount_percent=settings.VIP_DISCOUNT_PERCENT,
    )
