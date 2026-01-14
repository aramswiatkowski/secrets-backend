from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy.orm import Session
from app.db import get_db
from app.schemas import AdminSetPlanIn
from app.models import User, Subscription
from app.business import ensure_monthly_entitlements
from datetime import datetime
import os

router = APIRouter()

def _admin_key() -> str:
    return os.getenv("ADMIN_KEY", "dev-admin-key")

def require_admin(x_admin_key: str = Header(default="")):
    if x_admin_key != _admin_key():
        raise HTTPException(status_code=401, detail="Invalid admin key")

@router.post("/set-plan", dependencies=[Depends(require_admin)])
def set_plan(data: AdminSetPlanIn, db: Session = Depends(get_db)):
    """
    Testing helper: activate a plan without payment.
    Send header: X-Admin-Key: <ADMIN_KEY>
    """
    user = db.query(User).filter(User.email == data.email.lower().strip()).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    sub = db.query(Subscription).filter(Subscription.user_id == user.id).order_by(Subscription.id.desc()).first()
    if not sub:
        sub = Subscription(
            user_id=user.id,
            plan=data.plan,
            status=data.status,
            provider="manual",
            provider_subscription_id=f"manual:{user.email}"
        )
        db.add(sub)
    sub.plan = data.plan
    sub.status = data.status
    sub.period_start = datetime.utcnow()
    sub.period_end = None

    # Top-up entitlements now (idempotency key based on month)
    idem = f"manual:{user.email}:{data.plan}:{datetime.utcnow().year:04d}-{datetime.utcnow().month:02d}"
    ensure_monthly_entitlements(db, user.id, data.plan, datetime.utcnow(), idempotency_key=idem)
    db.commit()
    return {"ok": True}
