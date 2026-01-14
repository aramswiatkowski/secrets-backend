from fastapi import APIRouter, Request, HTTPException, Depends
from sqlalchemy.orm import Session
from app.db import get_db
from app.integrations_shopify import verify_webhook
from app.models import User, Subscription
from app.business import ensure_monthly_entitlements, month_key, maybe_award_vip_bonus
from datetime import datetime

router = APIRouter()

@router.post("/shopify/orders_paid")
async def shopify_orders_paid(request: Request, db: Session = Depends(get_db)):
    raw = await request.body()
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256", "")
    if not verify_webhook(raw, hmac_header):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    payload = await request.json()

    # Minimal extraction (Shopify payload differs by webhook topic)
    email = (payload.get("email") or "").lower().strip()
    total_price = float(payload.get("total_price") or 0.0)
    tags = (payload.get("tags") or "")
    is_credit_order = "credit_order" in [t.strip() for t in tags.split(",") if t.strip()]

    if not email:
        return {"ok": True, "skipped": "no_email"}

    user = db.query(User).filter(User.email == email).first()
    if not user:
        return {"ok": True, "skipped": "no_user"}

    # Determine billing month key. MVP: calendar month.
    mk = month_key(datetime.utcnow())
    awarded = maybe_award_vip_bonus(db, user.id, total_price, is_credit_order, mk)
    db.commit()
    return {"ok": True, "vip_bonus_awarded": awarded}

@router.post("/subscription/payment_succeeded")
async def subscription_payment_succeeded(request: Request, db: Session = Depends(get_db)):
    """
    Generic webhook placeholder:
    Call this from Stripe/Shopify Subscriptions event -> you map user email + plan + period.
    Body example:
    { "email":"...", "plan":"vip_print", "period_start":"2026-01-01T00:00:00Z", "period_end":"2026-02-01T00:00:00Z", "idempotency_key":"sub_123:2026-01" }
    """
    data = await request.json()
    email = (data.get("email") or "").lower().strip()
    plan = data.get("plan")
    period_start = data.get("period_start")
    period_end = data.get("period_end")
    idem = data.get("idempotency_key") or f"{email}:{plan}:{period_start}"

    if not email or not plan:
        raise HTTPException(status_code=400, detail="email and plan required")

    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Upsert subscription (manual provider for MVP)
    sub = db.query(Subscription).filter(Subscription.user_id == user.id).order_by(Subscription.id.desc()).first()
    if not sub:
        sub = Subscription(user_id=user.id, plan=plan, status="active", provider="manual", provider_subscription_id=idem)
        db.add(sub)
    sub.plan = plan
    sub.status = "active"
    sub.period_start = datetime.fromisoformat(period_start.replace("Z", "+00:00")) if period_start else None
    sub.period_end = datetime.fromisoformat(period_end.replace("Z", "+00:00")) if period_end else None

    ensure_monthly_entitlements(db, user.id, plan, datetime.utcnow(), idempotency_key=idem)
    db.commit()
    return {"ok": True}
