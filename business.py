from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.models import Subscription, CreditLedger, ClipartEntitlement, BonusAward
from app.core.config import settings

PLANS = {
    "vip_digital": {
        "name": "VIP Digital",
        "price_gbp": 9.99,
        "monthly_credits": 0,
        "monthly_cliparts": 2,
        "includes": ["VIP Library", "Community", "2 cliparts / month"],
    },
    "vip_print": {
        "name": "VIP Print Pack",
        "price_gbp": 14.99,
        "monthly_credits": 4,
        "monthly_cliparts": 2,
        "includes": ["Community", "4 credits / month", "2 cliparts / month"],
    },
    "pro_studio": {
        "name": "PRO Studio",
        "price_gbp": 24.99,
        "monthly_credits": 8,
        "monthly_cliparts": 4,
        "includes": ["Community", "8 credits / month", "4 cliparts / month"],
    },
}

def month_key(dt: datetime) -> str:
    return f"{dt.year:04d}-{dt.month:02d}"

def compute_credits_balance(db: Session, user_id: int) -> int:
    total = db.query(func.coalesce(func.sum(CreditLedger.delta), 0)).filter(CreditLedger.user_id == user_id).scalar()
    return int(total or 0)

def credits_cost_for_size(size: str) -> int:
    s = (size or "").upper().strip()
    if s == "A4":
        return 1
    if s == "A3":
        return 2
    raise ValueError("Invalid size (use A4 or A3)")

def ensure_monthly_entitlements(db: Session, user_id: int, plan_key: str, when: datetime, idempotency_key: str):
    """
    Call this when a subscription payment succeeds (webhook).
    Adds monthly credits (if any) and clipart entitlement for the month.
    """
    plan = PLANS.get(plan_key)
    if not plan:
        raise ValueError("Unknown plan")

    # Credits top-up (ledger idempotency)
    if plan["monthly_credits"] > 0:
        existing = db.query(CreditLedger).filter(
            CreditLedger.user_id == user_id,
            CreditLedger.reason == "monthly_topup",
            CreditLedger.ref_id == idempotency_key
        ).first()
        if not existing:
            db.add(CreditLedger(user_id=user_id, delta=plan["monthly_credits"], reason="monthly_topup", ref_id=idempotency_key))

    # Cliparts entitlement per month (idempotent by unique constraint on user_id+month_key)
    mk = month_key(when)
    ent = db.query(ClipartEntitlement).filter(ClipartEntitlement.user_id == user_id, ClipartEntitlement.month_key == mk).first()
    if not ent:
        ent = ClipartEntitlement(user_id=user_id, month_key=mk, amount=plan["monthly_cliparts"], used=0)
        db.add(ent)

def is_vip_active(db: Session, user_id: int) -> bool:
    sub = db.query(Subscription).filter(Subscription.user_id == user_id).order_by(Subscription.id.desc()).first()
    return bool(sub and sub.status == "active" and sub.plan in PLANS)

def current_plan(db: Session, user_id: int):
    sub = db.query(Subscription).filter(Subscription.user_id == user_id).order_by(Subscription.id.desc()).first()
    if not sub:
        return None, "inactive"
    return sub.plan, sub.status

def maybe_award_vip_bonus(db: Session, user_id: int, order_total_gbp: float, is_credit_order: bool, billing_month_key: str) -> bool:
    """
    VIP bonus 1x per month:
    +1 credit if VIP active and paid order >= £15, and NOT a credit order.
    """
    if is_credit_order:
        return False
    if order_total_gbp < settings.VIP_BONUS_MIN_ORDER_GBP:
        return False
    if not is_vip_active(db, user_id):
        return False

    already = db.query(BonusAward).filter(BonusAward.user_id == user_id, BonusAward.month_key == billing_month_key).first()
    if already:
        return False

    db.add(BonusAward(user_id=user_id, month_key=billing_month_key))
    db.add(CreditLedger(user_id=user_id, delta=settings.VIP_BONUS_CREDITS, reason="vip_bonus", ref_id=f"bonus:{billing_month_key}"))
    return True
