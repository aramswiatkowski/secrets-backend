from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.db import get_db
from app.deps import get_current_user
from app.models import User, CreditLedger
from app.schemas import CreditBalanceOut, LedgerItemOut, RedeemIn, RedeemOut
from app.business import compute_credits_balance, credits_cost_for_size
from app.integrations_shopify import create_draft_order_email_invoice

router = APIRouter()

@router.get("/balance", response_model=CreditBalanceOut)
def balance(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return CreditBalanceOut(balance=compute_credits_balance(db, user.id))

@router.get("/ledger", response_model=list[LedgerItemOut])
def ledger(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    items = db.query(CreditLedger).filter(CreditLedger.user_id == user.id).order_by(desc(CreditLedger.created_at)).limit(100).all()
    return [LedgerItemOut(delta=i.delta, reason=i.reason, ref_id=i.ref_id, created_at=i.created_at) for i in items]

@router.post("/redeem", response_model=RedeemOut)
def redeem(data: RedeemIn, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    # Calculate credits cost
    try:
        costs = [credits_cost_for_size(it.size) for it in data.items]
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    total_cost = sum(costs)
    if total_cost <= 0:
        raise HTTPException(status_code=400, detail="No items")

    bal = compute_credits_balance(db, user.id)
    if bal < total_cost:
        raise HTTPException(status_code=400, detail=f"Not enough credits (need {total_cost}, have {bal})")

    # Deduct credits (ledger)
    db.add(CreditLedger(user_id=user.id, delta=-total_cost, reason="redeem", ref_id=None))
    db.commit()

    # Optional: create draft order in Shopify (wire later with variant IDs)
    shopify_ref = None
    try:
        line_items = []
        for it in data.items:
            if it.variant_id:
                line_items.append({"variant_id": int(it.variant_id), "quantity": 1})
            else:
                # Placeholder line item when not wired to Shopify catalog yet
                line_items.append({"title": it.title or f"Rice paper {it.size}", "quantity": 1, "price": "0.00"})
        shopify_ref = create_draft_order_email_invoice(
            customer_email=user.email,
            line_items=line_items,
            note="Credit order created from PWA (tag: credit_order).",
            tags="credit_order",
        )
    except Exception:
        # In MVP we don't fail the redemption if Shopify isn't connected
        shopify_ref = None

    new_bal = compute_credits_balance(db, user.id)
    return RedeemOut(ok=True, credits_used=total_cost, new_balance=new_bal, shopify_order_ref=shopify_ref)
