from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Float, ForeignKey, Text, UniqueConstraint
from sqlalchemy.orm import relationship
from app.db import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    nickname = Column(String, unique=True, index=True, nullable=True)
    shopify_customer_id = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    subscriptions = relationship("Subscription", back_populates="user", cascade="all, delete-orphan")
    credit_ledger = relationship("CreditLedger", back_populates="user", cascade="all, delete-orphan")
    posts = relationship("Post", back_populates="user", cascade="all, delete-orphan")

class Subscription(Base):
    __tablename__ = "subscriptions"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    plan = Column(String, nullable=False)  # vip_digital | vip_print | pro_studio
    status = Column(String, nullable=False, default="inactive")  # active | inactive | past_due | canceled
    period_start = Column(DateTime, nullable=True)
    period_end = Column(DateTime, nullable=True)
    provider = Column(String, nullable=True)  # stripe | shopify | manual
    provider_subscription_id = Column(String, nullable=True)

    user = relationship("User", back_populates="subscriptions")

    __table_args__ = (
        UniqueConstraint("user_id", "provider", "provider_subscription_id", name="uq_sub_provider"),
    )

class CreditLedger(Base):
    __tablename__ = "credits_ledger"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    delta = Column(Integer, nullable=False)  # +4, -2, etc
    reason = Column(String, nullable=False)  # monthly_topup | redeem | vip_bonus | admin_adjust
    ref_id = Column(String, nullable=True)   # idempotency key or external ref
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="credit_ledger")

class ClipartEntitlement(Base):
    __tablename__ = "clipart_entitlements"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    month_key = Column(String, nullable=False)  # e.g. 2026-01
    amount = Column(Integer, nullable=False, default=0)
    used = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("user_id", "month_key", name="uq_cliparts_month"),
    )

class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    kind = Column(String, nullable=False, default="question")  # question | showcase
    title = Column(String, nullable=True)
    content = Column(Text, nullable=False)
    image_url = Column(String, nullable=True)  # for showcase (you can wire to S3 later)
    status = Column(String, nullable=False, default="published")  # published | hidden_pending_review | removed
    risk_flags = Column(String, nullable=True)  # comma separated flags
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="posts")

class BonusAward(Base):
    __tablename__ = "bonus_awards"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    month_key = Column(String, nullable=False)  # billing month key
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("user_id", "month_key", name="uq_bonus_month"),
    )
