import base64
import hashlib
import hmac
import json
from typing import Dict, Any, Optional
import requests

from app.core.config import settings

def _headers() -> Dict[str, str]:
    return {
        "X-Shopify-Access-Token": settings.SHOPIFY_ACCESS_TOKEN,
        "Content-Type": "application/json",
    }

def _base_url() -> str:
    return f"https://{settings.SHOPIFY_SHOP_DOMAIN}/admin/api/{settings.SHOPIFY_API_VERSION}"

def enabled() -> bool:
    return bool(settings.SHOPIFY_SHOP_DOMAIN and settings.SHOPIFY_ACCESS_TOKEN)

def verify_webhook(raw_body: bytes, hmac_header: str) -> bool:
    """
    Verifies Shopify webhook HMAC.
    """
    if not settings.SHOPIFY_WEBHOOK_SECRET:
        return True  # allow during MVP
    digest = hmac.new(settings.SHOPIFY_WEBHOOK_SECRET.encode("utf-8"), raw_body, hashlib.sha256).digest()
    computed = base64.b64encode(digest).decode("utf-8")
    return hmac.compare_digest(computed, hmac_header or "")

def add_customer_tag(customer_id: str, tag: str):
    if not enabled():
        return
    url = f"{_base_url()}/customers/{customer_id}.json"
    # Fetch existing tags
    r = requests.get(url, headers=_headers(), timeout=20)
    r.raise_for_status()
    customer = r.json()["customer"]
    tags = set([t.strip() for t in (customer.get("tags") or "").split(",") if t.strip()])
    tags.add(tag)
    payload = {"customer": {"id": customer_id, "tags": ", ".join(sorted(tags))}}
    ru = requests.put(url, headers=_headers(), data=json.dumps(payload), timeout=20)
    ru.raise_for_status()

def remove_customer_tag(customer_id: str, tag: str):
    if not enabled():
        return
    url = f"{_base_url()}/customers/{customer_id}.json"
    r = requests.get(url, headers=_headers(), timeout=20)
    r.raise_for_status()
    customer = r.json()["customer"]
    tags = set([t.strip() for t in (customer.get("tags") or "").split(",") if t.strip()])
    if tag in tags:
        tags.remove(tag)
    payload = {"customer": {"id": customer_id, "tags": ", ".join(sorted(tags))}}
    ru = requests.put(url, headers=_headers(), data=json.dumps(payload), timeout=20)
    ru.raise_for_status()

def create_draft_order_email_invoice(customer_email: str, line_items: list, note: str, tags: str) -> Optional[str]:
    """
    MVP helper: create a Draft Order in Shopify and return its ID.
    You can later complete it or email invoice.
    """
    if not enabled():
        return None
    url = f"{_base_url()}/draft_orders.json"
    payload = {
        "draft_order": {
            "email": customer_email,
            "line_items": line_items,
            "note": note,
            "tags": tags,
            "use_customer_default_address": True,
        }
    }
    r = requests.post(url, headers=_headers(), data=json.dumps(payload), timeout=20)
    r.raise_for_status()
    return str(r.json()["draft_order"]["id"])
