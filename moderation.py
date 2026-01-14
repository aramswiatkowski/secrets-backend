import re
from typing import List, Tuple

BAD_WORDS = {
    # Keep this short in code. Add a longer list in DB later if needed.
    "scam", "fraud", "idiot", "stupid"
}

EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
PHONE_RE = re.compile(r"(\+?\d[\d\s().-]{7,}\d)")
ADDRESS_HINT_RE = re.compile(r"\b(street|st\.|road|rd\.|avenue|ave\.|postcode|zip)\b", re.I)
URL_RE = re.compile(r"https?://", re.I)

def assess_risk(text: str) -> Tuple[List[str], bool]:
    """
    Returns (flags, should_hide)
    """
    flags: List[str] = []
    t = (text or "").strip()
    lower = t.lower()

    if any(w in lower for w in BAD_WORDS):
        flags.append("abuse_or_hostile")

    if EMAIL_RE.search(t):
        flags.append("contains_email")
    if PHONE_RE.search(t):
        flags.append("contains_phone")
    if ADDRESS_HINT_RE.search(t):
        flags.append("contains_address_hint")
    if URL_RE.search(t):
        flags.append("contains_link")

    # Hide if PII-ish or abuse
    should_hide = any(f in flags for f in ["contains_email", "contains_phone", "contains_address_hint", "abuse_or_hostile"])
    return flags, should_hide
