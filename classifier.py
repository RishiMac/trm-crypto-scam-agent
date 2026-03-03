"""
classifier.py — URL heuristic scoring and LLM-based site classification.

Two classification paths:
  1. LLM (GPT-4o) used when CLIENT is available.
  2. Keyword heuristic fallback used when no API key is set, or on LLM error.

Post-processing applies the URL score as a tiebreaker for ambiguous results.
"""
from __future__ import annotations
import json
import re
from urllib.parse import urlparse

from config import (
    CLIENT, MODEL,
    SYSTEM_PROMPT, USER_TEMPLATE,
    BOT_WALL_PHRASES, THIN_CONTENT, MAX_CONTENT,
    SCAM_URL_SIGNALS, SCAM_URL_TLDS,
)
from fetcher import FetchResult

# SPA path patterns that are nearly always fake exchanges
SPA_PATTERNS = re.compile(
    r'(/h5/|/wap/|/pc\.html|/pcweb/|/#/|/mobile|/static/html/)',
    re.I,
)


def url_scam_score(url, final_url = ""):
    """
    Returns a 0-1 score based purely on URL/final-URL signals.
    Used as a tiebreaker when content is thin or the LLM is uncertain.
    Scores both the original and final (post-redirect) URL, takes the max.
    """
    def score(u: str):
        s = 0.0
        ul = u.lower()
        for sig in SCAM_URL_SIGNALS:
            if sig in ul:
                s += 0.15
        for tld in SCAM_URL_TLDS:
            if tld in ul:
                s += 0.2
        parsed = urlparse(u)
        host = parsed.hostname or ""
        if host.startswith(("h5.", "m.", "wap.")):
            s += 0.25
        path = parsed.path.lower()
        if any(seg in path for seg in ("/h5", "/wap", "/pc")):
            s += 0.15
        # SPA hash fragment is a strong signal for fake exchange templates
        if "/#/" in u:
            s += 0.3
        return min(s, 1.0)

    base = score(url)
    if final_url and final_url != url:
        base = max(base, score(final_url))
    return base


def final_url_is_spa(final_url):
    """
    True if the final (post-redirect) URL shows a known fake-exchange SPA pattern.
    Catches sites like daxonbrite.info -> /pc.html, velantrix-aion.com -> /pc.html.
    """
    if not final_url:
        return False
    return bool(SPA_PATTERNS.search(final_url))


def blocked_or_bot_wall(fetch_r):
    content = (fetch_r.content or "").lower()
    if any(phrase in content for phrase in BOT_WALL_PHRASES):
        return True
    if len(content) < THIN_CONTENT and fetch_r.status in (403, 429, 521, 522):
        return True
    return False


def heuristic(url, r, note = ""):
    text = (r.content or "").lower()
    final_url = r.final_url or url
    scam_words = [
        "deposit", "withdraw", "recharge", "usdt", "trc20", "erc20",
        "investment plan", "guaranteed return", "mining", "wallet connect",
        "connect wallet", "copy address", "pig butcher",
    ]
    legit_words = [
        "add to cart", "free shipping", "checkout", "order tracking",
        "return policy", "contact us", "about us",
    ]
    score = (sum(3 for w in scam_words if w in text)
             - sum(2 for w in legit_words if w in text))
    url_score = url_scam_score(url, final_url)

    if score >= 4 or (url_score >= 0.5 and r.status == 200) or final_url_is_spa(final_url):
        return {
            "classification": "scam",
            "confidence": 0.6,
            "reasoning": f"Heuristic: scam signals={score}, url_score={url_score:.2f}. {note}",
            "crypto_addresses": [],
        }
    if r.error or r.status in (0, 404, 401, 403, 429, 521, 522):
        return {
            "classification": "unknown",
            "confidence": 0.2,
            "reasoning": f"Unreachable or blocked. {note}",
            "crypto_addresses": [],
        }
    return {
        "classification": "not scam",
        "confidence": 0.5,
        "reasoning": f"Heuristic: weak signals. {note}",
        "crypto_addresses": [],
    }


def llm_classify(url, fetch_r):
    """
    Classify a URL as 'scam', 'not scam', or 'unknown'.

    Falls back to heuristics when:
      - No API key is configured.
      - Content is empty/unreachable (saves API cost).
      - Bot wall detected (URL score tiebreaker applied first).
      - LLM call fails.
    """
    if not CLIENT:
        return heuristic(url, fetch_r)

    content_str = (fetch_r.content or "")[:MAX_CONTENT]
    final_url = fetch_r.final_url or url

    # Unreachable — skip LLM entirely
    if len(content_str) < 100 and fetch_r.error:
        return {
            "classification": "unknown",
            "confidence": 0.2,
            "reasoning": f"Unreachable: {fetch_r.error}",
            "crypto_addresses": [],
        }

    # SPA pattern in final URL = fake exchange template even if content is thin
    if final_url_is_spa(final_url) and fetch_r.status == 200:
        score = url_scam_score(url, final_url)
        if score >= 0.3:
            return {
                "classification": "scam",
                "confidence": max(0.85, score),
                "reasoning": f"Final URL matches fake-exchange SPA template: {final_url}",
                "crypto_addresses": [],
            }

    # Bot-protected — try URL score before giving up
    if blocked_or_bot_wall(fetch_r):
        score = url_scam_score(url, final_url)
        if score >= 0.4:
            return {
                "classification": "scam",
                "confidence": min(0.75, score),
                "reasoning": (
                    f"Bot-protected but URL strongly suggests crypto scam "
                    f"(score={score:.2f})"
                ),
                "crypto_addresses": [],
            }
        return {
            "classification": "unknown",
            "confidence": 0.2,
            "reasoning": "Blocked or bot protection; content too thin to judge.",
            "crypto_addresses": [],
        }

    user_msg = USER_TEMPLATE.format(
        url=url,
        status=fetch_r.status or "N/A",
        final_url=final_url,
        error=fetch_r.error or "none",
        content=content_str,
    )

    try:
        resp = CLIENT.chat.completions.create(
            model=MODEL, temperature=0,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ],
        )
        raw = resp.choices[0].message.content
        data = json.loads(raw)
        cls = (data.get("classification") or "unknown").lower().strip().replace("_", " ")
        if cls not in ("scam", "not scam", "unknown"):
            cls = "unknown"

        # URL tiebreaker: push confident unknowns on status-200 pages to scam
        if cls == "unknown" and fetch_r.status == 200:
            score = url_scam_score(url, final_url)
            if score >= 0.5:
                cls = "scam"
                data["reasoning"] = (
                    (data.get("reasoning") or "")
                    + f" [reclassified: URL score {score:.2f} + status 200]"
                )
            elif final_url_is_spa(final_url):
                cls = "scam"
                data["reasoning"] = (
                    (data.get("reasoning") or "")
                    + f" [reclassified: SPA final URL pattern {final_url}]"
                )

        return {
            "classification": cls,
            "confidence": float(data.get("confidence", 0.5)),
            "reasoning": data.get("reasoning", ""),
            "crypto_addresses": data.get("crypto_addresses") or [],
        }

    except Exception as e:
        return heuristic(url, fetch_r, note=f"LLM_ERROR: {str(e)[:120]}")