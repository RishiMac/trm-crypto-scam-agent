"""
addresses.py — Crypto address validation, extraction, and merging.

Handles:
  - Per-chain format validation (ETH, BTC, TRON, SOL)
  - False-positive filtering (base64, hex hashes, nav-text)
  - Context-window scoring to confirm an address is real
  - Regex sweep across raw page text
  - Merging LLM-extracted and regex-extracted addresses
"""
import re

from config import (
    RE_ETH, RE_BTC_L, RE_BTC_B, RE_TRON, RE_SOL,
    INFRA_ADDRS,
    REGEX_CONTEXT_KEYWORDS, SCAM_RELAXED_CONTEXT,
    SOL_CONTEXT_KEYWORDS, BTC_CONTEXT_KEYWORDS, TRON_CONTEXT_KEYWORDS,
)


# Low-level character tests

def looks_like_hex_hash(addr):
    """BTC legacy addresses that are actually just hex strings."""
    if not addr or addr[0] not in "13":
        return False
    body = addr[1:]
    return bool(25 <= len(addr) <= 34 and re.fullmatch(r"[0-9a-f]{24,33}", body, re.I))


def is_hex_only(s):
    return bool(s and re.fullmatch(r"[0-9a-f]+", s, re.I))


def is_base64_segment(s):
    """Reject strings that look like base64 chunks (slashes, plus, equals)."""
    if "/" in s or "+" in s or "=" in s:
        return True
    upper = sum(1 for c in s if c.isupper())
    lower = sum(1 for c in s if c.islower())
    if len(s) > 20 and upper > 0 and lower == 0:
        return True
    return False


def context_is_base64_stream(ctx):
    """True if the surrounding context looks like a raw base64 data stream."""
    if not ctx:
        return False
    is_url_context = (
        "://" in ctx
        or "http" in ctx.lower()
        or bool(re.search(r'\w+\.\w+/\w', ctx))
    )
    if is_url_context:
        return ctx.count("+") >= 2 and ctx.count("/") >= 2

    slash = ctx.count("/")
    plus = ctx.count("+")
    eq = ctx.count("=")
    if slash >= 2 and plus >= 1:
        return True
    if slash >= 3:
        return True
    if plus >= 2 and eq >= 1:
        return True
    longest_run = max((len(w) for w in ctx.split()), default=0)
    if longest_run > 60 and slash + plus + eq > 0:
        return True
    return False


def looks_like_garbage(ctx):
    if not ctx:
        return True
    alnum = sum(ch.isalnum() for ch in ctx)
    return (alnum / max(1, len(ctx))) < 0.55


# Per-chain validators

def valid_sol(addr):
    if not re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,44}", addr):
        return False
    if is_hex_only(addr):
        return False
    if is_base64_segment(addr):
        return False
    # Real SOL addresses always contain digits AND mixed case.
    # Pure-alpha or uniform-case strings are nav text concatenated together.
    if not any(c.isdigit() for c in addr):
        return False
    if not (any(c.isupper() for c in addr) and any(c.islower() for c in addr)):
        return False
    # Low unique-char count = repetitive / degenerate
    if len(set(addr)) < 8:
        return False
    return True


def valid_eth(addr):
    return bool(re.fullmatch(r"0x[a-fA-F0-9]{40}", addr))

def valid_tron(addr):
    return bool(re.fullmatch(r"T[1-9A-HJ-NP-Za-km-z]{33}", addr))

def valid_btc(addr):
    if looks_like_hex_hash(addr):
        return False
    return bool(RE_BTC_L.fullmatch(addr) or RE_BTC_B.fullmatch(addr))

def addr_valid(chain, addr):
    c = (chain or "").strip().upper()
    if c == "ETH":   return valid_eth(addr)
    if c == "SOL":   return valid_sol(addr)
    if c == "TRON":  return valid_tron(addr)
    if c == "BTC":   return valid_btc(addr)
    return len(addr) >= 25 and not is_hex_only(addr)


# Context scoring

def context_suggests_crypto_address(ctx, relaxed=False):
    if not ctx:
        return False
    lower = ctx.lower()
    keywords = SCAM_RELAXED_CONTEXT if relaxed else REGEX_CONTEXT_KEYWORDS
    return any(kw.lower() in lower for kw in keywords)


# Regex extraction

def regex_extract(text, relaxed=False):
    """
    Sweep raw page text for crypto addresses.

    relaxed=True is used on confirmed scam pages — broader context keywords
    are accepted, but chain-specific signals are still required for ambiguous
    formats (BTC, SOL) to keep false positives low.
    """
    found = []
    seen = set()

    def add(chain, addr, start, end, ctx_text):
        key = (chain, addr.lower())
        if key in seen:
            return
        if addr.lower() in INFRA_ADDRS:
            return
        if chain == "BTC" and looks_like_hex_hash(addr):
            return
        if chain == "SOL" and is_base64_segment(addr):
            return

        lo = max(0, start - 120)
        hi = min(len(ctx_text), end + 120)
        ctx = ctx_text[lo:hi].replace("\n", " ").strip()
        ctx_plain = re.sub(r"<[^>]+>", " ", ctx)
        ctx_plain = re.sub(r"\s+", " ", ctx_plain).strip()

        if looks_like_garbage(ctx_plain):
            return
        if context_is_base64_stream(ctx):
            return
        if not context_suggests_crypto_address(ctx_plain, relaxed=relaxed):
            return

        low = ctx_plain.lower()

        # BTC/SOL need explicit chain signals — their formats overlap with gibberish.
        # ETH (0x+40hex) is format-unique so the context check above is sufficient.
        # TRON needs at least broad deposit/wallet words (T+33base58 can false-positive).
        if chain == "BTC" and not any(k in low for k in BTC_CONTEXT_KEYWORDS):
            return
        if chain == "TRON" and not any(k in low for k in TRON_CONTEXT_KEYWORDS):
            broad_tron = ("wallet", "address", "deposit", "recharge", "withdraw",
                          "send", "receive", "payment", "transfer", "copy", "地址")
            if not any(k in low for k in broad_tron):
                return
        if chain == "SOL" and not any(k in low for k in SOL_CONTEXT_KEYWORDS):
            if not relaxed:
                return
            if not context_suggests_crypto_address(ctx_plain, relaxed=True):
                return

        seen.add(key)
        mid = start - lo
        c_lo = max(0, mid - 80)
        c_hi = min(len(ctx), mid + 120)
        context_raw = ctx[c_lo:c_hi]
        context_out = re.sub(r"<[^>]+>", " ", context_raw)
        context_out = re.sub(r"\s+", " ", context_out).strip()
        found.append({"chain": chain, "address": addr, "context": context_out[:200]})

    for m in RE_ETH.finditer(text):
        add("ETH", m.group(1), m.start(1), m.end(1), text)
    for m in RE_BTC_L.finditer(text):
        add("BTC", m.group(1), m.start(1), m.end(1), text)
    for m in RE_BTC_B.finditer(text):
        add("BTC", m.group(1), m.start(1), m.end(1), text)
    for m in RE_TRON.finditer(text):
        add("TRON", m.group(1), m.start(1), m.end(1), text)
    for m in RE_SOL.finditer(text):
        addr = m.group(1)
        if RE_BTC_L.fullmatch(addr) or RE_BTC_B.fullmatch(addr):
            continue
        add("SOL", addr, m.start(1), m.end(1), text)

    return found


# Merging

def normalize_chain(chain):
    c = (chain or "").strip().upper()
    return c if c in ("ETH", "BTC", "TRON", "SOL", "OTHER") else "OTHER"


def merge_addresses(llm_addrs, regex_addrs):
    """Deduplicate and validate addresses from both LLM and regex sources."""
    seen = set()
    merged = []
    for a in llm_addrs + regex_addrs:
        addr = (a.get("address") or "").strip()
        chain = (a.get("chain") or "OTHER").strip()
        if not addr or addr.lower() in INFRA_ADDRS:
            continue
        if not addr_valid(chain, addr):
            continue
        if addr.lower() not in seen:
            seen.add(addr.lower())
            merged.append({
                "chain": normalize_chain(chain),
                "address": addr,
                "context": (a.get("context") or "")[:200],
            })
    return merged