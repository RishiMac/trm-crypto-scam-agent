"""
config.py — All constants, tuning knobs, and shared settings.
"""
from __future__ import annotations
import os
import re
from pathlib import Path
from openai import OpenAI

API_KEY = os.environ.get("OPENAI_API_KEY", "")
MODEL = os.environ.get("MODEL", "gpt-4o")
CLIENT = OpenAI(api_key=API_KEY) if API_KEY else None

CONCURRENCY = int(os.environ.get("CONCURRENCY", "6"))
SCREENSHOTS = os.environ.get("SCREENSHOTS", "1") == "1"
URL_LIMIT = int(os.environ.get("URL_LIMIT", "0")) or None
CONTEXT_POOL_SIZE = min(3, max(2, int(os.environ.get("CONTEXT_POOL_SIZE", "3"))))
HUNT_POOL_SIZE = min(3, max(2, int(os.environ.get("HUNT_POOL_SIZE", "3"))))

OUTPUT_DIR = Path("output")
SCREENSHOT_DIR = OUTPUT_DIR / "screenshots"
RESULTS_FILE = OUTPUT_DIR / "results.json"

HTTPX_TIMEOUT = 12
PW_TIMEOUT_MS = 15_000
PW_WAIT_MS = 3_000
PW_SPA_TIMEOUT_MS = 4_000
PW_SCAM_PATH_TIMEOUT_MS = 5_000
MAX_CONTENT = 60_000
THIN_CONTENT = 500

# SPA paths
CANDIDATE_PATHS = (
    "/#/deposit", "/#/recharge", "/#/withdraw", "/#/wallet", "/#/assets",
    "/#/funds", "/#/finance", "/#/home",
    "/deposit", "/recharge", "/withdraw", "/wallet", "/assets", "/funds",
)

SCAM_EXTRA_PATHS = (
    "/#/user/recharge", "/#/user/deposit", "/#/user/wallet",
    "/#/trade", "/#/otc", "/#/mining", "/#/earn",
    "/user/recharge", "/user/deposit", "/finance/deposit",
    "/h5/#/deposit", "/h5/#/recharge", "/h5/#/wallet",
    "/wap/#/deposit", "/wap/#/recharge",
    "/pc/#/deposit", "/pc/#/recharge",
    "/register", "/signup", "/#/register", "/#/signup",
)

# Bot-wall detection
BOT_WALL_PHRASES = (
    "cloudflare", "checking your browser", "attention required", "just a moment",
    "ddos protection", "enable javascript", "please wait",
)

# Crypto address patterns
RE_ETH   = re.compile(r'\b(0x[a-fA-F0-9]{40})\b')
RE_BTC_L = re.compile(r'\b([13][a-km-zA-HJ-NP-Z1-9]{25,34})\b')
RE_BTC_B = re.compile(r'\b(bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{39,74})\b', re.I)
RE_TRON  = re.compile(r'\b(T[1-9A-HJ-NP-Za-km-z]{33})\b')
RE_SOL   = re.compile(r'\b([1-9A-HJ-NP-Za-km-z]{32,44})\b')

# Known infra/router addresses — never reported as findings
INFRA_ADDRS = {
    # Uniswap routers
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",   # Uniswap v2 router
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",   # Uniswap v3 router
    # Wrapped native tokens — these are protocol infrastructure, not deposit addresses
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",   # WETH (Ethereum)
    "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",   # WBNB (BSC)
    "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270",   # WMATIC (Polygon)
    "0x82af49447d8a07e3bd95bd0d56f35241523fbab1",   # WETH (Arbitrum)
    "0x21be370d5312f44cb42ce377bc9b8a0cef1a4c83",   # WFTM (Fantom)
    "0x5aea5775959fbc2557cc8789bc1bf90a239d9a91",   # WETH (zkSync)
    "0xe5d7c2a44ffddf6b295a15c148167daaaf5cf34f",   # WETH (Linea)
    "0x4200000000000000000000000000000000000006",   # WETH (Optimism/Base)
    "0xa1077a294dde1b09bb078844df40758a5d0f9a27",   # WPLS (PulseChain)
    # Solana system/wrapped
    "so11111111111111111111111111111111111111112",   # Wrapped SOL native mint
}

# Address context keywords
REGEX_CONTEXT_KEYWORDS = (
    "deposit", "recharge", "withdraw", "wallet", "address", "USDT", "TRC20", "ERC20",
    "QR", "scan", "send", "contract address", "ca:", "token address", "payment",
    "recipient", "transfer to", "solana", "spl", "phantom", "raydium", "jupiter",
    "bep20", "bep-20", "bsc", "binance smart chain", "erc-20", "trc-20", "trc20",
    "copy address", "receive", "send to", "activation wallet", "smart wallet",
    "充值", "提现", "提币", "充币", "收款", "地址", "扫码", "转账", "转入", "转出",
)

SCAM_RELAXED_CONTEXT = REGEX_CONTEXT_KEYWORDS + (
    "invest", "earn", "profit", "mining", "trade", "exchange", "fund", "amount",
    "balance", "account", "network", "chain", "coin", "crypto", "payment", "fee",
    "bonus", "reward", "yield", "stake", "pool", "liquidity",
)

SOL_CONTEXT_KEYWORDS  = ("solana", "phantom", "spl", "raydium", "jupiter", "sol", "solscan", "pump.fun", "pump")
BTC_CONTEXT_KEYWORDS  = ("btc", "bitcoin", "₿", "sats", "segwit", "onchain")
TRON_CONTEXT_KEYWORDS = ("trc20", "trc-20", "tron", "trx")

# URL scam heuristic signals
SCAM_URL_SIGNALS = (
    "coin", "bit", "crypto", "trade", "invest", "mining", "usdc", "usdt", "btc",
    "eth", "fx", "wallet", "finance", "exchange", "token", "defi", "swap", "earn",
    "profit", "fund", "asset", "capital", "market", "broker", "binary",
)

SCAM_URL_TLDS = (
    ".xyz", ".cc", ".top", ".fun", ".click", ".sbs", ".vip", ".cfd", ".lol",
    ".quest", ".store", ".shop", ".help", ".live", ".online", ".site",
)

# LLM prompts
SYSTEM_PROMPT = """You are a cryptocurrency fraud analyst at a blockchain intelligence company.
Your job: classify websites as scam or not scam, and extract any cryptocurrency wallet addresses.

SCAM indicators:
- Fake/impersonating crypto exchanges, wallets, trading platforms
- Phishing pages mimicking legitimate services (Binance, Coinbase, MetaMask, etc.)
- Investment schemes with unrealistic returns (pig butchering, romance scams)
- Sites pressuring users to send crypto to specific addresses
- Typosquat domains (bitmain→braiins, coinbase→coinbose, etc.)
- Token/airdrop sites asking users to connect wallets or send funds
- Fake cloud mining platforms promising guaranteed returns
- Task scam / pig butchering shopping platforms: fake e-commerce stores where victims
  complete "tasks" (buying products) to earn commissions, then are asked to deposit
  crypto to unlock withdrawals. These look like normal shops but have login/register
  flows, "commission" or "task" language, and ask for crypto deposits. Examples:
  sites with names like *-vault.store, *-rack.store, *-outlet.store, *-arena.store,
  *-zone.store, *-choice.store — especially clusters of similar store domains
- Sites with crypto exchange UI but no verifiable company, no real trading volume
- Mobile SPA exchange templates (h5.*, m.*, wap.*) with login/deposit flows
- Domain names containing "usdc", "btc", "eth", "coin", "trade" + suspicious TLD

IMPORTANT — task scam stores are SCAM, not legitimate e-commerce:
If a site appears to be an online shop BUT also has user login/register, mentions
"tasks", "commission", "earnings", "withdraw", or prompts for crypto deposits,
classify it as SCAM regardless of how legitimate the product listings look.

NOT SCAM: normal non-crypto sites with no login/deposit flows — e-commerce, blogs,
gambling, corporate. A shop with no crypto/task elements is not a scam.
UNKNOWN: ONLY if truly unreachable (status 0/403/5xx) AND content < 100 chars.
         If the URL looks like a crypto exchange and shows ANY content, lean toward SCAM.

Respond ONLY with valid JSON (no markdown):
{
  "classification": "scam" | "not scam" | "unknown",
  "confidence": 0.0-1.0,
  "reasoning": "one sentence",
  "crypto_addresses": [
    {"chain": "ETH"|"BTC"|"TRON"|"SOL"|"OTHER", "address": "...", "context": "brief surrounding text"}
  ]
}

For crypto_addresses: extract ALL wallet addresses (deposit, contract, send-here).
Do NOT include: code examples, placeholder addresses (0x000...000), infra contracts."""

USER_TEMPLATE = """URL: {url}
Status: {status}
Final URL: {final_url}
Error: {error}

Page content:
{content}"""