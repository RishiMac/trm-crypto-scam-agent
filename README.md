# Crypto Scam Detection Agent

## Overview

This project is an AI-powered crypto scam detection agent that analyzes websites to identify fraudulent cryptocurrency platforms and extract on-chain threat intelligence.

It combines large language model (LLM) classification with asynchronous web scraping and browser automation to detect scams that traditional rule-based systems often miss. The system processes URLs at scale using a concurrent pipeline and outputs structured results including scam classifications, extracted wallet addresses, and forensic screenshots.

Key highlights:
- Classified 160 crypto-related websites, identifying 89 scams
- Extracted 7 confirmed on-chain wallet addresses from malicious platforms
- Designed a concurrent async pipeline using httpx + Playwright with 6 workers
- Integrated OpenAI GPT-4o for semantic classification beyond keyword matching
- Built a multi-stage detection system combining heuristics, LLMs, and regex-based validation

This project demonstrates backend system design, async processing, and real-world application of LLMs for security and fraud detection.
## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt
playwright install chromium

# 2. Set your API key
echo "OPENAI_API_KEY=sk-..." > .env

# 3. Put URLs in urls.txt (one per line), then run
python main.py
```

Output: `output/results.json` + `output/screenshots/`

## Results (160 URLs)

| Classification | Count |
|---------------|-------|
| Scam | 89 |
| Not scam | 24 |
| Unknown | 47 |

**7 crypto addresses extracted** (3 ETH, 1 OTHER, 3 SOL)

| Site | Chain | Address | Notes |
|------|-------|---------|-------|
| `dexapp.uk` | ETH | `0xD499F95a...` | ICO "Smart Activation Wallet" |
| `dexapp.uk` | ETH | `0x59F25596...` | "Smart Contract Address" |
| `drops-marketplace.netlify.app` | ETH | `0xA562912e...` | Fake liquidity pool |
| `learingcenter.fun` | SOL | `3kC6gheQ5f...pump` | Memecoin contract |
| `orotoken.io` | ETH | `0xdd92c611...` | $ORO token contract |
| `pugmeme.io` | SOL | `EkPUWVb8yp...pump` | Pump.fun token |
| `pugmeme.io` | SOL | `6FResKVaRY...` | Declared burn wallet |

~70% of scam sites have zero extractable addresses by design pig-butchering SPA exchanges only reveal deposit addresses after SMS verification + an invitation code the scammer provides via chat. The address hunt navigates every likely deposit path but can't bypass these gates.


### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` | | GPT-4o key (heuristic-only if unset) |
| `MODEL` | `gpt-4o` | OpenAI model |
| `CONCURRENCY` | `6` | Parallel URL workers |
| `CONTEXT_POOL_SIZE` | `3` | Playwright fetch contexts |
| `HUNT_POOL_SIZE` | `3` | Playwright hunt contexts |
| `SCREENSHOTS` | `1` | `1` to save screenshots, `0` to skip |
| `URL_LIMIT` | all | Process only first N URLs (useful for testing) |

```bash
URL_LIMIT=20 python main.py    # quick test
SCREENSHOTS=0 python main.py   # faster, no screenshots
```


## Architecture

### File layout

```
scanner/
├── main.py        # Entry point, async orchestration, browser pool setup
├── config.py      # All constants, regexes, prompts, env vars
├── fetcher.py     # httpx fast-path + Playwright JS-rendered fallback
├── classifier.py  # URL heuristic scoring + LLM classification
├── addresses.py   # Address validation, regex extraction, deduplication
└── pipeline.py    # Per-URL three-pass processing pipeline
```

### Three-pass pipeline (per URL)

```
Pass 1+2 Fetch & Classify
  httpx (fast, no JS) ──► thin/blocked? ──► Playwright fallback
  LLM classifies page as scam / not scam / unknown
  unknowns on status-200 pages: Playwright retry with SPA paths
  still unknown: URL heuristic score + final-URL SPA pattern tiebreaker

Pass 3 Address Hunt (scams only)
  Playwright navigates 20+ deposit/recharge/wallet SPA paths
  Harvests: inline <script> bodies, data-clipboard-* attributes,
            deposit button clicks, all page frames
  Screenshot saved for evidence

Post-hunt reclassification
  If address hunt finds addresses on an "unknown" site → reclassified scam
```

### Two-queue design

With 6 concurrent workers and 3 Playwright contexts, holding a context for the full pipeline (fetch + hunt + screenshot) would starve other workers. Two separate pools prevent this:

```
context_queue (3 contexts) ──► Pass 1+2 only ──► returned BEFORE addr hunt
hunt_queue    (3 contexts) ──► Pass 3 only   ──► returned after hunt
```

### Address extraction

Two sources merged and deduplicated: LLM extraction from page content, and regex sweeps across raw HTML + JS. Each match is validated by a ±120 char context window that must contain crypto keywords. Chain-specific false-positive filters:

- **ETH** format-unique (`0x` + 40 hex); just needs any crypto context
- **TRON** needs `trc20 / tron / deposit / wallet` keywords
- **BTC** needs explicit `btc / bitcoin` keywords (base58 overlaps too much)
- **SOL** needs `solana / phantom / pump` + digits + mixed case + ≥8 unique chars (rejects nav text like `AssureDefiWebsiteDocsEarnBuyContact`)

Known infrastructure addresses (Uniswap routers, wrapped native tokens) are excluded.

### URL heuristic scoring

Every URL gets a 0–1 score based on crypto keywords in domain, suspicious TLDs, mobile SPA subdomain patterns (`h5.*`, `m.*`, `wap.*`), SPA hash fragments (`/#/`), and final redirect path. Used as a tiebreaker after LLM classification and catches bot-walled sites that return too little content to classify.


## What Constitutes a Scam

| Category | Examples |
|----------|---------|
| Fake crypto exchanges | `cofuturexs.com`, `byexdd.cc` SPA UIs with no real trading |
| Typosquat impersonation | `braiinscryptminning.com`, `coinmarkcapzwh.com`, `coinexvto.com` |
| Investment / HYIP scams | `keystonevaults.com` (20% ROI daily), `smartgrowsavings.com` (70%/month) |
| Task scam / pig butchering shops | `warelyshop-rack.store`, `dealloop-vault.store` fake e-commerce with crypto deposit flows |
| Meme token / ICO scams | `pugmeme.io`, `orotoken.io`, `dexapp.uk` |
| Mobile SPA exchange templates | `h5.bit-main.cc`, `m.bit-ligne.sbs` Chinese pig-butchering kit |

**Not scam**: legitimate e-commerce, IPTV services, gambling, corporate sites with no crypto elements.

**Unknown**: genuinely unreachable DNS failure, SSL error, status 0, or bot-walled with no content.

## Alternative Approaches

**Pure LLM vision (screenshots → GPT-4o)** simpler pipeline but vision models miss addresses embedded in JS or `data-clipboard` attributes, and it's slower and more expensive per URL.

**Headless browser only, no httpx fast-path** ~40% of sites return all needed content over plain HTTP. Running Playwright on every URL would be 3-5× slower with no accuracy gain on those sites.


## What I'd Do With More Time

**More addresses**: Intercept XHR/fetch responses during Playwright navigation deposit addresses are often returned by `/api/user/wallet` endpoints before login. Add TRON and BTC to the address hunt pass (currently strong on ETH/SOL only).

**Better classification**: Add WHOIS/DNS signals (domain age, registrar patterns) and perceptual hash comparison of exchange UI templates many fake exchanges share the same kit with swapped branding, so a visual similarity check would catch whole clusters at once.

**Infrastructure**: Residential proxy rotation to reach the sites that blocked the scanner's datacenter IP, and persistent intermediate results so a crash mid-run doesn't lose progress.


## Security Considerations

- Playwright runs headless with images/media/fonts blocked
- `verify=False` on httpx is intentional many scam sites have expired or self-signed certs
- Each Playwright context is isolated and fresh per site no cookies or credentials persist
- The scanner never submits forms with real user data
