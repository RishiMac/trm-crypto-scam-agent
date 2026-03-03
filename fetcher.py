"""
fetcher.py — Page fetching via httpx (fast) and Playwright (JS-rendered).

Strategy:
  1. Try httpx first (cheap, fast, no JS).
  2. If content is thin, errored, or blocked → fall back to Playwright.
  3. Playwright navigates common SPA hash-routes to expose hidden content.
  4. Inline scripts, clipboard attributes, and deposit-button clicks are all harvested to maximise address-extraction surface area.
"""
import re
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx
from playwright.async_api import TimeoutError as PWTimeout

from config import (
    HTTPX_TIMEOUT, PW_TIMEOUT_MS, PW_WAIT_MS,
    PW_SPA_TIMEOUT_MS, PW_SCAM_PATH_TIMEOUT_MS,
    MAX_CONTENT, CANDIDATE_PATHS,
)


@dataclass
class FetchResult:
    url: str
    final_url: str = ""
    status: int = 0
    content: str = ""
    raw_html: str = ""
    error: str = ""
    screenshot: str = ""
    screenshot_bytes: bytes = None


def normalize(u):
    u = u.strip()
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    return u


# httpx (plain HTTP, no JS)

async def fetch_httpx(url, client=None):
    own_client = client is None
    if client is None:
        client = httpx.AsyncClient(
            follow_redirects=True, timeout=HTTPX_TIMEOUT, verify=False,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                              "AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
                "Accept-Language": "en-US,en;q=0.9",
            },
        )
    try:
        resp = await client.get(url)
        html = resp.text[:200_000]
        text = re.sub(r"<(script|style)[^>]*>[\s\S]*?</\1>", "", html, flags=re.I)
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
        return FetchResult(
            url=url, final_url=str(resp.url), status=resp.status_code,
            content=text[:MAX_CONTENT], raw_html=html,
            error="" if resp.status_code < 400 else f"HTTP {resp.status_code}",
        )
    except Exception as e:
        return FetchResult(url=url, error=str(e)[:200])
    finally:
        if own_client:
            await client.aclose()


# Playwright page helpers

async def collect_page_text(page):
    """Text content from every frame on the page."""
    texts = []
    for frame in page.frames:
        try:
            t = await frame.evaluate("() => document.body ? document.body.textContent : ''")
            if t and t.strip():
                texts.append(t)
        except Exception:
            pass
    return " \n ".join(texts)


async def collect_inline_scripts(page):
    """All inline <script> bodies — addresses are often in JS config objects."""
    try:
        return await page.evaluate("""() =>
            Array.from(document.querySelectorAll('script:not([src])'))
                .map(s => s.textContent || '')
                .join('\\n')
        """) or ""
    except Exception:
        return ""


async def collect_clipboard_attrs(page):
    """data-clipboard-text and similar wallet-copy attributes."""
    try:
        return await page.evaluate("""() => {
            const attrs = ['data-clipboard-text','data-clipboard','data-copy',
                           'data-address','data-value','data-wallet','data-hash'];
            const sel = attrs.map(a => '[' + a + ']').join(',');
            const els = document.querySelectorAll(sel);
            const parts = [];
            for (const el of els) {
                for (const a of attrs) {
                    const v = el.getAttribute(a);
                    if (v && v.length > 20) parts.push(a + ':' + v);
                }
            }
            return parts.join(' ');
        }""") or ""
    except Exception:
        return ""


async def try_deposit_button(page):
    """Click common deposit/wallet CTAs and capture resulting content."""
    texts = []
    ctas = ["Deposit", "deposit", "充值", "Wallet", "wallet",
            "Recharge", "recharge", "Fund", "Assets"]
    for btn_text in ctas:
        try:
            btn = await page.query_selector(
                f'button:has-text("{btn_text}"), a:has-text("{btn_text}"), '
                f'[class*="deposit"]:has-text("{btn_text}"), '
                f'[class*="recharge"]:has-text("{btn_text}")'
            )
            if btn:
                await btn.click(timeout=2000)
                await page.wait_for_timeout(1500)
                texts.append(await collect_page_text(page))
                break
        except Exception:
            pass
    return " ".join(texts)


# Playwright core

async def fetch_playwright_impl(url, context, result, take_screenshot, extra_paths=()):
    page = await context.new_page()
    try:
        async def block(route):
            if route.request.resource_type in ("image", "media", "font"):
                await route.abort()
            else:
                await route.continue_()
        await page.route("**/*", block)

        resp = await page.goto(url, wait_until="domcontentloaded", timeout=PW_TIMEOUT_MS)
        result.status = resp.status if resp else 0
        await page.wait_for_timeout(PW_WAIT_MS)
        result.final_url = page.url

        texts = [
            await collect_page_text(page),
            await collect_inline_scripts(page),
            await collect_clipboard_attrs(page),
            await try_deposit_button(page),
        ]

        origin = urlparse(page.url)
        origin_base = f"{origin.scheme}://{origin.netloc}"

        for path in CANDIDATE_PATHS + extra_paths:
            target = origin_base + path
            if target == page.url:
                continue
            try:
                timeout = (PW_SPA_TIMEOUT_MS if path in CANDIDATE_PATHS else PW_SCAM_PATH_TIMEOUT_MS)
                await page.goto(target, wait_until="domcontentloaded", timeout=timeout)
                await page.wait_for_timeout(1200)
                texts.append(await collect_page_text(page))
                texts.append(await collect_clipboard_attrs(page))
                texts.append(await collect_inline_scripts(page))
            except Exception:
                pass

        html = await page.content()
        result.raw_html = html[:200_000]
        result.content = (" \n ".join(t for t in texts if t))[:MAX_CONTENT]

        if take_screenshot:
            try:
                await page.evaluate("window.scrollTo(0, 0)")
                result.screenshot_bytes = await page.screenshot(full_page=False)
            except Exception:
                pass

    except PWTimeout:
        result.error = "Timeout"
    except Exception as e:
        result.error = str(e)[:200]
    finally:
        await page.close()


async def fetch_playwright(url, take_screenshot=False, browser=None, context=None, extra_paths=()):
    """Render a page with Playwright. Reuses an existing context if provided."""
    from playwright.async_api import async_playwright

    result = FetchResult(url=url)

    if context is not None:
        await fetch_playwright_impl(url, context, result, take_screenshot, extra_paths=extra_paths)
        return result

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True, args=["--disable-dev-shm-usage", "--no-sandbox"]
        )
        ctx = await browser.new_context(
            ignore_https_errors=True,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
            viewport={"width": 1280, "height": 720},
            java_script_enabled=True, bypass_csp=True,
        )
        try:
            await fetch_playwright_impl(url, ctx, result, take_screenshot, extra_paths=extra_paths)
        finally:
            await ctx.close()
            await browser.close()

    return result


async def fetch(url, take_screenshot=False, browser=None, context=None, http_client=None, extra_paths=()):
    """
    Attempt httpx first; fall back to Playwright when content is thin,
    blocked, or errored.
    """
    r = await fetch_httpx(url, client=http_client)
    if r.error or len(r.content) < 500 or r.status in (403, 521, 522):
        r2 = await fetch_playwright(url, take_screenshot=take_screenshot, browser=browser, context=context, extra_paths=extra_paths,)
        if len(r2.content or "") > len(r.content or ""):
            return r2
    return r