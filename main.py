#!/usr/bin/env python3
"""
main.py — Orchestration and CLI entry point.

TRM Labs Crypto Scam Detection Agent
========================================
Reads urls.txt, classifies each URL as scam / not scam / unknown,
extracts any crypto wallet addresses, and writes output/results.json.

Usage:
    python main.py

Environment variables (all optional):
    OPENAI_API_KEY     — GPT-4o key (heuristic-only mode if unset)
    MODEL              — OpenAI model name (default: gpt-4o)
    CONCURRENCY        — parallel URL workers (default: 6)
    CONTEXT_POOL_SIZE  — Playwright fetch contexts (default: 3)
    HUNT_POOL_SIZE     — Playwright hunt contexts (default: 3)
    SCREENSHOTS        — 1/0 to enable/disable screenshots (default: 1)
    URL_LIMIT          — process only first N URLs (default: all)
"""
from dotenv import load_dotenv
load_dotenv()

import asyncio
import json
import sys
from dataclasses import asdict
from pathlib import Path

import httpx
from playwright.async_api import async_playwright

from config import (
    CLIENT, MODEL, CONCURRENCY, SCREENSHOTS, URL_LIMIT,
    CONTEXT_POOL_SIZE, HUNT_POOL_SIZE,
    OUTPUT_DIR, SCREENSHOT_DIR, RESULTS_FILE,
)
from fetcher import normalize
from pipeline import process_url, Result


async def make_context(browser):
    return await browser.new_context(
        ignore_https_errors=True,
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
        ),
        viewport={"width": 1280, "height": 720},
        java_script_enabled=True,
        bypass_csp=True,
    )


async def main_async(urls):
    sem = asyncio.Semaphore(CONCURRENCY)

    http_headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
        ),
        "Accept-Language": "en-US,en;q=0.9",
    }

    async with httpx.AsyncClient(
        follow_redirects=True, timeout=12, verify=False, headers=http_headers,
    ) as http_client:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--disable-dev-shm-usage", "--no-sandbox"],
            )

            # Two separate context pools to prevent deadlock:
            #   context_queue — initial fetch + classify only
            #   hunt_queue    — addr hunt + screenshot only
            context_queue = asyncio.Queue(maxsize=CONTEXT_POOL_SIZE)
            hunt_queue = asyncio.Queue(maxsize=HUNT_POOL_SIZE)
            all_contexts = []

            for _ in range(CONTEXT_POOL_SIZE):
                ctx = await make_context(browser)
                await context_queue.put(ctx)
                all_contexts.append(ctx)

            for _ in range(HUNT_POOL_SIZE):
                ctx = await make_context(browser)
                await hunt_queue.put(ctx)
                all_contexts.append(ctx)

            try:
                tasks = [
                    asyncio.create_task(
                        process_url(
                            sem, url, i + 1, len(urls),
                            browser=browser,
                            context_queue=context_queue,
                            hunt_queue=hunt_queue,
                            http_client=http_client,
                        )
                    )
                    for i, url in enumerate(urls)
                ]
                results = []
                for coro in asyncio.as_completed(tasks):
                    results.append(await coro)

            finally:
                for ctx in all_contexts:
                    try:
                        await ctx.close()
                    except Exception:
                        pass
                await browser.close()

    order = {normalize(u): i for i, u in enumerate(urls)}
    results.sort(key=lambda r: order.get(r.url, 9999))
    return results


def main():
    urls_file = Path("urls.txt")
    if not urls_file.exists():
        print("Error: urls.txt not found", file=sys.stderr)
        sys.exit(1)

    urls = [
        u.strip()
        for u in urls_file.read_text().splitlines()
        if u.strip() and not u.startswith("#")
    ]

    if URL_LIMIT:
        urls = urls[:URL_LIMIT]
        print(f"Limited to {URL_LIMIT} URLs")

    llm_status = "enabled" if CLIENT else "disabled (heuristics only)"
    print(f"LLM: {llm_status}")
    print(f"Processing {len(urls)} URLs (concurrency={CONCURRENCY})")
    print(f"Model: {MODEL} | Screenshots: {SCREENSHOTS}")
    print("-" * 60)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

    results = asyncio.run(main_async(urls))

    output = []
    for r in results:
        d = asdict(r)
        d["screenshot_path"] = d.pop("screenshot_path") or None
        output.append(d)
    RESULTS_FILE.write_text(json.dumps(output, indent=2))

    scams = sum(1 for r in results if r.classification == "scam")
    not_scams = sum(1 for r in results if r.classification == "not scam")
    unknowns = sum(1 for r in results if r.classification == "unknown")
    all_addrs = [a for r in results for a in r.crypto_addresses]
    by_chain = {}
    for a in all_addrs:
        ch = a.get("chain", "?")
        by_chain[ch] = by_chain.get(ch, 0) + 1

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  Total:     {len(results)}")
    print(f"  Scam:      {scams}")
    print(f"  Not scam:  {not_scams}")
    print(f"  Unknown:   {unknowns}")
    print(f"  Addresses: {len(all_addrs)}  {by_chain}")
    print(f"  Output:    {RESULTS_FILE}")


if __name__ == "__main__":
    main()