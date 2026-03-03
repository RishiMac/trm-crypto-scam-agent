"""
pipeline.py — Per-URL processing pipeline.

Three-pass design:
  Pass 1+2: Initial fetch and LLM classify, with retry for thin-but-reachable pages.
            Uses context_queue; context returned IMMEDIATELY after classify.
  Pass 3:   Address hunt + screenshot for confirmed scams. Uses hunt_queue —
            separate pool to prevent context starvation.

The two-queue architecture ensures initial fetches are never blocked waiting
for address hunts on long-running scam pages.
"""
import asyncio
import hashlib
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import httpx

from config import (
    SCREENSHOTS, SCREENSHOT_DIR,
    CANDIDATE_PATHS, SCAM_EXTRA_PATHS, THIN_CONTENT,
)
from fetcher import FetchResult, fetch, fetch_playwright, normalize
from classifier import llm_classify, url_scam_score, final_url_is_spa
from addresses import regex_extract, merge_addresses


@dataclass
class Result:
    url: str
    classification: str = "unknown"
    confidence: float = 0.2
    reasoning: str = ""
    crypto_addresses: list = field(default_factory=list)
    screenshot_path: str = ""
    final_url: str = ""
    status_code: int = 0
    error: str = ""


async def process_url(
    sem,
    url,
    idx,
    total,
    *,
    browser=None,
    context_queue=None,
    hunt_queue=None,
    http_client=None,
):
    url = normalize(url)
    task_id = hashlib.sha1(f"{url}-{time.time_ns()}".encode()).hexdigest()[:6]

    async with sem:
        print(f"[{idx}/{total}] {url} task={task_id}")
        t0 = time.monotonic()

        # Pass 1 + 2: fetch & classify
        context = None
        if context_queue is not None:
            context = await context_queue.get()
        try:
            fetch_r = await fetch(url, take_screenshot=False, browser=browser, http_client=http_client, context=context,)

            if (fetch_r.status == 0
                    and not (fetch_r.content or "").strip()
                    and not fetch_r.error):
                fetch_r.error = "Fetch failed (status 0, empty content)"

            llm_result = llm_classify(url, fetch_r)
            classification = llm_result["classification"]

            # Retry unknowns that returned status 200 with thin content
            if classification == "unknown" and fetch_r.status == 200 and context:
                print(f"  [RETRY] {url}")
                fetch_r2 = await fetch_playwright(url, take_screenshot=False, context=context, extra_paths=CANDIDATE_PATHS,)
                if fetch_r2.content and len(fetch_r2.content) > len(fetch_r.content or ""):
                    fetch_r = fetch_r2
                    llm_result = llm_classify(url, fetch_r)
                    classification = llm_result["classification"]
                    print(f"  [RETRY] → {classification} ({llm_result['confidence']:.2f})")

                # If still unknown, apply URL + final_url heuristic as final tiebreaker
                if classification == "unknown":
                    score = url_scam_score(url, fetch_r.final_url or url)
                    is_spa = final_url_is_spa(fetch_r.final_url or "")
                    if score >= 0.4 or is_spa:
                        classification = "scam"
                        note = (
                            f" [url heuristic score={score:.2f}]" if not is_spa
                            else f" [SPA pattern: {fetch_r.final_url}]"
                        )
                        llm_result = {
                            **llm_result,
                            "classification": "scam",
                            "confidence": min(0.7, score + 0.1),
                            "reasoning": llm_result.get("reasoning", "") + note,
                        }
                        print(f"  [HEURISTIC] → scam (url score={score:.2f}, spa={is_spa})")

        finally:
            # Return context to pool BEFORE addr hunt to prevent starvation
            if context_queue is not None and context is not None:
                context_queue.put_nowait(context)
            context = None

        # Force unknown for blocked+thin pages that slipped through
        if (classification != "scam" and fetch_r.status in (401, 403, 429, 521, 522) and len(fetch_r.content or "") < THIN_CONTENT):
            classification = "unknown"
            llm_result = {
                **llm_result,
                "classification": "unknown",
                "reasoning": llm_result.get("reasoning", "") + " [forced unknown: blocked+thin]",
            }

        # Pass 3: address hunt + screenshot (scams only)
        raw_text = (fetch_r.raw_html or "") + "\n" + (fetch_r.content or "")
        screenshot = ""

        if classification == "scam":
            hunt_ctx = None
            if hunt_queue is not None:
                hunt_ctx = await hunt_queue.get()
            try:
                print(f"  [ADDR HUNT] {url}")
                hunt_r = await fetch_playwright(url, take_screenshot=False, context=hunt_ctx, extra_paths=SCAM_EXTRA_PATHS,)
                raw_text += "\n" + (hunt_r.raw_html or "") + "\n" + (hunt_r.content or "")

                if SCREENSHOTS and hunt_ctx:
                    try:
                        ss_r = await fetch_playwright(url, take_screenshot=True, context=hunt_ctx)
                        if getattr(ss_r, "screenshot_bytes", None):
                            SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
                            safe = re.sub(r"[^\w\-.]", "_", urlparse(url).netloc or "unknown")[:60]
                            h = hashlib.sha1(url.encode()).hexdigest()[:8]
                            path = SCREENSHOT_DIR / f"{safe}_{h}.png"
                            path.write_bytes(ss_r.screenshot_bytes)
                            screenshot = str(path)
                    except Exception:
                        pass
            finally:
                if hunt_queue is not None and hunt_ctx is not None:
                    hunt_queue.put_nowait(hunt_ctx)

        # Address extraction
        regex_addrs = regex_extract(raw_text, relaxed=(classification == "scam"))
        addresses = merge_addresses(llm_result.get("crypto_addresses") or [], regex_addrs if classification in ("scam", "unknown") else [],)

        # Post-hunt reclassification: addresses found on an "unknown" site means scam
        # pugmeme.io pattern: bot wall blocked initial classify but hunt found addrs
        if classification == "unknown" and len(addresses) >= 1:
            classification = "scam"
            llm_result = {
                **llm_result,
                "classification": "scam",
                "confidence": 0.85,
                "reasoning": (llm_result.get("reasoning", "") + f" [reclassified: {len(addresses)} crypto address(es) found post-hunt]"),
            }
            print(f"  [POST-HUNT] reclassified → scam ({len(addresses)} addresses found)")

        elapsed = time.monotonic() - t0
        print(
            f"[{idx}/{total}] DONE {url} → {classification} "
            f"({llm_result['confidence']:.2f}) task={task_id} "
            f"| addrs={len(addresses)} | {elapsed:.1f}s"
        )
        for a in addresses:
            print(f"    {a['chain']}: {a['address']}")

        return Result(
            url=url,
            classification=classification,
            confidence=llm_result["confidence"],
            reasoning=llm_result["reasoning"],
            crypto_addresses=addresses,
            screenshot_path=screenshot,
            final_url=fetch_r.final_url or url,
            status_code=fetch_r.status,
            error=fetch_r.error,
        )