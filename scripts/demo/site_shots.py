"""Screenshot site/index.html at desktop and phone width, and fail on horizontal scroll at 375px.

Needs Playwright (jobwatch's venv has it).  Serves site/ on a throwaway port and stops it when done.

    python scripts/site_shots.py [OUTDIR]
"""

from __future__ import annotations

import functools
import http.server
import sys
import threading
from pathlib import Path

from playwright.sync_api import sync_playwright

SITE = Path(__file__).resolve().parent.parent / "site"
SIZES = {"1440": (1440, 900), "375": (375, 812)}


def main() -> int:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "site-shots")
    out.mkdir(parents=True, exist_ok=True)
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(SITE))
    handler.log_message = lambda *a, **k: None
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    status = 0
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            for scheme in ("light", "dark"):
                for name, (w, h) in SIZES.items():
                    page = browser.new_page(viewport={"width": w, "height": h}, color_scheme=scheme)
                    page.goto(url)
                    page.wait_for_timeout(900)
                    path = out / f"{name}-{scheme}.png"
                    page.screenshot(path=str(path), full_page=True)
                    overflow = page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
                    print(path, "horizontal overflow px:", overflow)
                    if overflow > 0:
                        status = 1
                    page.close()
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
    return status


if __name__ == "__main__":
    raise SystemExit(main())
