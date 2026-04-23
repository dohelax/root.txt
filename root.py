#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════╗
║  ROOT.PY - HTTP Stress Test Tool v2.0                    ║
║  Multi-threaded load tester with auto proxy rotation     ║
╚══════════════════════════════════════════════════════════╝
Author  : Dohela
Site    : https://dohela.com
Github  : https://github.com/dohelax
Python  : 3.7+
"""

import sys
import os
import subprocess
import importlib
import argparse
import time
import json
import re

# ── Version ──
__version__ = "2.0.0"

# ══════════════════════════════════════════════════════════
#  DEPENDENCY MANAGEMENT
# ══════════════════════════════════════════════════════════

REQUIRED_PACKAGES = {
    "requests":          "requests",
    "selenium":          "selenium",
    "webdriver_manager": "webdriver-manager",
    "bs4":               "beautifulsoup4",
}

def _check_missing():
    missing = {}
    for imp, pip_name in REQUIRED_PACKAGES.items():
        try:
            importlib.import_module(imp)
        except ImportError:
            missing[imp] = pip_name
    return missing

def _install(packages: dict):
    ok, fail = [], []
    print(f"\n[*] Installing {len(packages)} package(s) ...")
    for imp, pip_name in packages.items():
        try:
            print(f"    -> {pip_name} ... ", end="", flush=True)
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", pip_name, "--quiet"],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            importlib.import_module(imp)
            print("OK")
            ok.append(pip_name)
        except Exception as e:
            print(f"FAIL ({e})")
            fail.append(pip_name)
    return ok, fail

def ensure_dependencies():
    missing = _check_missing()
    if not missing:
        return
    print("\n" + "=" * 55)
    print("  MISSING DEPENDENCIES")
    print("=" * 55)
    for i, (imp, pip) in enumerate(missing.items(), 1):
        print(f"    {i}. {pip:<25} (import: {imp})")
    print("-" * 55)
    while True:
        try:
            a = input("  Install now? [Y/n]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            sys.exit(1)
        if a in ("", "y", "yes", "e", "evet"):
            break
        if a in ("n", "no", "h", "hayir"):
            print("[!] Exiting."); sys.exit(1)

    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip", "--quiet"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
    ok, fail = _install(missing)
    if fail:
        print(f"[!] Failed: {', '.join(fail)}")
        sys.exit(1)
    print("[+] All dependencies ready!\n")

ensure_dependencies()

# ── Imports (safe after dependency check) ──
import threading
import random
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

# ══════════════════════════════════════════════════════════
#  PROXY MANAGER
# ══════════════════════════════════════════════════════════

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROXY_FILE = os.path.join(SCRIPT_DIR, "proxies.txt")
PROXY_META = os.path.join(SCRIPT_DIR, "proxies_meta.json")

PROXY_SOURCES = [
    ("ProxyScrape HTTP",  "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all", ""),
    ("ProxyScrape SOCKS4","https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000&country=all", "socks4://"),
    ("ProxyScrape SOCKS5","https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all", "socks5://"),
    ("SpeedX HTTP",       "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt", ""),
    ("SpeedX SOCKS4",     "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt", "socks4://"),
    ("SpeedX SOCKS5",     "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt", "socks5://"),
    ("Monosans HTTP",     "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt", ""),
    ("Monosans SOCKS4",   "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt", "socks4://"),
    ("Monosans SOCKS5",   "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt", "socks5://"),
    ("Clarketm HTTP",     "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt", ""),
]

proxy_list = []
proxy_lock = threading.Lock()

def _fetch_source(name, url, prefix):
    proxies = []
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        for line in r.text.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                p = (prefix + line) if prefix and not line.startswith("socks") else line
                if not p.startswith(("http://", "https://", "socks4://", "socks5://")):
                    p = "http://" + p
                proxies.append(p)
    except Exception:
        pass
    return proxies

def fetch_all_proxies():
    results = {}
    threads = []
    def worker(i, n, u, p):
        results[i] = _fetch_source(n, u, p)
    print("\n[*] Fetching proxies from sources ...")
    for i, (n, u, p) in enumerate(PROXY_SOURCES):
        t = threading.Thread(target=worker, args=(i, n, u, p))
        t.start(); threads.append(t)
    for t in threads:
        t.join(timeout=30)
    all_p = []
    for i, (n, _, _) in enumerate(PROXY_SOURCES):
        got = results.get(i, [])
        s = f"{len(got)} proxies" if got else "FAILED"
        print(f"    [{n:<22}] {s}")
        all_p.extend(got)
    return list(dict.fromkeys(all_p))

def save_proxies(proxies):
    with open(PROXY_FILE, "w", encoding="utf-8") as f:
        f.write(f"# Proxies - {time.strftime('%Y-%m-%d %H:%M:%S')} - {len(proxies)} total\n")
        for p in proxies:
            f.write(p + "\n")
    meta = {
        "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total": len(proxies),
        "http": sum(1 for p in proxies if p.startswith("http")),
        "socks4": sum(1 for p in proxies if p.startswith("socks4")),
        "socks5": sum(1 for p in proxies if p.startswith("socks5")),
    }
    with open(PROXY_META, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    return meta

def load_proxies_file():
    if not os.path.exists(PROXY_FILE):
        return []
    with open(PROXY_FILE, "r", encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]

def update_proxies():
    global proxy_list
    print("\n" + "=" * 55)
    print("  PROXY UPDATE")
    print("=" * 55)
    proxies = fetch_all_proxies()
    if not proxies:
        old = load_proxies_file()
        if old:
            print(f"[*] Using {len(old)} cached proxies")
            proxy_list = old
        else:
            print("[!] No proxies. Running without proxy.")
            proxy_list = []
        return
    meta = save_proxies(proxies)
    print(f"\n[+] Proxies ready: {meta['total']} (HTTP:{meta['http']} S4:{meta['socks4']} S5:{meta['socks5']})")
    print(f"    Saved: {PROXY_FILE}\n")
    proxy_list = proxies

def get_proxy():
    if not proxy_list:
        return None
    with proxy_lock:
        return random.choice(proxy_list)

def proxy_dict(p):
    if not p:
        return None
    return {"http": p, "https": p}

# ══════════════════════════════════════════════════════════
#  GLOBAL STATE
# ══════════════════════════════════════════════════════════
target_url = ""
request_counter = 0
stop_flag = 0  # 0=run, 1=stopping, 2=stopped
counter_lock = threading.Lock()

def inc_counter():
    global request_counter
    with counter_lock:
        request_counter += 1

# ══════════════════════════════════════════════════════════
#  HTTP ENGINE
# ══════════════════════════════════════════════════════════

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/119.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1",
]

REFERERS = [
    "https://www.google.com/", "https://www.bing.com/",
    "https://www.yahoo.com/", "https://duckduckgo.com/",
    "https://www.facebook.com/", "https://twitter.com/",
]

def create_driver(proxy_str=None):
    opts = Options()
    opts.add_argument("--headless")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--disable-extensions")
    if proxy_str and not proxy_str.startswith("socks"):
        clean = re.sub(r"^https?://", "", proxy_str)
        opts.add_argument(f"--proxy-server={clean}")
    return webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=opts)

def fetch_selenium(url):
    driver = None
    try:
        driver = create_driver(get_proxy())
        driver.set_page_load_timeout(15)
        driver.get(url)
        src = driver.page_source
        driver.quit()
        return src
    except Exception:
        if driver:
            try: driver.quit()
            except: pass
        return None

def fetch_requests(url):
    s = requests.Session()
    adapter = HTTPAdapter(max_retries=Retry(total=2, backoff_factor=0.1, status_forcelist=[500,502,503,504]))
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Cache-Control": "no-cache",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": random.choice(REFERERS),
    }
    try:
        r = s.get(url, headers=headers, proxies=proxy_dict(get_proxy()), timeout=10)
        r.raise_for_status()
        return r.text
    except Exception:
        return None

def http_call(url, use_selenium=False):
    if not url.startswith("http"):
        url = "http://" + url
    result = fetch_requests(url)
    if not result and use_selenium:
        result = fetch_selenium(url)
    if result:
        inc_counter()

# ══════════════════════════════════════════════════════════
#  THREADS
# ══════════════════════════════════════════════════════════

class WorkerThread(threading.Thread):
    def __init__(self, url, use_selenium=False, safe_mode=False):
        super().__init__(daemon=True)
        self._url = url
        self._sel = use_selenium
        self._safe = safe_mode

    def run(self):
        try:
            while stop_flag < 2:
                http_call(self._url, self._sel)
                if self._safe and stop_flag == 1:
                    break
        except Exception:
            pass

class MonitorThread(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)

    def run(self):
        prev = 0
        start = time.time()
        while stop_flag == 0:
            time.sleep(1)
            curr = request_counter
            if curr > prev:
                elapsed = time.time() - start
                rps = curr / elapsed if elapsed > 0 else 0
                pinfo = f"Proxies:{len(proxy_list)}" if proxy_list else "NoProxy"
                print(f"  [+] {curr} sent | {rps:.1f} req/s | {pinfo}")
                prev = curr

# ══════════════════════════════════════════════════════════
#  CLI & HELP
# ══════════════════════════════════════════════════════════

BANNER = r"""
 ____   ___   ___ _____   ______   __
|  _ \ / _ \ / _ \_   _| |  _ \ \ / /
| |_) | | | | | | || |   | |_) \ V /
|  _ <| |_| | |_| || |   |  __/ | |
|_| \_\\___/ \___/ |_|   |_|    |_|
"""

def build_parser():
    parser = argparse.ArgumentParser(
        prog="root.py",
        description="HTTP Stress Test Tool v{} - Multi-threaded load tester with auto proxy rotation".format(__version__),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python3 root.py http://example.com
  python3 root.py http://example.com -t 100
  python3 root.py http://example.com -t 200 --safe
  python3 root.py http://example.com --no-proxy
  python3 root.py http://example.com --no-selenium -t 80
  python3 root.py --update-proxies

notes:
  - Proxies are auto-fetched from 10 public sources on every run
  - Use --no-proxy to send requests directly (no proxy rotation)
  - Use --no-selenium to skip Selenium fallback (faster, lighter)
  - Press Ctrl+C to stop at any time
  - Proxy list is saved to proxies.txt in the script directory
        """,
    )

    parser.add_argument("url", nargs="?", default=None,
                        help="Target URL to test (e.g. http://example.com)")

    parser.add_argument("-t", "--threads", type=int, default=50,
                        help="Number of concurrent threads (default: 50)")

    parser.add_argument("-s", "--safe", action="store_true",
                        help="Safe mode: auto-stop after one full cycle")

    parser.add_argument("--no-proxy", action="store_true",
                        help="Disable proxy rotation, send requests directly")

    parser.add_argument("--no-selenium", action="store_true",
                        help="Disable Selenium fallback (requests only, faster)")

    parser.add_argument("--update-proxies", action="store_true",
                        help="Only update proxy list and exit")

    parser.add_argument("--proxy-file", type=str, default=None,
                        help="Use a custom proxy file instead of auto-fetch")

    parser.add_argument("-v", "--version", action="version",
                        version=f"root.py v{__version__}")

    return parser

# ══════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════

def main():
    global target_url, stop_flag, proxy_list

    parser = build_parser()
    args = parser.parse_args()

    print(BANNER)
    print(f"  HTTP Stress Test Tool v{__version__}")
    print(f"  Python {sys.version.split()[0]}")
    print()

    # -- Proxy-only mode --
    if args.update_proxies:
        update_proxies()
        print("[*] Done. Proxy list updated.")
        sys.exit(0)

    # -- URL required --
    if not args.url:
        parser.print_help()
        sys.exit(1)

    # -- Validate URL --
    target_url = args.url
    if not target_url.startswith("http"):
        target_url = "http://" + target_url
    if target_url.count("/") == 2:
        target_url += "/"

    # -- Proxy setup --
    if args.no_proxy:
        print("[*] Proxy disabled by --no-proxy flag")
        proxy_list = []
    elif args.proxy_file:
        if not os.path.exists(args.proxy_file):
            print(f"[!] Proxy file not found: {args.proxy_file}")
            sys.exit(1)
        with open(args.proxy_file, "r") as f:
            proxy_list = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        print(f"[+] Loaded {len(proxy_list)} proxies from {args.proxy_file}")
    else:
        update_proxies()

    # -- Thread count validation --
    thread_count = max(1, min(args.threads, 500))
    if thread_count != args.threads:
        print(f"[!] Thread count clamped to {thread_count} (range: 1-500)")

    # -- Summary --
    print("=" * 55)
    print("  TEST STARTED")
    print("=" * 55)
    print(f"  Target  : {target_url}")
    print(f"  Threads : {thread_count}")
    print(f"  Proxies : {len(proxy_list)}")
    print(f"  Selenium: {'OFF' if args.no_selenium else 'ON (fallback)'}")
    print(f"  Mode    : {'Safe (auto-stop)' if args.safe else 'Continuous'}")
    print(f"  Stop    : Ctrl+C")
    print("=" * 55)
    print()

    # -- Launch workers --
    use_sel = not args.no_selenium
    for _ in range(thread_count):
        WorkerThread(target_url, use_selenium=use_sel, safe_mode=args.safe).start()
    MonitorThread().start()

    # -- Main loop --
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_flag = 2
        print(f"\n[!] Stopped. Total requests: {request_counter}")
        sys.exit(0)


if __name__ == "__main__":
    main()
