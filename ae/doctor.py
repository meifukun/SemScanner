#!/usr/bin/env python3

import argparse
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

# Keep direct execution (``python ae/doctor.py``) independent of the caller's
# working directory and of an externally configured PYTHONPATH.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from seleniumwire import webdriver
from OpenSSL import crypto

from utils.chrome_driver import configure_chrome_options, make_chrome_service


def command_version(executable: str, *args: str) -> str:
    path = shutil.which(executable)
    if not path:
        raise RuntimeError(f"{executable} is not on PATH")
    result = subprocess.run(
        [path, *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return result.stdout.strip().splitlines()[0]


def major_version(text: str) -> str:
    match = re.search(r"\b(\d+)\.", text)
    if not match:
        raise RuntimeError(f"Cannot parse version from: {text}")
    return match.group(1)


def verify_beacon() -> None:
    beacon_url = os.environ.get(
        "SEMSCANNER_XSS_BEACON_URL", "http://127.0.0.1:9091/"
    )
    beacon_log = Path(
        os.environ.get(
            "SEMSCANNER_XSS_BEACON_LOG", "/tmp/semscanner-xss/http_captured.txt"
        )
    )
    token = f"doctor_{uuid.uuid4().hex}"
    url = f"{beacon_url}?{urllib.parse.urlencode({'data': token})}"
    with urllib.request.urlopen(url, timeout=5) as response:
        if response.status != 200:
            raise RuntimeError(f"Beacon listener returned HTTP {response.status}")

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if beacon_log.exists() and token in beacon_log.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            print(f"[OK] XSS callback listener: {beacon_url}")
            return
        time.sleep(0.1)
    raise RuntimeError(f"Beacon token was not written to {beacon_log}")


def verify_browser(target_url: str | None) -> None:
    options = webdriver.ChromeOptions()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.page_load_strategy = "eager"
    options = configure_chrome_options(options)

    driver = webdriver.Chrome(service=make_chrome_service(), options=options)
    try:
        driver.set_page_load_timeout(30)
        driver.set_window_size(1920, 1080)
        if target_url:
            target_host = urllib.parse.urlparse(target_url).hostname

            def restrict_to_target(request) -> None:
                request_host = urllib.parse.urlparse(request.url).hostname
                if request_host != target_host:
                    request.abort()

            # Match the scanner's same-target request policy. This also keeps
            # the connectivity check deterministic when a packaged target
            # references optional CDN assets.
            driver.request_interceptor = restrict_to_target
            driver.execute_cdp_cmd("Network.enable", {})
            driver.execute_cdp_cmd(
                "Network.setBlockedURLs",
                {
                    "urls": [
                        "http://clients2.google.com/*",
                        "https://ajax.googleapis.com/*",
                        "https://use.fontawesome.com/*",
                        "https://fonts.googleapis.com/*",
                        "https://fonts.gstatic.com/*",
                    ]
                },
            )
        url = target_url or "data:text/html,<title>SemScanner%20AE</title><h1>OK</h1>"
        driver.get(url)
        if target_url:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                current_host = urllib.parse.urlparse(driver.current_url).hostname
                body_ready = driver.execute_script("return document.body !== null")
                if current_host == target_host and body_ready:
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError(
                    f"Headless browser did not render target {target_url}; "
                    f"current URL is {driver.current_url}"
                )
            if driver.current_url != target_url:
                print(
                    f"[INFO] Target redirected from {target_url} to {driver.current_url}"
                )
        print(f"[OK] Headless browser session: {driver.current_url}")
    finally:
        driver.quit()


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate the SemScanner AE runtime")
    parser.add_argument("--target-url", help="Optional target URL reachable in Docker")
    args = parser.parse_args()

    print(f"[OK] Python: {sys.version.split()[0]}")
    chromium = command_version(os.environ.get("CHROME_BINARY", "chromium"), "--version")
    chromedriver = command_version(
        os.environ.get("CHROMEDRIVER_PATH", "chromedriver"), "--version"
    )
    if major_version(chromium) != major_version(chromedriver):
        raise RuntimeError(
            f"Browser/driver major versions differ: {chromium!r} vs {chromedriver!r}"
        )
    print(f"[OK] Browser: {chromium}")
    print(f"[OK] Driver: {chromedriver}")
    print(f"[OK] sqlmap: {command_version('sqlmap', '--version')}")
    if not hasattr(crypto.X509(), "get_extension"):
        raise RuntimeError(
            "pyOpenSSL is incompatible with Selenium Wire's certificate parser"
        )
    print("[OK] Selenium Wire certificate compatibility")

    import autonomous_test  # noqa: F401

    print("[OK] SemScanner imports")
    verify_beacon()
    verify_browser(args.target_url)

    model = os.environ.get("LLM_MODEL", "<default in config/llm_config.py>")
    endpoint = os.environ.get("LLM_BASE_URL", "https://api.openai.com/v1")
    key_status = "set" if os.environ.get("LLM_API_KEY") else "not set"
    print(f"[INFO] LLM endpoint: {endpoint}")
    print(f"[INFO] LLM model: {model}")
    print(f"[INFO] LLM_API_KEY: {key_status} (no API request made by doctor)")
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
