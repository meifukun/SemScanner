# -*- coding: utf-8 -*-
"""
Parallel Driver Manager - Responsible for creating independent driver instances consistent with the main driver's state
"""

import os
import time
import json
from typing import Dict, List, Optional
from seleniumwire import webdriver  # Use selenium-wire to support network request capture
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager


class ParallelDriverManager:
    """Parallel Driver Manager"""

    def __init__(self, account_manager, base_url: str, chrome_options=None, target_domain: str = None):
        """
        Initialize the Parallel Driver Manager

        Args:
            account_manager: AccountManager instance for obtaining credentials
            base_url: Base URL of the target application
            chrome_options: Chrome configuration options (optional, defaults to headless mode)
        """
        self.account_manager = account_manager
        self.base_url = base_url
        self.chrome_options = chrome_options
        self.driver_pool: List[webdriver.Chrome] = []
        # Determine target domain (prefer the passed value, otherwise extract from base_url)
        if target_domain:
            self.target_domain = target_domain
            print(f"[ParallelDriverManager] Using provided target domain: {self.target_domain}")
        else:
            from urllib.parse import urlparse
            parsed = urlparse(base_url)
            self.target_domain = parsed.hostname
            print(f"[ParallelDriverManager] Auto-extracted target domain from base_url: {self.target_domain}")

        print(f"[ParallelDriverManager] Initialization complete, base URL: {base_url}")

    def create_cloned_driver(self, account_id: str) -> webdriver.Chrome:
        """
        Create an independent driver consistent with the main driver's state

        Core approach:
        1. Create a brand new driver instance (independent process)
        2. Visit a same-domain page (must visit before setting cookies)
        3. Inject cookies
        4. Inject localStorage/sessionStorage
        5. Refresh the page to apply state

        Args:
            account_id: Account ID (obtain credentials from AccountManager)

        Returns:
            Configured independent driver instance

        Raises:
            ValueError: If account credentials do not exist
            Exception: If driver creation or configuration fails
        """
        print(f"\n{'='*60}")
        print(f"[CloneDriver] Starting independent driver creation - Account: {account_id}")
        print(f"{'='*60}")

        # ===== Step 1: Get credentials =====
        credentials = self.account_manager.get_credentials(account_id)
        if not credentials:
            raise ValueError(f"No credentials found for account: {account_id}")

        print(f"[CloneDriver] Credential info:")
        print(f"  - Cookies: {len(credentials.get('cookies', []))} items")
        print(f"  - LocalStorage: {len(credentials.get('localStorage', {}))} items")
        print(f"  - SessionStorage: {len(credentials.get('sessionStorage', {}))} items")

        # ===== Step 2: Create new driver (same configuration as main driver) =====
        chrome_options = self._create_chrome_options()

        print(f"[CloneDriver] Starting Chrome browser...")
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)

        driver.set_page_load_timeout(60)
        driver.set_script_timeout(60)
        driver.set_window_size(1920, 1080)

        # Configure request interceptor (consistent with main driver)
        def interceptor(request):
            request_url = request.url
            # if '127.0.0.1' not in request_url and 'localhost' not in request_url:
            if self.target_domain not in request_url:
                request.abort()

        driver.request_interceptor = interceptor

        # Inject XSS detection script with beacon URL (consistent with main driver)
        try:
            from config.llm_config import BEACON_URL
            xss_script_path = "js/xss_xhr.js"
            if os.path.exists(xss_script_path):
                with open(xss_script_path, "r") as f:
                    xss_script = f.read().replace("{BEACON_URL}", BEACON_URL.rstrip("/"))
                    driver.add_script(xss_script)
                print(f"[CloneDriver] XSS detection script injected")
        except Exception as e:
            print(f"[CloneDriver] XSS script injection failed: {e}")

        # Inject event listener capture script (original version)
        try:
            # Original version: md5.js + lib.js + addeventlistener_wrapper.js
            scripts = [
                "js/md5.js",
                "js/lib.js",
                "js/addeventlistener_wrapper.js"
            ]
            for script_path in scripts:
                if os.path.exists(script_path):
                    with open(script_path, "r") as f:
                        driver.add_script(f.read())
                    print(f"[CloneDriver] Injected: {script_path}")
                else:
                    print(f"[CloneDriver] Cannot find {script_path}")

            print(f"[CloneDriver] Event capture scripts fully injected (original version)")
        except Exception as e:
            print(f"[CloneDriver] Event capture script injection failed: {e}")

        print(f"[CloneDriver] Driver instance created successfully")

        # ===== Step 3: Visit domain root path (required!) =====
        # Key: Must visit a same-domain page before setting cookies
        # Otherwise driver.add_cookie() will throw: "invalid cookie domain"
        # Fix: Visit a simple root path first, not the target page requiring authentication
        from urllib.parse import urlparse
        parsed = urlparse(self.base_url)
        domain_root = f"{parsed.scheme}://{parsed.netloc}/"

        print(f"[CloneDriver] Visiting domain root path: {domain_root}")
        try:
            driver.get(domain_root)
            time.sleep(0.8)  # Wait for page load
            print(f"[CloneDriver] Domain root path loaded successfully")
        except Exception as e:
            print(f"[CloneDriver] Failed to visit domain root path: {e}")
            driver.quit()
            raise

        # ===== Step 4: Inject Cookies =====
        cookies = credentials.get('cookies', [])
        if cookies:
            print(f"[CloneDriver] Injecting {len(cookies)} cookies...")
            success_count = 0
            for cookie in cookies:
                try:
                    # Selenium required cookie format
                    # Remove fields that may cause issues
                    cookie_dict = {
                        'name': cookie['name'],
                        'value': cookie['value'],
                        'domain': cookie.get('domain'),
                        'path': cookie.get('path', '/'),
                        'secure': cookie.get('secure', False),
                        'httpOnly': cookie.get('httpOnly', False),
                    }

                    # =================================================
                    # [Fix] Enhanced Expiry handling logic
                    # =================================================
                    expiry = None
                    # First check standard selenium's expiry field
                    if 'expiry' in cookie:
                        expiry = cookie['expiry']
                    # Then check CDP's expires field
                    elif 'expires' in cookie:
                        expiry = cookie['expires']

                    # If expiry exists, perform strict cleaning
                    if expiry is not None:
                        # 1. If it's a Session Cookie (expiry is -1 or 0), don't set expiry
                        if expiry <= 0:
                            pass
                        else:
                            # 2. Force convert to int (remove decimal part)
                            cookie_dict['expiry'] = int(expiry)
                    # =================================================

                    # Optional fields
                    if 'sameSite' in cookie:
                        cookie_dict['sameSite'] = cookie['sameSite']

                    driver.add_cookie(cookie_dict)
                    success_count += 1
                except Exception as e:
                    print(f"[CloneDriver] Cookie injection failed [{cookie.get('name')}]: {e}")

            print(f"[CloneDriver] Cookies injection complete: {success_count}/{len(cookies)}")

        # ===== Step 5: Inject LocalStorage =====
        local_storage = credentials.get('localStorage', {})
        if local_storage:
            print(f"[CloneDriver] Injecting {len(local_storage)} localStorage items...")
            success_count = 0
            for key, value in local_storage.items():
                try:
                    # Escape special characters to avoid JavaScript injection errors
                    escaped_key = json.dumps(key)
                    escaped_value = json.dumps(value)
                    driver.execute_script(
                        f"localStorage.setItem({escaped_key}, {escaped_value});"
                    )
                    success_count += 1
                except Exception as e:
                    print(f"[CloneDriver] LocalStorage injection failed [{key}]: {e}")

            print(f"[CloneDriver] LocalStorage injection complete: {success_count}/{len(local_storage)}")

        # ===== Step 6: Inject SessionStorage =====
        session_storage = credentials.get('sessionStorage', {})
        if session_storage:
            print(f"[CloneDriver] Injecting {len(session_storage)} sessionStorage items...")
            success_count = 0
            for key, value in session_storage.items():
                try:
                    escaped_key = json.dumps(key)
                    escaped_value = json.dumps(value)
                    driver.execute_script(
                        f"sessionStorage.setItem({escaped_key}, {escaped_value});"
                    )
                    success_count += 1
                except Exception as e:
                    print(f"[CloneDriver] SessionStorage injection failed [{key}]: {e}")

            print(f"[CloneDriver] SessionStorage injection complete: {success_count}/{len(session_storage)}")

        # ===== Step 7: Visit target page (verify credentials are effective) =====
        print(f"[CloneDriver] Visiting target page: {self.base_url}")
        try:
            driver.get(self.base_url)
            time.sleep(1.0)  # Wait for page load and possible redirects
            print(f"[CloneDriver] Target page loaded successfully")
        except Exception as e:
            print(f"[CloneDriver] Failed to visit target page: {e}")

        # ===== Step 8: Verify login status =====
        try:
            current_url = driver.current_url
            current_cookies = driver.get_cookies()

            print(f"\n[CloneDriver] Verification info:")
            print(f"  - Target URL: {self.base_url}")
            print(f"  - Current URL: {current_url}")
            print(f"  - Current cookie count: {len(current_cookies)}")

            # Fix: Check if redirected to login page
            is_login_redirect = 'login' in current_url.lower() and 'login' not in self.base_url.lower()

            if is_login_redirect:
                print(f"  - Status: Redirected to login page, credentials may be invalid")
            else:
                # Verify URL is basically consistent (ignore hash and query parameter differences)
                from urllib.parse import urlparse
                target_path = urlparse(self.base_url).path
                current_path = urlparse(current_url).path

                if target_path == current_path:
                    print(f"  - Status: Successfully reached target page")
                else:
                    print(f"  - Status: URL path mismatch (may be a normal redirect)")

            # Compare cookie names (if original had cookies)
            if cookies:
                original_cookie_names = {c['name'] for c in cookies}
                current_cookie_names = {c['name'] for c in current_cookies}
                matched = len(original_cookie_names & current_cookie_names)
                match_rate = (matched/len(original_cookie_names)*100) if original_cookie_names else 0
                print(f"  - Cookie match rate: {matched}/{len(original_cookie_names)} ({match_rate:.1f}%)")

            print(f"\n[CloneDriver] Driver cloning complete!")
            print(f"{'='*60}\n")

        except Exception as e:
            print(f"[CloneDriver] Verification warning: {e}")

        # Add to driver pool
        self.driver_pool.append(driver)

        return driver

    def _create_chrome_options(self):
        """Create Chrome options configuration"""
        if self.chrome_options:
            # If configuration already exists, clone a copy and add independent user directory
            chrome_options = self.chrome_options
        else:
            # Create default configuration
            chrome_options = webdriver.ChromeOptions()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--disable-web-security")
            chrome_options.add_argument("--allow-running-insecure-content")
            chrome_options.add_argument("--disable-xss-auditor")

        # Key: Each driver uses an independent temp directory to avoid conflicts
        # Chrome does not allow multiple processes to share the same profile
        unique_id = f"{os.getpid()}_{id(chrome_options)}_{int(time.time()*1000)}"
        user_data_dir = f"/tmp/chrome_parallel_{unique_id}"
        chrome_options.add_argument(f"--user-data-dir={user_data_dir}")

        return chrome_options

    def cleanup_all(self):
        """Clean up all created drivers"""
        print(f"\n[ParallelDriverManager] Cleaning up {len(self.driver_pool)} drivers...")
        for i, driver in enumerate(self.driver_pool, 1):
            try:
                driver.quit()
                print(f"  [{i}/{len(self.driver_pool)}] Driver closed")
            except Exception as e:
                print(f"  [{i}/{len(self.driver_pool)}] Close failed: {e}")

        self.driver_pool.clear()
        print(f"[ParallelDriverManager] Cleanup complete\n")
