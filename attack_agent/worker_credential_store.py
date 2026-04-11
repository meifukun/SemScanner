"""
WorkerCredentialStore - Credential store for a single attack worker thread.

Each worker thread independently manages its own credentials and CSRF tokens.
"""

import re
from typing import Dict, Any


class WorkerCredentialStore:
    """
    Credential and token store for a single worker thread.

    Responsibilities:
    1. Extract and store credentials from driver (cookies, localStorage, sessionStorage, headers)
    2. Extract and store CSRF tokens from the page
    3. Provide access interface for credentials and tokens
    """

    def __init__(self, worker_id: int):
        """
        Initialize the worker credential store.

        Args:
            worker_id: Worker ID (used for log identification)
        """
        self.worker_id = worker_id
        self.credentials: Dict[str, Any] = {}
        self.csrf_tokens: Dict[str, str] = {}

    def update_from_driver(self, driver, account_manager):
        """
        Extract the latest credentials and CSRF tokens from the driver.

        Args:
            driver: Selenium WebDriver instance
            account_manager: AccountManager instance (used to call _extract_credentials)
        """
        # 1. Extract credentials (cookies, localStorage, sessionStorage, headers)
        self.credentials = account_manager._extract_credentials(driver)

        # 2. Extract CSRF tokens
        self.csrf_tokens = self._extract_csrf_tokens(driver)

    def _extract_csrf_tokens(self, driver) -> Dict[str, str]:
        """
        Extract CSRF-related tokens from the page.

        Sources:
        1. hidden inputs (name contains csrf/token/nonce)
        2. meta tags (name="csrf-token" or "csrf_token")
        3. localStorage (key contains csrf/token)

        Args:
            driver: Selenium WebDriver instance

        Returns:
            {token_name: token_value} dict
        """
        try:
            tokens = driver.execute_script("""
                var tokens = {};
                
                // 1. Extract from hidden inputs (name contains csrf/token/nonce keywords)
                document.querySelectorAll('input[type="hidden"]').forEach(function(input) {
                    if (!input.name) return;
                    
                    var name = input.name.toLowerCase();
                    if (name.includes('csrf') || 
                        name.includes('token') || 
                        name.includes('nonce') ||
                        name.includes('_token') ||
                        name.includes('authenticity')) {
                        tokens[input.name] = input.value;
                    }
                });
                
                // 2. Extract from meta tags
                var metaSelectors = [
                    'meta[name="csrf-token"]',
                    'meta[name="csrf_token"]',
                    'meta[name="X-CSRF-Token"]',
                    'meta[name="_token"]'
                ];
                
                metaSelectors.forEach(function(selector) {
                    var meta = document.querySelector(selector);
                    if (meta) {
                        var name = meta.getAttribute('name');
                        tokens[name] = meta.content || meta.getAttribute('content');
                    }
                });
                
                // 3. Extract from localStorage
                try {
                    for (var i = 0; i < localStorage.length; i++) {
                        var key = localStorage.key(i);
                        if (!key) continue;
                        
                        var keyLower = key.toLowerCase();
                        if (keyLower.includes('csrf') || 
                            keyLower.includes('token') ||
                            keyLower.includes('nonce')) {
                            tokens[key] = localStorage.getItem(key);
                        }
                    }
                } catch(e) {
                    // localStorage may be disabled
                }
                
                return tokens;
            """)

            return tokens or {}

        except Exception as e:
            # JavaScript execution failed, return empty dict
            return {}

    def get_credentials(self) -> Dict[str, Any]:
        """
        Get currently stored credentials.

        Returns:
            Credentials dict (includes cookies, localStorage, sessionStorage, headers)
        """
        return self.credentials

    def get_csrf_tokens(self) -> Dict[str, str]:
        """
        Get currently stored CSRF tokens.

        Returns:
            {token_name: token_value} dict
        """
        return self.csrf_tokens

    def has_csrf_tokens(self) -> bool:
        """
        Check whether any CSRF tokens are present.

        Returns:
            True if tokens exist, False otherwise
        """
        return len(self.csrf_tokens) > 0

    def __repr__(self):
        """String representation"""
        csrf_count = len(self.csrf_tokens)
        csrf_names = list(self.csrf_tokens.keys()) if csrf_count > 0 else []

        return (f"WorkerCredentialStore(worker_id={self.worker_id}, "
                f"csrf_tokens={csrf_count} {csrf_names})")
    
    