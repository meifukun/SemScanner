"""
WorkerCredentialStore - 单个攻击线程的凭证存储

每个worker线程独立管理自己的凭证和CSRF token
"""

import re
from typing import Dict, Any


class WorkerCredentialStore:
    """
    单个worker线程的凭证和token存储
    
    职责：
    1. 从driver提取并存储凭证（cookies, localStorage, sessionStorage, headers）
    2. 从页面提取并存储CSRF token
    3. 提供凭证和token的访问接口
    """

    def __init__(self, worker_id: int):
        """
        初始化worker凭证存储
        
        Args:
            worker_id: worker编号（用于日志标识）
        """
        self.worker_id = worker_id
        self.credentials: Dict[str, Any] = {}
        self.csrf_tokens: Dict[str, str] = {}

    def update_from_driver(self, driver, account_manager):
        """
        从driver提取最新凭证和CSRF token
        
        Args:
            driver: Selenium WebDriver实例
            account_manager: AccountManager实例（用于调用_extract_credentials方法）
        """
        # 1. 提取凭证（cookies, localStorage, sessionStorage, headers）
        self.credentials = account_manager._extract_credentials(driver)

        # 2. 提取CSRF token
        self.csrf_tokens = self._extract_csrf_tokens(driver)

    def _extract_csrf_tokens(self, driver) -> Dict[str, str]:
        """
        从页面提取CSRF相关token
        
        提取来源：
        1. hidden input（name包含csrf/token/nonce）
        2. meta标签（name="csrf-token" 或 "csrf_token"）
        3. localStorage（key包含csrf/token）
        
        Args:
            driver: Selenium WebDriver实例
        
        Returns:
            {token_name: token_value} 字典
        """
        try:
            tokens = driver.execute_script("""
                var tokens = {};
                
                // 1. 从hidden input提取（name包含csrf/token/nonce关键词）
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
                
                // 2. 从meta标签提取
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
                
                // 3. 从localStorage提取
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
                    // localStorage可能被禁用
                }
                
                return tokens;
            """)

            return tokens or {}

        except Exception as e:
            # JavaScript执行失败，返回空字典
            return {}

    def get_credentials(self) -> Dict[str, Any]:
        """
        获取当前存储的凭证
        
        Returns:
            凭证字典（包含cookies, localStorage, sessionStorage, headers）
        """
        return self.credentials

    def get_csrf_tokens(self) -> Dict[str, str]:
        """
        获取当前存储的CSRF token
        
        Returns:
            {token_name: token_value} 字典
        """
        return self.csrf_tokens

    def has_csrf_tokens(self) -> bool:
        """
        检查是否有CSRF token
        
        Returns:
            True if有token, False otherwise
        """
        return len(self.csrf_tokens) > 0

    def __repr__(self):
        """字符串表示"""
        csrf_count = len(self.csrf_tokens)
        csrf_names = list(self.csrf_tokens.keys()) if csrf_count > 0 else []

        return (f"WorkerCredentialStore(worker_id={self.worker_id}, "
                f"csrf_tokens={csrf_count} {csrf_names})")
    
    