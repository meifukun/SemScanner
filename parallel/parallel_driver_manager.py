# -*- coding: utf-8 -*-
"""
并行Driver管理器 - 负责创建与主driver状态一致的独立driver实例
"""

import os
import time
import json
from typing import Dict, List, Optional
from seleniumwire import webdriver  # ✅ 使用selenium-wire以支持网络请求捕获
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager


class ParallelDriverManager:
    """并行Driver管理器"""

    def __init__(self, account_manager, base_url: str, chrome_options=None, target_domain: str = None):
        """
        初始化并行Driver管理器

        Args:
            account_manager: AccountManager实例，用于获取凭证
            base_url: 基础URL（如 http://127.0.0.1:4281）
            chrome_options: Chrome配置选项（可选，默认使用headless模式）
        """
        self.account_manager = account_manager
        self.base_url = base_url
        self.chrome_options = chrome_options
        self.driver_pool: List[webdriver.Chrome] = []
        # 🆕 确定目标域名（优先使用传入的，否则从base_url提取）
        if target_domain:
            self.target_domain = target_domain
            print(f"[ParallelDriverManager] 使用传入的目标域名: {self.target_domain}")
        else:
            from urllib.parse import urlparse
            parsed = urlparse(base_url)
            self.target_domain = parsed.hostname
            print(f"[ParallelDriverManager] 从base_url自动提取目标域名: {self.target_domain}")

        print(f"[ParallelDriverManager] 初始化完成，基础URL: {base_url}")

    def create_cloned_driver(self, account_id: str) -> webdriver.Chrome:
        """
        创建一个和主driver状态一致的独立driver

        核心思路：
        1. 创建全新的driver实例（独立进程）
        2. 访问同域页面（必须先访问才能设置cookies）
        3. 注入cookies
        4. 注入localStorage/sessionStorage
        5. 刷新页面使状态生效

        Args:
            account_id: 账户ID（从AccountManager获取凭证）

        Returns:
            配置好的独立driver实例

        Raises:
            ValueError: 如果账户凭证不存在
            Exception: 如果driver创建或配置失败
        """
        print(f"\n{'='*60}")
        print(f"[CloneDriver] 开始创建独立driver - 账户: {account_id}")
        print(f"{'='*60}")

        # ===== 步骤1: 获取凭证 =====
        credentials = self.account_manager.get_credentials(account_id)
        if not credentials:
            raise ValueError(f"No credentials found for account: {account_id}")

        print(f"[CloneDriver] 凭证信息:")
        print(f"  - Cookies: {len(credentials.get('cookies', []))} 个")
        print(f"  - LocalStorage: {len(credentials.get('localStorage', {}))} 项")
        print(f"  - SessionStorage: {len(credentials.get('sessionStorage', {}))} 项")

        # ===== 步骤2: 创建新driver（配置与主driver相同）=====
        chrome_options = self._create_chrome_options()

        print(f"[CloneDriver] 启动Chrome浏览器...")
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)

        driver.set_page_load_timeout(60)
        driver.set_script_timeout(60)
        driver.set_window_size(1920, 1080)

        # 配置请求拦截器（与主driver一致）
        def interceptor(request):
            request_url = request.url
            # if '127.0.0.1' not in request_url and 'localhost' not in request_url:
            if self.target_domain not in request_url:
                request.abort()

        driver.request_interceptor = interceptor

        # 注入XSS检测脚本（与主driver一致）
        try:
            xss_script_path = "js/xss_xhr.js"
            if os.path.exists(xss_script_path):
                with open(xss_script_path, "r") as f:
                    driver.add_script(f.read())
                print(f"[CloneDriver] ✅ XSS检测脚本已注入")
        except Exception as e:
            print(f"[CloneDriver] ⚠️ XSS脚本注入失败: {e}")

        # ✅ 注入事件监听器捕获脚本（原始版本）
        try:
            # 原始版本：md5.js + lib.js + addeventlistener_wrapper.js
            scripts = [
                "js/md5.js",
                "js/lib.js",
                "js/addeventlistener_wrapper.js"
            ]
            for script_path in scripts:
                if os.path.exists(script_path):
                    with open(script_path, "r") as f:
                        driver.add_script(f.read())
                    print(f"[CloneDriver] ✅ 已注入: {script_path}")
                else:
                    print(f"[CloneDriver] ⚠️ 找不到 {script_path}")

            print(f"[CloneDriver] ✅ 事件捕获脚本已完整注入（原始版本）")
        except Exception as e:
            print(f"[CloneDriver] ⚠️ 事件捕获脚本注入失败: {e}")

        print(f"[CloneDriver] ✅ Driver实例创建成功")

        # ===== 步骤3: 访问域名根路径（必须！）=====
        # ⚠️ 关键：在设置cookies前必须先访问同域页面
        # 否则driver.add_cookie()会报错："invalid cookie domain"
        # ✅ 修复：先访问一个简单的根路径，而不是需要认证的目标页面
        from urllib.parse import urlparse
        parsed = urlparse(self.base_url)
        domain_root = f"{parsed.scheme}://{parsed.netloc}/"

        print(f"[CloneDriver] 访问域名根路径: {domain_root}")
        try:
            driver.get(domain_root)
            time.sleep(0.8)  # 等待页面加载
            print(f"[CloneDriver] ✅ 域名根路径加载完成")
        except Exception as e:
            print(f"[CloneDriver] ⚠️ 访问域名根路径失败: {e}")
            driver.quit()
            raise

        # # ===== 步骤4: 注入Cookies =====
        # cookies = credentials.get('cookies', [])
        # if cookies:
        #     print(f"[CloneDriver] 注入 {len(cookies)} 个cookies...")
        #     success_count = 0
        #     for cookie in cookies:
        #         try:
        #             # ✅ Selenium要求的cookie格式
        #             # 移除可能导致问题的字段
        #             cookie_dict = {
        #                 'name': cookie['name'],
        #                 'value': cookie['value'],
        #                 'domain': cookie.get('domain'),
        #                 'path': cookie.get('path', '/'),
        #                 'secure': cookie.get('secure', False),
        #                 'httpOnly': cookie.get('httpOnly', False),
        #             }

        #             # 可选字段
        #             # 可选字段兼容处理
        #             if 'expiry' in cookie:
        #                 cookie_dict['expiry'] = int(cookie['expiry'])
        #             elif 'expires' in cookie:  # ✅ 新增：兼容 CDP 格式
        #                 cookie_dict['expiry'] = int(cookie['expires'])
        #             if 'sameSite' in cookie:
        #                 cookie_dict['sameSite'] = cookie['sameSite']

        #             driver.add_cookie(cookie_dict)
        #             success_count += 1
        #         except Exception as e:
        #             print(f"[CloneDriver] ⚠️ Cookie注入失败 [{cookie.get('name')}]: {e}")

        #     print(f"[CloneDriver] ✅ Cookies注入完成: {success_count}/{len(cookies)}")

        # ===== 步骤4: 注入Cookies =====
        cookies = credentials.get('cookies', [])
        if cookies:
            print(f"[CloneDriver] 注入 {len(cookies)} 个cookies...")
            success_count = 0
            for cookie in cookies:
                try:
                    # ✅ Selenium要求的cookie格式
                    # 移除可能导致问题的字段
                    cookie_dict = {
                        'name': cookie['name'],
                        'value': cookie['value'],
                        'domain': cookie.get('domain'),
                        'path': cookie.get('path', '/'),
                        'secure': cookie.get('secure', False),
                        'httpOnly': cookie.get('httpOnly', False),
                    }

                    # =================================================
                    # 🚑【修复】增强的 Expiry 处理逻辑
                    # =================================================
                    expiry = None
                    # 优先检查 standard selenium 的 expiry 字段
                    if 'expiry' in cookie:
                        expiry = cookie['expiry']
                    # 其次检查 CDP 的 expires 字段
                    elif 'expires' in cookie:
                        expiry = cookie['expires']
                    
                    # 如果存在 expiry，进行严格清洗
                    if expiry is not None:
                        # 1. 如果是 Session Cookie (过期时间为 -1 或 0)，直接不设置 expiry
                        if expiry <= 0:
                            pass 
                        else:
                            # 2. 强制转换为 int (去掉小数部分)
                            cookie_dict['expiry'] = int(expiry)
                    # =================================================

                    # 可选字段
                    if 'sameSite' in cookie:
                        cookie_dict['sameSite'] = cookie['sameSite']

                    driver.add_cookie(cookie_dict)
                    success_count += 1
                except Exception as e:
                    print(f"[CloneDriver] ⚠️ Cookie注入失败 [{cookie.get('name')}]: {e}")

            print(f"[CloneDriver] ✅ Cookies注入完成: {success_count}/{len(cookies)}")

        # ===== 步骤5: 注入LocalStorage =====
        local_storage = credentials.get('localStorage', {})
        if local_storage:
            print(f"[CloneDriver] 注入 {len(local_storage)} 个localStorage项...")
            success_count = 0
            for key, value in local_storage.items():
                try:
                    # ✅ 转义特殊字符，避免JavaScript注入错误
                    escaped_key = json.dumps(key)
                    escaped_value = json.dumps(value)
                    driver.execute_script(
                        f"localStorage.setItem({escaped_key}, {escaped_value});"
                    )
                    success_count += 1
                except Exception as e:
                    print(f"[CloneDriver] ⚠️ LocalStorage注入失败 [{key}]: {e}")

            print(f"[CloneDriver] ✅ LocalStorage注入完成: {success_count}/{len(local_storage)}")

        # ===== 步骤6: 注入SessionStorage =====
        session_storage = credentials.get('sessionStorage', {})
        if session_storage:
            print(f"[CloneDriver] 注入 {len(session_storage)} 个sessionStorage项...")
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
                    print(f"[CloneDriver] ⚠️ SessionStorage注入失败 [{key}]: {e}")

            print(f"[CloneDriver] ✅ SessionStorage注入完成: {success_count}/{len(session_storage)}")

        # ===== 步骤7: 访问目标页面（验证凭证是否生效）=====
        print(f"[CloneDriver] 访问目标页面: {self.base_url}")
        try:
            driver.get(self.base_url)
            time.sleep(1.0)  # 等待页面加载和可能的重定向
            print(f"[CloneDriver] ✅ 目标页面加载完成")
        except Exception as e:
            print(f"[CloneDriver] ⚠️ 访问目标页面失败: {e}")

        # ===== 步骤8: 验证登录状态 =====
        try:
            current_url = driver.current_url
            current_cookies = driver.get_cookies()

            print(f"\n[CloneDriver] 验证信息:")
            print(f"  - 目标URL: {self.base_url}")
            print(f"  - 当前URL: {current_url}")
            print(f"  - 当前Cookies数量: {len(current_cookies)}")

            # ✅ 修复：检查是否被重定向到登录页
            is_login_redirect = 'login' in current_url.lower() and 'login' not in self.base_url.lower()

            if is_login_redirect:
                print(f"  - 状态: ❌ 被重定向到登录页，凭证可能无效")
            else:
                # 验证URL是否基本一致（忽略hash和query参数的差异）
                from urllib.parse import urlparse
                target_path = urlparse(self.base_url).path
                current_path = urlparse(current_url).path

                if target_path == current_path:
                    print(f"  - 状态: ✅ 成功到达目标页面")
                else:
                    print(f"  - 状态: ⚠️ URL路径不一致（可能是正常重定向）")

            # 对比cookie名称（如果原始有cookies）
            if cookies:
                original_cookie_names = {c['name'] for c in cookies}
                current_cookie_names = {c['name'] for c in current_cookies}
                matched = len(original_cookie_names & current_cookie_names)
                match_rate = (matched/len(original_cookie_names)*100) if original_cookie_names else 0
                print(f"  - Cookie匹配率: {matched}/{len(original_cookie_names)} ({match_rate:.1f}%)")

            print(f"\n[CloneDriver] ✅ Driver克隆完成！")
            print(f"{'='*60}\n")

        except Exception as e:
            print(f"[CloneDriver] ⚠️ 验证警告: {e}")

        # 加入driver池
        self.driver_pool.append(driver)

        return driver

    def _create_chrome_options(self):
        """创建Chrome选项配置"""
        if self.chrome_options:
            # 如果已有配置，克隆一份并添加独立用户目录
            chrome_options = self.chrome_options
        else:
            # 创建默认配置
            chrome_options = webdriver.ChromeOptions()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--disable-web-security")
            chrome_options.add_argument("--allow-running-insecure-content")
            chrome_options.add_argument("--disable-xss-auditor")

        # ✅ 关键：每个driver使用独立的临时目录，避免冲突
        # Chrome不允许多个进程共享同一个profile
        unique_id = f"{os.getpid()}_{id(chrome_options)}_{int(time.time()*1000)}"
        user_data_dir = f"/tmp/chrome_parallel_{unique_id}"
        chrome_options.add_argument(f"--user-data-dir={user_data_dir}")

        return chrome_options

    def cleanup_all(self):
        """清理所有创建的driver"""
        print(f"\n[ParallelDriverManager] 清理 {len(self.driver_pool)} 个driver...")
        for i, driver in enumerate(self.driver_pool, 1):
            try:
                driver.quit()
                print(f"  [{i}/{len(self.driver_pool)}] Driver已关闭")
            except Exception as e:
                print(f"  [{i}/{len(self.driver_pool)}] 关闭失败: {e}")

        self.driver_pool.clear()
        print(f"[ParallelDriverManager] ✅ 清理完成\n")
