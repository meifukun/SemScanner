import json
import time
from typing import List, Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class Account:
    """账户信息（描述化）"""
    account_id: str  # 唯一标识
    login_task_description: str  # 登录任务描述（如"使用用户名admin和密码123456登录"）
    role: str = "user"  # 角色标签
    is_logged_in: bool = False
    credentials: Dict[str, Any] = field(default_factory=dict)  # {cookies, headers, localStorage, sessionStorage}
    login_url: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    has_driver: bool = False  # 是否有关联的 driver（用于标识）


class AccountManager:
    """
    账户管理器 - 描述化版本

    核心改进：
    1. 不再硬编码username/password字段
    2. 使用login_task_description传递登录信息
    3. 让Bridge/LLM自己决定如何填写表单
    4. 支持存储和管理 WebDriver 实例（用于 XSS 等需要 JS 执行的场景）
    """

    def __init__(self, store_path: str = "output/accounts.json", chrome_options=None, default_login_url: str = None):
        self.store_path = Path(store_path)
        self.accounts: List[Account] = []
        self.chrome_options = chrome_options
        self.default_login_url = default_login_url  # ← 保存默认登录 URL

        # ✅ Driver 存储（account_id -> WebDriver 实例）
        # 注意：driver 不会被序列化到 JSON，只在运行时存在
        self._drivers: Dict[str, Any] = {}

        # 加载已存储的账户
        self._load_accounts()
    
    def add_account(self, 
                   login_task_description: str,
                   role: str = "user",
                   account_id: Optional[str] = None) -> Account:
        """
        添加账户（描述化）
        
        Args:
            login_task_description: 登录任务描述，如：
                "Log in with username: admin, password: admin123"
                "使用邮箱test@example.com和密码Pass@123登录"
            role: 角色标签（用于分类）
            account_id: 可选的账户ID（默认自动生成）
        
        Returns:
            创建的Account对象
        """
        if account_id is None:
            account_id = f"account_{int(time.time())}_{len(self.accounts)}"
        
        account = Account(
            account_id=account_id,
            login_task_description=login_task_description,
            role=role
        )
        
        self.accounts.append(account)
        self.save_accounts()
        
        return account
    
    def login_account(self, 
                 account: Account,
                 login_url: str = None,  # ← 改为可选参数
                 bridge = None) -> bool:
        """
        执行账户登录
        
        Args:
            account: 要登录的账户
            login_url: 登录页面URL（可选，默认使用初始化时传入的 URL）
            bridge: Bridge实例
        
        Returns:
            登录是否成功
        """
        from task.tasks import Task
        
        # ✅ 使用传入的 URL 或默认 URL
        if login_url is None:
            login_url = self.default_login_url
        
        if not login_url:
            raise ValueError("No login URL provided and no default login URL set")
        
        print(f"[AccountManager] Logging in account: {account.account_id}")
        print(f"  Task: {account.login_task_description}")
        print(f"  URL: {login_url}")
        
        # 创建登录任务
        login_task = Task(
            task_id=f"login_{account.account_id}",
            description=account.login_task_description,
            initial_url=login_url
        )
        
        # 导航到登录页
        bridge.driver.get(login_url)
        time.sleep(0.6)
        
        # 执行登录
        try:
            bridge.run_task(login_task, 
                        photo_dir=Path("output/account_logins") / account.account_id,
                        logging_in=True)
            
            # 提取凭证
            time.sleep(1)
            credentials = self._extract_credentials(bridge.driver)

            # ✅ 保存 driver 实例
            self._drivers[account.account_id] = bridge.driver

            # 更新账户状态
            account.credentials = credentials
            account.is_logged_in = True
            account.login_url = login_url
            account.has_driver = True  # 标记有 driver

            self.save_accounts()
            
            print(f"[AccountManager] ✅ Login successful")
            return True
        
        except Exception as e:
            print(f"[AccountManager] ⚠️ Login failed: {e}")
            return False
    
    def _extract_credentials(self, driver) -> Dict[str, Any]:
        """
        从driver提取凭证（完整版，不做任何过滤）
        
        Returns:
            {
                "cookies": [...],
                "localStorage": {...},
                "sessionStorage": {...},
                "headers": {}  # 暂时为空，由攻击 Agent 自己决定用什么
            }
        """
        print(f"[DEBUG] 开始提取凭证...")
        print(f"[DEBUG] 当前URL: {driver.current_url}")

        # # 提取cookies（通常不会有问题）
        # try:
        #     cookies = driver.get_cookies()
        #     print(f"[DEBUG] Cookies提取成功: {len(cookies)} 个")
        # except Exception as e:
        #     print(f"[DEBUG] Cookies提取失败: {e}")
        #     cookies = []

        # ==========================================
        # ✅ 修复：使用官方 execute_cdp_cmd 方法
        # ==========================================
        cookies = []
        try:
            # Network.getAllCookies 是 Chrome DevTools 的原生命令
            # 它可以无视 Path 和 Domain 限制，拿到浏览器里的所有 Cookie
            result = driver.execute_cdp_cmd('Network.getAllCookies', {})
            cookies = result.get('cookies', [])
            print(f"[DEBUG] (CDP) Cookies提取成功: {len(cookies)} 个")
            
            # 🔍 Debug: 打印一下看看有没有 JSESSIONID
            for c in cookies:
                if 'SESSION' in c['name'].upper():
                    print(f"  🎯 捕获到关键 Cookie: {c['name']} = {c['value'][:10]}... (Path: {c['path']})")

        except Exception as e:
            print(f"[DEBUG] ⚠️ CDP 提取 Cookie 失败，尝试回退到标准方法: {e}")
            try:
                cookies = driver.get_cookies()
                print(f"[DEBUG] (Standard) Cookies提取成功: {len(cookies)} 个")
            except Exception as e2:
                print(f"[DEBUG] ❌ 所有 Cookie 提取方法均失败: {e2}")
                cookies = []

        # 🔍 localStorage详细诊断
        print(f"[DEBUG] 开始分析localStorage...")

        # 步骤1: 检查localStorage基本信息
        try:
            basic_info = driver.execute_script("""
                return {
                    length: localStorage.length,
                    url: window.location.href,
                    userAgent: navigator.userAgent.substring(0, 50)
                };
            """)
            print(f"[DEBUG] localStorage基本信息: {basic_info}")
        except Exception as e:
            print(f"[DEBUG] 获取localStorage基本信息失败: {e}")

        # 步骤2: 计算localStorage大小
        try:
            size_info = driver.execute_script("""
                let totalSize = 0;
                let keyCount = 0;
                let largestKey = '';
                let largestSize = 0;

                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    const value = localStorage.getItem(key);
                    const size = new Blob([key + value]).size;
                    totalSize += size;
                    keyCount++;

                    if (size > largestSize) {
                        largestSize = size;
                        largestKey = key;
                    }
                }

                return {
                    keyCount: keyCount,
                    totalSizeBytes: totalSize,
                    totalSizeKB: Math.round(totalSize / 1024 * 100) / 100,
                    largestKey: largestKey,
                    largestSizeBytes: largestSize,
                    largestSizeKB: Math.round(largestSize / 1024 * 100) / 100
                };
            """)
            print(f"[DEBUG] localStorage大小分析:")
            print(f"  - 键值对数量: {size_info['keyCount']}")
            print(f"  - 总大小: {size_info['totalSizeKB']} KB ({size_info['totalSizeBytes']} bytes)")
            print(f"  - 最大键: {size_info['largestKey']} ({size_info['largestSizeKB']} KB)")

            # 警告大数据量
            if size_info['totalSizeKB'] > 100:
                print(f"[DEBUG] ⚠️  localStorage数据量较大 (>100KB)，可能导致反序列化失败")

        except Exception as e:
            print(f"[DEBUG] 计算localStorage大小失败: {e}")

        # 步骤3: 尝试获取所有键名（不取值）
        try:
            keys_only = driver.execute_script("""
                const keys = [];
                for (let i = 0; i < localStorage.length; i++) {
                    keys.push(localStorage.key(i));
                }
                return keys;
            """)
            print(f"[DEBUG] localStorage键名列表: {keys_only}")
            print(f"[DEBUG] 键名数量: {len(keys_only)}")
        except Exception as e:
            print(f"[DEBUG] 获取localStorage键名失败: {e}")

        # 步骤4: 尝试完整提取（原逻辑）
        print(f"[DEBUG] 尝试完整提取localStorage...")
        try:
            localStorage = driver.execute_script("""
                console.log('开始提取localStorage，项目数量:', localStorage.length);
                const out = {};
                for (let i = 0; i < localStorage.length; i++) {
                    const k = localStorage.key(i);
                    const v = localStorage.getItem(k);
                    out[k] = v;
                    console.log(`提取键 ${i}: ${k.substring(0, 20)}... (长度: ${v.length})`);
                }
                console.log('localStorage提取完成，返回对象大小:', JSON.stringify(out).length);
                return out;
            """)
            print(f"[DEBUG] localStorage完整提取成功: {len(localStorage)} 个项目")

        except Exception as e:
            print(f"[DEBUG] ❌ localStorage完整提取失败: {e}")
            print(f"[DEBUG] 错误类型: {type(e).__name__}")
            print(f"[DEBUG] 错误消息: {str(e)}")
            localStorage = {}

            # 步骤5: 尝试逐个提取，找出问题键
            print(f"[DEBUG] 尝试逐个提取localStorage项目...")
            try:
                keys = driver.execute_script("return Array.from({length: localStorage.length}, (_, i) => localStorage.key(i));")
                problem_keys = []

                for key in keys[:10]:  # 只检查前10个
                    try:
                        value = driver.execute_script(f"return localStorage.getItem('{key}');")
                        print(f"[DEBUG] 键 '{key[:30]}...' 提取成功 (长度: {len(value) if value else 0})")
                    except Exception as e:
                        print(f"[DEBUG] ❌ 键 '{key[:30]}...' 提取失败: {e}")
                        problem_keys.append(key)

                if problem_keys:
                    print(f"[DEBUG] 发现问题键: {problem_keys}")

            except Exception as e:
                print(f"[DEBUG] 逐个提取也失败: {e}")

        # 🔍 sessionStorage类似诊断
        print(f"[DEBUG] 开始分析sessionStorage...")
        try:
            session_size_info = driver.execute_script("""
                let totalSize = 0;
                for (let i = 0; i < sessionStorage.length; i++) {
                    const key = sessionStorage.key(i);
                    const value = sessionStorage.getItem(key);
                    totalSize += new Blob([key + value]).size;
                }
                return {
                    keyCount: sessionStorage.length,
                    totalSizeKB: Math.round(totalSize / 1024 * 100) / 100
                };
            """)
            print(f"[DEBUG] sessionStorage: {session_size_info['keyCount']} 项, {session_size_info['totalSizeKB']} KB")
        except Exception as e:
            print(f"[DEBUG] sessionStorage大小分析失败: {e}")

        # 提取sessionStorage
        try:
            sessionStorage = driver.execute_script("""
                const out = {};
                for (let i = 0; i < sessionStorage.length; i++) {
                    const k = sessionStorage.key(i);
                    out[k] = sessionStorage.getItem(k);
                }
                return out;
            """)
            print(f"[DEBUG] sessionStorage提取成功: {len(sessionStorage)} 个项目")
        except Exception as e:
            print(f"[DEBUG] ❌ sessionStorage提取失败: {e}")
            sessionStorage = {}

        print(f"[DEBUG] 凭证提取完成")

        credentials = {
            "cookies": cookies,
            "localStorage": localStorage,
            "sessionStorage": sessionStorage,
            "headers": {}  # ← 不再自动提取 Authorization
        }
        
        return credentials
    
    def get_credentials(self, account_identifier: str) -> Optional[Dict[str, Any]]:
        """
        获取账户凭证
        
        Args:
            account_identifier: 账户ID或角色名（如"admin", "user1"）
                              特殊值："unauthenticated" 返回空凭证
        
        Returns:
            凭证字典 或 None
        """
        if account_identifier == "unauthenticated":
            return {"cookies": [], "headers": {}, "localStorage": {}, "sessionStorage": {}}
        
        # 先按ID查找
        for account in self.accounts:
            if account.account_id == account_identifier and account.is_logged_in:
                return account.credentials
        
        # 再按role查找
        for account in self.accounts:
            if account.role == account_identifier and account.is_logged_in:
                return account.credentials

        return None

    def get_driver(self, account_identifier: str) -> Optional[Any]:
        """
        获取账户关联的 WebDriver 实例

        Args:
            account_identifier: 账户ID或角色名

        Returns:
            WebDriver 实例 或 None
        """
        # 先按ID查找
        for account in self.accounts:
            if account.account_id == account_identifier and account.has_driver:
                return self._drivers.get(account.account_id)

        # 再按role查找
        for account in self.accounts:
            if account.role == account_identifier and account.has_driver:
                return self._drivers.get(account.account_id)

        return None

    def set_driver(self, account_identifier: str, driver: Any) -> bool:
        """
        为账户设置 WebDriver 实例

        Args:
            account_identifier: 账户ID
            driver: WebDriver 实例

        Returns:
            是否成功设置
        """
        for account in self.accounts:
            if account.account_id == account_identifier:
                self._drivers[account.account_id] = driver
                account.has_driver = True
                self.save_accounts()
                return True

        return False

    def has_driver(self, account_identifier: str) -> bool:
        """
        检查账户是否有可用的 Driver

        Args:
            account_identifier: 账户ID或角色名

        Returns:
            是否有 driver
        """
        driver = self.get_driver(account_identifier)
        if driver is None:
            return False

        # 检查 driver 是否仍然有效
        try:
            _ = driver.current_url
            return True
        except Exception:
            # Driver 已失效，清理
            for account in self.accounts:
                if account.account_id == account_identifier or account.role == account_identifier:
                    if account.account_id in self._drivers:
                        del self._drivers[account.account_id]
                    account.has_driver = False
                    self.save_accounts()
            return False

    def list_accounts(self) -> List[Account]:
        """返回所有账户"""
        return self.accounts

    def create_account_from_credentials(self,
                                       account_id: str,
                                       credentials: Dict[str, Any],
                                       role: str = "dynamic_user",
                                       login_url: Optional[str] = None) -> Account:
        """
        从凭证直接创建账户（用于动态登录场景）

        Args:
            account_id: 账户ID
            credentials: 凭证字典（包含cookies, headers等）
            role: 角色标签
            login_url: 登录URL（可选）

        Returns:
            创建的Account对象
        """
        # 检查账户是否已存在
        for acc in self.accounts:
            if acc.account_id == account_id:
                # 更新已存在的账户
                acc.credentials = credentials
                acc.is_logged_in = True
                acc.login_url = login_url or acc.login_url
                acc.role = role
                self.save_accounts()
                print(f"[AccountManager] ✅ Updated existing account: {account_id}")
                return acc

        # 创建新账户
        account = Account(
            account_id=account_id,
            login_task_description=f"Dynamically created account {account_id}",
            role=role,
            is_logged_in=True,
            credentials=credentials,
            login_url=login_url
        )

        self.accounts.append(account)
        self.save_accounts()

        print(f"[AccountManager] ✅ Created new account: {account_id}")
        return account

    def format_for_prompt(self) -> str:
        """
        格式化账户信息用于LLM prompt
        
        Returns:
            格式化的字符串，例如：
            Available Accounts:
            1. admin (role: admin, logged_in: True)
               Task: Log in with username: admin, password: admin123
            2. user1 (role: user, logged_in: True)
               Task: Log in with username: testuser, password: test123
            3. unauthenticated (no credentials)
        """
        if not self.accounts:
            return "Available Accounts:\n- unauthenticated (no credentials)"
        
        lines = ["Available Accounts:"]
        for i, account in enumerate(self.accounts, 1):
            status = "logged_in: True" if account.is_logged_in else "logged_in: False"
            lines.append(f"{i}. {account.account_id} (role: {account.role}, {status})")
            lines.append(f"   Task: {account.login_task_description}")
        
        lines.append("- unauthenticated (no credentials)")
        
        return "\n".join(lines)
    
    def save_accounts(self):
        """保存账户信息到JSON"""
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        
        data = []
        for account in self.accounts:
            data.append({
                "account_id": account.account_id,
                "login_task_description": account.login_task_description,
                "role": account.role,
                "is_logged_in": account.is_logged_in,
                "credentials": account.credentials,
                "login_url": account.login_url,
                "created_at": account.created_at,
                "has_driver": account.has_driver  # ✅ 保存 driver 标记
            })

        with open(self.store_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def _load_accounts(self):
        """从JSON加载账户信息"""
        if not self.store_path.exists():
            return
        
        try:
            with open(self.store_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            for item in data:
                account = Account(
                    account_id=item["account_id"],
                    login_task_description=item["login_task_description"],
                    role=item.get("role", "user"),
                    is_logged_in=item.get("is_logged_in", False),
                    credentials=item.get("credentials", {}),
                    login_url=item.get("login_url"),
                    created_at=item.get("created_at", time.time()),
                    has_driver=item.get("has_driver", False)  # ✅ 加载 driver 标记
                )
                self.accounts.append(account)
        
        except Exception as e:
            print(f"[AccountManager] Warning: Failed to load accounts: {e}")










# """
# 账户管理器 - 描述化版本
# 支持任意表单字段，通过任务描述传递登录信息
# """

# import json
# import time
# from typing import List, Dict, Any, Optional
# from pathlib import Path
# from dataclasses import dataclass, field


# @dataclass
# class Account:
#     """账户信息（描述化）"""
#     account_id: str  # 唯一标识
#     login_task_description: str  # 登录任务描述（如"使用用户名admin和密码123456登录"）
#     role: str = "user"  # 角色标签
#     is_logged_in: bool = False
#     credentials: Dict[str, Any] = field(default_factory=dict)  # {cookies, headers, localStorage, sessionStorage}
#     login_url: Optional[str] = None
#     created_at: float = field(default_factory=time.time)
#     has_driver: bool = False  # 是否有关联的 driver（用于标识）


# class AccountManager:
#     """
#     账户管理器 - 描述化版本

#     核心改进：
#     1. 不再硬编码username/password字段
#     2. 使用login_task_description传递登录信息
#     3. 让Bridge/LLM自己决定如何填写表单
#     4. 支持存储和管理 WebDriver 实例（用于 XSS 等需要 JS 执行的场景）
#     """

#     def __init__(self, store_path: str = "output/accounts.json", chrome_options=None, default_login_url: str = None):
#         self.store_path = Path(store_path)
#         self.accounts: List[Account] = []
#         self.chrome_options = chrome_options
#         self.default_login_url = default_login_url  # ← 保存默认登录 URL

#         # ✅ Driver 存储（account_id -> WebDriver 实例）
#         # 注意：driver 不会被序列化到 JSON，只在运行时存在
#         self._drivers: Dict[str, Any] = {}

#         # 加载已存储的账户
#         self._load_accounts()
    
#     def add_account(self, 
#                    login_task_description: str,
#                    role: str = "user",
#                    account_id: Optional[str] = None) -> Account:
#         """
#         添加账户（描述化）
        
#         Args:
#             login_task_description: 登录任务描述，如：
#                 "Log in with username: admin, password: admin123"
#                 "使用邮箱test@example.com和密码Pass@123登录"
#             role: 角色标签（用于分类）
#             account_id: 可选的账户ID（默认自动生成）
        
#         Returns:
#             创建的Account对象
#         """
#         if account_id is None:
#             account_id = f"account_{int(time.time())}_{len(self.accounts)}"
        
#         account = Account(
#             account_id=account_id,
#             login_task_description=login_task_description,
#             role=role
#         )
        
#         self.accounts.append(account)
#         self.save_accounts()
        
#         return account
    
#     def login_account(self, 
#                  account: Account,
#                  login_url: str = None,  # ← 改为可选参数
#                  bridge = None) -> bool:
#         """
#         执行账户登录
        
#         Args:
#             account: 要登录的账户
#             login_url: 登录页面URL（可选，默认使用初始化时传入的 URL）
#             bridge: Bridge实例
        
#         Returns:
#             登录是否成功
#         """
#         from task.tasks import Task
        
#         # ✅ 使用传入的 URL 或默认 URL
#         if login_url is None:
#             login_url = self.default_login_url
        
#         if not login_url:
#             raise ValueError("No login URL provided and no default login URL set")
        
#         print(f"[AccountManager] Logging in account: {account.account_id}")
#         print(f"  Task: {account.login_task_description}")
#         print(f"  URL: {login_url}")
        
#         # 创建登录任务
#         login_task = Task(
#             task_id=f"login_{account.account_id}",
#             description=account.login_task_description,
#             initial_url=login_url
#         )
        
#         # 导航到登录页
#         bridge.driver.get(login_url)
#         time.sleep(0.6)
        
#         # 执行登录
#         try:
#             bridge.run_task(login_task, 
#                         photo_dir=Path("output/account_logins") / account.account_id,
#                         logging_in=True)
            
#             # 提取凭证
#             time.sleep(1)
#             credentials = self._extract_credentials(bridge.driver)

#             # ✅ 保存 driver 实例
#             self._drivers[account.account_id] = bridge.driver

#             # 更新账户状态
#             account.credentials = credentials
#             account.is_logged_in = True
#             account.login_url = login_url
#             account.has_driver = True  # 标记有 driver

#             self.save_accounts()
            
#             print(f"[AccountManager] ✅ Login successful")
#             return True
        
#         except Exception as e:
#             print(f"[AccountManager] ⚠️ Login failed: {e}")
#             return False
    
#     def _extract_credentials(self, driver) -> Dict[str, Any]:
#         """
#         从driver提取凭证（完整版，不做任何过滤）
        
#         Returns:
#             {
#                 "cookies": [...],
#                 "localStorage": {...},
#                 "sessionStorage": {...},
#                 "headers": {}  # 暂时为空，由攻击 Agent 自己决定用什么
#             }
#         """
#         print(f"[DEBUG] 开始提取凭证...")
#         print(f"[DEBUG] 当前URL: {driver.current_url}")

#         # 提取cookies（通常不会有问题）
#         try:
#             cookies = driver.get_cookies()
#             print(f"[DEBUG] Cookies提取成功: {len(cookies)} 个")
#         except Exception as e:
#             print(f"[DEBUG] Cookies提取失败: {e}")
#             cookies = []

#         # 🔍 localStorage详细诊断
#         print(f"[DEBUG] 开始分析localStorage...")

#         # 步骤1: 检查localStorage基本信息
#         try:
#             basic_info = driver.execute_script("""
#                 return {
#                     length: localStorage.length,
#                     url: window.location.href,
#                     userAgent: navigator.userAgent.substring(0, 50)
#                 };
#             """)
#             print(f"[DEBUG] localStorage基本信息: {basic_info}")
#         except Exception as e:
#             print(f"[DEBUG] 获取localStorage基本信息失败: {e}")

#         # 步骤2: 计算localStorage大小
#         try:
#             size_info = driver.execute_script("""
#                 let totalSize = 0;
#                 let keyCount = 0;
#                 let largestKey = '';
#                 let largestSize = 0;

#                 for (let i = 0; i < localStorage.length; i++) {
#                     const key = localStorage.key(i);
#                     const value = localStorage.getItem(key);
#                     const size = new Blob([key + value]).size;
#                     totalSize += size;
#                     keyCount++;

#                     if (size > largestSize) {
#                         largestSize = size;
#                         largestKey = key;
#                     }
#                 }

#                 return {
#                     keyCount: keyCount,
#                     totalSizeBytes: totalSize,
#                     totalSizeKB: Math.round(totalSize / 1024 * 100) / 100,
#                     largestKey: largestKey,
#                     largestSizeBytes: largestSize,
#                     largestSizeKB: Math.round(largestSize / 1024 * 100) / 100
#                 };
#             """)
#             print(f"[DEBUG] localStorage大小分析:")
#             print(f"  - 键值对数量: {size_info['keyCount']}")
#             print(f"  - 总大小: {size_info['totalSizeKB']} KB ({size_info['totalSizeBytes']} bytes)")
#             print(f"  - 最大键: {size_info['largestKey']} ({size_info['largestSizeKB']} KB)")

#             # 警告大数据量
#             if size_info['totalSizeKB'] > 100:
#                 print(f"[DEBUG] ⚠️  localStorage数据量较大 (>100KB)，可能导致反序列化失败")

#         except Exception as e:
#             print(f"[DEBUG] 计算localStorage大小失败: {e}")

#         # 步骤3: 尝试获取所有键名（不取值）
#         try:
#             keys_only = driver.execute_script("""
#                 const keys = [];
#                 for (let i = 0; i < localStorage.length; i++) {
#                     keys.push(localStorage.key(i));
#                 }
#                 return keys;
#             """)
#             print(f"[DEBUG] localStorage键名列表: {keys}")
#             print(f"[DEBUG] 键名数量: {len(keys)}")
#         except Exception as e:
#             print(f"[DEBUG] 获取localStorage键名失败: {e}")

#         # 步骤4: 尝试完整提取（原逻辑）
#         print(f"[DEBUG] 尝试完整提取localStorage...")
#         try:
#             localStorage = driver.execute_script("""
#                 console.log('开始提取localStorage，项目数量:', localStorage.length);
#                 const out = {};
#                 for (let i = 0; i < localStorage.length; i++) {
#                     const k = localStorage.key(i);
#                     const v = localStorage.getItem(k);
#                     out[k] = v;
#                     console.log(`提取键 ${i}: ${k.substring(0, 20)}... (长度: ${v.length})`);
#                 }
#                 console.log('localStorage提取完成，返回对象大小:', JSON.stringify(out).length);
#                 return out;
#             """)
#             print(f"[DEBUG] localStorage完整提取成功: {len(localStorage)} 个项目")

#         except Exception as e:
#             print(f"[DEBUG] ❌ localStorage完整提取失败: {e}")
#             print(f"[DEBUG] 错误类型: {type(e).__name__}")
#             print(f"[DEBUG] 错误消息: {str(e)}")
#             localStorage = {}

#             # 步骤5: 尝试逐个提取，找出问题键
#             print(f"[DEBUG] 尝试逐个提取localStorage项目...")
#             try:
#                 keys = driver.execute_script("return Array.from({length: localStorage.length}, (_, i) => localStorage.key(i));")
#                 problem_keys = []

#                 for key in keys[:10]:  # 只检查前10个
#                     try:
#                         value = driver.execute_script(f"return localStorage.getItem('{key}');")
#                         print(f"[DEBUG] 键 '{key[:30]}...' 提取成功 (长度: {len(value) if value else 0})")
#                     except Exception as e:
#                         print(f"[DEBUG] ❌ 键 '{key[:30]}...' 提取失败: {e}")
#                         problem_keys.append(key)

#                 if problem_keys:
#                     print(f"[DEBUG] 发现问题键: {problem_keys}")

#             except Exception as e:
#                 print(f"[DEBUG] 逐个提取也失败: {e}")

#         # 🔍 sessionStorage类似诊断
#         print(f"[DEBUG] 开始分析sessionStorage...")
#         try:
#             session_size_info = driver.execute_script("""
#                 let totalSize = 0;
#                 for (let i = 0; i < sessionStorage.length; i++) {
#                     const key = sessionStorage.key(i);
#                     const value = sessionStorage.getItem(key);
#                     totalSize += new Blob([key + value]).size;
#                 }
#                 return {
#                     keyCount: sessionStorage.length,
#                     totalSizeKB: Math.round(totalSize / 1024 * 100) / 100
#                 };
#             """)
#             print(f"[DEBUG] sessionStorage: {session_size_info['keyCount']} 项, {session_size_info['totalSizeKB']} KB")
#         except Exception as e:
#             print(f"[DEBUG] sessionStorage大小分析失败: {e}")

#         # 提取sessionStorage
#         try:
#             sessionStorage = driver.execute_script("""
#                 const out = {};
#                 for (let i = 0; i < sessionStorage.length; i++) {
#                     const k = sessionStorage.key(i);
#                     out[k] = sessionStorage.getItem(k);
#                 }
#                 return out;
#             """)
#             print(f"[DEBUG] sessionStorage提取成功: {len(sessionStorage)} 个项目")
#         except Exception as e:
#             print(f"[DEBUG] ❌ sessionStorage提取失败: {e}")
#             sessionStorage = {}

#         print(f"[DEBUG] 凭证提取完成")

#         credentials = {
#             "cookies": cookies,
#             "localStorage": localStorage,
#             "sessionStorage": sessionStorage,
#             "headers": {}  # ← 不再自动提取 Authorization
#         }
        
#         return credentials
    
#     def get_credentials(self, account_identifier: str) -> Optional[Dict[str, Any]]:
#         """
#         获取账户凭证
        
#         Args:
#             account_identifier: 账户ID或角色名（如"admin", "user1"）
#                               特殊值："unauthenticated" 返回空凭证
        
#         Returns:
#             凭证字典 或 None
#         """
#         if account_identifier == "unauthenticated":
#             return {"cookies": [], "headers": {}, "localStorage": {}, "sessionStorage": {}}
        
#         # 先按ID查找
#         for account in self.accounts:
#             if account.account_id == account_identifier and account.is_logged_in:
#                 return account.credentials
        
#         # 再按role查找
#         for account in self.accounts:
#             if account.role == account_identifier and account.is_logged_in:
#                 return account.credentials

#         return None

#     def get_driver(self, account_identifier: str) -> Optional[Any]:
#         """
#         获取账户关联的 WebDriver 实例

#         Args:
#             account_identifier: 账户ID或角色名

#         Returns:
#             WebDriver 实例 或 None
#         """
#         # 先按ID查找
#         for account in self.accounts:
#             if account.account_id == account_identifier and account.has_driver:
#                 return self._drivers.get(account.account_id)

#         # 再按role查找
#         for account in self.accounts:
#             if account.role == account_identifier and account.has_driver:
#                 return self._drivers.get(account.account_id)

#         return None

#     def set_driver(self, account_identifier: str, driver: Any) -> bool:
#         """
#         为账户设置 WebDriver 实例

#         Args:
#             account_identifier: 账户ID
#             driver: WebDriver 实例

#         Returns:
#             是否成功设置
#         """
#         for account in self.accounts:
#             if account.account_id == account_identifier:
#                 self._drivers[account.account_id] = driver
#                 account.has_driver = True
#                 self.save_accounts()
#                 return True

#         return False

#     def has_driver(self, account_identifier: str) -> bool:
#         """
#         检查账户是否有可用的 Driver

#         Args:
#             account_identifier: 账户ID或角色名

#         Returns:
#             是否有 driver
#         """
#         driver = self.get_driver(account_identifier)
#         if driver is None:
#             return False

#         # 检查 driver 是否仍然有效
#         try:
#             _ = driver.current_url
#             return True
#         except Exception:
#             # Driver 已失效，清理
#             for account in self.accounts:
#                 if account.account_id == account_identifier or account.role == account_identifier:
#                     if account.account_id in self._drivers:
#                         del self._drivers[account.account_id]
#                     account.has_driver = False
#                     self.save_accounts()
#             return False

#     def list_accounts(self) -> List[Account]:
#         """返回所有账户"""
#         return self.accounts

#     def create_account_from_credentials(self,
#                                        account_id: str,
#                                        credentials: Dict[str, Any],
#                                        role: str = "dynamic_user",
#                                        login_url: Optional[str] = None) -> Account:
#         """
#         从凭证直接创建账户（用于动态登录场景）

#         Args:
#             account_id: 账户ID
#             credentials: 凭证字典（包含cookies, headers等）
#             role: 角色标签
#             login_url: 登录URL（可选）

#         Returns:
#             创建的Account对象
#         """
#         # 检查账户是否已存在
#         for acc in self.accounts:
#             if acc.account_id == account_id:
#                 # 更新已存在的账户
#                 acc.credentials = credentials
#                 acc.is_logged_in = True
#                 acc.login_url = login_url or acc.login_url
#                 acc.role = role
#                 self.save_accounts()
#                 print(f"[AccountManager] ✅ Updated existing account: {account_id}")
#                 return acc

#         # 创建新账户
#         account = Account(
#             account_id=account_id,
#             login_task_description=f"Dynamically created account {account_id}",
#             role=role,
#             is_logged_in=True,
#             credentials=credentials,
#             login_url=login_url
#         )

#         self.accounts.append(account)
#         self.save_accounts()

#         print(f"[AccountManager] ✅ Created new account: {account_id}")
#         return account

#     def format_for_prompt(self) -> str:
#         """
#         格式化账户信息用于LLM prompt
        
#         Returns:
#             格式化的字符串，例如：
#             Available Accounts:
#             1. admin (role: admin, logged_in: True)
#                Task: Log in with username: admin, password: admin123
#             2. user1 (role: user, logged_in: True)
#                Task: Log in with username: testuser, password: test123
#             3. unauthenticated (no credentials)
#         """
#         if not self.accounts:
#             return "Available Accounts:\n- unauthenticated (no credentials)"
        
#         lines = ["Available Accounts:"]
#         for i, account in enumerate(self.accounts, 1):
#             status = "logged_in: True" if account.is_logged_in else "logged_in: False"
#             lines.append(f"{i}. {account.account_id} (role: {account.role}, {status})")
#             lines.append(f"   Task: {account.login_task_description}")
        
#         lines.append("- unauthenticated (no credentials)")
        
#         return "\n".join(lines)
    
#     def save_accounts(self):
#         """保存账户信息到JSON"""
#         self.store_path.parent.mkdir(parents=True, exist_ok=True)
        
#         data = []
#         for account in self.accounts:
#             data.append({
#                 "account_id": account.account_id,
#                 "login_task_description": account.login_task_description,
#                 "role": account.role,
#                 "is_logged_in": account.is_logged_in,
#                 "credentials": account.credentials,
#                 "login_url": account.login_url,
#                 "created_at": account.created_at,
#                 "has_driver": account.has_driver  # ✅ 保存 driver 标记
#             })

#         with open(self.store_path, 'w', encoding='utf-8') as f:
#             json.dump(data, f, indent=2, ensure_ascii=False)
    
#     def _load_accounts(self):
#         """从JSON加载账户信息"""
#         if not self.store_path.exists():
#             return
        
#         try:
#             with open(self.store_path, 'r', encoding='utf-8') as f:
#                 data = json.load(f)
            
#             for item in data:
#                 account = Account(
#                     account_id=item["account_id"],
#                     login_task_description=item["login_task_description"],
#                     role=item.get("role", "user"),
#                     is_logged_in=item.get("is_logged_in", False),
#                     credentials=item.get("credentials", {}),
#                     login_url=item.get("login_url"),
#                     created_at=item.get("created_at", time.time()),
#                     has_driver=item.get("has_driver", False)  # ✅ 加载 driver 标记
#                 )
#                 self.accounts.append(account)
        
#         except Exception as e:
#             print(f"[AccountManager] Warning: Failed to load accounts: {e}")