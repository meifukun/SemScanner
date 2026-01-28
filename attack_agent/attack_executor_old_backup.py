"""
AttackExecutor - 修复版（支持统一的存储型漏洞检测 + 并行执行）
"""

from typing import List, Dict, Any, Set
from pathlib import Path
import json
import time
import threading
import hashlib
import re
import subprocess  # ✅ 修复：添加 subprocess 导入（用于执行 curl 命令）
from concurrent.futures import ThreadPoolExecutor, as_completed
# 🆕 导入WorkerCredentialStore
from attack_agent.worker_credential_store import WorkerCredentialStore

class AttackExecutor:
    """
    攻击执行器 - 修复版
    
    改进：
    1. 凭证获取逻辑优化（单账户/多账户分开处理）
    2. 统一的错误处理
    """
    
    def __init__(self, account_manager, crawler, client,
            log_dir: str = "output/attack_executor",
            edges_file: str = None,
            driver = None,
            beacon_base: str = "http://172.17.0.1:9091/",
            worker_drivers: List = None,           # 🆕 worker drivers列表
            chrome_options = None,                 # 🆕 chrome选项（用于创建driver）
            initial_url: str = None,               # 🆕 初始URL（用于登录检查）
            login_task = None):                    # 🆕 登录任务（用于重新登录）
        """
        初始化 AttackExecutor

        Args:
            account_manager: 账户管理器
            crawler: 爬虫实例
            client: OpenAI client（用于创建各类 agent）
            log_dir: 日志目录
            edges_file: 边文件路径（保留兼容性，现在不使用）
            driver: Selenium driver（用于访问页面和截图）
            beacon_base: Beacon URL 前缀（用于 OOB 检测）
        """
        self.account_manager = account_manager
        self.crawler = crawler
        self.client = client
        self.driver = driver  # ✅ 需要driver来访问页面和截图
        self.beacon_base = beacon_base  # 🆕 Beacon URL配置
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # 🆕 保存新参数
        self.worker_drivers = worker_drivers or []  # worker drivers列表
        self.chrome_options = chrome_options        # chrome选项
        self.initial_url = initial_url              # 初始URL
        self.login_task = login_task                # 登录任务

        # 🆕 为每个worker driver创建credential store
        self.worker_stores: Dict[int, WorkerCredentialStore] = {}
        if self.worker_drivers:
            for idx, worker_driver in enumerate(self.worker_drivers):
                self.worker_stores[idx] = WorkerCredentialStore(worker_id=idx)
            self._log(f"[Init] Created {len(self.worker_stores)} worker credential stores")

        # 🆕 不再预创建 agent 实例（改为在 _execute_task 中临时创建）
        self.edges_file = edges_file  # 保留兼容性（现在不使用）

        self.results = []
        self._log_path = self.log_dir / "executor.log"

        # 🆕 截图保存目录
        self.screenshot_dir = self.log_dir / "stored_vuln_screenshots"
        self.screenshot_dir.mkdir(parents=True, exist_ok=True)

        # 🆕 Session 保活截图目录
        self.keepalive_screenshot_dir = self.log_dir / "session_keepalive"
        self.keepalive_screenshot_dir.mkdir(parents=True, exist_ok=True)

        # 🆕 任务计数器（确保唯一编号）
        self.task_counter = 0
        self.task_counter_lock = threading.Lock()

        # 🆕 线程安全：保护共享资源
        self._lock = threading.Lock()
        self._log_lock = threading.Lock()
    
    def _log(self, *args):
        msg = " ".join(str(a) for a in args)
        try:
            with self._log_lock:  # 🆕 线程安全
                with open(self._log_path, "a", encoding="utf-8") as f:
                    f.write(msg + "\n")
        except Exception:
            pass

    def _url_to_filename(self, url: str) -> str:
        """
        将 URL 转换为合法的文件名

        策略：
        1. 移除协议前缀（http://、https://）
        2. 替换特殊字符为下划线
        3. 如果文件名太长（>200字符），使用 MD5 哈希 + 前缀

        Args:
            url: 原始 URL

        Returns:
            合法的文件名（不含扩展名）
        """
        # 移除协议
        filename = re.sub(r'^https?://', '', url)

        # 替换特殊字符为下划线
        filename = re.sub(r'[^\w\-.]', '_', filename)

        # 去除连续的下划线
        filename = re.sub(r'_+', '_', filename)

        # 去除首尾下划线
        filename = filename.strip('_')

        # 如果文件名太长，使用哈希
        if len(filename) > 200:
            # 使用 MD5 哈希 + 前50字符作为前缀
            url_hash = hashlib.md5(url.encode('utf-8')).hexdigest()[:8]
            filename = f"{filename[:50]}_{url_hash}"

        return filename

    def _create_agent_for_task(self, vuln_type: str, task_log_dir: Path):
        """
        🆕 根据漏洞类型创建对应的 agent 实例（任务专属）

        Args:
            vuln_type: 漏洞类型
            task_log_dir: 任务日志目录

        Returns:
            对应的 agent 实例

        每个任务创建独立的 agent，避免并发日志冲突
        """
        task_log_dir_str = str(task_log_dir)

        if vuln_type == "SQL_INJECTION":
            from attack_agent.sql_injection_agent import SQLInjectionAgent
            return SQLInjectionAgent(
                client=self.client,
                log_dir=task_log_dir_str
            )

        elif vuln_type == "XSS":
            from attack_agent.xss_agent import XSSAgent
            return XSSAgent(
                client=self.client,
                driver=self.driver,
                log_dir=task_log_dir_str
            )

        elif vuln_type == "SSTI":
            from attack_agent.ssti_agent import SSTIAgent
            return SSTIAgent(
                client=self.client,
                beacon_base=self.beacon_base,
                log_dir=task_log_dir_str
            )

        elif vuln_type == "SSRF":
            from attack_agent.ssrf_agent import SSRFAgent
            return SSRFAgent(
                client=self.client,
                beacon_base=self.beacon_base,
                log_dir=task_log_dir_str
            )

        elif vuln_type in ["CMDI", "COMMAND_INJECTION"]:
            from attack_agent.command_injection_agent import CommandInjectionAgent
            return CommandInjectionAgent(
                client=self.client,
                beacon_base=self.beacon_base,
                log_dir=task_log_dir_str
            )

        elif vuln_type in ["PT", "PATH_TRAVERSAL"]:
            from attack_agent.path_traversal_agent import PathTraversalAgent
            return PathTraversalAgent(
                client=self.client,
                log_dir=task_log_dir_str
            )

        elif vuln_type == "XXE":
            from attack_agent.xxe_agent import XXEAgent
            return XXEAgent(
                client=self.client,
                beacon_base=self.beacon_base,
                log_dir=task_log_dir_str
            )

        elif vuln_type in ["IDOR", "AUTH_BYPASS", "PRIVILEGE_ESCALATION", "BUSINESS_LOGIC"]:
            from attack_agent.business_logic_agent import BusinessLogicAgent
            return BusinessLogicAgent(
                client=self.client,
                log_dir=task_log_dir_str
            )

        else:
            raise ValueError(f"Unsupported vulnerability type: {vuln_type}")

    def _generate_replay_curl(self, request: Dict, account_identifier: str) -> str:
        """
        生成curl重放命令（完整版：包含method、url、headers、body、credentials）

        Args:
            request: 目标请求对象
            account_identifier: 账户标识

        Returns:
            完整的curl命令字符串
        """
        method = request.get("method", "GET")
        url = request.get("url", "")
        headers = request.get("headers", {})
        body = request.get("body")

        # 构造基础curl命令
        # ✅ 添加 --compressed 参数，让 curl 自动解压缩 gzip/deflate/br/zstd 响应
        parts = [f"curl --compressed -X {method}"]

        # 添加URL
        parts.append(f'"{url}"')

        # 添加headers（排除Cookie和Authorization，稍后从credentials添加）
        for key, value in headers.items():
            if key.lower() not in ["cookie", "authorization"]:
                # ✅ 转义 header 值中的双引号和反斜杠，避免 shell 语法错误
                value_escaped = str(value).replace('\\', '\\\\').replace('"', '\\"')
                parts.append(f'-H "{key}: {value_escaped}"')

        # 添加body
        if body and method in ["POST", "PUT", "PATCH"]:
            # 转义body中的引号
            body_str = str(body).replace('"', '\\"')
            parts.append(f'-d "{body_str}"')

        # 获取并追加credentials
        credentials = self.account_manager.get_credentials(account_identifier)
        if credentials:
            # 添加Cookie
            cookies = credentials.get("cookies", [])
            if cookies:
                cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
                # ✅ 转义 Cookie 值中的双引号和反斜杠
                cookie_str_escaped = cookie_str.replace('\\', '\\\\').replace('"', '\\"')
                parts.append(f'-H "Cookie: {cookie_str_escaped}"')

            # 添加Authorization（优先使用headers中的）
            cred_headers = credentials.get("headers", {})
            if "Authorization" in cred_headers:
                # ✅ 转义 Authorization 值中的双引号和反斜杠
                auth_value_escaped = str(cred_headers["Authorization"]).replace('\\', '\\\\').replace('"', '\\"')
                parts.append(f'-H "Authorization: {auth_value_escaped}"')
            else:
                # 从localStorage/sessionStorage提取token
                from attack_agent.request_utils import extract_auth_token
                token = extract_auth_token(credentials)
                if token:
                    # ✅ 转义 token 值中的双引号和反斜杠
                    token_escaped = str(token).replace('\\', '\\\\').replace('"', '\\"')
                    parts.append(f'-H "Authorization: Bearer {token_escaped}"')

        return " \\\n  ".join(parts)

    def _log_driver_credentials(self, log_func):
        """
        输出driver中实际存储的凭证信息（cookies、localStorage、sessionStorage）

        ✅ 完整打印，不截断

        Args:
            log_func: 日志输出函数
        """
        if not self.driver:
            log_func("No driver available")
            return

        try:
            # 1. 输出当前URL
            try:
                current_url = self.driver.current_url
                log_func(f"Current URL: {current_url}")
            except Exception as e:
                log_func(f"Current URL: Error - {e}")

            # 2. 输出cookies
            try:
                cookies = self.driver.get_cookies()
                log_func(f"")
                log_func(f"Cookies ({len(cookies)} total):")
                if cookies:
                    for cookie in cookies:
                        name = cookie.get("name", "")
                        value = cookie.get("value", "")  # ✅ 不截断
                        domain = cookie.get("domain", "")
                        path = cookie.get("path", "")
                        # 标记session相关的cookie
                        marker = "[SESSION]" if any(k in name.lower() for k in ['session', 'token', 'auth', 'jwt']) else ""
                        log_func(f"  {marker} {name}={value}")  # ✅ 完整打印
                        log_func(f"    domain={domain}, path={path}")
                else:
                    log_func("  (No cookies)")
            except Exception as e:
                log_func(f"Cookies: Error - {e}")

            # 3. 输出localStorage
            try:
                local_storage = self.driver.execute_script("return JSON.stringify(localStorage);")
                log_func(f"")
                log_func(f"LocalStorage:")
                if local_storage and local_storage != "{}":
                    import json
                    ls_data = json.loads(local_storage)
                    for key, value in ls_data.items():
                        marker = "[AUTH]" if any(k in key.lower() for k in ['session', 'token', 'auth', 'jwt', 'credentials']) else ""
                        log_func(f"  {marker} {key}={value}")  # ✅ 完整打印
                else:
                    log_func("  (Empty)")
            except Exception as e:
                log_func(f"LocalStorage: Error - {e}")

            # 4. 输出sessionStorage
            try:
                session_storage = self.driver.execute_script("return JSON.stringify(sessionStorage);")
                log_func(f"")
                log_func(f"SessionStorage:")
                if session_storage and session_storage != "{}":
                    import json
                    ss_data = json.loads(session_storage)
                    for key, value in ss_data.items():
                        marker = "[AUTH]" if any(k in key.lower() for k in ['session', 'token', 'auth', 'jwt']) else ""
                        log_func(f"  {marker} {key}={value}")  # ✅ 完整打印
                else:
                    log_func("  (Empty)")
            except Exception as e:
                log_func(f"SessionStorage: Error - {e}")

        except Exception as e:
            log_func(f"Error reading driver credentials: {e}")

    def _log_account_manager_credentials(self, account_identifier: str, log_func):
        """
        🆕 输出 account_manager 中存储的凭证信息（用于对比）

        ✅ 完整打印，不截断

        Args:
            account_identifier: 账户标识
            log_func: 日志输出函数
        """
        try:
            credentials = self.account_manager.get_credentials(account_identifier)
            if not credentials:
                log_func(f"Account: {account_identifier}")
                log_func("No credentials found in account_manager")
                return

            log_func(f"Account: {account_identifier}")
            log_func(f"")

            # 1. Cookies
            cookies = credentials.get("cookies", [])
            log_func(f"Cookies ({len(cookies)} total):")
            if cookies:
                for cookie in cookies:
                    name = cookie.get("name", "")
                    value = cookie.get("value", "")  # ✅ 完整打印
                    domain = cookie.get("domain", "")
                    path = cookie.get("path", "")
                    marker = "[SESSION]" if any(k in name.lower() for k in ['session', 'token', 'auth', 'jwt']) else ""
                    log_func(f"  {marker} {name}={value}")
                    log_func(f"    domain={domain}, path={path}")
            else:
                log_func("  (No cookies)")

            # 2. Headers
            headers = credentials.get("headers", {})
            log_func(f"")
            log_func(f"Headers ({len(headers)} total):")
            if headers:
                for key, value in headers.items():
                    marker = "[AUTH]" if any(k in key.lower() for k in ['authorization', 'token', 'auth']) else ""
                    log_func(f"  {marker} {key}: {value}")  # ✅ 完整打印
            else:
                log_func("  (No headers)")

            # 3. LocalStorage
            local_storage = credentials.get("localStorage", {})
            log_func(f"")
            log_func(f"LocalStorage ({len(local_storage)} items):")
            if local_storage:
                for key, value in local_storage.items():
                    marker = "[AUTH]" if any(k in key.lower() for k in ['session', 'token', 'auth', 'jwt', 'credentials']) else ""
                    log_func(f"  {marker} {key}={value}")  # ✅ 完整打印
            else:
                log_func("  (Empty)")

            # 4. SessionStorage
            session_storage = credentials.get("sessionStorage", {})
            log_func(f"")
            log_func(f"SessionStorage ({len(session_storage)} items):")
            if session_storage:
                for key, value in session_storage.items():
                    marker = "[AUTH]" if any(k in key.lower() for k in ['session', 'token', 'auth', 'jwt']) else ""
                    log_func(f"  {marker} {key}={value}")  # ✅ 完整打印
            else:
                log_func("  (Empty)")

        except Exception as e:
            log_func(f"Error reading account_manager credentials: {e}")

    def _execute_replay_curl(self, request: Dict, account_identifier: str, log_func) -> Dict[str, Any]:
        """
        🆕 生成并执行 curl 重放命令，返回完整结果

        Args:
            request: 目标请求对象
            account_identifier: 账户标识
            log_func: 日志输出函数

        Returns:
            {
                "command": str,        # curl 命令
                "success": bool,       # 是否执行成功
                "stdout": str,         # 响应内容（已移除HTTP_STATUS标记）
                "stderr": str,         # 错误输出
                "returncode": int,     # curl退出码
                "http_status": int     # HTTP状态码
            }
        """
        # 生成 curl 命令
        command = self._generate_replay_curl(request, account_identifier)

        # 执行命令
        try:
            result = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30
            )

            # ✅ 使用统一的HTTP状态码解析函数
            from attack_agent.request_utils import parse_http_status_from_response
            http_status, response_body = parse_http_status_from_response(result.stdout)

            return {
                "command": command,
                "success": result.returncode == 0,
                "stdout": response_body,
                "fullout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "http_status": http_status  # ✅ 新增HTTP状态码
            }
        except subprocess.TimeoutExpired:
            log_func("[Warning] Curl execution timeout after 30 seconds")
            return {
                "command": command,
                "success": False,
                "stdout": "",
                "stderr": "Timeout after 30 seconds",
                "returncode": -1,
                "http_status": None
            }
        except Exception as e:
            log_func(f"[Warning] Curl execution failed: {e}")
            return {
                "command": command,
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "returncode": -1,
                "http_status": None
            }

    def _save_screenshot(self, url: str, parent_counter: int = None, child_counter: int = None) -> bool:
        """
        保存当前页面的截图（支持层次化文件名）

        Args:
            url: 当前访问的 URL
            parent_counter: 父页面计数器（主页面编号）
            child_counter: 子页面计数器（从父页面提取的链接编号，None表示是主页面）

        Returns:
            True if screenshot saved successfully, False otherwise

        文件名格式：
            - 主页面：001_url.png
            - 子链接：001_1_url.png, 001_2_url.png, 001_3_url.png
        """
        if not self.driver:
            return False

        try:
            # 生成文件名
            base_filename = self._url_to_filename(url)

            # 根据是否有子计数器，生成不同格式的文件名
            if parent_counter is not None:
                if child_counter is not None:
                    # 子链接：001_1_url.png
                    filename = f"{parent_counter:03d}_{child_counter}_{base_filename}.png"
                else:
                    # 主页面：001_url.png
                    filename = f"{parent_counter:03d}_{base_filename}.png"
            else:
                # 没有计数器，直接使用URL
                filename = f"{base_filename}.png"

            screenshot_path = self.screenshot_dir / filename

            # 保存截图
            success = self.driver.save_screenshot(str(screenshot_path))

            if success:
                self._log(f"  📸 Screenshot saved: {filename}")
                return True
            else:
                self._log(f"  ⚠️  Screenshot failed: {filename}")
                return False

        except Exception as e:
            self._log(f"  ⚠️  Screenshot error: {e}")
            return False
    
    def execute_tasks(self, tasks: List) -> List[Dict]:
        """
        执行AttackTask列表（改进版 - 支持统一的存储型漏洞检测）

        Args:
            tasks: List[AttackTask]（来自AttackPlanningAgent）

        Returns:
            执行结果列表
        """
        self._log(f"\n{'='*70}")
        self._log(f"[AttackExecutor] Starting Execution")
        self._log(f"{'='*70}")
        self._log(f"[AttackExecutor] Total Tasks: {len(tasks)}")
        self._log(f"")

        # 打印任务摘要
        self._log(f"[Task Summary]:")
        vuln_type_counts = {}
        for task in tasks:
            vuln_type_counts[task.vuln_type] = vuln_type_counts.get(task.vuln_type, 0) + 1

        for vuln_type, count in sorted(vuln_type_counts.items()):
            self._log(f"  {vuln_type}: {count} task(s)")
        self._log(f"")

        self.results.clear()

        # ========== Phase 1: 注入阶段 ==========
        for i, task in enumerate(tasks, 1):
            try:
                self._log(f"\n{'~'*70}")
                self._log(f"[Task {i}/{len(tasks)}] {task.task_id}")
                self._log(f"{'~'*70}")
                self._log(f"[Task Info]:")
                self._log(f"  ID: {task.task_id}")
                self._log(f"  Type: {task.vuln_type}")
                self._log(f"  Account: {task.account_identifier}")
                self._log(f"  Description: {task.task_description}")
                self._log(f"  Target: {task.target_request.get('method')} {task.target_request.get('url')}")
                self._log(f"")

                result = self._execute_task(task)

                # 记录执行结果摘要
                self._log(f"\n[Task {task.task_id} Result]:")
                if "error" in result:
                    self._log(f"  ✗ ERROR: {result['error']}")
                elif "vulnerable" in result:
                    vuln_status = result['vulnerable']
                    if vuln_status is True:
                        self._log(f"  ✓ VULNERABLE")
                    elif vuln_status is False:
                        self._log(f"  ✓ SAFE (tested, not vulnerable)")
                    else:
                        self._log(f"  ? PENDING (waiting for finalize)")
                else:
                    self._log(f"  ✓ COMPLETED")
                self._log(f"")

                self.results.append({
                    "task_id": task.task_id,
                    "vuln_type": task.vuln_type,
                    "account": task.account_identifier,
                    "result": result
                })

                # ✅ 每完成一个任务就保存结果
                self._save_results()

            except Exception as e:
                self._log(f"\n[Task {task.task_id} Error]:")
                self._log(f"  ✗ Exception: {e}")
                import traceback
                self._log(f"  Traceback:")
                for line in traceback.format_exc().split('\n'):
                    self._log(f"    {line}")
                self._log(f"")

                self.results.append({
                    "task_id": task.task_id,
                    "error": str(e),
                    "traceback": traceback.format_exc()
                })

                # ✅ 每完成一个任务就保存结果（即使出错也保存）
                self._save_results()

        # ========== Phase 2: 统一的存储型漏洞检测阶段 ==========
        self._log(f"\n{'='*70}")
        self._log(f"[AttackExecutor] Stored Vulnerability Detection Phase")
        self._log(f"{'='*70}\n")

        # 检查是否有pending的任务
        pending_tasks = self._get_pending_tasks()

        if pending_tasks and self.driver:
            self._log(f"[Stored Vuln Detection] Found {len(pending_tasks)} pending task(s)")
            for vuln_type, count in pending_tasks.items():
                self._log(f"  {vuln_type}: {count}")
            self._log(f"")

            # ✅ 统一访问所有页面（触发存储型漏洞）
            self._finalize_stored_vulnerabilities()

            # ✅ 让各Agent检查最终结果
            self._check_all_stored_results()

        else:
            if not self.driver:
                self._log(f"[Stored Vuln Detection] Skipped - No driver available")
            elif not pending_tasks:
                self._log(f"[Stored Vuln Detection] Skipped - No pending tasks")

        # ========== Phase 3: 最终统计 ==========
        self._log(f"\n{'='*70}")
        self._log(f"[AttackExecutor] Execution Complete")
        self._log(f"{'='*70}")
        self._log(f"[Final Statistics]:")
        self._log(f"  Total Tasks: {len(tasks)}")
        self._log(f"  Completed: {len(self.results)}")

        # 统计漏洞结果
        vulnerable_count = sum(1 for r in self.results if r.get("result", {}).get("vulnerable") is True)
        safe_count = sum(1 for r in self.results if r.get("result", {}).get("vulnerable") is False)
        uncertain_count = sum(1 for r in self.results if r.get("result", {}).get("vulnerable") is None)
        error_count = sum(1 for r in self.results if "error" in r)

        self._log(f"  Vulnerable: {vulnerable_count}")
        self._log(f"  Safe: {safe_count}")
        self._log(f"  Uncertain: {uncertain_count}")
        self._log(f"  Errors: {error_count}")
        self._log(f"{'='*70}\n")

        self._save_results()

        return self.results

    def execute_tasks_parallel(self, tasks: List, max_workers: int = 10) -> List[Dict]:
        """
        🆕 并行执行AttackTask列表（优化版 - 大幅提升执行速度）

        改进：
        1. 使用线程池并行执行攻击任务（最多10个并发）
        2. 攻击任务完全独立，无需共享driver
        3. 保留原有的存储型漏洞检测机制

        Args:
            tasks: List[AttackTask]（来自AttackPlanningAgent）
            max_workers: 最大并发数（默认10）

        Returns:
            执行结果列表
        """
        self._log(f"\n{'='*70}")
        self._log(f"[AttackExecutor - PARALLEL MODE] Starting Execution")
        self._log(f"{'='*70}")
        self._log(f"[AttackExecutor] Total Tasks: {len(tasks)}")
        self._log(f"[AttackExecutor] Max Workers: {max_workers}")
        self._log(f"")

        # 打印任务摘要
        self._log(f"[Task Summary]:")
        vuln_type_counts = {}
        for task in tasks:
            vuln_type_counts[task.vuln_type] = vuln_type_counts.get(task.vuln_type, 0) + 1

        for vuln_type, count in sorted(vuln_type_counts.items()):
            self._log(f"  {vuln_type}: {count} task(s)")
        self._log(f"")

        self.results.clear()

        # ========== Phase 1: 并行注入阶段 ==========
        self._log(f"[Phase 1] Parallel Attack Execution")
        self._log(f"  Submitting {len(tasks)} task(s) to thread pool...")
        self._log(f"")

        start_time = time.time()
        completed_count = 0

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交所有任务到线程池
            future_to_task = {
                executor.submit(self._execute_task_safe, task, i+1, len(tasks)): task
                for i, task in enumerate(tasks)
            }

            # 收集结果（按完成顺序）
            for future in as_completed(future_to_task):
                task = future_to_task[future]
                completed_count += 1

                try:
                    result = future.result(timeout=600)  # ✅ 10分钟超时

                    with self._lock:  # 线程安全地添加结果
                        self.results.append({
                            "task_id": task.task_id,
                            "vuln_type": task.vuln_type,
                            "account": task.account_identifier,
                            "result": result
                        })
                        # ✅ 每完成一个任务就保存结果（线程安全）
                        self._save_results()

                    # 记录进度
                    if "error" in result:
                        self._log(f"  [{completed_count}/{len(tasks)}] {task.task_id} - ✗ ERROR")
                    elif result.get("vulnerable") is True:
                        self._log(f"  [{completed_count}/{len(tasks)}] {task.task_id} - ✓ VULNERABLE")
                    elif result.get("vulnerable") is False:
                        self._log(f"  [{completed_count}/{len(tasks)}] {task.task_id} - ✓ SAFE")
                    else:
                        self._log(f"  [{completed_count}/{len(tasks)}] {task.task_id} - ? PENDING")

                except TimeoutError:
                    self._log(f"  [{completed_count}/{len(tasks)}] {task.task_id} - ✗ TIMEOUT (10min)")
                    with self._lock:
                        self.results.append({
                            "task_id": task.task_id,
                            "error": "Task timeout after 600 seconds"
                        })
                        # ✅ 每完成一个任务就保存结果（即使超时也保存）
                        self._save_results()
                except Exception as e:
                    self._log(f"  [{completed_count}/{len(tasks)}] {task.task_id} - ✗ EXCEPTION: {e}")
                    with self._lock:
                        self.results.append({
                            "task_id": task.task_id,
                            "error": str(e)
                        })
                        # ✅ 每完成一个任务就保存结果（即使异常也保存）
                        self._save_results()

        phase1_duration = time.time() - start_time
        self._log(f"")
        self._log(f"[Phase 1 Complete] ⏱️  Time: {phase1_duration:.1f}s")
        self._log(f"")

        # ========== Phase 2: 统一的存储型漏洞检测阶段 ==========
        self._log(f"[Phase 2] Stored Vulnerability Detection Phase")
        self._log(f"{'~'*70}\n")

        # 检查是否有pending的任务
        pending_tasks = self._get_pending_tasks()

        if pending_tasks and self.driver:
            self._log(f"[Stored Vuln Detection] Found {len(pending_tasks)} pending task(s)")
            for vuln_type, count in pending_tasks.items():
                self._log(f"  {vuln_type}: {count}")
            self._log(f"")

            # ✅ 统一访问所有页面（触发存储型漏洞）
            self._finalize_stored_vulnerabilities()

            # ✅ 让各Agent检查最终结果
            self._check_all_stored_results()

        else:
            if not self.driver:
                self._log(f"[Stored Vuln Detection] Skipped - No driver available")
            elif not pending_tasks:
                self._log(f"[Stored Vuln Detection] Skipped - No pending tasks")

        # ========== Phase 3: 最终统计 ==========
        total_duration = time.time() - start_time

        self._log(f"\n{'='*70}")
        self._log(f"[AttackExecutor - PARALLEL MODE] Execution Complete")
        self._log(f"{'='*70}")
        self._log(f"[Final Statistics]:")
        self._log(f"  Total Tasks: {len(tasks)}")
        self._log(f"  Completed: {len(self.results)}")
        self._log(f"  Total Time: {total_duration:.1f}s")
        self._log(f"  Avg Time/Task: {total_duration/len(tasks):.2f}s")

        # 统计漏洞结果
        vulnerable_count = sum(1 for r in self.results if r.get("result", {}).get("vulnerable") is True)
        safe_count = sum(1 for r in self.results if r.get("result", {}).get("vulnerable") is False)
        uncertain_count = sum(1 for r in self.results if r.get("result", {}).get("vulnerable") is None)
        error_count = sum(1 for r in self.results if "error" in r)

        self._log(f"  Vulnerable: {vulnerable_count}")
        self._log(f"  Safe: {safe_count}")
        self._log(f"  Uncertain: {uncertain_count}")
        self._log(f"  Errors: {error_count}")
        self._log(f"{'='*70}\n")

        self._save_results()

        return self.results

    def _execute_task_safe(self, task, task_num: int, total_tasks: int) -> Dict:
        """
        🆕 线程安全的任务执行包装器

        在worker线程中执行单个任务，捕获所有异常
        """
        try:
            # 🆕 分配唯一的任务编号（替换LLM生成的编号）
            with self.task_counter_lock:
                self.task_counter += 1
                unique_task_id = f"TASK{self.task_counter:04d}"  # 例如：TASK0001
                original_task_id = task.task_id  # 保存原始编号用于日志

            # 🆕 Session 保活：每个任务开始前访问初始页面
            self._keepalive_visit(unique_task_id)

            self._log(f"\n{'~'*70}")
            self._log(f"[Task {task_num}/{total_tasks}] {unique_task_id} (原始: {original_task_id}) - STARTED")
            self._log(f"{'~'*70}")
            self._log(f"[Task Info]:")
            self._log(f"  ID: {unique_task_id} (原始LLM生成: {original_task_id})")
            self._log(f"  Type: {task.vuln_type}")
            self._log(f"  Account: {task.account_identifier}")
            self._log(f"  Description: {task.task_description}")
            self._log(f"  Target: {task.target_request.get('method')} {task.target_request.get('url')}")
            self._log(f"")

            # 🆕 更新任务编号
            task.task_id = unique_task_id

            # 执行任务
            result = self._execute_task(task)

            # 记录结果摘要
            self._log(f"\n[Task {task.task_id} Result]:")
            if "error" in result:
                self._log(f"  ✗ ERROR: {result['error']}")
            elif "vulnerable" in result:
                vuln_status = result['vulnerable']
                if vuln_status is True:
                    self._log(f"  ✓ VULNERABLE")
                elif vuln_status is False:
                    self._log(f"  ✓ SAFE (tested, not vulnerable)")
                else:
                    self._log(f"  ? PENDING (waiting for finalize)")
            else:
                self._log(f"  ✓ COMPLETED")
            self._log(f"")

            return result

        except Exception as e:
            self._log(f"\n[Task {task.task_id} Error]:")
            self._log(f"  ✗ Exception: {e}")
            import traceback
            self._log(f"  Traceback:")
            for line in traceback.format_exc().split('\n'):
                self._log(f"    {line}")
            self._log(f"")

            return {
                "error": str(e),
                "traceback": traceback.format_exc()
            }

    def _keepalive_visit(self, task_id: str):
        """
        🆕 Session 保活：访问初始页面并截图

        在每个攻击任务开始前调用，用于：
        1. 保持session活跃
        2. 验证session是否仍然有效
        3. 记录任务执行时的页面状态

        Args:
            task_id: 任务编号，用于截图文件命名
        """
        if not self.driver:
            return

        try:
            initial_url = self.crawler.initial_url

            # ✅ 计算任务日志目录（截图保存到任务目录下）
            task_log_dir = self.log_dir / "tasks" / task_id
            task_log_dir.mkdir(parents=True, exist_ok=True)

            self._log(f"[KeepAlive] 任务 {task_id} 开始前保活访问")
            self._log(f"[KeepAlive] 访问初始页面: {initial_url}")

            # 访问页面
            self.driver.get(initial_url)
            time.sleep(1.0)  # 等待页面加载

            # ✅ 截图前打印当前URL（对比验证）
            try:
                current_url = self.driver.current_url
                self._log(f"[KeepAlive] 当前Driver URL: {current_url}")
                if current_url != initial_url:
                    self._log(f"[KeepAlive] ⚠️  URL不匹配！期望: {initial_url}, 实际: {current_url}")
            except Exception as e:
                self._log(f"[KeepAlive] ⚠️  无法获取current_url: {e}")

            # ✅ 截图保存到任务目录下（而不是单独的session_keepalive目录）
            screenshot_path = task_log_dir / "keepalive.png"
            self.driver.save_screenshot(str(screenshot_path))

            # 获取页面标题（验证session）
            page_title = self.driver.title if self.driver.title else "(无标题)"

            self._log(f"[KeepAlive] ✅ 截图已保存: {screenshot_path.relative_to(self.log_dir)}")
            self._log(f"[KeepAlive] 页面标题: {page_title}")

        except Exception as e:
            self._log(f"[KeepAlive] ⚠️ 保活访问失败: {e}")
            # 失败不中断任务执行

    def _check_login_status(self, driver, initial_url: str) -> bool:
        """
        检查登录状态（通过URL对比）
        
        策略：访问初始页面，对比当前URL是否与初始URL一致
        如果跳转到其他页面（如登录页），说明session已过期
        
        Args:
            driver: Selenium WebDriver实例
            initial_url: 初始页面URL（应用首页）
        
        Returns:
            True表示已登录，False表示未登录
        """
        try:
            self._log(f"[Login Check] Visiting initial URL: {initial_url}")
            driver.get(initial_url)
            time.sleep(1.0)  # 等待页面加载

            current_url = driver.current_url
            self._log(f"[Login Check] Current URL: {current_url}")

            # URL对比（规范化处理：去除尾部斜杠、hash、query）
            from urllib.parse import urlparse

            initial_parsed = urlparse(initial_url)
            current_parsed = urlparse(current_url)

            # 比较 scheme + netloc + path（忽略query和fragment）
            initial_base = f"{initial_parsed.scheme}://{initial_parsed.netloc}{initial_parsed.path.rstrip('/')}"
            current_base = f"{current_parsed.scheme}://{current_parsed.netloc}{current_parsed.path.rstrip('/')}"

            if initial_base == current_base:
                self._log(f"[Login Check] ✓ Session valid (URL match)")
                return True
            else:
                self._log(f"[Login Check] ✗ Session expired (URL mismatch)")
                self._log(f"[Login Check]   Expected: {initial_base}")
                self._log(f"[Login Check]   Got: {current_base}")
                return False

        except Exception as e:
            self._log(f"[Login Check] ✗ Error: {e}")
            return False

    def _restore_login_status(self, worker_driver, worker_id: int, max_retries: int = 4) -> bool:
        """
        恢复登录状态（重新执行登录任务）
        
        Args:
            worker_driver: Worker的WebDriver实例
            worker_id: Worker编号
            max_retries: 最大重试次数（默认4次）
        
        Returns:
            True表示恢复成功，False表示失败
        """
        if not self.login_task:
            self._log(f"[Worker {worker_id}] ✗ No login task available, cannot restore")
            return False

        self._log(f"[Worker {worker_id}] Restoring login status...")

        for attempt in range(1, max_retries + 1):
            try:
                self._log(f"[Worker {worker_id}] Login attempt {attempt}/{max_retries}")

                # 🆕 重新执行登录任务（使用worker_driver）
                # 注意：需要临时切换crawler的driver到worker_driver
                original_driver = self.crawler.driver
                try:
                    # 临时切换driver
                    self.crawler.driver = worker_driver
                    self.crawler.sensors.driver = worker_driver
                    self.crawler.acts.sensors.driver = worker_driver

                    # 执行登录任务
                    self.crawler.run_a_task(self.login_task, logging_in=True)

                    # 检查登录是否成功
                    if self._check_login_status(worker_driver, self.initial_url):
                        self._log(f"[Worker {worker_id}] ✓ Login restored successfully on attempt {attempt}")
                        return True
                    else:
                        self._log(f"[Worker {worker_id}] ✗ Login check failed after attempt {attempt}")

                finally:
                    # 恢复原始driver
                    self.crawler.driver = original_driver
                    self.crawler.sensors.driver = original_driver
                    self.crawler.acts.sensors.driver = original_driver

            except Exception as e:
                self._log(f"[Worker {worker_id}] ✗ Login attempt {attempt} failed: {e}")
                import traceback
                self._log(traceback.format_exc())

        self._log(f"[Worker {worker_id}] ✗ Failed to restore login after {max_retries} attempts")
        return False

    def _ensure_login_status(self, worker_driver, worker_id: int) -> bool:
        """
        确保登录状态有效（检查+恢复）
        
        Args:
            worker_driver: Worker的WebDriver实例
            worker_id: Worker编号
        
        Returns:
            True表示登录有效，False表示无法恢复
        """
        self._log(f"[Worker {worker_id}] Ensuring login status...")

        # 1. 检查登录状态
        if self._check_login_status(worker_driver, self.initial_url):
            return True

        # 2. 登录已过期，尝试恢复
        self._log(f"[Worker {worker_id}] Session expired, attempting to restore...")
        return self._restore_login_status(worker_driver, worker_id)

    def _execute_task(self, task) -> Dict:
        """
        执行单个任务 - 修复版

        改进：
        1. 多账户场景不在这里获取凭证（由Agent内部处理）
        2. 单账户场景才获取凭证
        3. ✅ 为每个任务创建独立日志目录和文件
        """
        vuln_type = task.vuln_type

        # ✅ 创建任务独立日志目录
        task_log_dir = self.log_dir / "tasks" / task.task_id
        task_log_dir.mkdir(parents=True, exist_ok=True)
        task_log_file = task_log_dir / "attack.log"

        # ✅ 创建任务独立日志函数
        def task_log(*args):
            msg = " ".join(str(a) for a in args)
            try:
                with open(task_log_file, "a", encoding="utf-8") as f:
                    f.write(msg + "\n")
            except Exception:
                pass

        # ✅ 记录任务头部信息
        task_log(f"{'='*70}")
        task_log(f"[ATTACK TASK] {task.task_id}")
        task_log(f"{'='*70}")
        task_log(f"Vulnerability Type: {vuln_type}")
        task_log(f"Account: {task.account_identifier}")
        task_log(f"Description: {task.task_description}")
        task_log(f"")

        # ✅ 记录保活访问信息
        task_log(f"[SESSION KEEP-ALIVE]")
        task_log(f"Before starting this task, the initial URL was visited to keep session alive:")
        task_log(f"  Initial URL: {self.crawler.initial_url}")
        task_log(f"  Current URL: {self.driver.current_url}")
        task_log(f"  Screenshot: keepalive.png (saved in this task's directory)")
        task_log(f"")

        # ✅ 执行并记录 curl 重放（真正执行，获取 response）
        task_log(f"[TARGET REQUEST - CURL REPLAY & EXECUTION]:")
        task_log(f"")
        replay_result = self._execute_replay_curl(task.target_request, task.account_identifier, task_log)
        task_log(f"Command:")
        task_log(replay_result["command"])
        task_log(f"")
        task_log(f"Execution Result:")
        task_log(f"  Success: {replay_result['success']}")
        task_log(f"  Curl Exit Code: {replay_result['returncode']}")
        # ✅ 显示HTTP状态码
        http_status = replay_result.get('http_status')
        if http_status is not None:
            task_log(f"  HTTP Status: {http_status}")
        task_log(f"")
        task_log(f"Response (stdout):")
        task_log(replay_result["stdout"] if replay_result["stdout"] else "(empty)")
        task_log(f"")
        if replay_result["stderr"]:
            task_log(f"Errors (stderr):")
            task_log(replay_result["stderr"])
            task_log(f"")

        # ✅ 输出 account_manager 中存储的凭证（用于对比）
        task_log(f"{'='*70}")
        task_log(f"[ACCOUNT MANAGER CREDENTIALS]")
        task_log(f"{'='*70}")
        self._log_account_manager_credentials(task.account_identifier, task_log)
        task_log(f"")

        # ✅ 输出 driver 中实际存储的凭证信息（完整打印，不截断）
        task_log(f"{'='*70}")
        task_log(f"[DRIVER CREDENTIALS STATE]")
        task_log(f"{'='*70}")
        if self.driver:
            self._log_driver_credentials(task_log)
        else:
            task_log(f"No driver available")
        task_log(f"")

        # ✅ 判断是否多账户场景
        is_multi_account = "->" in task.account_identifier

        self._log(f"[Routing Task to Agent]:")
        self._log(f"  Task ID: {task.task_id}")
        self._log(f"  Vulnerability Type: {vuln_type}")
        self._log(f"  Multi-Account: {is_multi_account}")
        self._log(f"  Task Log: {task_log_file}")

        # 业务逻辑类漏洞
        if vuln_type in ["IDOR", "AUTH_BYPASS", "PRIVILEGE_ESCALATION", "BUSINESS_LOGIC"]:
            # 🆕 为当前任务创建独立的 BusinessLogicAgent
            try:
                logic_agent = self._create_agent_for_task(vuln_type, task_log_dir)
            except Exception as e:
                self._log(f"  ✗ ERROR: Failed to create agent: {e}")
                return {"error": f"Failed to create agent: {e}"}

            self._log(f"  → Using: BusinessLogicAgent (task-specific instance)")

            # 🆕 不再需要日志重定向（agent 已经使用任务目录初始化）
            if is_multi_account:
                # 多步骤（多账户）- Agent内部处理凭证
                accounts = [a.strip() for a in task.account_identifier.split("->")]
                self._log(f"  → Method: test_multi_step")
                self._log(f"  → Accounts: {accounts}")
                self._log(f"  → Passing account_manager to agent for credential management")
                self._log(f"")

                task_log(f"{'='*70}")
                task_log(f"[AGENT EXECUTION]")
                task_log(f"{'='*70}")
                task_log(f"Agent: BusinessLogicAgent")
                task_log(f"Method: test_multi_step")
                task_log(f"Accounts: {accounts}")
                task_log(f"")

                result = logic_agent.test_multi_step(
                    task_description=task.task_description,
                    target_request=task.target_request,
                    accounts=accounts,
                    account_manager=self.account_manager  # ← Agent内部获取凭证
                )
            else:
                # 单点分析 - 需要提前获取凭证
                self._log(f"  → Method: test_single_point")
                self._log(f"  → Fetching credentials for: {task.account_identifier}")

                credentials = self.account_manager.get_credentials(task.account_identifier)
                if not credentials:
                    self._log(f"  ✗ ERROR: Account not logged in: {task.account_identifier}")
                    task_log(f"[ERROR] Account not logged in: {task.account_identifier}")
                    return {"error": f"Account not logged in: {task.account_identifier}"}

                self._log(f"  ✓ Credentials obtained")
                self._log(f"  → Calling agent with credentials")
                self._log(f"")

                task_log(f"{'='*70}")
                task_log(f"[AGENT EXECUTION]")
                task_log(f"{'='*70}")
                task_log(f"Agent: BusinessLogicAgent")
                task_log(f"Method: test_single_point")
                task_log(f"")

                result = logic_agent.test_single_point(
                    task_description=task.task_description,
                    target_request=task.target_request,
                    credentials=credentials
                )

            # ✅ 记录结果到任务日志
            task_log(f"")
            task_log(f"{'='*70}")
            task_log(f"[RESULT]")
            task_log(f"{'='*70}")
            task_log(json.dumps(result, indent=2, ensure_ascii=False, default=str))
            task_log(f"")

            return result

        # 注入类漏洞（单账户）
        else:
            self._log(f"  → Fetching credentials for: {task.account_identifier}")

            # ✅ 单账户场景：提前获取凭证
            credentials = self.account_manager.get_credentials(task.account_identifier)
            if not credentials:
                self._log(f"  ✗ ERROR: Account not logged in: {task.account_identifier}")
                task_log(f"[ERROR] Account not logged in: {task.account_identifier}")
                return {"error": f"Account not logged in: {task.account_identifier}"}

            self._log(f"  ✓ Credentials obtained")

            # 🆕 为当前任务创建独立的注入 agent
            try:
                agent = self._create_agent_for_task(vuln_type, task_log_dir)
            except Exception as e:
                self._log(f"  ✗ ERROR: Failed to create agent: {e}")
                task_log(f"[ERROR] Failed to create agent: {e}")
                return {"error": f"Failed to create agent: {e}"}

            agent_name = agent.__class__.__name__
            self._log(f"  → Using: {agent_name} (task-specific instance)")

            task_log(f"{'='*70}")
            task_log(f"[AGENT EXECUTION]")
            task_log(f"{'='*70}")
            task_log(f"Agent: {agent_name}")
            task_log(f"Vulnerability Type: {vuln_type}")
            task_log(f"")

            # 🆕 不再需要日志重定向（agent 已经使用任务目录初始化）
            # ✅ 根据Agent类型调用不同接口
            if vuln_type == "SQL_INJECTION":
                # SQL Agent使用新接口（task_description作为参数）
                self._log(f"  → Method: test(task_description, target_request, credentials)")
                self._log(f"  → Calling {agent_name} with task description")
                self._log(f"")

                task_log(f"Method: test(task_description, target_request, credentials)")
                task_log(f"")

                result = agent.test(
                    task_description=task.task_description,
                    target_request=task.target_request,
                    credentials=credentials
                )
            else:
                # 其他Agent使用旧接口（只需request+credentials）
                self._log(f"  → Method: test(target_request, credentials)")
                self._log(f"  → Calling {agent_name}")
                self._log(f"")

                task_log(f"Method: test(target_request, credentials)")
                task_log(f"")

                result = agent.test(task.target_request, credentials)

            # ✅ 记录结果到任务日志
            task_log(f"")
            task_log(f"{'='*70}")
            task_log(f"[RESULT]")
            task_log(f"{'='*70}")
            task_log(json.dumps(result, indent=2, ensure_ascii=False, default=str))
            task_log(f"")

            return result
    
    def _save_results(self):
        """保存执行结果"""
        output_file = self.log_dir / "attack_results.json"
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            self._log(f"[Saved] Results saved to: {output_file}")
        except Exception as e:
            self._log(f"[Error] Failed to save results: {e}")

    def _add_result_and_save(self, result_dict: Dict[str, Any]):
        """
        添加结果并立即保存（线程安全）

        用于队列模式下的实时结果保存

        Args:
            result_dict: 结果字典
        """
        with self._lock:
            self.results.append(result_dict)
            self._save_results()

    def _get_pending_tasks(self) -> Dict[str, int]:
        """
        获取所有pending任务（vulnerable=None）

        Returns:
            {vuln_type: count}
        """
        pending = {}
        for result in self.results:
            if result.get("result", {}).get("vulnerable") is None:
                vuln_type = result.get("vuln_type")
                pending[vuln_type] = pending.get(vuln_type, 0) + 1
        return pending

    def _finalize_stored_vulnerabilities(self):
        """
        统一访问所有页面，触发存储型漏洞

        实现：
        1. 从crawler.store.pages获取所有已知页面
        2. 访问每个页面并保存截图（主页面编号）
        3. 提取页面上的所有链接（递归发现）
        4. 访问新发现的链接并保存截图（子链接编号：主页面编号_子编号）

        截图文件名层次：
            001_主页面.png
            001_1_子链接1.png
            001_2_子链接2.png
            002_主页面.png
            002_1_子链接1.png
            ...
        """
        self._log(f"[Unified Page Visit] Starting...")
        self._log(f"[Screenshots] Will be saved to: {self.screenshot_dir}")

        visited_urls = set()
        blacklist = ['/logout', '/delete', '/clear', '/reset', '/destroy', '/remove']
        parent_counter = 0  # 🆕 主页面计数器
        total_screenshots = 0  # 总截图数

        # ✅ 步骤1: 从内存中获取所有已知页面
        if not hasattr(self.crawler, 'store') or not hasattr(self.crawler.store, 'pages'):
            self._log(f"[Warning] Crawler.store.pages not available")
            return

        initial_pages = list(self.crawler.store.pages.keys())
        self._log(f"[Unified Page Visit] Found {len(initial_pages)} pages in crawler.store")

        # ✅ 步骤2: 访问所有已知页面并提取链接
        for idx, page_url in enumerate(initial_pages, 1):
            if page_url in visited_urls:
                continue

            # 🆕 主页面计数器递增
            parent_counter += 1

            self._log(f"\n[{idx}/{len(initial_pages)}] 📄 Main Page #{parent_counter}: {page_url}")

            try:
                # 访问主页面
                success = self.driver.get(page_url)
                if not success:
                    self._log(f"  ✗ Failed to visit (timeout or error)")
                    continue

                visited_urls.add(page_url)

                # 🆕 保存主页面截图（只有 parent_counter，没有 child_counter）
                self._save_screenshot(page_url, parent_counter=parent_counter)
                total_screenshots += 1

                # ✅ 步骤3: 提取页面上的所有链接
                try:
                    links = self._extract_links_from_current_page(blacklist)
                    if links:
                        self._log(f"  → Discovered {len(links)} child link(s)")

                    # ✅ 步骤4: 访问新发现的子链接
                    child_counter = 0  # 🆕 子链接计数器（每个主页面重新计数）
                    for link in links:
                        if link not in visited_urls:
                            child_counter += 1
                            self._log(f"    → Child #{parent_counter}_{child_counter}: {link}")
                            try:
                                success = self.driver.get(link)
                                if success:
                                    visited_urls.add(link)

                                    # 🆕 保存子链接截图（parent_counter + child_counter）
                                    self._save_screenshot(link, parent_counter=parent_counter, child_counter=child_counter)
                                    total_screenshots += 1

                            except Exception as e:
                                self._log(f"      ✗ Failed: {e}")

                except Exception as e:
                    self._log(f"  Warning: Failed to extract links: {e}")

            except Exception as e:
                self._log(f"  ✗ Failed to visit: {e}")

        self._log(f"\n{'='*70}")
        self._log(f"[Unified Page Visit] Complete")
        self._log(f"  - Main pages visited: {parent_counter}")
        self._log(f"  - Total URLs visited: {len(visited_urls)}")
        self._log(f"  - Total screenshots: {total_screenshots}")
        self._log(f"  - Screenshot directory: {self.screenshot_dir}")
        self._log(f"{'='*70}\n")

    def _extract_links_from_current_page(self, blacklist: List[str]) -> List[str]:
        """
        从当前页面提取所有可访问的链接

        Args:
            blacklist: 黑名单关键词列表

        Returns:
            去重后的URL列表
        """
        try:
            # 使用JavaScript提取所有<a>标签的href
            links = self.driver.execute_script("""
                return Array.from(document.querySelectorAll('a[href]'))
                             .map(a => a.href)
                             .filter(href => href.startsWith('http'));
            """)

            if not links:
                return []

            # 过滤黑名单
            filtered_links = []
            for link in links:
                # 检查是否包含黑名单关键词
                is_blacklisted = any(black in link.lower() for black in blacklist)
                if not is_blacklisted:
                    filtered_links.append(link)

            # 去重
            return list(set(filtered_links))

        except Exception as e:
            self._log(f"[Warning] Failed to extract links: {e}")
            return []

    def _check_all_stored_results(self):
        """
        让所有Agent检查最终结果

        每个Agent独立判断自己的token是否被触发
        """
        self._log(f"\n[Stored Vuln Detection] Checking final results...")

        # 支持延迟检测的Agent类型
        agents_to_check = [
            ("XSS", "XSS"),
            ("SSRF", "SSRF"),
            ("XXE", "XXE"),
            ("SSTI", "SSTI"),
            ("CMDI", "CMDI"),
            ("COMMAND_INJECTION", "CMDI"),
        ]

        for agent_key, vuln_type in agents_to_check:
            agent = self.injection_agents.get(agent_key)

            if agent and hasattr(agent, 'check_final_results'):
                try:
                    self._log(f"\n[{vuln_type}] Checking final results...")
                    updates = agent.check_final_results()

                    if updates:
                        self._apply_updates(updates, vuln_type)
                    else:
                        self._log(f"[{vuln_type}] No updates")

                except Exception as e:
                    self._log(f"[{vuln_type}] Error during check: {e}")
                    import traceback
                    self._log(traceback.format_exc())

    def _apply_updates(self, updates: Dict[Any, bool], vuln_type: str):
        """
        应用Agent返回的结果更新

        Args:
            updates: {token: is_vulnerable}
            vuln_type: 漏洞类型
        """
        updated_count = 0

        for result in self.results:
            if result.get("vuln_type") in [vuln_type, "COMMAND_INJECTION"] and vuln_type == "CMDI":
                # 特殊处理：CMDI和COMMAND_INJECTION是同一种
                task_result = result.get("result", {})

                if task_result.get("vulnerable") is None:
                    # 获取token（支持多种格式）
                    token = task_result.get("token") or task_result.get("random_id")

                    if token in updates:
                        task_result["vulnerable"] = updates[token]
                        updated_count += 1
                        status = "VULNERABLE" if updates[token] else "SAFE"
                        self._log(f"  [{result['task_id']}] Token {token}: {status}")

            elif result.get("vuln_type") == vuln_type:
                task_result = result.get("result", {})

                if task_result.get("vulnerable") is None:
                    # 获取token（支持多种格式）
                    token = task_result.get("token") or task_result.get("random_id")

                    if token in updates:
                        task_result["vulnerable"] = updates[token]
                        updated_count += 1
                        status = "VULNERABLE" if updates[token] else "SAFE"
                        self._log(f"  [{result['task_id']}] Token {token}: {status}")

        self._log(f"[{vuln_type}] Updated {updated_count} task(s)")

        # ✅ 如果有更新，立即保存结果
        if updated_count > 0:
            self._save_results()
            self._log(f"[{vuln_type}] Results saved after {updated_count} update(s)")

    def _is_get_xss_task(self, task) -> bool:
        """
        判断任务是否为 GET 型 XSS（需要串行执行以避免 driver 冲突）

        判断逻辑（简化版）：
        - 任务类型是 XSS
        - 请求方法是 GET

        Args:
            task: AttackTask 对象

        Returns:
            True 表示 GET 型 XSS，需要串行执行
        """
        if task.vuln_type != "XSS":
            return False

        request = task.target_request
        method = request.get("method", "GET")

        return method == "GET"

    def _has_url_params(self, task) -> bool:
        """
        判断 URL 是否包含参数

        Args:
            task: AttackTask 对象

        Returns:
            True 表示 URL 包含参数（? 或 =）
        """
        url = task.target_request.get("url", "")
        return "?" in url or "=" in url

    # ========== OLD VERSION (Kept for reference) ==========
    def execute_tasks_from_queue(self, task_queue, max_workers: int = 10) -> List[Dict]:
        """
        从队列消费任务并执行（并行模式）

        Args:
            task_queue: queue.Queue对象，任务来源
            max_workers: 最大并发数（默认10）

        Returns:
            执行结果列表
        """
        self._log(f"\n{'='*70}")
        self._log(f"[AttackExecutor - QUEUE MODE] Starting Execution")
        self._log(f"{'='*70}")
        self._log(f"[AttackExecutor] Max Workers: {max_workers}")
        self._log(f"[AttackExecutor] Waiting for tasks from queue...")
        self._log(f"")

        self.results.clear()
        tasks_received = []
        completed_count = 0
        start_time = time.time()

        # ========== Phase 1: 并行执行所有任务 ==========
        self._log(f"[Phase 1] Parallel Task Execution")
        self._log(f"{'~'*70}\n")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []

            while True:
                # 从队列获取任务
                task = task_queue.get()

                # 收到结束信号
                if task is None:
                    self._log(f"\n[Queue] Received termination signal")
                    self._log(f"[Queue] Total tasks received: {len(tasks_received)}")
                    self._log(f"[Queue] Waiting for {len(futures)} running task(s) to complete...")
                    break

                # 收到新任务
                tasks_received.append(task)
                self._log(f"[Queue] Task {task.task_id} received (total: {len(tasks_received)})")

                # 提交任务到线程池并行执行
                future = executor.submit(self._execute_task_safe, task, len(tasks_received), "?")
                futures.append((future, task))

                # 定期检查已完成的任务
                if len(futures) >= max_workers * 2:
                    self._log(f"[Queue] Checking {len(futures)} pending futures...")
                    completed_futures = []

                    for future, task_obj in futures:
                        if future.done():
                            try:
                                result = future.result()
                                self._add_result_and_save({
                                    "task_id": task_obj.task_id,
                                    "vuln_type": task_obj.vuln_type,
                                    "account": task_obj.account_identifier,
                                    "target_request": task_obj.target_request,
                                    "result": result
                                })
                                completed_count += 1
                                completed_futures.append((future, task_obj))

                                # 记录进度
                                if "error" in result:
                                    self._log(f"  [{completed_count}/?] {task_obj.task_id} - ✗ ERROR")
                                elif result.get("vulnerable") is True:
                                    self._log(f"  [{completed_count}/?] {task_obj.task_id} - ✓ VULNERABLE")
                                elif result.get("vulnerable") is False:
                                    self._log(f"  [{completed_count}/?] {task_obj.task_id} - ✓ SAFE")
                                else:
                                    self._log(f"  [{completed_count}/?] {task_obj.task_id} - ? PENDING")

                            except Exception as e:
                                self._log(f"  [{completed_count}/?] {task_obj.task_id} - ✗ EXCEPTION: {e}")
                                self._add_result_and_save({
                                    "task_id": task_obj.task_id,
                                    "target_request": task_obj.target_request,
                                    "error": str(e)
                                })
                                completed_count += 1
                                completed_futures.append((future, task_obj))

                    # 移除已完成的future
                    for completed in completed_futures:
                        futures.remove(completed)

                    self._log(f"[Queue] {len(completed_futures)} task(s) completed, {len(futures)} still running")

            # 等待所有剩余任务完成
            self._log(f"\n[Queue] Waiting for final {len(futures)} task(s)...")
            for future, task_obj in futures:
                try:
                    result = future.result(timeout=600)
                    self._add_result_and_save({
                        "task_id": task_obj.task_id,
                        "vuln_type": task_obj.vuln_type,
                        "account": task_obj.account_identifier,
                        "target_request": task_obj.target_request,
                        "result": result
                    })
                    completed_count += 1

                    # 记录进度
                    if "error" in result:
                        self._log(f"  [{completed_count}/?] {task_obj.task_id} - ✗ ERROR")
                    elif result.get("vulnerable") is True:
                        self._log(f"  [{completed_count}/?] {task_obj.task_id} - ✓ VULNERABLE")
                    elif result.get("vulnerable") is False:
                        self._log(f"  [{completed_count}/?] {task_obj.task_id} - ✓ SAFE")
                    else:
                        self._log(f"  [{completed_count}/?] {task_obj.task_id} - ? PENDING")

                except TimeoutError:
                    self._log(f"  [{completed_count}/?] {task_obj.task_id} - ✗ TIMEOUT (10min)")
                    self._add_result_and_save({
                        "task_id": task_obj.task_id,
                        "target_request": task_obj.target_request,
                        "error": "Task timeout after 600 seconds"
                    })
                    completed_count += 1
                except Exception as e:
                    self._log(f"  [{completed_count}/?] {task_obj.task_id} - ✗ EXCEPTION: {e}")
                    self._add_result_and_save({
                        "task_id": task_obj.task_id,
                        "target_request": task_obj.target_request,
                        "error": str(e)
                    })
                    completed_count += 1

        phase1_duration = time.time() - start_time
        self._log(f"")
        self._log(f"[Phase 1 Complete] ⏱️  Time: {phase1_duration:.1f}s")
        self._log(f"")

        # ========== Phase 2: 统一的存储型漏洞检测阶段 ==========
        self._log(f"[Phase 2] Stored Vulnerability Detection Phase")
        self._log(f"{'~'*70}\n")

        # 检查是否有pending的任务
        pending_tasks = self._get_pending_tasks()

        if pending_tasks and self.driver:
            self._log(f"[Stored Vuln Detection] Found {len(pending_tasks)} pending task(s)")
            for vuln_type, count in pending_tasks.items():
                self._log(f"  {vuln_type}: {count}")
            self._log(f"")

            # ✅ 统一访问所有页面（触发存储型漏洞）
            self._finalize_stored_vulnerabilities()

            # ✅ 让各Agent检查最终结果
            self._check_all_stored_results()

        else:
            if not self.driver:
                self._log(f"[Stored Vuln Detection] Skipped - No driver available")
            elif not pending_tasks:
                self._log(f"[Stored Vuln Detection] Skipped - No pending tasks")

        # ========== Phase 3: 最终统计 ==========
        total_duration = time.time() - start_time

        self._log(f"\n{'='*70}")
        self._log(f"[AttackExecutor - QUEUE MODE] Execution Complete")
        self._log(f"{'='*70}")
        self._log(f"[Final Statistics]:")
        self._log(f"  Total Tasks: {len(tasks_received)}")
        self._log(f"  Completed: {len(self.results)}")
        self._log(f"  Total Time: {total_duration:.1f}s")
        if len(tasks_received) > 0:
            self._log(f"  Avg Time/Task: {total_duration/len(tasks_received):.2f}s")

        # 统计漏洞结果
        vulnerable_count = sum(1 for r in self.results if r.get("result", {}).get("vulnerable") is True)
        safe_count = sum(1 for r in self.results if r.get("result", {}).get("vulnerable") is False)
        uncertain_count = sum(1 for r in self.results if r.get("result", {}).get("vulnerable") is None)
        error_count = sum(1 for r in self.results if "error" in r)

        self._log(f"  Vulnerable: {vulnerable_count}")
        self._log(f"  Safe: {safe_count}")
        self._log(f"  Uncertain: {uncertain_count}")
        self._log(f"  Errors: {error_count}")
        self._log(f"{'='*70}\n")

        self._save_results()

        return self.results

    # def execute_tasks_from_queue(self, task_queue, max_workers: int = 10) -> List[Dict]:
    #     """
    #     🆕 从队列消费任务并执行（改进版 - 支持 GET-XSS 串行执行）

    #     执行流程：
    #     Phase 1a: 并行执行非 GET-XSS 任务（使用 max_workers 个并发）
    #     Phase 1b: 串行执行 GET-XSS 任务（避免 driver 冲突）
    #     Phase 2: 统一的存储型漏洞检测

    #     特殊处理：
    #     - GET XSS 且没有 URL 参数的任务会被跳过（记录为 skipped）

    #     Args:
    #         task_queue: queue.Queue对象，任务来源
    #         max_workers: 最大并发数（默认10）

    #     Returns:
    #         执行结果列表
    #     """
    #     self._log(f"\n{'='*70}")
    #     self._log(f"[AttackExecutor - QUEUE MODE] Starting Execution")
    #     self._log(f"{'='*70}")
    #     self._log(f"[AttackExecutor] Max Workers: {max_workers}")
    #     self._log(f"[AttackExecutor] Waiting for tasks from queue...")
    #     self._log(f"")

    #     self.results.clear()
    #     tasks_received = []
    #     get_xss_buffer = []  # ✅ 缓存 GET-XSS 任务
    #     skipped_tasks = []   # ✅ 记录跳过的任务
    #     completed_count = 0
    #     start_time = time.time()

    #     # ========== Phase 1a: 并行执行非 GET-XSS 任务 ==========
    #     self._log(f"[Phase 1a] Parallel Execution (Non GET-XSS Tasks)")
    #     self._log(f"{'~'*70}\n")

    #     with ThreadPoolExecutor(max_workers=max_workers) as executor:
    #         futures = []

    #         while True:
    #             # 从队列获取任务
    #             task = task_queue.get()

    #             # 收到结束信号
    #             if task is None:
    #                 self._log(f"\n[Queue] Received termination signal")
    #                 self._log(f"[Queue] Total tasks received: {len(tasks_received)}")
    #                 self._log(f"[Queue] GET-XSS tasks buffered: {len(get_xss_buffer)}")
    #                 self._log(f"[Queue] Tasks skipped: {len(skipped_tasks)}")
    #                 self._log(f"[Queue] Normal tasks submitted: {len(tasks_received) - len(get_xss_buffer) - len(skipped_tasks)}")
    #                 self._log(f"[Queue] Waiting for {len(futures)} running task(s) to complete...")
    #                 break

    #             # 收到新任务
    #             tasks_received.append(task)

    #             # ✅ 判断是否为 GET-XSS
    #             if self._is_get_xss_task(task):
    #                 # 检查是否有 URL 参数
    #                 if not self._has_url_params(task):
    #                     # GET XSS 但没有 URL 参数，跳过
    #                     self._log(f"[Queue] Task {task.task_id} skipped (GET XSS without URL params)")
    #                     skipped_tasks.append(task)
    #                     # 记录跳过结果
    #                     self._add_result_and_save({
    #                         "task_id": task.task_id,
    #                         "vuln_type": task.vuln_type,
    #                         "account": task.account_identifier,
    #                         "target_request": task.target_request,
    #                         "result": {
    #                             "skipped": True,
    #                             "reason": "GET XSS without URL parameters",
    #                             "vulnerable": None
    #                         }
    #                     })
    #                 else:
    #                     # GET XSS 且有 URL 参数，缓存待串行执行
    #                     self._log(f"[Queue] Task {task.task_id} is GET-XSS (with params), buffering for serial execution")
    #                     get_xss_buffer.append(task)
    #             else:
    #                 # 普通任务，立即提交并行执行
    #                 self._log(f"[Queue] Task {task.task_id} received (total: {len(tasks_received)})")
    #                 future = executor.submit(self._execute_task_safe, task, len(tasks_received), "?")
    #                 futures.append((future, task))

    #             # 定期检查已完成的任务
    #             if len(futures) >= max_workers * 2:
    #                 self._log(f"[Queue] Checking {len(futures)} pending futures...")
    #                 completed_futures = []

    #                 for future, task_obj in futures:
    #                     if future.done():
    #                         try:
    #                             result = future.result()
    #                             self._add_result_and_save({
    #                                 "task_id": task_obj.task_id,
    #                                 "vuln_type": task_obj.vuln_type,
    #                                 "account": task_obj.account_identifier,
    #                                 "target_request": task_obj.target_request,
    #                                 "result": result
    #                             })
    #                             completed_count += 1
    #                             completed_futures.append((future, task_obj))

    #                             # 记录进度
    #                             if "error" in result:
    #                                 self._log(f"  [{completed_count}/?] {task_obj.task_id} - ✗ ERROR")
    #                             elif result.get("vulnerable") is True:
    #                                 self._log(f"  [{completed_count}/?] {task_obj.task_id} - ✓ VULNERABLE")
    #                             elif result.get("vulnerable") is False:
    #                                 self._log(f"  [{completed_count}/?] {task_obj.task_id} - ✓ SAFE")
    #                             else:
    #                                 self._log(f"  [{completed_count}/?] {task_obj.task_id} - ? PENDING")

    #                         except Exception as e:
    #                             self._log(f"  [{completed_count}/?] {task_obj.task_id} - ✗ EXCEPTION: {e}")
    #                             self._add_result_and_save({
    #                                 "task_id": task_obj.task_id,
    #                                 "target_request": task_obj.target_request,
    #                                 "error": str(e)
    #                             })
    #                             completed_count += 1
    #                             completed_futures.append((future, task_obj))

    #                 # 移除已完成的future
    #                 for completed in completed_futures:
    #                     futures.remove(completed)

    #                 self._log(f"[Queue] {len(completed_futures)} task(s) completed, {len(futures)} still running")

    #         # 等待所有剩余的普通任务完成
    #         self._log(f"\n[Queue] Waiting for final {len(futures)} task(s)...")
    #         for future, task_obj in futures:
    #             try:
    #                 result = future.result(timeout=600)
    #                 self._add_result_and_save({
    #                     "task_id": task_obj.task_id,
    #                     "vuln_type": task_obj.vuln_type,
    #                     "account": task_obj.account_identifier,
    #                     "target_request": task_obj.target_request,
    #                     "result": result
    #                 })
    #                 completed_count += 1

    #                 # 记录进度
    #                 if "error" in result:
    #                     self._log(f"  [{completed_count}/?] {task_obj.task_id} - ✗ ERROR")
    #                 elif result.get("vulnerable") is True:
    #                     self._log(f"  [{completed_count}/?] {task_obj.task_id} - ✓ VULNERABLE")
    #                 elif result.get("vulnerable") is False:
    #                     self._log(f"  [{completed_count}/?] {task_obj.task_id} - ✓ SAFE")
    #                 else:
    #                     self._log(f"  [{completed_count}/?] {task_obj.task_id} - ? PENDING")

    #             except TimeoutError:
    #                 self._log(f"  [{completed_count}/?] {task_obj.task_id} - ✗ TIMEOUT (10min)")
    #                 self._add_result_and_save({
    #                     "task_id": task_obj.task_id,
    #                     "target_request": task_obj.target_request,
    #                     "error": "Task timeout after 600 seconds"
    #                 })
    #                 completed_count += 1
    #             except Exception as e:
    #                 self._log(f"  [{completed_count}/?] {task_obj.task_id} - ✗ EXCEPTION: {e}")
    #                 self._add_result_and_save({
    #                     "task_id": task_obj.task_id,
    #                     "target_request": task_obj.target_request,
    #                     "error": str(e)
    #                 })
    #                 completed_count += 1

    #     phase1a_duration = time.time() - start_time
    #     self._log(f"")
    #     self._log(f"[Phase 1a Complete] ⏱️  Time: {phase1a_duration:.1f}s")
    #     self._log(f"  Normal tasks completed: {completed_count}")
    #     self._log(f"")

    #     # ========== Phase 1b: 串行执行 GET-XSS 任务 ==========
    #     if get_xss_buffer:
    #         self._log(f"[Phase 1b] Serial GET-XSS Execution")
    #         self._log(f"{'~'*70}")
    #         self._log(f"[GET-XSS] Total tasks: {len(get_xss_buffer)}")
    #         self._log(f"[GET-XSS] Reason: Avoid driver conflicts (all GET-XSS tasks share the same driver)")
    #         self._log(f"")

    #         phase1b_start = time.time()

    #         for i, task in enumerate(get_xss_buffer, 1):
    #             self._log(f"[GET-XSS {i}/{len(get_xss_buffer)}] Executing {task.task_id}...")

    #             try:
    #                 result = self._execute_task_safe(task, i, len(get_xss_buffer))

    #                 with self._lock:
    #                     self.results.append({
    #                         "task_id": task.task_id,
    #                         "vuln_type": task.vuln_type,
    #                         "account": task.account_identifier,
    #                         "target_request": task.target_request,
    #                         "result": result
    #                     })
    #                     self._save_results()

    #                 completed_count += 1

    #                 # 记录进度
    #                 if "error" in result:
    #                     self._log(f"  [{i}/{len(get_xss_buffer)}] {task.task_id} - ✗ ERROR")
    #                 elif result.get("vulnerable") is True:
    #                     self._log(f"  [{i}/{len(get_xss_buffer)}] {task.task_id} - ✓ VULNERABLE")
    #                 elif result.get("vulnerable") is False:
    #                     self._log(f"  [{i}/{len(get_xss_buffer)}] {task.task_id} - ✓ SAFE")
    #                 else:
    #                     self._log(f"  [{i}/{len(get_xss_buffer)}] {task.task_id} - ? PENDING")

    #             except Exception as e:
    #                 self._log(f"  [{i}/{len(get_xss_buffer)}] {task.task_id} - ✗ EXCEPTION: {e}")
    #                 with self._lock:
    #                     self.results.append({
    #                         "task_id": task.task_id,
    #                         "target_request": task.target_request,
    #                         "error": str(e)
    #                     })
    #                     self._save_results()
    #                 completed_count += 1

    #         phase1b_duration = time.time() - phase1b_start
    #         self._log(f"")
    #         self._log(f"[Phase 1b Complete] ⏱️  Time: {phase1b_duration:.1f}s")
    #         self._log(f"  GET-XSS tasks completed: {len(get_xss_buffer)}")
    #         self._log(f"")
    #     else:
    #         self._log(f"[Phase 1b] No GET-XSS tasks, skipping serial execution")
    #         self._log(f"")

    #     # ========== Phase 2: 统一的存储型漏洞检测阶段 ==========
    #     self._log(f"[Phase 2] Stored Vulnerability Detection Phase")
    #     self._log(f"{'~'*70}\n")

    #     # 检查是否有pending的任务
    #     pending_tasks = self._get_pending_tasks()

    #     if pending_tasks and self.driver:
    #         self._log(f"[Stored Vuln Detection] Found {len(pending_tasks)} pending task(s)")
    #         for vuln_type, count in pending_tasks.items():
    #             self._log(f"  {vuln_type}: {count}")
    #         self._log(f"")

    #         # ✅ 统一访问所有页面（触发存储型漏洞）
    #         self._finalize_stored_vulnerabilities()

    #         # ✅ 让各Agent检查最终结果
    #         self._check_all_stored_results()

    #     else:
    #         if not self.driver:
    #             self._log(f"[Stored Vuln Detection] Skipped - No driver available")
    #         elif not pending_tasks:
    #             self._log(f"[Stored Vuln Detection] Skipped - No pending tasks")

    #     # ========== Phase 3: 最终统计 ==========
    #     total_duration = time.time() - start_time

    #     self._log(f"\n{'='*70}")
    #     self._log(f"[AttackExecutor - QUEUE MODE] Execution Complete")
    #     self._log(f"{'='*70}")
    #     self._log(f"[Final Statistics]:")
    #     self._log(f"  Total Tasks: {len(tasks_received)}")
    #     self._log(f"  Tasks Skipped: {len(skipped_tasks)}")
    #     self._log(f"  Tasks Executed: {len(tasks_received) - len(skipped_tasks)}")
    #     self._log(f"  Completed: {len(self.results)}")
    #     self._log(f"  Total Time: {total_duration:.1f}s")
    #     if len(tasks_received) > 0:
    #         self._log(f"  Avg Time/Task: {total_duration/len(tasks_received):.2f}s")

    #     # 统计漏洞结果
    #     vulnerable_count = sum(1 for r in self.results if r.get("result", {}).get("vulnerable") is True)
    #     safe_count = sum(1 for r in self.results if r.get("result", {}).get("vulnerable") is False)
    #     uncertain_count = sum(1 for r in self.results if r.get("result", {}).get("vulnerable") is None)
    #     error_count = sum(1 for r in self.results if "error" in r)
    #     skipped_count = sum(1 for r in self.results if r.get("result", {}).get("skipped") is True)

    #     self._log(f"  Vulnerable: {vulnerable_count}")
    #     self._log(f"  Safe: {safe_count}")
    #     self._log(f"  Uncertain: {uncertain_count}")
    #     self._log(f"  Errors: {error_count}")
    #     self._log(f"  Skipped: {skipped_count}")
    #     self._log(f"{'='*70}\n")

    #     self._save_results()

    #     return self.results
