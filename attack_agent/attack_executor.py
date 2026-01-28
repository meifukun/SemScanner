"""
AttackExecutor - 完整重构版（支持独立worker drivers + 实时凭证更新 + CSRF注入）

核心改进：
1. 每个攻击线程使用独立的worker driver（复用Phase 3的drivers）
2. 每个worker独立的凭证存储（WorkerCredentialStore）
3. 任务开始前：登录检查 + 凭证和CSRF token实时更新
4. CSRF token自动注入到curl命令
5. 登录失败自动重试（最多4次）
"""

from typing import List, Dict, Any, Set
from pathlib import Path
import json
import time
import threading
import hashlib
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue, Empty
from urllib.parse import urlparse
from crawl.sensors import Sensors
from crawl.Actuators import Actuators
from crawl.Bridge import Bridge
from capture.network_capture import NetworkCapture
from crawl.tracer import ExecutionTracer
from task.tasks import Task
from seleniumwire import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from queue import Queue, Empty
# 导入WorkerCredentialStore
from attack_agent.worker_credential_store import WorkerCredentialStore
# ✅ 新增这行导入
from config.llm_config import get_model_name, get_temperature
from selenium.webdriver.support.ui import WebDriverWait # ✅ 新增
from selenium.common.exceptions import UnexpectedAlertPresentException, NoAlertPresentException # 补充 NoAlertPresentException
from urllib3.exceptions import MaxRetryError, NewConnectionError
from selenium.common.exceptions import WebDriverException
from attack_agent.request_utils import extract_useful_response

class AttackExecutor:
    """
    攻击执行器 - 完整重构版

    特性：
    - 复用任务规划阶段的driver instances
    - 每个worker独立管理凭证和session
    - 实时更新凭证和CSRF tokens
    - 自动检测和恢复登录状态
    """

    def __init__(self, account_manager, crawler, client,
                 log_dir: str = "output/attack_executor",
                 edges_file: str = None,
                 driver = None,
                 beacon_base: str = "http://172.17.0.1:9091/",
                 worker_drivers: List = None,
                 chrome_options = None,
                 initial_url: str = None,
                 login_task = None,
                 target_domain: str = None):
        """初始化 AttackExecutor"""
        self.account_manager = account_manager
        self.crawler = crawler
        self.client = client
        self.driver = driver
        self.beacon_base = beacon_base
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # 新参数
        self.worker_drivers = worker_drivers or []
        self.chrome_options = chrome_options
        self.initial_url = initial_url
        self.login_task = login_task

        # 🆕 Worker driver池（线程安全）
        self.driver_queue: Queue = Queue()
        self.worker_stores: Dict[int, WorkerCredentialStore] = {}

        if self.worker_drivers:
            for idx, worker_driver in enumerate(self.worker_drivers):
                self.driver_queue.put((idx, worker_driver))  # (worker_id, driver)
                self.worker_stores[idx] = WorkerCredentialStore(worker_id=idx)
            self._log(f"[Init] Created driver pool with {len(self.worker_drivers)} workers")
            self._log(f"[Init] Created {len(self.worker_stores)} worker credential stores")

        self.edges_file = edges_file
        self.results = []
        self._log_path = self.log_dir / "executor.log"

        # 截图目录
        self.screenshot_dir = self.log_dir / "stored_vuln_screenshots"
        self.screenshot_dir.mkdir(parents=True, exist_ok=True)

        # 任务计数器
        self.task_counter = 0
        self.task_counter_lock = threading.Lock()

        # 线程安全锁
        self._lock = threading.Lock()
        self._log_lock = threading.Lock()

        self.target_domain = target_domain # 保存下来，造新车时要用拦截器

    def _create_new_driver(self):
        """🆕 浏览器工厂：创建新 Driver 并注入必要脚本"""
        self._log("[DriverFactory] 正在销毁旧实例并创建新浏览器...")
        
        # 1. 配置
        options = self.chrome_options
        if not options:
            options = webdriver.ChromeOptions()
            options.add_argument("--headless")
            options.add_argument("--disable-web-security")
            options.add_argument("--allow-running-insecure-content")
            options.add_argument("--disable-xss-auditor")

        # 2. 启动
        service = Service(ChromeDriverManager().install())
        new_driver = webdriver.Chrome(service=service, options=options)
        
        # 3. 设置
        new_driver.set_page_load_timeout(60)
        new_driver.set_script_timeout(60)
        new_driver.set_window_size(1920, 1080)

        # 4. 拦截器 (依赖 self.target_domain)
        if self.target_domain:
            def interceptor(request):
                if self.target_domain not in request.url:
                    request.abort()
            new_driver.request_interceptor = interceptor

        # 5. 💉 注入脚本 (路径直接写死 js/...)
        try:
            # 辅助函数
            def send(driver, cmd, params={}):
                return driver.execute_cdp_cmd(cmd, params)

            # 需要注入的文件列表
            js_files = ["xss_xhr.js", "md5.js", "lib.js", "addeventlistener_wrapper.js"]
            
            for js_file in js_files:
                # 直接读取当前目录下 js/ 文件夹里的文件
                file_path = f"js/{js_file}"
                try:
                    with open(file_path, "r", encoding='utf-8') as f:
                        source_code = f.read()
                        send(new_driver, "Page.addScriptToEvaluateOnNewDocument", {"source": source_code})
                except FileNotFoundError:
                    self._log(f"[DriverFactory] ⚠️ 警告：找不到脚本文件 {file_path}，跳过")

            self._log("[DriverFactory] 新浏览器创建成功且已注入脚本")
            
        except Exception as e:
            self._log(f"[DriverFactory] ❌ 初始化失败: {e}")
            try:
                new_driver.quit()
            except:
                pass
            raise e

        return new_driver
    
    def _log(self, *args):
        """线程安全的日志输出"""
        msg = " ".join(str(a) for a in args)
        try:
            with self._log_lock:
                with open(self._log_path, "a", encoding="utf-8") as f:
                    f.write(msg + "\n")
                print(msg)  # 🆕 同时输出到控制台
        except Exception:
            pass

    def _url_to_filename(self, url: str) -> str:
        """将URL转换为合法的文件名"""
        filename = re.sub(r'^https?://', '', url)
        filename = re.sub(r'[^\w\-.]', '_', filename)
        filename = re.sub(r'_+', '_', filename)
        filename = filename.strip('_')

        if len(filename) > 200:
            url_hash = hashlib.md5(url.encode('utf-8')).hexdigest()[:8]
            filename = f"{filename[:50]}_{url_hash}"

        return filename

    def _create_agent_for_task(self, vuln_type: str, task_log_dir: Path):
        """根据漏洞类型创建对应的agent实例"""
        task_log_dir_str = str(task_log_dir)

        if vuln_type == "SQL_INJECTION":
            from attack_agent.sql_injection_agent import SQLInjectionAgent
            return SQLInjectionAgent(client=self.client, log_dir=task_log_dir_str)
        elif vuln_type == "XSS":
            from attack_agent.xss_agent import XSSAgent
            return XSSAgent(client=self.client, driver=self.driver, log_dir=task_log_dir_str)
        elif vuln_type == "SSTI":
            from attack_agent.ssti_agent import SSTIAgent
            return SSTIAgent(client=self.client, beacon_base=self.beacon_base, log_dir=task_log_dir_str)
        elif vuln_type == "SSRF":
            from attack_agent.ssrf_agent import SSRFAgent
            return SSRFAgent(client=self.client, beacon_base=self.beacon_base, log_dir=task_log_dir_str)
        elif vuln_type in ["CMDI", "COMMAND_INJECTION"]:
            from attack_agent.command_injection_agent import CommandInjectionAgent
            return CommandInjectionAgent(client=self.client, beacon_base=self.beacon_base, log_dir=task_log_dir_str)
        elif vuln_type in ["PT", "PATH_TRAVERSAL"]:
            from attack_agent.path_traversal_agent import PathTraversalAgent
            return PathTraversalAgent(client=self.client, log_dir=task_log_dir_str)
        elif vuln_type == "XXE":
            from attack_agent.xxe_agent import XXEAgent
            return XXEAgent(client=self.client, beacon_base=self.beacon_base, log_dir=task_log_dir_str)
        elif vuln_type in ["IDOR", "AUTH_BYPASS", "PRIVILEGE_ESCALATION", "BUSINESS_LOGIC"]:
            from attack_agent.business_logic_agent import BusinessLogicAgent
            return BusinessLogicAgent(client=self.client, log_dir=task_log_dir_str)
        else:
            raise ValueError(f"Unsupported vulnerability type: {vuln_type}")

    def _check_login_status(self, driver, initial_url: str, worker_id: int, task_log, task_log_dir: Path) -> bool:
        """
        检查登录状态（通过URL对比）

        策略：访问初始页面，对比当前URL是否与初始URL一致

        Args:
            driver: WebDriver实例
            initial_url: 初始页面URL
            worker_id: Worker编号
            task_log: 日志函数
            task_log_dir: 任务日志目录（用于保存截图）
        """
        try:
            task_log(f"[Worker {worker_id}] 检查登录状态...")
            task_log(f"[Worker {worker_id}] 访问初始页面: {initial_url}")

            driver.get(initial_url)
            time.sleep(1.0)

            current_url = driver.current_url
            task_log(f"[Worker {worker_id}] 当前URL: {current_url}")

            # 保存截图
            screenshot_path = task_log_dir / "login_check.png"
            driver.save_screenshot(str(screenshot_path))
            task_log(f"[Worker {worker_id}] 登录检查截图已保存: {screenshot_path.name}")

            initial_parsed = urlparse(initial_url)
            current_parsed = urlparse(current_url)

            initial_base = f"{initial_parsed.scheme}://{initial_parsed.netloc}{initial_parsed.path.rstrip('/')}"
            current_base = f"{current_parsed.scheme}://{current_parsed.netloc}{current_parsed.path.rstrip('/')}"

            is_match = initial_base == current_base
            if is_match:
                task_log(f"[Worker {worker_id}] ✓ URL匹配，登录状态有效")
            else:
                task_log(f"[Worker {worker_id}] ✗ URL不匹配，登录状态无效")
                task_log(f"[Worker {worker_id}]   期望: {initial_base}")
                task_log(f"[Worker {worker_id}]   实际: {current_base}")

            return is_match
        except Exception as e:
            task_log(f"[Worker {worker_id}] ✗ 登录检查异常: {e}")
            return False

    # def _restore_login_status(self, worker_driver, worker_id: int, task_log, task_log_dir: Path, max_retries: int = 4) -> bool:
    #     """
    #     恢复登录状态（重新执行登录任务）

    #     独立执行：不依赖主driver，每个worker自己恢复

    #     Args:
    #         worker_driver: Worker的WebDriver实例
    #         worker_id: Worker编号
    #         task_log: 日志函数
    #         task_log_dir: 任务日志目录
    #         max_retries: 最大重试次数
    #     """
    #     if not self.login_task:
    #         task_log(f"[Worker {worker_id}] ✗ 警告：没有登录任务，无法恢复登录状态")
    #         return False

    #     task_log(f"[Worker {worker_id}] 开始恢复登录状态...")

    #     for attempt in range(1, max_retries + 1):
    #         try:
    #             task_log(f"[Worker {worker_id}] 登录尝试 {attempt}/{max_retries}")

    #             # 临时切换crawler的driver到worker_driver
    #             original_driver = self.crawler.driver
    #             original_sensors_driver = self.crawler.sensors.driver
    #             original_acts_driver = self.crawler.acts.sensors.driver

    #             try:
    #                 self.crawler.driver = worker_driver
    #                 self.crawler.sensors.driver = worker_driver
    #                 self.crawler.acts.sensors.driver = worker_driver

    #                 # 执行登录任务
    #                 self.crawler.run_a_task(self.login_task, logging_in=True)

    #                 # 检查登录是否成功
    #                 if self._check_login_status(worker_driver, self.initial_url, worker_id, task_log, task_log_dir):
    #                     task_log(f"[Worker {worker_id}] ✓ 登录恢复成功（尝试{attempt}次）")
    #                     return True
    #                 else:
    #                     task_log(f"[Worker {worker_id}] ✗ 登录检查失败（尝试{attempt}次后）")

    #             finally:
    #                 # 恢复原始driver
    #                 self.crawler.driver = original_driver
    #                 self.crawler.sensors.driver = original_sensors_driver
    #                 self.crawler.acts.sensors.driver = original_acts_driver

    #         except Exception as e:
    #             task_log(f"[Worker {worker_id}] ✗ 登录尝试{attempt}失败: {e}")

    #     task_log(f"[Worker {worker_id}] ✗ 警告：{max_retries}次尝试后仍无法恢复登录")
    #     return False

    def _restore_login_status(self, worker_driver, worker_id: int, task_log, task_log_dir: Path, max_retries: int = 4) -> bool:
        """
        使用独立组件链恢复登录状态（完全线程安全）
        
        关键改进：
        1. 为每个worker创建独立的Sensors、Actuators、Bridge
        2. 创建独立的NetworkCapture和Tracer
        3. 使用不同的task_id避免路径冲突
        4. 完全不依赖共享的crawler实例
        
        Args:
            worker_driver: Worker的WebDriver实例
            worker_id: Worker编号
            task_log: 日志函数
            task_log_dir: 任务日志目录
            max_retries: 最大重试次数
        
        Returns:
            True表示登录成功，False表示失败
        """
        if not self.login_task:
            task_log(f"[Worker {worker_id}] ⚠️  无登录任务，跳过登录恢复")
            return False
        
        task_log(f"[Worker {worker_id}] 开始恢复登录状态（使用独立组件链）...")
        
        for attempt in range(1, max_retries + 1):
            try:
                task_log(f"[Worker {worker_id}] 登录尝试 {attempt}/{max_retries}...")
                
                # ========== 关键修复：创建独立的组件链 ==========
                
                # 1. 创建独立的 Sensors, Actuators
                task_log(f"[Worker {worker_id}] 创建独立的 Sensors 和 Actuators...")
                login_sensors = Sensors(worker_driver, use_improved_locator=True)
                login_actuators = Actuators(login_sensors)
                
                # 2. 创建独立的 Bridge
                task_log(f"[Worker {worker_id}] 创建独立的 Bridge...")
                login_bridge = Bridge(
                    sensors=login_sensors,
                    actuators=login_actuators,
                    client=self.client
                )
                
                # 3. 创建独立的 NetworkCapture
                task_log(f"[Worker {worker_id}] 创建独立的 NetworkCapture...")
                login_network_capture = NetworkCapture(worker_driver)
                
                # 4. 创建独立的 Tracer（关键！）
                task_log(f"[Worker {worker_id}] 创建独立的 ExecutionTracer...")
                login_tracer = ExecutionTracer(
                    store=self.crawler.store,  # store是共享的（有锁保护）
                    network_capture=login_network_capture,
                    on_new_page=lambda url: None,  # ✅ 使用空函数而不是None
                    construct_edge=lambda url: None,  # ✅ 使用空函数而不是None
                    debug=False
                )
                
                # 5. 配置 Bridge 的 Tracer
                login_bridge.set_tracer(
                    tracer=login_tracer,
                    task_queue=None,
                    store=self.crawler.store
                )
                
                # 6. 创建独立的登录任务（不同的 task_id）
                login_task_id = f"login_worker_{worker_id}_attempt_{attempt}"
                task_log(f"[Worker {worker_id}] 创建登录任务: {login_task_id}")
                login_task_copy = Task(
                    task_id=login_task_id,
                    description=self.login_task.description,
                    initial_url=self.login_task.initial_url
                )
                
                # 7. 启动 tracer
                login_tracer.start_task(login_task_id, login_task_copy.description)
                
                # 8. 导航到登录页面
                task_log(f"[Worker {worker_id}] 导航到登录页面: {login_task_copy.initial_url}")
                login_network_capture.clear_requests()
                worker_driver.get(login_task_copy.initial_url)
                time.sleep(0.6)
                
                # 9. 从缓存加载页面抽象（与 Phase 3 一致）
                page = self.crawler.store.get_page(login_task_copy.initial_url)
                if page and page.abstract_page:
                    task_log(f"[Worker {worker_id}] ✓ 从缓存加载页面抽象")
                    login_sensors.abstract_page = page.abstract_page
                    
                    # 恢复 actions_mapping
                    if page.actions_mapping:
                        login_sensors.actions_mapping.clear()
                        for action_id, locators_info in page.actions_mapping.items():
                            login_sensors.actions_mapping.set_mapping(
                                int(action_id),
                                locators_info
                            )
                        task_log(f"[Worker {worker_id}] ✓ 恢复了 {len(page.actions_mapping)} 个元素映射")
                    
                    # 恢复 event_mapping
                    if page.event_mapping:
                        login_sensors.event_mapping.clear()
                        for event_id, event_info in page.event_mapping.items():
                            login_sensors.event_mapping.mapping[int(event_id)] = event_info
                        max_event_id = max(int(k) for k in page.event_mapping.keys())
                        login_sensors.event_mapping.id_counter = max_event_id + 1
                        task_log(f"[Worker {worker_id}] ✓ 恢复了 {len(page.event_mapping)} 个事件映射")
                else:
                    task_log(f"[Worker {worker_id}] ⚠️  未找到缓存，重新扫描页面")
                    login_sensors.update_abstract_page()
                
                # 10. 执行登录任务（使用独立的 bridge）
                login_screenshot_dir = task_log_dir / f"login_attempt_{attempt}"
                login_screenshot_dir.mkdir(parents=True, exist_ok=True)
                
                task_log(f"[Worker {worker_id}] 开始执行登录任务...")
                login_bridge.run_task(
                    login_task_copy,
                    photo_dir=login_screenshot_dir,
                    logging_in=True
                )
                
                # 11. 结束 tracer 并保存
                trace = login_tracer.end_task()
                if trace:
                    self.crawler.store.save_trace(trace)
                    task_log(f"[Worker {worker_id}] ✓ 登录轨迹已保存")
                
                # 12. 检查登录是否成功
                time.sleep(1.0)
                if self._check_login_status(worker_driver, self.initial_url, worker_id, task_log, task_log_dir):
                    task_log(f"[Worker {worker_id}] ✓ 登录尝试 {attempt} 成功")
                    return True
                else:
                    task_log(f"[Worker {worker_id}] ✗ 登录检查失败（尝试{attempt}次后）")
            
            except Exception as e:
                task_log(f"[Worker {worker_id}] ✗ 登录尝试 {attempt} 失败: {e}")
                import traceback
                task_log(traceback.format_exc())
        
        task_log(f"[Worker {worker_id}] ✗ {max_retries}次尝试后仍无法恢复登录")
        return False

    # def _ensure_login_and_update_credentials(self, worker_driver, worker_id: int, task_log, task_log_dir: Path) -> bool:
    #     """
    #     🆕 核心方法：确保登录 + 更新凭证和CSRF token

    #     流程：
    #     1. 检查登录状态
    #     2. 如果未登录，尝试恢复（最多4次）
    #     3. 无论登录状态如何，都更新凭证和CSRF token（用户要求）

    #     Args:
    #         worker_driver: Worker的WebDriver实例
    #         worker_id: Worker编号
    #         task_log: 日志函数
    #         task_log_dir: 任务日志目录

    #     Returns:
    #         True表示登录有效，False表示无法恢复
    #     """
    #     task_log(f"")
    #     task_log(f"[Worker {worker_id}] ===== 登录检查 + 凭证更新 =====")

    #     # 1. 检查登录状态
    #     is_logged_in = self._check_login_status(worker_driver, self.initial_url, worker_id, task_log, task_log_dir)

    #     if not is_logged_in:
    #         # 2. 登录失效，尝试恢复
    #         task_log(f"[Worker {worker_id}] ⚠️  Session已过期，尝试恢复...")
    #         if not self._restore_login_status(worker_driver, worker_id, task_log, task_log_dir):
    #             task_log(f"[Worker {worker_id}] ✗ 无法恢复登录状态")
    #             return False
    #     else:
    #         task_log(f"[Worker {worker_id}] ✓ Session有效")

    #     # 3. 🆕 无论如何都更新凭证和CSRF token（用户要求：即使能访问initial_url也要更新）
    #     task_log(f"[Worker {worker_id}] 更新凭证和CSRF tokens...")
    #     worker_store = self.worker_stores[worker_id]
    #     worker_store.update_from_driver(worker_driver, self.account_manager)

    #     # 4. 输出更新后的信息
    #     creds = worker_store.get_credentials()
    #     csrf_tokens = worker_store.get_csrf_tokens()
    #     task_log(f"[Worker {worker_id}] ✓ 凭证已更新")
    #     task_log(f"[Worker {worker_id}]   - Cookies: {len(creds.get('cookies', []))} 个")
    #     task_log(f"[Worker {worker_id}]   - LocalStorage: {len(creds.get('localStorage', {}))} 项")
    #     task_log(f"[Worker {worker_id}]   - CSRF Tokens: {len(csrf_tokens)} 个")
    #     if csrf_tokens:
    #         task_log(f"[Worker {worker_id}]   - CSRF Token keys: {list(csrf_tokens.keys())}")
    #     task_log(f"")

    #     return True

    def _ensure_login_and_update_credentials(self, worker_driver, worker_id, task_log, task_log_dir):
        """
        核心修改：支持换车
        返回: (is_valid, current_driver)
        """
        current_driver = worker_driver

        # 1. 检查登录
        is_logged_in = self._check_login_status(current_driver, self.initial_url, worker_id, task_log, task_log_dir)

        if not is_logged_in:
            task_log(f"[Worker {worker_id}] ⚠️ 判定登录失效或浏览器异常")
            
            # ========== 🚑 换车逻辑 ==========
            try:
                task_log(f"[Worker {worker_id}] ♻️ 正在重置浏览器环境...")
                
                # 销毁旧的
                try:
                    current_driver.quit()
                except:
                    pass
                
                # 创建新的
                current_driver = self._create_new_driver()
                task_log(f"[Worker {worker_id}] ✓ 新浏览器已就绪")
                
            except Exception as e:
                task_log(f"[Worker {worker_id}] ❌ 浏览器重置失败: {e}")
                return False, current_driver

            # 2. 用新车尝试恢复登录
            if not self._restore_login_status(current_driver, worker_id, task_log, task_log_dir):
                task_log(f"[Worker {worker_id}] ✗ 新浏览器登录尝试也失败了")
                return False, current_driver
        
        # 3. 更新凭证 (从当前最新的 driver)
        worker_store = self.worker_stores[worker_id]
        worker_store.update_from_driver(current_driver, self.account_manager)

        # 4. 输出更新后的信息
        creds = worker_store.get_credentials()
        csrf_tokens = worker_store.get_csrf_tokens()
        task_log(f"[Worker {worker_id}] ✓ 凭证已更新")
        task_log(f"[Worker {worker_id}]   - Cookies: {len(creds.get('cookies', []))} 个")
        task_log(f"[Worker {worker_id}]   - LocalStorage: {len(creds.get('localStorage', {}))} 项")
        task_log(f"[Worker {worker_id}]   - CSRF Tokens: {len(csrf_tokens)} 个")
        if csrf_tokens:
            task_log(f"[Worker {worker_id}]   - CSRF Token keys: {list(csrf_tokens.keys())}")
        task_log(f"")
        
        # ✅ 返回最新的 driver 引用
        return True, current_driver

    def _generate_replay_curl_with_csrf(self, request: Dict, worker_id: int, task_log) -> str:
        """
        🆕 生成curl命令（带CSRF token注入）

        改进：
        1. 从worker_store获取凭证（不是account_manager）
        2. 检测body中是否有csrf相关参数
        3. 如果有，替换成worker_store中提取的最新token

        Args:
            request: 目标请求对象
            worker_id: Worker编号
            task_log: 日志函数
        """
        method = request.get("method", "GET")
        url = request.get("url", "")
        headers = request.get("headers", {})
        body = request.get("body")

        # 构造基础curl命令
        parts = [f"curl --compressed -X {method}"]
        parts.append(f'"{url}"')

        # 添加headers（排除Cookie和Authorization）
        for key, value in headers.items():
            if key.lower() not in ["cookie", "authorization"]:
                value_escaped = str(value).replace('\\', '\\\\').replace('"', '\\"')
                parts.append(f'-H "{key}: {value_escaped}"')

        # 🆕 从worker_store获取凭证
        worker_store = self.worker_stores[worker_id]
        credentials = worker_store.get_credentials()
        csrf_tokens = worker_store.get_csrf_tokens()

        # 🆕 处理body（CSRF token注入）
        if body and method in ["POST", "PUT", "PATCH"]:
            body_str = str(body)

            # 🆕 检测并替换CSRF token
            if csrf_tokens:
                for csrf_key, csrf_value in csrf_tokens.items():
                    # 匹配模式：key=任意值
                    # 例如：csrf_token=old_value → csrf_token=new_value
                    pattern = rf'({re.escape(csrf_key)}=)[^&"\s]+'
                    if re.search(pattern, body_str):
                        body_str = re.sub(pattern, rf'\1{csrf_value}', body_str)
                        task_log(f"[Worker {worker_id}] ✓ CSRF token已注入: {csrf_key}")

            # 转义body中的引号
            body_str_escaped = body_str.replace('"', '\\"')
            parts.append(f'-d "{body_str_escaped}"')

        # 添加Cookie
        if credentials:
            cookies = credentials.get("cookies", [])
            if cookies:
                cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
                cookie_str_escaped = cookie_str.replace('\\', '\\\\').replace('"', '\\"')
                parts.append(f'-H "Cookie: {cookie_str_escaped}"')

            # 添加Authorization
            cred_headers = credentials.get("headers", {})
            if "Authorization" in cred_headers:
                auth_value_escaped = str(cred_headers["Authorization"]).replace('\\', '\\\\').replace('"', '\\"')
                parts.append(f'-H "Authorization: {auth_value_escaped}"')
            else:
                # 从localStorage/sessionStorage提取token
                from attack_agent.request_utils import extract_auth_token
                token = extract_auth_token(credentials)
                if token:
                    token_escaped = str(token).replace('\\', '\\\\').replace('"', '\\"')
                    parts.append(f'-H "Authorization: Bearer {token_escaped}"')

        # 这行代码告诉 curl 在结束时打印 "\nHTTP_STATUS:200" 这样的标记
        parts.append('-w "\\nHTTP_STATUS:%{http_code}"')
        return " \\\n  ".join(parts)

    def _execute_replay_curl(self, command: str) -> Dict[str, Any]:
        """执行curl命令并返回结果"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30
            )

            from attack_agent.request_utils import parse_http_status_from_response
            http_status, response_body = parse_http_status_from_response(result.stdout)

            return {
                "command": command,
                "success": result.returncode == 0,
                "stdout": response_body,
                "fullout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "http_status": http_status
            }
        except subprocess.TimeoutExpired:
            return {
                "command": command,
                "success": False,
                "stdout": "",
                "stderr": "Timeout after 30 seconds",
                "returncode": -1,
                "http_status": None
            }
        except Exception as e:
            return {
                "command": command,
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "returncode": -1,
                "http_status": None
            }

    def execute_tasks_parallel(self, tasks: List, max_workers: int = None) -> List[Dict]:
        """
        🆕 并行执行攻击任务（完整重构版）

        改进：
        - 自动匹配worker数量（使用worker_drivers的数量）
        - 每个worker独立管理登录和凭证
        - 实时更新CSRF tokens
        """
        if max_workers is None:
            max_workers = len(self.worker_drivers) if self.worker_drivers else 10

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
        start_time = time.time()
        completed_count = 0

        # ========== Phase 1: 并行注入阶段 ==========
        self._log(f"[Phase 1] Parallel Attack Execution")
        self._log(f"  Submitting {len(tasks)} task(s) to thread pool...")
        self._log(f"")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_task = {
                executor.submit(self._execute_task_with_worker, task, i+1, len(tasks)): task
                for i, task in enumerate(tasks)
            }

            for future in as_completed(future_to_task):
                task = future_to_task[future]
                completed_count += 1

                try:
                    result = future.result()

                    with self._lock:
                        self.results.append({
                            "task_id": task.task_id,
                            "vuln_type": task.vuln_type,
                            "account": task.account_identifier,
                            "result": result
                        })
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
                        self._save_results()
                except Exception as e:
                    self._log(f"  [{completed_count}/{len(tasks)}] {task.task_id} - ✗ EXCEPTION: {e}")
                    with self._lock:
                        self.results.append({
                            "task_id": task.task_id,
                            "error": str(e)
                        })
                        self._save_results()

        phase1_duration = time.time() - start_time
        self._log(f"")
        self._log(f"[Phase 1 Complete] ⏱️  Time: {phase1_duration:.1f}s")
        self._log(f"")

        # ========== Phase 2: 存储型漏洞检测 ==========
        self._log(f"[Phase 2] Stored Vulnerability Detection (Hybrid Parallel)")
        self._log(f"{'~'*70}\n")

        # 1. 资源分配
        available_drivers = []
        if self.driver: 
            try: _ = self.driver.current_url; available_drivers.append((self.driver, "Main Driver"))
            except: pass
        if self.worker_drivers:
            for i, wd in enumerate(self.worker_drivers):
                try: _ = wd.current_url; available_drivers.append((wd, f"Worker {i}"))
                except: pass
        
        if available_drivers:
            patrol_info = available_drivers.pop(0)
            trigger_drivers = available_drivers
            
            self._log(f"👮 Patrol: {patrol_info[1]}")
            self._log(f"🤖 Trigger: {len(trigger_drivers)} workers")

            # 2. 准备数据
            page_queue = Queue()
            for p in list(self.crawler.store.pages.keys()):
                page_queue.put(p)
                
            try:
                with open("prompt/xss_trigger.txt", "r", encoding="utf-8") as f: prompt_tpl = f.read()
            except: prompt_tpl = "Output CLICK X commands."

            # 3. 并行执行
            with ThreadPoolExecutor(max_workers=len(trigger_drivers) + 1) as executor:
                futures = []
                futures.append(executor.submit(self._run_smart_patrol, patrol_info[0]))
                
                if trigger_drivers:
                    for i, (d, n) in enumerate(trigger_drivers):
                        futures.append(executor.submit(
                            self._run_llm_trigger_worker, i, d, page_queue, prompt_tpl
                        ))
                
                for f in as_completed(futures):
                    try: f.result()
                    except Exception as e: self._log(f"Phase 2 Error: {e}")
        else:
             self._log("❌ Phase 2 Skipped: No drivers.")

        self._log("[Phase 2] Complete.")

        # ========== Phase 3: 收网对账 ==========
        self._check_all_stored_results()
        self._save_results()

        return self.results

    def _check_all_stored_results(self):
        """
        [Final Check] 统一检查所有 OOB (Out-of-Band) 结果
        
        功能：
        遍历所有已执行的任务，提取其 Token/ID，去 Beacon 日志中查询是否触发。
        覆盖漏洞：XSS (Blind), SSRF, XXE, CMDI 等所有依赖回显的漏洞。
        """
        self._log(f"\n[Stored Vuln Detection] Checking final results from {len(self.results)} records...")
        
        from attack_agent.request_utils import check_beacon_detection
        
        updates_count = 0
        
        # 定义可能的 Token 键名列表（按优先级排序）
        # 这样无论 Agent 开发人员把 Token 命名为什么，只要在这个列表里都能被抓到
        POSSIBLE_KEYS = ["token", "random_id", "id", "uuid", "beacon_id", "payload_id"]

        for entry in self.results:
            task_id = entry.get("task_id")
            vuln_type = entry.get("vuln_type")
            task_result = entry.get("result", {})
            
            # 1. 如果已经确认为 Vulnerable，跳过 (避免重复日志)
            if task_result.get("vulnerable") is True:
                continue
            
            # 2. 动态提取 Token
            token = None
            for key in POSSIBLE_KEYS:
                val = task_result.get(key)
                if val:
                    token = val
                    break
            
            if not token:
                # 说明这个任务可能根本没生成 Token (比如是 SQL 注入)，跳过
                continue
                
            # 3. 强制转为字符串 (关键！XSS 的 random_id 是 int)
            token_str = str(token).strip()
            if not token_str:
                continue
            
            # 4. 检查 Beacon (核心检测逻辑)
            # 这一步是通用的，去查 HTTP Log 或 DNS Log
            try:
                is_triggered = check_beacon_detection(token_str)
                
                if is_triggered:
                    self._log(f"  🎉 [LATE FIND] Task {task_id} ({vuln_type}) triggered OOB Beacon! Token: {token_str}")
                    print(f"  🎉 [LATE FIND] Task {task_id} ({vuln_type}) triggered OOB Beacon! Token: {token_str}")
                    
                    # 更新状态
                    task_result["vulnerable"] = True
                    task_result["evidence"] = f"OOB Beacon Log Detected (Token: {token_str})"
                    updates_count += 1
                    continue # 已经确认了，就不需要检查下面的 xss_array 了
            except Exception as e:
                self._log(f"  ⚠️ Error checking beacon for {task_id}: {e}")

        if updates_count > 0:
            self._log(f"[Final Check] Updated {updates_count} tasks to VULNERABLE status.")
            # 只有当结果发生变化时才保存文件，减少 I/O
            self._save_results()
        else:
            self._log(f"[Final Check] No new vulnerabilities found.")

    def _wait_for_page_stable(self, driver, timeout=10, check_interval=0.5):
        """
        智能等待页面稳定：
        1. 等待 document.readyState 完成
        2. 等待 DOM 停止变化（连续两次快照一致）
        """
        # 1. 基础等待：DOM Ready
        try:
            WebDriverWait(driver, timeout).until(
                lambda d: d.execute_script("return document.readyState") == "complete"
            )
        except: pass

        # 2. 高级等待：DOM 稳定性检测
        end_time = time.time() + timeout
        last_source_len = 0
        stable_count = 0
        
        while time.time() < end_time:
            try:
                current_len = len(driver.page_source)
                if current_len == last_source_len:
                    stable_count += 1
                    if stable_count >= 2: # 连续两次没变，认为稳定
                        return
                else:
                    stable_count = 0
                    last_source_len = current_len
                
                time.sleep(check_interval)
            except:
                break

    def _execute_task_with_worker(self, task, task_num: int, total_tasks: int) -> Dict:
        """
        🆕 使用worker driver执行任务（增强版：支持坏车轮换）
        
        核心改进：
        1. 引入 Driver 轮换机制：如果当前 Driver 即使重建也无法登录，则丢弃它，换下一个 Driver。
        2. 池子自动缩减：无法修复的 Driver 不会放回队列。
        """
        worker_id = None
        worker_driver = None
        
        # 定义最大更换 Driver 的次数（防止死循环，如果所有号都封了，试3次就够了）
        max_driver_switches = 3 
        driver_acquired = False

        # ------------------------------------------------------------------
        # [Step 0] Driver 获取与健康检查循环
        # ------------------------------------------------------------------
        for switch_attempt in range(max_driver_switches):
            try:
                # 1. 从队列获取 Worker
                try:
                    worker_id, worker_driver = self.driver_queue.get()
                except Empty:
                    return {"error": "Worker driver timeout after 300 seconds"}

                # 2. 分配任务编号（仅在第一次尝试时分配，或者保留之前的）
                if switch_attempt == 0:
                    with self.task_counter_lock:
                        self.task_counter += 1
                        unique_task_id = f"TASK{self.task_counter:04d}"
                    task.task_id = unique_task_id

                # 创建日志工具
                task_log_dir = self.log_dir / "tasks" / task.task_id
                task_log_dir.mkdir(parents=True, exist_ok=True)
                task_log_file = task_log_dir / "attack.log"

                def task_log(*args):
                    msg = " ".join(str(a) for a in args)
                    try:
                        with open(task_log_file, "a", encoding="utf-8") as f:
                            f.write(msg + "\n")
                    except:
                        pass

                if switch_attempt == 0:
                    # 记录任务头部
                    task_log(f"{'='*70}")
                    task_log(f"[ATTACK TASK] {task.task_id}")
                    task_log(f"{'='*70}")
                    print(f"\n{'~'*70}")
                    print(f"[Task {task_num}/{total_tasks}] {task.task_id} - Start")

                task_log(f"[Driver Attempt {switch_attempt + 1}/{max_driver_switches}] 使用 Worker {worker_id}...")

                # 3. 🛡️ 登录检查 + 自动换车逻辑
                # is_valid: 最终是否可用
                # new_driver_ref: 可能是修复后的新 Driver
                is_valid, new_driver_ref = self._ensure_login_and_update_credentials(
                    worker_driver, worker_id, task_log, task_log_dir
                )
                
                # 🔄 更新引用
                worker_driver = new_driver_ref 

                if is_valid:
                    # ✅ 成功找到一个健康的（或已修好的）Driver
                    driver_acquired = True
                    break  # 跳出找车循环，开始干活
                else:
                    # ❌ 即使重建也无法登录（可能是密码改了，或者IP被封）
                    print(f"[Task {task.task_id}] ⚠️ Worker {worker_id} 彻底损坏（无法登录），正在丢弃...")
                    task_log(f"[Driver Error] Worker {worker_id} 无法恢复登录状态，丢弃该 Driver。")
                    
                    # 💥 核心逻辑：直接销毁坏掉的 Driver
                    try:
                        worker_driver.quit()
                    except:
                        pass
                    
                    # ⚠️ 关键：置空变量，防止 finally 块把它放回队列
                    worker_driver = None
                    worker_id = None
                    
                    # 继续循环，去 queue.get() 下一个 Driver
                    print(f"[Task {task.task_id}] 🔄 正在尝试获取池中其他可用 Driver...")
                    continue

            except Exception as e:
                task_log(f"[Driver Error] 获取或检查 Driver 时出错: {e}")
                # 同样的，如果出错，尝试清理并换下一个
                if worker_driver:
                    try:
                        worker_driver.quit()
                    except:
                        pass
                worker_driver = None
                worker_id = None
                continue

        # ------------------------------------------------------------------
        # [Step 1] 正式执行任务（只有拿到了健康的 Driver 才会到这里）
        # ------------------------------------------------------------------
        if not driver_acquired:
            print(f"[Task {task.task_id}] ❌ 任务失败：尝试了 {max_driver_switches} 个 Driver 都无法登录。")
            return {"error": "All attempted drivers failed to login (credentials changed?)"}

        try:
            # 此时 worker_driver 一定是已登录且健康的
            
            # =========================================================
            # 🔍 [DEBUG ADDITION] 打印传入的原始 Target Request 信息
            # =========================================================
            task_log(f"\n{'='*30} DEBUG: INCOMING TASK DATA {'='*30}")
            stored_response = task.target_request.get('response_body', '')
            if stored_response is None: stored_response = ""
            
            task_log(f"[Baseline Data in Memory]")
            task_log(f"  Target URL: {task.target_request.get('url')}")
            task_log(f"  Stored Status: {task.target_request.get('response_status')}")
            task_log(f"  Stored Body Type: {type(stored_response)}")
            task_log(f"  Stored Body Length: {len(str(stored_response))} bytes")
            task_log(f"  Body Preview: {stored_response}")
            task_log(f"{'='*80}\n")
            # =========================================================

            # 4. 生成 Curl 命令（仅用于日志/调试）
            task_log(f"\n[Step 1: Replay Request Generation]")
            curl_command = self._generate_replay_curl_with_csrf(task.target_request, worker_id, task_log)
            task_log(f"[Generated CURL Command]:\n{curl_command}\n")

            # 5. 执行 Curl 重放
            task_log(f"[Step 2: Replay Request Execution]")
            replay_result = self._execute_replay_curl(curl_command)
            
            http_status = replay_result.get('http_status')
            task_log(f"  Curl Success: {replay_result.get('success', False)}")
            task_log(f"  HTTP Status: {http_status}")

            # ✅✅✅ [修复点]：把下面这段打印 Body 的代码补回来
            response_body = replay_result.get('stdout', '')
            task_log(f"  Response Body: {response_body}")

            # =================================================================
            # ✅【修改核心】重放检查与请求体更新
            # =================================================================
            
            # 1. 检查重放是否失败
            # 如果 curl 执行失败，或者返回了严重的错误码（如 0 或 None），则中止任务
            if not replay_result.get('success') or not http_status:
                error_msg = f"Replay failed (Status: {http_status}). Aborting task to save tokens."
                task_log(f"  ❌ {error_msg}")
                print(f"[Task {task.task_id}] ⏭️ {error_msg}")
                return {"error": error_msg, "skipped": True}

            # 2. 检查是否是拒绝访问（可选，根据你的需求决定是否跳过 403/401）
            # 如果重放直接被 WAF 拦截 (403)，通常后续攻击也没戏，可以跳过
            if http_status in [403, 401] and task.vuln_type not in ["AUTH_BYPASS", "IDOR"]:
                error_msg = f"Target returned {http_status} (Access Denied). Aborting."
                task_log(f"  🛑 {error_msg}")
                return {"error": error_msg, "skipped": True}

            # 3. 更新 Response Body (为 LLM 提供最新鲜的页面)
            raw_body = replay_result.get('stdout', '')
            
            # 使用提取工具精简内容 (如果是 HTML)
            # 这样 LLM 不会因为 context 爆表而报错，且聚焦核心内容
            processed_body = extract_useful_response(raw_body, max_length=4000) 
            
            # 更新 task 对象
            task.target_request['response_body'] = processed_body
            task.target_request['response_status'] = http_status
            
            task_log(f"  ✓ Request context updated with fresh replay data.")
            task_log(f"  ✓ Response Body optimized for LLM ({len(processed_body)} chars).")
            # =================================================================
            
            # 6. 🚨 [CSRF Injection] 注入新 Token
            worker_store = self.worker_stores[worker_id]
            csrf_tokens = worker_store.get_csrf_tokens()
            original_body = task.target_request.get('body')
            
            if original_body and csrf_tokens and task.target_request.get('method') in ["POST", "PUT", "PATCH"]:
                try:
                    new_body = str(original_body)
                    replaced_count = 0
                    for csrf_key, csrf_value in csrf_tokens.items():
                        pattern = rf'({re.escape(csrf_key)}=)[^&"\s]*'
                        if re.search(pattern, new_body):
                            new_body = re.sub(pattern, rf'\1{csrf_value}', new_body)
                            replaced_count += 1
                            task_log(f"[Token Inject] 替换: {csrf_key} -> {csrf_value[:10]}...")
                    
                    if replaced_count > 0:
                        task.target_request['body'] = new_body
                        task_log(f"[Token Inject] ✅ Token 注入成功")
                except Exception as e:
                    task_log(f"[Token Inject] ⚠️ 注入出错: {e}")

            # 7. 创建 Agent 并执行
            task_log(f"\n[Step 3: Attack Execution]")
            credentials = worker_store.get_credentials()
            agent = self._create_agent_for_task(task.vuln_type, task_log_dir)

            if task.vuln_type in ["IDOR", "AUTH_BYPASS", "PRIVILEGE_ESCALATION", "BUSINESS_LOGIC"]:
                is_multi_account = "->" in task.account_identifier
                if is_multi_account:
                    accounts = [a.strip() for a in task.account_identifier.split("->")]
                    result = agent.test_multi_step(
                        task_description=task.task_description,
                        target_request=task.target_request,
                        accounts=accounts,
                        account_manager=self.account_manager
                    )
                else:
                    result = agent.test_single_point(
                        task_description=task.task_description,
                        target_request=task.target_request,
                        credentials=credentials
                    )
            elif task.vuln_type == "SQL_INJECTION":
                result = agent.test(
                    task_description=task.task_description,
                    target_request=task.target_request,
                    credentials=credentials
                )
            else:
                result = agent.test(task.target_request, credentials)

            return result

        # =================================================================
        # ✅【修改点】新增特定异常捕获，处理 Driver 崩溃
        # =================================================================
        except (WebDriverException, MaxRetryError, NewConnectionError) as e:
            err_msg = str(e)
            # 检测是否是连接拒绝（Driver 挂了）
            if "Connection refused" in err_msg or "Max retries exceeded" in err_msg or "invalid session" in err_msg:
                task_log(f"[CRITICAL ERROR] Driver 似乎已崩溃: {e}")
                print(f"[Task {task.task_id}] 🚨 Worker {worker_id} 的 Driver 崩溃了，正在销毁...")
                
                # 1. 尝试显式退出（虽然可能已经连不上了）
                if worker_driver:
                    try:
                        worker_driver.quit()
                    except:
                        pass
                
                # 2. 关键：将 worker_driver 置为 None
                # 这样 finally 块中的 if worker_driver is not None 判断就会失败
                # 这个坏掉的 driver 就不会被放回 driver_queue，从而实现了“剔除坏车”
                worker_driver = None
                
                return {
                    "error": "Driver crashed during execution",
                    "traceback": err_msg
                }
            else:
                # 其他常规 Selenium 错误（如找不到元素），按原样处理
                task_log(f"[Worker {worker_id}] ✗ WebDriver Error: {e}")
                return {"error": str(e)}
        # =================================================================

        except Exception as e:
            import traceback
            print(f"[Worker {worker_id}] ✗ Exception: {e}")
            print(traceback.format_exc())
            return {
                "error": str(e),
                "traceback": traceback.format_exc()
            }

        finally:
            # 8. 归还 Worker (只有 worker_driver 不为 None 时才归还)
            # 如果上面把车扔了(worker_driver=None)，这里就不会执行 put，池子长度自然 -1
            if worker_id is not None and worker_driver is not None:
                try:
                    # 🚑 简单的健康检查
                    _ = worker_driver.current_url
                    self.driver_queue.put((worker_id, worker_driver))
                except Exception as e:
                    print(f"[Worker {worker_id}] ⚠️ 归还时发现 Driver 异常 ({e})，直接丢弃。")
                    try:
                        worker_driver.quit()
                    except:
                        pass

    def _save_results(self):
        """保存执行结果"""
        output_file = self.log_dir / "attack_results.json"
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self._log(f"[Error] Failed to save results: {e}")

    # def _run_smart_patrol(self, driver):
    #     """
    #     全量智能巡检 (Smart Patrol) - 增强记录版
    #     """
    #     worker_name = "Smart Patrol"
        
    #     # 1. 📂 准备目录
    #     patrol_dir = self.log_dir / "phase2_smart_patrol"
    #     patrol_dir.mkdir(parents=True, exist_ok=True)
        
    #     # 独立日志文件
    #     patrol_log_file = patrol_dir / "patrol_summary.log"
        
    #     def p_log(msg):
    #         timestamp = time.strftime("[%H:%M:%S]")
    #         full_msg = f"{timestamp} {msg}"
    #         self._log(f"[{worker_name}] {msg}") # 输出到主日志
    #         try:
    #             with open(patrol_log_file, "a", encoding="utf-8") as f:
    #                 f.write(full_msg + "\n")
    #         except: pass

    #     p_log(f"🚀 Started with driver: {driver.title}")

    #     try:
    #         # A. 初始队列
    #         known_urls = set(list(self.crawler.store.pages.keys()))
    #         scan_queue = list(known_urls)
    #         visited_in_patrol = set()
            
    #         p_log(f"Base Queue: {len(scan_queue)} known pages")
            
    #         scan_start = time.time()
    #         new_links_found = 0
            
    #         # 黑名单
    #         DANGEROUS_KEYWORDS = [
    #             "logout", "signout", "logoff", "sign_out", "log_out", "exit", "quit",
    #             "delete", "remove", "destroy", "erase", "purge", "trash", "drop", 
    #             "reset", "clear", "disable", "deactivate", "ban", "block", "suspend",
    #             "password", "passwd", "pwd", "unsubscribe", "cancel", "abort"
    #         ]

    #         # B. 循环直到队列为空
    #         while scan_queue:
    #             url = scan_queue.pop(0)
                
    #             if url in visited_in_patrol:
    #                 continue
                
    #             url_lower = url.lower()
    #             if any(keyword in url_lower for keyword in DANGEROUS_KEYWORDS):
    #                 p_log(f"Skipping dangerous URL: {url}")
    #                 continue
    #             if "action=" in url_lower and any(act in url_lower for act in ["del", "rm", "out"]):
    #                 continue
                
    #             try:
    #                 # 访问页面
    #                 driver.get(url)
    #                 visited_in_patrol.add(url)
                    
    #                 # ✅ 使用智能等待替代死板 sleep
    #                 self._wait_for_page_stable(driver)
                    
    #                 # 📸 [新增] 访问后截图
    #                 safe_name = self._url_to_filename(url)
    #                 try:
    #                     driver.save_screenshot(str(patrol_dir / f"visit_{safe_name}.png"))
    #                 except: pass

    #                 # C. 简单提取新链接 (只提取 a 标签)
    #                 try:
    #                     elements = driver.find_elements("tag name", "a")
                        
    #                     for elem in elements:
    #                         try:
    #                             href = elem.get_attribute("href")
                                
    #                             # 检查链接有效性及是否在目标域内
    #                             if href and self.target_domain in href:
    #                                 # 简单的去锚点处理 (保留 /#/ 路由，去除普通锚点)
    #                                 clean_href = href.split('#')[0] if '#' in href and not '/#/' in href else href
                                    
    #                                 # 如果是新链接，加入队列
    #                                 if clean_href.startswith(('http', 'https')) and clean_href not in known_urls:
    #                                     known_urls.add(clean_href)
    #                                     scan_queue.append(clean_href)
    #                                     new_links_found += 1
    #                                     p_log(f"[+] New URL: {clean_href}")
    #                         except:
    #                             # 忽略单个元素的 StaleElementReferenceException 等错误
    #                             pass
    #                 except Exception as e:
    #                     # 🚑【关键修改】这里必须检查 Driver 是否已死
    #                     err_msg = str(e)
    #                     if "Connection refused" in err_msg or "invalid session" in err_msg or "Max retries exceeded" in err_msg:
    #                         p_log(f"🔥 CRITICAL: Driver died during link extraction at {url}.")
    #                         p_log(f"🛑 Abandoning Smart Patrol immediately.")
    #                         return # <--- 直接退出，不再继续死循环
    #                     else:
    #                         p_log(f"Link extraction error: {e}")

    #             except Exception as e:
    #                 # ✅ 2. 捕获 driver.get() 抛出的 UnexpectedAlertPresentException
    #                 if "unexpected alert open" in str(e) or isinstance(e, UnexpectedAlertPresentException):
    #                     try:
    #                         alert = driver.switch_to.alert
    #                         p_log(f"🔥 UNEXPECTED ALERT at {url}: {alert.text}")
    #                         alert.accept()
    #                     except: pass
    #                 # 2. 处理 Driver 死亡错误
    #                 elif "Connection refused" in err_msg or "invalid session" in err_msg or "Max retries exceeded" in err_msg:
    #                     p_log(f"🔥 CRITICAL: Driver died visiting {url}.")
    #                     p_log(f"🛑 Abandoning Smart Patrol immediately.")
                        
    #                     try: driver.quit()
    #                     except: pass
                        
    #                     return # <--- 直接退出
    #                 else:
    #                     p_log(f"⚠️ Error visiting {url}: {e}")

    #         p_log(f"✓ Scan complete. Visited {len(visited_in_patrol)} pages. Found {new_links_found} new URLs.")

    #     except Exception as e:
    #         p_log(f"❌ Fatal error: {e}")

    def _run_smart_patrol(self, driver):
        """
        全量智能巡检 (Smart Patrol) - 修复版 (包含弃车逻辑)
        """
        worker_name = "Smart Patrol"
        
        patrol_dir = self.log_dir / "phase2_smart_patrol"
        patrol_dir.mkdir(parents=True, exist_ok=True)
        patrol_log_file = patrol_dir / "patrol_summary.log"
        
        def p_log(msg):
            timestamp = time.strftime("[%H:%M:%S]")
            full_msg = f"{timestamp} {msg}"
            self._log(f"[{worker_name}] {msg}")
            try:
                with open(patrol_log_file, "a", encoding="utf-8") as f:
                    f.write(full_msg + "\n")
            except: pass

        p_log(f"🚀 Started with driver: {driver.title}")

        try:
            known_urls = set(list(self.crawler.store.pages.keys()))
            scan_queue = list(known_urls)
            visited_in_patrol = set()
            
            p_log(f"Base Queue: {len(scan_queue)} known pages")
            
            new_links_found = 0
            
            DANGEROUS_KEYWORDS = [
                "logout", "signout", "logoff", "sign_out", "log_out", "exit", "quit",
                "delete", "remove", "destroy", "erase", "purge", "trash", "drop", 
                "reset", "clear", "disable", "deactivate", "ban", "block", "suspend",
                "password", "passwd", "pwd", "unsubscribe", "cancel", "abort"
            ]

            while scan_queue:
                url = scan_queue.pop(0)
                
                if url in visited_in_patrol: continue
                
                url_lower = url.lower()
                if any(keyword in url_lower for keyword in DANGEROUS_KEYWORDS):
                    p_log(f"Skipping dangerous URL: {url}")
                    continue
                if "action=" in url_lower and any(act in url_lower for act in ["del", "rm", "out"]):
                    continue
                
                try:
                    # 1. 访问页面
                    driver.get(url)
                    visited_in_patrol.add(url)
                    self._wait_for_page_stable(driver)
                    
                    safe_name = self._url_to_filename(url)
                    try: driver.save_screenshot(str(patrol_dir / f"visit_{safe_name}.png"))
                    except: pass

                    # 2. 提取链接
                    elements = driver.find_elements("tag name", "a")
                    for elem in elements:
                        try:
                            href = elem.get_attribute("href")
                            if href and self.target_domain in href:
                                clean_href = href.split('#')[0] if '#' in href and not '/#/' in href else href
                                if clean_href.startswith(('http', 'https')) and clean_href not in known_urls:
                                    known_urls.add(clean_href)
                                    scan_queue.append(clean_href)
                                    new_links_found += 1
                                    p_log(f"[+] New URL: {clean_href}")
                        except: pass 

                except Exception as e:
                    err_msg = str(e)
                    # =========================================================
                    # 🛡️【修复】检测 Driver 是否暴毙，如果是，直接放弃治疗
                    # =========================================================
                    if "Connection refused" in err_msg or "invalid session" in err_msg or "Max retries exceeded" in err_msg:
                        p_log(f"🔥 CRITICAL: Driver died at {url}. Abandoning Smart Patrol.")
                        p_log(f"❌ Error details: {err_msg}")
                        try: driver.quit()
                        except: pass
                        return # <--- 直接退出，不再继续死循环
                    # =========================================================
                    
                    elif "unexpected alert open" in err_msg or isinstance(e, UnexpectedAlertPresentException):
                        try:
                            alert = driver.switch_to.alert
                            p_log(f"🔥 UNEXPECTED ALERT at {url}: {alert.text}")
                            alert.accept()
                        except: pass
                    else:
                        p_log(f"⚠️ Error visiting {url}: {e}")

            p_log(f"✓ Scan complete. Visited {len(visited_in_patrol)} pages. Found {new_links_found} new URLs.")

        except Exception as e:
            p_log(f"❌ Fatal error: {e}")

    # def _run_llm_trigger_worker(self, worker_id, driver, shared_queue, prompt_template):
    #     """
    #     LLM 智能触发 Worker - 增强记录版 + 智能等待
    #     """
    #     # 1. 📂 准备根目录
    #     trigger_root = self.log_dir / "phase2_llm_trigger"
    #     trigger_root.mkdir(parents=True, exist_ok=True)
        
    #     self._log(f"[LLM-Trigger-{worker_id}] 🚀 Started. Ready to consume pages.")
        
    #     # 创建独立的组件链
    #     sensors = Sensors(driver, use_improved_locator=True)
    #     actuators = Actuators(sensors)
    #     bridge = Bridge(sensors, actuators, self.client)
        
    #     processed_count = 0
        
    #     while True:
    #         try:
    #             url = shared_queue.get_nowait()
    #         except Empty:
    #             self._log(f"[LLM-Trigger-{worker_id}] No more pages. Finished.")
    #             break

    #         processed_count += 1
    #         if any(x in url.lower() for x in ["logout", "signout", "logoff", "delete"]):
    #             shared_queue.task_done()
    #             continue

    #         # 📂 准备页面目录
    #         page_safe_name = self._url_to_filename(url)
    #         page_dir = trigger_root / f"{processed_count:03d}_{page_safe_name}"
    #         page_dir.mkdir(parents=True, exist_ok=True)
            
    #         page_log_file = page_dir / "trigger.log"
    #         def w_log(msg):
    #             self._log(f"[LLM-Trigger-{worker_id}] {msg}")
    #             try:
    #                 with open(page_log_file, "a", encoding="utf-8") as f:
    #                     f.write(f"{time.strftime('[%H:%M:%S]')} {msg}\n")
    #             except: pass

    #         try:
    #             w_log(f"Processing: {url}")
    #             driver.get(url)
                
    #             # ✅ 智能等待 + 截图
    #             self._wait_for_page_stable(driver)
    #             driver.save_screenshot(str(page_dir / "00_initial.png"))

    #             sensors.update_abstract_page()
    #             full_abstract = sensors.get_abstract_page()
                
    #             # B. 过滤
    #             filtered_lines = []
    #             for line in full_abstract.splitlines():
    #                 if "<a " in line or line.strip().startswith("<a"): continue
    #                 filtered_lines.append(line)
                
    #             filtered_abstract = "\n".join(filtered_lines)
    #             if not filtered_abstract.strip():
    #                 w_log("Skipping: No interactive elements found.")
    #                 # shared_queue.task_done()
    #                 continue

    #             # C. 请求 LLM (使用配置)
    #             prompt = prompt_template.format(page_description=filtered_abstract)
    #             with open(page_dir / "llm_prompt.txt", "w", encoding="utf-8") as f: f.write(prompt)

    #             try:
    #                 response = self.client.chat.completions.create(
    #                     model=get_model_name("bridge"),
    #                     messages=[{"role": "system", "content": prompt}],
    #                     temperature=get_temperature("bridge")
    #                 ).choices[0].message.content
    #             except Exception as e:
    #                 w_log(f"LLM Error: {e}")
    #                 # shared_queue.task_done()
    #                 continue

    #             with open(page_dir / "llm_response.txt", "w", encoding="utf-8") as f: f.write(response)

    #             commands = [line.strip() for line in response.splitlines() if line.strip()]
    #             if commands: w_log(f"Executing {len(commands)} commands...")

    #             for idx, cmd in enumerate(commands):
    #                 kind, action_id, value, raw_cmd = bridge._parse_command(cmd)
    #                 if not kind or not action_id: continue

    #                 try:
    #                     # 智能归位
    #                     driver.get(url)
    #                     self._wait_for_page_stable(driver) # ✅ 智能等待
                        
    #                     # sensors.update_abstract_page()
                        
    #                     success = False
    #                     if kind == "CLICK": success = actuators.execute_action_by_id(action_id)
    #                     elif kind == "TRIGGER": success = bridge.execute_task_step(None, action_id, force_event=True)
                        
    #                     if success:
    #                         w_log(f"✓ {cmd}")
    #                         time.sleep(0.5) # 给Payload一点时间
    #                         driver.save_screenshot(str(page_dir / f"step_{idx+1:02d}_{kind}_{action_id}.png"))

    #                         try:
    #                             alert = driver.switch_to.alert
    #                             w_log(f"🔥 ALERT: {alert.text}")
    #                             alert.accept()
    #                             driver.save_screenshot(str(page_dir / "EVIDENCE_ALERT.png"))
    #                         except: pass
    #                     else:
    #                         w_log(f"✗ Failed: {cmd}")

    #                 except Exception as e:
    #                     # ✅✅✅ 关键修复：在这里捕获因操作触发的阻塞性弹窗
    #                     if "unexpected alert open" in str(e) or isinstance(e, UnexpectedAlertPresentException):
    #                         try:
    #                             alert = driver.switch_to.alert
    #                             w_log(f"🔥 UNEXPECTED ALERT CAUGHT: {alert.text}")
    #                             alert.accept() # 👈 必须接受，否则浏览器卡死
    #                             w_log("✓ Alert accepted (recovered)")
    #                         except:
    #                             w_log(f"⚠ Could not handle alert: {e}")
    #                     else:
    #                         w_log(f"Cmd Error: {e}")

    #                     # 记录原始错误
    #                     w_log(f"Cmd Error: {e}")
                        
    #         except Exception as e:
    #             w_log(f"Page Error: {e}")
    #         finally:
    #             shared_queue.task_done()

    def _run_llm_trigger_worker(self, worker_id, driver, shared_queue, prompt_template):
        """
        LLM 智能触发 Worker - 修复版 (防止队列卡死)
        """
        # 1. 📂 准备根目录
        trigger_root = self.log_dir / "phase2_llm_trigger"
        trigger_root.mkdir(parents=True, exist_ok=True)
        
        self._log(f"[LLM-Trigger-{worker_id}] 🚀 Started. Ready to consume pages.")
        
        # 创建独立的组件链
        sensors = Sensors(driver, use_improved_locator=True)
        actuators = Actuators(sensors)
        bridge = Bridge(sensors, actuators, self.client)
        
        processed_count = 0
        
        while True:
            try:
                url = shared_queue.get_nowait()
            except Empty:
                self._log(f"[LLM-Trigger-{worker_id}] No more pages. Finished.")
                break

            # 🛡️ 核心修复：整个处理逻辑包裹在 try...finally 中，确保 task_done 必执行
            try:
                processed_count += 1
                if any(x in url.lower() for x in ["logout", "signout", "logoff", "delete"]):
                    continue

                # 📂 准备页面目录
                page_safe_name = self._url_to_filename(url)
                page_dir = trigger_root / f"{processed_count:03d}_{page_safe_name}"
                page_dir.mkdir(parents=True, exist_ok=True)
                
                page_log_file = page_dir / "trigger.log"
                def w_log(msg):
                    self._log(f"[LLM-Trigger-{worker_id}] {msg}")
                    try:
                        with open(page_log_file, "a", encoding="utf-8") as f:
                            f.write(f"{time.strftime('[%H:%M:%S]')} {msg}\n")
                    except: pass

                w_log(f"Processing: {url}")
                
                # 1. 访问页面 (带异常捕获)
                try:
                    driver.get(url)
                    self._wait_for_page_stable(driver)
                    driver.save_screenshot(str(page_dir / "00_initial.png"))
                    
                    sensors.update_abstract_page()
                    full_abstract = sensors.get_abstract_page()
                except Exception as e:
                    w_log(f"Page Load Error: {e}")
                    continue # 跳过本页

                # B. 过滤
                filtered_lines = []
                for line in full_abstract.splitlines():
                    if "<a " in line or line.strip().startswith("<a"): continue
                    filtered_lines.append(line)
                
                filtered_abstract = "\n".join(filtered_lines)
                if not filtered_abstract.strip():
                    w_log("Skipping: No interactive elements found.")
                    continue 

                # C. 请求 LLM
                prompt = prompt_template.format(page_description=filtered_abstract)
                with open(page_dir / "llm_prompt.txt", "w", encoding="utf-8") as f: f.write(prompt)

                try:
                    response = self.client.chat.completions.create(
                        model=get_model_name("bridge"),
                        messages=[{"role": "system", "content": prompt}],
                        temperature=get_temperature("bridge")
                    ).choices[0].message.content
                except Exception as e:
                    w_log(f"LLM Error: {e}")
                    continue

                with open(page_dir / "llm_response.txt", "w", encoding="utf-8") as f: f.write(response)

                commands = [line.strip() for line in response.splitlines() if line.strip()]
                if commands: w_log(f"Executing {len(commands)} commands...")

                for idx, cmd in enumerate(commands):
                    kind, action_id, value, raw_cmd = bridge._parse_command(cmd)
                    if not kind or not action_id: continue

                    try:
                        # 智能归位
                        driver.get(url)
                        self._wait_for_page_stable(driver) 
                        
                        success = False
                        if kind == "CLICK": success = actuators.execute_action_by_id(action_id)
                        elif kind == "TRIGGER": success = bridge.execute_task_step(None, action_id, force_event=True)
                        
                        if success:
                            w_log(f"✓ {cmd}")
                            time.sleep(0.5) 
                            driver.save_screenshot(str(page_dir / f"step_{idx+1:02d}_{kind}_{action_id}.png"))
                            
                            # 尝试处理弹窗
                            try:
                                alert = driver.switch_to.alert
                                w_log(f"🔥 ALERT: {alert.text}")
                                alert.accept()
                                driver.save_screenshot(str(page_dir / "EVIDENCE_ALERT.png"))
                            except: pass
                        else:
                            w_log(f"✗ Failed: {cmd}")

                    except Exception as e:
                        # 处理弹窗阻塞
                        if "unexpected alert open" in str(e) or isinstance(e, UnexpectedAlertPresentException):
                            try:
                                alert = driver.switch_to.alert
                                w_log(f"🔥 UNEXPECTED ALERT CAUGHT: {alert.text}")
                                alert.accept() 
                                w_log("✓ Alert accepted (recovered)")
                            except:
                                w_log(f"⚠ Could not handle alert: {e}")
                        else:
                            w_log(f"Cmd Error: {e}")
                            
            except Exception as e:
                # 捕获循环内的其他未知错误，防止 worker 退出
                self._log(f"[LLM-Trigger-{worker_id}] Critical Worker Error: {e}")
            
            finally:
                # ✅ 这里的 finally 确保了无论上面的 if/continue/except 怎么走，
                # 这个任务最终都会被标记为完成，防止队列阻塞。
                shared_queue.task_done()

    def execute_tasks_from_queue(self, task_queue, max_workers: int = None) -> List[Dict]:
        """
        🆕 从队列消费任务并执行（使用worker driver机制）

        用于流水线模式：Phase 4持续生成任务 → Phase 5从队列消费执行

        Args:
            task_queue: queue.Queue对象，任务来源
            max_workers: 最大并发数（默认使用worker_drivers数量）

        Returns:
            执行结果列表
        """
        if max_workers is None:
            max_workers = len(self.worker_drivers) if self.worker_drivers else 10

        self._log(f"\n{'='*70}")
        self._log(f"[AttackExecutor - QUEUE MODE] Starting Execution")
        self._log(f"{'='*70}")
        self._log(f"[AttackExecutor] Max Workers: {max_workers}")
        self._log(f"[AttackExecutor] Worker Drivers: {len(self.worker_drivers)}")
        self._log(f"[AttackExecutor] Waiting for tasks from queue...")
        self._log(f"")

        self.results.clear()
        tasks_received = []
        completed_count = 0
        start_time = time.time()

        # ========== Phase 1: 并行执行所有任务 ==========
        self._log(f"[Phase 1] Parallel Attack Execution from Queue")
        self._log(f"  Submitting tasks to thread pool as they arrive...")
        self._log(f"")

        executor = ThreadPoolExecutor(max_workers=max_workers)
        try:
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
                self._log(f"[Queue] Task received: {task.task_id} (total: {len(tasks_received)})")

                # 🆕 使用新的worker执行方法
                future = executor.submit(
                    self._execute_task_with_worker,
                    task,
                    len(tasks_received),
                    "?"  # 总数未知（队列模式）
                )
                futures.append((future, task))

                # 定期检查已完成的任务
                if len(futures) >= max_workers * 2:
                    self._log(f"[Queue] Checking {len(futures)} pending futures...")
                    completed_futures = []

                    for future, task_obj in futures:
                        if future.done():
                            try:
                                result = future.result()

                                with self._lock:
                                    self.results.append({
                                        "task_id": task_obj.task_id,
                                        "vuln_type": task_obj.vuln_type,
                                        "account": task_obj.account_identifier,
                                        "result": result
                                    })
                                    self._save_results()

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

                                with self._lock:
                                    self.results.append({
                                        "task_id": task_obj.task_id,
                                        "error": str(e)
                                    })
                                    self._save_results()

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
                    result = future.result()

                    with self._lock:
                        self.results.append({
                            "task_id": task_obj.task_id,
                            "vuln_type": task_obj.vuln_type,
                            "account": task_obj.account_identifier,
                            "result": result
                        })
                        self._save_results()

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

                    with self._lock:
                        self.results.append({
                            "task_id": task_obj.task_id,
                            "error": "Task timeout after 600 seconds"
                        })
                        self._save_results()

                    completed_count += 1

                except Exception as e:
                    self._log(f"  [{completed_count}/?] {task_obj.task_id} - ✗ EXCEPTION: {e}")

                    with self._lock:
                        self.results.append({
                            "task_id": task_obj.task_id,
                            "error": str(e)
                        })
                        self._save_results()

                    completed_count += 1
        # ============ 关键修改2：添加finally块 ============
        finally:
            # 强制关闭线程池，不等待僵尸线程
            self._log(f"\n[Cleanup] Shutting down executor (wait=False)...")
            executor.shutdown(wait=False)
            self._log(f"[Cleanup] Executor shutdown complete")

        phase1_duration = time.time() - start_time
        self._log(f"")
        self._log(f"[Phase 1 Complete] ⏱️  Time: {phase1_duration:.1f}s")
        self._log(f"")

        # # ========== Phase 2: 存储型漏洞检测 (全量覆盖版) ==========
        # self._log(f"[Phase 2] Stored Vulnerability Detection (Full Coverage)")

        # # 1. 选车逻辑 (保持不变，因为这是必须的)
        # patrol_driver = None
        # candidates = []
        # if self.driver: candidates.append((self.driver, "Main Driver"))
        # if self.worker_drivers:
        #     for i, wd in enumerate(reversed(self.worker_drivers)):
        #         candidates.append((wd, f"Worker Driver {len(self.worker_drivers)-i-1}"))

        # for drv, name in candidates:
        #     try:
        #         # 简单的存活检查
        #         try: 
        #             _ = drv.current_url
        #         except: 
        #             continue
                
        #         # 登录检查
        #         if self._check_login_status(drv, self.initial_url, -1, self._log, self.log_dir):
        #             patrol_driver = drv
        #             self._log(f"  ✅ Selected [{name}] for patrol.")
        #             break
        #     except:
        #         pass

        # # 2. 执行全量巡检
        # if patrol_driver:
        #     try:
        #         self._log(f"  🚀 Starting FULL coverage scan...")
                
        #         # A. 初始队列：所有已知页面
        #         known_urls = set(list(self.crawler.store.pages.keys()))
        #         scan_queue = list(known_urls)
        #         visited_in_patrol = set()
                
        #         # ⚠️ 移除“枢纽”排序，按你的要求，朴实无华地遍历
        #         # 但为了逻辑正确，队列仍然是先进先出的
                
        #         self._log(f"     Base Queue: {len(scan_queue)} known pages")
                
        #         scan_start = time.time()
        #         new_links_found = 0
                
        #         # B. 循环直到队列为空 (不做数量限制)
        #         while scan_queue:
        #             url = scan_queue.pop(0)
                    
        #             # 基础去重 (防止死循环 A->B->A)
        #             if url in visited_in_patrol:
        #                 continue
                        
        #             # 黑名单过滤 (防止登出)
        #             if any(x in url.lower() for x in ["logout", "signout", "logoff", "exit", "quit"]):
        #                 continue
                    
        #             try:
        #                 # 访问页面
        #                 patrol_driver.get(url)
        #                 visited_in_patrol.add(url)
                        
        #                 # 让子弹飞一会儿 (给 Payload 执行时间)
        #                 time.sleep(1.0) 
                        
        #                 # (可选) 检查 Alert
        #                 try:
        #                     alert = patrol_driver.switch_to.alert
        #                     alert.accept()
        #                 except:
        #                     pass

        #                 # C. 动态提取新链接 (核心逻辑)
        #                 # 只要是同域名的、没见过的链接，全部加进去跑！
        #                 try:
        #                     elements = patrol_driver.find_elements("tag name", "a")
        #                     for elem in elements:
        #                         href = elem.get_attribute("href")
        #                         if href and self.target_domain in href:
        #                             # 简单的去锚点处理
        #                             clean_href = href.split('#')[0] if '#' in href and not '/#/' in href else href
                                    
        #                             # 如果是新链接，且不在待爬队列中
        #                             if clean_href not in known_urls:
        #                                 known_urls.add(clean_href)
        #                                 scan_queue.append(clean_href) # 加入队尾，等待被访问
        #                                 new_links_found += 1
        #                                 self._log(f"     [+] Discovered new URL: {clean_href}")
        #                 except:
        #                     pass 

        #             except Exception as e:
        #                 self._log(f"     ⚠️ Error patrolling {url}: {e}")

        #         scan_duration = time.time() - scan_start
        #         self._log(f"  ✓ Full scan complete.")
        #         self._log(f"     Total Visited: {len(visited_in_patrol)} pages")
        #         self._log(f"     New URLs Found & Visited: {new_links_found}")
        #         self._log(f"     Time: {scan_duration:.1f}s")

        #     except Exception as e:
        #         self._log(f"  ❌ Error during patrol: {e}")
        # else:
        #     self._log(f"  ❌ Phase 2 Skipped: No healthy driver found.")
        
        # self._log(f"")

        # ========== Phase 2: 存储型漏洞检测 (并行混合模式) ==========
        # ========== Phase 2: 存储型漏洞检测 (Smart Patrol + LLM Trigger) ==========
        self._log(f"[Phase 2] Stored Vulnerability Detection (Hybrid Parallel)")

        # 1. 资源盘点 (收集所有活着的 Driver)
        available_drivers = [] 
        if self.driver:
            try: 
                _ = self.driver.current_url
                # 检查登录
                if self._check_login_status(self.driver, self.initial_url, -1, self._log, self.log_dir):
                    available_drivers.append((self.driver, "Main Driver"))
            except: pass
            
        if self.worker_drivers:
            for i, wd in enumerate(self.worker_drivers):
                try:
                    _ = wd.current_url
                    if self._check_login_status(wd, self.initial_url, i, self._log, self.log_dir):
                        available_drivers.append((wd, f"Worker {i}"))
                except: pass

        if not available_drivers:
            self._log("❌ No healthy drivers available for Phase 2. Skipping.")
            self._save_results()
            return self.results

        # 2. 角色分配
        # 拿出第一个给 Patrol
        patrol_info = available_drivers.pop(0)
        patrol_driver = patrol_info[0]
        
        # 剩下的给 Trigger
        trigger_drivers = available_drivers
        
        self._log(f"👮 Assigned [{patrol_info[1]}] to Smart Patrol")
        self._log(f"🤖 Assigned {len(trigger_drivers)} drivers to LLM Trigger")

        # ... (前文代码：资源盘点、角色分配部分保持不变) ...

        # 3. 准备数据
        all_known_pages = list(self.crawler.store.pages.keys())
        
        # ✅ 改动：创建一个共享队列并填充数据
        page_queue = Queue()
        for p in all_known_pages:
            page_queue.put(p)

        self._log(f"📚 Shared Page Queue: {page_queue.qsize()} pages ready for analysis")

        # 加载 Prompt
        try:
            with open("prompt/xss_trigger.txt", "r", encoding="utf-8") as f:
                trigger_prompt = f.read()
        except:
            trigger_prompt = "You are a web tester. Output CLICK X commands."

        # 4. 并行执行
        with ThreadPoolExecutor(max_workers=len(trigger_drivers) + 1) as executor:
            futures = []
            
            # A. 启动巡检 (Smart Patrol) - 这是一个单独的任务，不消费队列
            futures.append(executor.submit(self._run_smart_patrol, patrol_driver))
            
            # B. 启动 LLM Trigger (所有剩下的 Drivers 作为消费者)
            if trigger_drivers:
                for i, (drv, name) in enumerate(trigger_drivers):
                    # ✅ 改动：传入 page_queue 而不是 page_chunk
                    futures.append(executor.submit(
                        self._run_llm_trigger_worker, 
                        i, 
                        drv, 
                        page_queue, 
                        trigger_prompt
                    ))
            else:
                 self._log("⚠️ No drivers available for LLM Triggering.")

            # 等待结束
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self._log(f"Phase 2 Thread Error: {e}")

        self._log("[Phase 2] Complete.")

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

    # 保留原有的其他方法（存储型漏洞检测等）
    def _get_pending_tasks(self) -> Dict[str, int]:
        """获取所有pending任务"""
        pending = {}
        for result in self.results:
            if result.get("result", {}).get("vulnerable") is None:
                vuln_type = result.get("vuln_type")
                pending[vuln_type] = pending.get(vuln_type, 0) + 1
        return pending
