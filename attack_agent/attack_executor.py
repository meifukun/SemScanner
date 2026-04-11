"""
AttackExecutor - （worker drivers +  + CSRF）

：
1. worker driver（Phase 3drivers）
2. worker（WorkerCredentialStore）
3. ： + CSRF token
4. CSRF tokencurl
5. （4）
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
from attack_agent.worker_credential_store import WorkerCredentialStore
from config.llm_config import get_model_name, get_temperature
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import UnexpectedAlertPresentException, NoAlertPresentException
from urllib3.exceptions import MaxRetryError, NewConnectionError
from selenium.common.exceptions import WebDriverException
from attack_agent.request_utils import extract_useful_response
from utils.token_tracker import tracker

_VULN_CATEGORY_MAP = {
    "SQL_INJECTION":        "attack_sqli",
    "XSS":                  "attack_xss",
    "SSTI":                 "attack_ssti",
    "SSRF":                 "attack_ssrf",
    "CMDI":                 "attack_cmdi",
    "COMMAND_INJECTION":    "attack_cmdi",
    "PT":                   "attack_path_traversal",
    "PATH_TRAVERSAL":       "attack_path_traversal",
    "XXE":                  "attack_xxe",
    "IDOR":                 "attack_business",
    "AUTH_BYPASS":          "attack_business",
    "PRIVILEGE_ESCALATION": "attack_business",
    "BUSINESS_LOGIC":       "attack_business",
}

class AttackExecutor:
    """
     -

    ：
    - driver instances
    - workersession
    - CSRF tokens
    -
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
        """ AttackExecutor"""
        self.account_manager = account_manager
        self.crawler = crawler
        self.client = client
        self.driver = driver
        self.beacon_base = beacon_base
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.worker_drivers = worker_drivers or []
        self.chrome_options = chrome_options
        self.initial_url = initial_url
        self.login_task = login_task

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

        self.screenshot_dir = self.log_dir / "stored_vuln_screenshots"
        self.screenshot_dir.mkdir(parents=True, exist_ok=True)

        self.task_counter = 0
        self.task_counter_lock = threading.Lock()

        self._lock = threading.Lock()
        self._log_lock = threading.Lock()

        self.target_domain = target_domain

    def _create_new_driver(self):
        """🆕 ： Driver """
        self._log("[DriverFactory] ...")
        
        options = self.chrome_options
        if not options:
            options = webdriver.ChromeOptions()
            options.add_argument("--headless")
            options.add_argument("--disable-web-security")
            options.add_argument("--allow-running-insecure-content")
            options.add_argument("--disable-xss-auditor")

        service = Service(ChromeDriverManager().install())
        new_driver = webdriver.Chrome(service=service, options=options)
        
        new_driver.set_page_load_timeout(60)
        new_driver.set_script_timeout(60)
        new_driver.set_window_size(1920, 1080)

        if self.target_domain:
            def interceptor(request):
                if self.target_domain not in request.url:
                    request.abort()
            new_driver.request_interceptor = interceptor

        try:
            def send(driver, cmd, params={}):
                return driver.execute_cdp_cmd(cmd, params)

            js_files = ["xss_xhr.js", "md5.js", "lib.js", "addeventlistener_wrapper.js"]
            
            for js_file in js_files:
                file_path = f"js/{js_file}"
                try:
                    with open(file_path, "r", encoding='utf-8') as f:
                        source_code = f.read()
                        send(new_driver, "Page.addScriptToEvaluateOnNewDocument", {"source": source_code})
                except FileNotFoundError:
                    self._log(f"[DriverFactory] ⚠️ ： {file_path}，")

            self._log("[DriverFactory] ")
            
        except Exception as e:
            self._log(f"[DriverFactory] ❌ : {e}")
            try:
                new_driver.quit()
            except:
                pass
            raise e

        return new_driver
    
    def _log(self, *args):
        """"""
        msg = " ".join(str(a) for a in args)
        try:
            with self._log_lock:
                with open(self._log_path, "a", encoding="utf-8") as f:
                    f.write(msg + "\n")
                print(msg)
        except Exception:
            pass

    def _url_to_filename(self, url: str) -> str:
        """URL"""
        filename = re.sub(r'^https?://', '', url)
        filename = re.sub(r'[^\w\-.]', '_', filename)
        filename = re.sub(r'_+', '_', filename)
        filename = filename.strip('_')

        if len(filename) > 200:
            url_hash = hashlib.md5(url.encode('utf-8')).hexdigest()[:8]
            filename = f"{filename[:50]}_{url_hash}"

        return filename

    def _create_agent_for_task(self, vuln_type: str, task_log_dir: Path):
        """agent"""
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
        （URL）

        Strategy:，URLURL

        Args:
            driver: WebDriver
            initial_url: URL
            worker_id: Worker
            task_log:
            task_log_dir: （）
        """
        try:
            task_log(f"[Worker {worker_id}] ...")
            task_log(f"[Worker {worker_id}] : {initial_url}")

            driver.get(initial_url)
            time.sleep(1.0)

            current_url = driver.current_url
            task_log(f"[Worker {worker_id}] URL: {current_url}")

            screenshot_path = task_log_dir / "login_check.png"
            driver.save_screenshot(str(screenshot_path))
            task_log(f"[Worker {worker_id}] : {screenshot_path.name}")

            initial_parsed = urlparse(initial_url)
            current_parsed = urlparse(current_url)

            initial_base = f"{initial_parsed.scheme}://{initial_parsed.netloc}{initial_parsed.path.rstrip('/')}"
            current_base = f"{current_parsed.scheme}://{current_parsed.netloc}{current_parsed.path.rstrip('/')}"

            is_match = initial_base == current_base
            if is_match:
                task_log(f"[Worker {worker_id}] ✓ URL，")
            else:
                task_log(f"[Worker {worker_id}] ✗ URL，")
                task_log(f"[Worker {worker_id}]   : {initial_base}")
                task_log(f"[Worker {worker_id}]   : {current_base}")

            return is_match
        except Exception as e:
            task_log(f"[Worker {worker_id}] ✗ : {e}")
            return False

    # def _restore_login_status(self, worker_driver, worker_id: int, task_log, task_log_dir: Path, max_retries: int = 4) -> bool:
    #     """
    #     （）

    #     ：driver，worker

    #     Args:
    #         worker_driver: WorkerWebDriver
    #         worker_id: Worker
    #         task_log:
    #         task_log_dir:
    #         max_retries:
    #     """
    #     if not self.login_task:
    #         return False


    #     for attempt in range(1, max_retries + 1):
    #         try:

    #             original_driver = self.crawler.driver
    #             original_sensors_driver = self.crawler.sensors.driver
    #             original_acts_driver = self.crawler.acts.sensors.driver

    #             try:
    #                 self.crawler.driver = worker_driver
    #                 self.crawler.sensors.driver = worker_driver
    #                 self.crawler.acts.sensors.driver = worker_driver

    #                 self.crawler.run_a_task(self.login_task, logging_in=True)

    #                 # check if login succeeded
    #                 if self._check_login_status(worker_driver, self.initial_url, worker_id, task_log, task_log_dir):
    #                     return True
    #                 else:

    #             finally:
    #                 self.crawler.driver = original_driver
    #                 self.crawler.sensors.driver = original_sensors_driver
    #                 self.crawler.acts.sensors.driver = original_acts_driver

    #         except Exception as e:

    #     return False

    def _restore_login_status(self, worker_driver, worker_id: int, task_log, task_log_dir: Path, max_retries: int = 4) -> bool:
        """
        （）
        
        ：
        1. workerSensors、Actuators、Bridge
        2. NetworkCaptureTracer
        3. task_id
        4. crawler
        
        Args:
            worker_driver: WorkerWebDriver
            worker_id: Worker
            task_log:
            task_log_dir:
            max_retries:
        
        Returns:
            True，False
        """
        if not self.login_task:
            task_log(f"[Worker {worker_id}] ⚠️  ，")
            return False
        
        task_log(f"[Worker {worker_id}] （）...")
        
        for attempt in range(1, max_retries + 1):
            try:
                task_log(f"[Worker {worker_id}]  {attempt}/{max_retries}...")
                
                
                task_log(f"[Worker {worker_id}]  Sensors  Actuators...")
                login_sensors = Sensors(worker_driver, use_improved_locator=True)
                login_actuators = Actuators(login_sensors)
                
                task_log(f"[Worker {worker_id}]  Bridge...")
                login_bridge = Bridge(
                    sensors=login_sensors,
                    actuators=login_actuators,
                    client=self.client
                )
                
                task_log(f"[Worker {worker_id}]  NetworkCapture...")
                login_network_capture = NetworkCapture(worker_driver)
                
                task_log(f"[Worker {worker_id}]  ExecutionTracer...")
                login_tracer = ExecutionTracer(
                    store=self.crawler.store,
                    network_capture=login_network_capture,
                    on_new_page=lambda url: None,
                    construct_edge=lambda url: None,
                    debug=False
                )
                
                login_bridge.set_tracer(
                    tracer=login_tracer,
                    task_queue=None,
                    store=self.crawler.store
                )
                
                login_task_id = f"login_worker_{worker_id}_attempt_{attempt}"
                task_log(f"[Worker {worker_id}] : {login_task_id}")
                login_task_copy = Task(
                    task_id=login_task_id,
                    description=self.login_task.description,
                    initial_url=self.login_task.initial_url
                )
                
                login_tracer.start_task(login_task_id, login_task_copy.description)
                
                task_log(f"[Worker {worker_id}] : {login_task_copy.initial_url}")
                login_network_capture.clear_requests()
                worker_driver.get(login_task_copy.initial_url)
                time.sleep(0.6)
                
                page = self.crawler.store.get_page(login_task_copy.initial_url)
                if page and page.abstract_page:
                    task_log(f"[Worker {worker_id}] ✓ ")
                    login_sensors.abstract_page = page.abstract_page
                    
                    if page.actions_mapping:
                        login_sensors.actions_mapping.clear()
                        for action_id, locators_info in page.actions_mapping.items():
                            login_sensors.actions_mapping.set_mapping(
                                int(action_id),
                                locators_info
                            )
                        task_log(f"[Worker {worker_id}] ✓  {len(page.actions_mapping)} ")
                    
                    if page.event_mapping:
                        login_sensors.event_mapping.clear()
                        for event_id, event_info in page.event_mapping.items():
                            login_sensors.event_mapping.mapping[int(event_id)] = event_info
                        max_event_id = max(int(k) for k in page.event_mapping.keys())
                        login_sensors.event_mapping.id_counter = max_event_id + 1
                        task_log(f"[Worker {worker_id}] ✓  {len(page.event_mapping)} ")
                else:
                    task_log(f"[Worker {worker_id}] ⚠️  ，")
                    login_sensors.update_abstract_page()
                
                login_screenshot_dir = task_log_dir / f"login_attempt_{attempt}"
                login_screenshot_dir.mkdir(parents=True, exist_ok=True)
                
                task_log(f"[Worker {worker_id}] ...")
                login_bridge.run_task(
                    login_task_copy,
                    photo_dir=login_screenshot_dir,
                    logging_in=True
                )
                
                trace = login_tracer.end_task()
                if trace:
                    self.crawler.store.save_trace(trace)
                    task_log(f"[Worker {worker_id}] ✓ ")
                
                time.sleep(1.0)
                if self._check_login_status(worker_driver, self.initial_url, worker_id, task_log, task_log_dir):
                    task_log(f"[Worker {worker_id}] ✓  {attempt} ")
                    return True
                else:
                    task_log(f"[Worker {worker_id}] ✗ （{attempt}）")
            
            except Exception as e:
                task_log(f"[Worker {worker_id}] ✗  {attempt} : {e}")
                import traceback
                task_log(traceback.format_exc())
        
        task_log(f"[Worker {worker_id}] ✗ {max_retries}")
        return False

    # def _ensure_login_and_update_credentials(self, worker_driver, worker_id: int, task_log, task_log_dir: Path) -> bool:
    #     """
    #     🆕 ： + CSRF token

    #     ：
    #     1.
    #     2. ，（4）
    #     3. ，CSRF token（）

    #     Args:
    #         worker_driver: WorkerWebDriver
    #         worker_id: Worker
    #         task_log:
    #         task_log_dir:

    #     Returns:
    #         True，False
    #     """
    #     task_log(f"")

    #     is_logged_in = self._check_login_status(worker_driver, self.initial_url, worker_id, task_log, task_log_dir)

    #     if not is_logged_in:
    #         if not self._restore_login_status(worker_driver, worker_id, task_log, task_log_dir):
    #             return False
    #     else:

    #     worker_store = self.worker_stores[worker_id]
    #     worker_store.update_from_driver(worker_driver, self.account_manager)

    #     creds = worker_store.get_credentials()
    #     csrf_tokens = worker_store.get_csrf_tokens()
    #     if csrf_tokens:
    #         task_log(f"[Worker {worker_id}]   - CSRF Token keys: {list(csrf_tokens.keys())}")
    #     task_log(f"")

    #     return True

    def _ensure_login_and_update_credentials(self, worker_driver, worker_id, task_log, task_log_dir):
        """
        ：
        : (is_valid, current_driver)
        """
        current_driver = worker_driver

        is_logged_in = self._check_login_status(current_driver, self.initial_url, worker_id, task_log, task_log_dir)

        if not is_logged_in:
            task_log(f"[Worker {worker_id}] ⚠️ ")
            
            try:
                task_log(f"[Worker {worker_id}] ♻️ ...")
                
                try:
                    current_driver.quit()
                except:
                    pass
                
                current_driver = self._create_new_driver()
                task_log(f"[Worker {worker_id}] ✓ ")
                
            except Exception as e:
                task_log(f"[Worker {worker_id}] ❌ : {e}")
                return False, current_driver

            if not self._restore_login_status(current_driver, worker_id, task_log, task_log_dir):
                task_log(f"[Worker {worker_id}] ✗ ")
                return False, current_driver
        
        worker_store = self.worker_stores[worker_id]
        worker_store.update_from_driver(current_driver, self.account_manager)

        creds = worker_store.get_credentials()
        csrf_tokens = worker_store.get_csrf_tokens()
        task_log(f"[Worker {worker_id}] ✓ ")
        task_log(f"[Worker {worker_id}]   - Cookies: {len(creds.get('cookies', []))} ")
        task_log(f"[Worker {worker_id}]   - LocalStorage: {len(creds.get('localStorage', {}))} ")
        task_log(f"[Worker {worker_id}]   - CSRF Tokens: {len(csrf_tokens)} ")
        if csrf_tokens:
            task_log(f"[Worker {worker_id}]   - CSRF Token keys: {list(csrf_tokens.keys())}")
        task_log(f"")
        
        return True, current_driver

    def _generate_replay_curl_with_csrf(self, request: Dict, worker_id: int, task_log) -> str:
        """
        🆕 curl（CSRF token）

        ：
        1. worker_store（account_manager）
        2. bodycsrf
        3. ，worker_storetoken

        Args:
            request:
            worker_id: Worker
            task_log:
        """
        method = request.get("method", "GET")
        url = request.get("url", "")
        headers = request.get("headers", {})
        body = request.get("body")

        parts = [f"curl --compressed -X {method}"]
        parts.append(f'"{url}"')

        for key, value in headers.items():
            if key.lower() not in ["cookie", "authorization"]:
                value_escaped = str(value).replace('\\', '\\\\').replace('"', '\\"')
                parts.append(f'-H "{key}: {value_escaped}"')

        worker_store = self.worker_stores[worker_id]
        credentials = worker_store.get_credentials()
        csrf_tokens = worker_store.get_csrf_tokens()

        if body and method in ["POST", "PUT", "PATCH"]:
            body_str = str(body)

            if csrf_tokens:
                for csrf_key, csrf_value in csrf_tokens.items():
                    pattern = rf'({re.escape(csrf_key)}=)[^&"\s]+'
                    if re.search(pattern, body_str):
                        body_str = re.sub(pattern, rf'\1{csrf_value}', body_str)
                        task_log(f"[Worker {worker_id}] ✓ CSRF token: {csrf_key}")

            body_str_escaped = body_str.replace('"', '\\"')
            parts.append(f'-d "{body_str_escaped}"')

        if credentials:
            cookies = credentials.get("cookies", [])
            if cookies:
                cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
                cookie_str_escaped = cookie_str.replace('\\', '\\\\').replace('"', '\\"')
                parts.append(f'-H "Cookie: {cookie_str_escaped}"')

            cred_headers = credentials.get("headers", {})
            if "Authorization" in cred_headers:
                auth_value_escaped = str(cred_headers["Authorization"]).replace('\\', '\\\\').replace('"', '\\"')
                parts.append(f'-H "Authorization: {auth_value_escaped}"')
            else:
                from attack_agent.request_utils import extract_auth_token
                token = extract_auth_token(credentials)
                if token:
                    token_escaped = str(token).replace('\\', '\\\\').replace('"', '\\"')
                    parts.append(f'-H "Authorization: Bearer {token_escaped}"')

        parts.append('-w "\\nHTTP_STATUS:%{http_code}"')
        return " \\\n  ".join(parts)

    def _execute_replay_curl(self, command: str) -> Dict[str, Any]:
        """curl"""
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
        🆕 （）

        ：
        - worker（worker_drivers）
        - worker
        - CSRF tokens
        """
        if max_workers is None:
            max_workers = len(self.worker_drivers) if self.worker_drivers else 10

        self._log(f"\n{'='*70}")
        self._log(f"[AttackExecutor - PARALLEL MODE] Starting Execution")
        self._log(f"{'='*70}")
        self._log(f"[AttackExecutor] Total Tasks: {len(tasks)}")
        self._log(f"[AttackExecutor] Max Workers: {max_workers}")
        self._log(f"")

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

        self._log(f"[Phase 2] Stored Vulnerability Detection (Hybrid Parallel)")
        self._log(f"{'~'*70}\n")

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

            with ThreadPoolExecutor(max_workers=1) as executor:
                futures = []
                futures.append(executor.submit(self._run_smart_patrol, patrol_info[0]))

                # if trigger_drivers:
                #     for i, (d, n) in enumerate(trigger_drivers):
                #         futures.append(executor.submit(
                #             self._run_llm_trigger_worker, i, d, page_queue, prompt_tpl
                #         ))

                for f in as_completed(futures):
                    try: f.result()
                    except Exception as e: self._log(f"Phase 2 Error: {e}")
        else:
             self._log("❌ Phase 2 Skipped: No drivers.")

        self._log("[Phase 2] Complete.")

        self._check_all_stored_results()
        self._save_results()

        return self.results

    def _check_all_stored_results(self):
        """
        [Final Check]  OOB (Out-of-Band)
        
        ：
        ， Token/ID， Beacon 。
        ：XSS (Blind), SSRF, XXE, CMDI 。
        """
        self._log(f"\n[Stored Vuln Detection] Checking final results from {len(self.results)} records...")
        
        from attack_agent.request_utils import check_beacon_detection
        
        updates_count = 0
        
        POSSIBLE_KEYS = ["token", "random_id", "id", "uuid", "beacon_id", "payload_id"]

        for entry in self.results:
            task_id = entry.get("task_id")
            vuln_type = entry.get("vuln_type")
            task_result = entry.get("result", {})
            
            if task_result.get("vulnerable") is True:
                continue
            
            token = None
            for key in POSSIBLE_KEYS:
                val = task_result.get(key)
                if val:
                    token = val
                    break
            
            if not token:
                continue
                
            token_str = str(token).strip()
            if not token_str:
                continue
            
            try:
                is_triggered = check_beacon_detection(token_str)
                
                if is_triggered:
                    self._log(f"  🎉 [LATE FIND] Task {task_id} ({vuln_type}) triggered OOB Beacon! Token: {token_str}")
                    print(f"  🎉 [LATE FIND] Task {task_id} ({vuln_type}) triggered OOB Beacon! Token: {token_str}")
                    
                    task_result["vulnerable"] = True
                    task_result["evidence"] = f"OOB Beacon Log Detected (Token: {token_str})"
                    updates_count += 1
                    continue
            except Exception as e:
                self._log(f"  ⚠️ Error checking beacon for {task_id}: {e}")

        if updates_count > 0:
            self._log(f"[Final Check] Updated {updates_count} tasks to VULNERABLE status.")
            self._save_results()
        else:
            self._log(f"[Final Check] No new vulnerabilities found.")

    def _wait_for_page_stable(self, driver, timeout=10, check_interval=0.5):
        """
        ：
        1.  document.readyState
        2.  DOM （）
        """
        try:
            WebDriverWait(driver, timeout).until(
                lambda d: d.execute_script("return document.readyState") == "complete"
            )
        except: pass

        end_time = time.time() + timeout
        last_source_len = 0
        stable_count = 0
        
        while time.time() < end_time:
            try:
                current_len = len(driver.page_source)
                if current_len == last_source_len:
                    stable_count += 1
                    if stable_count >= 2:
                        return
                else:
                    stable_count = 0
                    last_source_len = current_len
                
                time.sleep(check_interval)
            except:
                break

    def _execute_task_with_worker(self, task, task_num: int, total_tasks: int) -> Dict:
        """
        🆕 worker driver（：）
        
        ：
        1.  Driver ： Driver ，， Driver。
        2. ： Driver 。
        """
        worker_id = None
        worker_driver = None
        
        max_driver_switches = 3 
        driver_acquired = False

        # ------------------------------------------------------------------
        # ------------------------------------------------------------------
        for switch_attempt in range(max_driver_switches):
            try:
                try:
                    worker_id, worker_driver = self.driver_queue.get()
                except Empty:
                    return {"error": "Worker driver timeout after 300 seconds"}

                if switch_attempt == 0:
                    with self.task_counter_lock:
                        self.task_counter += 1
                        unique_task_id = f"TASK{self.task_counter:04d}"
                    task.task_id = unique_task_id

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
                    task_log(f"{'='*70}")
                    task_log(f"[ATTACK TASK] {task.task_id}")
                    task_log(f"{'='*70}")
                    print(f"\n{'~'*70}")
                    print(f"[Task {task_num}/{total_tasks}] {task.task_id} - Start")

                task_log(f"[Driver Attempt {switch_attempt + 1}/{max_driver_switches}]  Worker {worker_id}...")

                is_valid, new_driver_ref = self._ensure_login_and_update_credentials(
                    worker_driver, worker_id, task_log, task_log_dir
                )
                
                worker_driver = new_driver_ref 

                if is_valid:
                    driver_acquired = True
                    break
                else:
                    print(f"[Task {task.task_id}] ⚠️ Worker {worker_id} （），...")
                    task_log(f"[Driver Error] Worker {worker_id} ， Driver。")
                    
                    try:
                        worker_driver.quit()
                    except:
                        pass
                    
                    worker_driver = None
                    worker_id = None
                    
                    print(f"[Task {task.task_id}] 🔄  Driver...")
                    continue

            except Exception as e:
                task_log(f"[Driver Error]  Driver : {e}")
                if worker_driver:
                    try:
                        worker_driver.quit()
                    except:
                        pass
                worker_driver = None
                worker_id = None
                continue

        # ------------------------------------------------------------------
        # ------------------------------------------------------------------
        if not driver_acquired:
            print(f"[Task {task.task_id}] ❌ ： {max_driver_switches}  Driver 。")
            return {"error": "All attempted drivers failed to login (credentials changed?)"}

        try:
            
            # =========================================================
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

            task_log(f"\n[Step 1: Replay Request Generation]")
            curl_command = self._generate_replay_curl_with_csrf(task.target_request, worker_id, task_log)
            task_log(f"[Generated CURL Command]:\n{curl_command}\n")

            task_log(f"[Step 2: Replay Request Execution]")
            replay_result = self._execute_replay_curl(curl_command)
            
            http_status = replay_result.get('http_status')
            task_log(f"  Curl Success: {replay_result.get('success', False)}")
            task_log(f"  HTTP Status: {http_status}")

            response_body = replay_result.get('stdout', '')
            task_log(f"  Response Body: {response_body}")

            # =================================================================
            # =================================================================
            
            if not replay_result.get('success') or not http_status:
                error_msg = f"Replay failed (Status: {http_status}). Aborting task to save tokens."
                task_log(f"  ❌ {error_msg}")
                print(f"[Task {task.task_id}] ⏭️ {error_msg}")
                return {"error": error_msg, "skipped": True}

            if http_status in [403, 401] and task.vuln_type not in ["AUTH_BYPASS", "IDOR"]:
                error_msg = f"Target returned {http_status} (Access Denied). Aborting."
                task_log(f"  🛑 {error_msg}")
                return {"error": error_msg, "skipped": True}

            raw_body = replay_result.get('stdout', '')
            
            processed_body = extract_useful_response(raw_body, max_length=4000) 
            
            task.target_request['response_body'] = processed_body
            task.target_request['response_status'] = http_status
            
            task_log(f"  ✓ Request context updated with fresh replay data.")
            task_log(f"  ✓ Response Body optimized for LLM ({len(processed_body)} chars).")
            # =================================================================
            
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
                            task_log(f"[Token Inject] : {csrf_key} -> {csrf_value[:10]}...")
                    
                    if replaced_count > 0:
                        task.target_request['body'] = new_body
                        task_log(f"[Token Inject] ✅ Token ")
                except Exception as e:
                    task_log(f"[Token Inject] ⚠️ : {e}")

            task_log(f"\n[Step 3: Attack Execution]")
            tracker.set_category(_VULN_CATEGORY_MAP.get(task.vuln_type, f"attack_{task.vuln_type.lower()}"))
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
        # =================================================================
        except (WebDriverException, MaxRetryError, NewConnectionError) as e:
            err_msg = str(e)
            if "Connection refused" in err_msg or "Max retries exceeded" in err_msg or "invalid session" in err_msg:
                task_log(f"[CRITICAL ERROR] Driver : {e}")
                print(f"[Task {task.task_id}] 🚨 Worker {worker_id}  Driver ，...")
                
                if worker_driver:
                    try:
                        worker_driver.quit()
                    except:
                        pass
                
                worker_driver = None
                
                return {
                    "error": "Driver crashed during execution",
                    "traceback": err_msg
                }
            else:
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
            if worker_id is not None and worker_driver is not None:
                try:
                    _ = worker_driver.current_url
                    self.driver_queue.put((worker_id, worker_driver))
                except Exception as e:
                    print(f"[Worker {worker_id}] ⚠️  Driver  ({e})，。")
                    try:
                        worker_driver.quit()
                    except:
                        pass

    def _save_results(self):
        """"""
        output_file = self.log_dir / "attack_results.json"
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self._log(f"[Error] Failed to save results: {e}")

    # def _run_smart_patrol(self, driver):
    #     """
    #      (Smart Patrol) -
    #     """
    #     worker_name = "Smart Patrol"
        
    #     patrol_dir = self.log_dir / "phase2_smart_patrol"
    #     patrol_dir.mkdir(parents=True, exist_ok=True)
        
    #     patrol_log_file = patrol_dir / "patrol_summary.log"
        
    #     def p_log(msg):
    #         timestamp = time.strftime("[%H:%M:%S]")
    #         full_msg = f"{timestamp} {msg}"
    #         try:
    #             with open(patrol_log_file, "a", encoding="utf-8") as f:
    #                 f.write(full_msg + "\n")
    #         except: pass

    #     p_log(f"🚀 Started with driver: {driver.title}")

    #     try:
    #         known_urls = set(list(self.crawler.store.pages.keys()))
    #         scan_queue = list(known_urls)
    #         visited_in_patrol = set()
            
    #         p_log(f"Base Queue: {len(scan_queue)} known pages")
            
    #         scan_start = time.time()
    #         new_links_found = 0
            
    #         DANGEROUS_KEYWORDS = [
    #             "logout", "signout", "logoff", "sign_out", "log_out", "exit", "quit",
    #             "delete", "remove", "destroy", "erase", "purge", "trash", "drop", 
    #             "reset", "clear", "disable", "deactivate", "ban", "block", "suspend",
    #             "password", "passwd", "pwd", "unsubscribe", "cancel", "abort"
    #         ]

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
    #                 driver.get(url)
    #                 visited_in_patrol.add(url)
                    
    #                 self._wait_for_page_stable(driver)
                    
    #                 safe_name = self._url_to_filename(url)
    #                 try:
    #                     driver.save_screenshot(str(patrol_dir / f"visit_{safe_name}.png"))
    #                 except: pass

    #                 try:
    #                     elements = driver.find_elements("tag name", "a")
                        
    #                     for elem in elements:
    #                         try:
    #                             href = elem.get_attribute("href")
                                
    #                             if href and self.target_domain in href:
    #                                 clean_href = href.split('#')[0] if '#' in href and not '/#/' in href else href
                                    
    #                                 if clean_href.startswith(('http', 'https')) and clean_href not in known_urls:
    #                                     known_urls.add(clean_href)
    #                                     scan_queue.append(clean_href)
    #                                     new_links_found += 1
    #                                     p_log(f"[+] New URL: {clean_href}")
    #                         except:
    #                             pass
    #                 except Exception as e:
    #                     err_msg = str(e)
    #                     if "Connection refused" in err_msg or "invalid session" in err_msg or "Max retries exceeded" in err_msg:
    #                         p_log(f"🔥 CRITICAL: Driver died during link extraction at {url}.")
    #                         p_log(f"🛑 Abandoning Smart Patrol immediately.")
    #                     else:
    #                         p_log(f"Link extraction error: {e}")

    #             except Exception as e:
    #                 if "unexpected alert open" in str(e) or isinstance(e, UnexpectedAlertPresentException):
    #                     try:
    #                         alert = driver.switch_to.alert
    #                         p_log(f"🔥 UNEXPECTED ALERT at {url}: {alert.text}")
    #                         alert.accept()
    #                     except: pass
    #                 elif "Connection refused" in err_msg or "invalid session" in err_msg or "Max retries exceeded" in err_msg:
    #                     p_log(f"🔥 CRITICAL: Driver died visiting {url}.")
    #                     p_log(f"🛑 Abandoning Smart Patrol immediately.")
                        
    #                     try: driver.quit()
    #                     except: pass
                        
    #                 else:
    #                     p_log(f"⚠️ Error visiting {url}: {e}")

    #         p_log(f"✓ Scan complete. Visited {len(visited_in_patrol)} pages. Found {new_links_found} new URLs.")

    #     except Exception as e:
    #         p_log(f"❌ Fatal error: {e}")

    def _run_smart_patrol(self, driver):
        """
         (Smart Patrol) -  ()
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
                    driver.get(url)
                    visited_in_patrol.add(url)
                    self._wait_for_page_stable(driver)
                    
                    safe_name = self._url_to_filename(url)
                    try: driver.save_screenshot(str(patrol_dir / f"visit_{safe_name}.png"))
                    except: pass

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
                    # =========================================================
                    if "Connection refused" in err_msg or "invalid session" in err_msg or "Max retries exceeded" in err_msg:
                        p_log(f"🔥 CRITICAL: Driver died at {url}. Abandoning Smart Patrol.")
                        p_log(f"❌ Error details: {err_msg}")
                        try: driver.quit()
                        except: pass
                        return
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
    #     LLM  Worker -  +
    #     """
    #     trigger_root = self.log_dir / "phase2_llm_trigger"
    #     trigger_root.mkdir(parents=True, exist_ok=True)
        
    #     self._log(f"[LLM-Trigger-{worker_id}] 🚀 Started. Ready to consume pages.")
        
    # # create independent component chain
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
                
    #             self._wait_for_page_stable(driver)
    #             driver.save_screenshot(str(page_dir / "00_initial.png"))

    #             sensors.update_abstract_page()
    #             full_abstract = sensors.get_abstract_page()
                
    #             filtered_lines = []
    #             for line in full_abstract.splitlines():
    #                 if "<a " in line or line.strip().startswith("<a"): continue
    #                 filtered_lines.append(line)
                
    #             filtered_abstract = "\n".join(filtered_lines)
    #             if not filtered_abstract.strip():
    #                 w_log("Skipping: No interactive elements found.")
    #                 # shared_queue.task_done()
    #                 continue

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
    #                     driver.get(url)
                        
    #                     # sensors.update_abstract_page()
                        
    #                     success = False
    #                     if kind == "CLICK": success = actuators.execute_action_by_id(action_id)
    #                     elif kind == "TRIGGER": success = bridge.execute_task_step(None, action_id, force_event=True)
                        
    #                     if success:
    #                         w_log(f"✓ {cmd}")
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
    #                     if "unexpected alert open" in str(e) or isinstance(e, UnexpectedAlertPresentException):
    #                         try:
    #                             alert = driver.switch_to.alert
    #                             w_log(f"🔥 UNEXPECTED ALERT CAUGHT: {alert.text}")
    #                             w_log("✓ Alert accepted (recovered)")
    #                         except:
    #                             w_log(f"⚠ Could not handle alert: {e}")
    #                     else:
    #                         w_log(f"Cmd Error: {e}")

    #                     w_log(f"Cmd Error: {e}")
                        
    #         except Exception as e:
    #             w_log(f"Page Error: {e}")
    #         finally:
    #             shared_queue.task_done()

    def _run_llm_trigger_worker(self, worker_id, driver, shared_queue, prompt_template):
        """
        LLM  Worker -  ()
        """
        trigger_root = self.log_dir / "phase2_llm_trigger"
        trigger_root.mkdir(parents=True, exist_ok=True)
        
        self._log(f"[LLM-Trigger-{worker_id}] 🚀 Started. Ready to consume pages.")
        
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

            try:
                processed_count += 1
                if any(x in url.lower() for x in ["logout", "signout", "logoff", "delete"]):
                    continue

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
                
                try:
                    driver.get(url)
                    self._wait_for_page_stable(driver)
                    driver.save_screenshot(str(page_dir / "00_initial.png"))
                    
                    sensors.update_abstract_page()
                    full_abstract = sensors.get_abstract_page()
                except Exception as e:
                    w_log(f"Page Load Error: {e}")
                    continue

                filtered_lines = []
                for line in full_abstract.splitlines():
                    if "<a " in line or line.strip().startswith("<a"): continue
                    filtered_lines.append(line)
                
                filtered_abstract = "\n".join(filtered_lines)
                if not filtered_abstract.strip():
                    w_log("Skipping: No interactive elements found.")
                    continue 

                prompt = prompt_template.format(page_description=filtered_abstract)
                with open(page_dir / "llm_prompt.txt", "w", encoding="utf-8") as f: f.write(prompt)

                try:
                    tracker.set_category("attack_executor")
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
                        driver.get(url)
                        self._wait_for_page_stable(driver) 
                        
                        success = False
                        if kind == "CLICK": success = actuators.execute_action_by_id(action_id)
                        elif kind == "TRIGGER": success = bridge.execute_task_step(None, action_id, force_event=True)
                        
                        if success:
                            w_log(f"✓ {cmd}")
                            time.sleep(0.5) 
                            driver.save_screenshot(str(page_dir / f"step_{idx+1:02d}_{kind}_{action_id}.png"))
                            
                            try:
                                alert = driver.switch_to.alert
                                w_log(f"🔥 ALERT: {alert.text}")
                                alert.accept()
                                driver.save_screenshot(str(page_dir / "EVIDENCE_ALERT.png"))
                            except: pass
                        else:
                            w_log(f"✗ Failed: {cmd}")

                    except Exception as e:
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
                self._log(f"[LLM-Trigger-{worker_id}] Critical Worker Error: {e}")
            
            finally:
                shared_queue.task_done()

    def execute_tasks_from_queue(self, task_queue, max_workers: int = None) -> List[Dict]:
        """
        🆕 （worker driver）

        ：Phase 4 → Phase 5

        Args:
            task_queue: queue.Queue，
            max_workers: （worker_drivers）

        Returns:

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

        self._log(f"[Phase 1] Parallel Attack Execution from Queue")
        self._log(f"  Submitting tasks to thread pool as they arrive...")
        self._log(f"")

        executor = ThreadPoolExecutor(max_workers=max_workers)
        try:
            futures = []

            while True:
                task = task_queue.get()

                if task is None:
                    self._log(f"\n[Queue] Received termination signal")
                    self._log(f"[Queue] Total tasks received: {len(tasks_received)}")
                    self._log(f"[Queue] Waiting for {len(futures)} running task(s) to complete...")
                    break

                tasks_received.append(task)
                self._log(f"[Queue] Task received: {task.task_id} (total: {len(tasks_received)})")

                future = executor.submit(
                    self._execute_task_with_worker,
                    task,
                    len(tasks_received),
                    "?"
                )
                futures.append((future, task))

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

                    for completed in completed_futures:
                        futures.remove(completed)

                    self._log(f"[Queue] {len(completed_futures)} task(s) completed, {len(futures)} still running")

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
        finally:
            self._log(f"\n[Cleanup] Shutting down executor (wait=False)...")
            executor.shutdown(wait=False)
            self._log(f"[Cleanup] Executor shutdown complete")

        phase1_duration = time.time() - start_time
        self._phase1_duration = phase1_duration
        self._log(f"")
        self._log(f"[Phase 1 Complete] ⏱️  Time: {phase1_duration:.1f}s")
        self._log(f"")

        # self._log(f"[Phase 2] Stored Vulnerability Detection (Full Coverage)")

        # patrol_driver = None
        # candidates = []
        # if self.driver: candidates.append((self.driver, "Main Driver"))
        # if self.worker_drivers:
        #     for i, wd in enumerate(reversed(self.worker_drivers)):
        #         candidates.append((wd, f"Worker Driver {len(self.worker_drivers)-i-1}"))

        # for drv, name in candidates:
        #     try:
        #         try: 
        #             _ = drv.current_url
        #         except: 
        #             continue
                
        #         if self._check_login_status(drv, self.initial_url, -1, self._log, self.log_dir):
        #             patrol_driver = drv
        #             self._log(f"  ✅ Selected [{name}] for patrol.")
        #             break
        #     except:
        #         pass

        # if patrol_driver:
        #     try:
        #         self._log(f"  🚀 Starting FULL coverage scan...")
                
        #         known_urls = set(list(self.crawler.store.pages.keys()))
        #         scan_queue = list(known_urls)
        #         visited_in_patrol = set()
                
                
        #         self._log(f"     Base Queue: {len(scan_queue)} known pages")
                
        #         scan_start = time.time()
        #         new_links_found = 0
                
        #         while scan_queue:
        #             url = scan_queue.pop(0)
                    
        #             if url in visited_in_patrol:
        #                 continue
                        
        #             if any(x in url.lower() for x in ["logout", "signout", "logoff", "exit", "quit"]):
        #                 continue
                    
        #             try:
        #                 patrol_driver.get(url)
        #                 visited_in_patrol.add(url)
                        
        #                 time.sleep(1.0) 
                        
        #                 try:
        #                     alert = patrol_driver.switch_to.alert
        #                     alert.accept()
        #                 except:
        #                     pass

        #                 try:
        #                     elements = patrol_driver.find_elements("tag name", "a")
        #                     for elem in elements:
        #                         href = elem.get_attribute("href")
        #                         if href and self.target_domain in href:
        #                             clean_href = href.split('#')[0] if '#' in href and not '/#/' in href else href
                                    
        #                             if clean_href not in known_urls:
        #                                 known_urls.add(clean_href)
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

        phase2_start = time.time()
        self._log(f"[Phase 2] Stored Vulnerability Detection (Hybrid Parallel)")

        available_drivers = [] 
        if self.driver:
            try: 
                _ = self.driver.current_url
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

        patrol_info = available_drivers.pop(0)
        patrol_driver = patrol_info[0]
        
        trigger_drivers = available_drivers
        
        self._log(f"👮 Assigned [{patrol_info[1]}] to Smart Patrol")


        with ThreadPoolExecutor(max_workers=1) as executor:
            futures = []

            futures.append(executor.submit(self._run_smart_patrol, patrol_driver))

            # if trigger_drivers:
            #     for i, (drv, name) in enumerate(trigger_drivers):
            #         futures.append(executor.submit(
            #             self._run_llm_trigger_worker,
            #             i, drv, page_queue, trigger_prompt
            #         ))

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self._log(f"Phase 2 Thread Error: {e}")

        self._log("[Phase 2] Complete.")
        phase2_duration = time.time() - phase2_start
        self._log(f"[Phase 2 Complete] ⏱️  Time: {phase2_duration:.1f}s")

        total_duration = time.time() - start_time

        self._phase1_duration = phase1_duration
        self._phase2_duration = phase2_duration

        self._log(f"\n{'='*70}")
        self._log(f"[AttackExecutor - QUEUE MODE] Execution Complete")
        self._log(f"{'='*70}")
        self._log(f"[Final Statistics]:")
        self._log(f"  Total Tasks: {len(tasks_received)}")
        self._log(f"  Completed: {len(self.results)}")
        self._log(f"  Phase 1 (Attack Execution): {phase1_duration:.1f}s")
        self._log(f"  Phase 2 (Smart Patrol):     {phase2_duration:.1f}s")
        self._log(f"  Total Time: {total_duration:.1f}s")
        if len(tasks_received) > 0:
            self._log(f"  Avg Time/Task: {phase1_duration/len(tasks_received):.2f}s (attack phase only)")

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

    def _get_pending_tasks(self) -> Dict[str, int]:
        """pending"""
        pending = {}
        for result in self.results:
            if result.get("result", {}).get("vulnerable") is None:
                vuln_type = result.get("vuln_type")
                pending[vuln_type] = pending.get(vuln_type, 0) + 1
        return pending
