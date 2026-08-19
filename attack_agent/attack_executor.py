"""
AttackExecutor - (worker drivers +  + CSRF)

1. worker driver(Phase 3drivers)
2. worker(WorkerCredentialStore)
3. : + CSRF token
4. CSRF tokencurl
"""

from typing import List, Dict, Any, Set
from pathlib import Path
import json
import time
import threading
import hashlib
import re
import shlex
import subprocess
import os
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
from queue import Queue, Empty
from urllib.parse import urlparse
from crawl.dom_semantic_extractor import DOMSemanticExtractor
from crawl.Actuators import Actuators
from crawl.interaction_execution_agent import InteractionExecutionAgent
from capture.network_capture import NetworkCapture
from crawl.tracer import ExecutionTracer
from task.tasks import Task
from seleniumwire import webdriver
from attack_agent.worker_credential_store import WorkerCredentialStore
from config.llm_config import BEACON_URL, get_model_name, get_temperature
from utils.chrome_driver import configure_chrome_options, make_chrome_service
from utils.url_scope import UrlScope
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import UnexpectedAlertPresentException, NoAlertPresentException
from urllib3.exceptions import MaxRetryError, NewConnectionError
from selenium.common.exceptions import WebDriverException
from attack_agent.request_utils import extract_useful_response, kill_process_group_and_collect
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

_UNLIMITED_TIMEOUT_VALUES = {"none", "inf", "infinite", "unlimited"}
_TASK_TIMEOUT_DEFAULTS = {
    "SQL_INJECTION": None,
    "XSS": 300,
    "IDOR": 420,
    "AUTH_BYPASS": 420,
    "PRIVILEGE_ESCALATION": 420,
    "BUSINESS_LOGIC": 420,
}
_TASK_TIMEOUT_ENVS = {
    "SQL_INJECTION": "SEMSCANNER_ATTACK_TASK_TIMEOUT_SQL",
    "XSS": "SEMSCANNER_ATTACK_TASK_TIMEOUT_XSS",
    "IDOR": "SEMSCANNER_ATTACK_TASK_TIMEOUT_BUSINESS",
    "AUTH_BYPASS": "SEMSCANNER_ATTACK_TASK_TIMEOUT_BUSINESS",
    "PRIVILEGE_ESCALATION": "SEMSCANNER_ATTACK_TASK_TIMEOUT_BUSINESS",
    "BUSINESS_LOGIC": "SEMSCANNER_ATTACK_TASK_TIMEOUT_BUSINESS",
}
_AUTH_COOKIE_NAME_PATTERN = re.compile(
    r"session|sess|sid|auth|token|jwt|login",
    re.IGNORECASE,
)

class AttackExecutor:
    """
     -

    - driver instances
    - workersession
    - CSRF tokens
    -
    """

    def __init__(self, account_manager, crawler, client,
                 log_dir: str = "output/attack_executor",
                 edges_file: str = None,
                 driver = None,
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
        self._driver_registry_lock = threading.Lock()
        self._session_recovery_lock = threading.Lock()
        self._session_recovery_attempts: Set[str] = set()

        self._lock = threading.Lock()
        self._log_lock = threading.Lock()

        self.target_domain = target_domain
        self.url_scope = getattr(crawler, "url_scope", None)
        if self.url_scope is None and initial_url:
            self.url_scope = UrlScope(
                initial_url,
                request_exception_urls=(BEACON_URL,),
            )

    def _create_new_driver(self):
        """: Driver """
        self._log("[DriverFactory] Creating worker Chrome driver...")
        
        options = self.chrome_options
        if not options:
            options = webdriver.ChromeOptions()
            options.add_argument("--headless=new")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-gpu")
            options.add_argument("--disable-web-security")
            options.add_argument("--allow-running-insecure-content")
            options.add_argument("--disable-xss-auditor")
            options.page_load_strategy = "eager"

        options = configure_chrome_options(options)
        service = make_chrome_service()
        new_driver = webdriver.Chrome(service=service, options=options)
        
        new_driver.set_page_load_timeout(60)
        new_driver.set_script_timeout(60)
        new_driver.set_window_size(1920, 1080)

        if self.url_scope:
            def interceptor(request):
                if not self.url_scope.allows_request(request.url):
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
                        if js_file == "xss_xhr.js":
                            from config.llm_config import BEACON_URL
                            source_code = source_code.replace("{BEACON_URL}", BEACON_URL.rstrip("/"))
                        send(new_driver, "Page.addScriptToEvaluateOnNewDocument", {"source": source_code})
                except FileNotFoundError:
                    self._log(f"[DriverFactory] JS file not found: {file_path}")

            self._log("[DriverFactory] JS scripts injected")
            
        except Exception as e:
            self._log(f"[DriverFactory] : {e}")
            try:
                new_driver.quit()
            except:
                pass
            raise e

        return new_driver

    def _register_replacement_driver(self, worker_id: int, old_driver, new_driver,
                                     was_main_driver: bool = False):
        """Keep the authoritative driver registry aligned with queue replacements."""
        with self._driver_registry_lock:
            if 0 <= worker_id < len(self.worker_drivers):
                self.worker_drivers[worker_id] = new_driver
            if was_main_driver or self.driver is old_driver:
                self.driver = new_driver

    @staticmethod
    def _authentication_cookie_fingerprints(credentials: Dict[str, Any]) -> Set[str]:
        """Return opaque identifiers for cookies likely to carry a session.

        Cookie names are selected generically rather than assuming a framework-
        specific name such as PHPSESSID.  If an application uses no recognizable
        session-cookie name, all non-empty cookies are used as a conservative
        fallback.
        """
        cookies = (credentials or {}).get("cookies", []) or []
        usable = [
            cookie for cookie in cookies
            if cookie.get("name") and cookie.get("value") not in (None, "")
        ]
        preferred = [
            cookie for cookie in usable
            if _AUTH_COOKIE_NAME_PATTERN.search(str(cookie.get("name", "")))
        ]
        selected = preferred or usable
        return {
            hashlib.sha256(
                f"{str(cookie.get('name')).lower()}\0{cookie.get('value')}".encode("utf-8")
            ).hexdigest()
            for cookie in selected
        }

    def _worker_auth_cookie_fingerprints(self, worker_id: int, driver=None) -> Set[str]:
        store = self.worker_stores.get(worker_id)
        credentials = store.get_credentials() if store is not None else {}
        fingerprints = self._authentication_cookie_fingerprints(credentials)
        if fingerprints or driver is None:
            return fingerprints

        try:
            return self._authentication_cookie_fingerprints(
                {"cookies": driver.get_cookies()}
            )
        except Exception:
            return set()

    @staticmethod
    def _quit_driver_quietly(driver):
        if driver is None:
            return
        try:
            driver.quit()
        except Exception:
            pass

    def _force_new_authenticated_session(self, worker_id: int, worker_driver,
                                         task_log, task_log_dir: Path):
        """Replace one worker driver and establish a fresh authenticated session."""
        was_main_driver = worker_driver is self.driver
        self._quit_driver_quietly(worker_driver)

        new_driver = None
        try:
            new_driver = self._create_new_driver()
            self._register_replacement_driver(
                worker_id,
                worker_driver,
                new_driver,
                was_main_driver=was_main_driver,
            )
            task_log(f"[Worker {worker_id}] [Session Recovery] Created a fresh driver")

            if self.login_task:
                restored = self._restore_login_status(
                    new_driver,
                    worker_id,
                    task_log,
                    task_log_dir,
                )
            elif self.initial_url:
                new_driver.get(self.initial_url)
                time.sleep(0.5)
                restored = self._check_login_status(
                    new_driver,
                    self.initial_url,
                    worker_id,
                    task_log,
                    task_log_dir,
                )
            else:
                restored = True

            if not restored:
                task_log(f"[Worker {worker_id}] [Session Recovery] Fresh login failed")
                return False, new_driver

            self.worker_stores[worker_id].update_from_driver(
                new_driver,
                self.account_manager,
            )
            task_log(f"[Worker {worker_id}] [Session Recovery] Fresh session is ready")
            return True, new_driver
        except Exception as exc:
            task_log(f"[Worker {worker_id}] [Session Recovery] Failed: {exc}")
            if new_driver is None:
                self._register_replacement_driver(
                    worker_id,
                    worker_driver,
                    None,
                    was_main_driver=was_main_driver,
                )
            return False, new_driver

    def _retire_idle_workers_sharing_session(self, stale_fingerprints: Set[str],
                                             task_log) -> int:
        """Remove queued workers that still share a session known to be blocked."""
        if not stale_fingerprints:
            return 0

        queued = []
        while True:
            try:
                queued.append(self.driver_queue.get_nowait())
            except Empty:
                break

        retained = []
        retired = 0
        for queued_worker_id, queued_driver in queued:
            fingerprints = self._worker_auth_cookie_fingerprints(
                queued_worker_id,
                queued_driver,
            )
            if fingerprints.intersection(stale_fingerprints):
                self._quit_driver_quietly(queued_driver)
                self._register_replacement_driver(
                    queued_worker_id,
                    queued_driver,
                    None,
                )
                retired += 1
            else:
                retained.append((queued_worker_id, queued_driver))

        for item in retained:
            self.driver_queue.put(item)

        if retired:
            task_log(
                f"[Session Recovery] Retired {retired} idle worker(s) sharing the stale session"
            )
        return retired

    def _recover_session_after_replay_timeout(self, worker_id: int, worker_driver,
                                              task_log, task_log_dir: Path):
        """Rotate a blocked session without replaying the timed-out request."""
        with self._session_recovery_lock:
            stale_fingerprints = self._worker_auth_cookie_fingerprints(
                worker_id,
                worker_driver,
            )
            attempt_key_material = ",".join(sorted(stale_fingerprints)) or f"driver:{id(worker_driver)}"
            attempt_key = hashlib.sha256(attempt_key_material.encode("utf-8")).hexdigest()
            if attempt_key in self._session_recovery_attempts:
                task_log(
                    f"[Worker {worker_id}] [Session Recovery] "
                    "This stale session has already had one recovery attempt"
                )
                return False, worker_driver
            self._session_recovery_attempts.add(attempt_key)

            task_log(
                f"[Worker {worker_id}] [Session Recovery] Replay timed out; "
                "rotating the authenticated session without resending the request"
            )
            restored, new_driver = self._force_new_authenticated_session(
                worker_id,
                worker_driver,
                task_log,
                task_log_dir,
            )
            if restored:
                self._retire_idle_workers_sharing_session(
                    stale_fingerprints,
                    task_log,
                )
            return restored, new_driver
    
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

    def _parse_timeout_env(self, env_name: str, default: int = None):
        raw = os.environ.get(env_name)
        if raw is None or str(raw).strip() == "":
            return default

        normalized = str(raw).strip().lower()
        if normalized in _UNLIMITED_TIMEOUT_VALUES:
            return None

        try:
            timeout = int(float(normalized))
        except ValueError:
            self._log(f"[Timeout] Invalid {env_name}={raw!r}; using default {default}s")
            return default

        if timeout <= 0:
            return default
        return timeout

    def _timeout_for_task(self, task):
        vuln_type = getattr(task, "vuln_type", "")
        default = _TASK_TIMEOUT_DEFAULTS.get(vuln_type, 600)
        specific_env = _TASK_TIMEOUT_ENVS.get(vuln_type)

        if specific_env and os.environ.get(specific_env) is not None:
            return self._parse_timeout_env(specific_env, default)

        if vuln_type == "SQL_INJECTION":
            return default

        global_timeout = self._parse_timeout_env("SEMSCANNER_ATTACK_TASK_TIMEOUT", None)
        if global_timeout is not None:
            return global_timeout

        return default

    def _task_deadline_remaining(self, task):
        deadline = getattr(task, "_semscanner_deadline", None)
        if deadline is None:
            return None
        return max(0.0, deadline - time.time())

    def _task_deadline_exceeded(self, task) -> bool:
        remaining = self._task_deadline_remaining(task)
        return remaining is not None and remaining <= 0

    def _task_timeout_result(self, task_timeout):
        return {
            "error": f"Task timeout after {task_timeout} seconds",
            "timeout": True,
            "vulnerable": None,
        }

    def _create_agent_for_task(self, vuln_type: str, task_log_dir: Path, driver=None):
        """agent"""
        task_log_dir_str = str(task_log_dir)

        if vuln_type == "SQL_INJECTION":
            from attack_agent.sql_injection_agent import SQLInjectionAgent
            return SQLInjectionAgent(client=self.client, log_dir=task_log_dir_str)
        elif vuln_type == "XSS":
            from attack_agent.xss_agent import XSSAgent
            return XSSAgent(client=self.client, driver=driver or self.driver, log_dir=task_log_dir_str)
        elif vuln_type in ["IDOR", "AUTH_BYPASS", "PRIVILEGE_ESCALATION", "BUSINESS_LOGIC"]:
            from attack_agent.business_logic_agent import BusinessLogicAgent
            return BusinessLogicAgent(client=self.client, log_dir=task_log_dir_str)
        else:
            raise ValueError(f"Unsupported vulnerability type: {vuln_type}")

    def _check_login_status(self, driver, initial_url: str, worker_id: int, task_log, task_log_dir: Path) -> bool:
        """
        (URL)

        Strategy:, URLURL

        Args:
            driver: WebDriver
            initial_url: URL
            worker_id: Worker
            task_log:
            task_log_dir: ()
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
                task_log(f"[Worker {worker_id}] [OK] URL, ")
            else:
                task_log(f"[Worker {worker_id}] [FAIL] URL, ")
                task_log(f"[Worker {worker_id}]   : {initial_base}")
                task_log(f"[Worker {worker_id}]   : {current_base}")

            return is_match
        except Exception as e:
            task_log(f"[Worker {worker_id}] [FAIL] : {e}")
            return False

    def _restore_login_status(self, worker_driver, worker_id: int, task_log, task_log_dir: Path, max_retries: int = 4) -> bool:
        """
        
        1. workerDOMSemanticExtractor、Actuators、InteractionExecutionAgent
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
            True, False
        """
        if not self.login_task:
            task_log(f"[Worker {worker_id}]  , ")
            return False
        
        task_log(f"[Worker {worker_id}] ()...")
        
        for attempt in range(1, max_retries + 1):
            try:
                task_log(f"[Worker {worker_id}]  {attempt}/{max_retries}...")
                
                
                task_log(f"[Worker {worker_id}]  DOMSemanticExtractor  Actuators...")
                login_sensors = DOMSemanticExtractor(worker_driver, use_improved_locator=True)
                login_actuators = Actuators(login_sensors)
                
                task_log(f"[Worker {worker_id}]  InteractionExecutionAgent...")
                login_bridge = InteractionExecutionAgent(
                    sensors=login_sensors,
                    actuators=login_actuators,
                    client=self.client,
                    url_in_scope=self.crawler.is_url_in_scope,
                )
                
                task_log(f"[Worker {worker_id}]  NetworkCapture...")
                login_network_capture = NetworkCapture(worker_driver)
                
                task_log(f"[Worker {worker_id}]  ExecutionTracer...")
                login_tracer = ExecutionTracer(
                    store=self.crawler.store,
                    network_capture=login_network_capture,
                    on_new_page=lambda url: None,
                    construct_edge=lambda url: None,
                    url_in_scope=self.crawler.is_url_in_scope,
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
                    task_log(f"[Worker {worker_id}] [OK] ")
                    login_sensors.abstract_page = page.abstract_page
                    
                    if page.actions_mapping:
                        login_sensors.actions_mapping.clear()
                        for action_id, locators_info in page.actions_mapping.items():
                            login_sensors.actions_mapping.set_mapping(
                                int(action_id),
                                locators_info
                            )
                        task_log(f"[Worker {worker_id}] [OK]  {len(page.actions_mapping)} ")
                    
                    if page.event_mapping:
                        login_sensors.event_mapping.clear()
                        for event_id, event_info in page.event_mapping.items():
                            login_sensors.event_mapping.mapping[int(event_id)] = event_info
                        max_event_id = max(int(k) for k in page.event_mapping.keys())
                        login_sensors.event_mapping.id_counter = max_event_id + 1
                        task_log(f"[Worker {worker_id}] [OK]  {len(page.event_mapping)} ")
                else:
                    task_log(f"[Worker {worker_id}]  , ")
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
                    task_log(f"[Worker {worker_id}] [OK] ")
                
                time.sleep(1.0)
                if self._check_login_status(worker_driver, self.initial_url, worker_id, task_log, task_log_dir):
                    task_log(f"[Worker {worker_id}] [OK]  {attempt} ")
                    return True
                else:
                    task_log(f"[Worker {worker_id}] [FAIL] ({attempt})")
            
            except Exception as e:
                task_log(f"[Worker {worker_id}] [FAIL]  {attempt} : {e}")
                import traceback
                task_log(traceback.format_exc())
        
        task_log(f"[Worker {worker_id}] [FAIL] {max_retries}")
        return False

    def _ensure_login_and_update_credentials(self, worker_driver, worker_id, task_log, task_log_dir, max_resets: int = 20):
        """
        : (is_valid, current_driver)
        """
        current_driver = worker_driver
        worker_is_main_driver = worker_driver is self.driver

        for reset_count in range(0, max_resets + 1):
            is_logged_in = self._check_login_status(current_driver, self.initial_url, worker_id, task_log, task_log_dir)

            if is_logged_in:
                worker_store = self.worker_stores[worker_id]
                worker_store.update_from_driver(current_driver, self.account_manager)

                creds = worker_store.get_credentials()
                csrf_tokens = worker_store.get_csrf_tokens()
                task_log(f"[Worker {worker_id}] [OK] ")
                task_log(f"[Worker {worker_id}]   - Cookies: {len(creds.get('cookies', []))} ")
                task_log(f"[Worker {worker_id}]   - LocalStorage: {len(creds.get('localStorage', {}))} ")
                task_log(f"[Worker {worker_id}]   - CSRF Tokens: {len(csrf_tokens)} ")
                if csrf_tokens:
                    task_log(f"[Worker {worker_id}]   - CSRF Token keys: {list(csrf_tokens.keys())}")
                task_log(f"")
                return True, current_driver

            if reset_count >= max_resets:
                task_log(f"[Worker {worker_id}] [FAIL] login/session restore failed after {max_resets} driver reset(s)")
                return False, current_driver

            task_log(f"[Worker {worker_id}] login/session invalid; resetting driver {reset_count + 1}/{max_resets}")

            try:
                replaced_driver = current_driver
                if current_driver is not None:
                    try:
                        current_driver.quit()
                    except Exception as e:
                        task_log(f"[Worker {worker_id}] old driver quit failed during reset: {e}")

                current_driver = self._create_new_driver()
                task_log(f"[Worker {worker_id}] [OK] new worker driver created")

                if self.login_task:
                    if not self._restore_login_status(current_driver, worker_id, task_log, task_log_dir):
                        task_log(f"[Worker {worker_id}] [FAIL] login restore failed after reset {reset_count + 1}")
                        continue
                elif self.initial_url:
                    current_driver.get(self.initial_url)
                    time.sleep(0.5)

                self._register_replacement_driver(
                    worker_id,
                    replaced_driver,
                    current_driver,
                    was_main_driver=worker_is_main_driver,
                )
                task_log(f"[Worker {worker_id}] [OK] live driver registry updated")

            except Exception as e:
                task_log(f"[Worker {worker_id}] driver reset failed: {e}")
                continue

        return False, current_driver

    def _generate_replay_curl_with_csrf(self, request: Dict, worker_id: int, task_log) -> str:
        """
        curl(CSRF token)

        1. worker_store(account_manager)
        2. bodycsrf
        3. , worker_storetoken

        Args:
            request:
            worker_id: Worker
            task_log:
        """
        method = request.get("method", "GET")
        url = request.get("url", "")
        headers = request.get("headers", {})
        body = request.get("body")

        parts = [f"curl --compressed -X {shlex.quote(method)}"]
        parts.append(shlex.quote(url))

        skip_headers = {
            "cookie",
            "authorization",
            "host",
            "content-length",
            "proxy-connection",
            "connection",
            "accept-encoding",
        }
        for key, value in headers.items():
            if key.lower() not in skip_headers:
                parts.append(f"-H {shlex.quote(f'{key}: {value}')}")

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
                        task_log(f"[Worker {worker_id}] [OK] CSRF token: {csrf_key}")

            parts.append(f"-d {shlex.quote(body_str)}")

        if credentials:
            cookies = credentials.get("cookies", [])
            if cookies:
                cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
                parts.append(f"-H {shlex.quote(f'Cookie: {cookie_str}')}")

            cred_headers = credentials.get("headers", {})
            if "Authorization" in cred_headers:
                auth_header = f"Authorization: {cred_headers['Authorization']}"
                parts.append(f"-H {shlex.quote(auth_header)}")
            else:
                from attack_agent.request_utils import extract_auth_token
                token = extract_auth_token(credentials)
                if token:
                    parts.append(f"-H {shlex.quote(f'Authorization: Bearer {token}')}")

        parts.append('-w "\\nHTTP_STATUS:%{http_code}"')
        return " \\\n  ".join(parts)

    def _execute_replay_curl(self, command: str) -> Dict[str, Any]:
        """curl"""
        proc = None
        timeout = self._parse_timeout_env("SEMSCANNER_REPLAY_TIMEOUT", 120)
        try:
            proc = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            stdout, stderr = proc.communicate(timeout=timeout) if timeout is not None else proc.communicate()

            from attack_agent.request_utils import parse_http_status_from_response
            http_status, response_body = parse_http_status_from_response(stdout)

            return {
                "command": command,
                "success": proc.returncode == 0,
                "stdout": response_body,
                "fullout": stdout,
                "stderr": stderr,
                "returncode": proc.returncode,
                "http_status": http_status
            }
        except subprocess.TimeoutExpired:
            if proc is not None:
                stdout, stderr, cleanup_complete = kill_process_group_and_collect(proc)
            else:
                stdout, stderr = "", ""
                cleanup_complete = True
            cleanup_note = (
                "killed replay process group"
                if cleanup_complete
                else "killed replay process group; pipe cleanup remained incomplete"
            )
            return {
                "command": command,
                "success": False,
                "stdout": "",
                "fullout": stdout or "",
                "stderr": (stderr or "") + f"\nTimeout after replay subprocess timeout; {cleanup_note}",
                "error": f"Replay curl timeout after {timeout} seconds",
                "timeout": True,
                "returncode": -9,
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

    def _truncate_for_log(self, text: Any, limit: int = 4000) -> str:
        text = "" if text is None else str(text)
        if len(text) <= limit:
            return text
        return f"{text[:limit]}... [truncated {len(text) - limit} chars]"

    def _wait_for_page_stable(self, driver, timeout=10, check_interval=0.5):
        """
        1.  document.readyState
        2.  DOM ()
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

    def _execute_task_with_worker(self, task, task_num: int, total_tasks: int,
                                  task_timeout: int = None) -> Dict:
        """
        worker driver(:)
        
        1.  Driver : Driver , ,  Driver.
        2. : Driver .
        """
        task_started_at = time.time()
        setattr(task, "_semscanner_started_at", task_started_at)
        if task_timeout is not None:
            setattr(task, "_semscanner_deadline", task_started_at + task_timeout)
        else:
            setattr(task, "_semscanner_deadline", None)

        worker_id = None
        worker_driver = None
        task_log_dir = self.log_dir / "tasks" / getattr(task, "task_id", "pending")

        def task_log(*args):
            self._log(*args)

        try:
            worker_id, worker_driver = self.driver_queue.get()

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

            task_log(f"{'='*70}")
            task_log(f"[ATTACK TASK] {task.task_id}")
            task_log(f"{'='*70}")
            print(f"\n{'~'*70}")
            print(f"[Task {task_num}/{total_tasks}] {task.task_id} - Start")
            task_log(f"[Worker] Using worker {worker_id}; max driver resets: 20")

            is_valid, worker_driver = self._ensure_login_and_update_credentials(
                worker_driver, worker_id, task_log, task_log_dir, max_resets=20
            )

            if not is_valid:
                error_msg = "Worker driver failed to restore login/session after 20 reset attempts"
                task_log(f"[Driver Error] {error_msg}")
                print(f"[Task {task.task_id}] {error_msg}")
                if worker_id is not None and worker_driver is not None:
                    self.driver_queue.put((worker_id, worker_driver))
                    worker_id = None
                    worker_driver = None
                return {"error": error_msg}

        except Exception as e:
            task_log(f"[Driver Error] Driver acquisition/reset failed: {e}")
            if worker_id is not None and worker_driver is not None:
                self.driver_queue.put((worker_id, worker_driver))
                worker_id = None
                worker_driver = None
            return {"error": f"Driver acquisition/reset failed: {e}"}

        try:
            if self._task_deadline_exceeded(task):
                return self._task_timeout_result(task_timeout)

            task_log(f"\n[Step 1: Replay Request Generation]")
            curl_command = self._generate_replay_curl_with_csrf(task.target_request, worker_id, task_log)
            task_log(f"[Generated CURL Command]:\n{curl_command}\n")

            task_log(f"[Step 2: Replay Request Execution]")
            replay_result = self._execute_replay_curl(curl_command)
            
            http_status = replay_result.get('http_status')
            task_log(f"  Curl Success: {replay_result.get('success', False)}")
            task_log(f"  HTTP Status: {http_status}")

            response_body = replay_result.get('stdout', '')
            task_log(f"  Response Body: {self._truncate_for_log(response_body)}")

            # =================================================================
            # =================================================================
            
            if not replay_result.get('success') or not http_status:
                stderr = self._truncate_for_log(replay_result.get('stderr', ''), 1200)
                fullout_tail = self._truncate_for_log(replay_result.get('fullout', '')[-1200:], 1200)
                task_log(f"  Curl Return Code: {replay_result.get('returncode')}")
                if stderr:
                    task_log(f"  Curl Stderr: {stderr}")
                if fullout_tail:
                    task_log(f"  Curl Output Tail: {fullout_tail}")
                error_msg = f"Replay failed (Status: {http_status}, returncode: {replay_result.get('returncode')}). Aborting task to save tokens."
                recovery_attempted = False
                recovery_succeeded = False
                if replay_result.get("timeout"):
                    recovery_attempted = True
                    recovery_succeeded, worker_driver = self._recover_session_after_replay_timeout(
                        worker_id,
                        worker_driver,
                        task_log,
                        task_log_dir,
                    )
                    task_log(
                        f"  Session recovery after replay timeout: "
                        f"{'succeeded' if recovery_succeeded else 'failed'}"
                    )
                task_log(f"  {error_msg}")
                print(f"[Task {task.task_id}] {error_msg}")
                return {
                    "error": error_msg,
                    "skipped": True,
                    "timeout": bool(replay_result.get("timeout")),
                    "session_recovery_attempted": recovery_attempted,
                    "session_recovered": recovery_succeeded,
                }

            if http_status in [403, 401] and task.vuln_type not in ["AUTH_BYPASS", "IDOR"]:
                error_msg = f"Target returned {http_status} (Access Denied). Aborting."
                task_log(f"  🛑 {error_msg}")
                return {"error": error_msg, "skipped": True}

            raw_body = replay_result.get('stdout', '')
            
            processed_body = extract_useful_response(raw_body, max_length=4000) 
            
            task.target_request['response_body'] = processed_body
            task.target_request['response_status'] = http_status
            
            task_log(f"  [OK] Request context updated with fresh replay data.")
            task_log(f"  [OK] Response Body optimized for LLM ({len(processed_body)} chars).")
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
                        task_log(f"[Token Inject] Token ")
                except Exception as e:
                    task_log(f"[Token Inject] : {e}")

            task_log(f"\n[Step 3: Attack Execution]")
            tracker.set_category(_VULN_CATEGORY_MAP.get(task.vuln_type, f"attack_{task.vuln_type.lower()}"))
            credentials = worker_store.get_credentials()
            agent = self._create_agent_for_task(task.vuln_type, task_log_dir, driver=worker_driver)
            if hasattr(agent, "set_deadline"):
                agent.set_deadline(getattr(task, "_semscanner_deadline", None))

            if task.vuln_type in ["IDOR", "AUTH_BYPASS", "PRIVILEGE_ESCALATION", "BUSINESS_LOGIC"]:
                is_multi_account = "->" in task.account_identifier
                if is_multi_account:
                    # Multi-account IDOR testing is not supported in this release.
                    # Fall through to single-point testing instead.
                    result = agent.test_single_point(
                        task_description=task.task_description,
                        target_request=task.target_request,
                        credentials=credentials
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
                print(f"[Task {task.task_id}] Worker {worker_id} driver error during execution")
                return {
                    "error": "Driver crashed during execution",
                    "traceback": err_msg
                }
            else:
                task_log(f"[Worker {worker_id}] [FAIL] WebDriver Error: {e}")
                return {"error": str(e)}
        # =================================================================

        except Exception as e:
            import traceback
            print(f"[Worker {worker_id}] [FAIL] Exception: {e}")
            print(traceback.format_exc())
            return {
                "error": str(e),
                "traceback": traceback.format_exc()
            }

        finally:
            if worker_id is not None and worker_driver is not None:
                self.driver_queue.put((worker_id, worker_driver))

    def _save_results(self):
        """"""
        output_file = self.log_dir / "attack_results.json"
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self._log(f"[Error] Failed to save results: {e}")

    def _build_xss_beacon_log_candidates(self) -> List[Path]:
        candidates = []
        for env_name in ("SEMSCANNER_XSS_BEACON_LOG", "XSS_BEACON_LOG", "BEACON_LOG_FILE"):
            value = os.environ.get(env_name)
            if value:
                candidates.append(Path(value))

        candidates.append(Path("http_captured.txt"))
        for parent in [self.log_dir, *self.log_dir.parents]:
            candidates.append(parent / "http_captured.txt")
            candidates.append(parent / "logs" / "http_captured.txt")
            candidates.append(parent / "xss_beacon" / "http_captured.txt")

        deduped = []
        seen = set()
        for path in candidates:
            key = str(path)
            if key not in seen:
                deduped.append(path)
                seen.add(key)
        return deduped

    def _read_xss_beacon_logs(self):
        contents = []
        loaded_paths = []
        for path in self._build_xss_beacon_log_candidates():
            if not path.exists():
                continue
            try:
                contents.append(path.read_text(encoding="utf-8", errors="ignore"))
                loaded_paths.append(path)
            except Exception as e:
                self._log(f"[XSS Reconcile] Failed to read beacon log {path}: {e}")
        return "\n".join(contents), loaded_paths

    def _collect_xss_random_ids(self, value: Any) -> Set[str]:
        tokens = set()

        def normalize_token(raw_value):
            if raw_value is None:
                return None
            token = str(raw_value).strip()
            if re.fullmatch(r"\d+", token):
                return token
            return None

        def walk(obj):
            if isinstance(obj, dict):
                for key, nested_value in obj.items():
                    if key == "random_id":
                        token = normalize_token(nested_value)
                        if token:
                            tokens.add(token)
                    else:
                        walk(nested_value)
            elif isinstance(obj, list):
                for item in obj:
                    walk(item)

        walk(value)
        return tokens

    def _xss_beacon_log_has_token(self, beacon_content: str, token: str) -> bool:
        return re.search(rf"(?<!\d){re.escape(token)}(?!\d)", beacon_content) is not None

    def _reconcile_xss_beacon_results(self):
        beacon_content, loaded_paths = self._read_xss_beacon_logs()
        if not beacon_content:
            self._log("[XSS Reconcile] No readable beacon log content; skipping.")
            return []

        updates = []
        for entry in self.results:
            if entry.get("vuln_type") != "XSS":
                continue
            result = entry.get("result")
            if not isinstance(result, dict) or result.get("vulnerable") is True:
                continue

            tokens = self._collect_xss_random_ids(result)
            matched_tokens = sorted(
                token for token in tokens
                if self._xss_beacon_log_has_token(beacon_content, token)
            )
            if not matched_tokens:
                continue

            result["vulnerable"] = True
            result["detected_in_phase2"] = True
            result["detection_method"] = "post_patrol_beacon"
            result["post_patrol_beacon_tokens"] = matched_tokens
            result["post_patrol_beacon_logs"] = [str(path) for path in loaded_paths]

            note = f"Post-patrol beacon detected token(s): {', '.join(matched_tokens)}"
            if result.get("note"):
                result["note"] = f"{result['note']}; {note}"
            else:
                result["note"] = note

            updates.append({
                "task_id": entry.get("task_id"),
                "tokens": matched_tokens,
            })

        if updates:
            details = ", ".join(
                f"{item['task_id']}[{','.join(item['tokens'])}]" for item in updates
            )
            self._log(f"[XSS Reconcile] Marked {len(updates)} XSS task(s) vulnerable: {details}")
        else:
            self._log("[XSS Reconcile] No additional XSS beacon matches found.")
        return updates

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

        p_log(f"Started with driver: {driver.title}")

        try:
            known_urls = set(list(self.crawler.store.pages.keys()))
            scan_queue = list(known_urls)
            visited_in_patrol = set()
            raw_max_visits = os.environ.get("SEMSCANNER_SMART_PATROL_MAX_VISITS", "400")
            try:
                max_visits = int(float(str(raw_max_visits).strip()))
            except ValueError:
                max_visits = 400
                p_log(f"Invalid SEMSCANNER_SMART_PATROL_MAX_VISITS={raw_max_visits!r}; using 400")
            if max_visits <= 0:
                max_visits = 400
            
            p_log(f"Base Queue: {len(scan_queue)} known pages")
            p_log(f"Max visits: {max_visits}")
            
            new_links_found = 0
            
            DANGEROUS_KEYWORDS = [
                "logout", "signout", "logoff", "sign_out", "log_out", "exit", "quit",
                "delete", "remove", "destroy", "erase", "purge", "trash", "drop", 
                "reset", "clear", "disable", "deactivate", "ban", "block", "suspend",
                "password", "passwd", "pwd", "unsubscribe", "cancel", "abort"
            ]

            while scan_queue:
                if len(visited_in_patrol) >= max_visits:
                    p_log(f"[STOP] Max visits reached: {max_visits}. Remaining queued URLs: {len(scan_queue)}")
                    break

                url = scan_queue.pop(0)
                
                if url in visited_in_patrol: continue
                if self.url_scope and not self.url_scope.allows_navigation(url):
                    p_log(f"Skipping out-of-scope URL: {url}")
                    continue
                
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
                            if not href:
                                continue
                            resolved = (
                                self.url_scope.resolve(href, current_url=url)
                                if self.url_scope else href
                            )
                            if self.url_scope and not self.url_scope.allows_navigation(
                                resolved
                            ):
                                continue
                            clean_href = (
                                resolved.split('#')[0]
                                if '#' in resolved and '/#/' not in resolved
                                else resolved
                            )
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
                        p_log(f"CRITICAL: Driver died at {url}. Abandoning Smart Patrol.")
                        p_log(f"Error details: {err_msg}")
                        try: driver.quit()
                        except: pass
                        return
                    # =========================================================
                    
                    elif "unexpected alert open" in err_msg or isinstance(e, UnexpectedAlertPresentException):
                        try:
                            alert = driver.switch_to.alert
                            p_log(f"UNEXPECTED ALERT at {url}: {alert.text}")
                            alert.accept()
                        except: pass
                    else:
                        p_log(f"Error visiting {url}: {e}")

            p_log(f"[OK] Scan complete. Visited {len(visited_in_patrol)} pages. Found {new_links_found} new URLs.")

        except Exception as e:
            p_log(f"Fatal error: {e}")

    def execute_tasks_from_queue(self, task_queue, max_workers: int = None,
                                 planning_done_event=None) -> List[Dict]:
        """
        (worker driver)

        :Phase 4 -> Phase 5

        Args:
            task_queue: queue.Queue, 
            max_workers: (worker_drivers)
            planning_done_event: set by the producer when attack planning has
                finished, used as a fallback if the termination sentinel is lost

        Returns:

        """
        if max_workers is None:
            max_workers = 1

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
        def record_queue_result(task_obj, result):
            nonlocal completed_count
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
                self._log(f"  [{completed_count}/?] {task_obj.task_id} - [FAIL] ERROR")
            elif result.get("vulnerable") is True:
                self._log(f"  [{completed_count}/?] {task_obj.task_id} - [OK] VULNERABLE")
            elif result.get("vulnerable") is False:
                self._log(f"  [{completed_count}/?] {task_obj.task_id} - [OK] SAFE")
            else:
                self._log(f"  [{completed_count}/?] {task_obj.task_id} - ? PENDING")

        def collect_done_futures(futures):
            remaining = []
            completed = 0
            now = time.time()

            for future, task_obj, submitted_at, task_timeout in futures:
                if future.done():
                    try:
                        record_queue_result(task_obj, future.result())
                    except Exception as e:
                        self._log(f"  [{completed_count}/?] {task_obj.task_id} - [FAIL] EXCEPTION: {e}")
                        record_queue_result(task_obj, {"error": str(e)})
                    completed += 1
                else:
                    deadline = getattr(task_obj, "_semscanner_deadline", None)
                    if deadline is not None and now > deadline and not getattr(task_obj, "_semscanner_deadline_warned", False):
                        if future.running():
                            self._log(
                                f"  [Timeout] {task_obj.task_id} exceeded {task_timeout}s; "
                                "waiting for cooperative task exit"
                            )
                        else:
                            self._log(
                                f"  [Timeout] {task_obj.task_id} exceeded {task_timeout}s before worker start; "
                                "keeping it pending"
                            )
                        setattr(task_obj, "_semscanner_deadline_warned", True)
                    remaining.append((future, task_obj, submitted_at, task_timeout))

            return remaining, completed

        self._log(f"[Phase 1] Parallel Attack Execution from Queue")
        self._log(f"  Submitting tasks to thread pool as they arrive...")
        self._log(f"")

        executor = ThreadPoolExecutor(max_workers=max_workers)
        try:
            futures = []

            while True:
                try:
                    task = task_queue.get(timeout=5)
                except Empty:
                    if planning_done_event is not None and planning_done_event.is_set():
                        self._log(
                            "\n[Queue] Planning thread finished and queue is empty; "
                            "assuming termination signal was already consumed or lost"
                        )
                        self._log(f"[Queue] Total tasks received: {len(tasks_received)}")
                        self._log(f"[Queue] Waiting for {len(futures)} running task(s) to complete...")
                        break

                    futures, completed_now = collect_done_futures(futures)
                    self._log(
                        f"[Queue] Waiting for planner... {completed_now} completed, "
                        f"{len(futures)} running"
                    )
                    continue

                if task is None:
                    self._log(f"\n[Queue] Received termination signal")
                    self._log(f"[Queue] Total tasks received: {len(tasks_received)}")
                    self._log(f"[Queue] Waiting for {len(futures)} running task(s) to complete...")
                    break

                tasks_received.append(task)
                self._log(f"[Queue] Task received: {task.task_id} (total: {len(tasks_received)})")

                while len(futures) >= max_workers:
                    done, _ = wait(
                        [future for future, _, _, _ in futures],
                        timeout=5,
                        return_when=FIRST_COMPLETED
                    )
                    if done:
                        remaining = []
                        for future, task_obj, submitted_at, task_timeout in futures:
                            if future in done:
                                try:
                                    record_queue_result(task_obj, future.result())
                                except Exception as e:
                                    self._log(f"  [{completed_count}/?] {task_obj.task_id} - [FAIL] EXCEPTION: {e}")
                                    record_queue_result(task_obj, {"error": str(e)})
                            else:
                                remaining.append((future, task_obj, submitted_at, task_timeout))
                        futures = remaining
                    else:
                        futures, completed_now = collect_done_futures(futures)
                        self._log(f"[Queue] Backpressure wait... {completed_now} completed, {len(futures)} running")

                task_timeout = self._timeout_for_task(task)
                timeout_label = f"{task_timeout}s" if task_timeout is not None else "unlimited"
                self._log(f"[Queue] Submitting {task.task_id} with timeout: {timeout_label}")
                future = executor.submit(
                    self._execute_task_with_worker,
                    task,
                    len(tasks_received),
                    "?",
                    task_timeout,
                )
                futures.append((future, task, time.time(), task_timeout))

            self._log(f"\n[Queue] Waiting for final {len(futures)} task(s)...")
            while futures:
                future_map = {future: (task_obj, submitted_at, task_timeout) for future, task_obj, submitted_at, task_timeout in futures}
                done, _ = wait(future_map.keys(), timeout=5, return_when=FIRST_COMPLETED)

                if done:
                    remaining = []
                    for future, task_obj, submitted_at, task_timeout in futures:
                        if future in done:
                            try:
                                record_queue_result(task_obj, future.result())
                            except Exception as e:
                                self._log(f"  [{completed_count}/?] {task_obj.task_id} - [FAIL] EXCEPTION: {e}")
                                record_queue_result(task_obj, {"error": str(e)})
                        else:
                            remaining.append((future, task_obj, submitted_at, task_timeout))
                    futures = remaining
                else:
                    futures, completed_now = collect_done_futures(futures)
                    self._log(f"[Queue] Waiting... {completed_now} completed, {len(futures)} still running")
        finally:
            self._log(f"\n[Cleanup] Shutting down executor (wait=False)...")
            executor.shutdown(wait=False, cancel_futures=True)
            self._log(f"[Cleanup] Executor shutdown complete")

        phase1_duration = time.time() - start_time
        self._phase1_duration = phase1_duration
        self._log(f"")
        self._log(f"[Phase 1 Complete]  Time: {phase1_duration:.1f}s")
        self._log(f"")


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
            self._log("No healthy drivers available for Phase 2. Skipping.")
            self._save_results()
            return self.results

        patrol_info = available_drivers.pop(0)
        patrol_driver = patrol_info[0]
        
        trigger_drivers = available_drivers
        
        self._log(f"Assigned [{patrol_info[1]}] to Smart Patrol")


        with ThreadPoolExecutor(max_workers=1) as executor:
            futures = []

            futures.append(executor.submit(self._run_smart_patrol, patrol_driver))

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self._log(f"Phase 2 Thread Error: {e}")

        self._log("[Phase 2] Complete.")
        phase2_duration = time.time() - phase2_start
        self._log(f"[Phase 2 Complete]  Time: {phase2_duration:.1f}s")

        total_duration = time.time() - start_time

        self._phase1_duration = phase1_duration
        self._phase2_duration = phase2_duration

        self._reconcile_xss_beacon_results()

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
