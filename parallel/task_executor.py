# -*- coding: utf-8 -*-
"""
Independent Task Executor - Execute a single task using an independent driver
"""

import time
from typing import Dict, Any, Optional
from pathlib import Path

from seleniumwire import webdriver  # Use selenium-wire to support network request capture
from selenium.webdriver.common.by import By

from crawl.sensors import Sensors
from crawl.Actuators import Actuators
from crawl.Bridge import Bridge
from capture.network_capture import NetworkCapture
from crawl.tracer import ExecutionTracer
from app_info.models import PageInfo, NetworkRequest, Edge
from task.tasks import Task


class IndependentTaskExecutor:
    """
    Independent Task Executor

    Features:
    1. Execute a single task using an independent driver
    2. Create an independent component chain (sensors, bridge, tracer, etc.)
    3. Record complete trace data to shared store
    4. Thread-safe new page discovery and caching

    Key design:
    - Each task has an independent component chain
    - All components share the same driver (obtained from the pool)
    - Write to shared store (with lock protection)
    """

    def __init__(self, shared_store, client, base_url: str, task_gen=None, content_index=None, debug_session: bool = True):
        """
        Initialize the independent task executor

        Args:
            shared_store: Shared WebAppStore instance (thread-safe)
            client: OpenAI client
            base_url: Base URL
            task_gen: TaskGenerator instance (for new page task generation)
            content_index: ContentDedupeIndex instance (for page deduplication)
            debug_session: Whether to enable session state debug (default True)
        """
        self.shared_store = shared_store
        self.client = client
        self.base_url = base_url
        self.task_gen = task_gen
        self.content_index = content_index  # Page dedup index
        self.debug_session = debug_session  # Session debug switch

        # Current task context (for callbacks)
        self._current_driver: Optional[webdriver.Chrome] = None
        self._current_sensors: Optional[Sensors] = None
        self._current_network_capture: Optional[NetworkCapture] = None

    def _capture_session_state(self, driver: webdriver.Chrome, task_id: str, phase: str) -> Dict[str, Any]:
        """
        Capture the driver's current session state (for debugging login state loss issues)

        Args:
            driver: WebDriver instance
            task_id: Task ID
            phase: Phase identifier ("BEFORE" or "AFTER")

        Returns:
            Session state dictionary
        """
        state = {
            "task_id": task_id,
            "phase": phase,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "current_url": None,
            "page_title": None,
            "cookies": [],
            "localStorage": {},
            "sessionStorage": {},
            "error": None
        }

        try:
            # Get current URL
            state["current_url"] = driver.current_url
        except Exception as e:
            state["error"] = f"Failed to get URL: {e}"

        try:
            # Get page title
            state["page_title"] = driver.title
        except Exception as e:
            state["error"] = f"Failed to get title: {e}"

        try:
            # Get all cookies
            cookies = driver.get_cookies()
            # Only keep key info to avoid overly long logs
            state["cookies"] = [
                {
                    "name": c["name"],
                    "value": c["value"][:20] + "..." if len(c.get("value", "")) > 20 else c.get("value", ""),
                    "domain": c.get("domain"),
                    "path": c.get("path"),
                    "expiry": c.get("expiry")
                }
                for c in cookies
            ]
        except Exception as e:
            state["error"] = f"Failed to get Cookies: {e}"

        try:
            # Get localStorage
            local_storage = driver.execute_script("return JSON.stringify(localStorage);")
            state["localStorage"] = local_storage if local_storage else "{}"
        except Exception as e:
            state["error"] = f"Failed to get localStorage: {e}"

        try:
            # Get sessionStorage
            session_storage = driver.execute_script("return JSON.stringify(sessionStorage);")
            state["sessionStorage"] = session_storage if session_storage else "{}"
        except Exception as e:
            state["error"] = f"Failed to get sessionStorage: {e}"

        return state

    def _log_session_state(self, driver: webdriver.Chrome, task_id: str, phase: str, log_file: str = None):
        """
        Record and print the driver's session state

        Args:
            driver: WebDriver instance
            task_id: Task ID
            phase: Phase identifier ("BEFORE" or "AFTER")
            log_file: Optional log file path (if provided, also writes to file)
        """
        state = self._capture_session_state(driver, task_id, phase)

        # Generate log content
        log_lines = []
        log_lines.append(f"\n{'='*70}")
        log_lines.append(f"[SESSION-DEBUG] Task {task_id} - {phase}")
        log_lines.append(f"{'='*70}")
        log_lines.append(f"Time: {state['timestamp']}")
        log_lines.append(f"Current URL: {state['current_url']}")
        log_lines.append(f"Page title: {state['page_title']}")

        # Detect if on login page (simple check)
        is_login_page = False
        if state['current_url']:
            url_lower = state['current_url'].lower()
            title_lower = (state['page_title'] or "").lower()
            is_login_page = ('login' in url_lower or 'signin' in url_lower or
                           'login' in title_lower or 'signin' in title_lower)

        if is_login_page:
            log_lines.append(f"WARNING: Possibly on login page!")

        log_lines.append(f"\nCookies ({len(state['cookies'])} items):")
        if state['cookies']:
            for cookie in state['cookies']:
                # Highlight session-related cookies
                marker = "[KEY]" if any(k in cookie['name'].lower() for k in ['session', 'token', 'auth', 'jwt']) else "  "
                log_lines.append(f"  {marker} {cookie['name']}: {cookie['value']}")
                log_lines.append(f"     domain={cookie['domain']}, path={cookie['path']}")
        else:
            log_lines.append("  (no cookies)")

        # localStorage and sessionStorage only print key names (values can be very long)
        try:
            ls_data = eval(state['localStorage']) if state['localStorage'] != "{}" else {}
            if ls_data:
                log_lines.append(f"\nLocalStorage ({len(ls_data)} items):")
                for key in ls_data.keys():
                    marker = "[KEY]" if any(k in key.lower() for k in ['session', 'token', 'auth', 'jwt']) else "  "
                    log_lines.append(f"  {marker} {key}")
            else:
                log_lines.append(f"\nLocalStorage: (empty)")
        except:
            log_lines.append(f"\nLocalStorage: (parse failed)")

        try:
            ss_data = eval(state['sessionStorage']) if state['sessionStorage'] != "{}" else {}
            if ss_data:
                log_lines.append(f"\nSessionStorage ({len(ss_data)} items):")
                for key in ss_data.keys():
                    marker = "[KEY]" if any(k in key.lower() for k in ['session', 'token', 'auth', 'jwt']) else "  "
                    log_lines.append(f"  {marker} {key}")
            else:
                log_lines.append(f"\nSessionStorage: (empty)")
        except:
            log_lines.append(f"\nSessionStorage: (parse failed)")

        if state['error']:
            log_lines.append(f"\nError: {state['error']}")

        log_lines.append(f"{'='*70}\n")

        # Generate log text
        log_text = "\n".join(log_lines)

        # Write to task log file (no longer output to stdout to reduce main log noise)
        if log_file:
            try:
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write(log_text + "\n")
            except Exception as e:
                print(f"[SESSION-DEBUG] Cannot write to log file: {e}")

    def execute_task(self, task: Task, driver: webdriver.Chrome, driver_info: str = "unknown") -> Dict[str, Any]:
        """
        Execute a single task using the specified driver

        Args:
            task: Task to execute
            driver: Driver obtained from the pool
            driver_info: Driver info ("main" or "sub_{number}"), used for screenshot directory naming

        Returns:
            Execution result dictionary:
            {
                "task_id": str,
                "status": "success" | "error",
                "trace": TaskRunTrace (if successful),
                "error": str (if failed)
            }
        """
        print(f"\n[IndependentExecutor] Starting task execution: {task.task_id}")
        print(f"  Driver: {driver_info}")
        print(f"  Description: {task.description}")
        print(f"  URL: {task.initial_url}")

        try:
            # ===== Step 1: Create independent component chain =====
            sensors = Sensors(driver, use_improved_locator=True)
            actuators = Actuators(sensors)
            bridge = Bridge(
                sensors=sensors,
                actuators=actuators,
                client=self.client
            )
            network_capture = NetworkCapture(driver)

            # Save current context (for callbacks)
            self._current_driver = driver
            self._current_sensors = sensors
            self._current_network_capture = network_capture

            # ===== Step 2: Create independent Tracer =====
            tracer = ExecutionTracer(
                store=self.shared_store,  # Shared store (with lock protection)
                network_capture=network_capture,
                on_new_page=self._on_new_page_discovered_parallel,  # Lightweight callback
                construct_edge=self._construct_edge_parallel,       # Lightweight callback
                debug=False
            )

            bridge.set_tracer(
                tracer=tracer,
                task_queue=None,  # No need for dynamic task generation during parallel execution
                store=self.shared_store
            )

            # ===== Step 3: Load page abstract (from cache) =====
            driver.get(task.initial_url)
            time.sleep(0.6)

            # Create screenshot directory with driver info identifier
            photo_dir = self.shared_store.traces_dir / f"{driver_info}_{task.task_id}"
            photo_dir.mkdir(parents=True, exist_ok=True)  # Ensure directory exists

            # Create session debug log file path
            session_log_file = photo_dir / "session_debug.log"

            # Load page abstract and mapping from shared store
            page = self.shared_store.get_page(task.initial_url)
            if page and page.abstract_page:
                sensors.abstract_page = page.abstract_page
                print(f"[IndependentExecutor] Loaded page abstract from cache ({len(page.abstract_page)} chars)")

                # ===== DEBUG: Check cached mappings =====
                print(f"[IndependentExecutor] [DEBUG] Cached mapping info:")
                print(f"  - actions_mapping: {len(page.actions_mapping) if page.actions_mapping else 0} items")
                print(f"  - event_mapping: {len(page.event_mapping) if page.event_mapping else 0} items")
                if page.event_mapping:
                    print(f"  - event_mapping keys: {list(page.event_mapping.keys())[:5]}...")  # Show first 5

                # Restore actions_mapping
                if page.actions_mapping:
                    sensors.actions_mapping.clear()
                    for action_id, locators_info in page.actions_mapping.items():
                        sensors.actions_mapping.set_mapping(
                            int(action_id),
                            locators_info
                        )
                    print(f"[IndependentExecutor] Restored {len(page.actions_mapping)} element mappings")
                else:
                    print(f"[IndependentExecutor] Warning: No actions_mapping in page cache")

                # Restore event_mapping (fix bug: previously missing this part caused TRIGGER command failure)
                if page.event_mapping:
                    sensors.event_mapping.clear()
                    for event_id, event_info in page.event_mapping.items():
                        sensors.event_mapping.mapping[int(event_id)] = event_info
                    # Update id_counter to max ID + 1
                    max_event_id = max(int(k) for k in page.event_mapping.keys())
                    sensors.event_mapping.id_counter = max_event_id + 1
                    print(f"[IndependentExecutor] Restored {len(page.event_mapping)} event mappings")
                    print(f"[IndependentExecutor] [DEBUG] Restored event IDs: {list(sensors.event_mapping.mapping.keys())[:5]}...")
                else:
                    print(f"[IndependentExecutor] Warning: No event_mapping in page cache")

                # ===== DEBUG: Verify restored state =====
                print(f"[IndependentExecutor] [DEBUG] Post-restoration sensors state:")
                print(f"  - sensors.actions_mapping: {len(sensors.actions_mapping.mapping)} items")
                print(f"  - sensors.event_mapping: {len(sensors.event_mapping.mapping)} items")
            else:
                # Fallback: rescan
                print(f"[IndependentExecutor] Cache not found, rescanning")
                sensors.update_abstract_page()

                # DEBUG: Record scan log (write to file)
                if hasattr(sensors, 'debug_scan_log'):
                    debug_log_path = photo_dir / "scan_debug.log"
                    with open(debug_log_path, 'w', encoding='utf-8') as f:
                        f.write("\n".join(sensors.debug_scan_log))
                    print(f"[IndependentExecutor] Scan debug log saved: {debug_log_path}")

            # SESSION DEBUG: Record session state before task execution
            if self.debug_session:
                self._log_session_state(driver, task.task_id, "BEFORE", log_file=str(session_log_file))

            # ===== Step 4: Start trace recording =====
            tracer.start_task(task.task_id, task.description)

            # ===== Step 5: Execute task =====
            network_capture.clear_requests()

            # photo_dir already defined in Step 3
            bridge.run_task(task, photo_dir=photo_dir, logging_in=False)

            # ===== Step 6: End trace and save =====
            trace = tracer.end_task()
            if trace:
                self.shared_store.save_trace(trace)  # Thread-safe
                print(f"[IndependentExecutor] Trace saved")

            # SESSION DEBUG: Record session state after task execution
            if self.debug_session:
                self._log_session_state(driver, task.task_id, "AFTER", log_file=str(session_log_file))

            print(f"[IndependentExecutor] Task completed: {task.task_id}\n")

            return {
                "task_id": task.task_id,
                "status": "success",
                "trace": trace
            }

        except Exception as e:
            print(f"[IndependentExecutor] Task failed: {task.task_id} - {e}")
            import traceback
            traceback.print_exc()

            return {
                "task_id": task.task_id,
                "status": "error",
                "error": str(e)
            }

        finally:
            # Clean up context
            self._current_driver = None
            self._current_sensors = None
            self._current_network_capture = None

    def _on_new_page_discovered_parallel(self, url: str):
        """
        New page callback during parallel execution

        Content dedup check (consistent with serial mode)
        Cache page info (thread-safe)
        Generate tasks (consistent with serial mode)
        """
        # Check if already processed (avoid duplication)
        if self.shared_store.has_page(url):
            return

        print(f"[ParallelNewPage] New page discovered: {url}")

        try:
            # Wait for page to stabilize
            time.sleep(0.6)

            driver = self._current_driver
            sensors = self._current_sensors
            network_capture = self._current_network_capture

            if not all([driver, sensors, network_capture]):
                print(f"[ParallelNewPage] Context incomplete, skipping")
                return

            # Fix: Add content dedup check (consistent with serial mode)
            if self.content_index:
                try:
                    html_src = driver.page_source
                    dedup_result = self.content_index.classify(url, html_src)
                    is_new = bool(dedup_result.get("is_new", True))

                    if not is_new:
                        # Duplicate page: skip processing
                        cluster_id = dedup_result.get("cluster_id")
                        repr_url = dedup_result.get("repr_url")
                        print(f"[ParallelNewPage] Duplicate page content, skipping: {url} (cluster: {cluster_id}, repr: {repr_url})")
                        return
                except Exception as e:
                    print(f"[ParallelNewPage] Dedup check failed, continuing: {e}")
                    # Dedup failure does not affect page processing
            else:
                print(f"[ParallelNewPage] content_index not provided, skipping dedup check")

            # 1. Capture network requests
            captured_requests = network_capture.capture_current(url, exclude_static=True)
            network_requests = [
                NetworkRequest(
                    method=req.get('method', ''),
                    url=req.get('url', ''),
                    headers=req.get('headers', {}),
                    query_params=req.get('query_params', {}),
                    body=req.get('body'),
                    response_status=req.get('response', {}).get('status'),
                    response_headers=req.get('response', {}).get('headers', {}),
                    response_body=req.get('response', {}).get('body'),
                )
                for req in captured_requests
            ]

            # 2. Collect page links
            outgoing_links = []
            try:
                elements = driver.find_elements(By.TAG_NAME, 'a')
                for elem in elements:
                    href = elem.get_attribute('href')
                    if href and '127.0.0.1' in href:
                        outgoing_links.append(href.strip())
                outgoing_links = list(set(outgoing_links))  # Deduplicate
            except Exception as e:
                print(f"[ParallelNewPage] Link collection failed: {e}")

            # 3. Rescan current page for latest DOM structure (fix: consistent with serial mode)
            sensors.update_abstract_page()
            abstract = sensors.get_abstract_page()
            print(f"[ParallelNewPage] Rescanned page for latest DOM")

            # 4. Save to shared store (thread-safe)
            page_info = PageInfo(
                url=url,
                title=driver.title.strip() if driver.title else "",
                abstract_page=abstract,
                outgoing_links=outgoing_links,
                network_requests=network_requests,
                actions_mapping=dict(sensors.actions_mapping.mapping),
                event_mapping=dict(sensors.event_mapping.mapping)  # Save event mapping
            )

            # Store has lock protection, thread-safe
            self.shared_store.add_page(page_info, persist=True)

            print(f"[ParallelNewPage] Page cached: {url}")

            # Fix: Generate tasks (consistent with serial mode)
            if self.task_gen:
                page = self.shared_store.get_page(url)
                if page:
                    title = (driver.title or "").strip()
                    reasoning, task_descriptions = self.task_gen.generate_logic_for_page(page)
                    page.description = f"Title: {title}\nDescription: {reasoning}"
                    page.logic_tasks = task_descriptions
                    self.shared_store.upsert_page(page, merge_outgoing_links=False, merge_requests=False, persist=True)
                    print(f"[ParallelNewPage] Generated {len(task_descriptions)} tasks")

        except Exception as e:
            print(f"[ParallelNewPage] Processing failed: {url} - {e}")

    def _construct_edge_parallel(self, url: str):
        """
        Edge construction callback during parallel execution (lightweight version)

        Retained: collect links and create "discovered" edges
        """
        try:
            driver = self._current_driver
            if not driver:
                return

            # Collect links
            links = []
            try:
                elements = driver.find_elements(By.TAG_NAME, 'a')
                for elem in elements:
                    href = elem.get_attribute('href')
                    if href and '127.0.0.1' in href:
                        links.append(href.strip())
            except:
                pass

            # Create "discovered" edges (thread-safe)
            for link in links:
                if not self.shared_store.has_edge(url, link):
                    edge = Edge(
                        from_url=url,
                        to_url=link,
                        via_action_id=-1,  # -1 means not actually clicked
                        via_repr="link",
                        jump_kind="discovered",
                    )
                    self.shared_store.add_edge(edge)  # Has lock protection

        except Exception as e:
            print(f"[ParallelEdge] Edge construction failed: {url} - {e}")
