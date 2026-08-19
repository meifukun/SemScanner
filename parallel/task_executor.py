# -*- coding: utf-8 -*-
"""
Independent Task Executor - Execute a single task using an independent driver
"""

import time
from typing import Dict, Any, Optional
from pathlib import Path

from seleniumwire import webdriver  # Use selenium-wire to support network request capture
from selenium.webdriver.common.by import By

from crawl.dom_semantic_extractor import DOMSemanticExtractor
from crawl.Actuators import Actuators
from crawl.interaction_execution_agent import InteractionExecutionAgent
from capture.network_capture import NetworkCapture
from crawl.tracer import ExecutionTracer
from app_info.models import PageInfo, NetworkRequest, Edge
from task.tasks import Task
from utils.url_scope import UrlScope


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

    def __init__(self, shared_store, client, base_url: str, task_gen=None, content_index=None):
        """
        Initialize the independent task executor

        Args:
            shared_store: Shared WebAppStore instance (thread-safe)
            client: OpenAI client
            base_url: Base URL
            task_gen: TaskGenerator instance (for new page task generation)
            content_index: ContentDedupeIndex instance (for page deduplication)
        """
        self.shared_store = shared_store
        self.client = client
        self.base_url = base_url
        self.url_scope = UrlScope(base_url)
        self.task_gen = task_gen
        self.content_index = content_index  # Page dedup index

        # Current task context (for callbacks)
        self._current_driver: Optional[webdriver.Chrome] = None
        self._current_sensors: Optional[DOMSemanticExtractor] = None
        self._current_network_capture: Optional[NetworkCapture] = None

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

        if not self.url_scope.allows_navigation(task.initial_url):
            message = f"[ScopeGuard] Refusing task outside target origin: {task.initial_url}"
            print(message)
            return {"task_id": task.task_id, "status": "error", "error": message}

        try:
            # ===== Step 1: Create independent component chain =====
            sensors = DOMSemanticExtractor(driver, use_improved_locator=True)
            actuators = Actuators(sensors)
            bridge = InteractionExecutionAgent(
                sensors=sensors,
                actuators=actuators,
                client=self.client,
                url_in_scope=self.url_scope.allows_navigation,
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
                url_in_scope=self.url_scope.allows_navigation,
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
            if not self.url_scope.allows_navigation(driver.current_url):
                raise ValueError(
                    f"[ScopeGuard] Task navigation left target origin: "
                    f"{task.initial_url} -> {driver.current_url}"
                )

            # Create screenshot directory with driver info identifier
            photo_dir = self.shared_store.traces_dir / f"{driver_info}_{task.task_id}"
            photo_dir.mkdir(parents=True, exist_ok=True)  # Ensure directory exists

            # Load page abstract and mapping from shared store
            page = self.shared_store.get_page(task.initial_url)
            if page and page.abstract_page:
                sensors.abstract_page = page.abstract_page
                print(f"[IndependentExecutor] Loaded page abstract from cache ({len(page.abstract_page)} chars)")

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
                else:
                    print(f"[IndependentExecutor] Warning: No event_mapping in page cache")
            else:
                # Fallback: rescan
                print(f"[IndependentExecutor] Cache not found, rescanning")
                sensors.update_abstract_page()

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
        if not self.url_scope.allows_navigation(url):
            print(f"[ScopeGuard] Ignoring page outside target origin: {url}")
            return

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
                    resolved = self.url_scope.resolve(href, current_url=url) if href else None
                    if resolved and self.url_scope.allows_navigation(resolved):
                        outgoing_links.append(resolved)
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
            if not self.url_scope.allows_navigation(url):
                print(f"[ScopeGuard] Skipping edge construction outside target origin: {url}")
                return
            driver = self._current_driver
            if not driver:
                return

            # Collect links
            links = []
            try:
                elements = driver.find_elements(By.TAG_NAME, 'a')
                for elem in elements:
                    href = elem.get_attribute('href')
                    resolved = self.url_scope.resolve(href, current_url=url) if href else None
                    if resolved and self.url_scope.allows_navigation(resolved):
                        links.append(resolved)
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
