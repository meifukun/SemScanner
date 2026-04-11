# -*- coding: utf-8 -*-
"""
Parallel Task Scheduler
"""

import time
import threading
import json
from pathlib import Path
from queue import Queue, Empty
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from typing import Dict, List, Set, Optional, Any

from task.tasks import Task
from parallel.driver_pool import DriverPool
from parallel.task_executor import IndependentTaskExecutor
from utils.token_tracker import tracker


class ParallelTaskScheduler:
    """
    Parallel Task Scheduler

    Core features:
    1. Planning thread (producer): calls LLM to plan tasks and enqueue
    2. Execution thread pool (consumer): takes tasks from queue and executes in parallel
    3. UPDATE_PAGES synchronization point: pauses planning, waits for execution to complete
    4. Smart termination condition: checks if there are unexecuted pages/tasks
    """

    def __init__(self,
                 crawler,
                 task_planning_agent,
                 account_manager,
                 client,
                 max_workers: int = 10,
                 use_main_driver: bool = True):
        """
        Initialize the parallel task scheduler

        Args:
            crawler: Crawler instance (for accessing store, etc.)
            task_planning_agent: TaskPlanningAgent instance (for planning)
            account_manager: AccountManager instance
            client: OpenAI client
            max_workers: Maximum concurrent workers (default 10)
            use_main_driver: Whether the main driver participates in task execution (default True, keeps session active)
        """
        self.crawler = crawler
        self.task_planning_agent = task_planning_agent
        self.account_manager = account_manager
        self.client = client
        self.max_workers = max_workers
        self.use_main_driver = use_main_driver

        # Driver pool
        self.driver_pool: Optional[DriverPool] = None

        # Save main driver reference (for passing to DriverPool)
        self.main_driver = crawler.driver if use_main_driver else None

        # Task queue
        self.task_queue: Queue = Queue()

        # Executing tasks (task_id -> Future)
        self.executing_tasks: Dict[str, Future] = {}
        self.executing_lock = threading.Lock()  # Protect executing_tasks

        # State control
        self.planning_active = True
        self.planning_pause = threading.Event()
        self.planning_pause.set()  # Initially not paused

        # Confirmation wait control (for confirmation after LLM returns FINISH)
        self.wait_confirmation = threading.Event()  # Wait for main thread to confirm if there are new pages
        self.wait_confirmation.clear()  # Initially not waiting for confirmation
        self.should_continue = False  # Main thread tells planning thread whether to continue (True=new pages, continue; False=no new pages, exit)

        # Track whether this is a "re-ask" (FINISH followed by discovering unexecuted pages, ask again)
        self.is_retry_after_finish = False  # Flag whether current iteration is a retry after FINISH

        # Task planning records
        self.planned_tasks: List[Dict[str, Any]] = []  # Store all planned tasks
        self.tasks_lock = threading.Lock()  # Protect planned_tasks
        self.tasks_json_path = Path(crawler.root_dir) / "planned_tasks.json"

        if use_main_driver:
            print(f"[ParallelScheduler] Initialization complete, max_workers={max_workers} (includes 1 main driver + {max_workers-1} sub-drivers)")
        else:
            print(f"[ParallelScheduler] Initialization complete, max_workers={max_workers} (all sub-drivers)")

    def run(self, max_iterations: int = 100, target_domain=None):
        """
        Main loop: parallel planning and execution

        Flow:
        1. Create driver pool
        2. Start planning thread (producer)
        3. Execution loop (consumer)
        4. Clean up resources

        Args:
            max_iterations: Maximum planning iterations (prevents infinite loop)
        """
        print(f"\n{'='*70}")
        print(f"[ParallelScheduler] Starting parallel task scheduling")
        print(f"{'='*70}\n")

        start_time = time.time()

        try:
            # ===== Step 1: Create driver pool =====
            self._create_driver_pool(target_domain)

            # ===== Step 2: Start planning thread =====
            planning_thread = threading.Thread(
                target=self._planning_loop,
                args=(max_iterations,),
                name="PlanningThread"
            )
            planning_thread.start()

            # ===== Step 3: Execution loop =====
            with ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="Worker") as executor:
                while True:
                    # Fix: Extra safety check - if planning thread is dead and queue is empty, force exit
                    if not planning_thread.is_alive() and self.task_queue.empty():
                        with self.executing_lock:
                            has_executing_tasks = len(self.executing_tasks) > 0
                        if not has_executing_tasks:
                            print(f"[ParallelScheduler] Planning thread ended and no pending tasks, force exiting execution loop")
                            break

                    # Check termination condition
                    if self._should_terminate():
                        print(f"[ParallelScheduler] Termination condition met, stopping execution loop")
                        break

                    # Get task from queue
                    try:
                        task = self.task_queue.get(timeout=1)
                    except Empty:
                        # No task, continue waiting
                        continue

                    # Submit for execution
                    future = executor.submit(self._execute_task_wrapper, task)

                    with self.executing_lock:
                        self.executing_tasks[task.task_id] = future

            # ===== Step 4: Wait for planning thread to end =====
            planning_thread.join(timeout=10)

            if planning_thread.is_alive():
                print(f"[ParallelScheduler] Planning thread did not terminate normally")

            # ===== Step 5: Ensure all tasks are complete =====
            self._wait_all_tasks()

        finally:
            # ===== Step 6: Do not clean up driver pool (Phase 4-5 attack execution still needs them) =====
            # Fix: Phase 3 drivers will be passed to Phase 4-5, cannot close here
            # Cleanup is handled uniformly by decision_agent after the entire flow ends
            if self.driver_pool:
                print(f"[ParallelScheduler] Driver pool kept open (will be passed to Phase 4-5)")
                print(f"[ParallelScheduler] Cleanup will be handled uniformly by decision_agent")

        elapsed = time.time() - start_time

        print(f"\n{'='*70}")
        print(f"[ParallelScheduler] Parallel scheduling complete")
        print(f"[ParallelScheduler] Total time: {elapsed:.1f} seconds")
        print(f"[ParallelScheduler] Executed pages: {len(self.task_planning_agent.state.executed_pages)}")
        print(f"{'='*70}\n")

        return {
            "total_pages": len(self.task_planning_agent.state.executed_pages),
            "elapsed": elapsed
        }

    def _create_driver_pool(self, target_domain):
        """Create driver pool"""
        print(f"[ParallelScheduler] Creating driver pool...")

        self.driver_pool = DriverPool(size=self.max_workers)
        self.driver_pool.create(
            account_manager=self.account_manager,
            base_url=self.crawler.initial_url,
            chrome_options=self.crawler.driver.options if hasattr(self.crawler.driver, 'options') else None,
            main_driver=self.main_driver,
            target_domain=target_domain
        )

        print(f"[ParallelScheduler] Driver pool creation complete\n")

    def _planning_loop(self, max_iterations: int):
        """
        Planning loop (runs in a separate thread)

        Fixed logic:
        - After LLM returns FINISH, don't exit immediately; wait for main thread confirmation
        - Main thread checks if there are new pages (discovered during task execution)
        - If new pages exist: ask LLM again with the new graph
        - If no new pages: actually exit

        Args:
            max_iterations: Maximum number of iterations
        """
        print(f"[PlanningThread] Planning thread started\n")

        iteration = 0
        need_confirmation = False  # Whether to wait for main thread confirmation

        # Fix: Even if planning_active=False, continue loop if need_confirmation=True (waiting for confirmation)
        while (self.planning_active or need_confirmation) and iteration < max_iterations:
            # If waiting for confirmation (LLM just returned FINISH)
            if need_confirmation:
                print(f"[PlanningThread] Waiting for main thread to confirm if there are new pages...")
                self.wait_confirmation.wait()  # No timeout, wait indefinitely for main thread notification

                if self.should_continue:
                    # Main thread says: new pages exist, continue planning
                    print(f"[PlanningThread] Main thread confirmed new pages, continuing planning")
                    need_confirmation = False
                    self.planning_active = True  # Restore active state
                    self.wait_confirmation.clear()  # Reset event
                    # Continue loop, ask LLM again with new graph
                else:
                    # Main thread says: no new pages, can exit
                    print(f"[PlanningThread] Main thread confirmed no new pages, exiting")
                    break

            iteration += 1

            # Wait (if paused, e.g., UPDATE_PAGES synchronization point)
            self.planning_pause.wait()

            print(f"\n[PlanningThread] ===== Iteration {iteration} =====")

            # Call LLM for planning
            try:
                action_type, action_data = self.task_planning_agent._plan_next_action()

                # Handle different actions
                if action_type == "EXECUTE_TASKS":
                    self.is_retry_after_finish = False  # Reset retry flag (LLM actually executed tasks)
                    self._handle_execute_tasks(action_data)

                elif action_type == "UPDATE_PAGES":
                    # Don't reset retry flag! If LLM returns FINISH again after UPDATE_PAGES, it should count as "second FINISH"
                    self._handle_update_pages(action_data)

                elif action_type == "FINISH":
                    # Check if this is a "FINISH after retry"
                    if self.is_retry_after_finish:
                        # Second FINISH, LLM refuses to execute, exit directly
                        print(f"[PlanningThread] LLM still returned FINISH after retry, exiting directly")
                        self.planning_active = False
                        break  # Exit loop directly, no need for main thread confirmation

                    # First FINISH, wait for tasks to complete then let main thread check
                    print(f"[PlanningThread] LLM returned FINISH, waiting for all tasks to complete...")
                    self._wait_all_tasks()

                    print(f"[PlanningThread] Entering confirmation wait state, main thread will check whether to continue")
                    need_confirmation = True
                    self.planning_active = False  # Set False so main thread can enter check, but loop continues due to need_confirmation=True

                else:
                    print(f"[PlanningThread] Unknown action type: {action_type}")

            except Exception as e:
                print(f"[PlanningThread] Planning failed: {e}")
                import traceback
                traceback.print_exc()

        # Fix: Force set planning_active = False before planning thread exits
        # Avoid main thread waiting forever if exiting due to max_iterations while planning_active is still True
        self.planning_active = False
        print(f"\n[PlanningThread] Planning thread ended ({iteration} iterations)\n")

    def _handle_execute_tasks(self, action_data):
        """
        Handle EXECUTE_TASKS action

        Args:
            action_data: ExecuteTasksAction object
        """
        page_url = action_data.page_url
        tasks = action_data.tasks

        # Fix: Check page_url
        if not page_url:
            print(f"[PlanningThread] Empty page_url, skipping")
            return

        # Fix: Even if task list is empty, mark page as executed (avoid infinite loop)
        if not tasks:
            print(f"[PlanningThread] No tasks to execute for {page_url}, but marking as executed")
            self.task_planning_agent.state.executed_pages.add(page_url)
            return

        print(f"[PlanningThread] EXECUTE_TASKS: {page_url}")
        print(f"[PlanningThread] Task count: {len(tasks)}")

        # Mark page as executed (sync to task_planning_agent's state)
        self.task_planning_agent.state.executed_pages.add(page_url)

        # Fix: Update page tasks in Store (consistent with serial mode)
        # This way the exported task graph reflects the tasks actually planned by Planning Agent
        page = self.crawler.store.get_page(page_url)
        if page:
            print(f"[PlanningThread] Updating page tasks: {len(page.logic_tasks)} -> {len(tasks)}")
            page.logic_tasks = tasks
            self.crawler.store.upsert_page(page, merge_outgoing_links=False, merge_requests=False, persist=True)

        # Create task objects and enqueue
        task_list = []
        for task_desc in tasks:
            task_id = self.task_planning_agent.task_queue.next_task_id()
            task = Task(
                task_id=task_id,
                description=task_desc,
                initial_url=page_url
            )

            self.task_queue.put(task)
            print(f"[PlanningThread] Task enqueued: {task_id} - {task_desc}")

            # Record to planned_tasks
            task_list.append({
                "task_id": task_id,
                "description": task_desc,
                "initial_url": page_url,
                "status": "queued"
            })

        # Save to JSON file (thread-safe)
        with self.tasks_lock:
            self.planned_tasks.extend(task_list)
            self._save_tasks_to_json()

    def _handle_update_pages(self, action_data):
        """
        Handle UPDATE_PAGES action (synchronization point)

        Flow:
        1. Pause planning
        2. Wait for all executing tasks to complete
        3. Execute UPDATE operation
        4. Resume planning

        Args:
            action_data: UpdatePagesAction object
        """
        page_urls = action_data.page_urls
        reason = action_data.reason

        print(f"\n[PlanningThread] *** UPDATE_PAGES synchronization point ***")
        print(f"[PlanningThread] Reason: {reason}")
        print(f"[PlanningThread] Page count: {len(page_urls)}")

        # 1. Pause planning
        self.planning_pause.clear()
        print(f"[PlanningThread] Planning paused")

        # 2. Wait for all executing tasks to complete
        self._wait_all_tasks()

        # 3. Execute UPDATE operation (using main driver or independent driver)
        try:
            self._update_pages(page_urls)
        except Exception as e:
            print(f"[PlanningThread] UPDATE failed: {e}")

        # 4. Resume planning
        self.planning_pause.set()
        print(f"[PlanningThread] Planning resumed\n")

    def _update_pages(self, page_urls: List[str]):
        """
        Update pages (rescan page abstract and regenerate tasks)

        Full flow:
        1. Revisit the page
        2. Recollect page information (DOM, requests, etc.)
        3. Regenerate tasks (call LLM)
        4. Mark state, allow LLM to re-plan

        Args:
            page_urls: List of page URLs to update
        """
        print(f"[UpdatePages] Starting update of {len(page_urls)} pages")

        # Use main driver for updates (avoid concurrency issues)
        driver = self.crawler.driver

        for i, url in enumerate(page_urls, 1):
            print(f"[UpdatePages] [{i}/{len(page_urls)}] Updating page: {url}")

            try:
                # 1. Navigate to the page
                driver.get(url)
                time.sleep(0.6)

                # 2. Recollect page information (consistent with serial mode)
                self.crawler._collect_page_info(url)

                # 3. Regenerate tasks (call LLM)
                page = self.crawler.store.get_page(url)
                if page:
                    title = (driver.title or "").strip()
                    reasoning, task_descriptions = self.crawler.task_gen.generate_logic_for_page(page)
                    page.description = f"Title: {title}\nDescription: {reasoning}"
                    page.logic_tasks = task_descriptions
                    self.crawler.store.add_page(page, persist=True)

                    print(f"[UpdatePages] Page updated, regenerated {len(task_descriptions)} tasks")

                    # 4. Mark state (allow LLM to re-plan this page)
                    self.task_planning_agent.state.updated_pages.add(url)
                    self.task_planning_agent.state.executed_pages.discard(url)
                else:
                    print(f"[UpdatePages] Page not in store")

            except Exception as e:
                print(f"[UpdatePages] Update failed: {e}")

        print(f"[UpdatePages] Update complete\n")

    def _execute_task_wrapper(self, task: Task):
        """
        Task execution wrapper (runs in worker thread)

        Flow:
        1. Get driver from pool (unified management, including main driver)
        2. Execute task
        3. Return driver to pool
        4. Remove from executing_tasks

        Args:
            task: Task to execute
        """
        driver = None

        try:
            # ThreadPoolExecutor does not inherit parent thread ContextVar, need to set category explicitly in worker thread
            tracker.set_category("task_exec_bridge")

            # ===== Step 1: Get driver from pool (main driver and sub-drivers unified management) =====
            driver = self.driver_pool.acquire(task.task_id, timeout=300)

            if not driver:
                print(f"[Worker] Driver acquisition timed out: {task.task_id}")
                return {"task_id": task.task_id, "status": "error", "error": "Driver timeout"}

            # ===== Step 2: Execute task =====
            executor = IndependentTaskExecutor(
                shared_store=self.crawler.store,
                client=self.client,
                base_url=self.crawler.initial_url,
                task_gen=self.crawler.task_gen,
                content_index=self.crawler.content_index  # Pass dedup index
            )

            # Generate driver info identifier (main driver identified as "main", sub-drivers as "sub_XX")
            pool_index = getattr(driver, '_pool_index', 0)
            if pool_index == "main":
                driver_info = "main"
            else:
                driver_info = f"sub_{pool_index:02d}"

            result = executor.execute_task(task, driver, driver_info=driver_info)

            return result

        finally:
            # ===== Step 3: Return driver to pool =====
            if driver:
                self.driver_pool.release(task.task_id, cleanup=False)

            # ===== Step 4: Remove from executing_tasks =====
            with self.executing_lock:
                self.executing_tasks.pop(task.task_id, None)

    def _wait_all_tasks(self):
        """
        Wait for all tasks to complete (including those in queue and executing)

        Improvement: Wait for queue to empty first, then wait for executing tasks to complete
        """
        # Step 1: Wait for queue to empty (no timeout, wait indefinitely)
        if not self.task_queue.empty():
            queue_size = self.task_queue.qsize()
            print(f"[ParallelScheduler] Waiting for queue to empty (current queue: {queue_size} tasks)...")

            # Wait indefinitely for queue to be empty
            while not self.task_queue.empty():
                current_size = self.task_queue.qsize()
                print(f"[ParallelScheduler] Queue remaining: {current_size} tasks...")
                time.sleep(1)

            print(f"[ParallelScheduler] Queue emptied")

        # Step 2: Wait for all executing tasks to complete
        with self.executing_lock:
            tasks_to_wait = list(self.executing_tasks.values())
            task_count = len(tasks_to_wait)

        if task_count == 0:
            print(f"[ParallelScheduler] No executing tasks")
            return

        print(f"[ParallelScheduler] Waiting for {task_count} executing tasks to complete...")

        for future in as_completed(tasks_to_wait):
            try:
                future.result()
            except Exception as e:
                print(f"[ParallelScheduler] Task execution error: {e}")

        print(f"[ParallelScheduler] All tasks completed\n")

    def _should_terminate(self) -> bool:
        """
        Determine whether to terminate

        Logic:
        1. Base condition: planning inactive + queue empty + no executing tasks
        2. Check for unexecuted pages
        3. If unexecuted pages exist:
           - First time (is_retry_after_finish=False) -> set flag, ask LLM once more
           - Second time (is_retry_after_finish=True) -> LLM returned FINISH twice, end directly
        4. If no unexecuted pages -> end directly

        Returns:
            True means should terminate
        """
        # Layer 1: Base conditions
        with self.executing_lock:
            has_executing_tasks = len(self.executing_tasks) > 0

        if self.planning_active or \
           not self.task_queue.empty() or \
           has_executing_tasks:
            return False

        # Layer 2: Check for unexecuted pages
        if self._has_unexecuted_pages():
            # Unexecuted pages exist
            if self.is_retry_after_finish:
                # This is already a retry, LLM returned FINISH a second time -> end directly
                print(f"[ParallelScheduler] LLM still returned FINISH after retry, force ending")
                print(f"[ParallelScheduler] -> Notifying planning thread to exit")

                self.should_continue = False
                self.is_retry_after_finish = False  # Reset flag
                self.wait_confirmation.set()
                return True
            else:
                # First time, give LLM a chance to reconsider
                print(f"[ParallelScheduler] Detected unexecuted pages, giving LLM a chance to reconsider")
                print(f"[ParallelScheduler] -> Notifying planning thread to continue (retry)")

                self.is_retry_after_finish = True  # Set retry flag
                self.should_continue = True
                self.planning_active = True
                self.wait_confirmation.set()
                return False
        else:
            # No unexecuted pages -> end directly
            print(f"[ParallelScheduler] No unexecuted pages, confirming termination")
            print(f"[ParallelScheduler] -> Notifying planning thread to exit")

            self.should_continue = False
            self.is_retry_after_finish = False  # Reset flag
            self.wait_confirmation.set()
            return True

    def _has_unexecuted_pages(self) -> bool:
        """
        Check if there are still unexecuted pages

        Returns:
            True means there are still unexecuted pages
        """
        try:
            # Generate the current task planning graph
            graph = self.crawler._generate_graph_for_task_plan()

            # Check each node for unexecuted tasks
            for node in graph.get("nodes", []):
                url = node["url"]
                tasks = node.get("tasks", [])

                # If page is not executed and has tasks
                if url not in self.task_planning_agent.state.executed_pages and tasks:
                    return True

            return False

        except Exception as e:
            print(f"[CheckUnexecuted] Check failed: {e}")
            return False

    def _save_tasks_to_json(self):
        """
        Save all planned tasks to JSON file

        Note: This method should be called under tasks_lock protection
        """
        try:
            with open(self.tasks_json_path, 'w', encoding='utf-8') as f:
                json.dump({
                    "total_tasks": len(self.planned_tasks),
                    "tasks": self.planned_tasks
                }, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[ParallelScheduler] Failed to save tasks JSON: {e}")

    def get_worker_drivers(self) -> list:
      """
      Get all worker drivers (for passing to next phase)

      Returns:
          Worker drivers list
      """
      if hasattr(self, 'driver_pool') and self.driver_pool:
          return self.driver_pool.drivers  # DriverPool.drivers is List[webdriver.Chrome]
      return []
