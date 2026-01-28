# -*- coding: utf-8 -*-
"""
Parallel Task Scheduler - 并行任务调度器
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


class ParallelTaskScheduler:
    """
    并行任务调度器

    核心功能：
    1. 规划线程（生产者）：调用LLM规划任务并入队
    2. 执行线程池（消费者）：从队列取任务并行执行
    3. UPDATE_PAGES同步点：暂停规划，等待执行完成
    4. 智能结束条件：检查是否还有未执行的页面/任务
    """

    def __init__(self,
                 crawler,
                 task_planning_agent,
                 account_manager,
                 client,
                 max_workers: int = 10,
                 use_main_driver: bool = True):
        """
        初始化并行任务调度器

        Args:
            crawler: Crawler实例（用于获取store等）
            task_planning_agent: TaskPlanningAgent实例（用于规划）
            account_manager: AccountManager实例
            client: OpenAI client
            max_workers: 最大并发worker数（默认10）
            use_main_driver: 是否让主driver也参与任务执行（默认True，保持session活跃）
        """
        self.crawler = crawler
        self.task_planning_agent = task_planning_agent
        self.account_manager = account_manager
        self.client = client
        self.max_workers = max_workers
        self.use_main_driver = use_main_driver

        # Driver池
        self.driver_pool: Optional[DriverPool] = None

        # 🆕 保存主driver引用（用于传给DriverPool）
        self.main_driver = crawler.driver if use_main_driver else None

        # 任务队列
        self.task_queue: Queue = Queue()

        # 执行中的任务（task_id -> Future）
        self.executing_tasks: Dict[str, Future] = {}
        self.executing_lock = threading.Lock()  # 保护executing_tasks

        # 状态控制
        self.planning_active = True
        self.planning_pause = threading.Event()
        self.planning_pause.set()  # 初始不暂停

        # 🆕 确认等待控制（用于LLM返回FINISH后的确认）
        self.wait_confirmation = threading.Event()  # 等待主线程确认是否有新页面
        self.wait_confirmation.clear()  # 初始不等待确认
        self.should_continue = False  # 主线程告诉规划线程是否继续（True=有新页面，继续；False=无新页面，退出）

        # 🆕 追踪是否是"重新询问"（FINISH后发现未执行页面，再问一次）
        self.is_retry_after_finish = False  # 标记当前迭代是否是FINISH后的重试

        # 任务规划记录
        self.planned_tasks: List[Dict[str, Any]] = []  # 存储所有规划的任务
        self.tasks_lock = threading.Lock()  # 保护planned_tasks
        self.tasks_json_path = Path(crawler.root_dir) / "planned_tasks.json"

        if use_main_driver:
            print(f"[ParallelScheduler] 初始化完成，max_workers={max_workers} (包含1个主driver + {max_workers-1}个子driver)")
        else:
            print(f"[ParallelScheduler] 初始化完成，max_workers={max_workers} (全部为子driver)")

    def run(self, max_iterations: int = 100, target_domain=None):
        """
        主循环：并行的规划和执行

        流程：
        1. 创建driver池
        2. 启动规划线程（生产者）
        3. 执行循环（消费者）
        4. 清理资源

        Args:
            max_iterations: 最大规划迭代次数（防止无限循环）
        """
        print(f"\n{'='*70}")
        print(f"[ParallelScheduler] 开始并行任务调度")
        print(f"{'='*70}\n")

        start_time = time.time()

        try:
            # ===== 步骤1: 创建driver池 =====
            self._create_driver_pool(target_domain)

            # ===== 步骤2: 启动规划线程 =====
            planning_thread = threading.Thread(
                target=self._planning_loop,
                args=(max_iterations,),
                name="PlanningThread"
            )
            planning_thread.start()

            # ===== 步骤3: 执行循环 =====
            with ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="Worker") as executor:
                while True:
                    # 🔧 修复：额外的安全检查 - 如果规划线程已死且队列为空，强制退出
                    if not planning_thread.is_alive() and self.task_queue.empty():
                        with self.executing_lock:
                            has_executing_tasks = len(self.executing_tasks) > 0
                        if not has_executing_tasks:
                            print(f"[ParallelScheduler] ⚠️ 规划线程已结束且无待执行任务，强制退出执行循环")
                            break

                    # 检查结束条件
                    if self._should_terminate():
                        print(f"[ParallelScheduler] 满足结束条件，停止执行循环")
                        break

                    # 从队列取任务
                    try:
                        task = self.task_queue.get(timeout=1)
                    except Empty:
                        # 没有任务，继续等待
                        continue

                    # 提交执行
                    future = executor.submit(self._execute_task_wrapper, task)

                    with self.executing_lock:
                        self.executing_tasks[task.task_id] = future

            # ===== 步骤4: 等待规划线程结束 =====
            planning_thread.join(timeout=10)

            if planning_thread.is_alive():
                print(f"[ParallelScheduler] ⚠️ 规划线程未正常结束")

            # ===== 步骤5: 确保所有任务完成 =====
            self._wait_all_tasks()

        finally:
            # ===== 步骤6: 不清理driver池（Phase 4-5攻击执行还需要用）=====
            # 🔧 修复：Phase 3的drivers会被传递给Phase 4-5，不能在这里关闭
            # 清理工作由 decision_agent 在整个流程结束后统一处理
            if self.driver_pool:
                print(f"[ParallelScheduler] Driver池保持打开（将被传递给Phase 4-5）")
                print(f"[ParallelScheduler] 清理工作将由decision_agent统一处理")

        elapsed = time.time() - start_time

        print(f"\n{'='*70}")
        print(f"[ParallelScheduler] 并行调度完成")
        print(f"[ParallelScheduler] 总耗时: {elapsed:.1f}秒")
        print(f"[ParallelScheduler] 执行的页面数: {len(self.task_planning_agent.state.executed_pages)}")
        print(f"{'='*70}\n")

        return {
            "total_pages": len(self.task_planning_agent.state.executed_pages),
            "elapsed": elapsed
        }

    def _create_driver_pool(self, target_domain):
        """创建driver池"""
        print(f"[ParallelScheduler] 创建driver池...")

        self.driver_pool = DriverPool(size=self.max_workers)
        self.driver_pool.create(
            account_manager=self.account_manager,
            base_url=self.crawler.initial_url,
            chrome_options=self.crawler.driver.options if hasattr(self.crawler.driver, 'options') else None,
            main_driver=self.main_driver,
            target_domain=target_domain
        )

        print(f"[ParallelScheduler] ✓ Driver池创建完成\n")

    def _planning_loop(self, max_iterations: int):
        """
        规划循环（在独立线程中运行）

        🆕 修复逻辑：
        - LLM返回FINISH后，不立即退出，而是等待主线程确认
        - 主线程会检查是否有新页面（任务执行过程中发现的）
        - 如果有新页面：用新图再问LLM
        - 如果没有新页面：真正退出

        Args:
            max_iterations: 最大迭代次数
        """
        print(f"[PlanningThread] 规划线程启动\n")

        iteration = 0
        need_confirmation = False  # 是否需要等待主线程确认

        # ✅ 修复：即使planning_active=False，如果need_confirmation=True也要继续循环（等待确认）
        while (self.planning_active or need_confirmation) and iteration < max_iterations:
            # 如果需要等待确认（LLM刚返回了FINISH）
            if need_confirmation:
                print(f"[PlanningThread] 等待主线程确认是否有新页面...")
                self.wait_confirmation.wait()  # 🔑 无超时，无限期等待主线程通知

                if self.should_continue:
                    # 主线程说：有新页面，继续规划
                    print(f"[PlanningThread] ✓ 主线程确认有新页面，继续规划")
                    need_confirmation = False
                    self.planning_active = True  # ✅ 恢复活跃状态
                    self.wait_confirmation.clear()  # 重置事件
                    # 继续循环，用新图再问LLM
                else:
                    # 主线程说：没有新页面，可以退出
                    print(f"[PlanningThread] ✓ 主线程确认无新页面，退出")
                    break

            iteration += 1

            # 等待（如果被暂停，如UPDATE_PAGES同步点）
            self.planning_pause.wait()

            print(f"\n[PlanningThread] ===== 迭代 {iteration} =====")

            # 调用LLM规划
            try:
                action_type, action_data = self.task_planning_agent._plan_next_action()

                # 处理不同的action
                if action_type == "EXECUTE_TASKS":
                    self.is_retry_after_finish = False  # 重置重试标记（因为LLM确实执行了任务）
                    self._handle_execute_tasks(action_data)

                elif action_type == "UPDATE_PAGES":
                    # ✅ 不重置重试标记！UPDATE_PAGES后如果LLM再次FINISH，应该算作"第二次FINISH"
                    self._handle_update_pages(action_data)

                elif action_type == "FINISH":
                    # ✅ 检查是否是"重试后的FINISH"
                    if self.is_retry_after_finish:
                        # 第二次FINISH了，LLM拒绝执行，直接退出
                        print(f"[PlanningThread] LLM重试后仍返回FINISH，直接退出")
                        self.planning_active = False
                        break  # 直接退出循环，不需要等主线程确认

                    # 第一次FINISH，等待任务完成后让主线程检查
                    print(f"[PlanningThread] LLM返回FINISH，等待所有任务执行完成...")
                    self._wait_all_tasks()

                    print(f"[PlanningThread] 进入等待确认状态，由主线程检查是否继续")
                    need_confirmation = True
                    self.planning_active = False  # ✅ 设置False让主线程能进入检查，但循环因need_confirmation=True继续

                else:
                    print(f"[PlanningThread] ⚠️ 未知action类型: {action_type}")

            except Exception as e:
                print(f"[PlanningThread] ✗ 规划失败: {e}")
                import traceback
                traceback.print_exc()

        # 🔧 修复：规划线程退出前，强制设置 planning_active = False
        # 避免因达到 max_iterations 退出时，planning_active 还是 True，导致主线程永远等待
        self.planning_active = False
        print(f"\n[PlanningThread] 规划线程结束（迭代{iteration}次）\n")

    def _handle_execute_tasks(self, action_data):
        """
        处理EXECUTE_TASKS操作

        Args:
            action_data: ExecuteTasksAction对象
        """
        page_url = action_data.page_url
        tasks = action_data.tasks

        # ✅ 修复：检查 page_url
        if not page_url:
            print(f"[PlanningThread] ⚠️ Empty page_url, skipping")
            return

        # ✅ 修复：即使任务列表为空，也要标记页面为已执行（避免死循环）
        if not tasks:
            print(f"[PlanningThread] No tasks to execute for {page_url}, but marking as executed")
            self.task_planning_agent.state.executed_pages.add(page_url)
            return

        print(f"[PlanningThread] EXECUTE_TASKS: {page_url}")
        print(f"[PlanningThread] 任务数量: {len(tasks)}")

        # ✅ 标记页面为已执行（同步到task_planning_agent的状态）
        self.task_planning_agent.state.executed_pages.add(page_url)

        # ✅ 修复：更新Store中的页面任务（与串行模式保持一致）
        # 这样导出任务图时，能够反映Planning Agent实际规划的任务
        page = self.crawler.store.get_page(page_url)
        if page:
            print(f"[PlanningThread] 更新页面任务: {len(page.logic_tasks)} -> {len(tasks)}")
            page.logic_tasks = tasks
            self.crawler.store.upsert_page(page, merge_outgoing_links=False, merge_requests=False, persist=True)

        # 创建任务对象并入队
        task_list = []
        for task_desc in tasks:
            task_id = self.task_planning_agent.task_queue.next_task_id()
            task = Task(
                task_id=task_id,
                description=task_desc,
                initial_url=page_url
            )

            self.task_queue.put(task)
            print(f"[PlanningThread] 任务入队: {task_id} - {task_desc}")

            # 记录到planned_tasks
            task_list.append({
                "task_id": task_id,
                "description": task_desc,
                "initial_url": page_url,
                "status": "queued"
            })

        # 保存到JSON文件（线程安全）
        with self.tasks_lock:
            self.planned_tasks.extend(task_list)
            self._save_tasks_to_json()

    def _handle_update_pages(self, action_data):
        """
        处理UPDATE_PAGES操作（同步点）

        流程：
        1. 暂停规划
        2. 等待所有执行中的任务完成
        3. 执行UPDATE操作
        4. 恢复规划

        Args:
            action_data: UpdatePagesAction对象
        """
        page_urls = action_data.page_urls
        reason = action_data.reason

        print(f"\n[PlanningThread] *** UPDATE_PAGES同步点 ***")
        print(f"[PlanningThread] 原因: {reason}")
        print(f"[PlanningThread] 页面数: {len(page_urls)}")

        # 1. 暂停规划
        self.planning_pause.clear()
        print(f"[PlanningThread] 已暂停规划")

        # 2. 等待所有执行中的任务完成
        self._wait_all_tasks()

        # 3. 执行UPDATE操作（使用主driver或独立driver）
        try:
            self._update_pages(page_urls)
        except Exception as e:
            print(f"[PlanningThread] ✗ UPDATE失败: {e}")

        # 4. 恢复规划
        self.planning_pause.set()
        print(f"[PlanningThread] 已恢复规划\n")

    def _update_pages(self, page_urls: List[str]):
        """
        更新页面（重新扫描页面抽象并重新生成任务）

        完整流程：
        1. 重新访问页面
        2. 重新收集页面信息（DOM、请求等）
        3. 重新生成任务（调用LLM）
        4. 标记状态，允许LLM重新规划

        Args:
            page_urls: 要更新的页面URL列表
        """
        print(f"[UpdatePages] 开始更新 {len(page_urls)} 个页面")

        # 使用主driver进行更新（避免并发问题）
        driver = self.crawler.driver

        for i, url in enumerate(page_urls, 1):
            print(f"[UpdatePages] [{i}/{len(page_urls)}] 更新页面: {url}")

            try:
                # 1. 导航到页面
                driver.get(url)
                time.sleep(0.6)

                # 2. 重新收集页面信息（和串行模式一致）
                self.crawler._collect_page_info(url)

                # 3. 重新生成任务（调用LLM）
                page = self.crawler.store.get_page(url)
                if page:
                    title = (driver.title or "").strip()
                    reasoning, task_descriptions = self.crawler.task_gen.generate_logic_for_page(page)
                    page.description = f"Title: {title}\nDescription: {reasoning}"
                    page.logic_tasks = task_descriptions
                    self.crawler.store.add_page(page, persist=True)

                    print(f"[UpdatePages] ✓ 页面已更新，重新生成了 {len(task_descriptions)} 个任务")

                    # 4. 标记状态（允许LLM重新规划这个页面）
                    self.task_planning_agent.state.updated_pages.add(url)
                    self.task_planning_agent.state.executed_pages.discard(url)
                else:
                    print(f"[UpdatePages] ⚠️ 页面不在store中")

            except Exception as e:
                print(f"[UpdatePages] ✗ 更新失败: {e}")

        print(f"[UpdatePages] 更新完成\n")

    def _execute_task_wrapper(self, task: Task):
        """
        任务执行包装器（在worker线程中运行）

        流程：
        1. 从driver池获取driver（统一管理，包括主driver）
        2. 执行任务
        3. 归还driver到池
        4. 从executing_tasks移除

        Args:
            task: 要执行的任务
        """
        driver = None

        try:
            # ===== 步骤1: 从池中获取driver（主driver和子driver统一管理）=====
            driver = self.driver_pool.acquire(task.task_id, timeout=300)

            if not driver:
                print(f"[Worker] ✗ 获取driver超时: {task.task_id}")
                return {"task_id": task.task_id, "status": "error", "error": "Driver timeout"}

            # ===== 步骤2: 执行任务 =====
            executor = IndependentTaskExecutor(
                shared_store=self.crawler.store,
                client=self.client,
                base_url=self.crawler.initial_url,
                task_gen=self.crawler.task_gen,
                content_index=self.crawler.content_index  # ✅ 传入去重索引
            )

            # 🆕 生成driver信息标识（主driver标识为"main"，子driver标识为"sub_XX"）
            pool_index = getattr(driver, '_pool_index', 0)
            if pool_index == "main":
                driver_info = "main"
            else:
                driver_info = f"sub_{pool_index:02d}"

            result = executor.execute_task(task, driver, driver_info=driver_info)

            return result

        finally:
            # ===== 步骤3: 归还driver到池 =====
            if driver:
                self.driver_pool.release(task.task_id, cleanup=False)

            # ===== 步骤4: 从executing_tasks移除 =====
            with self.executing_lock:
                self.executing_tasks.pop(task.task_id, None)

    def _wait_all_tasks(self):
        """
        等待所有任务完成（包括队列中的和执行中的）

        改进：先等待队列清空，再等待执行中的任务完成
        """
        # ✅ 步骤1: 等待队列清空（无超时，一直等待）
        if not self.task_queue.empty():
            queue_size = self.task_queue.qsize()
            print(f"[ParallelScheduler] 等待队列清空（当前队列: {queue_size} 个任务）...")

            # 无限等待队列为空
            while not self.task_queue.empty():
                current_size = self.task_queue.qsize()
                print(f"[ParallelScheduler] 队列剩余: {current_size} 个任务...")
                time.sleep(1)

            print(f"[ParallelScheduler] ✓ 队列已清空")

        # ✅ 步骤2: 等待所有执行中的任务完成
        with self.executing_lock:
            tasks_to_wait = list(self.executing_tasks.values())
            task_count = len(tasks_to_wait)

        if task_count == 0:
            print(f"[ParallelScheduler] ✓ 没有执行中的任务")
            return

        print(f"[ParallelScheduler] 等待 {task_count} 个执行中的任务完成...")

        for future in as_completed(tasks_to_wait):
            try:
                future.result()
            except Exception as e:
                print(f"[ParallelScheduler] 任务执行出错: {e}")

        print(f"[ParallelScheduler] ✓ 所有任务已完成\n")

    def _should_terminate(self) -> bool:
        """
        判断是否应该终止

        逻辑：
        1. 基础条件：规划不活跃 + 队列为空 + 无执行中任务
        2. 检查是否有未执行页面
        3. 如果有未执行页面：
           - 如果是第一次（is_retry_after_finish=False）→ 设置标记，再问LLM一次
           - 如果是第二次（is_retry_after_finish=True）→ LLM连续两次FINISH，直接结束
        4. 如果没有未执行页面 → 直接结束

        Returns:
            True表示应该终止
        """
        # 第1层：基础条件
        with self.executing_lock:
            has_executing_tasks = len(self.executing_tasks) > 0

        if self.planning_active or \
           not self.task_queue.empty() or \
           has_executing_tasks:
            return False

        # 第2层：检查是否有未执行页面
        if self._has_unexecuted_pages():
            # 有未执行页面
            if self.is_retry_after_finish:
                # 这已经是重试了，LLM第二次还是FINISH → 直接结束
                print(f"[ParallelScheduler] ⚠️ LLM重试后仍返回FINISH，强制结束")
                print(f"[ParallelScheduler] → 通知规划线程退出")

                self.should_continue = False
                self.is_retry_after_finish = False  # 重置标记
                self.wait_confirmation.set()
                return True
            else:
                # 第一次，给LLM一次重新考虑的机会
                print(f"[ParallelScheduler] ✓ 检测到未执行页面，给LLM一次重新考虑的机会")
                print(f"[ParallelScheduler] → 通知规划线程继续（重试）")

                self.is_retry_after_finish = True  # 设置重试标记
                self.should_continue = True
                self.planning_active = True
                self.wait_confirmation.set()
                return False
        else:
            # 没有未执行页面 → 直接结束
            print(f"[ParallelScheduler] ✓ 无未执行页面，确认终止")
            print(f"[ParallelScheduler] → 通知规划线程退出")

            self.should_continue = False
            self.is_retry_after_finish = False  # 重置标记
            self.wait_confirmation.set()
            return True

    def _has_unexecuted_pages(self) -> bool:
        """
        检查是否还有未执行的页面

        Returns:
            True表示还有未执行的页面
        """
        try:
            # 生成当前的任务规划图
            graph = self.crawler._generate_graph_for_task_plan()

            # 检查每个节点是否有未执行的任务
            for node in graph.get("nodes", []):
                url = node["url"]
                tasks = node.get("tasks", [])

                # ✅ 如果页面未执行且有任务
                if url not in self.task_planning_agent.state.executed_pages and tasks:
                    return True

            return False

        except Exception as e:
            print(f"[CheckUnexecuted] 检查失败: {e}")
            return False

    def _save_tasks_to_json(self):
        """
        保存所有规划的任务到JSON文件

        注意：此方法应在tasks_lock保护下调用
        """
        try:
            with open(self.tasks_json_path, 'w', encoding='utf-8') as f:
                json.dump({
                    "total_tasks": len(self.planned_tasks),
                    "tasks": self.planned_tasks
                }, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[ParallelScheduler] 保存任务JSON失败: {e}")

    def get_worker_drivers(self) -> list:
      """
      获取所有worker drivers（用于传递给下一阶段）
      
      Returns:
          worker drivers列表
      """
      if hasattr(self, 'driver_pool') and self.driver_pool:  # ✅ 正确
          return self.driver_pool.drivers  # ✅ DriverPool.drivers 是 List[webdriver.Chrome]
      return []
