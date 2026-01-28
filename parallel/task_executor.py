# -*- coding: utf-8 -*-
"""
Independent Task Executor - 使用独立driver执行单个任务
"""

import time
from typing import Dict, Any, Optional
from pathlib import Path

from seleniumwire import webdriver  # ✅ 使用selenium-wire以支持网络请求捕获
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
    独立任务执行器

    功能：
    1. 使用独立driver执行单个任务
    2. 创建独立的组件链（sensors, bridge, tracer等）
    3. 记录完整的trace数据到共享store
    4. 线程安全的新页面发现和缓存

    关键设计：
    - 每个任务有独立的组件链
    - 所有组件共享同一个driver（从池中获取）
    - 写入共享store（有锁保护）
    """

    def __init__(self, shared_store, client, base_url: str, task_gen=None, content_index=None, debug_session: bool = True):
        """
        初始化独立任务执行器

        Args:
            shared_store: 共享的WebAppStore实例（线程安全）
            client: OpenAI client
            base_url: 基础URL
            task_gen: TaskGenerator实例（用于新页面任务生成）
            content_index: ContentDedupeIndex实例（用于页面去重）
            debug_session: 是否启用session状态debug（默认True）
        """
        self.shared_store = shared_store
        self.client = client
        self.base_url = base_url
        self.task_gen = task_gen
        self.content_index = content_index  # ✅ 页面去重索引
        self.debug_session = debug_session  # 🆕 Session debug开关

        # 当前任务上下文（供回调使用）
        self._current_driver: Optional[webdriver.Chrome] = None
        self._current_sensors: Optional[Sensors] = None
        self._current_network_capture: Optional[NetworkCapture] = None

    def _capture_session_state(self, driver: webdriver.Chrome, task_id: str, phase: str) -> Dict[str, Any]:
        """
        捕获driver的当前会话状态（用于debug登录状态丢失问题）

        Args:
            driver: WebDriver实例
            task_id: 任务ID
            phase: 阶段标识（"BEFORE" 或 "AFTER"）

        Returns:
            会话状态字典
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
            # 获取当前URL
            state["current_url"] = driver.current_url
        except Exception as e:
            state["error"] = f"获取URL失败: {e}"

        try:
            # 获取页面标题
            state["page_title"] = driver.title
        except Exception as e:
            state["error"] = f"获取标题失败: {e}"

        try:
            # 获取所有cookies
            cookies = driver.get_cookies()
            # 只保留关键信息，避免日志过长
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
            state["error"] = f"获取Cookies失败: {e}"

        try:
            # 获取localStorage
            local_storage = driver.execute_script("return JSON.stringify(localStorage);")
            state["localStorage"] = local_storage if local_storage else "{}"
        except Exception as e:
            state["error"] = f"获取localStorage失败: {e}"

        try:
            # 获取sessionStorage
            session_storage = driver.execute_script("return JSON.stringify(sessionStorage);")
            state["sessionStorage"] = session_storage if session_storage else "{}"
        except Exception as e:
            state["error"] = f"获取sessionStorage失败: {e}"

        return state

    def _log_session_state(self, driver: webdriver.Chrome, task_id: str, phase: str, log_file: str = None):
        """
        记录并打印driver的会话状态

        Args:
            driver: WebDriver实例
            task_id: 任务ID
            phase: 阶段标识（"BEFORE" 或 "AFTER"）
            log_file: 可选的日志文件路径（如果提供则同时写入文件）
        """
        state = self._capture_session_state(driver, task_id, phase)

        # 生成日志内容
        log_lines = []
        log_lines.append(f"\n{'='*70}")
        log_lines.append(f"[SESSION-DEBUG] 任务 {task_id} - {phase}")
        log_lines.append(f"{'='*70}")
        log_lines.append(f"时间: {state['timestamp']}")
        log_lines.append(f"当前URL: {state['current_url']}")
        log_lines.append(f"页面标题: {state['page_title']}")

        # 检测是否在登录页（简单判断）
        is_login_page = False
        if state['current_url']:
            url_lower = state['current_url'].lower()
            title_lower = (state['page_title'] or "").lower()
            is_login_page = ('login' in url_lower or 'signin' in url_lower or
                           'login' in title_lower or 'signin' in title_lower)

        if is_login_page:
            log_lines.append(f"⚠️  WARNING: 可能在登录页面！")

        log_lines.append(f"\nCookies ({len(state['cookies'])} 个):")
        if state['cookies']:
            for cookie in state['cookies']:
                # 高亮session相关的cookie
                marker = "🔑" if any(k in cookie['name'].lower() for k in ['session', 'token', 'auth', 'jwt']) else "  "
                log_lines.append(f"  {marker} {cookie['name']}: {cookie['value']}")
                log_lines.append(f"     domain={cookie['domain']}, path={cookie['path']}")
        else:
            log_lines.append("  (无cookies)")

        # localStorage和sessionStorage只打印键名（值可能很长）
        try:
            ls_data = eval(state['localStorage']) if state['localStorage'] != "{}" else {}
            if ls_data:
                log_lines.append(f"\nLocalStorage ({len(ls_data)} 项):")
                for key in ls_data.keys():
                    marker = "🔑" if any(k in key.lower() for k in ['session', 'token', 'auth', 'jwt']) else "  "
                    log_lines.append(f"  {marker} {key}")
            else:
                log_lines.append(f"\nLocalStorage: (空)")
        except:
            log_lines.append(f"\nLocalStorage: (解析失败)")

        try:
            ss_data = eval(state['sessionStorage']) if state['sessionStorage'] != "{}" else {}
            if ss_data:
                log_lines.append(f"\nSessionStorage ({len(ss_data)} 项):")
                for key in ss_data.keys():
                    marker = "🔑" if any(k in key.lower() for k in ['session', 'token', 'auth', 'jwt']) else "  "
                    log_lines.append(f"  {marker} {key}")
            else:
                log_lines.append(f"\nSessionStorage: (空)")
        except:
            log_lines.append(f"\nSessionStorage: (解析失败)")

        if state['error']:
            log_lines.append(f"\n⚠️  错误: {state['error']}")

        log_lines.append(f"{'='*70}\n")

        # 生成日志文本
        log_text = "\n".join(log_lines)

        # 🆕 写入到任务日志文件（不再输出到stdout，减少主日志噪音）
        if log_file:
            try:
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write(log_text + "\n")
            except Exception as e:
                print(f"[SESSION-DEBUG] ⚠️ 无法写入日志文件: {e}")

    def execute_task(self, task: Task, driver: webdriver.Chrome, driver_info: str = "unknown") -> Dict[str, Any]:
        """
        使用指定driver执行单个任务

        Args:
            task: 要执行的任务
            driver: 从池中获取的driver
            driver_info: 🆕 driver信息（"main" 或 "sub_{编号}"），用于截图目录命名

        Returns:
            执行结果字典:
            {
                "task_id": str,
                "status": "success" | "error",
                "trace": TaskRunTrace (如果成功),
                "error": str (如果失败)
            }
        """
        print(f"\n[IndependentExecutor] 开始执行任务: {task.task_id}")
        print(f"  Driver: {driver_info}")
        print(f"  描述: {task.description}")
        print(f"  URL: {task.initial_url}")

        try:
            # ===== 步骤1: 创建独立的组件链 =====
            sensors = Sensors(driver, use_improved_locator=True)
            actuators = Actuators(sensors)
            bridge = Bridge(
                sensors=sensors,
                actuators=actuators,
                client=self.client
            )
            network_capture = NetworkCapture(driver)

            # 保存当前上下文（供回调使用）
            self._current_driver = driver
            self._current_sensors = sensors
            self._current_network_capture = network_capture

            # ===== 步骤2: 创建独立的Tracer =====
            tracer = ExecutionTracer(
                store=self.shared_store,  # ✅ 共享store（有锁保护）
                network_capture=network_capture,
                on_new_page=self._on_new_page_discovered_parallel,  # ✅ 轻量级回调
                construct_edge=self._construct_edge_parallel,       # ✅ 轻量级回调
                debug=False
            )

            bridge.set_tracer(
                tracer=tracer,
                task_queue=None,  # 并行执行时不需要动态生成任务
                store=self.shared_store
            )

            # ===== 步骤3: 加载页面抽象（从缓存）=====
            driver.get(task.initial_url)
            time.sleep(0.6)

            # 🆕 根据driver信息创建带标识的截图目录
            photo_dir = self.shared_store.traces_dir / f"{driver_info}_{task.task_id}"
            photo_dir.mkdir(parents=True, exist_ok=True)  # 确保目录存在

            # 🆕 创建session debug日志文件路径
            session_log_file = photo_dir / "session_debug.log"

            # 从共享store加载页面抽象和mapping
            page = self.shared_store.get_page(task.initial_url)
            if page and page.abstract_page:
                sensors.abstract_page = page.abstract_page
                print(f"[IndependentExecutor] ✓ 从缓存加载页面抽象（{len(page.abstract_page)} 字符）")

                # ===== DEBUG: 检查缓存中的映射 =====
                print(f"[IndependentExecutor] [DEBUG] 缓存中的映射信息:")
                print(f"  - actions_mapping: {len(page.actions_mapping) if page.actions_mapping else 0} 个")
                print(f"  - event_mapping: {len(page.event_mapping) if page.event_mapping else 0} 个")
                if page.event_mapping:
                    print(f"  - event_mapping keys: {list(page.event_mapping.keys())[:5]}...")  # 显示前5个

                # 恢复actions_mapping
                if page.actions_mapping:
                    sensors.actions_mapping.clear()
                    for action_id, locators_info in page.actions_mapping.items():
                        sensors.actions_mapping.set_mapping(
                            int(action_id),
                            locators_info
                        )
                    print(f"[IndependentExecutor] ✓ 恢复了 {len(page.actions_mapping)} 个元素映射")
                else:
                    print(f"[IndependentExecutor] ⚠️ 警告：页面缓存中没有 actions_mapping")

                # 🆕 恢复event_mapping（修复bug：之前缺少这部分导致TRIGGER命令失败）
                if page.event_mapping:
                    sensors.event_mapping.clear()
                    for event_id, event_info in page.event_mapping.items():
                        sensors.event_mapping.mapping[int(event_id)] = event_info
                    # 更新id_counter为最大ID+1
                    max_event_id = max(int(k) for k in page.event_mapping.keys())
                    sensors.event_mapping.id_counter = max_event_id + 1
                    print(f"[IndependentExecutor] ✓ 恢复了 {len(page.event_mapping)} 个事件映射")
                    print(f"[IndependentExecutor] [DEBUG] 恢复的事件ID: {list(sensors.event_mapping.mapping.keys())[:5]}...")
                else:
                    print(f"[IndependentExecutor] ⚠️ 警告：页面缓存中没有 event_mapping")

                # ===== DEBUG: 验证恢复后的状态 =====
                print(f"[IndependentExecutor] [DEBUG] 恢复后的sensors状态:")
                print(f"  - sensors.actions_mapping: {len(sensors.actions_mapping.mapping)} 个")
                print(f"  - sensors.event_mapping: {len(sensors.event_mapping.mapping)} 个")
            else:
                # 兜底：重新扫描
                print(f"[IndependentExecutor] ⚠️ 未找到缓存，重新扫描")
                sensors.update_abstract_page()

                # 🔍 DEBUG: 记录扫描日志（写入文件）
                if hasattr(sensors, 'debug_scan_log'):
                    debug_log_path = photo_dir / "scan_debug.log"
                    with open(debug_log_path, 'w', encoding='utf-8') as f:
                        f.write("\n".join(sensors.debug_scan_log))
                    print(f"[IndependentExecutor] 🔍 扫描debug日志已保存: {debug_log_path}")

            # 🆕 SESSION DEBUG: 记录任务执行前的会话状态
            if self.debug_session:
                self._log_session_state(driver, task.task_id, "BEFORE", log_file=str(session_log_file))

            # ===== 步骤4: 启动轨迹记录 =====
            tracer.start_task(task.task_id, task.description)

            # ===== 步骤5: 执行任务 =====
            network_capture.clear_requests()

            # photo_dir 已在步骤3提前定义
            bridge.run_task(task, photo_dir=photo_dir, logging_in=False)

            # ===== 步骤6: 结束轨迹并保存 =====
            trace = tracer.end_task()
            if trace:
                self.shared_store.save_trace(trace)  # ✅ 线程安全
                print(f"[IndependentExecutor] ✓ Trace已保存")

            # 🆕 SESSION DEBUG: 记录任务执行后的会话状态
            if self.debug_session:
                self._log_session_state(driver, task.task_id, "AFTER", log_file=str(session_log_file))

            print(f"[IndependentExecutor] ✅ 任务完成: {task.task_id}\n")

            return {
                "task_id": task.task_id,
                "status": "success",
                "trace": trace
            }

        except Exception as e:
            print(f"[IndependentExecutor] ✗ 任务失败: {task.task_id} - {e}")
            import traceback
            traceback.print_exc()

            return {
                "task_id": task.task_id,
                "status": "error",
                "error": str(e)
            }

        finally:
            # 清理上下文
            self._current_driver = None
            self._current_sensors = None
            self._current_network_capture = None

    def _on_new_page_discovered_parallel(self, url: str):
        """
        并行执行时的新页面回调

        ✅ 内容去重检查（与串行模式一致）
        ✅ 缓存页面信息（线程安全）
        ✅ 生成任务（与串行模式一致）
        """
        # 检查是否已被处理（避免重复）
        if self.shared_store.has_page(url):
            return

        print(f"[ParallelNewPage] 发现新页面: {url}")

        try:
            # 等待页面稳定
            time.sleep(0.6)

            driver = self._current_driver
            sensors = self._current_sensors
            network_capture = self._current_network_capture

            if not all([driver, sensors, network_capture]):
                print(f"[ParallelNewPage] ✗ 上下文不完整，跳过")
                return

            # ✅ 修复：加入内容去重检查（与串行模式保持一致）
            if self.content_index:
                try:
                    html_src = driver.page_source
                    dedup_result = self.content_index.classify(url, html_src)
                    is_new = bool(dedup_result.get("is_new", True))

                    if not is_new:
                        # 重复页面：跳过处理
                        cluster_id = dedup_result.get("cluster_id")
                        repr_url = dedup_result.get("repr_url")
                        print(f"[ParallelNewPage] 页面内容重复，跳过: {url} (cluster: {cluster_id}, repr: {repr_url})")
                        return
                except Exception as e:
                    print(f"[ParallelNewPage] ⚠️ 去重检查失败，继续处理: {e}")
                    # 去重失败不影响页面处理
            else:
                print(f"[ParallelNewPage] ⚠️ content_index未提供，跳过去重检查")

            # 1. 捕获网络请求
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

            # 2. 收集页面链接
            outgoing_links = []
            try:
                elements = driver.find_elements(By.TAG_NAME, 'a')
                for elem in elements:
                    href = elem.get_attribute('href')
                    if href and '127.0.0.1' in href:
                        outgoing_links.append(href.strip())
                outgoing_links = list(set(outgoing_links))  # 去重
            except Exception as e:
                print(f"[ParallelNewPage] 收集链接失败: {e}")

            # 3. 重新扫描当前页面获取最新的DOM结构（修复：与串行模式保持一致）
            sensors.update_abstract_page()
            abstract = sensors.get_abstract_page()
            print(f"[ParallelNewPage] ✓ 已重新扫描页面获取最新DOM")

            # 4. 保存到共享store（线程安全）
            page_info = PageInfo(
                url=url,
                title=driver.title.strip() if driver.title else "",
                abstract_page=abstract,
                outgoing_links=outgoing_links,
                network_requests=network_requests,
                actions_mapping=dict(sensors.actions_mapping.mapping),
                event_mapping=dict(sensors.event_mapping.mapping)  # 🆕 保存事件映射
            )

            # ✅ Store有锁保护，线程安全
            self.shared_store.add_page(page_info, persist=True)

            print(f"[ParallelNewPage] ✓ 页面已缓存: {url}")

            # ✅ 修复：生成任务（与串行模式保持一致）
            if self.task_gen:
                page = self.shared_store.get_page(url)
                if page:
                    title = (driver.title or "").strip()
                    reasoning, task_descriptions = self.task_gen.generate_logic_for_page(page)
                    page.description = f"Title: {title}\nDescription: {reasoning}"
                    page.logic_tasks = task_descriptions
                    self.shared_store.upsert_page(page, merge_outgoing_links=False, merge_requests=False, persist=True)
                    print(f"[ParallelNewPage] ✓ 生成了 {len(task_descriptions)} 个任务")

        except Exception as e:
            print(f"[ParallelNewPage] ✗ 处理失败: {url} - {e}")

    def _construct_edge_parallel(self, url: str):
        """
        并行执行时的边构建回调（轻量级版本）

        ✅ 保留：收集链接并创建"discovered"边
        """
        try:
            driver = self._current_driver
            if not driver:
                return

            # 收集链接
            links = []
            try:
                elements = driver.find_elements(By.TAG_NAME, 'a')
                for elem in elements:
                    href = elem.get_attribute('href')
                    if href and '127.0.0.1' in href:
                        links.append(href.strip())
            except:
                pass

            # 创建"发现"边（线程安全）
            for link in links:
                if not self.shared_store.has_edge(url, link):
                    edge = Edge(
                        from_url=url,
                        to_url=link,
                        via_action_id=-1,  # -1表示未实际点击
                        via_repr="link",
                        jump_kind="discovered",
                    )
                    self.shared_store.add_edge(edge)  # ✅ 有锁保护

        except Exception as e:
            print(f"[ParallelEdge] 构建边失败: {url} - {e}")
