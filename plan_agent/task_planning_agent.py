"""
Task Planning Agent - 负责基于应用图语义进行任务规划和调度
"""

import json
import re
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
import time
from pathlib import Path
from openai import OpenAI
from task.task_queue import TaskQueue
from task.tasks import Task
from app_info.webapp_store import WebAppStore
from crawl.crawler import Crawler
from config.llm_config import get_model_name, get_temperature


class ActionType(Enum):
    """规划 Agent 可以执行的操作类型"""
    EXECUTE_TASKS = "execute_tasks"      # 执行一批任务
    UPDATE_PAGES = "update_pages"        # 更新页面信息
    FINISH = "finish"                     # 完成所有任务


@dataclass
class ExecuteTasksAction:
    """执行任务的动作"""
    page_url: str
    tasks: List[str]  # 只包含 description 的列表
    reasoning: str = ""  # 推理过程


@dataclass
class UpdatePagesAction:
    """更新页面的动作"""
    page_urls: List[str]
    reason: str  # 更新原因


@dataclass
class PlanningState:
    """规划状态，追踪哪些页面的任务已执行"""
    executed_pages: Set[str] = field(default_factory=set)
    updated_pages: Set[str] = field(default_factory=set)
    total_tasks_executed: int = 0
    # 新增：历史操作记录
    action_history: List[Dict[str, str]] = field(default_factory=list)


class TaskPlanningAgent:
    """任务规划 Agent - 负责决定执行顺序和任务调度"""
    
    def __init__(self, client: OpenAI, crawler: Crawler, 
                 account_manager,  # ← 新增参数
                 prompt_file: str = "prompt/task_plan_agent.txt"):
        """
        初始化任务规划 Agent
        
        Args:
            client: OpenAI 客户端
            crawler: 爬虫实例，用于执行任务
            prompt_file: 提示词文件路径
        """
        self.client = client
        self.crawler = crawler
        self.store = crawler.store
        self.state = PlanningState()
        self.task_queue = crawler.task_queue  # 不创建新队列
        
        # 设置日志
        log_base = Path(self.crawler.root_dir) / "plan_agent"
        log_base.mkdir(parents=True, exist_ok=True)
        self._log_path = log_base / "task_plan.log"
        
        self.account_manager = account_manager  # ← 新增

        # 加载提示词
        try:
            with open(prompt_file, 'r', encoding='utf-8') as f:
                self.prompt_template = f.read()
        except FileNotFoundError:
            self._log(f"[Warning] Prompt file {prompt_file} not found, using default prompt")
            self.prompt_template = self._get_default_prompt()
    
    def _log(self, *args, sep=" ", end="\n"):
        """统一日志函数"""
        msg = sep.join(str(a) for a in args)
        try:
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(msg + end)
        except Exception as e:
            print(f"[Log Error] {e}")
    
    def _get_default_prompt(self) -> str:
        """获取默认提示词模板"""
        return """You are a Task Planning Agent for web application security testing."""
    
    def _record_action(self, action_type: str, target: str):
        """记录历史操作"""
        self.state.action_history.append({
            "action": action_type,
            "target": target
        })
    
    def _format_action_history(self) -> str:
        """格式化历史操作为字符串"""
        if not self.state.action_history:
            return "No actions taken yet."

        lines = []
        for i, record in enumerate(self.state.action_history, 1):
            action = record["action"]
            target = record["target"]
            lines.append(f"{i}. {action}: {target}")
        return "\n".join(lines)

    def _build_graph_with_execution_status(self) -> Dict:
        """构建带有执行状态的应用图"""
        graph = self.crawler._generate_graph_for_task_plan()

        # 为每个节点添加执行状态
        for node in graph["nodes"]:
            url = node["url"]
            node["execution_status"] = {
                "tasks_executed": url in self.state.executed_pages,
                "page_updated": url in self.state.updated_pages,
            }

        return graph

    def _check_all_pages_executed(self, graph: Dict) -> bool:
        """
        检查图中所有页面是否都已执行

        Args:
            graph: 带有execution_status的图

        Returns:
            True if 所有页面都已执行
        """
        nodes = graph.get("nodes", [])

        if not nodes:
            self._log("[TaskPlanningAgent] No nodes in graph, considering as all executed")
            return True

        for node in nodes:
            url = node["url"]
            execution_status = node.get("execution_status", {})
            tasks_executed = execution_status.get("tasks_executed", False)

            if not tasks_executed:
                self._log(f"[TaskPlanningAgent] Page not executed: {url}")
                return False

        self._log("[TaskPlanningAgent] ✅ All pages have been executed")
        return True
    
    def _call_llm(self, prompt: str) -> str:
        """调用大语言模型"""
        try:
            response = self.client.chat.completions.create(
                model=get_model_name("task_planning"),
                messages=[
                    {"role": "system", "content": "You are a task planning expert for web application testing."},
                    {"role": "user", "content": prompt}
                ],
                temperature=get_temperature("task_planning")
            )
            return response.choices[0].message.content
        except Exception as e:
            self._log(f"[TaskPlanningAgent] LLM call failed: {e}")
            return ""
    
    # def _parse_llm_response(self, response: str) -> Tuple[ActionType, Optional[object]]:
    #     """
    #     解析 LLM 响应 - 使用两段式纯文本格式（类似 task_generate_logic）
        
    #     格式示例:
    #     Action: execute_tasks
    #     Page: http://example.com/page
    #     Reasoning: 
    #     This page contains user management functions...
        
    #     Tasks:
    #     Create a new user account with test credentials
    #     Search for the newly created user
    #     Update the user's profile information
        
    #     Returns:
    #         (ActionType, action_data) 元组
    #     """
    #     try:
    #         self._log("[TaskPlanningAgent] Parsing LLM response...")
    #         self._log(f"Response preview: {response[:200]}...")
            
    #         # 提取 Action 类型
    #         action_match = re.search(r'Action:\s*(\w+)', response, re.IGNORECASE)
    #         if not action_match:
    #             self._log("[TaskPlanningAgent] No 'Action:' field found")
    #             return (ActionType.FINISH, None)
            
    #         action_type = action_match.group(1).lower()
    #         self._log(f"[TaskPlanningAgent] Detected action type: {action_type}")
            
    #         if action_type == "execute_tasks":
    #             # 提取 Page URL
    #             page_match = re.search(r'Page:\s*(.+?)(?:\n|$)', response)
    #             if not page_match:
    #                 self._log("[TaskPlanningAgent] No 'Page:' field found")
    #                 return (ActionType.FINISH, None)
                
    #             page_url = page_match.group(1).strip()
    #             self._log(f"[TaskPlanningAgent] Target page: {page_url}")
                
    #             # 提取 Reasoning（可选）
    #             reasoning = ""
    #             reasoning_match = re.search(r'Reasoning:\s*\n(.*?)\n\s*Tasks:', response, re.DOTALL)
    #             if reasoning_match:
    #                 reasoning = reasoning_match.group(1).strip()
                
    #             # 提取 Tasks（必须）
    #             tasks_match = re.search(r'Tasks:\s*\n(.*?)(?:\n\s*\n|\Z)', response, re.DOTALL)
    #             if not tasks_match:
    #                 self._log("[TaskPlanningAgent] No 'Tasks:' section found")
    #                 return (ActionType.FINISH, None)
                
    #             tasks_text = tasks_match.group(1).strip()
    #             # 按行分割，过滤空行
    #             task_lines = [
    #                 line.strip() 
    #                 for line in tasks_text.splitlines() 
    #                 if line.strip()
    #             ]
                
    #             if not task_lines:
    #                 self._log("[TaskPlanningAgent] No tasks extracted")
    #                 return (ActionType.FINISH, None)
                
    #             self._log(f"[TaskPlanningAgent] Extracted {len(task_lines)} tasks")
                
    #             return (ActionType.EXECUTE_TASKS, ExecuteTasksAction(
    #                 page_url=page_url,
    #                 tasks=task_lines,
    #                 reasoning=reasoning
    #             ))
            
    #         elif action_type == "update_pages":
    #             # 提取 Pages (可能是多行)
    #             pages_match = re.search(r'Pages:\s*\n(.*?)\n\s*Reason:', response, re.DOTALL)
    #             if not pages_match:
    #                 self._log("[TaskPlanningAgent] No 'Pages:' section found")
    #                 return (ActionType.FINISH, None)
                
    #             pages_text = pages_match.group(1).strip()
    #             page_urls = [
    #                 line.strip() 
    #                 for line in pages_text.splitlines() 
    #                 if line.strip()
    #             ]
                
    #             # 提取 Reason
    #             reason_match = re.search(r'Reason:\s*\n(.*?)(?:\n\s*\n|\Z)', response, re.DOTALL)
    #             reason = reason_match.group(1).strip() if reason_match else "State changed by previous tasks"
                
    #             if not page_urls:
    #                 self._log("[TaskPlanningAgent] No page URLs extracted")
    #                 return (ActionType.FINISH, None)
                
    #             return (ActionType.UPDATE_PAGES, UpdatePagesAction(
    #                 page_urls=page_urls,
    #                 reason=reason
    #             ))
            
    #         elif action_type == "finish":
    #             return (ActionType.FINISH, None)
            
    #         else:
    #             self._log(f"[TaskPlanningAgent] Unknown action type: {action_type}")
    #             return (ActionType.FINISH, None)
        
    #     except Exception as e:
    #         self._log(f"[TaskPlanningAgent] Response parsing error: {e}")
    #         import traceback
    #         self._log(traceback.format_exc())
    #         return (ActionType.FINISH, None)

    def _parse_llm_response(self, response: str) -> Tuple[ActionType, Optional[object]]:
        """
        解析 LLM 响应 - 使用两段式纯文本格式（类似 task_generate_logic）

        格式示例:
        Action: execute_tasks
        Page: http://example.com/page
        Reasoning:
        This page contains user management functions...

        Tasks:
        Create a new user account with test credentials
        Search for the newly created user
        Update the user's profile information

        Returns:
            (ActionType, action_data) 元组

        Note:
            即使解析失败，也尽量返回对应的ActionType + 空数据，而不是FINISH
            这样不会因为LLM输出格式问题就终止整个爬取阶段
        """
        self._log("[TaskPlanningAgent] Parsing LLM response...")
        self._log(f"Response preview: {response[:200]}...")

        # 提取 Action 类型
        action_match = re.search(r'\*\*Action:\s*(\w+)\*\*|Action:\s*(\w+)', response)
        if not action_match:
            self._log("[TaskPlanningAgent] ⚠️ No 'Action:' field found, skipping this iteration")
            # ✅ 无法识别action时，返回空的execute_tasks，不要FINISH
            return (ActionType.EXECUTE_TASKS, ExecuteTasksAction(
                page_url="",
                tasks=[],
                reasoning="Failed to parse action type"
            ))

        # 支持Markdown和纯文本格式，提取实际值
        action_type = (action_match.group(1) or action_match.group(2)).lower()
        self._log(f"[TaskPlanningAgent] Detected action type: {action_type}")

        if action_type == "execute_tasks":
            # 提取 Page URL（支持Markdown）
            page_match = re.search(r'\*\*Page:\s*(https?://[^\s\*]+)\*\*|Page:\s*(https?://\S+)', response)
            if not page_match:
                self._log("[TaskPlanningAgent] ⚠️ No 'Page:' field found, returning empty task")
                # ✅ 已经识别出是execute_tasks，返回空任务而不是FINISH
                return (ActionType.EXECUTE_TASKS, ExecuteTasksAction(
                    page_url="",
                    tasks=[],
                    reasoning="Failed to parse page URL"
                ))

            # 获取匹配的group（可能是1或2）
            page_url = (page_match.group(1) or page_match.group(2)).strip()
            self._log(f"[TaskPlanningAgent] Target page: {page_url}")

            # 提取 Reasoning（可选，支持Markdown）
            reasoning = ""
            reasoning_match = re.search(
                r'\*\*Reasoning:\*\*\s*\n(.*?)\n\s*\*\*Tasks:\*\*|Reasoning:\s*\n(.*?)\n\s*Tasks:',
                response,
                re.DOTALL
            )
            if reasoning_match:
                reasoning = (reasoning_match.group(1) or reasoning_match.group(2) or "").strip()

            # 提取 Tasks（支持Markdown）
            tasks_match = re.search(
                r'\*\*Tasks:\*\*\s*\n(.*?)(?:\n\s*\n|\Z)|Tasks:\s*\n(.*?)(?:\n\s*\n|\Z)',
                response,
                re.DOTALL
            )
            if not tasks_match:
                self._log("[TaskPlanningAgent] ⚠️ No 'Tasks:' section found, returning empty task list")
                # ✅ 已经识别出是execute_tasks，返回空任务而不是FINISH
                return (ActionType.EXECUTE_TASKS, ExecuteTasksAction(
                    page_url=page_url,
                    tasks=[],
                    reasoning=reasoning or "Failed to parse tasks section"
                ))

            # 获取匹配的group（可能是1或2）
            tasks_text = (tasks_match.group(1) or tasks_match.group(2) or "").strip()
            # 按行分割，过滤空行
            task_lines = [
                line.strip()
                for line in tasks_text.splitlines()
                if line.strip()
            ]

            if not task_lines:
                self._log("[TaskPlanningAgent] ⚠️ No tasks extracted (empty task list)")
                # ✅ 空任务不是错误，返回空列表继续，不要FINISH
                return (ActionType.EXECUTE_TASKS, ExecuteTasksAction(
                    page_url=page_url,
                    tasks=[],
                    reasoning=reasoning or "Empty task list"
                ))

            self._log(f"[TaskPlanningAgent] Extracted {len(task_lines)} tasks")

            # ✅ 新逻辑：提取账户创建信息（单行登录任务描述）
            # ⚠️ 已禁用：动态账户创建功能已注释
            # account_creation = None
            # # 不过这里可能和目前的prompt格式没统一好
            # ac_match = re.search(
            #     r'New_Account_Login_Task:\s*\n(.+?)\nRole:\s*(\w+)',
            #     response,
            #     re.DOTALL
            # )
            # if ac_match:
            #     login_task_desc = ac_match.group(1).strip()
            #     role = ac_match.group(2).strip()
            #     account_creation = {
            #         "login_task_description": login_task_desc,
            #         "role": role
            #     }

            action_data = ExecuteTasksAction(
                page_url=page_url,
                tasks=task_lines,
                reasoning=reasoning
            )
            # if account_creation:
            #     action_data.account_creation = account_creation

            return (ActionType.EXECUTE_TASKS, action_data)

        elif action_type == "update_pages":
            # 提取 Pages (可能是多行)
            pages_match = re.search(r'Pages:\s*\n(.*?)\n\s*Reason:', response, re.DOTALL)
            if not pages_match:
                self._log("[TaskPlanningAgent] ⚠️ No 'Pages:' section found, skipping update")
                # ✅ 已经识别出是update_pages，返回空列表而不是FINISH
                return (ActionType.UPDATE_PAGES, UpdatePagesAction(
                    page_urls=[],
                    reason="Failed to parse pages section"
                ))

            pages_text = pages_match.group(1).strip()
            page_urls = [
                line.strip()
                for line in pages_text.splitlines()
                if line.strip()
            ]

            # 提取 Reason
            reason_match = re.search(r'Reason:\s*\n(.*?)(?:\n\s*\n|\Z)', response, re.DOTALL)
            reason = reason_match.group(1).strip() if reason_match else "State changed by previous tasks"

            if not page_urls:
                self._log("[TaskPlanningAgent] ⚠️ No page URLs extracted, skipping update")
                # ✅ 已经识别出是update_pages，返回空列表而不是FINISH
                return (ActionType.UPDATE_PAGES, UpdatePagesAction(
                    page_urls=[],
                    reason=reason
                ))

            return (ActionType.UPDATE_PAGES, UpdatePagesAction(
                page_urls=page_urls,
                reason=reason
            ))

        elif action_type == "finish":
            return (ActionType.FINISH, None)

        else:
            self._log(f"[TaskPlanningAgent] ⚠️ Unknown action type: {action_type}, skipping")
            # ✅ 未知action type，返回空任务而不是FINISH
            return (ActionType.EXECUTE_TASKS, ExecuteTasksAction(
                page_url="",
                tasks=[],
                reasoning=f"Unknown action type: {action_type}"
            ))

    def _execute_tasks_action(self, action: ExecuteTasksAction):
        """
        执行任务动作 - 修复版

        改进：账户创建后的登录逻辑优化
        """
        self._log(f"\n[TaskPlanningAgent] Executing tasks for page: {action.page_url}")
        self._log(f"[TaskPlanningAgent] Number of tasks: {len(action.tasks)}")
        if action.reasoning:
            self._log(f"[TaskPlanningAgent] Reasoning: {action.reasoning}")

        # ✅ 如果page_url为空，直接返回
        if not action.page_url:
            self._log(f"[TaskPlanningAgent] Skipping execution (empty page_url)")
            return

        # ✅ 如果任务列表为空，也要标记页面为已执行（避免无限循环）
        if not action.tasks:
            self._log(f"[TaskPlanningAgent] No tasks to execute, but marking page as executed")
            self._record_action("EXECUTE_TASKS", action.page_url)
            self.state.executed_pages.add(action.page_url)
            return

        # ✅ 修复：Planning Agent可以更新页面的任务定义
        # 这允许Planning Agent在运行时调整任务列表
        # 注意：action.tasks 必须是正确解析出来的任务列表（纯文本数组），而不是LLM响应的原始格式
        page = self.store.get_page(action.page_url)
        if page:
            self._log(f"[TaskPlanningAgent] Updating page tasks from {len(page.logic_tasks)} to {len(action.tasks)}")
            page.logic_tasks = action.tasks
            self.store.upsert_page(page, merge_outgoing_links=False, merge_requests=False, persist=True)

        # 构建任务并加入队列
        for task_desc in action.tasks:
            task_id = self.task_queue.next_task_id()
            task = Task(
                task_id=task_id,
                description=task_desc,
                initial_url=action.page_url
            )
            self.task_queue.push(task)
            self.state.total_tasks_executed += 1
        
        # 执行队列中的所有任务
        while True:
            task = self.task_queue.pop()
            if task is None:
                break
            
            self._log(f"[TaskPlanningAgent] Executing task {task.task_id}: {task.description}")
            self.crawler.run_a_task(task)
            time.sleep(0.5)
        
        # 记录操作历史
        self._record_action("EXECUTE_TASKS", action.page_url)

        # 标记该页面的任务已执行
        self.state.executed_pages.add(action.page_url)

        # ✅ 账户创建逻辑
        # ⚠️ 已禁用：动态账户创建功能已注释
        # 原因：
        # 1. 大部分场景下用不到这个功能
        # 2. 避免driver状态污染（每次登录会切换driver状态）
        # 3. 简化账户管理逻辑
        # if hasattr(action, 'account_creation'):
        #     ac = action.account_creation
        #
        #     # 直接使用 LLM 生成的登录任务描述
        #     login_task_desc = ac["login_task_description"]
        #     role = ac["role"]
        #
        #     # 生成唯一 account_id
        #     timestamp = int(time.time())
        #     account_id = f"created_{role}_{timestamp}"
        #
        #     # 添加账户
        #     account = self.account_manager.add_account(
        #         login_task_description=login_task_desc,
        #         role=role,
        #         account_id=account_id
        #     )
        #
        #     # 执行登录
        #     try:
        #         success = self.account_manager.login_account(
        #             account=account,
        #             bridge=self.crawler.bridge
        #         )
        #         if success:
        #             self._log(f"[TaskPlanning] ✅ New account created and logged in")
        #             self._log(f"  - Account ID: {account_id}")
        #             self._log(f"  - Task: {login_task_desc}")
        #         else:
        #             self._log(f"[TaskPlanning] ⚠️ Account created but login failed")
        #     except Exception as e:
        #         self._log(f"[TaskPlanning] ⚠️ Login failed: {e}")

    
    def _update_pages_action(self, action: UpdatePagesAction):
        """更新页面信息动作"""
        self._log(f"\n[TaskPlanningAgent] Updating {len(action.page_urls)} pages")
        self._log(f"[TaskPlanningAgent] Reason: {action.reason}")

        # ✅ 如果page_urls为空，跳过执行
        if not action.page_urls:
            self._log(f"[TaskPlanningAgent] Skipping update (empty page_urls list)")
            return

        for page_url in action.page_urls:
            self._log(f"[TaskPlanningAgent] Updating page: {page_url}")
            
            # 导航到页面
            self.crawler.driver.get(page_url)
            time.sleep(0.6)
            
            # 重新收集页面信息
            self.crawler._collect_page_info(page_url)
            
            # 重新生成任务
            page = self.store.get_page(page_url)
            if page:
                title = (self.crawler.driver.title or "").strip()
                reasoning, task_descriptions = self.crawler.task_gen.generate_logic_for_page(page)
                page.description = f"Title: {title}\nDescription: {reasoning}"
                page.logic_tasks = task_descriptions
                self.store.add_page(page, persist=True)
                
                self._log(f"[TaskPlanningAgent] Updated {len(task_descriptions)} tasks for {page_url}")
            
            # 记录历史操作
            self._record_action("UPDATE_PAGES", page_url)
            
            # 标记页面已更新
            self.state.updated_pages.add(page_url)
            # 页面更新后，需要重新执行任务
            self.state.executed_pages.discard(page_url)
    
    def _plan_next_action(self):
        """
        规划下一步操作（单次迭代）

        供并行调度器调用的方法

        Returns:
            (action_type_str, action_data): 元组
                - action_type_str: "EXECUTE_TASKS" | "UPDATE_PAGES" | "FINISH"
                - action_data: ExecuteTasksAction | UpdatePagesAction | None
        """
        # 构建当前状态的图（动态更新，包含新发现的页面）
        graph_with_status = self._build_graph_with_execution_status()

        # ✅ 新增：提前检查是否所有页面都已执行（避免LLM幻觉）
        if self._check_all_pages_executed(graph_with_status):
            self._log("[TaskPlanningAgent] 🎯 All pages executed, skipping LLM call, returning FINISH directly")
            return ("FINISH", None)

        # 格式化历史操作
        action_history_str = self._format_action_history()

        # 准备提示词
        graph_json = json.dumps(graph_with_status, indent=2, ensure_ascii=False)
        prompt = self.prompt_template.format(
            graph_json=graph_json,
            executed_pages=list(self.state.executed_pages),
            updated_pages=list(self.state.updated_pages),
            total_tasks_executed=self.state.total_tasks_executed,
            action_history=action_history_str
        )

        self._log("\n" + "="*60)
        self._log("[Current Graph State]")
        self._log(graph_json)
        self._log("="*60 + "\n")

        # 调用 LLM 获取下一步操作
        self._log("[TaskPlanningAgent] Consulting LLM for next action...")
        llm_response = self._call_llm(prompt)

        # 记录完整的 LLM 响应到日志
        self._log("\n[LLM Response]:")
        self._log(llm_response)
        self._log("\n" + "="*60)

        if not llm_response:
            self._log("[TaskPlanningAgent] Empty LLM response, returning FINISH")
            return ("FINISH", None)

        # 解析响应
        action_type, action_data = self._parse_llm_response(llm_response)

        # 转换ActionType枚举为字符串
        if action_type == ActionType.EXECUTE_TASKS:
            return ("EXECUTE_TASKS", action_data)
        elif action_type == ActionType.UPDATE_PAGES:
            return ("UPDATE_PAGES", action_data)
        elif action_type == ActionType.FINISH:
            return ("FINISH", None)
        else:
            # 未知action，返回FINISH
            return ("FINISH", None)

    def plan_and_execute(self, max_iterations: int = 1000):
        """
        主规划和执行循环

        Args:
            max_iterations: 最大迭代次数，防止无限循环
        """
        self._log("[TaskPlanningAgent] Starting task planning and execution")

        # 🗑️ 移除旧逻辑：不再自动标记第一个页面为已执行
        # 原因：
        # 1. 在新框架中，登录任务在阶段3已完成，不在deep_crawl的图里
        # 2. 深度爬取从登录后的页面开始，第一个页面可能是profile等功能页面
        # 3. 不应假设第一个页面就是登录页面并跳过其任务
        self._log(f"[TaskPlanningAgent] Starting fresh - no pages pre-marked as executed")

        iteration = 0
        while iteration < max_iterations:
            iteration += 1
            self._log(f"\n{'='*60}")
            self._log(f"[TaskPlanningAgent] Iteration {iteration}")

            # 构建当前状态的图（动态更新，包含新发现的页面）
            graph_with_status = self._build_graph_with_execution_status()

            # ✅ 新增：提前检查是否所有页面都已执行（避免LLM幻觉）
            if self._check_all_pages_executed(graph_with_status):
                self._log("[TaskPlanningAgent] 🎯 All pages executed, skipping LLM call, finishing directly")
                break

            # 格式化历史操作
            action_history_str = self._format_action_history()

            # 准备提示词
            graph_json=json.dumps(graph_with_status, indent=2, ensure_ascii=False)
            prompt = self.prompt_template.format(
                graph_json=graph_json,
                executed_pages=list(self.state.executed_pages),
                updated_pages=list(self.state.updated_pages),
                total_tasks_executed=self.state.total_tasks_executed,
                action_history=action_history_str
            )

            self._log("\n" + "="*60)
            self._log("[Current Graph State]")
            self._log(graph_json)
            self._log("="*60 + "\n")

            # 调用 LLM 获取下一步操作
            self._log("[TaskPlanningAgent] Consulting LLM for next action...")
            llm_response = self._call_llm(prompt)

            # 记录完整的 LLM 响应到日志
            self._log("\n[LLM Response]:")
            self._log(llm_response)
            self._log("\n" + "="*60)

            if not llm_response:
                self._log("[TaskPlanningAgent] Empty LLM response, finishing")
                break

            # 解析响应
            action_type, action_data = self._parse_llm_response(llm_response)

            # 执行操作
            if action_type == ActionType.EXECUTE_TASKS:
                self._execute_tasks_action(action_data)
            elif action_type == ActionType.UPDATE_PAGES:
                self._update_pages_action(action_data)
            elif action_type == ActionType.FINISH:
                self._log("[TaskPlanningAgent] Planning completed - all tasks executed")
                break
        
        # 输出最终统计
        self._log(f"\n{'='*60}")
        self._log("[TaskPlanningAgent] Final Statistics:")
        self._log(f"  - Total iterations: {iteration}")
        self._log(f"  - Total tasks executed: {self.state.total_tasks_executed}")
        self._log(f"  - Pages with executed tasks: {len(self.state.executed_pages)}")
        self._log(f"  - Pages updated: {len(self.state.updated_pages)}")
        self._log(f"\n[TaskPlanningAgent] Action History:")
        self._log(self._format_action_history())
        
        return {
            "iterations": iteration,
            "total_tasks": self.state.total_tasks_executed,
            "executed_pages": list(self.state.executed_pages),
            "updated_pages": list(self.state.updated_pages),
            "action_history": self.state.action_history
        }
    
    def reset_state(self):
        """重置规划状态"""
        self.state = PlanningState()
        self._log("[TaskPlanningAgent] State reset")