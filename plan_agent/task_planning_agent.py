"""
Task Planning Agent - Responsible for task planning and scheduling based on application graph semantics
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
from utils.token_tracker import tracker


class ActionType(Enum):
    """Action types the Planning Agent can execute"""
    EXECUTE_TASKS = "execute_tasks"      # Execute a batch of tasks
    UPDATE_PAGES = "update_pages"        # Update page information
    FINISH = "finish"                     # Complete all tasks


@dataclass
class ExecuteTasksAction:
    """Execute tasks action"""
    page_url: str
    tasks: List[str]  # List containing only descriptions
    reasoning: str = ""  # Reasoning process


@dataclass
class UpdatePagesAction:
    """Update pages action"""
    page_urls: List[str]
    reason: str  # Update reason


@dataclass
class PlanningState:
    """Planning state, tracking which pages have had their tasks executed"""
    executed_pages: Set[str] = field(default_factory=set)
    updated_pages: Set[str] = field(default_factory=set)
    total_tasks_executed: int = 0
    # New: historical action records
    action_history: List[Dict[str, str]] = field(default_factory=list)


class TaskPlanningAgent:
    """Task Planning Agent - Responsible for deciding execution order and task scheduling"""

    def __init__(self, client: OpenAI, crawler: Crawler,
                 account_manager,  # New parameter
                 prompt_file: str = "prompt/task_plan_agent.txt"):
        """
        Initialize the Task Planning Agent

        Args:
            client: OpenAI client
            crawler: Crawler instance for executing tasks
            prompt_file: Prompt file path
        """
        self.client = client
        self.crawler = crawler
        self.store = crawler.store
        self.state = PlanningState()
        self.task_queue = crawler.task_queue  # Don't create a new queue

        # Set up logging
        log_base = Path(self.crawler.root_dir) / "plan_agent"
        log_base.mkdir(parents=True, exist_ok=True)
        self._log_path = log_base / "task_plan.log"
        
        self.account_manager = account_manager  # New

        # Load prompt
        try:
            with open(prompt_file, 'r', encoding='utf-8') as f:
                self.prompt_template = f.read()
        except FileNotFoundError:
            self._log(f"[Warning] Prompt file {prompt_file} not found, using default prompt")
            self.prompt_template = self._get_default_prompt()
    
    def _log(self, *args, sep=" ", end="\n"):
        """Unified logging function"""
        msg = sep.join(str(a) for a in args)
        try:
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(msg + end)
        except Exception as e:
            print(f"[Log Error] {e}")
    
    def _get_default_prompt(self) -> str:
        """Get default prompt template"""
        return """You are a Task Planning Agent for web application security testing."""
    
    def _record_action(self, action_type: str, target: str):
        """Record historical action"""
        self.state.action_history.append({
            "action": action_type,
            "target": target
        })
    
    def _format_action_history(self) -> str:
        """Format historical actions as string"""
        if not self.state.action_history:
            return "No actions taken yet."

        lines = []
        for i, record in enumerate(self.state.action_history, 1):
            action = record["action"]
            target = record["target"]
            lines.append(f"{i}. {action}: {target}")
        return "\n".join(lines)

    def _build_graph_with_execution_status(self) -> Dict:
        """Build application graph with execution status"""
        graph = self.crawler._generate_graph_for_task_plan()

        # Add execution status to each node
        for node in graph["nodes"]:
            url = node["url"]
            node["execution_status"] = {
                "tasks_executed": url in self.state.executed_pages,
                "page_updated": url in self.state.updated_pages,
            }

        return graph

    def _check_all_pages_executed(self, graph: Dict) -> bool:
        """
        Check if all pages in the graph have been executed

        Args:
            graph: Graph with execution_status

        Returns:
            True if all pages have been executed
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

        self._log("[TaskPlanningAgent] All pages have been executed")
        return True
    
    def _call_llm(self, prompt: str) -> str:
        """Call large language model"""
        try:
            with tracker.phase("task_planning"):
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
    
    def _parse_llm_response(self, response: str) -> Tuple[ActionType, Optional[object]]:
        """
        Parse LLM response - using two-section plain text format (similar to task_generate_logic)

        Format example:
        Action: execute_tasks
        Page: http://example.com/page
        Reasoning:
        This page contains user management functions...

        Tasks:
        Create a new user account with test credentials
        Search for the newly created user
        Update the user's profile information

        Returns:
            (ActionType, action_data) tuple

        Note:
            Even if parsing fails, try to return the corresponding ActionType + empty data instead of FINISH
            This way, LLM output format issues won't terminate the entire crawling phase
        """
        self._log("[TaskPlanningAgent] Parsing LLM response...")
        self._log(f"Response preview: {response[:200]}...")

        # Extract Action type
        action_match = re.search(r'\*\*Action:\s*(\w+)\*\*|Action:\s*(\w+)', response)
        if not action_match:
            self._log("[TaskPlanningAgent] No 'Action:' field found, skipping this iteration")
            # When action cannot be identified, return empty execute_tasks, not FINISH
            return (ActionType.EXECUTE_TASKS, ExecuteTasksAction(
                page_url="",
                tasks=[],
                reasoning="Failed to parse action type"
            ))

        # Support Markdown and plain text formats, extract actual value
        action_type = (action_match.group(1) or action_match.group(2)).lower()
        self._log(f"[TaskPlanningAgent] Detected action type: {action_type}")

        if action_type == "execute_tasks":
            # Extract Page URL (supports Markdown)
            page_match = re.search(r'\*\*Page:\s*(https?://[^\s\*]+)\*\*|Page:\s*(https?://\S+)', response)
            if not page_match:
                self._log("[TaskPlanningAgent] No 'Page:' field found, returning empty task")
                # Already identified as execute_tasks, return empty task instead of FINISH
                return (ActionType.EXECUTE_TASKS, ExecuteTasksAction(
                    page_url="",
                    tasks=[],
                    reasoning="Failed to parse page URL"
                ))

            # Get matched group (could be 1 or 2)
            page_url = (page_match.group(1) or page_match.group(2)).strip()
            self._log(f"[TaskPlanningAgent] Target page: {page_url}")

            # Extract Reasoning (optional, supports Markdown)
            reasoning = ""
            reasoning_match = re.search(
                r'\*\*Reasoning:\*\*\s*\n(.*?)\n\s*\*\*Tasks:\*\*|Reasoning:\s*\n(.*?)\n\s*Tasks:',
                response,
                re.DOTALL
            )
            if reasoning_match:
                reasoning = (reasoning_match.group(1) or reasoning_match.group(2) or "").strip()

            # Extract Tasks (supports Markdown)
            tasks_match = re.search(
                r'\*\*Tasks:\*\*\s*\n(.*?)(?:\n\s*\n|\Z)|Tasks:\s*\n(.*?)(?:\n\s*\n|\Z)',
                response,
                re.DOTALL
            )
            if not tasks_match:
                self._log("[TaskPlanningAgent] No 'Tasks:' section found, returning empty task list")
                # Already identified as execute_tasks, return empty task instead of FINISH
                return (ActionType.EXECUTE_TASKS, ExecuteTasksAction(
                    page_url=page_url,
                    tasks=[],
                    reasoning=reasoning or "Failed to parse tasks section"
                ))

            # Get matched group (could be 1 or 2)
            tasks_text = (tasks_match.group(1) or tasks_match.group(2) or "").strip()
            # Split by lines, filter empty lines
            task_lines = [
                line.strip()
                for line in tasks_text.splitlines()
                if line.strip()
            ]

            if not task_lines:
                self._log("[TaskPlanningAgent] No tasks extracted (empty task list)")
                # Empty tasks is not an error, return empty list and continue, don't FINISH
                return (ActionType.EXECUTE_TASKS, ExecuteTasksAction(
                    page_url=page_url,
                    tasks=[],
                    reasoning=reasoning or "Empty task list"
                ))

            self._log(f"[TaskPlanningAgent] Extracted {len(task_lines)} tasks")

            action_data = ExecuteTasksAction(
                page_url=page_url,
                tasks=task_lines,
                reasoning=reasoning
            )
            return (ActionType.EXECUTE_TASKS, action_data)

        elif action_type == "update_pages":
            # Extract Pages (may be multiple lines)
            pages_match = re.search(r'Pages:\s*\n(.*?)\n\s*Reason:', response, re.DOTALL)
            if not pages_match:
                self._log("[TaskPlanningAgent] No 'Pages:' section found, skipping update")
                # Already identified as update_pages, return empty list instead of FINISH
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

            # Extract Reason
            reason_match = re.search(r'Reason:\s*\n(.*?)(?:\n\s*\n|\Z)', response, re.DOTALL)
            reason = reason_match.group(1).strip() if reason_match else "State changed by previous tasks"

            if not page_urls:
                self._log("[TaskPlanningAgent] No page URLs extracted, skipping update")
                # Already identified as update_pages, return empty list instead of FINISH
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
            self._log(f"[TaskPlanningAgent] Unknown action type: {action_type}, skipping")
            # Unknown action type, return empty task instead of FINISH
            return (ActionType.EXECUTE_TASKS, ExecuteTasksAction(
                page_url="",
                tasks=[],
                reasoning=f"Unknown action type: {action_type}"
            ))

    def _execute_tasks_action(self, action: ExecuteTasksAction):
        """
        Execute tasks action - fixed version

        Improvement: optimized account creation login logic after creation
        """
        self._log(f"\n[TaskPlanningAgent] Executing tasks for page: {action.page_url}")
        self._log(f"[TaskPlanningAgent] Number of tasks: {len(action.tasks)}")
        if action.reasoning:
            self._log(f"[TaskPlanningAgent] Reasoning: {action.reasoning}")

        # If page_url is empty, return directly
        if not action.page_url:
            self._log(f"[TaskPlanningAgent] Skipping execution (empty page_url)")
            return

        if not self.crawler.is_url_in_scope(action.page_url):
            self._log(
                f"[ScopeGuard] Refusing task page outside target origin: "
                f"{action.page_url}"
            )
            return

        if not self.store.has_page(action.page_url):
            self._log(
                f"[TaskPlanningAgent] Page is not present in the semantic graph, "
                f"skipping: {action.page_url}"
            )
            return

        # If task list is empty, also mark page as executed (avoid infinite loop)
        if not action.tasks:
            self._log(f"[TaskPlanningAgent] No tasks to execute, but marking page as executed")
            self._record_action("EXECUTE_TASKS", action.page_url)
            self.state.executed_pages.add(action.page_url)
            return

        # Fix: Planning Agent can update page task definitions
        # This allows Planning Agent to adjust task list at runtime
        # Note: action.tasks must be the correctly parsed task list (plain text array), not LLM response raw format
        page = self.store.get_page(action.page_url)
        if page:
            self._log(f"[TaskPlanningAgent] Updating page tasks from {len(page.logic_tasks)} to {len(action.tasks)}")
            page.logic_tasks = action.tasks
            self.store.upsert_page(page, merge_outgoing_links=False, merge_requests=False, persist=True)

        # Build tasks and add to queue
        for task_desc in action.tasks:
            task_id = self.task_queue.next_task_id()
            task = Task(
                task_id=task_id,
                description=task_desc,
                initial_url=action.page_url
            )
            self.task_queue.push(task)
            self.state.total_tasks_executed += 1
        
        # Execute all tasks in the queue
        while True:
            task = self.task_queue.pop()
            if task is None:
                break
            
            self._log(f"[TaskPlanningAgent] Executing task {task.task_id}: {task.description}")
            self.crawler.run_a_task(task)
            time.sleep(0.5)
        
        # Record operation history
        self._record_action("EXECUTE_TASKS", action.page_url)

        # Mark this page's tasks as executed
        self.state.executed_pages.add(action.page_url)


    def _update_pages_action(self, action: UpdatePagesAction):
        """Update page information action"""
        self._log(f"\n[TaskPlanningAgent] Updating {len(action.page_urls)} pages")
        self._log(f"[TaskPlanningAgent] Reason: {action.reason}")

        # If page_urls is empty, skip execution
        if not action.page_urls:
            self._log(f"[TaskPlanningAgent] Skipping update (empty page_urls list)")
            return

        for page_url in action.page_urls:
            self._log(f"[TaskPlanningAgent] Updating page: {page_url}")

            if not self.crawler.is_url_in_scope(page_url):
                self._log(f"[ScopeGuard] Refusing page update outside target origin: {page_url}")
                continue
            if not self.store.has_page(page_url):
                self._log(f"[TaskPlanningAgent] Page is not present in the graph: {page_url}")
                continue
            
            # Navigate to the page
            self.crawler.driver.get(page_url)
            time.sleep(0.6)
            if not self.crawler.is_url_in_scope(self.crawler.driver.current_url):
                self._log(
                    f"[ScopeGuard] Page update left target origin: "
                    f"{page_url} -> {self.crawler.driver.current_url}"
                )
                self.crawler.driver.get(self.crawler.initial_url)
                continue
            
            # Recollect page information
            self.crawler._collect_page_info(page_url)
            
            # Regenerate tasks
            page = self.store.get_page(page_url)
            if page:
                title = (self.crawler.driver.title or "").strip()
                reasoning, task_descriptions = self.crawler.task_gen.generate_logic_for_page(page)
                page.description = f"Title: {title}\nDescription: {reasoning}"
                page.logic_tasks = task_descriptions
                self.store.add_page(page, persist=True)
                
                self._log(f"[TaskPlanningAgent] Updated {len(task_descriptions)} tasks for {page_url}")
            
            # Record historical action
            self._record_action("UPDATE_PAGES", page_url)
            
            # Mark page as updated
            self.state.updated_pages.add(page_url)
            # After page update, tasks need to be re-executed
            self.state.executed_pages.discard(page_url)

    def _plan_next_action(self):
        """
        Plan the next action for one scheduler iteration.

        This method is used by the parallel scheduler. The implementation
        mirrors the previously working code in /data/users/meifukun/Web-Agent/Web-Agent.
        """
        graph_with_status = self._build_graph_with_execution_status()

        if self._check_all_pages_executed(graph_with_status):
            self._log("[TaskPlanningAgent] All pages executed, returning FINISH directly")
            return ("FINISH", None)

        action_history_str = self._format_action_history()
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

        self._log("[TaskPlanningAgent] Consulting LLM for next action...")
        llm_response = self._call_llm(prompt)

        self._log("\n[LLM Response]:")
        self._log(llm_response)
        self._log("\n" + "="*60)

        if not llm_response:
            self._log("[TaskPlanningAgent] Empty LLM response, returning FINISH")
            return ("FINISH", None)

        action_type, action_data = self._parse_llm_response(llm_response)

        if action_type == ActionType.EXECUTE_TASKS:
            return ("EXECUTE_TASKS", action_data)
        elif action_type == ActionType.UPDATE_PAGES:
            return ("UPDATE_PAGES", action_data)
        elif action_type == ActionType.FINISH:
            return ("FINISH", None)
        else:
            return ("FINISH", None)

    def plan_and_execute(self, max_iterations: int = 1000):
        """
        Main planning and execution loop

        Args:
            max_iterations: Maximum iteration count to prevent infinite loops
        """
        self._log("[TaskPlanningAgent] Starting task planning and execution")

        # Removed old logic: no longer auto-mark first page as executed
        # Reasons:
        # 1. In the new framework, login task is completed in Phase 3, not in deep_crawl graph
        # 2. Deep crawl starts from the post-login page, first page may be a functional page like profile
        # 3. Should not assume the first page is a login page and skip its tasks
        self._log(f"[TaskPlanningAgent] Starting fresh - no pages pre-marked as executed")

        iteration = 0
        while iteration < max_iterations:
            iteration += 1
            self._log(f"\n{'='*60}")
            self._log(f"[TaskPlanningAgent] Iteration {iteration}")

            # Build current state graph (dynamically updated, includes newly discovered pages)
            graph_with_status = self._build_graph_with_execution_status()

            # New: Pre-check if all pages have been executed (avoid LLM hallucination)
            if self._check_all_pages_executed(graph_with_status):
                self._log("[TaskPlanningAgent] All pages executed, skipping LLM call, finishing directly")
                break

            # Format historical actions
            action_history_str = self._format_action_history()

            # Prepare prompt
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

            # Call LLM to get next action
            self._log("[TaskPlanningAgent] Consulting LLM for next action...")
            llm_response = self._call_llm(prompt)

            # Record full LLM response to log
            self._log("\n[LLM Response]:")
            self._log(llm_response)
            self._log("\n" + "="*60)

            if not llm_response:
                self._log("[TaskPlanningAgent] Empty LLM response, finishing")
                break

            # Parse response
            action_type, action_data = self._parse_llm_response(llm_response)

            # Execute action
            if action_type == ActionType.EXECUTE_TASKS:
                self._execute_tasks_action(action_data)
            elif action_type == ActionType.UPDATE_PAGES:
                self._update_pages_action(action_data)
            elif action_type == ActionType.FINISH:
                self._log("[TaskPlanningAgent] Planning completed - all tasks executed")
                break
        
        # Output final statistics
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
