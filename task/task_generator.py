# -*- coding: utf-8 -*-
# crawl/task_generator.py
from __future__ import annotations
from typing import List, Optional
from pathlib import Path
from task.tasks import Task
from app_info.models import PageInfo
from config.llm_config import get_model_name, get_temperature
from utils.token_tracker import tracker

class TaskGenerator:
    """
    "Page -> Task" generator
    """
    def __init__(self, client, task_queue, root_dir,prompt_path: str = "prompt/task_generate.txt", crawl_prompt_path: str = "prompt/task_generate_crawl.txt",
        logic_prompt_path: str = "prompt/task_generate_logic.txt",):
        self.client = client  # Can pass in the OpenAI(client) created in main
        self.prompt_path = Path(prompt_path)
        self.task_queue = task_queue  # Optional: used for providing HISTORICAL TASKS
        self.crawl_prompt_path = Path(crawl_prompt_path)
        self.logic_prompt_path = Path(logic_prompt_path)
        self.root_dir = Path(root_dir)
        log_base = self.root_dir/"taskgen"
        log_base.mkdir(parents=True, exist_ok=True)
        self._nav_log_path = log_base / "navigation_task_gen.log"
        self._biz_log_path = log_base / "business_task_gen.log"
        self._biz_new_log_path = log_base / "business_new_task_gen.log"

        def _mk_logger(path: Path):
            def _log(*args, sep=" ", end="\n"):
                try:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with open(path, "a", encoding="utf-8") as f:
                        f.write(sep.join(str(a) for a in args) + end)
                except Exception:
                    pass
            return _log

        self._log_nav = _mk_logger(self._nav_log_path)
        self._log_biz = _mk_logger(self._biz_log_path)
        self._log_new_biz = _mk_logger(self._biz_new_log_path)


    def _build_page_context(self, page: PageInfo, ) -> str:
        # Can be replaced with a more detailed abstract as needed; here combines URL/Title/Abstract/PageInfo
        ctx = []
        ctx.append(f"URL: {page.url}")
        if getattr(page, "title", None):
            ctx.append(f"Title: {page.title}")
        if getattr(page, "abstract_page", None):
            ctx.append("Abstract:")
            ctx.append(str(page.abstract_page))
        # if getattr(page, "page_info", None):
        #     ctx.append("Extracted Info:")
        #     ctx.append(str(page.page_info))
        return "\n".join(ctx)

    def _load_prompt_template(self, prompt_path) -> str:
        # Use your newly defined Planner Prompt (containing PAGE CONTEXT and HISTORICAL TASKS sections)
        return prompt_path.read_text(encoding="utf-8")

    def generate_navigation_for_page(self, page: PageInfo, historical: str = "") -> List[Task]:
        """
        Use LLM to generate several "root tasks" (avoid repeating history, try to expand coverage/depth)
        """
        tmpl = self._load_prompt_template(self.crawl_prompt_path)
        page_context = self._build_page_context(page)

        # Two-part input: System=template; User=assembled PAGE CONTEXT / HISTORICAL TASKS per specification
        user_block = f"""--- INPUTS YOU RECEIVE ---
PAGE CONTEXT:
{page_context}

HISTORICAL (do not repeat):
{historical}"""
        self._log_nav(f"[TaskGenerator] LLM input:\n{tmpl}\n{user_block}")
        tracker.set_category("crawl_taskgen_nav")
        completion = self.client.chat.completions.create(
            model=get_model_name("task_generator"),
            messages=[
                {"role": "system", "content": tmpl},
                {"role": "user",   "content": user_block},
            ],
            temperature=get_temperature("task_generator")
        )
        text = completion.choices[0].message.content
        self._log_nav(f"[TaskGenerator] LLM output:\n{text}")

        # Parse Tasks section
        task_lines = self._parse_tasks(text)

        return task_lines

    def generate_logic_for_page(self, page: PageInfo):
        """
        Use LLM to generate several "root tasks" (avoid repeating history, try to expand coverage/depth)
        """
        self._log_biz(f"generate_logic_task_for_page {page.url}")
        # This would cause wordpress configuration errors
        # if "options" in page.url or "login" in page.url:
        if "login" in page.url:
            self._log_biz(f"[TaskGenerator] Skip logic task generation for {page.url}")
            return "", []  # Return empty reasoning and empty task list
        tmpl = self._load_prompt_template(self.logic_prompt_path)
        page_context = self._build_page_context(page)

        # Two-part input: System=template; User=assembled PAGE CONTEXT / HISTORICAL TASKS per specification
        user_block = f"""--- INPUTS YOU RECEIVE ---
PAGE CONTEXT:
{page_context}
"""
        self._log_biz(f"[TaskGenerator] LLM input:\n{tmpl}\n{user_block}")
        tracker.set_category("crawl_taskgen_logic")
        completion = self.client.chat.completions.create(
            model=get_model_name("task_generator"),
            messages=[
                {"role": "system", "content": tmpl},
                {"role": "user",   "content": user_block},
            ],
            temperature=get_temperature("task_generator")
        )
        text = completion.choices[0].message.content
        self._log_biz(f"[TaskGenerator] LLM output:\n{text}")

        # Parse Reasoning and Tasks sections
        reasoning, task_lines = self._parse_reasoning_and_tasks(text)

        # # Build Tasks (task_id assigned by external queue; using -1 as placeholder here)
        # tasks = [Task(task_id=-1, description=desc, initial_url=page.url)
        #         for desc in task_lines]

        # for t in tasks:
        #     if getattr(t, "task_id", None) in (None, "-1"):
        #         t.task_id = self.task_queue.next_task_id()
        #         self._log_biz(t.task_id)
        #     self._log_biz(t.task_id)
        #     self.task_queue.push(t)

        # return reasoning
        # Build task description list
        task_descriptions = [desc for desc in task_lines]

        # Modified: Don't push to queue, return task list instead
        # for t in tasks:
        #     if getattr(t, "task_id", None) in (None, "-1"):
        #         t.task_id = self.task_queue.next_task_id()
        #     self.task_queue.push(t)

        # Return reasoning and task list
        return reasoning, task_descriptions

    def _parse_tasks(self, text: str) -> List[str]:
        """
        Parse strict two-section output (Reasoning/Tasks). Only extract the Tasks section.
        """
        # Defense: ensure "Tasks:" marker exists
        idx = text.find("Tasks:")
        if idx > 0:
            tasks_section = text[idx + len("Tasks:"):].strip()

            next_reason = tasks_section.find("Reasoning:")
            if next_reason >= 0:
                tasks_section = tasks_section[:next_reason].strip()

            # Split by lines
            lines = [ln.strip() for ln in tasks_section.splitlines() if ln.strip()]

        # Defense: ensure "Tasks:" marker exists
        idx = text.find("URLs:")
        if idx > 0:
            tasks_section = text[idx + len("URLs:"):].strip()

            next_reason = tasks_section.find("Reasoning:")
            if next_reason >= 0:
                tasks_section = tasks_section[:next_reason].strip()

            # Split by lines
            lines = [ln.strip() for ln in tasks_section.splitlines() if ln.strip()]

        return lines

    def _parse_reasoning_and_tasks(self, text: str) -> tuple[str, List[str]]:
        """
        Parse two-section output (Reasoning/Tasks). Return both Reasoning and Tasks sections.
        Relaxed mode: every line in the Tasks section is kept, no format restrictions.
        """
        reasoning = ""
        task_lines = []

        # Find Reasoning section
        idx_reasoning = text.find("Reasoning:")
        if idx_reasoning >= 0:
            # Start from after Reasoning:
            after_reasoning = text[idx_reasoning + len("Reasoning:"):].strip()

            # Find Tasks: marker
            idx_tasks = after_reasoning.find("Tasks:")
            if idx_tasks >= 0:
                # Reasoning content is the part between the two markers
                reasoning = after_reasoning[:idx_tasks].strip()
                # Tasks content is the part after Tasks:
                tasks_text = after_reasoning[idx_tasks + len("Tasks:"):].strip()
                # Relaxed parsing: keep every line, only filter completely empty lines
                task_lines = [
                    ln.strip()  # Only strip leading/trailing whitespace
                    for ln in tasks_text.splitlines()
                    if ln.strip()  # Keep as long as not empty
                ]
            else:
                # No Tasks section, everything is Reasoning
                reasoning = after_reasoning.strip()
        else:
            # No Reasoning marker, try to find Tasks directly
            idx_tasks = text.find("Tasks:")
            if idx_tasks >= 0:
                tasks_text = text[idx_tasks + len("Tasks:"):].strip()
                # Same relaxed parsing
                task_lines = [
                    ln.strip()
                    for ln in tasks_text.splitlines()
                    if ln.strip()
                ]

        return reasoning, task_lines
