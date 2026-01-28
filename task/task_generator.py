# -*- coding: utf-8 -*-
# crawl/task_generator.py
from __future__ import annotations
from typing import List, Optional
from pathlib import Path
from task.tasks import Task
from app_info.models import PageInfo
from config.llm_config import get_model_name, get_temperature

class TaskGenerator:
    """
    “页面 → 任务” 生成器
    """
    def __init__(self, client, task_queue, root_dir,prompt_path: str = "prompt/task_generate.txt", crawl_prompt_path: str = "prompt/task_generate_crawl.txt",
        logic_prompt_path: str = "prompt/task_generate_logic.txt",):
        self.client = client  # 可传入你在 main 里创建的 OpenAI(client)
        self.prompt_path = Path(prompt_path)
        self.task_queue = task_queue  # 可选：用于提供 HISTORICAL TASKS
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
        # 你可以按需更换为更详细的抽象；这里组合 URL/Title/Abstract/PageInfo
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
        # 使用你新定义的 Planner Prompt（包含 PAGE CONTEXT 与 HISTORICAL TASKS 两段）
        return prompt_path.read_text(encoding="utf-8")

    def generate_navigation_for_page(self, page: PageInfo, historical: str = "") -> List[Task]:
        """
        使用 LLM 生成若干“根任务”（避免与历史重复，尽量扩展覆盖/深度）
        """
        tmpl = self._load_prompt_template(self.crawl_prompt_path)
        page_context = self._build_page_context(page)

        # 用两段式输入：System=模板；User=按规范拼接 PAGE CONTEXT / HISTORICAL TASKS
        user_block = f"""--- INPUTS YOU RECEIVE ---
PAGE CONTEXT:
{page_context}

HISTORICAL (do not repeat):
{historical}"""
        self._log_nav(f"[TaskGenerator] LLM input:\n{tmpl}\n{user_block}")
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

        # 解析 Tasks 段
        task_lines = self._parse_tasks(text)

        return task_lines
    
    def generate_logic_for_page(self, page: PageInfo):
        """
        使用 LLM 生成若干“根任务”（避免与历史重复，尽量扩展覆盖/深度）
        """
        self._log_biz(f"generate_logic_task_for_page {page.url}")
        # 这个会导致wordpress配置错误
        # if "options" in page.url or "login" in page.url:
        if "login" in page.url:
            self._log_biz(f"[TaskGenerator] Skip logic task generation for {page.url}")
            return "", []  # 返回空reasoning和空任务列表
        tmpl = self._load_prompt_template(self.logic_prompt_path)
        page_context = self._build_page_context(page)

        # 用两段式输入：System=模板；User=按规范拼接 PAGE CONTEXT / HISTORICAL TASKS
        user_block = f"""--- INPUTS YOU RECEIVE ---
PAGE CONTEXT:
{page_context}
"""
        self._log_biz(f"[TaskGenerator] LLM input:\n{tmpl}\n{user_block}")
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

        # 解析 Reasoning 和 Tasks 部分
        reasoning, task_lines = self._parse_reasoning_and_tasks(text)

        # # 构建 Task（task_id 由外部队列分配；此处给 -1 占位）
        # tasks = [Task(task_id=-1, description=desc, initial_url=page.url)
        #         for desc in task_lines]
    
        # for t in tasks:
        #     if getattr(t, "task_id", None) in (None, "-1"):
        #         t.task_id = self.task_queue.next_task_id()
        #         self._log_biz(t.task_id)
        #     self._log_biz(t.task_id)
        #     self.task_queue.push(t)

        # return reasoning
        # 构建 Task 描述列表
        task_descriptions = [desc for desc in task_lines]
        
        # 👇 修改：不要 push 到队列，而是返回任务列表
        # for t in tasks:
        #     if getattr(t, "task_id", None) in (None, "-1"):
        #         t.task_id = self.task_queue.next_task_id()
        #     self.task_queue.push(t)
        
        # 返回 reasoning 和任务列表
        return reasoning, task_descriptions

    def _parse_tasks(self, text: str) -> List[str]:
        """
        解析严格两段式输出（Reasoning/Tasks）。仅提取 Tasks 段。
        """
        # 防御：确保存在 "Tasks:" 标记
        idx = text.find("Tasks:") 
        if idx > 0:
            tasks_section = text[idx + len("Tasks:"):].strip()

            next_reason = tasks_section.find("Reasoning:")
            if next_reason >= 0:
                tasks_section = tasks_section[:next_reason].strip()

            # 按行拆
            lines = [ln.strip() for ln in tasks_section.splitlines() if ln.strip()]

        # 防御：确保存在 "Tasks:" 标记
        idx = text.find("URLs:") 
        if idx > 0:
            tasks_section = text[idx + len("URLs:"):].strip()

            next_reason = tasks_section.find("Reasoning:")
            if next_reason >= 0:
                tasks_section = tasks_section[:next_reason].strip()

            # 按行拆
            lines = [ln.strip() for ln in tasks_section.splitlines() if ln.strip()]
        
        return lines
    
    def _parse_reasoning_and_tasks(self, text: str) -> tuple[str, List[str]]:
        """
        解析两段式输出（Reasoning/Tasks）。返回 Reasoning 和 Tasks 两部分内容。
        宽松模式：Tasks 部分每行都保留，不做格式限制。
        """
        reasoning = ""
        task_lines = []
        
        # 查找 Reasoning 部分
        idx_reasoning = text.find("Reasoning:")
        if idx_reasoning >= 0:
            # 从 Reasoning: 后开始
            after_reasoning = text[idx_reasoning + len("Reasoning:"):].strip()
            
            # 查找 Tasks: 标记
            idx_tasks = after_reasoning.find("Tasks:")
            if idx_tasks >= 0:
                # Reasoning 内容是两个标记之间的部分
                reasoning = after_reasoning[:idx_tasks].strip()
                # Tasks 内容是 Tasks: 之后的部分
                tasks_text = after_reasoning[idx_tasks + len("Tasks:"):].strip()
                # 👇 宽松解析：每行都保留，只过滤完全空行
                task_lines = [
                    ln.strip()  # 只做去除首尾空格
                    for ln in tasks_text.splitlines() 
                    if ln.strip()  # 只要不是空行就保留
                ]
            else:
                # 没有 Tasks 部分，全部是 Reasoning
                reasoning = after_reasoning.strip()
        else:
            # 没有 Reasoning 标记，尝试直接查找 Tasks
            idx_tasks = text.find("Tasks:")
            if idx_tasks >= 0:
                tasks_text = text[idx_tasks + len("Tasks:"):].strip()
                # 👇 同样宽松解析
                task_lines = [
                    ln.strip()
                    for ln in tasks_text.splitlines() 
                    if ln.strip()
                ]
        
        return reasoning, task_lines

