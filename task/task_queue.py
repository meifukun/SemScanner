# -*- coding: utf-8 -*-
# crawl/task_queue.py
from __future__ import annotations
from pathlib import Path
from typing import List, Optional
import json
from task.tasks import Task

class TaskQueue:
    """
    简单任务队列：内存 + JSONL 落盘
    - 不做并发保护（后续如需要可加锁/SQLite）
    """
    def __init__(self, path: str = "output/tasks_queue.jsonl", startid = 100):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._buf: List[Task] = []
        self._next_id_hint = startid  # 自动分配 task_id 的起点（避免与你现有的冲突）

        self._discovered_tasks: List[Task] = []  # 额外的任务队列，用于存储新发现的任务

    def next_task_id(self) -> str:
        tid = self._next_id_hint
        self._next_id_hint += 1
        return str(tid)

    def push(self, task: Task, persist: bool = True):
        self._buf.append(task)
        if persist:
            payload = {
                "task_id": getattr(task, "task_id", None),
                "description": getattr(task, "description", ""),
                "initial_url": getattr(task, "initial_url", "")
            }
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def push_discovered_task(self, task: Task, persist: bool = True):
        """将发现的任务推送到 discovered_tasks 队列"""
        self._discovered_tasks.append(task)
        if persist:
            payload = {
                "task_id": getattr(task, "task_id", None),
                "description": getattr(task, "description", ""),
                "initial_url": getattr(task, "initial_url", "")
            }
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def pop(self) -> Optional[Task]:
        return self._buf.pop(0) if self._buf else None

    def pop_discovered(self) -> Optional[Task]:
        """从 discovered_tasks 队列中弹出任务"""
        return self._discovered_tasks.pop(0) if self._discovered_tasks else None

    def __len__(self):
        return len(self._buf)
    
    def __len_discovered(self):
        """获取 discovered_tasks 队列中的任务数量"""
        return len(self._discovered_tasks)

    def peek_all(self) -> List[Task]:
        return list(self._buf)
    
    def peek_discovered(self) -> List[Task]:
        return list(self._discovered_tasks)
    
    # === 新增：结构化拿到所有任务（描述、URL、ID） ===
    def all_tasks(self) -> List[str]:
        out: List[str] = []
        for t in self._buf:
            desc = getattr(t, "description", "") or ""
            out.append(desc)
        return out

    def all_discovered_tasks(self) -> List[str]:
        """获取所有新发现的任务描述"""
        out: List[str] = []
        for t in self._discovered_tasks:
            desc = getattr(t, "description", "") or ""
            out.append(desc)
        return out


    # === 新增：导出为 Planner Prompt 的 HISTORICAL TASKS 文本块 ===
    # 每行一个任务： "<description> @ <initial_url>"
    def historical_as_text(self, max_items: Optional[int] = None) -> str:
        items = self.all_tasks()
        if max_items is not None:
            items = items[-max_items:]  # 最近的若干条（可按需调整策略）
        lines = []
        for desc in items:
            desc = desc.strip()
            lines.append(desc)

        return "\n".join(lines)
