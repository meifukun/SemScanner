# -*- coding: utf-8 -*-
# crawl/task_queue.py
from __future__ import annotations
from pathlib import Path
from typing import List, Optional
import json
from task.tasks import Task

class TaskQueue:
    """
    Simple task queue: in-memory + JSONL persistence
    - No concurrency protection (can add locks/SQLite later if needed)
    """
    def __init__(self, path: str = "output/tasks_queue.jsonl", startid = 100):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._buf: List[Task] = []
        self._next_id_hint = startid  # Starting point for auto-assigned task_id (to avoid conflicts with existing ones)

        self._discovered_tasks: List[Task] = []  # Extra task queue for storing newly discovered tasks

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
        """Push discovered task to discovered_tasks queue"""
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
        """Pop task from discovered_tasks queue"""
        return self._discovered_tasks.pop(0) if self._discovered_tasks else None

    def __len__(self):
        return len(self._buf)

    def __len_discovered(self):
        """Get the number of tasks in discovered_tasks queue"""
        return len(self._discovered_tasks)

    def peek_all(self) -> List[Task]:
        return list(self._buf)

    def peek_discovered(self) -> List[Task]:
        return list(self._discovered_tasks)

    # === New: Get all tasks in structured form (description, URL, ID) ===
    def all_tasks(self) -> List[str]:
        out: List[str] = []
        for t in self._buf:
            desc = getattr(t, "description", "") or ""
            out.append(desc)
        return out

    def all_discovered_tasks(self) -> List[str]:
        """Get all discovered task descriptions"""
        out: List[str] = []
        for t in self._discovered_tasks:
            desc = getattr(t, "description", "") or ""
            out.append(desc)
        return out


    # === New: Export as HISTORICAL TASKS text block for Planner Prompt ===
    # One task per line: "<description> @ <initial_url>"
    def historical_as_text(self, max_items: Optional[int] = None) -> str:
        items = self.all_tasks()
        if max_items is not None:
            items = items[-max_items:]  # Most recent items (strategy can be adjusted as needed)
        lines = []
        for desc in items:
            desc = desc.strip()
            lines.append(desc)

        return "\n".join(lines)
