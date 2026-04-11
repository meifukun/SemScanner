# task/tasks.py
from typing import List, Optional

class Task:
    def __init__(self, task_id: str, description: str, initial_url: str, parent_id: Optional[str] = None):
        """
        :param task_id: Task ID (string), e.g. "1", "1_1", "1_2_3"
        :param description: Task description
        :param initial_url: Starting URL
        :param parent_id: Parent task ID
        """
        self.task_id = str(task_id)
        self.description = description
        self.initial_url = initial_url
        self.parent_id = parent_id
        self.children: List["Task"] = []
        self.history = []
        self.completed = False

        self.add_history(f"Task initial_url='{initial_url}'")

    def add_child(self, child: "Task"):
        self.children.append(child)

    def add_history(self, step: str):
        self.history.append(step)

    def clear_history(self):
        self.history = []
        self.add_history(f"Task initial_url='{self.initial_url}'")

    def set_completed(self):
        self.completed = True

    def get_history(self):
        return '\n'.join(self.history)

    def get_status(self):
        return "Completed" if self.completed else "In Progress"
