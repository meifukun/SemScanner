


class Task:
    def __init__(self, task_id: int, description: str, initial_url: str):
        """
        初始化任务对象。
        :param task_id: 任务ID
        :param description: 任务描述
        :param url: 当前页面的URL
        """
        self.task_id = task_id
        self.description = description
        self.initial_url = initial_url
        self.history = []  # 存储历史执行步骤的记录
        self.completed = False

    def add_history(self, step: str):
        """记录任务历史执行步骤"""
        self.history.append(step)

    def set_completed(self):
        """设置任务已完成"""
        self.completed = True

    def get_history(self):
        """返回格式化后的历史记录（每行一个步骤）"""
        return '\n'.join(self.history)

    def get_status(self):
        """返回任务的当前状态"""
        return "Completed" if self.completed else "In Progress"
