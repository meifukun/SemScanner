import time
import openai
from typing import Optional
from app_info.tasks import Task 
import os

class Bridge:
    def __init__(self, sensors, actuators, client):
        self.sensors = sensors
        self.driver = sensors.driver
        self.actuators = actuators
        self.client = client

    def load_bridge_prompt(self) -> str:
        """
        加载并返回用于调用 LLM 的 prompt 模板。
        可以进一步根据实际任务调整模板
        """
        with open("prompt/bridge.txt", "r") as file:
            return file.read()
        
    def load_page_info_prompt(self) -> str:
        """
        加载并返回用于调用 LLM 的 prompt 模板。
        可以进一步根据实际任务调整模板
        """
        with open("prompt/page_description.txt", "r") as file:
            return file.read()

    def generate_bridge_prompt(self, task: Task, page_description: str, last_step: str) -> str:
        """
        生成用于发送给 LLM 的完整 prompt。
        :param task: 当前任务对象
        :param page_description: 当前页面的简化描述
        :param last_step: 上一步操作
        :return: 格式化后的 prompt 字符串
        """
        prompt = self.load_bridge_prompt()
        return prompt.format(
            page_description=page_description,
            task_description=task.description,
            current_url=self.driver.current_url,
            last_step=last_step,
            page_title=self.driver.title
        )

    def query_llm(self, prompt: str) -> str:
        """
        调用 LLM 生成下一个操作指令。
        :param prompt: 发送给 LLM 的完整 prompt
        :return: LLM 返回的指令（如: "CLICK X" 或 "TYPE X with 'text'"）
        """
        try:
            idx = prompt.rfind("CURRENT BROWSER CONTENT:")
            system_content = prompt[:idx]
            user_content = prompt[idx:]
            prompt = [
                {"role": "system", "content": system_content},
                {"role": "user", "content": user_content}
            ]
            completion = self.client.chat.completions.create(
            # model='deepseek-reasoner', 
            model='deepseek-chat',
                messages=prompt
            )
            return completion.choices[0].message.content
        except Exception as e:
            print(f"[Bridge] LLM 调用失败: {e}")
            return "STOP"

    def execute_task_step(self, task: Task, action_id: int, value: Optional[str] = None) -> bool:
        """
        根据生成的指令，执行相应的操作，并记录到任务历史。
        :param task: 当前任务
        :param action_id: 执行的操作 ID
        :param value: 与操作相关的额外参数，例如文本或选择的值（对于需要值的操作，如 TYPE, SELECT）
        :return: 是否成功执行
        """
        # 获取操作元素
        action = self.sensors.get_actions_mapping().get_action_elem(action_id)
        if action is None:
            print(f"[Bridge] 找不到操作 {action_id}")
            return False

        # 调用执行器执行对应的操作
        success = self.actuators.execute_action_by_id(action_id, value=value)

        return success


    def run_task(self, task: Task):
        """
        持续运行任务，直到任务完成。
        :param task: 当前任务
        """
        print(f"[Bridge] 开始执行任务 {task.task_id}: {task.description}")
        
        # 创建任务截图存储目录
        screenshot_dir = f"output/screenshot/task_{task.task_id}"
        os.makedirs(screenshot_dir, exist_ok=True)

        self.driver.get(task.initial_url)  # 确保在任务的初始页面

        while not task.completed:
            # 获取页面简化描述
            self.sensors.update_abstract_page()
            page_description = self.sensors.get_abstract_page()
            prompt = self.generate_bridge_prompt(task, page_description, task.get_history())

            # 调用 LLM 生成下一步指令
            print(f"[Bridge] 发送给 LLM 的 prompt:\n{prompt}")
            command = self.query_llm(prompt)

            # 调试用，让大模型抽象网页整体语义
            page_info = self.sensors.extract_valuable_information()
            print(f"[Bridge] 提取的网页有价值信息:\n{page_info}")

            print(f"[Bridge] LLM 返回的指令: {command}")
            # 提取实际command部分
            idx = command.rfind("Command:") + len("Command:")  # 跳过"Command:"的长度
            command = command[idx:].strip()

            if command == "STOP":
                print(f"[Bridge] 任务 {task.task_id} 已完成或无法继续")
                task.set_completed()
                break

            # 解析指令并执行操作
            success = False
            if command.startswith("CLICK"):
                action_id = int(command.split()[1])
                success = self.execute_task_step(task, action_id)
                if success:
                    task.add_history(command)
            elif command.startswith("TYPE"):
                action_id = int(command.split()[1])
                text = command.split("with")[-1].strip().strip('"')  # 提取文本
                success = self.execute_task_step(task, action_id, value=text)  # 传递文本值
                if success:
                    task.add_history(command)
            elif command.startswith("SELECT"):
                action_id = int(command.split()[1])
                value = command.split("with")[-1].strip().strip('"')  # 提取选择的值
                success = self.execute_task_step(task, action_id, value=value)  # 传递选择的值
                if success:
                    task.add_history(command)
            elif command.startswith("CHECK"):
                action_id = int(command.split()[1])
                success = self.execute_task_step(task, action_id)
                if success:
                    task.add_history(command)
            elif command.startswith("UNCHECK"):
                action_id = int(command.split()[1])
                success = self.execute_task_step(task, action_id)
                if success:
                    task.add_history(command)
            elif command.startswith("SUBMIT FORM"):
                action_id = int(command.split()[3])  # 取 "with" 后的 ID
                success = self.execute_task_step(task, action_id)
                if success:
                    task.add_history(command)
            elif command.startswith("UPLOAD FILE"):
                action_id = int(command.split()[3])  # 取 "with" 后的 ID
                # 如果有文件路径，需要传递到 execute_task_step 作为 value 参数
                file_path = command.split("with")[-1].strip()  # 假设文件路径通过 "with" 后传递
                success = self.execute_task_step(task, action_id, value=file_path)  # 传递文件路径
                if success:
                    task.add_history(command)
            else:
                print(f"[Bridge] 无法识别的指令: {command}")
                break


            # 保存截图
            if success:
                screenshot_filename = f"{command}.png"
                screenshot_path = os.path.join(screenshot_dir, screenshot_filename)
                self.driver.save_screenshot(screenshot_path)
                print(f"[Bridge] 截图保存至: {screenshot_path}")
            

