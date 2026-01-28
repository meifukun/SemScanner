"""
LLM全局配置文件

在这里统一配置所有Agent使用的模型名称
只需要修改这个文件，就能改变所有地方的模型配置
"""

# ========== 模型配置 ==========

# 主要使用的推理模型（用于规划、攻击等）
# DEFAULT_MODEL = "deepseek-reasoner"
DEFAULT_MODEL = "deepseek-r1"

# 可选：如果需要区分不同场景使用不同模型，可以配置以下：

# 任务规划模型（TaskPlanningAgent）
TASK_PLANNING_MODEL = DEFAULT_MODEL

# 攻击规划模型（AttackPlanningAgent）
ATTACK_PLANNING_MODEL = DEFAULT_MODEL

# 爬虫Bridge模型
BRIDGE_MODEL = DEFAULT_MODEL

# 任务生成器模型（TaskGenerator）
TASK_GENERATOR_MODEL = DEFAULT_MODEL

# 攻击Agent模型（SQL注入、XSS、XXE等）
ATTACK_AGENT_MODEL = DEFAULT_MODEL

# ========== 其他可选配置 ==========

# 温度参数（控制随机性，0=确定性，1=创造性）
DEFAULT_TEMPERATURE = 0.1

# 按Agent类型配置温度（可选，不设置则使用DEFAULT_TEMPERATURE）
TASK_PLANNING_TEMPERATURE = DEFAULT_TEMPERATURE
ATTACK_PLANNING_TEMPERATURE = DEFAULT_TEMPERATURE
BRIDGE_TEMPERATURE = DEFAULT_TEMPERATURE
TASK_GENERATOR_TEMPERATURE = DEFAULT_TEMPERATURE
ATTACK_AGENT_TEMPERATURE = DEFAULT_TEMPERATURE

# 最大token数（可选）
DEFAULT_MAX_TOKENS = None  # None表示使用模型默认值


# ========== 辅助函数 ==========

def get_model_name(agent_type: str = "default") -> str:
    """
    根据Agent类型获取模型名称

    Args:
        agent_type: Agent类型，可选值：
            - "default": 默认模型
            - "task_planning": 任务规划
            - "attack_planning": 攻击规划
            - "bridge": 爬虫bridge
            - "task_generator": 任务生成器
            - "attack_agent": 攻击agent

    Returns:
        模型名称字符串
    """
    model_mapping = {
        "default": DEFAULT_MODEL,
        "task_planning": TASK_PLANNING_MODEL,
        "attack_planning": ATTACK_PLANNING_MODEL,
        "bridge": BRIDGE_MODEL,
        "task_generator": TASK_GENERATOR_MODEL,
        "attack_agent": ATTACK_AGENT_MODEL,
    }

    return model_mapping.get(agent_type, DEFAULT_MODEL)


def get_temperature(agent_type: str = "default") -> float:
    """
    根据Agent类型获取温度参数

    Args:
        agent_type: Agent类型（同get_model_name）

    Returns:
        温度值（0-1之间的浮点数）
    """
    temperature_mapping = {
        "default": DEFAULT_TEMPERATURE,
        "task_planning": TASK_PLANNING_TEMPERATURE,
        "attack_planning": ATTACK_PLANNING_TEMPERATURE,
        "bridge": BRIDGE_TEMPERATURE,
        "task_generator": TASK_GENERATOR_TEMPERATURE,
        "attack_agent": ATTACK_AGENT_TEMPERATURE,
    }

    return temperature_mapping.get(agent_type, DEFAULT_TEMPERATURE)
