"""
LLM Global Configuration

Configure the model names used by all agents here.
Modify this file to change the model configuration across the entire framework.
"""

# ========== Model Configuration ==========

# Primary reasoning model (used for planning, attacks, etc.)
# Change this to match the model name supported by your API provider.
DEFAULT_MODEL = "deepseek-reasoner"

# Optional: Configure different models for different scenarios below:

# Task planning model (TaskPlanningAgent)
TASK_PLANNING_MODEL = DEFAULT_MODEL

# Attack planning model (AttackPlanningAgent)
ATTACK_PLANNING_MODEL = DEFAULT_MODEL

# Interaction Execution Agent model
BRIDGE_MODEL = DEFAULT_MODEL

# Task generator model (TaskGenerator)
TASK_GENERATOR_MODEL = DEFAULT_MODEL

# Attack Agent model (SQL injection, XSS, XXE, etc.)
ATTACK_AGENT_MODEL = DEFAULT_MODEL

# ========== Beacon Listener Configuration ==========

# URL of the beacon listener (listen_server.py) used for blind XSS confirmation.
# When an XSS payload fires, the browser sends a callback to this URL.
# Since Selenium Chrome runs on the same host as the listener, 127.0.0.1 is sufficient.
# Change the port if listen_server.py is configured differently.
BEACON_URL = "http://127.0.0.1:9091/"

# ========== Other Optional Configuration ==========

# Temperature parameter (controls randomness, 0=deterministic, 1=creative)
DEFAULT_TEMPERATURE = 0.1

# Temperature by agent type (optional, uses DEFAULT_TEMPERATURE if not set)
TASK_PLANNING_TEMPERATURE = DEFAULT_TEMPERATURE
ATTACK_PLANNING_TEMPERATURE = DEFAULT_TEMPERATURE
BRIDGE_TEMPERATURE = DEFAULT_TEMPERATURE
TASK_GENERATOR_TEMPERATURE = DEFAULT_TEMPERATURE
ATTACK_AGENT_TEMPERATURE = DEFAULT_TEMPERATURE

# Maximum tokens (optional)
DEFAULT_MAX_TOKENS = None  # None means use model default


# ========== Helper Functions ==========

def get_model_name(agent_type: str = "default") -> str:
    """
    Get the model name based on agent type.

    Args:
        agent_type: Agent type, possible values:
            - "default": Default model
            - "task_planning": Task planning
            - "attack_planning": Attack planning
            - "bridge": Crawler bridge
            - "task_generator": Task generator
            - "attack_agent": Attack agent

    Returns:
        Model name string
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
    Get the temperature parameter based on agent type.

    Args:
        agent_type: Agent type (same as get_model_name)

    Returns:
        Temperature value (float between 0 and 1)
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
