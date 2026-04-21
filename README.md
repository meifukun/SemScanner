# SemScanner

SemScanner is an LLM-driven black-box web application vulnerability scanner. It operates in three phases: **Semantic-Driven Crawling**, **Audit Task Formulation**, and **Semantic-Guided Vulnerability Auditing**.

## Requirements

- Python 3.11
- Google Chrome
- ChromeDriver (auto-managed via `webdriver-manager`)
- An OpenAI-compatible LLM API

## Setup

### 1. Create the Conda Environment

```bash
conda env create -f environment.yml
conda activate web-vul
```

### 2. Configure the LLM API Key

```bash
export LLM_API_KEY="your-api-key-here"

# Optional: override the default API base URL (must be OpenAI-compatible)
export LLM_BASE_URL="https://api.example.com/v1"
```

The default model is configured in `config/llm_config.py`.

### 3. Configure and Start the Beacon Listener (Optional)

The beacon listener is used to confirm blind XSS vulnerabilities. When an XSS payload fires in the browser, a callback is sent to this listener for verification.

```bash
nohup python listen_server.py --logfile http_captured.txt &> listener.log &
```

The beacon URL is configured via `BEACON_URL` in `config/llm_config.py` (default: `http://127.0.0.1:9091/`). Since the Selenium browser runs on the same host as the listener, `127.0.0.1` is typically sufficient. Change the port if `listen_server.py` is configured differently.

## Usage

```bash
python autonomous_test.py \
    --target_url <URL> \
    --login_task <LOGIN_DESCRIPTION> \
    --output <OUTPUT_DIR>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--target_url` | Yes | Entry URL of the target application (e.g., login page) |
| `--login_task` | No | Natural language description of the login action |
| `--crawl_start_url` | No | URL to start crawling from after login |
| `--output` | Yes | Output directory for results |

### Examples

```bash
# With login
python autonomous_test.py \
    --target_url "http://127.0.0.1:3000/login" \
    --login_task "Log in with username: admin, password: admin123" \
    --output "output/test1"

# Without login
python autonomous_test.py \
    --target_url "http://127.0.0.1:3000" \
    --output "output/test2"
```

## Workflow

```
Semantic-Driven Crawling ──> Audit Task Formulation ──> Semantic-Guided Vulnerability Auditing
                                   (pipelined: formulation streams tasks into a shared queue,
                                    vulnerability agents consume and execute in parallel)
```

Given a target URL and optional credentials, SemScanner first performs login (if specified), then runs the three phases sequentially. Audit Task Formulation and Vulnerability Auditing are pipelined via a producer-consumer queue for efficiency.

## Supported Vulnerability Types

Primary:
- **SQL Injection** — LLM-generated `sqlmap` invocations
- **Cross-Site Scripting (XSS)** — OOB beacon-based confirmation for reflected, stored, and DOM-based XSS
- **Business Logic Vulnerabilities** — LLM-driven differential testing for business constraint violations

All agents use **Reflective Execution**: if the first attempt does not confirm a vulnerability, the agent feeds back the server response and retries with a revised strategy.

## Output

```
output/your_project/
  high_level_agent.log        # Main execution log
  agent_state.json            # Phase completion state
  final_report.json           # Vulnerability report with evidence
  token_usage.json            # LLM token usage and cost breakdown
  crawl/                      # WASG data (pages, edges, deduplication index)
  task_planning/              # Interaction execution traces with captured requests
  attack_execution/
    attack_results.json       # Vulnerability detection results
```

## Project Structure

The table below maps each code module to its role in the paper's framework.

### Semantic-Driven Crawling

Builds the **Web Application Semantic Graph (WASG)**: discovers pages via BFS with content-structural deduplication, extracts semantic representations, generates and executes interaction tasks, and records all triggered HTTP traffic.

| Paper Component | Code | Description |
|---|---|---|
| DOM Semantic Extractor | `crawl/dom_semantic_extractor.py` (`DOMSemanticExtractor`) | Extracts a compact semantic representation from the live DOM; maintains an **ElementMapping** (`actions_mapping`) from element IDs to DOM locators |
| Interaction Generator | `task/task_generator.py` (`TaskGenerator`) | LLM produces interaction tasks (single-step and exploratory) from the semantic representation |
| Interaction Scheduling Agent | `plan_agent/task_planning_agent.py` (`TaskPlanningAgent`) | Coordinates tasks across pages into an execution schedule |
| Interaction Execution Agent | `crawl/interaction_execution_agent.py` (`InteractionExecutionAgent`) | Closed-loop LLM-to-browser execution (perceive → plan → act → re-perceive) |
| Page Discovery + Deduplication | `crawl/crawler.py` (`Crawler`, `ContentDedupeIndex`) | BFS crawling with dual SimHash fingerprint deduplication |
| Network Interceptor | `capture/network_capture.py` + `crawl/tracer.py` | Captures HTTP traffic and records it into the WASG |
| WASG Store | `app_info/webapp_store.py` (`WebAppStore`) + `app_info/models.py` | In-memory graph store for pages, edges, and network requests |

### Audit Task Formulation

| Paper Component | Code | Description |
|---|---|---|
| Audit Task Formulation | `plan_agent/attack_planning_agent.py` (`AttackPlanningAgent`) | Analyzes WASG requests with exclusion-based reasoning to generate targeted audit tasks |

### Semantic-Guided Vulnerability Auditing

| Paper Component | Code | Description |
|---|---|---|
| SQL Injection Agent | `attack_agent/sql_injection_agent.py` (`SQLInjectionAgent`) | LLM generates tailored `sqlmap` commands based on request format |
| XSS Agent | `attack_agent/xss_agent.py` (`XSSAgent`) | LLM identifies injection points; payloads trigger OOB callbacks to the beacon listener; final page traversal detects stored XSS |
| Business Logic Agent | `attack_agent/business_logic_agent.py` (`BusinessLogicAgent`) | Two-step: LLM generates constraint-violating requests, then verifies via differential response comparison |
| Reflective Execution | `_execute_stage2_*` methods in each agent | Feeds first-attempt results back to LLM for strategy refinement |
| Parallel Dispatcher | `attack_agent/attack_executor.py` (`AttackExecutor`) | Thread-pool executor consuming audit tasks from the pipeline queue |

### Supporting Modules

| Module | Description |
|---|---|
| `high_level_agent/decision_agent.py` | Top-level orchestrator: runs login, crawling, formulation, and auditing phases |
| `parallel/` | Driver pool and producer-consumer scheduler for parallel interaction execution |
| `account/` | Login state and credential management |
| `js/` | Injected browser scripts (event listener capture, XSS OOB callbacks) |
| `prompt/` | LLM prompt templates |
| `config/llm_config.py` | Model names and temperature settings per agent |
| `listen_server.py` | OOB beacon HTTP listener |
| `utils/token_tracker.py` | LLM API token/cost tracking |
