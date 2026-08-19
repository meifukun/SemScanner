# SemScanner

SemScanner is an LLM-driven black-box web application vulnerability scanner. It operates in three phases: **Semantic-Driven Crawling**, **Audit Task Formulation**, and **Semantic-Guided Vulnerability Auditing**.

## Requirements

The requirements and setup steps in this section describe running
SemScanner directly from the source tree. The pre-built Docker workflow for
artifact evaluation is documented separately in [Prebuilt Docker Image](#prebuilt-docker-image).

- A Linux `x86_64` host with at least 16 GB RAM
- Conda
- Docker Engine with the Compose v2 plugin
- Python 3.11
- Google Chrome/Chromium
- ChromeDriver (auto-managed via `webdriver-manager`)
- An OpenAI-compatible LLM API
- `curl`

## Source-based Setup

### 1. Create the Conda Environment

```bash
conda env create -n semscanner -f environment.yml
conda activate semscanner
```

### 2. Configure the LLM API Key

```bash
export LLM_API_KEY="your-api-key-here"

# Optional: override the default API base URL (must be OpenAI-compatible)
export LLM_BASE_URL="https://api.example.com/v1"

# Optional: use the model name exposed by the selected endpoint
export LLM_MODEL="your-model-name"
```

If `LLM_MODEL` is unset, the model in `config/llm_config.py` is used.

For artifact evaluation, keep attack execution sequential so that state-changing tests cannot interfere with one another:

```bash
export SEMSCANNER_ATTACK_MAX_WORKERS=1
```

### 3. Default Timeouts

The repository defaults are intended for unattended revision experiments. There is no default overall wall-clock limit for a whole scan; scan size is controlled by the crawler/page/task bounds. Do not wrap the scanner with shell-level commands such as `timeout 6h` unless you intentionally want an external cutoff.

| Item | Default | Environment override |
|---|---:|---|
| LLM request | `300s` | `LLM_REQUEST_TIMEOUT` |
| SQLMap subprocess | `600s` | `SEMSCANNER_SQLMAP_TIMEOUT` |
| SQL task total timeout | unlimited | `SEMSCANNER_ATTACK_TASK_TIMEOUT_SQL` |
| XSS task total timeout | `300s` | `SEMSCANNER_ATTACK_TASK_TIMEOUT_XSS` |
| Business logic task total timeout | `420s` | `SEMSCANNER_ATTACK_TASK_TIMEOUT_BUSINESS` |
| Replay curl before attack execution | `120s` | `SEMSCANNER_REPLAY_TIMEOUT` |
| Single curl command in XSS/business agents | `120s` | `SEMSCANNER_CURL_TIMEOUT` |

Notes:
- SQL injection is limited at the `sqlmap` subprocess level only by default. The SQL task itself has no queue-level total timeout.
- `0` or an invalid timeout value falls back to the default above.
- Set a timeout variable to `none`, `inf`, `infinite`, or `unlimited` only when you explicitly want no limit for that layer.

### 4. Configure and Start the XSS Beacon Listener

The beacon listener is required for reliable XSS confirmation. When an injected XSS payload fires in the browser, the payload calls the beacon URL with `?data=<random_id>`, and `listen_server.py` appends that ID to a log file.

Use one listener and one log for the evaluation. Multiple scans can share this listener because each XSS task generates a random beacon token.

```bash
SEMSCANNER_ARTIFACT_ROOT="$PWD"
mkdir -p "$SEMSCANNER_ARTIFACT_ROOT/ae_runtime/xss_beacon"

export SEMSCANNER_XSS_BEACON_URL="http://127.0.0.1:9091/"
export SEMSCANNER_XSS_BEACON_LOG="$SEMSCANNER_ARTIFACT_ROOT/ae_runtime/xss_beacon/http_captured.txt"

nohup python listen_server.py \
    --bind 127.0.0.1 \
    --port 9091 \
    --logfile "$SEMSCANNER_XSS_BEACON_LOG" \
    > "$SEMSCANNER_ARTIFACT_ROOT/ae_runtime/xss_beacon/listener.log" 2>&1 &
echo $! > "$SEMSCANNER_ARTIFACT_ROOT/ae_runtime/xss_beacon/listener.pid"
```

The two XSS environment variables have different roles:

| Variable | Purpose |
|---|---|
| `SEMSCANNER_XSS_BEACON_URL` | URL injected into Selenium browsers through `js/xss_xhr.js`; must point to the running listener. |
| `SEMSCANNER_XSS_BEACON_LOG` | Local file that XSS agents read when checking whether a random ID was triggered. This must match the listener's `--logfile`. |

Defaults and conventions:
- If `SEMSCANNER_XSS_BEACON_URL` is not set, `config/llm_config.py` uses `http://127.0.0.1:9091/`.
- For artifact evaluation, keep `SEMSCANNER_XSS_BEACON_LOG` under `ae_runtime/xss_beacon/` as shown above.
- If `SEMSCANNER_XSS_BEACON_LOG` is not set, the agent falls back to likely paths such as `http_captured.txt`, `<run>/http_captured.txt`, and `<run>/logs/http_captured.txt`; do not rely on that fallback for experiments.
- Before a new formal batch, the log may be archived or truncated to make manual inspection easier.

Before starting a scan, verify the listener and log path:

```bash
curl "http://127.0.0.1:9091/?data=beacon_test_123"
grep "beacon_test_123" "$SEMSCANNER_XSS_BEACON_LOG"
```

The `grep` command should print `beacon_test_123`. If it does not, fix the listener URL, port, or log path before running XSS experiments.

### 5. Deploy the Packaged Applications

The complete artifact attached to the GitHub Release includes the prebuilt
target-image archive. Reset the four targets to their packaged baselines with:

```bash
./benchmark_apps/manage.sh reset all
./benchmark_apps/manage.sh status all
```

A source-only Git checkout does not contain the packaged target images. Download
the complete artifact from the corresponding GitHub Release before using these
commands. Target URLs, credentials, individual reset commands, port overrides,
and troubleshooting are documented in
[`benchmark_apps/README.md`](benchmark_apps/README.md).

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

## Prebuilt Docker Artifact

The complete artifact is available from the repository's GitHub Release page.
It includes a prebuilt `linux/amd64` SemScanner image under `ae/images/`, which
contains the SemScanner source code, Python environment, Chromium,
ChromeDriver, `sqlmap`, and the other runtime dependencies. A separate archive
under `benchmark_apps/images/` contains four packaged applications: Loan
Management, Online Food Ordering, Simple E-Learning, and changedetection.io
0.45.20, including their initial application state.

Docker Engine with the Compose v2 plugin is required. Load and check the
SemScanner image with:

```bash
./ae.sh load
./ae.sh doctor
```

Configure an OpenAI-compatible LLM API and run one of the packaged targets:

```bash
export LLM_API_KEY="<API-KEY>"
export LLM_BASE_URL="<OPENAI-COMPATIBLE-ENDPOINT>"
export LLM_MODEL="<MODEL-NAME>"

./ae.sh run loan
```

For more stable end-to-end vulnerability discovery, we recommend a frontier
model such as GPT-5.5 when it is available through the selected endpoint.

The available target names are `loan`, `online-food`, `e-learning`, and
`changedetection`. The
selected application is restored to its packaged baseline before each run.
Results are written to `ae_results/<TARGET>/<RUN-ID>/`; the principal files are
`final_report.json`, `high_level_agent.log`,
`attack_execution/attack_results.json`, and `token_usage.json`.

After modifying the source code, rebuild and export the image with:

```bash
./ae.sh build
./ae.sh export
```
