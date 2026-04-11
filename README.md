# SemScanner

An LLM-driven autonomous web application security testing framework. SemScanner automatically crawls web applications, identifies attack surfaces, plans and executes security tests, and generates vulnerability reports.

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

SemScanner reads the API key from environment variables. Set them before running:

```bash
export LLM_API_KEY="your-api-key-here"

# Optional: override the default API base URL (must be OpenAI-compatible)
export LLM_BASE_URL="https://api.example.com/v1"
```

The default model is configured in `config/llm_config.py`. You can change the model name there to match your API provider.

### 3. Start the Beacon Listener (Optional)

The beacon listener is used to confirm out-of-band (OOB) vulnerabilities such as blind XSS and SSRF. It is optional and does not affect the main scanning workflow.

```bash
nohup python listen_server.py --logfile http_captured.txt &> listener.log &
```

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
| `--attack_planning_mode` | No | `llm` (default, intelligent planning) or `exhaustive` (test all types) |

### Examples

**Application that requires login:**

```bash
python autonomous_test.py \
    --target_url "http://127.0.0.1:3000/login" \
    --login_task "Log in with username: admin, password: admin123" \
    --output "output/test1"
```

**Application without login:**

```bash
python autonomous_test.py \
    --target_url "http://127.0.0.1:3000" \
    --output "output/test2"
```

**Exhaustive mode (for ablation study):**

```bash
python autonomous_test.py \
    --target_url "http://127.0.0.1:3000/login" \
    --login_task "Log in with username: admin, password: admin123" \
    --output "output/experiment_exhaustive" \
    --attack_planning_mode exhaustive
```

## Workflow

SemScanner operates as a six-phase pipeline:

```
Phase 1: Login  -->  Phase 2: Deep Crawl  -->  Phase 3: Task Planning
    -->  Phase 4: Attack Planning  -->  Phase 5: Attack Execution  -->  Phase 6: Report
```

1. **Login** - Automatically performs login based on the natural language description.
2. **Deep Crawl** - Crawls the application from the specified URL (up to 50 pages by default).
3. **Task Planning** - Identifies business-logic tasks within the application.
4. **Attack Planning** - Analyzes captured requests and identifies potential attack surfaces.
5. **Attack Execution** - Executes vulnerability tests against identified injection points.
6. **Report Generation** - Aggregates results into a detailed report.

## Supported Vulnerability Types

SemScanner primarily supports detection of the following three vulnerability categories:

- **SQL Injection** - Leverages sqlmap for automated parameter testing.
- **Cross-Site Scripting (XSS)** - Covers reflected, stored, and DOM-based XSS with beacon-based confirmation.
- **Business Logic Flaws** - Includes IDOR, privilege escalation, and authentication bypass.

Additionally, basic integration is provided for SSTI, SSRF, Command Injection, Path Traversal, and XXE.

## Output

Results are saved in the directory specified by `--output`:

```
output/your_project/
  high_level_agent.log        # Main execution log
  agent_state.json            # Current state snapshot
  final_report.json           # Final report summary
  token_usage.json            # LLM token usage and cost breakdown
  crawl/                      # Crawl results (pages, edges, graph)
  task_planning/              # Task planning results
  attack_execution/           # Attack execution results
    attack_results.json       # Vulnerability detection results
```

## Project Structure

```
.
  autonomous_test.py          # Entry point
  listen_server.py            # OOB beacon listener (optional)
  config/                     # LLM model configuration
  high_level_agent/           # Top-level decision agent (6-phase pipeline)
  crawl/                      # Browser-based crawler engine
  task/                       # Task data structures and generation
  plan_agent/                 # Task planning and attack planning agents
  attack_agent/               # Vulnerability-specific attack agents
  parallel/                   # Parallel execution components
  account/                    # Login and account management
  capture/                    # Network traffic capture
  js/                         # Browser-injected scripts
  prompt/                     # LLM prompt templates
  utils/                      # Token usage tracking
```
