# Web-Agent-Scan

基于大语言模型（LLM）的自动化 Web 应用安全测试框架。本框架能够自动爬取 Web 应用、识别攻击面、规划并执行安全测试，最后生成漏洞报告。

## 目录

- [环境配置](#环境配置)
- [快速开始](#快速开始)
- [启动参数说明](#启动参数说明)
- [关键配置](#关键配置)
  - [LLM 模型配置](#llm-模型配置)
  - [API 密钥配置](#api-密钥配置)
  - [Beacon 服务器配置](#beacon-服务器配置)
- [工作流程](#工作流程)
- [输出文件说明](#输出文件说明)
- [支持的漏洞类型](#支持的漏洞类型)
- [注意事项](#注意事项)

---

## 环境配置

### 系统要求

- Python 3.11
- Google Chrome 浏览器
- ChromeDriver（通过 webdriver-manager 自动管理）

### 安装依赖

推荐使用 Conda 创建虚拟环境：

```bash
# 从 environment.yml 创建环境
conda env create -f environment.yml

# 激活环境
conda activate web-vul
```

主要依赖包括：
- `selenium` / `selenium-wire` - 浏览器自动化和网络请求捕获
- `openai` - LLM API 调用
- `beautifulsoup4` - HTML 解析
- `mitmproxy` - 网络代理
- `flask` - HTTP 服务器

---

## 快速开始

### 1. 启动 XSS Beacon 监听服务器

在运行扫描之前，需要先启动 XSS 回调监听服务器：

```bash
nohup python listen_server.py --logfile http_captured.txt &> listener.log &
```

这个只会影响XSS攻击的确认，不影响程序的运行，如果目的是收集流量的话可运行可不运行。

### 2. 运行扫描

```bash
python autonomous_test.py \
    --target_url "http://127.0.0.1:4281/#/login" \
    --login_task "Log in with username: 1474715931@qq.com, password: 123456" \
    --output "output/juiceshop" \
    &> logs/juiceshop.log
```

---

## 启动参数说明

| 参数 | 必填 | 说明 | 示例 |
|------|------|------|------|
| `--target_url` | 是 | 目标应用的入口URL（通常是登录页面） | `http://127.0.0.1:3000/login` |
| `--login_task` | 否 | 登录任务的自然语言描述 | `Log in with username: admin, password: admin123` |
| `--crawl_start_url` | 否 | 登录后开始爬取的URL（不提供则从登录后页面开始） | `http://127.0.0.1:3000/admin` |
| `--output` | 是 | 结果输出目录 | `output/test1` |
| `--attack_planning_mode` | 否 | 攻击规划模式：`llm`（智能规划，默认）或 `exhaustive`（穷举全测） | `llm` |

### 使用示例

**需要登录的应用：**
```bash
python autonomous_test.py \
    --target_url "http://127.0.0.1:3000/login" \
    --login_task "Log in with username: admin, password: admin123" \
    --output "output/test1"
```

**无需登录的应用：**
```bash
python autonomous_test.py \
    --target_url "http://127.0.0.1:3000" \
    --output "output/test2"
```

**登录后指定爬取起始页面：**
```bash
python autonomous_test.py \
    --target_url "http://127.0.0.1:3000/login" \
    --login_task "Log in with username: admin, password: admin123" \
    --crawl_start_url "http://127.0.0.1:3000/admin" \
    --output "output/test3"
```

**穷举模式（用于实验/消融研究）：**
```bash
python autonomous_test.py \
    --target_url "http://127.0.0.1:3000/login" \
    --login_task "Log in with username: admin, password: admin123" \
    --output "output/experiment_exhaustive" \
    --attack_planning_mode exhaustive
```

---

## 关键配置

### LLM 模型配置

配置文件位置：`config/llm_config.py`

```python
# 主要使用的推理模型
DEFAULT_MODEL = "deepseek-r1"

# 按Agent类型可单独配置（默认都使用 DEFAULT_MODEL）
TASK_PLANNING_MODEL = DEFAULT_MODEL      # 任务规划
ATTACK_PLANNING_MODEL = DEFAULT_MODEL    # 攻击规划
BRIDGE_MODEL = DEFAULT_MODEL             # 爬虫Bridge
TASK_GENERATOR_MODEL = DEFAULT_MODEL     # 任务生成器
ATTACK_AGENT_MODEL = DEFAULT_MODEL       # 攻击Agent（SQL注入、XSS等）

# 温度参数（0=确定性，1=创造性）
DEFAULT_TEMPERATURE = 0.1
```

### API 密钥配置

配置位置：`autonomous_test.py` 第93-101行

```python
# 初始化OpenAI client
client = OpenAI(
    api_key="your-api-key-here",
    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",  # 阿里云
)

# 或使用 DeepSeek
# client = OpenAI(
#     api_key="your-deepseek-api-key",
#     base_url="https://api.deepseek.com"
# )
```

支持的 API 服务商：
- 阿里云 DashScope
- DeepSeek
- OpenAI（及兼容接口）

### Beacon 服务器配置

Beacon 服务器用于验证 OOB（Out-of-Band）类型漏洞，如 XSS、SSRF、命令注入等。

#### 1. XSS Beacon 监听服务器

配置位置：`listen_server.py`

```bash
# 启动命令
python listen_server.py --bind 0.0.0.0 --port 9091 --logfile http_captured.txt

# 参数说明
--bind      # 绑定地址，默认 0.0.0.0
--port      # 监听端口，默认 9091
--logfile   # 日志文件路径，默认 request_captured.txt
```

#### 2. 浏览器端 XSS 回调地址

配置位置：`js/xss_xhr.js` 第8行

```javascript
var url = "http://127.0.0.1:9091/?data=" + encodeURIComponent(data);
```

#### 3. 服务端漏洞 Beacon 地址

用于 SSRF、命令注入、XXE、SSTI 等服务端漏洞的验证。

配置位置及默认值：

| 文件 | 位置 | 默认值 |
|------|------|--------|
| `attack_agent/attack_executor.py` | 第58行 | `http://172.17.0.1:9091/` |
| `attack_agent/ssrf_agent.py` | 第31行 | `http://172.17.0.1:9091/` |
| `attack_agent/command_injection_agent.py` | 第33行 | `http://172.17.0.1:9091/` |
| `attack_agent/xxe_agent.py` | 第31行 | `http://172.17.0.1:9091/` |
| `attack_agent/ssti_agent.py` | 第38行 | `http://172.17.0.1:9091/` |

> **说明**：`172.17.0.1` 是 Docker 默认网桥的宿主机地址。如果目标应用运行在 Docker 容器中，服务端发起的请求会通过此地址访问宿主机上的 Beacon 服务器。

#### 4. Beacon 日志文件

配置位置：`attack_agent/request_utils.py` 第10行

```python
def check_beacon_detection(token: str, log_file: str = "http_captured.txt") -> bool:
```

---

## 工作流程

框架采用六阶段流水线：

```
Phase 1: 登录 → Phase 2: 深度爬取 → Phase 3: 任务规划
→ Phase 4: 攻击规划 → Phase 5: 攻击执行 → Phase 6: 报告生成
```

1. **登录阶段**：根据 `login_task` 描述自动完成登录
2. **深度爬取**：从指定URL开始爬取应用（默认最多50页）
3. **任务规划**：识别应用中的业务功能任务
4. **攻击规划**：分析捕获的请求，识别潜在攻击面
5. **攻击执行**：针对各注入点执行漏洞测试
6. **报告生成**：汇总测试结果，生成详细报告

---

## 输出文件说明

扫描完成后，结果保存在 `--output` 指定的目录中：

```
output/your_project/
├── high_level_agent.log       # 主执行日志
├── agent_state.json           # 当前状态快照
├── final_report.json          # 最终报告摘要
├── crawl/                     # 爬取结果
│   ├── pages.jsonl            # 页面信息
│   ├── edges.jsonl            # 页面跳转关系
│   └── graph.json             # 应用结构图
├── task_planning/             # 任务规划结果
├── attack_planning/           # 攻击规划结果
│   └── planned_attacks.json   # 已规划的攻击任务
└── attack_execution/          # 攻击执行结果
    └── attack_results.json    # 漏洞检测结果
```

---

## 支持的漏洞类型

| 漏洞类型 | 说明 |
|----------|------|
| SQL_INJECTION | SQL 注入 |
| XSS | 跨站脚本（反射型、存储型、DOM型） |
| XXE | XML 外部实体注入 |
| SSTI | 服务端模板注入 |
| SSRF | 服务端请求伪造 |
| CMDI | 操作系统命令注入 |
| PATH_TRAVERSAL | 路径遍历 |
| BUSINESS_LOGIC | 业务逻辑漏洞（IDOR、权限提升等） |

---

## 注意事项

### 目标应用要求

1. **目标必须是本地可访问的端口**：由于 Beacon 服务器和网络捕获的机制，目标应用需要通过本地端口访问（如 `127.0.0.1:xxxx`）

2. **Docker 环境配置**：如果目标应用运行在 Docker 中：
   - Beacon 地址默认配置为 `172.17.0.1:9091`（Docker 网桥宿主机地址）
   - 确保容器可以访问宿主机的 9091 端口

    