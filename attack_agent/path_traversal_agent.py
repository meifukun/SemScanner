"""
Path Traversal Agent - 优化版
优化点：
1. 使用 Deep-Travelsal.txt 模板 + 6个常见文件 = 5000+ payloads
2. 规则匹配到敏感信息立即停止测试
3. 响应去重 + 采样15个 + LLM研判
4. 日志只记录关键的15个请求
"""

import time
from typing import Dict, Any, List
from pathlib import Path
import subprocess
import re
import json
import hashlib
import random
from attack_agent.request_utils import append_credentials_to_curl
from config.llm_config import get_model_name, get_temperature


class PathTraversalAgent:
    """
    路径遍历测试Agent（优化版）

    工作流程：
    1. 调用LLM分析请求，识别路径遍历注入点
    2. LLM生成带{PAYLOAD}占位符的curl命令模板
    3. 从模板文件生成大量payload（~5000个）
    4. 执行测试，规则匹配到敏感信息立即停止
    5. 响应去重 + 采样15个
    6. 调用LLM研判最终结果
    """

    # 🆕 6个跨平台常见文件（用于生成payload）
    TARGET_FILES = [
        # "etc/passwd",                              # Linux/Unix 用户信息
        "etc/hosts",                               # 几乎所有系统都有
        # "Windows/win.ini",                         # Windows 配置文件
        "Windows/System32/drivers/etc/hosts",      # Windows hosts文件
        ".env"                                     # 现代应用配置文件
    ]

    def __init__(self, client,
                 attack_prompt_path: str = "prompt/path_traversal_attack.txt",
                 judge_prompt_path: str = "prompt/path_traversal_judge.txt",
                 log_dir: str = "output/attack_logs/path_traversal",
                 template_file: str = "attack_agent/Deep-Travelsal.txt",
                 request_delay: float = 0.4):  # ✅ 新增：请求间隔（默认50ms，即每秒20请求）
        self.client = client
        self.attack_prompt_path = Path(attack_prompt_path)
        self.judge_prompt_path = Path(judge_prompt_path)
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._log_path = self.log_dir / "path_traversal_agent.log"
        self.request_delay = request_delay  # ✅ 保存请求延迟参数

        # 🆕 加载payload模板
        self.template_file = Path(template_file)
        self.payload_templates = self._load_payload_templates()

        # 🆕 在启动时生成并缓存所有payload
        self.all_payloads = self._generate_payloads()

        # 🆕 记录所有payload到日志（启动时打印一次）
        self._log_all_payloads()

    def _log(self, *args):
        msg = " ".join(str(a) for a in args)
        try:
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(msg + "\n")
        except Exception:
            pass

    def _load_prompt_template(self, path: Path) -> str:
        """加载prompt模板"""
        return path.read_text(encoding="utf-8")

    def _load_payload_templates(self) -> List[str]:
        """
        🆕 从 Deep-Travelsal.txt 加载payload模板

        Returns:
            模板列表（每行一个，包含{FILE}占位符）
        """
        try:
            templates = []
            with open(self.template_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and '{FILE}' in line:
                        templates.append(line)

            self._log(f"[PayloadTemplates] Loaded {len(templates)} templates from {self.template_file}")
            return templates
        except Exception as e:
            self._log(f"[PayloadTemplates] Failed to load templates: {e}")
            return []

    def _generate_payloads(self) -> List[str]:
        """
        🆕 生成所有payload（模板 × 文件名）

        Returns:
            完整的payload列表（~5000个）
        """
        payloads = []
        for template in self.payload_templates:
            for target_file in self.TARGET_FILES:
                payload = template.replace('{FILE}', target_file)
                payloads.append(payload)

        self._log(f"[PayloadGeneration] Generated {len(payloads)} payloads")
        self._log(f"  Templates: {len(self.payload_templates)}")
        self._log(f"  Target Files: {len(self.TARGET_FILES)}")
        self._log(f"  Total: {len(self.payload_templates)} × {len(self.TARGET_FILES)} = {len(payloads)}")

        return payloads

    def _log_all_payloads(self):
        """
        🆕 在启动时将所有payload记录到日志（只记录一次）

        格式：
        - 按目标文件分组显示
        - 每个文件显示所有模板生成的payload
        - 便于查看和调试
        """
        self._log(f"\n{'='*70}")
        self._log(f"[Payload List] All Path Traversal Payloads (Total: {len(self.all_payloads)})")
        self._log(f"{'='*70}")

        # 按目标文件分组
        for target_file in self.TARGET_FILES:
            # 筛选出属于当前文件的payload
            file_payloads = [p for p in self.all_payloads if target_file in p]

            self._log(f"\n[Target File: {target_file}] ({len(file_payloads)} payloads)")
            self._log(f"-" * 70)

            # 记录前10个和后10个payload（如果数量较多）
            if len(file_payloads) <= 20:
                # 数量少，全部记录
                for i, payload in enumerate(file_payloads, 1):
                    self._log(f"  {i:4d}. {payload}")
            else:
                # 数量多，记录前10个和后10个
                for i, payload in enumerate(file_payloads[:10], 1):
                    self._log(f"  {i:4d}. {payload}")

                self._log(f"  ... (省略 {len(file_payloads) - 20} 个中间payload)")

                for i, payload in enumerate(file_payloads[-10:], len(file_payloads) - 9):
                    self._log(f"  {i:4d}. {payload}")

        # 额外保存完整的payload列表到单独的文件
        payload_list_path = self.log_dir / "all_payloads.txt"
        try:
            with open(payload_list_path, 'w', encoding='utf-8') as f:
                f.write(f"# Path Traversal Payload List\n")
                f.write(f"# Total: {len(self.all_payloads)} payloads\n")
                f.write(f"# Generated from {len(self.payload_templates)} templates × {len(self.TARGET_FILES)} files\n\n")

                for target_file in self.TARGET_FILES:
                    f.write(f"\n## Target File: {target_file}\n")
                    f.write(f"{'='*70}\n")

                    file_payloads = [p for p in self.all_payloads if target_file in p]
                    for i, payload in enumerate(file_payloads, 1):
                        f.write(f"{i:4d}. {payload}\n")

            self._log(f"\n[Payload List] Complete list saved to: {payload_list_path}")
        except Exception as e:
            self._log(f"\n[Payload List] Failed to save complete list: {e}")

        self._log(f"{'='*70}\n")

    def _contains_sensitive_content(self, response: str) -> bool:
        """
        🆕 检查响应是否包含敏感文件内容（扩展版规则）

        扩展覆盖：
        - Linux/Unix 配置文件
        - Windows 配置文件
        - 应用配置文件
        - 环境变量
        - 源代码特征
        """
        patterns = [
            # Linux/Unix 文件
            r"root:x:\d+:\d+",                      # /etc/passwd
            r"root:\$\d+\$",                        # /etc/shadow
            r"127\.0\.0\.1\s+localhost",            # /etc/hosts
            r"PATH=/usr/local",                     # environ
            r"HOME=/root",                          # environ

            # Windows 文件
            r"\[fonts\]",                           # win.ini
            r"\[extensions\]",                      # win.ini
            r"\[MCI Extensions\]",                  # win.ini

            # 应用配置文件
            r"DB_PASSWORD\s*=",                     # .env
            r"API_KEY\s*=",                         # .env
            r"SECRET_KEY\s*=",                      # .env
            r"DATABASE_URL\s*=",                    # .env

            # 代码特征
            r"<\?php",                              # PHP 源代码
            r"import\s+os",                         # Python 源代码
            r"const\s+\w+\s*=\s*require",          # Node.js 源代码

            # 敏感关键词组合
            r"password\s*[:=]\s*['\"]?\w+",        # 密码配置
            r"secret\s*[:=]\s*['\"]?\w+",          # 密钥配置
        ]

        for pattern in patterns:
            if re.search(pattern, response, re.IGNORECASE):
                return True

        return False

    def _hash_response(self, response: str) -> str:
        """
        🆕 对响应内容生成哈希（用于去重）

        Returns:
            MD5 哈希值
        """
        return hashlib.md5(response.encode('utf-8', errors='ignore')).hexdigest()

    def test(self, request: Dict[str, Any], credentials: Dict[str, Any]) -> Dict[str, Any]:
        """
        🆕 测试单个请求的路径遍历（优化版）

        优化点：
        1. 大量payload（~5000个）
        2. 规则匹配到立即停止
        3. 响应去重 + 采样15个
        4. LLM研判（总是调用）

        Args:
            request: 完整请求数据（包含response）
            credentials: 账户凭证

        Returns:
            {
                "vulnerable": True/False,
                "payloads_tested": int,
                "sensitive_found": bool,
                "sampled_results": List[Dict],  # 采样的15个请求
                "analysis": str  # LLM分析
            }
        """
        method = request.get("method", "GET")
        url = request.get("url", "")

        self._log(f"\n{'='*70}")
        self._log(f"[PathTraversal] New Test Started")
        self._log(f"{'='*70}")
        self._log(f"[PathTraversal] Testing: {method} {url}")

        # ========== 第一步：调用LLM生成curl模板 ==========
        self._log(f"[Step 1: Calling LLM to Identify Injection Points]")
        curl_templates = self._generate_curl_templates(request)

        if not curl_templates:
            self._log(f"[PathTraversal] No injection points identified by LLM")
            return {
                "vulnerable": False,
                "payloads_tested": 0,
                "sensitive_found": False,
                "sampled_results": [],
                "analysis": "No injection points found"
            }

        self._log(f"[LLM Generated {len(curl_templates)} curl template(s)]")
        for i, tmpl in enumerate(curl_templates, 1):
            self._log(f"  {i}. {tmpl}")

        # ========== 第二步：使用预生成的payload ==========
        payloads = self.all_payloads  # 🆕 使用缓存的payload（启动时已生成）
        self._log(f"\n[Step 2: Using Pre-generated {len(payloads)} Path Traversal Payloads]")

        # ========== 第三步：执行测试（规则匹配立即停止）==========
        self._log(f"\n[Step 3: Executing Tests with Early Stopping]")

        all_results = []  # 所有结果
        sensitive_results = []  # 匹配到敏感信息的结果
        response_groups = {}  # 按响应内容分组（用于去重）
        payloads_tested = 0
        stopped_early = False

        for template in curl_templates:
            if stopped_early:
                break

            # 打印完整模板（不截断）
            self._log(f"\n[Testing Template]: {template}")

            for payload in payloads:
                if stopped_early:
                    break

                # 替换{PAYLOAD}为实际payload
                if '{PAYLOAD}' not in template:
                    continue

                final_command = template.replace('{PAYLOAD}', payload)
                final_command = append_credentials_to_curl(final_command, credentials)

                try:
                    # ✅ 速率控制：在每次请求前延迟
                    if self.request_delay > 0:
                        time.sleep(self.request_delay)

                    process = subprocess.Popen(
                        final_command,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    stdout, stderr = process.communicate(timeout=10)

                    payloads_tested += 1

                    # 解析HTTP状态码
                    from attack_agent.request_utils import parse_http_status_from_response
                    http_status, response_body = parse_http_status_from_response(stdout)

                    # 打印每个请求的状态和响应
                    self._log(f"  ✓ Executed (curl_exit_code: {process.returncode})")
                    if http_status is not None:
                        self._log(f"  HTTP Status: {http_status}")
                    self._log(f"  Response length: {len(response_body)} bytes")
                    # 打印完整响应（不截断）
                    self._log(f"  Response: {response_body}")
                    if stderr:
                        self._log(f"  Stderr: {stderr}")

                    # 🆕 生成响应哈希（用于去重） - 使用response_body
                    response_hash = self._hash_response(response_body)

                    # 🆕 检查是否包含敏感内容
                    is_sensitive = self._contains_sensitive_content(response_body)

                    result = {
                        "payload": payload,
                        "command": final_command,
                        "response": response_body,  # 使用清理后的响应体
                        "response_hash": response_hash,
                        "is_sensitive": is_sensitive
                    }

                    all_results.append(result)

                    # 🆕 按响应哈希分组（用于去重）
                    if response_hash not in response_groups:
                        response_groups[response_hash] = []
                    response_groups[response_hash].append(result)

                    # 🆕 如果匹配到敏感信息，立即停止！
                    if is_sensitive:
                        sensitive_results.append(result)
                        self._log(f"  ✓✓✓ SENSITIVE CONTENT DETECTED! Stopping test.")
                        self._log(f"  Payload: {payload}")
                        self._log(f"  Response:")
                        stopped_early = True
                        break

                except subprocess.TimeoutExpired:
                    payloads_tested += 1
                except Exception as e:
                    payloads_tested += 1

        self._log(f"\n[Payload Testing Complete]:")
        self._log(f"  Total Payloads Tested: {payloads_tested} / {len(payloads)}")
        self._log(f"  Unique Responses: {len(response_groups)}")
        self._log(f"  Sensitive Results: {len(sensitive_results)}")
        self._log(f"  Stopped Early: {stopped_early}")

        # ========== 第四步：采样15个唯一响应 ==========
        self._log(f"\n[Step 4: Sampling Up to 15 Unique Responses for LLM Analysis]")

        sampled_results = self._sample_responses(
            response_groups=response_groups,
            sensitive_results=sensitive_results,
            max_samples=15
        )

        self._log(f"  Sampled: {len(sampled_results)} unique responses")
        self._log(f"  (Including {len(sensitive_results)} sensitive result(s))")

        # ========== 第五步：LLM研判 ==========
        self._log(f"\n[Step 5: LLM Analysis]")

        judgment = self._judge_vulnerability(sampled_results)
        vulnerable = judgment.get("vulnerable", False)
        analysis = judgment.get("analysis", "")

        self._log(f"\n{'='*70}")
        self._log(f"[PathTraversal Test Summary]")
        self._log(f"  Payloads Tested: {payloads_tested}")
        self._log(f"  Unique Responses: {len(response_groups)}")
        self._log(f"  Sensitive Found: {len(sensitive_results) > 0}")
        self._log(f"  Sampled for LLM: {len(sampled_results)}")
        self._log(f"  Result: {'VULNERABLE' if vulnerable else 'SAFE'}")
        self._log(f"{'='*70}\n")

        return {
            "vulnerable": vulnerable,
            "payloads_tested": payloads_tested,
            "sensitive_found": len(sensitive_results) > 0,
            "sampled_results": sampled_results,
            "analysis": analysis
        }

    def _sample_responses(self, response_groups: Dict[str, List[Dict]],
                         sensitive_results: List[Dict],
                         max_samples: int = 15) -> List[Dict]:
        """
        🆕 从响应中采样最多15个唯一响应

        策略：
        1. 敏感结果必须包含
        2. 从每个唯一响应组中随机选一个
        3. 最多15个

        Args:
            response_groups: 按哈希分组的响应
            sensitive_results: 匹配到敏感信息的结果
            max_samples: 最大采样数

        Returns:
            采样的结果列表
        """
        sampled = []

        # 1. 敏感结果必须包含（取每个哈希组的第一个）
        sensitive_hashes = set()
        for result in sensitive_results:
            if len(sampled) >= max_samples:
                break
            sampled.append(result)
            sensitive_hashes.add(result["response_hash"])

        self._log(f"  [Sampling] Added {len(sensitive_results)} sensitive result(s)")

        # 2. 从其他唯一响应中随机采样
        other_hashes = [h for h in response_groups.keys() if h not in sensitive_hashes]
        random.shuffle(other_hashes)

        for response_hash in other_hashes:
            if len(sampled) >= max_samples:
                break

            # 从该组中随机选一个
            group = response_groups[response_hash]
            sampled.append(random.choice(group))

        self._log(f"  [Sampling] Added {len(sampled) - len(sensitive_results)} other unique response(s)")
        self._log(f"  [Sampling] Total sampled: {len(sampled)}")

        return sampled

    def _generate_curl_templates(self, request: Dict[str, Any]) -> List[str]:
        """
        调用LLM生成带{PAYLOAD}占位符的curl模板

        Returns:
            curl模板列表（包含{PAYLOAD}占位符）
        """
        sys_prompt = self._load_prompt_template(self.attack_prompt_path)

        # 格式化请求信息
        user_prompt = f"""REQUEST INFORMATION:
Method: {request.get('method', 'GET')}
URL: {request.get('url', '')}
Headers: {json.dumps(request.get('headers', {}), indent=2)}
Body: {json.dumps(request.get('body'), indent=2) if request.get('body') else 'None'}
Response Status: {request.get('response_status', 'N/A')}
Response Body (preview): {str(request.get('response_body', ''))}

Please analyze this request and generate curl command templates with {{PAYLOAD}} placeholder for path traversal testing."""

        try:
            # 在调用大模型前，记录输入
            self._log(f"[Attack Model Input] sys_prompt: {sys_prompt}")
            self._log(f"[Attack Model Input] user_prompt: {user_prompt}")
            completion = self.client.chat.completions.create(
                model=get_model_name("attack_agent"),
                messages=[
                    {"role": "system", "content": sys_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=get_temperature("attack_agent")
            )

            llm_output = completion.choices[0].message.content

            # 解析Commands部分
            templates = self._parse_curl_templates(llm_output)

            return templates

        except Exception as e:
            self._log(f"[Error] LLM call failed: {e}")
            return []

    def _parse_curl_templates(self, llm_output: str) -> List[str]:
        """解析LLM输出中的curl命令模板"""
        templates = []

        # 查找Commands部分
        lines = llm_output.split('\n')
        in_commands_section = False

        for line in lines:
            line = line.strip()

            if 'Commands:' in line or 'commands:' in line.lower():
                in_commands_section = True
                continue

            if in_commands_section:
                # 提取curl命令
                if line.startswith('curl'):
                    templates.append(line)
                elif line.startswith('-'):
                    # 可能是列表格式
                    if 'curl' in line:
                        # 提取curl部分
                        curl_part = line.split('curl', 1)[1] if 'curl' in line else ''
                        if curl_part:
                            templates.append('curl' + curl_part)

        return templates

    def _judge_vulnerability(self, sampled_results: List[Dict]) -> Dict[str, Any]:
        """
        🆕 调用LLM研判是否存在路径遍历漏洞（基于采样结果）

        Args:
            sampled_results: 采样的测试结果（最多15个）

        Returns:
            {
                "vulnerable": True/False,
                "analysis": str
            }
        """
        judge_prompt = self._load_prompt_template(self.judge_prompt_path)

        # ✅ 修复：提供完整的命令，让LLM知道payload是如何使用的
        test_results_text = []
        for idx, result in enumerate(sampled_results, 1):
            sensitive_tag = " [SENSITIVE]" if result.get("is_sensitive") else ""

            # ✅ 格式化完整的curl命令（可能很长，只显示关键部分）
            command = result['command']
            command_preview = command

            test_results_text.append(f"""
Test {idx}{sensitive_tag}:
Payload: {result['payload']}

Complete Command Used:
{command_preview}

Response (first 2000 chars):
{result['response'][:2000]}
{'...(truncated)' if len(result['response']) > 2000 else ''}
""")

        user_prompt = f"""
Sampled Test Results ({len(sampled_results)} unique responses):

{chr(10).join(test_results_text)}

Please analyze these results and determine if there is a path traversal vulnerability.

IMPORTANT:
- Each test shows the COMPLETE COMMAND used (including how the payload was injected)
- Results marked with [SENSITIVE] matched sensitive content patterns
- Consider response patterns, error messages, and content variations
- A TRUE POSITIVE requires actual sensitive file content or clear evidence of file access
- Pay attention to WHERE and HOW the payload was injected in the request

Output format:
Judgment: VULNERABLE / NOT VULNERABLE
Analysis: [Your detailed analysis]
"""

        try:
            # 在调用大模型前，记录输入
            self._log(f"[Judgment Model Input] judge_prompt: {judge_prompt}")
            self._log(f"[Judgment Model Input] user_prompt: {user_prompt}")
            completion = self.client.chat.completions.create(
                model=get_model_name("attack_agent"),
                messages=[
                    {"role": "system", "content": judge_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=get_temperature("attack_agent")
            )

            llm_output = completion.choices[0].message.content

            # 解析判断结果
            vulnerable = False
            if re.search(r'Judgment:\s*VULNERABLE', llm_output, re.IGNORECASE):
                vulnerable = True
            elif re.search(r'Judgment:\s*NOT\s*VULNERABLE', llm_output, re.IGNORECASE):
                vulnerable = False

            return {
                "vulnerable": vulnerable,
                "analysis": llm_output
            }

        except Exception as e:
            self._log(f"[Error] LLM judgment failed: {e}")
            return {
                "vulnerable": False,
                "analysis": f"LLM analysis failed: {e}"
            }
