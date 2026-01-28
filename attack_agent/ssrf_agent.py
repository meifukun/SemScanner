"""
SSRF Agent - 完整版（使用LLM生成注入点）
"""

from typing import Dict, Any, List
from pathlib import Path
import subprocess
import random
import string
import json
import re
from attack_agent.request_utils import append_credentials_to_curl, check_beacon_detection, extract_useful_response
from config.llm_config import get_model_name, get_temperature

class SSRFAgent:
    """
    SSRF测试Agent（完整实现）

    工作流程：
    1. 调用LLM分析请求，识别SSRF注入点
    2. LLM生成带{PAYLOAD}占位符的curl命令模板
    3. 生成统一的token（用于beacon检测）
    4. 生成SSRF payload列表（包含beacon URL + token）
    5. 用实际payload替换{PAYLOAD}占位符
    6. 执行测试并记录token
    7. 检查beacon服务器日志确认漏洞
    """

    def __init__(self, client,
                 prompt_path: str = "prompt/ssrf_attack.txt",
                 beacon_base: str = "http://172.17.0.1:9091/",
                 log_dir: str = "output/attack_logs/ssrf",
                 reflection_enabled: bool = True):  # ✅ 新增：反思功能开关
        self.client = client
        self.prompt_path = Path(prompt_path)
        self.beacon_base = beacon_base.rstrip("/") + "/"
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._log_path = self.log_dir / "ssrf_agent.log"
        self.reflection_enabled = reflection_enabled  # ✅ 保存配置

        # ✅ 新增：记录所有执行的测试（用于延迟检测）
        self.execution_records: Dict[str, Dict[str, Any]] = {}  # {token: {url, payloads, ...}}

    def _log(self, *args):
        msg = " ".join(str(a) for a in args)
        try:
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(msg + "\n")
        except Exception:
            pass

    def _load_prompt_template(self) -> str:
        """加载SSRF prompt模板"""
        return self.prompt_path.read_text(encoding="utf-8")

    def _generate_token(self, length: int = 12) -> str:
        """生成随机token"""
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))

    def test(self, request: Dict[str, Any], credentials: Dict[str, Any]) -> Dict[str, Any]:
        """
        测试单个请求的SSRF（两阶段版本）

        两阶段测试流程：
        - Stage 1: 初始攻击（使用原始prompt）
        - Stage 2: 反思攻击（如果Stage 1失败，基于失败分析生成新策略）

        Args:
            request: 完整请求数据（包含response）
            credentials: 账户凭证

        Returns:
            {
                "vulnerable": True/False/None,
                "stage": 1 or 2,  # 表示在哪个阶段检测到/确认
                "token": str,
                "beacon_url": str,
                "curl_templates": List[str],
                "commands_executed": List[str],
                ...
            }
        """
        # ========== Stage 1: 初始攻击 ==========
        self._log(f"\n{'='*70}")
        self._log(f"[STAGE 1: Initial Attack]")
        self._log(f"{'='*70}\n")

        result_stage1 = self._execute_stage1(request, credentials)

        # 如果检测到漏洞，直接返回
        if result_stage1.get("vulnerable") is True:
            self._log(f"\n[STAGE 1] ✓ VULNERABLE - Skipping Stage 2")
            return result_stage1

        # 如果未启用反思，直接返回Stage 1结果
        if not self.reflection_enabled:
            self._log(f"\n[Reflection] Disabled - Returning Stage 1 result")
            return result_stage1

        # ========== Stage 2: 反思攻击 ==========
        self._log(f"\n{'='*70}")
        self._log(f"[STAGE 2: Reflective Attack]")
        self._log(f"{'='*70}")
        self._log(f"[Reflection] Stage 1 did not detect vulnerability, starting reflection analysis...")
        self._log(f"")

        result_stage2 = self._execute_stage2(
            request=request,
            credentials=credentials,
            stage1_context=result_stage1
        )

        return result_stage2

    def _execute_stage1(self, request: Dict[str, Any], credentials: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行Stage 1初始攻击（原test方法逻辑）

        Returns:
            {
                "vulnerable": True/False/None,
                "stage": 1,
                "token": str,
                "beacon_url": str,
                "curl_templates": List[str],  # ✅ 保存用于反思
                "commands_executed": List[str],
                "test_results": List[Dict],  # ✅ 保存用于反思
                "llm_analysis": str,  # ✅ 保存LLM分析输出
                ...
            }
        """
        method = request.get("method", "GET")
        url = request.get("url", "")

        self._log(f"\n{'='*70}")
        self._log(f"[SSRF] New Test Started")
        self._log(f"{'='*70}")
        self._log(f"[SSRF] Testing: {method} {url}")
        self._log(f"\n[Received from Planning Agent]:")
        self._log(f"  Target Request:")
        self._log(f"    Method: {method}")
        self._log(f"    URL: {url}")
        self._log(f"    Headers: {json.dumps(request.get('headers', {}), indent=6)}")
        self._log(f"    Body: {request.get('body', 'None')}")
        self._log(f"    Response Status: {request.get('response_status', 'N/A')}")
        original_response = str(request.get('response_body', ''))
        extracted_response = extract_useful_response(original_response, max_length=2000)
        self._log(f"    Response Body (preview): {extracted_response}")
        self._log(f"  Credentials: {json.dumps(credentials, indent=6, default=str)}")
        self._log(f"")

        # ========== 第一步：调用LLM生成curl模板 ==========
        self._log(f"[Step 1: Calling LLM to Identify Injection Points]")
        curl_templates, llm_analysis = self._generate_curl_templates(request)  # ✅ 获取LLM分析输出

        if not curl_templates:
            self._log(f"[SSRF] No injection points identified by LLM")
            return {
                "vulnerable": False,
                "stage": 1,  # ✅ 添加stage标记
                "token": None,
                "beacon_url": None,
                "curl_templates": [],
                "commands_executed": [],
                "test_results": [],  # ✅ 添加test_results
                "llm_analysis": llm_analysis,  # ✅ 保存LLM分析
                "note": "No injection points found"
            }

        self._log(f"[LLM Generated {len(curl_templates)} curl template(s)]:")
        for i, tmpl in enumerate(curl_templates, 1):
            self._log(f"  {i}. {tmpl}")
        self._log(f"")

        # ========== 第二步：生成统一的token ==========
        token = self._generate_token()
        beacon_url = f"{self.beacon_base}?data={token}"
        self._log(f"[Step 2: Generated Unified Token]: {token}")
        self._log(f"[Beacon URL]: {beacon_url}")
        self._log(f"")

        # ========== 第三步：生成SSRF payload列表 ==========
        ssrf_payloads = self._get_payloads(beacon_url)
        self._log(f"[Step 3: Generated {len(ssrf_payloads)} SSRF Payloads]:")
        for i, payload in enumerate(ssrf_payloads, 1):
            self._log(f"  {i}. {payload}")
        self._log(f"")

        # ========== 第四步：执行测试 ==========
        self._log(f"[Step 4: Executing Tests]")
        executed_commands = []
        test_results = []  # ✅ 保存测试结果用于反思

        for template in curl_templates:
            self._log(f"\n[Testing Template]: {template}")

            for payload in ssrf_payloads:
                # 替换{PAYLOAD}为实际payload
                if '{PAYLOAD}' not in template:
                    self._log(f"  ⚠️  Template missing {{PAYLOAD}} placeholder, skipping")
                    continue

                final_command = template.replace('{PAYLOAD}', payload)

                # 追加凭证
                final_command = append_credentials_to_curl(final_command, credentials)

                self._log(f"  [Payload]: {payload}")
                # 打印完整命令（不截断）
                self._log(f"  [Command]: {final_command}")

                try:
                    process = subprocess.Popen(
                        final_command,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    stdout, stderr = process.communicate(timeout=10)

                    # 解析HTTP状态码
                    from attack_agent.request_utils import parse_http_status_from_response
                    http_status, response_body = parse_http_status_from_response(stdout)

                    extracted_response = extract_useful_response(response_body, max_length=2000)
                    self._log(f"  ✓ Executed (curl_exit_code: {process.returncode})")
                    if http_status is not None:
                        self._log(f"  HTTP Status: {http_status}")
                    self._log(f"  Response length: {len(response_body)} bytes")
                    self._log(f"  Response (extracted):\n{extracted_response}")
                    if stderr:
                        self._log(f"  Stderr: {stderr}")
                    executed_commands.append(final_command)

                    # ✅ 保存测试结果
                    test_results.append({
                        "template": template,
                        "payload": payload,
                        "command": final_command,
                        "http_status": http_status,
                        "response": extracted_response,
                        "stderr": stderr,
                        "returncode": process.returncode
                    })

                except subprocess.TimeoutExpired:
                    self._log(f"  ✗ Timeout after 10 seconds")
                    # ✅ 保存超时结果
                    test_results.append({
                        "template": template,
                        "payload": payload,
                        "command": final_command,
                        "error": "Timeout after 10 seconds"
                    })
                except Exception as e:
                    self._log(f"  ✗ Failed: {e}")
                    # ✅ 保存失败结果
                    test_results.append({
                        "template": template,
                        "payload": payload,
                        "command": final_command,
                        "error": str(e)
                    })

        self._log(f"\n[Execution Complete]:")
        self._log(f"  Commands Executed: {len(executed_commands)}")
        self._log(f"")

        # ✅ 记录执行信息（用于延迟检测）
        self.execution_records[token] = {
            "token": token,
            "beacon_url": beacon_url,
            "url": url,
            "method": method,
            "curl_templates": curl_templates,
            "commands_executed": executed_commands
        }

        # ========== 第五步：检查beacon日志（立即检测）==========
        self._log(f"[Step 5: Checking Beacon Detection (immediate)]")
        vulnerable = check_beacon_detection(token)

        if vulnerable:
            self._log(f"  ✓ TOKEN FOUND - SSRF confirmed immediately")
        else:
            self._log(f"  ✗ Token not found yet - May be stored SSRF, will check in finalize()")

        self._log(f"")
        self._log(f"{'='*70}")
        self._log(f"[SSRF Test Summary]")
        self._log(f"  Token: {token}")
        self._log(f"  Commands Executed: {len(executed_commands)}")
        self._log(f"  Immediate Detection: {'✓ TOKEN FOUND' if vulnerable else '✗ Token not found'}")
        if vulnerable:
            self._log(f"  Result: VULNERABLE")
        else:
            self._log(f"  Result: PENDING (waiting for finalize)")
        self._log(f"{'='*70}\n")

        return {
            "vulnerable": vulnerable if vulnerable else None,  # ✅ None表示pending
            "stage": 1,  # ✅ 标记为Stage 1
            "beacon_url": beacon_url,
            "token": token,
            "curl_templates": curl_templates,  # ✅ 保存用于反思
            "commands_executed": executed_commands,
            "test_results": test_results,  # ✅ 保存用于反思
            "llm_analysis": llm_analysis,  # ✅ 保存LLM分析输出
            "note": f"Stage 1 - Immediate detection: {'SSRF confirmed' if vulnerable else 'Pending finalize'}"
        }

    def _generate_curl_templates(self, request: Dict[str, Any]) -> tuple:
        """
        调用LLM生成带{PAYLOAD}占位符的curl模板

        Returns:
            (curl模板列表, LLM完整输出) 元组
        """
        sys_prompt = self._load_prompt_template()

        # 格式化请求信息
        original_response = str(request.get('response_body', ''))
        extracted_response = extract_useful_response(original_response, max_length=2000)
        user_prompt = f"""REQUEST INFORMATION:
Method: {request.get('method', 'GET')}
URL: {request.get('url', '')}
Headers: {json.dumps(request.get('headers', {}), indent=2)}
Body: {json.dumps(request.get('body'), indent=2) if request.get('body') else 'None'}
Response Status: {request.get('response_status', 'N/A')}
Response Body (extracted): {extracted_response}

Please analyze this request and generate curl command templates with {{PAYLOAD}} placeholder for SSRF testing."""

        self._log(f"\n[LLM INPUT - SSRF Analysis Prompt]:")
        self._log(f"{'~'*70}")
        self._log(f"{user_prompt}")
        self._log(f"{'~'*70}\n")

        try:
            completion = self.client.chat.completions.create(
                model=get_model_name("attack_agent"),
                messages=[
                    {"role": "system", "content": sys_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=get_temperature("attack_agent")
            )

            llm_output = completion.choices[0].message.content

            self._log(f"[LLM OUTPUT - SSRF Analysis Response]:")
            self._log(f"{'~'*70}")
            self._log(f"{llm_output}")
            self._log(f"{'~'*70}\n")

            # 解析Commands部分
            templates = self._parse_curl_templates(llm_output)

            return templates, llm_output  # ✅ 返回元组

        except Exception as e:
            self._log(f"[SSRF] LLM call failed: {e}")
            import traceback
            self._log(traceback.format_exc())
            return [], ""  # ✅ 错误时返回空列表和空字符串

    def _parse_curl_templates(self, llm_output: str) -> List[str]:
        """
        从LLM输出中提取curl模板（改进版，兼容多种LLM输出格式）

        Returns:
            curl模板列表
        """
        templates = []
        lines = llm_output.splitlines()

        # 查找 "Commands" 关键词所在行的索引
        commands_line_idx = -1
        for i, line in enumerate(lines):
            # 简单判断：行中是否包含 "command:" (不区分大小写)
            line_lower = line.lower()
            if 'command:' in line_lower or 'commands:' in line_lower:
                commands_line_idx = i
                break

        if commands_line_idx == -1:
            self._log(f"[Warning] No Commands section found in LLM output")
            return []

        # 从Commands行之后开始解析
        for i in range(commands_line_idx + 1, len(lines)):
            line = lines[i].strip()

            # 跳过空行
            if not line:
                continue

            # 跳过markdown代码块标记
            if line.startswith('```'):
                continue

            # 检查是否包含 curl 关键词和 {PAYLOAD} 占位符
            if 'curl' in line and '{PAYLOAD}' in line:
                # 清理可能的markdown格式
                cleaned = line.lstrip('`').rstrip('`').strip()
                templates.append(cleaned)

        if not templates:
            self._log(f"[Warning] No valid curl commands found after Commands section")

        return templates

    def _get_payloads(self, beacon_url: str) -> List[str]:
        """
        生成SSRF payload列表

        Args:
            beacon_url: 回调URL（包含token）

        Returns:
            payload列表
        """
        from urllib.parse import quote

        # URL编码
        encoded_url = quote(beacon_url, safe='')

        return [
            beacon_url,                    # 直接注入
            # f"http://{beacon_url}",        # 添加协议（如果LLM模板中没有）
            # f"https://{beacon_url}",
            # encoded_url,                    # URL编码
            # f"file://{beacon_url}",        # file协议
            # f"gopher://{beacon_url}",      # gopher协议
        ]

    # ========== Stage 2: 反思攻击方法 ==========

    def _execute_stage2(self, request: Dict[str, Any], credentials: Dict[str, Any],
                       stage1_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行Stage 2反思攻击

        核心逻辑：
        1. 构建反思输入（基于Stage 1失败分析）
        2. 调用LLM生成新模板
        3. 执行新模板（复用Stage 1的执行逻辑）
        4. 检测OOB（复用）

        Args:
            request: 原始请求
            credentials: 凭证
            stage1_context: Stage 1的完整结果

        Returns:
            Stage 2的结果字典
        """
        # 1. 构建反思suffix
        self._log(f"[Reflection] Building reflection analysis...")
        reflection_suffix = self._build_reflection_suffix(stage1_context)

        # 2. 调用LLM生成新模板（在原prompt基础上append）
        self._log(f"[Step 1: Generating Reflection Templates via LLM]")
        new_templates, llm_reflection_output = self._generate_curl_templates_with_reflection(
            request=request,
            reflection_suffix=reflection_suffix
        )

        if not new_templates:
            self._log(f"[Reflection] LLM did not generate new templates, returning Stage 1 result")
            # 返回Stage 1结果，但标记为Stage 2尝试过
            stage1_context["reflection_attempted"] = True
            stage1_context["reflection_note"] = "No new templates generated"
            return stage1_context

        self._log(f"[LLM Generated {len(new_templates)} new template(s)]:")
        for i, tmpl in enumerate(new_templates, 1):
            self._log(f"  {i}. {tmpl}")
        self._log(f"")

        # 3. 生成新的token（避免和Stage 1冲突）
        token = self._generate_token()
        beacon_url = f"{self.beacon_base}?data={token}"
        self._log(f"[Step 2: Generated New Token]: {token}")
        self._log(f"[Beacon URL]: {beacon_url}")
        self._log(f"")

        # 4. 生成payload列表（复用现有逻辑）
        ssrf_payloads = self._get_payloads(beacon_url)
        self._log(f"[Step 3: Generated {len(ssrf_payloads)} SSRF Payloads]:")
        for i, payload in enumerate(ssrf_payloads, 1):
            self._log(f"  {i}. {payload}")
        self._log(f"")

        # 5. 执行测试（复用Stage 1的执行逻辑）
        self._log(f"[Step 4: Executing Tests]")
        executed_commands = []
        test_results = []

        for template in new_templates:
            self._log(f"\n[Testing Template]: {template}")

            for payload in ssrf_payloads:
                if '{PAYLOAD}' not in template:
                    self._log(f"  ⚠️  Template missing {{PAYLOAD}} placeholder, skipping")
                    continue

                final_command = template.replace('{PAYLOAD}', payload)
                final_command = append_credentials_to_curl(final_command, credentials)

                self._log(f"  [Payload]: {payload}")
                self._log(f"  [Command]: {final_command}")

                try:
                    process = subprocess.Popen(
                        final_command,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    stdout, stderr = process.communicate(timeout=10)

                    from attack_agent.request_utils import parse_http_status_from_response
                    http_status, response_body = parse_http_status_from_response(stdout)

                    extracted_response = extract_useful_response(response_body, max_length=2000)
                    self._log(f"  ✓ Executed (curl_exit_code: {process.returncode})")
                    if http_status is not None:
                        self._log(f"  HTTP Status: {http_status}")
                    self._log(f"  Response length: {len(response_body)} bytes")
                    self._log(f"  Response (extracted):\n{extracted_response}")
                    if stderr:
                        self._log(f"  Stderr: {stderr}")
                    executed_commands.append(final_command)

                    test_results.append({
                        "template": template,
                        "payload": payload,
                        "command": final_command,
                        "http_status": http_status,
                        "response": extracted_response,
                        "stderr": stderr,
                        "returncode": process.returncode
                    })

                except subprocess.TimeoutExpired:
                    self._log(f"  ✗ Timeout after 10 seconds")
                    test_results.append({
                        "template": template,
                        "payload": payload,
                        "command": final_command,
                        "error": "Timeout after 10 seconds"
                    })
                except Exception as e:
                    self._log(f"  ✗ Failed: {e}")
                    test_results.append({
                        "template": template,
                        "payload": payload,
                        "command": final_command,
                        "error": str(e)
                    })

        self._log(f"\n[Execution Complete]:")
        self._log(f"  Commands Executed: {len(executed_commands)}")
        self._log(f"")

        # 6. 记录执行信息（用于延迟检测）
        method = request.get("method", "GET")
        url = request.get("url", "")
        self.execution_records[token] = {
            "token": token,
            "beacon_url": beacon_url,
            "url": url,
            "method": method,
            "curl_templates": new_templates,
            "commands_executed": executed_commands
        }

        # 7. 检查beacon日志（立即检测）
        self._log(f"[Step 5: Checking Beacon Detection (immediate)]")
        vulnerable = check_beacon_detection(token)

        if vulnerable:
            self._log(f"  ✓ TOKEN FOUND - SSRF confirmed in Stage 2!")
        else:
            self._log(f"  ✗ Token not found yet - May be stored SSRF, will check in finalize()")

        self._log(f"")
        self._log(f"{'='*70}")
        self._log(f"[SSRF Test Summary - Stage 2]")
        self._log(f"  Token: {token}")
        self._log(f"  Commands Executed: {len(executed_commands)}")
        self._log(f"  Immediate Detection: {'✓ TOKEN FOUND' if vulnerable else '✗ Token not found'}")
        if vulnerable:
            self._log(f"  Result: VULNERABLE (detected in Stage 2)")
        else:
            self._log(f"  Result: PENDING (waiting for finalize)")
        self._log(f"{'='*70}\n")

        return {
            "vulnerable": vulnerable if vulnerable else None,
            "stage": 2,
            "beacon_url": beacon_url,
            "token": token,
            "curl_templates": new_templates,
            "commands_executed": executed_commands,
            "test_results": test_results,
            "llm_reflection_output": llm_reflection_output,
            "reflection_analysis": reflection_suffix,
            # ✅ 新增：保留Stage 1的完整结果
            "stage1_results": {
                "test_results": stage1_context.get("test_results", []),
                "curl_templates": stage1_context.get("curl_templates", []),
                "commands_executed": stage1_context.get("commands_executed", []),
                "llm_analysis": stage1_context.get("llm_analysis", "")
            },
            "note": f"Stage 2 - Reflection attack: {'SSRF confirmed' if vulnerable else 'Pending finalize'}"
        }

    def _build_reflection_suffix(self, stage1_context: Dict[str, Any]) -> str:
        """
        构建追加到原prompt的反思内容

        Args:
            stage1_context: Stage 1的完整结果

        Returns:
            反思suffix（追加到原始prompt后面）
        """
        # 提取Stage 1数据
        templates = stage1_context.get("curl_templates", [])
        test_results = stage1_context.get("test_results", [])
        vulnerable = stage1_context.get("vulnerable")

        # 构建反思内容
        suffix = "\n\n"
        suffix += "="*70 + "\n"
        suffix += "STAGE 1 RESULTS (Failed Detection)\n"
        suffix += "="*70 + "\n\n"

        # 1. 之前生成的模板
        suffix += "Previous Templates Generated:\n"
        for i, tmpl in enumerate(templates, 1):
            suffix += f"{i}. {tmpl}\n"
        suffix += "\n"

        # 2. 执行结果（智能提取响应）
        suffix += "Execution Results:\n"
        suffix += "-"*70 + "\n"

        # 去重 + 采样（最多10个）
        sampled = self._sample_test_results(test_results, max_samples=10)

        for i, result in enumerate(sampled, 1):
            suffix += f"\nTest {i}:\n"
            suffix += f"  Command: {result.get('command', 'N/A')}\n" 
            suffix += f"  HTTP Status: {result.get('http_status', 'N/A')}\n"

            # ✅ 使用智能提取
            response = result.get('response', '')
            if response:
                suffix += f"  Response (extracted):\n{response}\n"

            if result.get('error'):
                suffix += f"  Error: {result['error']}\n"

        suffix += "\n"

        # 3. 结果说明
        suffix += f"Result: {'NOT VULNERABLE' if vulnerable is False else 'UNCERTAIN/PENDING'}\n"
        suffix += "\n"

        # 4. 反思任务说明
        suffix += "="*70 + "\n"
        suffix += "YOUR TASK FOR STAGE 2 - REFLECTION\n"
        suffix += "="*70 + "\n\n"

        suffix += """Based on the above failed attempt, please:

1. **Analyze Why Stage 1 Failed**:
   - Was the injection point correct?
   - Did responses show filtering/blocking patterns?
   - Were there error messages revealing protection mechanisms?
   - Did we test the right parameters/headers?

2. **Design NEW Injection Strategy**:
   - Try DIFFERENT injection points (different parameters, headers, paths, etc.)
   - Adjust request structure based on error messages
   - Consider alternative approaches (e.g., if URL parameter failed, try headers)

3. **Generate NEW Curl Command Templates**:
   - Use {PAYLOAD} placeholder (payload content will remain the same)
   - Focus on changing WHERE to inject, not WHAT to inject
   - You can modify field names, add/remove parameters, change headers, etc.
   - If previous templates tested URL parameters, try headers or body
   - If previous templates used GET, consider POST with different structure

IMPORTANT:
- Keep the {PAYLOAD} placeholder unchanged
- Focus on changing injection points/request structure
- Generate 3-5 NEW templates with DIFFERENT injection points
- Be creative - try unconventional injection points

Output Format (same as Stage 1):

Analysis:
<Your failure analysis and new strategy explanation>

Commands:
<curl command 1 with {PAYLOAD}>
<curl command 2 with {PAYLOAD}>
<curl command 3 with {PAYLOAD}>
...
"""

        return suffix

    def _generate_curl_templates_with_reflection(self, request: Dict[str, Any],
                                                 reflection_suffix: str) -> tuple:
        """
        调用LLM生成反思后的新模板

        策略：在原始prompt基础上append reflection_suffix

        Args:
            request: 原始请求
            reflection_suffix: 反思分析内容

        Returns:
            (新模板列表, LLM输出) 元组
        """
        # 1. 加载原始prompt
        sys_prompt = self._load_prompt_template()

        # 2. 构建user prompt（和Stage 1相同的格式）
        original_response = str(request.get('response_body', ''))
        extracted_response = extract_useful_response(original_response, max_length=2000)
        user_prompt = f"""REQUEST INFORMATION:
Method: {request.get('method', 'GET')}
URL: {request.get('url', '')}
Headers: {json.dumps(request.get('headers', {}), indent=2)}
Body: {json.dumps(request.get('body'), indent=2) if request.get('body') else 'None'}
Response Status: {request.get('response_status', 'N/A')}
Response Body (extracted): {extracted_response} 

Please analyze this request and generate curl command templates with {{PAYLOAD}} placeholder for SSRF testing.
"""

        # 3. ✅ Append反思内容
        user_prompt += reflection_suffix

        # 4. 调用LLM
        self._log(f"\n[LLM INPUT - Reflection Prompt]:")
        self._log(f"{'~'*70}")
        self._log(f"{user_prompt}")
        self._log(f"{'~'*70}\n")

        try:
            completion = self.client.chat.completions.create(
                model=get_model_name("attack_agent"),
                messages=[
                    {"role": "system", "content": sys_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=get_temperature("attack_agent")
            )

            llm_output = completion.choices[0].message.content

            self._log(f"[LLM OUTPUT - Reflection Response]:")
            self._log(f"{'~'*70}")
            self._log(f"{llm_output}")
            self._log(f"{'~'*70}\n")

            # 5. 解析模板（复用现有的_parse_curl_templates）
            templates = self._parse_curl_templates(llm_output)
            return templates, llm_output

        except Exception as e:
            self._log(f"[Reflection] LLM call failed: {e}")
            import traceback
            self._log(traceback.format_exc())
            return [], ""

    def _sample_test_results(self, test_results: List[Dict], max_samples: int = 10) -> List[Dict]:
        """
        从测试结果中采样（去重 + 采样）

        Args:
            test_results: 完整测试结果列表
            max_samples: 最大采样数量

        Returns:
            采样后的结果列表
        """
        if not test_results:
            return []

        # 按响应哈希去重
        seen = {}
        for r in test_results:
            resp = r.get("response", "")
            key = resp[:500] if resp else "empty"  # 简单哈希
            if key not in seen:
                seen[key] = r

        deduped = list(seen.values())

        # 采样（最多max_samples个）
        if len(deduped) <= max_samples:
            return deduped
        else:
            # 均匀采样
            import random
            return random.sample(deduped, max_samples)

    def check_final_results(self) -> Dict[str, bool]:
        """
        检查最终结果（在统一访问所有页面后调用）

        Returns:
            {token: is_vulnerable}
        """
        self._log(f"\n{'='*70}")
        self._log(f"[SSRF] Checking Final Results")
        self._log(f"{'='*70}\n")

        updates = {}

        for token in self.execution_records.keys():
            # 重新检查beacon日志
            is_vulnerable = check_beacon_detection(token)
            updates[token] = is_vulnerable

            if is_vulnerable:
                self._log(f"  ✓ Token {token}: VULNERABLE (detected in beacon log)")
            else:
                self._log(f"  ✗ Token {token}: SAFE (not in beacon log)")

        self._log(f"\n[SSRF] Final Summary:")
        successful = sum(1 for v in updates.values() if v)
        self._log(f"  Total tests: {len(updates)}")
        self._log(f"  Successful SSRF: {successful}")
        self._log(f"{'='*70}\n")

        return updates
