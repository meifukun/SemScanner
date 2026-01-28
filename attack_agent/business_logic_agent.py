"""
Business Logic Agent - 改造版（单点分析为主）
"""

from typing import Dict, Any, List, Optional
from pathlib import Path
import subprocess
import json
import re
import time
from config.llm_config import get_model_name, get_temperature
from attack_agent.request_utils import extract_useful_response

class BusinessLogicAgent:
    """
    业务逻辑漏洞测试Agent - 改造版
    
    职责：
    1. 接收AttackTask（任务描述+完整请求）
    2. 根据任务描述分析请求/响应
    3. 生成针对性的测试curl命令
    4. 调用LLM研判是否存在漏洞
    
    主流场景：单点分析（单个请求的业务逻辑问题）
    特殊场景：多步骤测试（IDOR等，需要多个账户）
    """
    
    def __init__(self, client, log_dir: str = "output/attack_logs/business_logic",
                 reflection_enabled: bool = True):  # ✅ 新增：反思功能开关
        self.client = client
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._log_path = self.log_dir / "business_logic_agent.log"
        self.reflection_enabled = reflection_enabled  # ✅ 保存配置

        # 加载prompt
        self._analysis_prompt = self._load_analysis_prompt()
        self._judgment_prompt = self._load_judgment_prompt()
    
    def _log(self, *args):
        msg = " ".join(str(a) for a in args)
        try:
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(msg + "\n")
        except Exception:
            pass
    
    def _load_analysis_prompt(self) -> str:
        """加载分析prompt（生成测试命令）"""
        return """You are a security testing expert analyzing business logic vulnerabilities.

Your task: Given a request and a task description, generate executable commands to test the business logic vulnerability.

=== INPUT ===
You will receive:
1. Task Description: What vulnerability to test (e.g., "Test if negative prices are accepted")
2. Target Request: Full HTTP request with response data
3. Account Credentials: Available for authentication

=== YOUR TASK ===
Generate executable curl commands that test the described vulnerability by:
1. Analyzing the request parameters and business logic
2. Identifying which parameters to manipulate
3. Creating multiple test cases that violate business rules
4. Testing different boundary values and edge cases
5. Using provided credentials for authentication

=== OUTPUT FORMAT ===

Analysis:
<Explain your understanding of:
- What business logic is being tested
- Which parameters are relevant
- What values would violate business rules
- What specific hypotheses you're testing
- Expected vs actual behavior>

Test_Commands:
<command 1>
<command 2>
<command 3>
...

=== EXAMPLES ===

Example 1 - Price Manipulation:
Task: Test if negative amounts are accepted in checkout
Request: POST /api/checkout with {{"item_id": 123, "quantity": 2, "price": 100}}

Analysis:
The checkout endpoint accepts price and quantity as parameters. Testing if server-side validation prevents price manipulation.
Hypotheses to test:
1. Negative price values (-100, -1)
2. Zero price
3. Negative quantity
4. Extremely large values
5. Decimal manipulation (0.01)

Test_Commands:
curl -i -X POST 'http://example.com/api/checkout' -H 'Content-Type: application/json' -d '{{"item_id":123,"quantity":2,"price":-100}}'
curl -i -X POST 'http://example.com/api/checkout' -H 'Content-Type: application/json' -d '{{"item_id":123,"quantity":2,"price":-1}}'
curl -i -X POST 'http://example.com/api/checkout' -H 'Content-Type: application/json' -d '{{"item_id":123,"quantity":2,"price":0}}'
curl -i -X POST 'http://example.com/api/checkout' -H 'Content-Type: application/json' -d '{{"item_id":123,"quantity":-5,"price":100}}'
curl -i -X POST 'http://example.com/api/checkout' -H 'Content-Type: application/json' -d '{{"item_id":123,"quantity":2,"price":0.01}}'

Example 2 - IDOR:
Task: Test if basket ID can be manipulated to access other users' baskets
Request: GET /api/basket/6

Analysis:
The endpoint uses basket ID in URL path. Testing if authorization checks prevent accessing other users' data.
Testing sequential IDs and edge cases.

Test_Commands:
curl -i -X GET 'http://example.com/api/basket/1'
curl -i -X GET 'http://example.com/api/basket/2'
curl -i -X GET 'http://example.com/api/basket/3'
curl -i -X GET 'http://example.com/api/basket/5'
curl -i -X GET 'http://example.com/api/basket/7'
curl -i -X GET 'http://example.com/api/basket/999'
curl -i -X GET 'http://example.com/api/basket/-1'
curl -i -X GET 'http://example.com/api/basket/0'

=== GUIDELINES ===
1. **Generate 5-10 test cases** per vulnerability
2. **IMPORTANT: All curl commands MUST include the -i flag** to show HTTP response headers
3. **DO NOT include authentication headers** (Cookie, Authorization) - they will be added automatically
4. **Use realistic but rule-violating values**
5. **Each test should have ONE specific hypothesis**
6. **Generate only curl commands** - one command per line

Now analyze this task:

Task Description: {task_description}

Target Request:
Method: {method}
URL: {url}
Headers: {headers}
Body: {body}
Response Status: {response_status}
Response Body: {response_body}

Available Credentials:
{credentials_info}

Generate your analysis and test commands:
"""
    
    def _load_judgment_prompt(self) -> str:
        """加载研判prompt"""
        return """You are a security analyst reviewing business logic vulnerability test results.

    Your task: Determine if the test results prove a real business logic vulnerability exists.

    === INPUT ===
    You will receive:
    1. Task Description: What was being tested
    2. Baseline Request and Response:
    - Original request method, URL, headers, and body
    - Original response status code and extracted response body
    3. Test Execution Results:
    - Test commands that were executed (with parameters)
    - Response status codes
    - Extracted response bodies

    === EVALUATION CRITERIA ===

    Evidence of vulnerability:
    - **Response Analysis**: Does the server response indicate unexpected behavior? (e.g., negative balance accepted, unauthorized access granted, validation bypassed, or exposure of information that should not be visible)
    - **Status Codes**: Are there successful responses (200/201) where there should be errors (400/403)?
    - **Response Content**: Does the response body show data modifications that violate business rules?
    - **Comparison Logic**: Compare attack results with expected normal behavior - what's different?
    - **False Positives**: Consider whether observed behavior might be legitimate (e.g., error handling, graceful degradation)

    NOT vulnerabilities:
    ✗ Proper error responses (400 Bad Request)
    ✗ Validation error messages
    ✗ 401/403 for unauthorized operations
    ✗ Server-side recalculation catching manipulation
    ✗ Test responses that are essentially the same as the baseline behavior

    === OUTPUT FORMAT ===

    Analysis:
    <Step-by-step reasoning:
    - What does the baseline request/response show?
    - What did each test attempt? What responses were received?
    - How do test responses compare to the baseline behavior?>

    Result:
    [If NO vulnerability:]
    No vulnerability exists

    [If vulnerability found:]
    <Vulnerability description with evidence>

    === GUIDELINES ===
    1. Be rigorous - require clear evidence
    2. Do NOT rely only on HTTP status codes
    3. Compare test responses to the baseline behavior
    4. Look for business rule violations in responses
    5. Avoid False positive: A finding should not be considered a vulnerability when the server shows proper validation, when responses do not exhibit the expected abnormal behavior, or when all tests return consistent response patterns (e.g., all 400-series errors), indicating normal and stable baseline behavior.
    6. At the same time, it is very very important to avoid missing real vulnerabilities when clear evidence is present.
    
    Now analyze these results:

    Task Description: {task_description}

    Baseline Request:
    Method: {method}
    URL: {url}
    Headers: {headers}
    Body: {body}
    Baseline Response Status: {response_status}
    Baseline Response Body (extracted):
    {response_body}

    Test Execution Results:
    {execution_results}

    Provide your analysis:
    """
    

    # def test_multi_step(self, task_description: str,
    #                    target_request: Dict[str, Any],
    #                    accounts: List[str],
    #                    account_manager) -> Dict[str, Any]:
    #     """
    #     测试多步骤业务逻辑漏洞（特殊场景，如IDOR）
        
    #     Args:
    #         task_description: 任务描述（如"测试用户A是否能访问用户B的订单"）
    #         target_request: 完整请求对象
    #         accounts: 账户列表（如["user1", "user2"]）
    #         account_manager: 账户管理器
        
    #     Returns:
    #         {
    #             "vulnerable": True/False/None,
    #             "steps_executed": int,
    #             "analysis": str,
    #             "step_results": List[Dict]
    #         }
    #     """
    #     self._log(f"[BusinessLogic] Testing multi-step task:")
    #     self._log(f"  Description: {task_description}")
    #     self._log(f"  Accounts: {accounts}")
        
    #     # 为每个账户执行相同请求
    #     step_results = []
        
    #     for account_id in accounts:
    #         self._log(f"  Step: {account_id} -> {target_request.get('method')} {target_request.get('url')}")
            
    #         # 获取账户凭证
    #         credentials = account_manager.get_credentials(account_id)
    #         if not credentials:
    #             self._log(f"    ⚠️  Account not logged in: {account_id}")
    #             step_results.append({
    #                 "account": account_id,
    #                 "error": "Account not logged in"
    #             })
    #             continue
            
    #         from attack_agent.request_utils import append_credentials_to_curl
    #         # 构造基础 curl（不含凭证）
    #         base_curl = self._build_base_curl_command(target_request)
    #         # 追加凭证
    #         full_curl = append_credentials_to_curl(base_curl, credentials)
    #         result = self._execute_curl_command(full_curl)

    #         step_results.append({
    #             "account": account_id,
    #             "command": full_curl,
    #             "status": result.get("status", 0),
    #             "body": result.get("body", "")
    #         })

    #         # ✅ 显示curl退出码和HTTP状态码
    #         self._log(f"    ✓ Executed (curl_exit_code: {result.get('curl_exit_code', 'N/A')})")
    #         http_status = result.get("status", 0)
    #         if http_status > 0:
    #             self._log(f"    HTTP Status: {http_status}")
    #         # 打印完整响应（不截断）
    #         response_body = result.get("body", "")
    #         self._log(f"    Response length: {len(response_body)} bytes")
    #         self._log(f"    Response: {response_body}")
    #         if result.get("stderr"):
    #             self._log(f"    Stderr: {result['stderr']}")
        
    #     # 调用LLM研判（使用多步骤分析）
    #     judgment = self._judge_multi_step_vulnerability(
    #         task_description,
    #         step_results
    #     )
        
    #     vulnerable = judgment.get("vulnerable", False)
        
    #     self._log(f"  Result: {'VULNERABLE' if vulnerable else 'SAFE'}")
        
    #     return {
    #         "vulnerable": vulnerable,
    #         "steps_executed": len(step_results),
    #         "analysis": judgment.get("analysis", ""),
    #         "step_results": step_results
    #     }
    
    def _generate_test_commands(self, task_description: str,
                                target_request: Dict[str, Any],
                                credentials: Dict[str, Any]) -> tuple:
        """
        调用LLM生成测试命令

        Returns:
            (测试命令列表, LLM完整输出) 元组
        """
        # 格式化凭证信息
        from attack_agent.request_utils import format_credentials_for_display
        credentials_info = format_credentials_for_display(credentials)

        # 构造prompt
        original_response = str(target_request.get("response_body", ""))
        extracted_response = extract_useful_response(original_response, max_length=2000)
        prompt = self._analysis_prompt.format(
            task_description=task_description,
            method=target_request.get("method", "GET"),
            url=target_request.get("url", ""),
            headers=json.dumps(target_request.get("headers", {}), indent=2),
            body=json.dumps(target_request.get("body", {}), indent=2) if target_request.get("body") else "None",
            response_status=target_request.get("response_status", "N/A"),
            response_body=extracted_response,  # 使用智能提取后的
            credentials_info=credentials_info
        )

        # ✅ 记录LLM输入
        self._log(f"\n[Step 1: Generating Test Commands via LLM]")
        self._log(f"{'~'*70}")
        self._log(f"[LLM INPUT - Analysis Prompt]:")
        self._log(f"{prompt}")
        self._log(f"{'~'*70}\n")

        try:
            completion = self.client.chat.completions.create(
                model=get_model_name("attack_agent"),
                messages=[
                    {"role": "system", "content": "You are a security testing expert."},
                    {"role": "user", "content": prompt}
                ],
                temperature=get_temperature("attack_agent")
            )

            llm_output = completion.choices[0].message.content

            # ✅ 记录LLM输出
            self._log(f"[LLM OUTPUT - Analysis Response]:")
            self._log(f"{'~'*70}")
            self._log(f"{llm_output}")
            self._log(f"{'~'*70}\n")

            # 解析Test_Commands部分
            commands = self._parse_test_commands(llm_output)

            self._log(f"[Parsed {len(commands)} Commands]:")
            for i, cmd in enumerate(commands, 1):
                self._log(f"  {i}. {cmd}")
            self._log(f"")

            return commands, llm_output  # ✅ 返回元组

        except Exception as e:
            self._log(f"[BusinessLogic] LLM call failed: {e}")
            import traceback
            self._log(f"[BusinessLogic] Traceback:")
            self._log(traceback.format_exc())
            return [], ""  # ✅ 错误时返回空列表和空字符串

    def _parse_test_commands(self, llm_output: str) -> List[str]:
        """
        从LLM输出中提取测试命令

        支持多种格式:
        - Test_Commands:
        - **Test_Commands:**
        - **Test_Commands:**
          ```bash
          curl ...
          ```

        Returns:
            curl命令列表
        """
        # 查找包含Test_Commands的行（忽略markdown标记**）
        lines = llm_output.splitlines()
        start_idx = -1

        for i, line in enumerate(lines):
            # 匹配 Test_Commands: 或 **Test_Commands:** 等变体
            if re.search(r'\*{0,2}\s*Test_Commands\s*:\s*\*{0,2}', line, re.IGNORECASE):
                start_idx = i
                break

        if start_idx == -1:
            self._log("[Warning] No Test_Commands section found in LLM output")
            return []

        # 从start_idx开始提取命令
        commands = []
        in_code_block = False

        for line in lines[start_idx + 1:]:
            line = line.strip()

            # 跳过空行
            if not line:
                # 遇到空行可能表示section结束
                if commands:  # 如果已经有命令了，空行可能是结束标志
                    continue
                else:  # 还没找到命令，继续找
                    continue

            # 处理markdown代码块标记
            if line.startswith('```'):
                in_code_block = not in_code_block
                continue

            # 如果是curl命令，提取
            if line.startswith('curl'):
                commands.append(line)
            # 如果遇到下一个section（如Analysis:, Reasoning:等），停止
            elif re.match(r'^[A-Z][a-z]+\s*:', line) or re.match(r'^\*\*[A-Z][a-z]+\s*:\*\*', line):
                break

        if not commands:
            self._log("[Warning] No curl commands found in Test_Commands section")
        else:
            self._log(f"[Info] Extracted {len(commands)} test commands")

        return commands
    
    def _execute_curl_command(self, curl_cmd: str) -> Dict[str, Any]:
        """
        执行curl命令

        Returns:
            {status: int, body: str, stderr: str}
        """
        try:
            process = subprocess.Popen(
                curl_cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # ✅ timeout参数应该在communicate()中，不是Popen()中
            stdout, stderr = process.communicate(timeout=30)

            # ✅ 使用统一的HTTP状态码解析函数
            from attack_agent.request_utils import parse_http_status_from_response
            http_status, response_body = parse_http_status_from_response(stdout)

            return {
                "status": http_status if http_status is not None else 0,
                "body": response_body,
                "stderr": stderr,
                "curl_exit_code": process.returncode
            }

        except subprocess.TimeoutExpired:
            # 超时处理
            process.kill()
            return {
                "status": 0,
                "body": "",
                "stderr": "",
                "error": "Command timeout (30s exceeded)"
            }
        except Exception as e:
            return {
                "status": 0,
                "body": "",
                "stderr": "",
                "error": str(e)
            }
    
    def _extract_status_code(self, curl_output: str) -> int:
        """从curl -i输出中提取状态码"""
        match = re.search(r'HTTP/\d\.\d\s+(\d{3})', curl_output)
        return int(match.group(1)) if match else 0
    
    def _judge_vulnerability(self, task_description: str,
                             target_request: Dict[str, Any],
                            execution_results: List[Dict]) -> Dict[str, Any]:
        """
        调用LLM研判单点漏洞

        Returns:
            {vulnerable: bool, analysis: str}
        """

        # ===== 1. 格式化测试执行结果 =====
        results_text = ""
        for i, result in enumerate(execution_results, 1):
            results_text += f"\nTest {i}:\n"
            results_text += f"Command: {result['command']}\n"
            results_text += f"Status: {result['status']}\n"
            # ✅ 使用智能提取处理响应body
            response_extracted = extract_useful_response(result['body'], max_length=2000)
            results_text += f"Response (extracted):\n{response_extracted}\n"
            results_text += "-" * 40 + "\n"
        
        # ===== 2. 构造 baseline 信息（与 analysis LLM 类似） =====
        original_response = str(target_request.get("response_body", ""))
        baseline_extracted = extract_useful_response(original_response, max_length=2000)

        baseline_body = (
            json.dumps(target_request.get("body", {}), indent=2)
            if target_request.get("body") is not None
            else "None"
        )

        # 构造prompt
        prompt = self._judgment_prompt.format(
        task_description=task_description,
        method=target_request.get("method", "GET"),
        url=target_request.get("url", ""),
        headers=json.dumps(target_request.get("headers", {}), indent=2),
        body=baseline_body,
        response_status=target_request.get("response_status", "N/A"),
        response_body=baseline_extracted,
        execution_results=results_text,
        )

        self._log(f"\n[LLM Judgment - Analyzing Test Results]")
        self._log(f"{'~'*70}")
        self._log(f"[LLM INPUT - Judgment Prompt]:")
        self._log(f"{prompt}")
        self._log(f"{'~'*70}\n")

        try:
            completion = self.client.chat.completions.create(
                model=get_model_name("attack_agent"),
                messages=[
                    {"role": "system", "content": "You are a security analyst."},
                    {"role": "user", "content": prompt}
                ],
                temperature=get_temperature("attack_agent")
            )

            llm_output = completion.choices[0].message.content

            self._log(f"[LLM OUTPUT - Judgment Response]:")
            self._log(f"{'~'*70}")
            self._log(f"{llm_output}")
            self._log(f"{'~'*70}\n")

            # 解析结论
            vulnerable = self._parse_vulnerability_conclusion(llm_output)

            self._log(f"[Parsed Conclusion]: Vulnerable = {vulnerable}\n")

            return {
                "vulnerable": vulnerable,
                "analysis": llm_output
            }

        except Exception as e:
            self._log(f"[BusinessLogic] Judgment failed: {e}")
            import traceback
            self._log(f"[BusinessLogic] Traceback: {traceback.format_exc()}")
            return {
                "vulnerable": None,
                "analysis": str(e)
            }
    
    # def _judge_multi_step_vulnerability(self, task_description: str,
    #                                    step_results: List[Dict]) -> Dict[str, Any]:
    #     """
    #     调用LLM研判多步骤漏洞
        
    #     Returns:
    #         {vulnerable: bool, analysis: str}
    #     """
    #     # 格式化步骤结果
    #     results_text = ""
    #     for result in step_results:
    #         account = result.get("account", "unknown")
    #         results_text += f"\nAccount: {account}\n"
            
    #         if "error" in result:
    #             results_text += f"Error: {result['error']}\n"
    #         else:
    #             results_text += f"Command: {result['command']}\n"
    #             results_text += f"Status: {result['status']}\n"
    #             results_text += f"Response (truncated):\n{result['body']}\n"
            
    #         results_text += "-" * 40 + "\n"
        
    #     # 使用相同的研判prompt（但上下文不同）
    #     prompt = self._judgment_prompt.format(
    #         task_description=task_description,
    #         execution_results=results_text
    #     )

    #     try:
    #         completion = self.client.chat.completions.create(
    #             model=get_model_name("attack_agent"),
    #             messages=[
    #                 {"role": "system", "content": "You are a security analyst."},
    #                 {"role": "user", "content": prompt}
    #             ],
    #             temperature=get_temperature("attack_agent")
    #         )
            
    #         llm_output = completion.choices[0].message.content
            
    #         vulnerable = self._parse_vulnerability_conclusion(llm_output)
            
    #         return {
    #             "vulnerable": vulnerable,
    #             "analysis": llm_output
    #         }
        
    #     except Exception as e:
    #         self._log(f"[BusinessLogic] Multi-step judgment failed: {e}")
    #         return {
    #             "vulnerable": None,
    #             "analysis": str(e)
    #         }
    
    def _parse_vulnerability_conclusion(self, llm_output: str) -> bool:
        """
        解析LLM输出判断是否有漏洞
        
        查找关键字：
        - "No vulnerability exists" -> False
        - 其他描述性文本 -> True
        """
        # 提取Result部分
        match = re.search(r'Result:\s*\n(.+)', llm_output, re.DOTALL)
        
        if not match:
            # 如果没有Result部分，尝试全文匹配
            if "No vulnerability exists" in llm_output:
                return False
            elif "vulnerability" in llm_output.lower() and any(
                keyword in llm_output.lower() 
                for keyword in ["found", "exists", "successful", "accepted", "bypassed"]
            ):
                return True
            return False
        
        result_text = match.group(1).strip()
        
        # 明确判断
        if "No vulnerability exists" in result_text:
            return False
        
        # 如果有具体的漏洞描述（非"No vulnerability"开头），认为有漏洞
        if result_text and not result_text.startswith("No"):
            return True
        
        return False


    def test_single_point(self, task_description: str,
                        target_request: Dict[str, Any],
                        credentials: Dict[str, Any]) -> Dict[str, Any]:
        """
        测试单点业务逻辑漏洞（两阶段版本）

        两阶段测试流程：
        - Stage 1: 初始攻击（使用原始prompt）
        - Stage 2: 反思攻击（如果Stage 1失败，基于失败分析生成新策略）

        Args:
            task_description: 任务描述
            target_request: 完整请求数据
            credentials: 账户凭证

        Returns:
            {
                "vulnerable": True/False/None,
                "stage": 1 or 2,
                "commands_executed": int,
                "analysis": str,
                "test_results": List[Dict]
            }
        """
        # ========== Stage 1: 初始攻击 ==========
        self._log(f"\n{'='*70}")
        self._log(f"[STAGE 1: Initial Attack]")
        self._log(f"{'='*70}\n")

        result_stage1 = self._execute_stage1_single_point(task_description, target_request, credentials)

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

        result_stage2 = self._execute_stage2_single_point(
            task_description=task_description,
            target_request=target_request,
            credentials=credentials,
            stage1_context=result_stage1
        )

        return result_stage2

    def _execute_stage1_single_point(self, task_description: str,
                                     target_request: Dict[str, Any],
                                     credentials: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行Stage 1初始攻击（单点分析）

        Returns:
            Stage 1结果字典（包含test_results和llm_analysis用于反思）
        """
        self._log(f"\n{'='*70}")
        self._log(f"[BusinessLogic] New Test Started (Single-Point)")
        self._log(f"{'='*70}")
        self._log(f"[BusinessLogic] Testing single-point task:")
        self._log(f"  Description: {task_description}")
        self._log(f"  Request: {target_request.get('method')} {target_request.get('url')}")
        self._log(f"\n[Received from Planning Agent]:")
        self._log(f"  Target Request:")
        self._log(f"    Method: {target_request.get('method')}")
        self._log(f"    URL: {target_request.get('url')}")
        self._log(f"    Headers: {json.dumps(target_request.get('headers', {}), indent=6)}")
        self._log(f"    Body: {target_request.get('body', 'None')}")
        self._log(f"    Response Status: {target_request.get('response_status', 'N/A')}")
        original_response = str(target_request.get('response_body', ''))
        extracted_response = extract_useful_response(original_response, max_length=2000)
        self._log(f"    Response Body (preview): {extracted_response}")
        self._log(f"  Credentials: {json.dumps(credentials, indent=6, default=str)}")
        self._log(f"")

        # 步骤1: 调用LLM生成测试命令
        test_commands, llm_analysis = self._generate_test_commands(  # ✅ 获取LLM分析输出
            task_description,
            target_request,
            credentials
        )

        if not test_commands:
            return {
                "vulnerable": False,
                "stage": 1,  # ✅ 添加stage标记
                "commands_executed": 0,
                "analysis": "Failed to generate test commands",
                "test_results": [],
                "llm_analysis": llm_analysis,  # ✅ 保存LLM分析
                "note": "No test commands generated"
            }

        self._log(f"[Generated {len(test_commands)} Test Commands]:")
        for i, cmd in enumerate(test_commands, 1):
            self._log(f"  {i}. {cmd}")
        self._log(f"")

        # 步骤2: 执行测试命令
        execution_results = []
        for i, cmd in enumerate(test_commands, 1):
            self._log(f"[Executing Test {i}/{len(test_commands)}]:")
            self._log(f"  Base command: {cmd}")

            # 追加凭证
            from attack_agent.request_utils import append_credentials_to_curl
            full_cmd = append_credentials_to_curl(cmd, credentials)

            self._log(f"  Full command: {full_cmd}")

            result = self._execute_curl_command(full_cmd)
            raw_response = result.get('body', '')
            extracted_response = extract_useful_response(raw_response, max_length=2000)

            # 显示curl退出码和HTTP状态码
            self._log(f"  ✓ Executed (curl_exit_code: {result.get('curl_exit_code', 'N/A')})")
            http_status = result.get("status", 0)
            if http_status > 0:
                self._log(f"  HTTP Status: {http_status}")
            self._log(f"  Response length: {len(raw_response)} bytes")
            self._log(f"  Response (extracted):\n{extracted_response}")  # ✅ 打印提取后的
            if 'error' in result:
                self._log(f"  Error: {result['error']}")
            if 'stderr' in result and result['stderr']:
                self._log(f"  Stderr: {result['stderr']}")
            self._log(f"")

            # ✅ 保存提取后的响应
            execution_results.append({
                "command": full_cmd,
                "status": result.get("status", 0),
                "body": extracted_response  # ✅ 保存提取后的
            })

        # 步骤3: 调用LLM研判
        judgment = self._judge_vulnerability(
            task_description,
            target_request,
            execution_results
        )

        vulnerable = judgment.get("vulnerable", False)

        self._log(f"{'='*70}")
        self._log(f"[BusinessLogic Test Summary]")
        self._log(f"  Commands Executed: {len(test_commands)}")
        self._log(f"  Result: {'VULNERABLE' if vulnerable else 'SAFE'}")
        self._log(f"{'='*70}\n")

        return {
            "vulnerable": vulnerable,
            "stage": 1,  # ✅ 标记为Stage 1
            "commands_executed": len(test_commands),
            "analysis": judgment.get("analysis", ""),
            "test_results": execution_results,
            "test_commands": test_commands,  # ✅ 保存用于反思
            "llm_analysis": llm_analysis,  # ✅ 保存LLM分析输出
            "note": f"Stage 1 - Immediate detection: {'Vulnerability confirmed' if vulnerable else 'Safe'}"
        }    # ========== Stage 2: 反思攻击方法（单点分析）==========

    def _execute_stage2_single_point(self, task_description: str,
                                     target_request: Dict[str, Any],
                                     credentials: Dict[str, Any],
                                     stage1_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行Stage 2反思攻击（单点分析）

        特点：完全重新设计测试命令（不限于{PAYLOAD}占位符）
        """
        # 1. 构建反思suffix
        self._log(f"[Reflection] Building reflection analysis...")
        reflection_suffix = self._build_reflection_suffix_single_point(stage1_context)

        # 2. 调用LLM生成新测试命令
        self._log(f"[Step 1: Generating Reflection Commands via LLM]")
        new_commands, llm_reflection_output = self._generate_test_commands_with_reflection(
            task_description=task_description,
            target_request=target_request,
            credentials=credentials,
            reflection_suffix=reflection_suffix
        )

        if not new_commands:
            self._log(f"[Reflection] LLM did not generate new commands, returning Stage 1 result")
            stage1_context["reflection_attempted"] = True
            stage1_context["reflection_note"] = "No new commands generated"
            return stage1_context

        self._log(f"[LLM Generated {len(new_commands)} new command(s)]:")
        for i, cmd in enumerate(new_commands, 1):
            self._log(f"  {i}. {cmd}")
        self._log(f"")

        # 3. 执行新测试命令
        self._log(f"[Step 2: Executing Reflection Tests]")
        execution_results = []

        for i, cmd in enumerate(new_commands, 1):
            self._log(f"[Executing Test {i}/{len(new_commands)}]:")
            self._log(f"  Base command: {cmd}")

            # 追加凭证
            from attack_agent.request_utils import append_credentials_to_curl
            full_cmd = append_credentials_to_curl(cmd, credentials)

            self._log(f"  Full command: {full_cmd}")

            result = self._execute_curl_command(full_cmd)
            raw_response = result.get('body', '')
            extracted_response = extract_useful_response(raw_response, max_length=2000)

            # 显示curl退出码和HTTP状态码
            self._log(f"  ✓ Executed (curl_exit_code: {result.get('curl_exit_code', 'N/A')})")
            http_status = result.get("status", 0)
            if http_status > 0:
                self._log(f"  HTTP Status: {http_status}")
            self._log(f"  Response length: {len(raw_response)} bytes")
            self._log(f"  Response (extracted):\n{extracted_response}")  # ✅ 打印提取后的
            if 'error' in result:
                self._log(f"  Error: {result['error']}")
            if 'stderr' in result and result['stderr']:
                self._log(f"  Stderr: {result['stderr']}")
            self._log(f"")

            # ✅ 保存提取后的响应
            execution_results.append({
                "command": full_cmd,
                "status": result.get("status", 0),
                "body": extracted_response  # ✅ 保存提取后的
            })

        # 4. 调用LLM研判
        judgment = self._judge_vulnerability(
            task_description,
            target_request,
            execution_results
        )

        vulnerable = judgment.get("vulnerable", False)

        self._log(f"{'='*70}")
        self._log(f"[BusinessLogic Test Summary - Stage 2]")
        self._log(f"  Commands Executed: {len(new_commands)}")
        if vulnerable:
            self._log(f"  Result: VULNERABLE (detected in Stage 2)")
        else:
            self._log(f"  Result: SAFE")
        self._log(f"{'='*70}\n")

        return {
            "vulnerable": vulnerable,
            "stage": 2,
            "commands_executed": len(new_commands),
            "analysis": judgment.get("analysis", ""),
            "test_results": execution_results,
            "test_commands": new_commands,
            "llm_reflection_output": llm_reflection_output,
            "reflection_analysis": reflection_suffix,
            # ✅ 新增：保留Stage 1的完整结果
            "stage1_results": {
                "test_results": stage1_context.get("test_results", []),
                "test_commands": stage1_context.get("test_commands", []),
                "commands_executed": stage1_context.get("commands_executed", 0),
                "llm_analysis": stage1_context.get("llm_analysis", "")
            },
            "note": f"Stage 2 - Reflection attack: {'Vulnerability confirmed' if vulnerable else 'Safe'}"
        }

    def _build_reflection_suffix_single_point(self, stage1_context: Dict[str, Any]) -> str:
        """
        构建单点分析的反思suffix

        特点：不提{PAYLOAD}占位符，完全重新设计命令
        """
        test_commands = stage1_context.get("test_commands", [])
        test_results = stage1_context.get("test_results", [])
        vulnerable = stage1_context.get("vulnerable")

        suffix = "\n\n"
        suffix += "="*70 + "\n"
        suffix += "STAGE 1 RESULTS (Failed Detection)\n"
        suffix += "="*70 + "\n\n"

        # 1. 之前生成的命令
        suffix += "Previous Test Commands Generated:\n"
        for i, cmd in enumerate(test_commands, 1):
            suffix += f"{i}. {cmd}\n"
        suffix += "\n"

        # 2. 执行结果
        suffix += "Execution Results:\n"
        suffix += "-"*70 + "\n"

        # 去重 + 采样（最多10个）
        sampled = self._sample_test_results(test_results, max_samples=10)

        for i, result in enumerate(sampled, 1):
            suffix += f"\nTest {i}:\n"
            suffix += f"  Command: {result.get('command', 'N/A')}\n"
            suffix += f"  HTTP Status: {result.get('status', 'N/A')}\n"

            # ✅ 使用智能提取
            response = result.get('body', '')
            if response:
                suffix += f"  Response (extracted):\n{response}\n" 

        suffix += "\n"

        # 3. 结果说明
        suffix += f"Result: {'NOT VULNERABLE' if vulnerable is False else 'UNCERTAIN'}\n"
        suffix += "\n"

        # 4. 反思任务说明
        suffix += "="*70 + "\n"
        suffix += "YOUR TASK FOR STAGE 2 - REFLECTION\n"
        suffix += "="*70 + "\n\n"

        suffix += """Based on the above failed business logic test attempt, please:

1. **Analyze Why Stage 1 Failed**:
   - Was the business logic hypothesis correct?
   - Did responses show proper validation?
   - Were there error messages indicating protection mechanisms?
   - Did we test the right parameters/scenarios?
   - Were the test values appropriate for bypassing validation?

2. **Design NEW Testing Strategy**:
   - Try DIFFERENT business scenarios (different parameter combinations)
   - Adjust test values based on error messages
   - Consider alternative attack vectors
   - Think about edge cases not tested in Stage 1

3. **Generate NEW Test Commands** (Complete curl commands):
   - Generate complete curl commands (NOT templates)
   - You can completely redesign the commands (change both WHERE and WHAT)
   - Try different parameter combinations
   - Test different boundary values
   - Use alternative business logic bypasses
   - Generate 5-10 new test commands

IMPORTANT:
- Generate COMPLETE curl commands (not templates with placeholders)
- Be creative - try completely different approaches
- Focus on business logic bypasses specific to this endpoint
- Consider the application's business rules and constraints

Output Format (same as Stage 1):

Analysis:
<Your failure analysis and new strategy explanation>

Test_Commands:
<complete curl command 1>
<complete curl command 2>
<complete curl command 3>
...
"""

        return suffix

    def _generate_test_commands_with_reflection(self, task_description: str,
                                                target_request: Dict[str, Any],
                                                credentials: Dict[str, Any],
                                                reflection_suffix: str) -> tuple:
        """
        调用LLM生成反思后的新测试命令
        """
        # 格式化凭证信息
        from attack_agent.request_utils import format_credentials_for_display
        credentials_info = format_credentials_for_display(credentials)

        # 构造prompt（和Stage 1相同的格式）
        original_response = str(target_request.get("response_body", ""))
        extracted_response = extract_useful_response(original_response, max_length=2000)
        prompt = self._analysis_prompt.format(
            task_description=task_description,
            method=target_request.get("method", "GET"),
            url=target_request.get("url", ""),
            headers=json.dumps(target_request.get("headers", {}), indent=2),
            body=json.dumps(target_request.get("body", {}), indent=2) if target_request.get("body") else "None",
            response_status=target_request.get("response_status", "N/A"),
            response_body=extracted_response,  # 使用智能提取后的
            credentials_info=credentials_info
        )

        # ✅ Append反思内容
        prompt += reflection_suffix

        self._log(f"\n[LLM INPUT - Reflection Prompt]:")
        self._log(f"{'~'*70}")
        self._log(f"{prompt}")
        self._log(f"{'~'*70}\n")

        try:
            completion = self.client.chat.completions.create(
                model=get_model_name("attack_agent"),
                messages=[
                    {"role": "system", "content": "You are a security testing expert."},
                    {"role": "user", "content": prompt}
                ],
                temperature=get_temperature("attack_agent")
            )

            llm_output = completion.choices[0].message.content

            self._log(f"[LLM OUTPUT - Reflection Response]:")
            self._log(f"{'~'*70}")
            self._log(f"{llm_output}")
            self._log(f"{'~'*70}\n")

            # 解析Test_Commands部分
            commands = self._parse_test_commands(llm_output)
            return commands, llm_output

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
            resp = r.get("body", "")
            key = resp if resp else "empty"
            if key not in seen:
                seen[key] = r

        deduped = list(seen.values())

        # 采样
        if len(deduped) <= max_samples:
            return deduped
        else:
            import random
            return random.sample(deduped, max_samples)
