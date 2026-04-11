"""
SSRF Agent - （LLM）
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
    SSRFAgent（）

    Workflow:
    1. LLM，SSRF
    2. LLM generates curl command templates with {PAYLOAD} placeholder
    3. token（beacon）
    4. SSRF payload（beacon URL + token）
    5. payload{PAYLOAD}
    6. token
    7. beacon
    """

    def __init__(self, client,
                 prompt_path: str = "prompt/ssrf_attack.txt",
                 beacon_base: str = "http://172.17.0.1:9091/",
                 log_dir: str = "output/attack_logs/ssrf",
                 reflection_enabled: bool = True):
        self.client = client
        self.prompt_path = Path(prompt_path)
        self.beacon_base = beacon_base.rstrip("/") + "/"
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._log_path = self.log_dir / "ssrf_agent.log"
        self.reflection_enabled = reflection_enabled

        self.execution_records: Dict[str, Dict[str, Any]] = {}  # {token: {url, payloads, ...}}

    def _log(self, *args):
        msg = " ".join(str(a) for a in args)
        try:
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(msg + "\n")
        except Exception:
            pass

    def _load_prompt_template(self) -> str:
        """SSRF prompt"""
        return self.prompt_path.read_text(encoding="utf-8")

    def _generate_token(self, length: int = 12) -> str:
        """token"""
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))

    def test(self, request: Dict[str, Any], credentials: Dict[str, Any]) -> Dict[str, Any]:
        """
        SSRF（）

        Two-stage test flow:
        - Stage 1: initial attack (original prompt)
        - Stage 2: reflection attack (if Stage 1 fails)

        Args:
            request: full request data (including response)
            credentials: account credentials

        Returns:
            {
                "vulnerable": True/False/None,
                "stage": 1 or 2,  # /
                "token": str,
                "beacon_url": str,
                "curl_templates": List[str],
                "commands_executed": List[str],
                ...
            }
        """
        self._log(f"\n{'='*70}")
        self._log(f"[STAGE 1: Initial Attack]")
        self._log(f"{'='*70}\n")

        result_stage1 = self._execute_stage1(request, credentials)

        if result_stage1.get("vulnerable") is True:
            self._log(f"\n[STAGE 1] ✓ VULNERABLE - Skipping Stage 2")
            return result_stage1

        if not self.reflection_enabled:
            self._log(f"\n[Reflection] Disabled - Returning Stage 1 result")
            return result_stage1

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
        Execute Stage 1 initial attack（test）

        Returns:
            {
                "vulnerable": True/False/None,
                "stage": 1,
                "token": str,
                "beacon_url": str,
                "curl_templates": List[str],  # ✅
                "commands_executed": List[str],
                "test_results": List[Dict],  # ✅
                "llm_analysis": str,
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

        self._log(f"[Step 1: Calling LLM to Identify Injection Points]")
        curl_templates, llm_analysis = self._generate_curl_templates(request)

        if not curl_templates:
            self._log(f"[SSRF] No injection points identified by LLM")
            return {
                "vulnerable": False,
                "stage": 1,
                "token": None,
                "beacon_url": None,
                "curl_templates": [],
                "commands_executed": [],
                "test_results": [],
                "llm_analysis": llm_analysis,
                "note": "No injection points found"
            }

        self._log(f"[LLM Generated {len(curl_templates)} curl template(s)]:")
        for i, tmpl in enumerate(curl_templates, 1):
            self._log(f"  {i}. {tmpl}")
        self._log(f"")

        token = self._generate_token()
        beacon_url = f"{self.beacon_base}?data={token}"
        self._log(f"[Step 2: Generated Unified Token]: {token}")
        self._log(f"[Beacon URL]: {beacon_url}")
        self._log(f"")

        ssrf_payloads = self._get_payloads(beacon_url)
        self._log(f"[Step 3: Generated {len(ssrf_payloads)} SSRF Payloads]:")
        for i, payload in enumerate(ssrf_payloads, 1):
            self._log(f"  {i}. {payload}")
        self._log(f"")

        self._log(f"[Step 4: Executing Tests]")
        executed_commands = []
        test_results = []

        for template in curl_templates:
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

        self.execution_records[token] = {
            "token": token,
            "beacon_url": beacon_url,
            "url": url,
            "method": method,
            "curl_templates": curl_templates,
            "commands_executed": executed_commands
        }

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
            "vulnerable": vulnerable if vulnerable else None,
            "stage": 1,
            "beacon_url": beacon_url,
            "token": token,
            "curl_templates": curl_templates,
            "commands_executed": executed_commands,
            "test_results": test_results,
            "llm_analysis": llm_analysis,
            "note": f"Stage 1 - Immediate detection: {'SSRF confirmed' if vulnerable else 'Pending finalize'}"
        }

    def _generate_curl_templates(self, request: Dict[str, Any]) -> tuple:
        """
        Call LLM to generate curl templates with {PAYLOAD} placeholder

        Returns:
            Returns (curl template list, full LLM output) tuple
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

            templates = self._parse_curl_templates(llm_output)

            return templates, llm_output

        except Exception as e:
            self._log(f"[SSRF] LLM call failed: {e}")
            import traceback
            self._log(traceback.format_exc())
            return [], ""

    def _parse_curl_templates(self, llm_output: str) -> List[str]:
        """
        Extract curl templates from LLM output (multi-format compatible)

        Returns:
            Returns list of curl templates
        """
        templates = []
        lines = llm_output.splitlines()

        commands_line_idx = -1
        for i, line in enumerate(lines):
            line_lower = line.lower()
            if 'command:' in line_lower or 'commands:' in line_lower:
                commands_line_idx = i
                break

        if commands_line_idx == -1:
            self._log(f"[Warning] No Commands section found in LLM output")
            return []

        for i in range(commands_line_idx + 1, len(lines)):
            line = lines[i].strip()

            if not line:
                continue

            if line.startswith('```'):
                continue

            if 'curl' in line and '{PAYLOAD}' in line:
                cleaned = line.lstrip('`').rstrip('`').strip()
                templates.append(cleaned)

        if not templates:
            self._log(f"[Warning] No valid curl commands found after Commands section")

        return templates

    def _get_payloads(self, beacon_url: str) -> List[str]:
        """
        SSRF payload

        Args:
            beacon_url: URL（token）

        Returns:
            payload
        """
        from urllib.parse import quote

        encoded_url = quote(beacon_url, safe='')

        return [
            beacon_url,
            # f"https://{beacon_url}",
        ]


    def _execute_stage2(self, request: Dict[str, Any], credentials: Dict[str, Any],
                       stage1_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Stage 2

        ：
        1. （Stage 1）
        2. LLM
        3. （Stage 1）
        4. OOB（）

        Args:
            request:
            credentials:
            stage1_context: Stage 1

        Returns:
            Stage 2
        """
        self._log(f"[Reflection] Building reflection analysis...")
        reflection_suffix = self._build_reflection_suffix(stage1_context)

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

        token = self._generate_token()
        beacon_url = f"{self.beacon_base}?data={token}"
        self._log(f"[Step 2: Generated New Token]: {token}")
        self._log(f"[Beacon URL]: {beacon_url}")
        self._log(f"")

        ssrf_payloads = self._get_payloads(beacon_url)
        self._log(f"[Step 3: Generated {len(ssrf_payloads)} SSRF Payloads]:")
        for i, payload in enumerate(ssrf_payloads, 1):
            self._log(f"  {i}. {payload}")
        self._log(f"")

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
        prompt

        Args:
            stage1_context: Stage 1

        Returns:
            suffix（prompt）
        """
        templates = stage1_context.get("curl_templates", [])
        test_results = stage1_context.get("test_results", [])
        vulnerable = stage1_context.get("vulnerable")

        suffix = "\n\n"
        suffix += "="*70 + "\n"
        suffix += "STAGE 1 RESULTS (Failed Detection)\n"
        suffix += "="*70 + "\n\n"

        suffix += "Previous Templates Generated:\n"
        for i, tmpl in enumerate(templates, 1):
            suffix += f"{i}. {tmpl}\n"
        suffix += "\n"

        suffix += "Execution Results:\n"
        suffix += "-"*70 + "\n"

        sampled = self._sample_test_results(test_results, max_samples=10)

        for i, result in enumerate(sampled, 1):
            suffix += f"\nTest {i}:\n"
            suffix += f"  Command: {result.get('command', 'N/A')}\n" 
            suffix += f"  HTTP Status: {result.get('http_status', 'N/A')}\n"

            response = result.get('response', '')
            if response:
                suffix += f"  Response (extracted):\n{response}\n"

            if result.get('error'):
                suffix += f"  Error: {result['error']}\n"

        suffix += "\n"

        suffix += f"Result: {'NOT VULNERABLE' if vulnerable is False else 'UNCERTAIN/PENDING'}\n"
        suffix += "\n"

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
        LLM

        Strategy:promptappend reflection_suffix

        Args:
            request:
            reflection_suffix:

        Returns:
            (, LLM)
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

Please analyze this request and generate curl command templates with {{PAYLOAD}} placeholder for SSRF testing.
"""

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
        （ + ）

        Args:
            test_results:
            max_samples:

        Returns:

        """
        if not test_results:
            return []

        seen = {}
        for r in test_results:
            resp = r.get("response", "")
            key = resp[:500] if resp else "empty"
            if key not in seen:
                seen[key] = r

        deduped = list(seen.values())

        if len(deduped) <= max_samples:
            return deduped
        else:
            import random
            return random.sample(deduped, max_samples)

    def check_final_results(self) -> Dict[str, bool]:
        """
        Check final results (called after visiting all pages)

        Returns:
            {token: is_vulnerable}
        """
        self._log(f"\n{'='*70}")
        self._log(f"[SSRF] Checking Final Results")
        self._log(f"{'='*70}\n")

        updates = {}

        for token in self.execution_records.keys():
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
