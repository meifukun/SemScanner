"""
Business Logic Agent - ()
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
    Agent -
    
    1. AttackTask(+)
    2. /
    3. curl
    4. LLM
    
    :(IDOR, )
    """
    
    def __init__(self, client, log_dir: str = "output/attack_logs/business_logic",
                 reflection_enabled: bool = True):
        self.client = client
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._log_path = self.log_dir / "business_logic_agent.log"
        self.reflection_enabled = reflection_enabled

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
        return Path("prompt/business_logic_attack.txt").read_text(encoding="utf-8")
    
    def _load_judgment_prompt(self) -> str:
        return Path("prompt/business_logic_judge.txt").read_text(encoding="utf-8")
    

    def _generate_test_commands(self, task_description: str,
                                target_request: Dict[str, Any],
                                credentials: Dict[str, Any]) -> tuple:
        """
        LLM

        Returns:
            (, LLM)
        """
        from attack_agent.request_utils import format_credentials_for_display
        credentials_info = format_credentials_for_display(credentials)

        original_response = str(target_request.get("response_body", ""))
        extracted_response = extract_useful_response(original_response, max_length=2000)
        prompt = self._analysis_prompt.format(
            task_description=task_description,
            method=target_request.get("method", "GET"),
            url=target_request.get("url", ""),
            headers=json.dumps(target_request.get("headers", {}), indent=2),
            body=json.dumps(target_request.get("body", {}), indent=2) if target_request.get("body") else "None",
            response_status=target_request.get("response_status", "N/A"),
            response_body=extracted_response,
            credentials_info=credentials_info
        )

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

            self._log(f"[LLM OUTPUT - Analysis Response]:")
            self._log(f"{'~'*70}")
            self._log(f"{llm_output}")
            self._log(f"{'~'*70}\n")

            commands = self._parse_test_commands(llm_output)

            self._log(f"[Parsed {len(commands)} Commands]:")
            for i, cmd in enumerate(commands, 1):
                self._log(f"  {i}. {cmd}")
            self._log(f"")

            return commands, llm_output

        except Exception as e:
            self._log(f"[BusinessLogic] LLM call failed: {e}")
            import traceback
            self._log(f"[BusinessLogic] Traceback:")
            self._log(traceback.format_exc())
            return [], ""

    def _parse_test_commands(self, llm_output: str) -> List[str]:
        """
        LLM

        :
        - Test_Commands:
        - **Test_Commands:**
        - **Test_Commands:**
          ```bash
          curl ...
          ```

        Returns:
            curl
        """
        lines = llm_output.splitlines()
        start_idx = -1

        for i, line in enumerate(lines):
            if re.search(r'\*{0,2}\s*Test_Commands\s*:\s*\*{0,2}', line, re.IGNORECASE):
                start_idx = i
                break

        if start_idx == -1:
            self._log("[Warning] No Test_Commands section found in LLM output")
            return []

        commands = []
        in_code_block = False

        for line in lines[start_idx + 1:]:
            line = line.strip()

            if not line:
                if commands:
                    continue
                else:
                    continue

            if line.startswith('```'):
                in_code_block = not in_code_block
                continue

            if line.startswith('curl'):
                commands.append(line)
            elif re.match(r'^[A-Z][a-z]+\s*:', line) or re.match(r'^\*\*[A-Z][a-z]+\s*:\*\*', line):
                break

        if not commands:
            self._log("[Warning] No curl commands found in Test_Commands section")
        else:
            self._log(f"[Info] Extracted {len(commands)} test commands")

        return commands
    
    def _execute_curl_command(self, curl_cmd: str) -> Dict[str, Any]:
        """
        curl

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

            stdout, stderr = process.communicate(timeout=30)

            from attack_agent.request_utils import parse_http_status_from_response
            http_status, response_body = parse_http_status_from_response(stdout)

            return {
                "status": http_status if http_status is not None else 0,
                "body": response_body,
                "stderr": stderr,
                "curl_exit_code": process.returncode
            }

        except subprocess.TimeoutExpired:
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
        """curl -i"""
        match = re.search(r'HTTP/\d\.\d\s+(\d{3})', curl_output)
        return int(match.group(1)) if match else 0
    
    def _judge_vulnerability(self, task_description: str,
                             target_request: Dict[str, Any],
                            execution_results: List[Dict]) -> Dict[str, Any]:
        """
        LLM

        Returns:
            {vulnerable: bool, analysis: str}
        """

        results_text = ""
        for i, result in enumerate(execution_results, 1):
            results_text += f"\nTest {i}:\n"
            results_text += f"Command: {result['command']}\n"
            results_text += f"Status: {result['status']}\n"
            response_extracted = extract_useful_response(result['body'], max_length=2000)
            results_text += f"Response (extracted):\n{response_extracted}\n"
            results_text += "-" * 40 + "\n"
        
        original_response = str(target_request.get("response_body", ""))
        baseline_extracted = extract_useful_response(original_response, max_length=2000)

        baseline_body = (
            json.dumps(target_request.get("body", {}), indent=2)
            if target_request.get("body") is not None
            else "None"
        )

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
    
    def _parse_vulnerability_conclusion(self, llm_output: str) -> bool:
        """
        LLM
        
        - "No vulnerability exists" -> False
        -  -> True
        """
        match = re.search(r'Result:\s*\n(.+)', llm_output, re.DOTALL)
        
        if not match:
            if "No vulnerability exists" in llm_output:
                return False
            elif "vulnerability" in llm_output.lower() and any(
                keyword in llm_output.lower() 
                for keyword in ["found", "exists", "successful", "accepted", "bypassed"]
            ):
                return True
            return False
        
        result_text = match.group(1).strip()
        
        if "No vulnerability exists" in result_text:
            return False
        
        if result_text and not result_text.startswith("No"):
            return True
        
        return False


    def test_single_point(self, task_description: str,
                        target_request: Dict[str, Any],
                        credentials: Dict[str, Any]) -> Dict[str, Any]:
        """

        Two-stage test flow:
        - Stage 1: initial attack (original prompt)
        - Stage 2: reflection attack (if Stage 1 fails)

        Args:
            task_description:
            target_request:
            credentials: account credentials

        Returns:
            {
                "vulnerable": True/False/None,
                "stage": 1 or 2,
                "commands_executed": int,
                "analysis": str,
                "test_results": List[Dict]
            }
        """
        self._log(f"\n{'='*70}")
        self._log(f"[STAGE 1: Initial Attack]")
        self._log(f"{'='*70}\n")

        result_stage1 = self._execute_stage1_single_point(task_description, target_request, credentials)

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
        Execute Stage 1 initial attack()

        Returns:
            Stage 1 result dict (includes test_results and llm_analysis for reflection)
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

        test_commands, llm_analysis = self._generate_test_commands(
            task_description,
            target_request,
            credentials
        )

        if not test_commands:
            return {
                "vulnerable": False,
                "stage": 1,
                "commands_executed": 0,
                "analysis": "Failed to generate test commands",
                "test_results": [],
                "llm_analysis": llm_analysis,
                "note": "No test commands generated"
            }

        self._log(f"[Generated {len(test_commands)} Test Commands]:")
        for i, cmd in enumerate(test_commands, 1):
            self._log(f"  {i}. {cmd}")
        self._log(f"")

        execution_results = []
        for i, cmd in enumerate(test_commands, 1):
            self._log(f"[Executing Test {i}/{len(test_commands)}]:")
            self._log(f"  Base command: {cmd}")

            from attack_agent.request_utils import append_credentials_to_curl
            full_cmd = append_credentials_to_curl(cmd, credentials)

            self._log(f"  Full command: {full_cmd}")

            result = self._execute_curl_command(full_cmd)
            raw_response = result.get('body', '')
            extracted_response = extract_useful_response(raw_response, max_length=2000)

            self._log(f"  ✓ Executed (curl_exit_code: {result.get('curl_exit_code', 'N/A')})")
            http_status = result.get("status", 0)
            if http_status > 0:
                self._log(f"  HTTP Status: {http_status}")
            self._log(f"  Response length: {len(raw_response)} bytes")
            self._log(f"  Response (extracted):\n{extracted_response}")
            if 'error' in result:
                self._log(f"  Error: {result['error']}")
            if 'stderr' in result and result['stderr']:
                self._log(f"  Stderr: {result['stderr']}")
            self._log(f"")

            execution_results.append({
                "command": full_cmd,
                "status": result.get("status", 0),
                "body": extracted_response
            })

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
            "stage": 1,
            "commands_executed": len(test_commands),
            "analysis": judgment.get("analysis", ""),
            "test_results": execution_results,
            "test_commands": test_commands,
            "llm_analysis": llm_analysis,
            "note": f"Stage 1 - Immediate detection: {'Vulnerability confirmed' if vulnerable else 'Safe'}"
        }

    def _execute_stage2_single_point(self, task_description: str,
                                     target_request: Dict[str, Any],
                                     credentials: Dict[str, Any],
                                     stage1_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Stage 2()

        :({PAYLOAD})
        """
        self._log(f"[Reflection] Building reflection analysis...")
        reflection_suffix = self._build_reflection_suffix_single_point(stage1_context)

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

        self._log(f"[Step 2: Executing Reflection Tests]")
        execution_results = []

        for i, cmd in enumerate(new_commands, 1):
            self._log(f"[Executing Test {i}/{len(new_commands)}]:")
            self._log(f"  Base command: {cmd}")

            from attack_agent.request_utils import append_credentials_to_curl
            full_cmd = append_credentials_to_curl(cmd, credentials)

            self._log(f"  Full command: {full_cmd}")

            result = self._execute_curl_command(full_cmd)
            raw_response = result.get('body', '')
            extracted_response = extract_useful_response(raw_response, max_length=2000)

            self._log(f"  ✓ Executed (curl_exit_code: {result.get('curl_exit_code', 'N/A')})")
            http_status = result.get("status", 0)
            if http_status > 0:
                self._log(f"  HTTP Status: {http_status}")
            self._log(f"  Response length: {len(raw_response)} bytes")
            self._log(f"  Response (extracted):\n{extracted_response}")
            if 'error' in result:
                self._log(f"  Error: {result['error']}")
            if 'stderr' in result and result['stderr']:
                self._log(f"  Stderr: {result['stderr']}")
            self._log(f"")

            execution_results.append({
                "command": full_cmd,
                "status": result.get("status", 0),
                "body": extracted_response
            })

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
        suffix

        :{PAYLOAD}, 
        """
        test_commands = stage1_context.get("test_commands", [])
        test_results = stage1_context.get("test_results", [])
        vulnerable = stage1_context.get("vulnerable")

        suffix = "\n\n"
        suffix += "="*70 + "\n"
        suffix += "STAGE 1 RESULTS (Failed Detection)\n"
        suffix += "="*70 + "\n\n"

        suffix += "Previous Test Commands Generated:\n"
        for i, cmd in enumerate(test_commands, 1):
            suffix += f"{i}. {cmd}\n"
        suffix += "\n"

        suffix += "Execution Results:\n"
        suffix += "-"*70 + "\n"

        sampled = self._sample_test_results(test_results, max_samples=10)

        for i, result in enumerate(sampled, 1):
            suffix += f"\nTest {i}:\n"
            suffix += f"  Command: {result.get('command', 'N/A')}\n"
            suffix += f"  HTTP Status: {result.get('status', 'N/A')}\n"

            response = result.get('body', '')
            if response:
                suffix += f"  Response (extracted):\n{response}\n" 

        suffix += "\n"

        suffix += f"Result: {'NOT VULNERABLE' if vulnerable is False else 'UNCERTAIN'}\n"
        suffix += "\n"

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
        LLM
        """
        from attack_agent.request_utils import format_credentials_for_display
        credentials_info = format_credentials_for_display(credentials)

        original_response = str(target_request.get("response_body", ""))
        extracted_response = extract_useful_response(original_response, max_length=2000)
        prompt = self._analysis_prompt.format(
            task_description=task_description,
            method=target_request.get("method", "GET"),
            url=target_request.get("url", ""),
            headers=json.dumps(target_request.get("headers", {}), indent=2),
            body=json.dumps(target_request.get("body", {}), indent=2) if target_request.get("body") else "None",
            response_status=target_request.get("response_status", "N/A"),
            response_body=extracted_response,
            credentials_info=credentials_info
        )

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

            commands = self._parse_test_commands(llm_output)
            return commands, llm_output

        except Exception as e:
            self._log(f"[Reflection] LLM call failed: {e}")
            import traceback
            self._log(traceback.format_exc())
            return [], ""

    def _sample_test_results(self, test_results: List[Dict], max_samples: int = 10) -> List[Dict]:
        """
        """
        if not test_results:
            return []

        seen = {}
        for r in test_results:
            resp = r.get("body", "")
            key = resp if resp else "empty"
            if key not in seen:
                seen[key] = r

        deduped = list(seen.values())

        if len(deduped) <= max_samples:
            return deduped
        else:
            import random
            return random.sample(deduped, max_samples)
