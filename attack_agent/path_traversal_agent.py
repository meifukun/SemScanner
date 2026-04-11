"""
Path Traversal Agent -
：
1.  Deep-Travelsal.txt  + 6 = 5000+ payloads
2.
3.  + 15 + LLM
4. 15
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
    Agent（）

    Workflow:
    1. LLM，
    2. LLM generates curl command templates with {PAYLOAD} placeholder
    3. payload（~5000）
    4. ，
    5.  + 15
    6. LLM
    """

    TARGET_FILES = [
        "etc/hosts",
        "Windows/System32/drivers/etc/hosts",
        ".env"
    ]

    def __init__(self, client,
                 attack_prompt_path: str = "prompt/path_traversal_attack.txt",
                 judge_prompt_path: str = "prompt/path_traversal_judge.txt",
                 log_dir: str = "output/attack_logs/path_traversal",
                 template_file: str = "attack_agent/Deep-Travelsal.txt",
                 request_delay: float = 0.4):
        self.client = client
        self.attack_prompt_path = Path(attack_prompt_path)
        self.judge_prompt_path = Path(judge_prompt_path)
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._log_path = self.log_dir / "path_traversal_agent.log"
        self.request_delay = request_delay

        self.template_file = Path(template_file)
        self.payload_templates = self._load_payload_templates()

        self.all_payloads = self._generate_payloads()

        self._log_all_payloads()

    def _log(self, *args):
        msg = " ".join(str(a) for a in args)
        try:
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(msg + "\n")
        except Exception:
            pass

    def _load_prompt_template(self, path: Path) -> str:
        """prompt"""
        return path.read_text(encoding="utf-8")

    def _load_payload_templates(self) -> List[str]:
        """
        🆕  Deep-Travelsal.txt payload

        Returns:
            （，{FILE}）
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
        🆕 payload（ × ）

        Returns:
            payload（~5000）
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
        🆕 payload（）

        ：
        -
        - payload
        -
        """
        self._log(f"\n{'='*70}")
        self._log(f"[Payload List] All Path Traversal Payloads (Total: {len(self.all_payloads)})")
        self._log(f"{'='*70}")

        for target_file in self.TARGET_FILES:
            file_payloads = [p for p in self.all_payloads if target_file in p]

            self._log(f"\n[Target File: {target_file}] ({len(file_payloads)} payloads)")
            self._log(f"-" * 70)

            if len(file_payloads) <= 20:
                for i, payload in enumerate(file_payloads, 1):
                    self._log(f"  {i:4d}. {payload}")
            else:
                for i, payload in enumerate(file_payloads[:10], 1):
                    self._log(f"  {i:4d}. {payload}")

                self._log(f"  ... ( {len(file_payloads) - 20} payload)")

                for i, payload in enumerate(file_payloads[-10:], len(file_payloads) - 9):
                    self._log(f"  {i:4d}. {payload}")

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
        🆕 （）

        ：
        - Linux/Unix
        - Windows
        -
        -
        -
        """
        patterns = [
            r"root:x:\d+:\d+",                      # /etc/passwd
            r"root:\$\d+\$",                        # /etc/shadow
            r"127\.0\.0\.1\s+localhost",            # /etc/hosts
            r"PATH=/usr/local",                     # environ
            r"HOME=/root",                          # environ

            r"\[fonts\]",                           # win.ini
            r"\[extensions\]",                      # win.ini
            r"\[MCI Extensions\]",                  # win.ini

            r"DB_PASSWORD\s*=",                     # .env
            r"API_KEY\s*=",                         # .env
            r"SECRET_KEY\s*=",                      # .env
            r"DATABASE_URL\s*=",                    # .env

            r"<\?php",
            r"import\s+os",
            r"const\s+\w+\s*=\s*require",

            r"password\s*[:=]\s*['\"]?\w+",
            r"secret\s*[:=]\s*['\"]?\w+",
        ]

        for pattern in patterns:
            if re.search(pattern, response, re.IGNORECASE):
                return True

        return False

    def _hash_response(self, response: str) -> str:
        """
        🆕 （）

        Returns:
            MD5
        """
        return hashlib.md5(response.encode('utf-8', errors='ignore')).hexdigest()

    def test(self, request: Dict[str, Any], credentials: Dict[str, Any]) -> Dict[str, Any]:
        """
        🆕 （）

        ：
        1. payload（~5000）
        2.
        3.  + 15
        4. LLM（）

        Args:
            request: full request data (including response)
            credentials: account credentials

        Returns:
            {
                "vulnerable": True/False,
                "payloads_tested": int,
                "sensitive_found": bool,
                "sampled_results": List[Dict],  # 15
                "analysis": str  # LLM
            }
        """
        method = request.get("method", "GET")
        url = request.get("url", "")

        self._log(f"\n{'='*70}")
        self._log(f"[PathTraversal] New Test Started")
        self._log(f"{'='*70}")
        self._log(f"[PathTraversal] Testing: {method} {url}")

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

        payloads = self.all_payloads
        self._log(f"\n[Step 2: Using Pre-generated {len(payloads)} Path Traversal Payloads]")

        self._log(f"\n[Step 3: Executing Tests with Early Stopping]")

        all_results = []
        sensitive_results = []
        response_groups = {}
        payloads_tested = 0
        stopped_early = False

        for template in curl_templates:
            if stopped_early:
                break

            self._log(f"\n[Testing Template]: {template}")

            for payload in payloads:
                if stopped_early:
                    break

                if '{PAYLOAD}' not in template:
                    continue

                final_command = template.replace('{PAYLOAD}', payload)
                final_command = append_credentials_to_curl(final_command, credentials)

                try:
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

                    from attack_agent.request_utils import parse_http_status_from_response
                    http_status, response_body = parse_http_status_from_response(stdout)

                    self._log(f"  ✓ Executed (curl_exit_code: {process.returncode})")
                    if http_status is not None:
                        self._log(f"  HTTP Status: {http_status}")
                    self._log(f"  Response length: {len(response_body)} bytes")
                    self._log(f"  Response: {response_body}")
                    if stderr:
                        self._log(f"  Stderr: {stderr}")

                    response_hash = self._hash_response(response_body)

                    is_sensitive = self._contains_sensitive_content(response_body)

                    result = {
                        "payload": payload,
                        "command": final_command,
                        "response": response_body,
                        "response_hash": response_hash,
                        "is_sensitive": is_sensitive
                    }

                    all_results.append(result)

                    if response_hash not in response_groups:
                        response_groups[response_hash] = []
                    response_groups[response_hash].append(result)

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

        self._log(f"\n[Step 4: Sampling Up to 15 Unique Responses for LLM Analysis]")

        sampled_results = self._sample_responses(
            response_groups=response_groups,
            sensitive_results=sensitive_results,
            max_samples=15
        )

        self._log(f"  Sampled: {len(sampled_results)} unique responses")
        self._log(f"  (Including {len(sensitive_results)} sensitive result(s))")

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
        🆕 15

        Strategy:
        1.
        2.
        3. 15

        Args:
            response_groups:
            sensitive_results:
            max_samples:

        Returns:

        """
        sampled = []

        sensitive_hashes = set()
        for result in sensitive_results:
            if len(sampled) >= max_samples:
                break
            sampled.append(result)
            sensitive_hashes.add(result["response_hash"])

        self._log(f"  [Sampling] Added {len(sensitive_results)} sensitive result(s)")

        other_hashes = [h for h in response_groups.keys() if h not in sensitive_hashes]
        random.shuffle(other_hashes)

        for response_hash in other_hashes:
            if len(sampled) >= max_samples:
                break

            group = response_groups[response_hash]
            sampled.append(random.choice(group))

        self._log(f"  [Sampling] Added {len(sampled) - len(sensitive_results)} other unique response(s)")
        self._log(f"  [Sampling] Total sampled: {len(sampled)}")

        return sampled

    def _generate_curl_templates(self, request: Dict[str, Any]) -> List[str]:
        """
        Call LLM to generate curl templates with {PAYLOAD} placeholder

        Returns:
            Returns list of curl templates（{PAYLOAD}）
        """
        sys_prompt = self._load_prompt_template(self.attack_prompt_path)

        user_prompt = f"""REQUEST INFORMATION:
Method: {request.get('method', 'GET')}
URL: {request.get('url', '')}
Headers: {json.dumps(request.get('headers', {}), indent=2)}
Body: {json.dumps(request.get('body'), indent=2) if request.get('body') else 'None'}
Response Status: {request.get('response_status', 'N/A')}
Response Body (preview): {str(request.get('response_body', ''))}

Please analyze this request and generate curl command templates with {{PAYLOAD}} placeholder for path traversal testing."""

        try:
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

            templates = self._parse_curl_templates(llm_output)

            return templates

        except Exception as e:
            self._log(f"[Error] LLM call failed: {e}")
            return []

    def _parse_curl_templates(self, llm_output: str) -> List[str]:
        """LLMcurl"""
        templates = []

        lines = llm_output.split('\n')
        in_commands_section = False

        for line in lines:
            line = line.strip()

            if 'Commands:' in line or 'commands:' in line.lower():
                in_commands_section = True
                continue

            if in_commands_section:
                if line.startswith('curl'):
                    templates.append(line)
                elif line.startswith('-'):
                    if 'curl' in line:
                        curl_part = line.split('curl', 1)[1] if 'curl' in line else ''
                        if curl_part:
                            templates.append('curl' + curl_part)

        return templates

    def _judge_vulnerability(self, sampled_results: List[Dict]) -> Dict[str, Any]:
        """
        🆕 LLM（）

        Args:
            sampled_results: （15）

        Returns:
            {
                "vulnerable": True/False,
                "analysis": str
            }
        """
        judge_prompt = self._load_prompt_template(self.judge_prompt_path)

        test_results_text = []
        for idx, result in enumerate(sampled_results, 1):
            sensitive_tag = " [SENSITIVE]" if result.get("is_sensitive") else ""

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
