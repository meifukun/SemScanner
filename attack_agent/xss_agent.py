"""
XSS Agent - uses LLM to identify injection points
"""

from typing import Dict, Any, List, Set
from pathlib import Path
import subprocess
import os
import random
import string
import json
import re
import time
from attack_agent.request_utils import (
    append_credentials_to_curl,
    check_beacon_detection,
    kill_process_group_and_collect,
)
import shlex
from config.llm_config import get_model_name, get_temperature
from attack_agent.request_utils import extract_useful_response
from urllib.parse import urljoin, urlsplit, urlunsplit, parse_qsl, urlencode, quote

_UNLIMITED_TIMEOUT_VALUES = {"none", "inf", "infinite", "unlimited"}

class XSSAgent:
    """
    XSS testing agent

    Workflow:
    1. LLM analyzes request and identifies XSS injection points
    2. LLM generates curl command templates with {PAYLOAD} placeholder
    3. Generate random_id (xss() sends it to beacon automatically)
    4. Replace {PAYLOAD} with actual XSS payloads
    5. Execute tests:
          - GET URL injection: visit via driver.get(), check beacon log + window.xss_array
          - Other injection: execute with curl, record token
    6. Detection logic:
          - Primary: check beacon log for random_id
          - Secondary: check window.xss_array
    7. finalize(): visit all URLs and collect window.xss_array
    """

    def __init__(self, client, driver,
                 xss_prompt_path: str = "prompt/xss_attack.txt",
                 log_dir: str = "output/attack_logs/xss",
                 reflection_enabled: bool = True):
        self.client = client
        self.driver = driver
        self.xss_prompt_path = Path(xss_prompt_path)
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._log_path = self.log_dir / "xss_agent.log"
        self.reflection_enabled = reflection_enabled

        self.execution_records: Dict[int, Dict[str, Any]] = {}

        self.triggered_tokens: Set[str] = set()
        self.xss_array: Set[int] = set()
        self.stored_verification_attempts: Dict[int, List[str]] = {}
        self.stored_verification_hits: Dict[int, str] = {}
        self.beacon_log_candidates = self._build_beacon_log_candidates()
        self.deadline = None

    def _log(self, *args):
        msg = " ".join(str(a) for a in args)
        try:
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(msg + "\n")
        except Exception:
            pass

    def set_deadline(self, deadline):
        self.deadline = deadline

    def _deadline_exceeded(self) -> bool:
        return self.deadline is not None and time.time() >= self.deadline

    def _timeout_result(self, stage: int, payloads_tested: int = 0,
                        random_id=None, curl_templates=None, extra=None) -> Dict[str, Any]:
        result = {
            "vulnerable": None,
            "timeout": True,
            "stage": stage,
            "payloads_tested": payloads_tested,
            "random_id": random_id,
            "curl_templates": curl_templates or [],
            "note": f"XSS task timeout during stage {stage}",
            "error": f"XSS task timeout during stage {stage}",
        }
        if extra:
            result.update(extra)
        return result

    def _load_prompt_template(self) -> str:
        """Load XSS prompt template"""
        return self.xss_prompt_path.read_text(encoding="utf-8")

    def _get_curl_timeout(self):
        raw = os.environ.get("SEMSCANNER_CURL_TIMEOUT", "120")
        normalized = str(raw).strip().lower()
        if normalized in _UNLIMITED_TIMEOUT_VALUES:
            return None
        try:
            timeout = int(float(normalized))
        except ValueError:
            self._log(f"[XSS] Invalid SEMSCANNER_CURL_TIMEOUT={raw!r}; using 120s")
            return 120
        return timeout if timeout > 0 else 120

    def _get_render_timeout(self):
        raw = os.environ.get("SEMSCANNER_XSS_RENDER_TIMEOUT", "60")
        normalized = str(raw).strip().lower()
        if normalized in _UNLIMITED_TIMEOUT_VALUES:
            return None
        try:
            timeout = int(float(normalized))
        except ValueError:
            self._log(f"[XSS] Invalid SEMSCANNER_XSS_RENDER_TIMEOUT={raw!r}; using 60s")
            return 60
        return timeout if timeout > 0 else 60

    def _build_beacon_log_candidates(self) -> List[Path]:
        """
        Build likely beacon log locations for this task.
        Task logs live under <run>/output/attack_execution/tasks/TASKxxxx,
        while listeners have been started with either <run>/http_captured.txt
        or <run>/logs/http_captured.txt in different reproduction scripts.
        """
        candidates = []
        for env_name in ("SEMSCANNER_XSS_BEACON_LOG", "XSS_BEACON_LOG", "BEACON_LOG_FILE"):
            value = __import__("os").environ.get(env_name)
            if value:
                candidates.append(Path(value))

        candidates.append(Path("http_captured.txt"))

        for parent in [self.log_dir, *self.log_dir.parents]:
            candidates.append(parent / "http_captured.txt")
            candidates.append(parent / "logs" / "http_captured.txt")

        deduped = []
        seen = set()
        for path in candidates:
            key = str(path)
            if key not in seen:
                deduped.append(path)
                seen.add(key)
        return deduped

    def _check_beacon(self, random_id: int) -> bool:
        for path in self.beacon_log_candidates:
            if check_beacon_detection(str(random_id), str(path)):
                self._log(f"  [Beacon] Token {random_id} found in {path}")
                self.triggered_tokens.add(str(random_id))
                return True
        return False

    def _stored_xss_candidate_urls(self, request: Dict[str, Any]) -> List[str]:
        """Return conservative, same-origin display pages for immediate stored-XSS checks."""
        method = str(request.get("method", "GET")).upper()
        if method not in {"POST", "PUT", "PATCH"}:
            return []

        request_url = str(request.get("url", ""))
        request_parts = urlsplit(request_url)
        if not request_parts.scheme or not request_parts.netloc:
            return []

        headers = request.get("headers") or {}
        referer = next(
            (str(value) for key, value in headers.items() if str(key).lower() == "referer" and value),
            "",
        )
        if not referer:
            return []

        candidate = urljoin(request_url, referer)
        parts = urlsplit(candidate)
        if (parts.scheme.lower(), parts.netloc.lower()) != (
            request_parts.scheme.lower(),
            request_parts.netloc.lower(),
        ):
            self._log(f"  [Stored Verification] Skipping cross-origin Referer: {candidate}")
            return []

        candidate = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))
        candidate_lower = candidate.lower()
        dangerous_keywords = (
            "logout", "signout", "logoff", "delete", "remove", "destroy",
            "erase", "purge", "drop", "reset", "deactivate", "unsubscribe",
        )
        if any(keyword in candidate_lower for keyword in dangerous_keywords):
            self._log(f"  [Stored Verification] Skipping potentially destructive Referer: {candidate}")
            return []

        return [candidate]

    def _visit_stored_xss_candidates(self, request: Dict[str, Any], random_id: int,
                                     template_index: int = 0, payload_index: int = 0) -> bool:
        """Immediately visit likely display pages before later attacks can overwrite the payload."""
        if not self.driver:
            return False

        candidates = self._stored_xss_candidate_urls(request)
        if not candidates:
            return False

        attempts = self.stored_verification_attempts.setdefault(random_id, [])
        for candidate in candidates:
            if self._deadline_exceeded():
                self._log("  [Stored Verification] Deadline reached before candidate visit")
                return False

            if candidate not in attempts:
                attempts.append(candidate)

            self._log(f"  [Stored Verification] Visiting captured Referer: {candidate}")
            try:
                self.driver.get(candidate)
                time.sleep(0.5)
                self._save_screenshot(random_id, template_index, payload_index)

                if self._check_beacon(random_id):
                    self.stored_verification_hits[random_id] = candidate
                    self._log(f"  [Stored Verification] XSS triggered via beacon at {candidate}")
                    return True

                try:
                    arr = self.driver.execute_script("return window.xss_array || [];")
                    if random_id in arr:
                        self.xss_array.add(random_id)
                        self.stored_verification_hits[random_id] = candidate
                        self._log(f"  [Stored Verification] XSS triggered via xss_array at {candidate}")
                        return True
                except Exception as e:
                    self._log(f"  [Stored Verification] Failed to inspect xss_array: {e}")
            except Exception as e:
                self._log(f"  [Stored Verification] Candidate visit failed: {e}")

        return False

    def test(self, request: Dict[str, Any], credentials: Dict[str, Any]) -> Dict[str, Any]:
        """
        Test a single request for XSS (two-stage)

        Two-stage test flow:
        - Stage 1: initial attack (original prompt)
        - Stage 2: reflection attack (if Stage 1 fails)

        Args:
            request: full request data (including response)
            credentials: account credentials

        Returns:
            {
                "vulnerable": True/False/None,
                "stage": 1 or 2,
                "payloads_tested": int,
                "random_id": int,
                "curl_templates": List[str]
            }
        """
        self._log(f"\n{'='*70}")
        self._log(f"[STAGE 1: Initial Attack]")
        self._log(f"{'='*70}\n")

        result_stage1 = self._execute_stage1(request, credentials)
        if result_stage1.get("timeout"):
            return result_stage1

        if result_stage1.get("vulnerable") is True:
            self._log(f"\n[STAGE 1] ✓ VULNERABLE - Skipping Stage 2")
            return result_stage1

        if not self.reflection_enabled:
            self._log(f"\n[Reflection] Disabled - Returning Stage 1 result")
            return result_stage1

        if self._deadline_exceeded():
            self._log("[XSS] Deadline reached before Stage 2; returning timeout result")
            return self._timeout_result(
                stage=2,
                payloads_tested=result_stage1.get("payloads_tested", 0),
                random_id=result_stage1.get("random_id"),
                curl_templates=result_stage1.get("curl_templates", []),
                extra={"stage1_results": result_stage1}
            )

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
        URL-encode path/query to avoid curl/driver parsing issues
        """
        try:
            parts = urlsplit(url)
            path = quote(parts.path, safe="/%")
            qsl = parse_qsl(parts.query, keep_blank_values=True)
            query = urlencode(qsl, doseq=True, quote_via=quote)
            return urlunsplit((parts.scheme, parts.netloc, path, query, parts.fragment))
        except Exception:
            return url

    def _rewrite_curl_url(self, curl_command: str, new_url: str) -> str:
        """
        Replace the first URL argument in a curl command with new_url
        """
        try:
            parts = shlex.split(curl_command)
        except Exception:
            return curl_command

        for i, p in enumerate(parts):
            if p.startswith("http://") or p.startswith("https://"):
                parts[i] = new_url
                return " ".join(shlex.quote(x) for x in parts)
        return curl_command


    def _execute_stage1(self, request: Dict[str, Any], credentials: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute Stage 1 initial attack

        Returns:
            Stage 1 result dict (includes test_results and llm_analysis for reflection)
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

        if self._deadline_exceeded():
            self._log("[XSS] Deadline reached before Stage 1 LLM analysis")
            return self._timeout_result(stage=1)

        self._log(f"[Step 1: Calling LLM to Identify Injection Points]")
        curl_templates, llm_analysis = self._generate_curl_templates(request)

        if self._deadline_exceeded():
            self._log("[XSS] Deadline reached after Stage 1 LLM analysis")
            return self._timeout_result(
                stage=1,
                curl_templates=curl_templates,
                extra={"llm_analysis": llm_analysis}
            )

        if not curl_templates:
            self._log(f"[XSS] No injection points identified by LLM")
            return {
                "vulnerable": False,
                "stage": 1,
                "payloads_tested": 0,
                "random_id": None,
                "curl_templates": [],
                "test_results": [],
                "llm_analysis": llm_analysis,
                "note": "No injection points found"
            }

        self._log(f"[LLM Generated {len(curl_templates)} curl template(s)]:")
        for i, tmpl in enumerate(curl_templates, 1):
            self._log(f"  {i}. {tmpl}")
        self._log(f"")

        random_id = random.randint(100000, 999999)

        self._log(f"[Step 2: Generated Random ID (beacon token)]: {random_id}")
        self._log(f"  Expected beacon callback with data={random_id}")
        self._log(f"")

        xss_payloads = self._get_xss_payloads(random_id)
        self._log(f"[Step 3: Generated {len(xss_payloads)} XSS Payloads]:")
        for i, payload in enumerate(xss_payloads, 1):
            self._log(f"  {i}. {payload[:100]}{'...' if len(payload) > 100 else ''}")
        self._log(f"")

        self._log(f"[Step 4: Executing Tests]")
        payloads_tested = 0
        vulnerable = False
        any_payload_reflected = False

        # Payload-first ordering gives the highest-value, most broadly useful
        # probes a chance against every candidate injection point early.
        for payload_index, payload in enumerate(xss_payloads, 1):
            if self._deadline_exceeded():
                self._log("[XSS] Deadline reached before next Stage 1 payload")
                return self._timeout_result(
                    stage=1,
                    payloads_tested=payloads_tested,
                    random_id=random_id,
                    curl_templates=curl_templates,
                    extra={"llm_analysis": llm_analysis}
                )

            self._log(f"\n[Testing Payload Across Templates]: {payload}")

            for template_index, template in enumerate(curl_templates, 1):
                if self._deadline_exceeded():
                    self._log("[XSS] Deadline reached before next Stage 1 template")
                    return self._timeout_result(
                        stage=1,
                        payloads_tested=payloads_tested,
                        random_id=random_id,
                        curl_templates=curl_templates,
                        extra={"llm_analysis": llm_analysis}
                    )

                self._log(f"[Testing Template]: {template}")

                if '{PAYLOAD}' not in template:
                    self._log(f"   Template missing {{PAYLOAD}} placeholder, skipping")
                    continue

                final_command = self._inject_payload(template, payload)
                injected_url = self._extract_url_from_curl(final_command)
                safe_url = self._sanitize_url_for_http(injected_url)
                if safe_url != injected_url:
                    final_command = self._rewrite_curl_url(final_command, safe_url)

                final_command = self._ensure_curl_include_headers(final_command)

                final_command = append_credentials_to_curl(final_command, credentials)
                final_command = self._normalize_xss_curl_command(final_command)

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
                    stdout, stderr, returncode = self._execute_curl_command(final_command)

                    http_status, headers, body = self._parse_curl_response(stdout)

                    current_reflected = payload in body
                    
                    if current_reflected:
                        any_payload_reflected = True
                        self._log(f"   [Reflection] Payload reflected verbatim in response body! (High Suspicion)")
                        
                    self._log(f"  ✓ Executed via curl (curl_exit_code: {returncode})")
                    if http_status is not None:
                        self._log(f"  HTTP Status: {http_status}")
                    self._log(f"  Body length: {len(body)} bytes")

                    extracted_body = extract_useful_response(body, max_length=2000)
                    self._log(f"  Response (extracted): {extracted_body}")
                    if stderr:
                        self._log(f"  Stderr: {stderr}")

                    is_html = self._is_html_response(headers, body)
                    self._log(f"  Is HTML: {is_html}")

                    if is_html and self.driver:
                        if self._render_and_check_xss(body, random_id, template_index, payload_index):
                            self._log(f"  XSS confirmed, stopping further tests for this request")
                            vulnerable = True
                            payloads_tested += 1
                            break

                    if (
                        not vulnerable
                        and returncode == 0
                        and http_status is not None
                        and 200 <= http_status < 400
                        and self._visit_stored_xss_candidates(
                            request,
                            random_id,
                            template_index=template_index,
                            payload_index=payload_index,
                        )
                    ):
                        self._log(f"  Stored XSS confirmed, stopping further tests for this request")
                        vulnerable = True
                        payloads_tested += 1
                        break

                    payloads_tested += 1

                except Exception as e:
                    self._log(f"  ✗ Failed: {e}")

            if vulnerable:
                break

        self._log(f"\n[Step 5: Checking Beacon Detection]")
        if not vulnerable:
            vulnerable = self._check_beacon(random_id)
        else:
            if self._check_beacon(random_id):
                self._log(f"  (Beacon also confirms XSS for Random ID {random_id})")

        if not vulnerable and random_id in self.xss_array:
            self._log(f"  ✓ XSS_ARRAY DETECTION: Random ID {random_id} found!")
            vulnerable = True

        self._log(f"\n{'='*70}")
        self._log(f"[XSS Test Summary]")
        self._log(f"  Total Payloads Tested: {payloads_tested}")
        self._log(f"  Random ID (beacon token): {random_id}")
        self._log(f"  Beacon Triggered: {str(random_id) in self.triggered_tokens}")
        self._log(f"  XSS Array Count: {len(self.xss_array)}")

        final_status = "SAFE"
        if vulnerable:
            final_status = "VULNERABLE (Verified)"
        elif any_payload_reflected:
            final_status = "SUSPECTED (Reflected)" 
        
        self._log(f"  Result: {final_status}")
        
        result = {
            "vulnerable": vulnerable,
            "is_reflected": any_payload_reflected,
            "stage": 1,
            "payloads_tested": payloads_tested,
            "random_id": random_id,
            "curl_templates": curl_templates,
            "llm_analysis": llm_analysis,
            "note": f"Stage 1 - Result: {final_status}. (Reflected: {any_payload_reflected}, Executed: {vulnerable})"
        }
        attempted_urls = self.stored_verification_attempts.get(random_id, [])
        if attempted_urls:
            result["stored_verification_urls"] = attempted_urls
        if random_id in self.stored_verification_hits:
            result["detection_method"] = "immediate_stored_referer"
            result["stored_verification_hit"] = self.stored_verification_hits[random_id]
        return result

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

            templates = self._parse_curl_templates(llm_output)

            return templates, llm_output

        except Exception as e:
            self._log(f"[XSS] LLM call failed: {e}")
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
            self._log(f"[Warning] No Commands section found; scanning full LLM output")
            command_lines = lines
        else:
            command_lines = lines[commands_line_idx + 1:]

        current_parts = []
        seen = set()

        def add_candidate(parts):
            candidate = " ".join(part.strip() for part in parts if part.strip()).strip()
            if self._is_valid_curl_template(candidate) and candidate not in seen:
                templates.append(candidate)
                seen.add(candidate)

        for raw_line in command_lines:
            line = raw_line.strip()

            if not line or line.startswith('```'):
                # An outstanding continuation cannot legitimately terminate at
                # a blank line or a Markdown fence; discard the partial command.
                if current_parts:
                    current_parts = []
                continue

            curl_match = re.search(r'(?<![\w-])curl(?=\s|$)', line)
            if curl_match:
                if current_parts:
                    current_parts = []
                line = line[curl_match.start():].strip().strip('`').strip()
            elif not current_parts:
                continue

            has_continuation = line.rstrip().endswith('\\')
            if has_continuation:
                line = line.rstrip()[:-1].rstrip()

            current_parts.append(line)

            if not has_continuation:
                add_candidate(current_parts)
                current_parts = []

        # Do not add current_parts here: a command left in the accumulator had
        # a trailing backslash and is therefore incomplete.

        if not templates:
            self._log(f"[Warning] No valid curl commands found after Commands section")

        return templates

    def _is_valid_curl_template(self, curl_command: str) -> bool:
        """Reject incomplete or non-executable curl templates before testing."""
        if not curl_command or curl_command.rstrip().endswith('\\'):
            return False

        try:
            args = shlex.split(curl_command)
        except ValueError:
            return False

        if not args or args[0] != 'curl':
            return False
        if '{PAYLOAD}' not in curl_command:
            return False
        return any(re.search(r'https?://', arg, re.IGNORECASE) for arg in args[1:])

    @staticmethod
    def _inject_payload(curl_template: str, payload: str) -> str:
        """Insert a payload without letting its quotes corrupt shell parsing."""
        try:
            args = shlex.split(curl_template)
        except ValueError:
            return curl_template.replace('{PAYLOAD}', payload)

        injected_args = [arg.replace('{PAYLOAD}', payload) for arg in args]
        return shlex.join(injected_args)

    @staticmethod
    def _iter_payload_template_pairs(payloads, templates):
        """Yield every test pair in payload-first order."""
        for payload in payloads:
            for template in templates:
                yield payload, template

    def _normalize_xss_curl_command(self, curl_command: str) -> str:
        """
        Normalize curl generated for XSS probes before execution.

        XSS payloads often start with '<'. With curl -F, values like
        field=<img... are interpreted as "read this local file". For XSS tests
        these multipart fields must be literal strings, so use --form-string.
        """
        try:
            args = shlex.split(curl_command)
        except ValueError:
            return curl_command

        if not args or args[0] != "curl":
            return curl_command

        normalized = ["curl"]
        skip_next = False
        for arg in args[1:]:
            if skip_next:
                skip_next = False
                continue
            if arg in ("--connect-timeout", "--max-time"):
                skip_next = True
                continue
            if arg.startswith("--connect-timeout=") or arg.startswith("--max-time="):
                continue
            if arg in ("-F", "--form"):
                normalized.append("--form-string")
            else:
                normalized.append(arg)

        return " ".join(shlex.quote(arg) for arg in normalized)

    def _execute_curl_command(self, curl_command: str):
        args = shlex.split(curl_command)
        timeout = self._get_curl_timeout()
        process = subprocess.Popen(
            args,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout) if timeout is not None else process.communicate()
            return stdout, stderr, process.returncode
        except subprocess.TimeoutExpired:
            stdout, stderr, cleanup_complete = kill_process_group_and_collect(process)
            cleanup_note = "process group killed"
            if not cleanup_complete:
                cleanup_note += "; pipe cleanup exceeded 3 seconds and was abandoned"
            stderr = (stderr or "") + f"\nTimeout after {timeout} seconds; {cleanup_note}"
            return stdout or "", stderr, 124

    def _get_xss_payloads(self, random_id: int) -> List[str]:
        """
        Generate a compact XSS payload list covering distinct injection contexts.

        Args:
            random_id: random ID sent to beacon and stored in xss_array

        Returns:
            Returns payload list ordered from broadly useful to context-specific
        """
        return [
            # HTML element body: common, auto-triggering baseline probe.
            f'<img src=x onerror=xss({random_id})>',
            # SVG parsing context.
            f'<svg onload=xss({random_id})>',
            # Double-quoted, single-quoted, and unquoted attribute values.
            f'x" onerror="xss({random_id})" x="',
            f"x' onerror='xss({random_id})' x='",
            f'x onfocus=xss({random_id}) autofocus x=',
            # Raw-text elements (the browser ignores non-matching end tags).
            f'</title></textarea></style><img src=x onerror=xss({random_id})>',
            # Script element data context.
            f'</script><img src=x onerror=xss({random_id})>',
            # JavaScript single- and double-quoted string contexts.
            f"';xss({random_id});//",
            f'";xss({random_id});//',
            # HTML comment context.
            f'--><img src=x onerror=xss({random_id})><!--',
        ]

    def _ensure_curl_include_headers(self, curl_command: str) -> str:
        """
        curl -i / --include(HTTP)
        """
        if '-i' not in curl_command and '--include' not in curl_command:
            return curl_command.replace('curl ', 'curl -i ', 1)
        return curl_command

    def _parse_curl_response(self, curl_output: str):
        """
         curl -i :
         (http_status:int|None, headers:dict, body:str)
        """
        lines = curl_output.split('\n')

        http_status = None
        headers = {}
        body_start_idx = 0

        for i, line in enumerate(lines):
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
        Decide whether the curl response body is actual HTML worth rendering.

        curl commands append an HTTP_STATUS marker in some paths. That marker
        must not make a plain response look renderable.
        """
        html_markers = (
            '<!doctype html',
            '<html',
            '<head',
            '<body',
            '<script',
            '<svg',
            '<img',
            '<iframe',
            '<form',
        )

        content_type = headers.get('content-type', '').lower()
        body = re.sub(r'\r?\nHTTP_STATUS:\d{3}\s*$', '', body or '').strip()
        body_lower = body.lower()[:2000]

        if not body_lower:
            return False

        body_has_html = any(marker in body_lower for marker in html_markers)

        if 'text/html' in content_type:
            return body_has_html

        if content_type == '' or 'text/' in content_type:
            return body_has_html

        return False

    def _is_crash_prone_page(self, html_content: str) -> bool:
        """
        Check if HTML is a server error page that could crash the driver
        """
        if not html_content:
            return False
            
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
        Render HTML with driver and check if XSS triggered
        
        Args:
            html_content: HTML content
            random_id: random ID
            template_index: template index (for screenshot naming)
            payload_index: payload index (for screenshot naming)
        """
        import base64
        import time
        from datetime import datetime

        self._log(f"  [Rendering HTML with driver...]")

        if self._is_crash_prone_page(html_content):
            self._log(f"  🛑 [SKIP RENDER] Detected Server Error Page (400/500).")
            return False

        try:
            render_timeout = self._get_render_timeout()
            if self.deadline is not None:
                remaining = self.deadline - time.time()
                if remaining <= 0:
                    self._log("  [SKIP RENDER] XSS task deadline already exceeded")
                    return False
                if render_timeout is None:
                    render_timeout = max(1, int(remaining))
                else:
                    render_timeout = max(1, min(render_timeout, int(remaining)))

            if render_timeout is not None:
                try:
                    self.driver.set_page_load_timeout(render_timeout)
                    self.driver.set_script_timeout(render_timeout)
                    command_executor = getattr(self.driver, "command_executor", None)
                    if command_executor and hasattr(command_executor, "set_timeout"):
                        command_executor.set_timeout(render_timeout + 5)
                    self._log(f"  [Render Timeout Configured]: {render_timeout}s")
                except Exception as e:
                    self._log(f"  [Render Timeout Configuration Failed]: {e}")

            # 1. HTML -> base64 data URL
            b64_html = base64.b64encode(html_content.encode('utf-8')).decode('utf-8')
            data_url = f"data:text/html;base64,{b64_html}"

            self.driver.get(data_url)

            time.sleep(0.5)

            screenshot_saved = self._save_screenshot(random_id, template_index, payload_index)
            if screenshot_saved:
                self._log(f"  📸 Screenshot saved")

            if self._check_beacon(random_id):
                self._log(f"  ✓✓✓ XSS TRIGGERED via BEACON! Random ID {random_id}")
                return True

            try:
                arr = self.driver.execute_script("return window.xss_array || [];")
                self._log(f"  [XSS Array]: {arr}")

                if random_id in arr:
                    self._log(f"  ✓ XSS TRIGGERED via xss_array! Random ID {random_id}")
                    self.xss_array.add(random_id)
                    return True
            except Exception as e:
                self._log(f"   Failed to check xss_array: {e}")

            self._log(f"  ✗ XSS not triggered in rendered HTML")
            return False

        except Exception as e:
            self._log(f"  ✗ Rendering failed: {e}")
            return False

    def _save_screenshot(self, random_id: int, template_index: int, payload_index: int) -> bool:
        """
        Save a screenshot of the current page
        
        Args:
            random_id: random ID
            template_index: template index
            payload_index: payload index
            
        Returns:
            Returns True if screenshot saved successfully
        """
        try:
            from datetime import datetime
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"rid_{random_id}_t{template_index}_p{payload_index}_{timestamp}.png"
            screenshot_path = self.log_dir / filename
            
            self.driver.save_screenshot(str(screenshot_path))
            
            return True
            
        except Exception as e:
            self._log(f"   Failed to save screenshot: {e}")
            return False

    def _extract_url_from_curl(self, curl_command: str) -> str:
        try:
            parts = shlex.split(curl_command)
        except Exception:
            parts = curl_command.split()

        for p in parts:
            if p.startswith("http://") or p.startswith("https://"):
                return p

        match = re.search(r"(https?://[^\s'\"\\]+)", curl_command)
        if match:
            return match.group(1)

        return ""

    def _execute_stage2(self, request: Dict[str, Any], credentials: Dict[str, Any],
                    stage1_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute Stage 2 reflection attack (curl + HTML rendering)
        """
        if self._deadline_exceeded():
            self._log("[XSS] Deadline reached before Stage 2 reflection analysis")
            return self._timeout_result(
                stage=2,
                payloads_tested=stage1_context.get("payloads_tested", 0),
                random_id=stage1_context.get("random_id"),
                curl_templates=stage1_context.get("curl_templates", []),
                extra={"stage1_results": stage1_context}
            )

        self._log(f"[Reflection] Building reflection analysis...")
        reflection_suffix = self._build_reflection_suffix(stage1_context)

        self._log(f"[Step 1: Generating Reflection Templates via LLM]")
        new_templates, llm_reflection_output = self._generate_curl_templates_with_reflection(
            request=request,
            reflection_suffix=reflection_suffix
        )

        if self._deadline_exceeded():
            self._log("[XSS] Deadline reached after Stage 2 LLM analysis")
            return self._timeout_result(
                stage=2,
                curl_templates=new_templates,
                extra={
                    "llm_reflection_output": llm_reflection_output,
                    "reflection_analysis": reflection_suffix,
                    "stage1_results": stage1_context
                }
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

        random_id = random.randint(100000, 999999)
        self._log(f"[Step 2: Generated New Random ID (beacon token)]: {random_id}")
        self._log(f"  Expected beacon callback with data={random_id}")
        self._log(f"")

        xss_payloads = self._get_xss_payloads(random_id)
        self._log(f"[Step 3: Generated {len(xss_payloads)} XSS Payloads]:")
        for i, payload in enumerate(xss_payloads, 1):
            self._log(f"  {i}. {payload[:100]}{'...' if len(payload) > 100 else ''}")
        self._log(f"")

        self._log(f"[Step 4: Executing Tests]")
        payloads_tested = 0
        method = request.get("method", "GET")
        url = request.get("url", "")
        vulnerable = False
        any_payload_reflected = False

        # Keep the same payload-first ordering as Stage 1.
        for payload_index, payload in enumerate(xss_payloads, 1):
            if self._deadline_exceeded():
                self._log("[XSS] Deadline reached before next Stage 2 payload")
                return self._timeout_result(
                    stage=2,
                    payloads_tested=payloads_tested,
                    random_id=random_id,
                    curl_templates=new_templates,
                    extra={
                        "llm_reflection_output": llm_reflection_output,
                        "reflection_analysis": reflection_suffix,
                        "stage1_results": stage1_context
                    }
                )

            self._log(f"\n[Testing Payload Across Templates]: {payload}")

            for template_index, template in enumerate(new_templates, 1):
                if self._deadline_exceeded():
                    self._log("[XSS] Deadline reached before next Stage 2 template")
                    return self._timeout_result(
                        stage=2,
                        payloads_tested=payloads_tested,
                        random_id=random_id,
                        curl_templates=new_templates,
                        extra={
                            "llm_reflection_output": llm_reflection_output,
                            "reflection_analysis": reflection_suffix,
                            "stage1_results": stage1_context
                        }
                    )

                self._log(f"[Testing Template]: {template}")

                if '{PAYLOAD}' not in template:
                    self._log(f"   Template missing {{PAYLOAD}} placeholder, skipping")
                    continue

                final_command = self._inject_payload(template, payload)
                injected_url = self._extract_url_from_curl(final_command)
                safe_url = self._sanitize_url_for_http(injected_url)
                if safe_url != injected_url:
                    final_command = self._rewrite_curl_url(final_command, safe_url)


                final_command = self._ensure_curl_include_headers(final_command)

                final_command = append_credentials_to_curl(final_command, credentials)
                final_command = self._normalize_xss_curl_command(final_command)

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
                    stdout, stderr, returncode = self._execute_curl_command(final_command)

                    http_status, headers, body = self._parse_curl_response(stdout)

                    current_reflected = payload in body
                    
                    if current_reflected:
                        any_payload_reflected = True
                        self._log(f"   [Reflection] Payload reflected verbatim in response body! (High Suspicion)")

                    self._log(f"  ✓ Executed via curl (curl_exit_code: {returncode})")
                    if http_status is not None:
                        self._log(f"  HTTP Status: {http_status}")
                    self._log(f"  Body length: {len(body)} bytes")

                    extracted_body = extract_useful_response(body, max_length=2000)
                    self._log(f"  Response (extracted): {extracted_body}")
                    if stderr:
                        self._log(f"  Stderr: {stderr}")

                    is_html = self._is_html_response(headers, body)
                    self._log(f"  Is HTML: {is_html}")

                    if is_html and self.driver:
                        if self._render_and_check_xss(body, random_id, template_index, payload_index):
                            self._log(f"  XSS confirmed in Stage 2, stopping further tests")
                            vulnerable = True
                            payloads_tested += 1
                            break

                    if (
                        not vulnerable
                        and returncode == 0
                        and http_status is not None
                        and 200 <= http_status < 400
                        and self._visit_stored_xss_candidates(
                            request,
                            random_id,
                            template_index=template_index,
                            payload_index=payload_index,
                        )
                    ):
                        self._log(f"  Stored XSS confirmed in Stage 2, stopping further tests")
                        vulnerable = True
                        payloads_tested += 1
                        break

                    payloads_tested += 1

                except Exception as e:
                    self._log(f"  ✗ Failed: {e}")

            if vulnerable:
                break

        self._log(f"\n[Step 5: Checking Beacon Detection]")
        if not vulnerable:
            if self._check_beacon(random_id):
                self._log(f"  ✓✓✓ BEACON DETECTION: Random ID {random_id} found in log!")
                vulnerable = True
            else:
                self._log(f"  ✗ Beacon not detected (random_id {random_id} not in log)")
        else:
            if self._check_beacon(random_id):
                self._log(f"  (Beacon also confirms XSS for Random ID {random_id})")

        if not vulnerable and random_id in self.xss_array:
            self._log(f"  ✓ XSS_ARRAY DETECTION: Random ID {random_id} found!")
            vulnerable = True

        self._log(f"\n{'='*70}")
        self._log(f"[XSS Test Summary - Stage 2]")
        self._log(f"  Total Payloads Tested: {payloads_tested}")
        self._log(f"  Random ID (beacon token): {random_id}")
        self._log(f"  Beacon Triggered: {str(random_id) in self.triggered_tokens}")
        self._log(f"  XSS Array Count: {len(self.xss_array)}")

        final_status = "SAFE"
        if vulnerable:
            final_status = "VULNERABLE (Verified)"
        elif any_payload_reflected:
            final_status = "SUSPECTED (Reflected)" 
        
        self._log(f"  Result: {final_status}")


        result = {
            "vulnerable": vulnerable,
            "is_reflected": any_payload_reflected,
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
        attempted_urls = self.stored_verification_attempts.get(random_id, [])
        if attempted_urls:
            result["stored_verification_urls"] = attempted_urls
        if random_id in self.stored_verification_hits:
            result["detection_method"] = "immediate_stored_referer"
            result["stored_verification_hit"] = self.stored_verification_hits[random_id]
        return result

    def _build_reflection_suffix(self, stage1_context: Dict[str, Any]) -> str:
        """
        Build XSS reflection suffix
        """
        templates = stage1_context.get("curl_templates", [])
        payloads_tested = stage1_context.get("payloads_tested", 0)
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
        suffix += f"Total payloads tested: {payloads_tested}\n"
        suffix += f"OOB beacon detection: FAILED (random_id not found)\n"
        suffix += f"XSS array detection: FAILED (no random_id in window.xss_array)\n"
        suffix += "\n"

        suffix += f"Result: {'NOT VULNERABLE' if vulnerable is False else 'UNCERTAIN/PENDING'}\n"
        suffix += "\n"

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
        Call LLM to generate new XSS templates after reflection
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
        Check final results (called after visiting all pages)

        Returns:
            {random_id: is_vulnerable}
        """
        self._log(f"\n{'='*70}")
        self._log(f"[XSS] Checking Final Results")
        self._log(f"{'='*70}\n")

        updates = {}

        for random_id in self.execution_records.keys():
            beacon_triggered = self._check_beacon(random_id)

            array_triggered = random_id in self.xss_array

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

        self._save_final_results(updates)

        return updates

    def _save_final_results(self, updates: Dict[int, bool]):
        """Save final results"""
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
