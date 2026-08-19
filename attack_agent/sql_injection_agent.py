"""
SQLAgent - ()
"""

from typing import Dict, Any
from pathlib import Path
import subprocess
import os
import json
import re
from collections import defaultdict
from config.llm_config import get_model_name, get_temperature
from attack_agent.request_utils import extract_useful_response, kill_process_group_and_collect

_UNLIMITED_TIMEOUT_VALUES = {"none", "inf", "infinite", "unlimited"}
_SQLMAP_FATAL_EXECUTION_MARKERS = (
    "does not contain a usable http request",
    "you must provide at least one target option",
    "no parameter(s) found for testing in the provided data",
    "specified target url is not valid",
)
_SQLMAP_POSITIVE_HEADER = re.compile(
    r"^sqlmap (?:identified the following injection point\(s\) with a total of "
    r"\d+ HTTP\(s\) requests|resumed the following injection point\(s\) from "
    r"stored session):?\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_SQLMAP_NEGATIVE_MARKER = "all tested parameters do not appear to be injectable"
_SQLMAP_CANDIDATE_REJECTION_MARKER = (
    "false positive or unexploitable injection point detected"
)
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_SQLMAP_REPORT_MAX_CHARS = 4_000_000
_SQLMAP_POSITIVE_NEEDLES = (
    "sqlmap identified the following injection point(s)",
    "sqlmap resumed the following injection point(s) from stored session",
)
_SQLMAP_CANDIDATE_INJECTION = re.compile(
    r"(?:^|\n)(?:\[[0-9:]+\][ \t]+)?\[INFO\][ \t]+"
    r"(?P<place>[A-Za-z][A-Za-z0-9 _-]*?)[ \t]+parameter[ \t]+"
    r"'(?P<parameter>[^'\n]+)'[ \t]+appears[ \t]+to[ \t]+be[ \t]+"
    r"'(?P<technique>[^'\n]+)'[ \t]+injectable"
    r"(?:[ \t]+\([^\n]*\))?[ \t]*(?=\n|$)",
    re.IGNORECASE | re.MULTILINE,
)


def classify_sqlmap_output(stdout: str, allow_negative: bool = True) -> Dict[str, Any]:
    """Classify sqlmap's own final report without using an LLM.

    A positive result accepts either sqlmap's standard final injection report
    or its structured ``parameter ... appears to be ... injectable`` signal.
    A later false-positive rejection or all-parameters-negative conclusion
    overrides the preliminary signal.  A final negative is returned only when
    the caller knows the execution completed.
    """
    raw_output = stdout or ""
    search_output = _ANSI_ESCAPE.sub("", raw_output).replace("\r", "\n")
    lower_output = search_output.lower()
    header_start = max(lower_output.rfind(needle) for needle in _SQLMAP_POSITIVE_NEEDLES)
    output = ""
    header = None
    if header_start >= 0:
        # The report follows the header.  Limiting this slice avoids copying
        # sqlmap's potentially very large verbose traffic trace.
        report_end = header_start + _SQLMAP_REPORT_MAX_CHARS
        output = search_output[header_start:report_end]
        header = _SQLMAP_POSITIVE_HEADER.search(output)

    # Check positive evidence first because sqlmap can reject some parameters
    # while still confirming an injection point in another one.
    if header:
        report = output[header.end():]
        parameter_match = re.search(
            r"^Parameter:\s*(?P<parameter>[^\n]+?)\s*$",
            report,
            re.IGNORECASE | re.MULTILINE,
        )
        if parameter_match:
            finding = report[parameter_match.start():]
            technique_match = re.search(
                r"^\s+Type:\s*(?P<technique>[^\n]+?)\s*$",
                finding,
                re.IGNORECASE | re.MULTILINE,
            )
            parameter = parameter_match.group("parameter").strip()
            technique = technique_match.group("technique").strip() if technique_match else None
            detail = f"; Type: {technique}" if technique else ""
            return {
                "vulnerable": True,
                "evidence": (
                    "sqlmap's final injection report identified "
                    f"Parameter: {parameter}{detail}"
                ),
                "detection_method": "sqlmap_final_report",
            }

    candidate_matches = list(_SQLMAP_CANDIDATE_INJECTION.finditer(search_output))
    if candidate_matches:
        candidate = candidate_matches[-1]
        later_output = lower_output[candidate.end():]

        # sqlmap can initially call a parameter injectable and subsequently
        # retract that candidate.  Never preserve the preliminary signal over
        # an explicit later rejection or final all-parameters-negative result.
        if _SQLMAP_NEGATIVE_MARKER in later_output:
            if allow_negative:
                return {
                    "vulnerable": False,
                    "evidence": (
                        "sqlmap later reported that all tested parameters do "
                        "not appear to be injectable"
                    ),
                    "detection_method": "sqlmap_final_negative_report",
                }
            return {
                "vulnerable": None,
                "evidence": (
                    "sqlmap's preliminary injection signal was followed by a "
                    "negative conclusion during an incomplete execution"
                ),
                "detection_method": "sqlmap_output_inconclusive",
            }

        if _SQLMAP_CANDIDATE_REJECTION_MARKER in later_output:
            return {
                "vulnerable": None,
                "evidence": (
                    "sqlmap explicitly retracted its preliminary injection "
                    "signal as false-positive or unexploitable"
                ),
                "detection_method": "sqlmap_output_inconclusive",
            }

        place = candidate.group("place").strip()
        parameter = candidate.group("parameter").strip()
        technique = candidate.group("technique").strip()
        return {
            "vulnerable": True,
            "evidence": (
                "sqlmap reported a structured injection signal for "
                f"{place} Parameter: {parameter}; Type: {technique}"
            ),
            "detection_method": "sqlmap_structured_injection_signal",
        }

    if (
        allow_negative
        and header_start < 0
        and _SQLMAP_NEGATIVE_MARKER in raw_output.lower()
    ):
        return {
            "vulnerable": False,
            "evidence": (
                "sqlmap reported that all tested parameters do not appear "
                "to be injectable"
            ),
            "detection_method": "sqlmap_final_negative_report",
        }

    return {
        "vulnerable": None,
        "evidence": (
            "sqlmap produced neither a confirmed injection report nor an "
            "explicit all-parameters-negative conclusion"
        ),
        "detection_method": "sqlmap_output_inconclusive",
    }

def extract_sqlmap_info(file_content: str) -> Dict:
    """
    sqlmap


    Returns:
        {
            'by_status': {
                '200': {
                    'response_body_1': [request1, request2, ...],
                    'response_body_2': [...]
                },
                '404': {...}
            },
            'critical_info': str or None,
            'last_10_lines': str  # :10
        }
    """
    results = {
        'by_status': defaultdict(lambda: defaultdict(list)),
        'critical_info': None,
        'last_10_lines': ''
    }

    traffic_in_pattern = r'\[TRAFFIC IN\].*HTTP response.*\((\d+)\b'
    lines = file_content.splitlines()
    i = 0

    non_empty_lines = [line for line in lines if line.strip()]
    if non_empty_lines:
        results['last_20_lines'] = '\n'.join(non_empty_lines[-20:])

    while i < len(lines):
        line = lines[i].strip()

        m = re.search(traffic_in_pattern, line)
        if m:
            status_code = m.group(1)
            response_info = {'body': '', 'example_request': None}

            i += 1
            while i < len(lines):
                cur = lines[i]
                if not cur.strip():
                    i += 1
                    break
                if cur.strip().startswith('['):
                    break
                i += 1

            body_lines = []
            while i < len(lines) and not lines[i].strip().startswith('['):
                body_lines.append(lines[i].strip())
                i += 1

            response_info['body'] = '\n'.join(body_lines).strip()

            response_key = response_info['body']
            results['by_status'][status_code][response_key].append(response_info)

            continue

        crit_m = re.search(r'\[CRITICAL\]\s*(.+)', line)
        if crit_m:
            results['critical_info'] = crit_m.group(1).strip()

        i += 1

    return results


def format_summary(results: Dict) -> str:
    """


    Returns:

    """
    by_status = results.get('by_status', {})
    if not by_status:
        last_10 = results.get('last_20_lines', '')
        if last_10:
            return f"No HTTP response records found\n\nLast 10 lines of log:\n{'-'*50}\n{last_10}"
        return "No HTTP response records found"

    summary_lines = []
    status_codes = sorted(by_status.keys(), key=lambda x: int(x))

    summary_lines.append(f"\nFound {len(status_codes)} distinct HTTP status codes:")
    summary_lines.append("-" * 50)

    total_count = 0
    for idx, status in enumerate(status_codes, start=1):
        responses = by_status[status]
        summary_lines.append(f"\n{idx}. Status Code: {status}")

        unique_responses = list(responses.values())
        count = sum(len(group) for group in unique_responses)
        summary_lines.append(f"   Occurrences: {count}")

        response_examples = []
        for group in unique_responses:
            if len(response_examples) >= 10 - total_count:
                break
            response_examples.append(group[0])

        for s_idx, resp in enumerate(response_examples, start=1):
            summary_lines.append(f"   Example {s_idx}:")
            body_original = resp['body']
            body_extracted = extract_useful_response(body_original, max_length=2000)
            summary_lines.append(f"     Body:")
            for line in body_extracted.splitlines():
                summary_lines.append(f"       {line}")

        total_count += len(response_examples)

    if results.get('critical_info'):
        summary_lines.append("\nFinal Critical Information:")
        summary_lines.append(f"  {results['critical_info']}")

    last_10 = results.get('last_20_lines', '')
    if last_10:
        summary_lines.append("\n" + "=" * 70)
        summary_lines.append("Last 20 lines of log:")
        summary_lines.append("=" * 70)
        summary_lines.append(last_10)

    return "\n".join(summary_lines)


class SQLInjectionAgent:
    """Generate and run sqlmap commands, then parse sqlmap's final verdict.

    The LLM translates a captured request into a sqlmap command.  It does not
    participate in deciding whether the completed test found a vulnerability.
    """
    
    def __init__(self, client, log_dir: str = "output/attack_logs/sql",
                 analysis_prompt_path: str = "prompt/sql_agent_attack.txt"):
        self.client = client
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._log_path = self.log_dir / "sql_agent.log"

        self._analysis_prompt = self._load_prompt_from_file(analysis_prompt_path)
    
    def _log(self, *args):
        msg = " ".join(str(a) for a in args)
        try:
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(msg + "\n")
        except Exception:
            pass
    
    def _load_prompt_from_file(self, file_path: str) -> str:
        """prompt"""
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    
    def test(self, task_description: str,
            target_request: Dict[str, Any],
            credentials: Dict[str, Any]) -> Dict[str, Any]:
        """
        SQL

        Args:
            task_description:
            target_request:
            credentials: account credentials

        Returns:
            {
                "vulnerable": True/False/None,
                "sqlmap_command": str,
                "log_file": str,
                "summary": str,
                "analysis": str
            }
        """
        method = target_request.get("method", "GET")
        url = target_request.get("url", "")

        self._log(f"\n{'='*70}")
        self._log(f"[SQLi] New Test Started")
        self._log(f"{'='*70}")
        self._log(f"[SQLi] Testing: {method} {url}")
        self._log(f"  Task Description: {task_description}")
        self._log(f"\n[Received from Planning Agent]:")
        self._log(f"  Target Request:")
        self._log(f"    Method: {method}")
        self._log(f"    URL: {url}")
        self._log(f"    Headers: {json.dumps(target_request.get('headers', {}), indent=6)}")
        self._log(f"    Body: {target_request.get('body', 'None')}")
        self._log(f"    Response Status: {target_request.get('response_status', 'N/A')}")
        response_body = str(target_request.get('response_body', ''))[:2000]
        self._log(f"    Response Body (preview): {response_body}{'...(truncated)' if len(str(target_request.get('response_body', ''))) > 2000 else ''}")
        self._log(f"  Credentials: {json.dumps(credentials, indent=6, default=str)}")
        self._log(f"")
        
        sqlmap_command = self._generate_sqlmap_command(
            task_description,
            target_request,
            credentials
        )
        
        if not sqlmap_command:
            return {
                "vulnerable": None,
                "sqlmap_command": "",
                "log_file": "",
                "summary": "Failed to generate sqlmap command",
                "analysis": ""
            }
        
        self._log(f"  SQLMap command: {sqlmap_command}")
        
        log_file = self.log_dir / f"sqlmap_{hash(url) % 100000}.log"
        execution_result = self._execute_sqlmap(sqlmap_command, log_file)
        
        if "error" in execution_result:
            return {
                "vulnerable": None,
                "sqlmap_command": sqlmap_command,
                "log_file": str(log_file),
                "summary": execution_result.get("error", ""),
                "analysis": ""
            }
        
        summary = execution_result.get("summary", "")
        
        self._log(f"  Log summary extracted ({len(summary)} chars)")
        
        vulnerable = execution_result.get("vulnerable")
        evidence = execution_result.get("evidence", "")

        if vulnerable is True:
            result_label = "VULNERABLE"
        elif vulnerable is False:
            result_label = "SAFE"
        else:
            result_label = "INCONCLUSIVE"
        self._log(f"  Result: {result_label}")
        self._log(f"  Deterministic evidence: {evidence}")
        
        return {
            "vulnerable": vulnerable,
            "sqlmap_command": sqlmap_command,
            "log_file": str(log_file),
            "summary": summary,
            "analysis": evidence,
            "evidence": evidence,
            "detection_method": execution_result.get(
                "detection_method",
                "sqlmap_output",
            )
        }
    
    def _generate_sqlmap_command(self, task_description: str,
                                 target_request: Dict[str, Any],
                                 credentials: Dict[str, Any]) -> str:
        """
        LLMsqlmap

        Returns:
            sqlmap
        """
        from attack_agent.request_utils import format_credentials_for_display
        credentials_info = format_credentials_for_display(credentials)

        abs_log_dir = self.log_dir.resolve().as_posix()

        req_body = target_request.get("body")
        if not req_body:
            body_str = "None"
        elif isinstance(req_body, (dict, list)):
            body_str = json.dumps(req_body, indent=2)
        else:
            body_str = str(req_body)
        prompt = self._analysis_prompt.format(
            task_description=task_description,
            log_dir=abs_log_dir,
            method=target_request.get("method", "GET"),
            url=target_request.get("url", ""),
            headers=json.dumps(target_request.get("headers", {}), indent=2),
            query_params=json.dumps(target_request.get("query_params", {}), indent=2),
            body=body_str,
            credentials_info=credentials_info
        )

        self._log(f"\n[Step 1: Generating SQLMap Command via LLM]")
        self._log(f"{'~'*70}")
        self._log(f"[LLM INPUT - Analysis Prompt]:")
        self._log(f"{prompt}")
        self._log(f"{'~'*70}\n")

        try:
            completion = self.client.chat.completions.create(
                model=get_model_name("attack_agent"),
                messages=[
                    {"role": "system", "content": "You are a SQL injection testing expert."},
                    {"role": "user", "content": prompt}
                ],
                temperature=get_temperature("attack_agent")
            )

            llm_output = completion.choices[0].message.content

            self._log(f"[LLM OUTPUT - Analysis Response]:")
            self._log(f"{'~'*70}")
            self._log(f"{llm_output}")
            self._log(f"{'~'*70}\n")

            command = self._parse_and_handle_file(llm_output, abs_log_dir)

            self._log(f"[Parsed SQLMap Command (before credentials)]:")
            self._log(f"  {command}\n")

            command = self._append_credentials_to_command(command, credentials)
            command = self._ensure_sqlmap_ignore_stdin(command)

            self._log(f"[Final SQLMap Command (with credentials)]:")
            self._log(f"  {command}\n")

            return command

        except Exception as e:
            self._log(f"[SQLi] LLM call failed: {e}")
            import traceback
            self._log(traceback.format_exc())
            return ""

    def _parse_and_handle_file(self, llm_output: str, log_dir_path: str) -> str:
        """
        : Prompt  Response Examples
        """
        import os
        
        self._log(f"[LLM Output Raw]:\n{llm_output}\n{'-'*30}")

        file_match = re.search(
            r'Request_File_Content:\s*\n(.+?)(?=\n\s*SQLMap_Command:)', 
            llm_output, 
            re.DOTALL | re.IGNORECASE
        )
        
        request_file_written = False
        if file_match:
            content = file_match.group(1).strip()
            if content.lower() != "none":
                content = re.sub(r'^```\w*\s*\n?', '', content)
                content = re.sub(r'\n?```\s*$', '', content)
                content = self._normalize_request_file_content(content)

                validation_error = self._validate_request_file_content(content)
                if validation_error:
                    self._log(f"[Error] Invalid generated request file: {validation_error}")
                    return ""
                
                file_path = Path(log_dir_path) / "target.req"
                try:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(content)
                    request_file_written = True
                    self._log(f"[File] Saved request to: {file_path}")
                except Exception as e:
                    self._log(f"[Error] Failed to save file: {e}")
                    return ""

        cmd_match = re.search(
            r'SQLMap_Command:\s*\n(.+?)(?:\n\s*\n|\Z)', 
            llm_output, 
            re.DOTALL | re.IGNORECASE
        )
        
        if cmd_match:
            raw_cmd = cmd_match.group(1).strip()
            clean_cmd = raw_cmd.replace('`', '').strip()
            
            clean_cmd = clean_cmd.replace('\\\n', ' ').replace('\\ \n', ' ')
            
            lines = [l.strip() for l in clean_cmd.splitlines() if l.strip()]
            if lines:
                command = lines[0]
                if re.search(r'(^|\s)-r(?:\s|=)', command) and not request_file_written:
                    self._log("[Error] SQLMap command uses -r but no valid request file was generated")
                    return ""
                return command
        
        return ""

    @staticmethod
    def _normalize_request_file_content(content: str) -> str:
        """Remove model-added Markdown whitespace without changing line order."""
        normalized = content.replace("\r\n", "\n").replace("\r", "\n")
        lines = [line.rstrip(" \t") for line in normalized.split("\n")]
        while lines and not lines[0]:
            lines.pop(0)
        while lines and not lines[-1]:
            lines.pop()
        return "\n".join(lines)

    @staticmethod
    def _validate_request_file_content(content: str) -> str:
        """Return an error message when generated raw HTTP is not sqlmap-usable."""
        lines = content.split("\n")
        if not lines or not re.fullmatch(r"[A-Z]+ \S+ HTTP/1\.[01]", lines[0]):
            return "request line must exactly match 'METHOD path HTTP/1.x'"

        try:
            separator_index = lines.index("")
        except ValueError:
            return "missing blank line between headers and body"

        header_lines = lines[1:separator_index]
        if not header_lines:
            return "missing HTTP headers"
        if not any(line.lower().startswith("host:") for line in header_lines):
            return "missing Host header"
        if any(":" not in line or line[:1].isspace() for line in header_lines):
            return "malformed or indented HTTP header"

        content_type = next(
            (line.split(":", 1)[1].strip() for line in header_lines
             if line.lower().startswith("content-type:")),
            "",
        )
        if "multipart/form-data" in content_type.lower():
            boundary_match = re.search(r"boundary=(?:\"([^\"]+)\"|([^;\s]+))", content_type, re.IGNORECASE)
            if not boundary_match:
                return "multipart Content-Type is missing a boundary"
            boundary = boundary_match.group(1) or boundary_match.group(2)
            body = "\n".join(lines[separator_index + 1:])
            if f"--{boundary}" not in body:
                return "multipart body does not contain the declared boundary"

        return ""

    def _append_credentials_to_command(self, base_command: str,
                                     credentials: Dict[str, Any]) -> str:
        """
        sqlmap(: Content-Type  Auth )
        """
        if not base_command:
            return ""

        parts = [base_command.rstrip()]
        
        if "--cookie" not in base_command.lower():
            cookies = credentials.get("cookies", [])
            if cookies:
                cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
                parts.append(f'--cookie "{cookie_str}"')

        
        headers_to_add = credentials.get("headers", {}).copy()
        
        if "Authorization" not in headers_to_add:
            from attack_agent.request_utils import extract_auth_token
            token = extract_auth_token(credentials)
            if token:
                headers_to_add["Authorization"] = f"Bearer {token}"

        for key, value in headers_to_add.items():
            header_flag_pattern = f"{key}:"
            
            if header_flag_pattern not in base_command:
                parts.append(f'-H "{key}: {value}"')

        return " ".join(parts)

    def _ensure_sqlmap_ignore_stdin(self, command: str) -> str:
        """
        Force sqlmap to use explicit -u/-r targets instead of parsing stdin.
        In automated runs stdin can be a pipe, which makes sqlmap switch to
        "using STDIN for parsing targets list" and skip the request file.
        """
        if not command:
            return command
        if "--ignore-stdin" in command:
            return command
        return f"{command.rstrip()} --ignore-stdin"
    
    def _execute_sqlmap(self, command: str, log_file: Path) -> Dict[str, Any]:
        """
        sqlmap()

        Returns:
            {summary: str}  {error: str}
        """
        self._log(f"[SQLi] Executing sqlmap...")
        self._log(f"[SQLi] Command: {command}")
        timeout_raw = os.environ.get("SEMSCANNER_SQLMAP_TIMEOUT", "600").strip().lower()
        if timeout_raw in _UNLIMITED_TIMEOUT_VALUES:
            timeout = None
        else:
            try:
                parsed_timeout = int(float(timeout_raw))
            except ValueError:
                self._log(f"[SQLi] Invalid SEMSCANNER_SQLMAP_TIMEOUT={timeout_raw!r}; using 600s")
                parsed_timeout = 600
            timeout = parsed_timeout if parsed_timeout > 0 else 600
        self._log(f"[SQLi] Timeout limit: {timeout}s" if timeout is not None else "[SQLi] Timeout limit: unlimited")

        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid
            )

            try:
                stdout, stderr = process.communicate(timeout=timeout) if timeout is not None else process.communicate()
            except subprocess.TimeoutExpired:
                stdout, stderr, cleanup_complete = kill_process_group_and_collect(process)
                cleanup_note = (
                    "process group killed"
                    if cleanup_complete
                    else "process group killed; pipe cleanup remained incomplete"
                )
                stderr = (stderr or "") + f"\nSQLMap timeout after {timeout} seconds; {cleanup_note}"
                with open(log_file, "w", encoding="utf-8") as f:
                    f.write("=== COMMAND ===\n")
                    f.write(command + "\n\n")
                    f.write("=== STDOUT ===\n")
                    f.write((stdout or "") + "\n\n")
                    f.write("=== STDERR ===\n")
                    f.write(stderr + "\n")
                extracted_info = extract_sqlmap_info(stdout or "")
                summary = format_summary(extracted_info)
                classification = classify_sqlmap_output(
                    stdout or "",
                    allow_negative=False,
                )

                self._log(f"[SQLi] Timeout after {timeout}s, log saved to: {log_file}")
                self._log(f"[SQLi] Deterministic partial-output verdict: {classification['vulnerable']}")
                self._log(f"[SQLi] Verdict evidence: {classification['evidence']}")

                result = {
                    "summary": summary,
                    "timeout": True,
                    **classification,
                }
                if classification["vulnerable"] is True:
                    result["warning"] = f"SQLMap timeout after {timeout} seconds"
                else:
                    result["error"] = f"SQLMap timeout after {timeout} seconds"
                return result

            with open(log_file, "w", encoding="utf-8") as f:
                f.write("=== COMMAND ===\n")
                f.write(command + "\n\n")
                f.write("=== STDOUT ===\n")
                f.write(stdout + "\n\n")
                if stderr:
                    f.write("=== STDERR ===\n")
                    f.write(stderr + "\n")

            extracted_info = extract_sqlmap_info(stdout)
            summary = format_summary(extracted_info)

            fatal_error = self._detect_sqlmap_execution_error(stdout, stderr)
            if fatal_error:
                self._log(f"[SQLi] Fatal execution error: {fatal_error}")
                return {"error": fatal_error, "summary": summary}

            classification = classify_sqlmap_output(stdout)

            self._log(f"[SQLi] Execution completed, log saved to: {log_file}")
            self._log(f"[SQLi] Summary length: {len(summary)} chars")
            self._log(f"[SQLi] Deterministic verdict: {classification['vulnerable']}")
            self._log(f"[SQLi] Verdict evidence: {classification['evidence']}")

            return {"summary": summary, **classification}

        except Exception as e:
            self._log(f"[SQLi] Execution error: {e}")
            import traceback
            self._log(f"[SQLi] Traceback: {traceback.format_exc()}")
            return {"error": str(e)}

    @staticmethod
    def _detect_sqlmap_execution_error(stdout: str, stderr: str) -> str:
        combined = f"{stdout}\n{stderr}".lower()
        for marker in _SQLMAP_FATAL_EXECUTION_MARKERS:
            if marker in combined:
                return f"SQLMap execution failed: {marker}"
        return ""
