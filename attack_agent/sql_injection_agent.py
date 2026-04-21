"""
SQLAgent - ()
"""

from typing import Dict, Any, List
from pathlib import Path
import subprocess
import json
import re
from collections import defaultdict
from config.llm_config import get_model_name, get_temperature
from attack_agent.request_utils import extract_useful_response

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
    """
    SQLAgent -
    
    1. AttackTask(+)
    2. sqlmap
    3. sqlmap
    4.
    5. LLM
    """
    
    def __init__(self, client, log_dir: str = "output/attack_logs/sql",
                 analysis_prompt_path: str = "prompt/sql_agent_attack.txt",
                 judgment_prompt_path: str = "prompt/sql_agent_judge.txt"):
        self.client = client
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._log_path = self.log_dir / "sql_agent.log"

        self._analysis_prompt = self._load_prompt_from_file(analysis_prompt_path)
        self._judgment_prompt = self._load_prompt_from_file(judgment_prompt_path)
    
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
        
        judgment = self._judge_vulnerability(
            task_description,
            sqlmap_command,
            summary
        )
        
        vulnerable = judgment.get("vulnerable", False)
        
        self._log(f"  Result: {'VULNERABLE' if vulnerable else 'SAFE'}")
        
        return {
            "vulnerable": vulnerable,
            "sqlmap_command": sqlmap_command,
            "log_file": str(log_file),
            "summary": summary,
            "analysis": judgment.get("analysis", "")
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
        
        if file_match:
            content = file_match.group(1).strip()
            if content.lower() != "none":
                content = re.sub(r'^```\w*\s*\n?', '', content)
                content = re.sub(r'\n?```\s*$', '', content)
                
                file_path = Path(log_dir_path) / "target.req"
                try:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(content)
                    self._log(f"[File] Saved request to: {file_path}")
                except Exception as e:
                    self._log(f"[Error] Failed to save file: {e}")

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
                return lines[0]
        
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
    
    def _execute_sqlmap(self, command: str, log_file: Path) -> Dict[str, Any]:
        """
        sqlmap()

        Returns:
            {summary: str}  {error: str}
        """
        self._log(f"[SQLi] Executing sqlmap...")
        self._log(f"[SQLi] Command: {command}")
        self._log(f"[SQLi] Note: No timeout limit - sqlmap will run until completion")

        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            stdout, stderr = process.communicate()

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

            self._log(f"[SQLi] Execution completed, log saved to: {log_file}")
            self._log(f"[SQLi] Summary length: {len(summary)} chars")

            return {"summary": summary}

        except Exception as e:
            self._log(f"[SQLi] Execution error: {e}")
            import traceback
            self._log(f"[SQLi] Traceback: {traceback.format_exc()}")
            return {"error": str(e)}
    
    def _judge_vulnerability(self, task_description: str,
                            sqlmap_command: str,
                            summary: str) -> Dict[str, Any]:
        """
        LLMSQL

        Returns:
            {vulnerable: bool, analysis: str}
        """
        prompt = self._judgment_prompt.format(
            task_description=task_description,
            sqlmap_command=sqlmap_command,
            summary=summary
        )

        self._log(f"\n[Step 2: Judging Vulnerability via LLM]")
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
            self._log(f"[SQLi] Judgment failed: {e}")
            import traceback
            self._log(traceback.format_exc())
            return {
                "vulnerable": None,
                "analysis": str(e)
            }
    
    def _parse_vulnerability_conclusion(self, llm_output: str) -> bool:
        """
        LLM
        
        - "Vulnerability exists: Yes" -> True
        - "Vulnerability exists: No" -> False
        """
        match = re.search(r'Vulnerability exists:\s*(Yes|No)', llm_output, re.IGNORECASE)
        
        if match:
            return match.group(1).lower() == "yes"
        
        if "vulnerability exists" in llm_output.lower():
            if "yes" in llm_output.lower():
                return True
            elif "no" in llm_output.lower():
                return False
        
        return False
