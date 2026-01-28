"""
SQL注入Agent - 完整版（包含研判）
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
    从sqlmap日志中提取关键信息
    按状态码和响应内容分组

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
            'last_10_lines': str  # 新增：最后10行
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

    # ✅ 新增：提取最后10行（去除空行）
    non_empty_lines = [line for line in lines if line.strip()]
    if non_empty_lines:
        results['last_20_lines'] = '\n'.join(non_empty_lines[-20:])

    while i < len(lines):
        line = lines[i].strip()

        # 匹配 TRAFFIC IN 行，提取状态码
        m = re.search(traffic_in_pattern, line)
        if m:
            status_code = m.group(1)
            response_info = {'body': '', 'example_request': None}

            i += 1
            # 跳过响应头
            while i < len(lines):
                cur = lines[i]
                if not cur.strip():
                    i += 1
                    break
                if cur.strip().startswith('['):
                    break
                i += 1

            # 读取响应体
            body_lines = []
            while i < len(lines) and not lines[i].strip().startswith('['):
                body_lines.append(lines[i].strip())
                i += 1

            response_info['body'] = '\n'.join(body_lines).strip()

            # 按响应体内容分组
            response_key = response_info['body']
            results['by_status'][status_code][response_key].append(response_info)

            continue

        # 提取CRITICAL信息
        crit_m = re.search(r'\[CRITICAL\]\s*(.+)', line)
        if crit_m:
            results['critical_info'] = crit_m.group(1).strip()

        i += 1

    return results


def format_summary(results: Dict) -> str:
    """
    格式化提取的摘要信息
    限制：总示例数不超过10个

    Returns:
        格式化的字符串
    """
    by_status = results.get('by_status', {})
    if not by_status:
        # ✅ 如果没有HTTP响应，返回最后20行
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

        # 计算该状态码下的总请求数
        unique_responses = list(responses.values())
        count = sum(len(group) for group in unique_responses)
        summary_lines.append(f"   Occurrences: {count}")

        # 从每种响应内容中选取示例
        response_examples = []
        for group in unique_responses:
            if len(response_examples) >= 10 - total_count:
                break
            response_examples.append(group[0])

        # 展示示例
        for s_idx, resp in enumerate(response_examples, start=1):
            summary_lines.append(f"   Example {s_idx}:")
            # ✅ 不截断body，保留完整内容供LLM判断
            body_original = resp['body']
            body_extracted = extract_useful_response(body_original, max_length=2000)
            summary_lines.append(f"     Body:")
            for line in body_extracted.splitlines():
                summary_lines.append(f"       {line}")

        total_count += len(response_examples)

    if results.get('critical_info'):
        summary_lines.append("\nFinal Critical Information:")
        summary_lines.append(f"  {results['critical_info']}")

    # ✅ 新增：添加最后10行
    last_10 = results.get('last_20_lines', '')
    if last_10:
        summary_lines.append("\n" + "=" * 70)
        summary_lines.append("Last 20 lines of log:")
        summary_lines.append("=" * 70)
        summary_lines.append(last_10)

    return "\n".join(summary_lines)


class SQLInjectionAgent:
    """
    SQL注入测试Agent - 完整版
    
    职责：
    1. 接收AttackTask（任务描述+完整请求）
    2. 根据任务描述构造sqlmap命令
    3. 执行sqlmap
    4. 提取日志关键信息
    5. 调用LLM研判是否存在漏洞
    """
    
    def __init__(self, client, log_dir: str = "output/attack_logs/sql",
                 analysis_prompt_path: str = "prompt/sql_agent_attack.txt",
                 judgment_prompt_path: str = "prompt/sql_agent_judge.txt"):
        self.client = client
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._log_path = self.log_dir / "sql_agent.log"

        # ✅ 从文件加载prompt（而不是硬编码）
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
        """从文件加载prompt"""
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    
    def test(self, task_description: str,
            target_request: Dict[str, Any],
            credentials: Dict[str, Any]) -> Dict[str, Any]:
        """
        测试SQL注入

        Args:
            task_description: 任务描述
            target_request: 完整请求对象
            credentials: 账户凭证

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
        # ✅ 添加这两行
        response_body = str(target_request.get('response_body', ''))[:2000]
        self._log(f"    Response Body (preview): {response_body}{'...(truncated)' if len(str(target_request.get('response_body', ''))) > 2000 else ''}")
        self._log(f"  Credentials: {json.dumps(credentials, indent=6, default=str)}")
        self._log(f"")
        
        # 步骤1: 调用LLM生成sqlmap命令
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
        
        # 步骤2: 执行sqlmap
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
        
        # 步骤3: 提取日志关键信息
        summary = execution_result.get("summary", "")
        
        self._log(f"  Log summary extracted ({len(summary)} chars)")
        
        # 步骤4: 调用LLM研判
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
    
    # def _generate_sqlmap_command(self, task_description: str,
    #                              target_request: Dict[str, Any],
    #                              credentials: Dict[str, Any]) -> str:
    #     """
    #     调用LLM生成sqlmap命令

    #     Returns:
    #         sqlmap命令字符串
    #     """
    #     # 格式化凭证信息
    #     from attack_agent.request_utils import format_credentials_for_display
    #     credentials_info = format_credentials_for_display(credentials)

    #     # 构造prompt
    #     prompt = self._analysis_prompt.format(
    #         task_description=task_description,
    #         method=target_request.get("method", "GET"),
    #         url=target_request.get("url", ""),
    #         headers=json.dumps(target_request.get("headers", {}), indent=2),
    #         query_params=json.dumps(target_request.get("query_params", {}), indent=2),
    #         body=json.dumps(target_request.get("body", {}), indent=2) if target_request.get("body") else "None",
    #         credentials_info=credentials_info
    #     )

    #     self._log(f"\n[Step 1: Generating SQLMap Command via LLM]")
    #     self._log(f"{'~'*70}")
    #     self._log(f"[LLM INPUT - Analysis Prompt]:")
    #     self._log(f"{prompt}")
    #     self._log(f"{'~'*70}\n")

    #     try:
    #         completion = self.client.chat.completions.create(
    #             model=get_model_name("attack_agent"),
    #             messages=[
    #                 {"role": "system", "content": "You are a SQL injection testing expert."},
    #                 {"role": "user", "content": prompt}
    #             ],
    #             temperature=get_temperature("attack_agent")
    #         )

    #         llm_output = completion.choices[0].message.content

    #         self._log(f"[LLM OUTPUT - Analysis Response]:")
    #         self._log(f"{'~'*70}")
    #         self._log(f"{llm_output}")
    #         self._log(f"{'~'*70}\n")

    #         # 解析SQLMap_Command部分
    #         command = self._parse_sqlmap_command(llm_output)

    #         self._log(f"[Parsed SQLMap Command (before credentials)]:")
    #         self._log(f"  {command}\n")

    #         # ✅ 追加凭证信息（使用统一的函数）
    #         from attack_agent.request_utils import append_credentials_to_sqlmap
    #         command = append_credentials_to_sqlmap(command, credentials)

    #         self._log(f"[Final SQLMap Command (with credentials)]:")
    #         self._log(f"  {command}\n")

    #         return command

    #     except Exception as e:
    #         self._log(f"[SQLi] LLM call failed: {e}")
    #         import traceback
    #         self._log(traceback.format_exc())
    #         return ""
    
    def _generate_sqlmap_command(self, task_description: str,
                                 target_request: Dict[str, Any],
                                 credentials: Dict[str, Any]) -> str:
        """
        调用LLM生成sqlmap命令

        Returns:
            sqlmap命令字符串
        """
        # 格式化凭证信息
        from attack_agent.request_utils import format_credentials_for_display
        credentials_info = format_credentials_for_display(credentials)

        # ✅ 1. 获取绝对路径，并统一使用正斜杠（防止Windows路径反斜杠被转义问题）
        abs_log_dir = self.log_dir.resolve().as_posix()

        # ✅ 2. 渲染Prompt，将 abs_log_dir 填入 {log_dir}
        # 获取 body
        req_body = target_request.get("body")
        if not req_body:
            body_str = "None"
        elif isinstance(req_body, (dict, list)):
            # 如果是字典/列表，转 JSON 字符串
            body_str = json.dumps(req_body, indent=2)
        else:
            # 如果已经是字符串（如 raw multipart），直接使用
            body_str = str(req_body)
        # 注意：Prompt模板里现在有 {log_dir} 占位符
        prompt = self._analysis_prompt.format(
            task_description=task_description,
            log_dir=abs_log_dir,  # <--- 关键：告诉LLM文件存哪，以及命令里写哪个路径
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

            # ✅ 3. 解析并处理文件
            command = self._parse_and_handle_file(llm_output, abs_log_dir)

            self._log(f"[Parsed SQLMap Command (before credentials)]:")
            self._log(f"  {command}\n")

            # ✅ 追加凭证信息（使用统一的函数）
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
        解析逻辑：与 Prompt 的 Response Examples 严丝合缝
        """
        import os
        
        self._log(f"[LLM Output Raw]:\n{llm_output}\n{'-'*30}")

        # ✅ 正则 1: 提取文件内容
        # 匹配规则：从 Request_File_Content: 换行后开始，直到 SQLMap_Command: 前为止
        file_match = re.search(
            r'Request_File_Content:\s*\n(.+?)(?=\n\s*SQLMap_Command:)', 
            llm_output, 
            re.DOTALL | re.IGNORECASE
        )
        
        if file_match:
            content = file_match.group(1).strip()
            # 如果内容不是 "None"，则写入文件
            if content.lower() != "none":
                # 清理可能存在的 Markdown 代码块符号
                content = re.sub(r'^```\w*\s*\n?', '', content)
                content = re.sub(r'\n?```\s*$', '', content)
                
                # 写入 target.req
                file_path = Path(log_dir_path) / "target.req"
                try:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(content)
                    self._log(f"[File] Saved request to: {file_path}")
                except Exception as e:
                    self._log(f"[Error] Failed to save file: {e}")

        # ✅ 正则 2: 提取命令
        cmd_match = re.search(
            r'SQLMap_Command:\s*\n(.+?)(?:\n\s*\n|\Z)', 
            llm_output, 
            re.DOTALL | re.IGNORECASE
        )
        
        if cmd_match:
            raw_cmd = cmd_match.group(1).strip()
            # 清理 Markdown 和 多余符号
            clean_cmd = raw_cmd.replace('`', '').strip()
            
            # 移除可能的多行反斜杠
            clean_cmd = clean_cmd.replace('\\\n', ' ').replace('\\ \n', ' ')
            
            # 提取第一行有效命令
            lines = [l.strip() for l in clean_cmd.splitlines() if l.strip()]
            if lines:
                return lines[0]
        
        return ""

    def _parse_sqlmap_command(self, llm_output: str) -> str:
        """
        从LLM输出中提取sqlmap命令（增强版 - 处理各种格式）
        Returns:
            sqlmap命令字符串
        """
        # 查找SQLMap_Command部分
        match = re.search(r'SQLMap_Command:\s*\n(.+?)(?:\n\s*\n|\Z)', llm_output, re.DOTALL)
        if not match:
            self._log("[WARN] No SQLMap_Command section found in LLM output")
            return ""
        
        command_text = match.group(1).strip()
        original_text = command_text  # 保存原始文本用于日志
        
        # ✅ 1. 移除代码块标记
        command_text = re.sub(r'^```(?:bash|sh|shell)?\s*\n?', '', command_text, flags=re.IGNORECASE)
        command_text = re.sub(r'\n?```\s*$', '', command_text)
        
        # ✅ 2. 移除反引号（成对移除）
        command_text = command_text.strip('`')
        command_text = command_text.replace('`', '')
        
        # ✅ 3. 移除引号包裹（成对移除）
        command_text = command_text.strip()
        if (command_text.startswith('"') and command_text.endswith('"')) or \
        (command_text.startswith("'") and command_text.endswith("'")):
            command_text = command_text[1:-1]
        
        # ✅ 4. 移除Shell提示符
        command_text = re.sub(r'^\$\s+', '', command_text)
        
        # ✅ 5. 移除行号
        command_text = re.sub(r'^\d+[\.)]\s+', '', command_text)
        
        # ✅ 6. 处理多行命令（移除反斜杠续行符）
        command_text = command_text.replace('\\\n', ' ').replace('\\ \n', ' ')
        
        # ✅ 7. 压缩多余空格
        command_text = re.sub(r'\s+', ' ', command_text).strip()
        
        # 记录清理前后的对比
        if original_text != command_text:
            self._log(f"[DEBUG] Command cleaned:")
            self._log(f"  Before: {original_text[:200]}...")
            self._log(f"  After:  {command_text[:200]}...")
        
        # 提取sqlmap命令行
        lines = [line.strip() for line in command_text.splitlines() if line.strip()]
        
        for line in lines:
            # 再次清理该行（防止多行情况）
            cleaned_line = line.strip('`').strip('"').strip("'").replace('`', '')  # ✅ 修复：'`'
            cleaned_line = re.sub(r'^\$\s+', '', cleaned_line)
            cleaned_line = re.sub(r'^\d+[\.)]\s+', '', cleaned_line)
            
            self._log(f"[DEBUG] Final extracted command: {cleaned_line[:200]}...")
            return cleaned_line
        
        # 如果没有找到，尝试返回第一行
        if lines:
            cleaned_first = lines[0].strip('`').strip('"').strip("'").replace('`', '')  # ✅ 修复：'`'
            cleaned_first = re.sub(r'^\$\s+', '', cleaned_first)
            cleaned_first = re.sub(r'^\d+[\.)]\s+', '', cleaned_first)
            self._log(f"[DEBUG] Fallback to first line: {cleaned_first[:200]}...")
            return cleaned_first
        
        self._log("[ERROR] No valid sqlmap command found after cleaning")
        return ""
    
    # def _append_credentials_to_command(self, base_command: str,
    #                                   credentials: Dict[str, Any]) -> str:
    #     """
    #     向sqlmap命令追加凭证信息（✅ 改进版：支持从storage提取token）

    #     Args:
    #         base_command: LLM生成的基础命令
    #         credentials: 账户凭证

    #     Returns:
    #         完整的sqlmap命令
    #     """
    #     if not base_command:
    #         return ""

    #     parts = [base_command.rstrip()]

    #     # 检查命令中是否已有cookie/header
    #     has_cookie = "--cookie" in base_command.lower()
    #     has_header = "-H" in base_command or "--header" in base_command.lower()

    #     # 添加Cookie
    #     cookies = credentials.get("cookies", [])
    #     if cookies and not has_cookie:
    #         cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
    #         parts.append(f'--cookie "{cookie_str}"')

    #     # ✅ 添加自定义Header（优先headers，其次从storage提取Authorization）
    #     headers = credentials.get("headers", {})
    #     if headers and not has_header:
    #         for key, value in headers.items():
    #             parts.append(f'-H "{key}: {value}"')
    #     elif not has_header:
    #         # ✅ 如果headers中没有Authorization，尝试从storage提取
    #         from attack_agent.request_utils import extract_auth_token
    #         token = extract_auth_token(credentials)
    #         if token:
    #             parts.append(f'-H "Authorization: Bearer {token}"')

    #     return " ".join(parts)

    def _append_credentials_to_command(self, base_command: str,
                                     credentials: Dict[str, Any]) -> str:
        """
        向sqlmap命令追加凭证信息（修复版：解决 Content-Type 和 Auth 冲突问题）
        """
        if not base_command:
            return ""

        parts = [base_command.rstrip()]
        
        # 1. 处理 Cookie (逻辑不变)
        # 检查命令中是否已有 cookie 参数
        if "--cookie" not in base_command.lower():
            cookies = credentials.get("cookies", [])
            if cookies:
                cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
                parts.append(f'--cookie "{cookie_str}"')

        # 2. 处理 Headers (逻辑大改)
        # 我们不再检查 has_header，而是检查具体的 Key 是否存在
        
        # 获取所有需要添加的 Header
        headers_to_add = credentials.get("headers", {}).copy()
        
        # 如果没有 Authorization header，尝试从 storage 提取 token
        if "Authorization" not in headers_to_add:
            from attack_agent.request_utils import extract_auth_token
            token = extract_auth_token(credentials)
            if token:
                headers_to_add["Authorization"] = f"Bearer {token}"

        # 遍历要添加的 Header，只有当命令里没有这个 Key 时才添加
        for key, value in headers_to_add.items():
            # 简单的字符串检查，防止重复添加
            # 注意：这里假设 header key 不会恰好出现在 URL 或其他参数里，通常是安全的
            header_flag_pattern = f"{key}:"
            
            if header_flag_pattern not in base_command:
                parts.append(f'-H "{key}: {value}"')

        return " ".join(parts)
    
    def _execute_sqlmap(self, command: str, log_file: Path) -> Dict[str, Any]:
        """
        执行sqlmap命令（无超时限制）

        Returns:
            {summary: str} 或 {error: str}
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

            # ✅ 移除timeout参数，让sqlmap自然完成
            stdout, stderr = process.communicate()

            # 写入日志文件
            with open(log_file, "w", encoding="utf-8") as f:
                f.write("=== COMMAND ===\n")
                f.write(command + "\n\n")
                f.write("=== STDOUT ===\n")
                f.write(stdout + "\n\n")
                if stderr:
                    f.write("=== STDERR ===\n")
                    f.write(stderr + "\n")

            # 提取关键信息
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
        调用LLM研判SQL注入漏洞

        Returns:
            {vulnerable: bool, analysis: str}
        """
        # 构造prompt
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

            # 解析结论
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
        解析LLM输出判断是否有漏洞
        
        查找关键字：
        - "Vulnerability exists: Yes" -> True
        - "Vulnerability exists: No" -> False
        """
        match = re.search(r'Vulnerability exists:\s*(Yes|No)', llm_output, re.IGNORECASE)
        
        if match:
            return match.group(1).lower() == "yes"
        
        # 兜底：查找其他关键字
        if "vulnerability exists" in llm_output.lower():
            if "yes" in llm_output.lower():
                return True
            elif "no" in llm_output.lower():
                return False
        
        return False
