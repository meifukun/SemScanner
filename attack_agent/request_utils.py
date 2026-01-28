"""
请求处理工具 - 优化版
"""

from typing import Dict, List, Optional, Any  # <--- 加上这个
from pathlib import Path
import json


def check_beacon_detection(token: str, log_file: str = "http_captured.txt") -> bool:
    """
    检查beacon日志文件中是否包含指定token

    用于CMDI和SSRF的漏洞验证：检查外部beacon服务器是否收到了带有token的回调

    Args:
        token: 要查找的token字符串
        log_file: beacon日志文件路径（默认http_captured.txt）

    Returns:
        True if token found in log, False otherwise
    """
    log_path = Path(log_file)

    if not log_path.exists():
        return False

    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            content = f.read()
            return token in content
    except Exception:
        return False


def append_credentials_to_command(base_command: str, credentials: Dict,
                                   command_type: str = "curl") -> str:
    """
    向命令追加凭证（统一函数，支持curl和sqlmap）

    Args:
        base_command: 基础命令（不含认证）
        credentials: 账户凭证 {cookies, headers, localStorage, sessionStorage}
        command_type: 命令类型 "curl" 或 "sqlmap"

    Returns:
        追加凭证后的完整命令
    """
    if not base_command:
        return base_command

    # ✅ 对于curl命令，自动添加 -s (silent) 选项以禁用进度条
    # 这样stderr中就不会包含curl的进度信息，避免干扰LLM判断
    if command_type == "curl" and base_command.strip().startswith("curl"):
        # 检查是否已有 -s 或 --silent
        if not ("-s " in base_command or " -s" in base_command or "--silent" in base_command):
            # 在curl命令后立即插入 -s
            base_command = base_command.replace("curl ", "curl -s ", 1)

        # ✅ 自动添加 --compressed 选项，让 curl 自动解压缩 gzip/deflate/br/zstd 响应
        # 避免 "utf-8 codec can't decode byte 0x8b" 错误
        if not ("--compressed" in base_command):
            # 在curl命令后立即插入 --compressed
            base_command = base_command.replace("curl ", "curl --compressed ", 1)

        # ✅ 自动添加 -w 参数以获取HTTP状态码
        # 在响应末尾追加 HTTP_STATUS:xxx 格式的状态码
        if not ("-w " in base_command or "--write-out" in base_command):
            # 在命令末尾添加（在所有其他参数之后）
            base_command = base_command.rstrip() + ' -w "\\nHTTP_STATUS:%{http_code}"'

    parts = [base_command.rstrip()]

    if not credentials:
        return " ".join(parts)

    # 检查是否已有凭证
    has_cookie = "-H \"Cookie:" in base_command or "-H 'Cookie:" in base_command or "--cookie" in base_command.lower()
    has_auth = "Authorization:" in base_command

    # 1. 追加 Cookie
    cookies = credentials.get("cookies", [])
    if cookies and not has_cookie:
        cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
        if command_type == "sqlmap":
            parts.append(f'--cookie "{cookie_str}"')
        else:  # curl
            parts.append(f'-H "Cookie: {cookie_str}"')

    # 2. 追加 Authorization（优先使用headers中的，其次从storage提取）
    headers = credentials.get("headers", {})
    if "Authorization" in headers and not has_auth:
        parts.append(f'-H "Authorization: {headers["Authorization"]}"')
    elif not has_auth:
        # 从 localStorage/sessionStorage 提取 token
        token = extract_auth_token(credentials)
        if token:
            parts.append(f'-H "Authorization: Bearer {token}"')

    return " ".join(parts)


def append_credentials_to_curl(curl_command: str, credentials: Dict) -> str:
    """
    向 curl 命令追加凭证（兼容性包装）

    Args:
        curl_command: curl 命令（不含认证）
        credentials: 账户凭证

    Returns:
        追加凭证后的完整命令
    """
    return append_credentials_to_command(curl_command, credentials, command_type="curl")


def append_credentials_to_sqlmap(sqlmap_command: str, credentials: Dict) -> str:
    """
    向 sqlmap 命令追加凭证（便捷函数）

    Args:
        sqlmap_command: sqlmap 命令（不含认证）
        credentials: 账户凭证

    Returns:
        追加凭证后的完整命令
    """
    return append_credentials_to_command(sqlmap_command, credentials, command_type="sqlmap")


# def extract_auth_token(credentials: Dict) -> Optional[str]:
#     """
#     从localStorage/sessionStorage中智能提取认证token
    
#     优先级：
#     1. 包含 "token" 的键
#     2. 包含 "auth" 的键
#     3. 包含 "jwt" 的键
#     4. 包含 "access" 的键
    
#     Returns:
#         提取到的token字符串，或None
#     """
#     # 合并 localStorage 和 sessionStorage
#     all_storage = {}
#     all_storage.update(credentials.get("localStorage", {}))
#     all_storage.update(credentials.get("sessionStorage", {}))
    
#     # 按优先级搜索
#     keywords = ['token', 'auth', 'jwt', 'access', 'refresh']
    
#     for keyword in keywords:
#         for key, value in all_storage.items():
#             if keyword in key.lower() and value:
#                 # 过滤掉明显不是token的值（太短或太长）
#                 if isinstance(value, str) and 10 < len(value) < 2000:
#                     return value
    
#     return None

def extract_auth_token(credentials: Dict) -> Optional[str]:
    """
    从localStorage/sessionStorage中智能提取认证token（修复版）
    
    改进策略：
    1. 引入优先级：优先匹配 access_token, authorization 等明确字段
    2. 增加校验：过滤 JSON 对象、过短字符串、refresh_token
    3. 排除干扰：避免提取到 auth_time, token_type 等无关字段
    
    Returns:
        提取到的token字符串，或None
    """
    # 合并 localStorage 和 sessionStorage
    all_storage = {}
    all_storage.update(credentials.get("localStorage", {}))
    all_storage.update(credentials.get("sessionStorage", {}))
    
    if not all_storage:
        return None

    # 定义辅助验证函数
    def _is_valid_token_format(value: Any) -> bool:
        if not isinstance(value, str):
            return False
        
        val = value.strip()
        
        # 1. 过滤掉 JSON 对象/数组 (例如 {"token": "..."} 或 ["..."])
        # 目前只提取纯字符串形式的 Token，不深入解析 JSON 内部
        if val.startswith('{') or val.startswith('['):
            return False
            
        # 2. 过滤掉布尔值和空值字符串
        if val.lower() in ['true', 'false', 'null', 'undefined', 'nan']:
            return False
            
        # 3. 长度校验
        # JWT 通常很长，普通 Session ID 也有一定长度
        # 太短的通常是 type="bearer" 或 expires_in="3600"
        if len(val) < 10 or len(val) > 5000:
            return False
            
        return True

    # =======================================================
    # Round 1: 高优先级精确匹配
    # 目标：命中概率极高的标准字段
    # =======================================================
    high_priority_keywords = ['access_token', 'id_token', 'authorization', 'bearer_token']
    
    for key, value in all_storage.items():
        k_lower = key.lower()
        
        # 排除 refresh token (通常不能直接用于 API 请求)
        if 'refresh' in k_lower:
            continue
            
        # 检查是否包含高优先级关键词
        if any(keyword == k_lower or k_lower.endswith(f"_{keyword}") or k_lower.endswith(f".{keyword}") for keyword in high_priority_keywords):
            if _is_valid_token_format(value):
                return value.strip('"').strip("'") # 去除可能的额外引号

    # =======================================================
    # Round 2: 中优先级模糊匹配 (JWT)
    # 目标：根据 Value 的特征（ey...）反向查找
    # =======================================================
    for key, value in all_storage.items():
        if isinstance(value, str) and value.strip().startswith('eyJh'):  # JWT Header "{"alg"..." base64 coded
            if _is_valid_token_format(value):
                return value.strip('"').strip("'")

    # =======================================================
    # Round 3: 低优先级宽泛匹配
    # 目标：token, auth, session 等通用词
    # =======================================================
    low_priority_keywords = ['token', 'auth', 'jwt', 'session', 'key']
    
    for key, value in all_storage.items():
        k_lower = key.lower()
        
        # 再次排除 refresh token 和一些干扰项
        # type, time, date, expire 通常是数字或短字符串
        if any(x in k_lower for x in ['refresh', 'type', 'time', 'date', 'expire', 'config', 'user_info']):
            continue
            
        if any(keyword in k_lower for keyword in low_priority_keywords):
            if _is_valid_token_format(value):
                return value.strip('"').strip("'")
    
    return None


def format_credentials_for_display(credentials: Dict) -> str:
    """
    格式化凭证用于日志显示
    
    Returns:
        可读的凭证摘要字符串
    """
    lines = []
    
    # Cookies
    cookies = credentials.get("cookies", [])
    if cookies:
        lines.append(f"Cookies ({len(cookies)}):")
        for c in cookies[:3]:  # 只显示前3个
            value_preview = c['value'][:15] + "..." if len(c['value']) > 15 else c['value']
            lines.append(f"  - {c['name']}={value_preview}")
        if len(cookies) > 3:
            lines.append(f"  ... and {len(cookies) - 3} more")
    
    # Headers
    headers = credentials.get("headers", {})
    if headers:
        lines.append(f"\nHeaders ({len(headers)}):")
        for key, value in list(headers.items())[:3]:
            value_preview = str(value)[:30] + "..." if len(str(value)) > 30 else str(value)
            lines.append(f"  - {key}: {value_preview}")
    
    # Storage Tokens
    token = extract_auth_token(credentials)
    if token:
        lines.append(f"\nAuth Token:")
        token_preview = token[:20] + "..." if len(token) > 20 else token
        lines.append(f"  - {token_preview}")
    
    # localStorage/sessionStorage summary
    local_storage = credentials.get("localStorage", {})
    session_storage = credentials.get("sessionStorage", {})
    if local_storage or session_storage:
        total_keys = len(local_storage) + len(session_storage)
        lines.append(f"\nStorage: {total_keys} keys total")
        lines.append(f"  - localStorage: {len(local_storage)} keys")
        lines.append(f"  - sessionStorage: {len(session_storage)} keys")
    
    return "\n".join(lines) if lines else "No credentials"


def format_credentials_for_llm(credentials: Dict) -> str:
    """
    格式化凭证用于LLM prompt（更详细）
    
    Returns:
        适合放入prompt的凭证信息
    """
    lines = []
    
    # Cookies（列出所有）
    cookies = credentials.get("cookies", [])
    if cookies:
        lines.append(f"Cookies:")
        for c in cookies:
            lines.append(f"  {c['name']}={c['value']}")
    
    # Headers
    headers = credentials.get("headers", {})
    if headers:
        lines.append(f"\nHeaders:")
        for key, value in headers.items():
            lines.append(f"  {key}: {value}")
    
    # Storage（只列出可能的token）
    token = extract_auth_token(credentials)
    if token:
        lines.append(f"\nAuth Token (from storage):")
        lines.append(f"  {token}")
    
    return "\n".join(lines) if lines else "No credentials available"


def safe_replace_payload(template: str, payload: str) -> str:
    """
    在 curl 命令模板中安全地替换 {PAYLOAD}

    策略：
    - 检测 {PAYLOAD} 是否在 URL 中（http://... 或 https://...）
    - 如果在 URL 中：进行 URL 编码（safe=''，编码所有特殊字符）
    - 如果在其他位置（POST body, header）：不编码

    Args:
        template: curl 命令模板（包含 {PAYLOAD} 占位符）
        payload: 要插入的 payload 字符串

    Returns:
        替换后的命令字符串
    """
    from urllib.parse import quote
    import shlex

    # 使用 shlex 解析命令（正确处理引号）
    try:
        args = shlex.split(template)
    except ValueError:
        # 如果解析失败（引号不匹配等），fallback 到简单替换
        return template.replace('{PAYLOAD}', payload)

    # 遍历所有参数，找到包含 {PAYLOAD} 的参数
    for i, arg in enumerate(args):
        if '{PAYLOAD}' not in arg:
            continue

        # 判断 payload 位置
        if arg.startswith('http://') or arg.startswith('https://'):
            # 情况1：在 URL 中 → 需要 URL 编码
            safe_payload = quote(payload, safe='')  # 编码所有特殊字符
            args[i] = arg.replace('{PAYLOAD}', safe_payload)

        elif i > 0 and args[i-1] in ['-d', '--data', '--data-raw', '--data-binary']:
            # 情况2：在 POST body 中 → 不编码
            # （JSON/form 有自己的转义规则）
            args[i] = arg.replace('{PAYLOAD}', payload)

        elif i > 0 and args[i-1] in ['-H', '--header']:
            # 情况3：在 HTTP header 中 → 不编码
            # （HTTP header 不使用百分号编码）
            args[i] = arg.replace('{PAYLOAD}', payload)

        else:
            # 情况4：未知位置 → 保守起见不编码
            args[i] = arg.replace('{PAYLOAD}', payload)

    # 重新组合为命令字符串（带引号保护）
    return ' '.join(shlex.quote(arg) for arg in args)


def execute_curl_safe(template: str, payload: str, credentials: Dict,
                      timeout: int = 15) -> tuple:
    """
    安全执行 curl 命令（避免 shell 注入和引号问题）

    工作流程：
    1. 使用 safe_replace_payload 安全替换 payload（根据位置决定是否 URL 编码）
    2. 使用 shlex.split 解析命令为参数列表
    3. 添加凭证（作为独立参数）
    4. 使用 shell=False 执行（避免 shell 解析引号、空格等）

    Args:
        template: curl 命令模板（包含 {PAYLOAD}）
        payload: 要插入的 payload
        credentials: 凭证字典
        timeout: 超时时间（秒）

    Returns:
        (stdout, stderr, returncode, final_cmd) 元组
        - final_cmd 是最终执行的完整 curl 命令字符串（可直接复制到 shell 执行）
    """
    import subprocess
    import shlex

    # Step 1: 安全替换 payload（自动处理 URL 编码）
    filled_cmd = safe_replace_payload(template, payload)

    # 默认 final_cmd：先用填充后的字符串兜底
    final_cmd = filled_cmd

    # Step 2: 解析为参数列表
    try:
        args = shlex.split(filled_cmd)
    except ValueError as e:
        # 如果解析失败，返回错误，同时把 filled_cmd 当作 final_cmd 返回，方便排查
        return "", f"Failed to parse command: {e}", 1, final_cmd

    # Step 3: 添加凭证（作为独立参数）
    args = _append_credentials_to_args(args, credentials)

    # 此时 args 已经是最终执行的参数列表，可以构造真正的命令字符串
    final_cmd = " ".join(shlex.quote(a) for a in args)

    # Step 4: 使用 shell=False 执行
    try:
        process = subprocess.Popen(
            args,
            shell=False,  # 关键：不使用 shell
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate(timeout=timeout)
        return stdout, stderr, process.returncode, final_cmd

    except subprocess.TimeoutExpired:
        process.kill()
        return "", "Timeout expired", 124, final_cmd
    except Exception as e:
        return "", f"Execution failed: {e}", 1, final_cmd



def _append_credentials_to_args(args: List[str], credentials: Dict) -> List[str]:
    """
    将凭证添加为独立的命令行参数

    Args:
        args: 命令参数列表
        credentials: 凭证字典

    Returns:
        添加凭证后的参数列表
    """
    result = args.copy()

    # 检查是否已有凭证
    has_cookie = any('-H' in arg or '--header' in arg for arg in args) and \
                 any('Cookie:' in arg for arg in args)
    has_auth = any('Authorization:' in arg for arg in args)

    # 添加 Cookie
    cookies = credentials.get("cookies", [])
    if cookies and not has_cookie:
        cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
        result.extend(['-H', f'Cookie: {cookie_str}'])

    # 添加 Authorization
    headers = credentials.get("headers", {})
    if "Authorization" in headers and not has_auth:
        result.extend(['-H', f'Authorization: {headers["Authorization"]}'])
    elif not has_auth:
        # 从 storage 提取 token
        token = extract_auth_token(credentials)
        if token:
            result.extend(['-H', f'Authorization: Bearer {token}'])

    return result


def parse_http_status_from_response(response: str) -> tuple:
    """
    从curl响应中解析HTTP状态码

    curl命令使用了 -w "\\nHTTP_STATUS:%{http_code}"，
    状态码会被追加到响应末尾，格式为：HTTP_STATUS:200

    Args:
        response: curl命令的stdout输出

    Returns:
        (http_status_code: int, response_body: str) 元组
        如果未找到状态码，返回 (None, response)
    """
    import re

    # 查找 HTTP_STATUS:xxx 模式（在响应末尾）
    pattern = r'\nHTTP_STATUS:(\d+)$'
    match = re.search(pattern, response)

    if match:
        http_code = int(match.group(1))
        # 去掉状态码部分，只保留响应体
        response_body = response[:match.start()]
        return (http_code, response_body)
    else:
        # 没有找到状态码（可能是旧的curl命令或执行失败）
        return (None, response)


def extract_useful_response(response: str, max_length: int = 3000) -> str:
    """
    从HTTP响应中智能提取有用信息，避免token超限

    主要用于LLM研判时减少无用的HTML标签、CSS、JS等内容。

    策略：
    1. 输入验证和边界处理
    2. 检测响应类型（HTML / JSON / 纯文本）
    3. 如果是HTML：提取标题、错误信息、可见文本
    4. 如果是JSON：保留完整JSON（通常有价值）
    5. 如果是纯文本：直接截断
    6. 确保总长度不超过max_length

    Args:
        response: HTTP响应内容
        max_length: 最大返回长度（默认3000字符）

    Returns:
        提取后的文本（≤ max_length字符）

    Examples:
        >>> html = "<html><title>Error</title><body>Invalid input</body></html>"
        >>> extract_useful_response(html, 100)
        '[Title] Error\\n\\n[Error/Alert] Invalid input'
    """
    import re

    max_length = 10000

    # 1. 边界处理
    if not response:
        return ""

    if not isinstance(response, str):
        response = str(response)

    # 如果响应已经很短，直接返回
    if len(response) <= max_length:
        # 但仍然尝试清理HTML（如果是HTML的话）
        if _is_html_response(response):
            return _extract_from_html_response(response, max_length)
        return response

    # 2. 检测响应类型并处理
    if _is_html_response(response):
        return _extract_from_html_response(response, max_length)
    elif _is_json_response(response):
        # JSON通常有价值，尽量保留完整
        return response[:max_length]
    else:
        # 纯文本，直接截断
        return response[:max_length]


def _is_html_response(text: str) -> bool:
    """
    检测响应是否为HTML格式

    使用多个指标综合判断，避免误判。

    Args:
        text: 响应文本

    Returns:
        True if 看起来像HTML, False otherwise
    """
    if not text:
        return False

    # 转小写便于匹配
    text_lower = text.lower()

    # HTML特征指标（只要匹配2个以上就认为是HTML）
    html_indicators = [
        '<!doctype' in text_lower,
        '<html' in text_lower,
        '<head>' in text_lower or '<head ' in text_lower,
        '<body>' in text_lower or '<body ' in text_lower,
        '<div' in text_lower,
        '<script' in text_lower,
        '<style' in text_lower,
    ]

    # 统计匹配数
    match_count = sum(html_indicators)

    return match_count >= 2


def _is_json_response(text: str) -> bool:
    """
    检测响应是否为JSON格式

    Args:
        text: 响应文本

    Returns:
        True if 看起来像JSON, False otherwise
    """
    if not text:
        return False

    text_stripped = text.strip()

    # JSON通常以 { 或 [ 开头
    if not (text_stripped.startswith('{') or text_stripped.startswith('[')):
        return False

    # 尝试解析JSON（但不抛出异常）
    try:
        json.loads(text_stripped)
        return True
    except (json.JSONDecodeError, ValueError):
        return False


def _extract_from_html_response(html: str, max_length: int) -> str:
    """
    从HTML响应中提取有用信息

    优先提取：
    1. <title>标签内容
    2. 包含错误/警告关键词的文本
    3. 可见文本（去除script、style等）

    Args:
        html: HTML响应文本
        max_length: 最大长度

    Returns:
        提取后的文本
    """
    import re

    extracted_parts = []
    remaining_length = max_length

    # 1. 提取<title>内容
    title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    if title_match:
        title = title_match.group(1).strip()
        if title:
            title_clean = _clean_html_text(title)
            extracted_parts.append(f"[Title] {title_clean}")
            remaining_length -= len(extracted_parts[-1]) + 2  # +2 for \n\n

    # 2. 提取错误/警告信息（优先级最高）
    error_keywords = [
        'error', 'exception', 'invalid', 'forbidden', 'denied',
        'failed', 'alert', 'warning', 'violation', 'rejected',
        'unauthorized', 'not found', 'bad request'
    ]

    # 查找包含错误关键词的段落/div/span等
    # 匹配常见的错误信息容器
    error_pattern = r'<(?:div|p|span|li|td|h\d)[^>]*?(?:class|id)=["\']?[^"\']*(?:' + '|'.join(error_keywords) + r')[^"\']*["\']?[^>]*>(.*?)</(?:div|p|span|li|td|h\d)>'

    error_matches = re.finditer(error_pattern, html, re.IGNORECASE | re.DOTALL)

    for match in error_matches:
        if remaining_length <= 100:  # 保留至少100字符给body
            break

        error_text = match.group(1)
        error_clean = _clean_html_text(error_text)

        # 跳过太短或太长的片段
        if 5 < len(error_clean) < 500:
            extracted_parts.append(f"[Error/Alert] {error_clean}")
            remaining_length -= len(extracted_parts[-1]) + 2

    # 3. 如果没找到特定错误信息，提取body的可见文本
    if not extracted_parts or remaining_length > 500:
        # 移除script、style、注释等
        html_cleaned = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.IGNORECASE | re.DOTALL)
        html_cleaned = re.sub(r'<style[^>]*>.*?</style>', '', html_cleaned, flags=re.IGNORECASE | re.DOTALL)
        html_cleaned = re.sub(r'<!--.*?-->', '', html_cleaned, flags=re.DOTALL)

        # 提取body内容（如果有）
        body_match = re.search(r'<body[^>]*>(.*?)</body>', html_cleaned, re.IGNORECASE | re.DOTALL)
        if body_match:
            body_html = body_match.group(1)
        else:
            body_html = html_cleaned

        # 清理HTML标签，提取文本
        body_text = _clean_html_text(body_html)

        # 分割成行，去除空行
        lines = [line.strip() for line in body_text.split('\n') if line.strip()]

        # 取前N行（确保不超过remaining_length）
        body_preview_lines = []
        current_length = 0
        for line in lines[:30]:  # 最多30行
            if current_length + len(line) + 1 > remaining_length:
                break
            body_preview_lines.append(line)
            current_length += len(line) + 1

        if body_preview_lines:
            body_preview = '\n'.join(body_preview_lines)
            if not extracted_parts:
                # 如果没有其他内容，直接返回body
                extracted_parts.append(body_preview)
            else:
                # 作为补充添加
                extracted_parts.append(f"[Body Preview]\n{body_preview}")

    # 组合所有提取的部分
    result = '\n\n'.join(extracted_parts)

    # 确保不超过max_length
    if len(result) > max_length:
        result = result[:max_length]

    return result


def _clean_html_text(html: str) -> str:
    """
    清理HTML文本，移除标签和多余空白

    Args:
        html: 包含HTML标签的文本

    Returns:
        清理后的纯文本
    """
    import re

    # 移除所有HTML标签
    text = re.sub(r'<[^>]+>', '', html)

    # 解码常见HTML实体
    html_entities = {
        '&lt;': '<',
        '&gt;': '>',
        '&amp;': '&',
        '&quot;': '"',
        '&#39;': "'",
        '&apos;': "'",
        '&nbsp;': ' ',
        '&#x2713;': '✓',
    }

    for entity, char in html_entities.items():
        text = text.replace(entity, char)

    # 清理多余的空白
    text = re.sub(r'\s+', ' ', text)
    text = text.strip()

    return text