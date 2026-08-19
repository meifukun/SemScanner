"""
Request utility functions
"""

from typing import Dict, List, Optional, Any
from pathlib import Path
import json
import os
import signal
import subprocess


def _subprocess_output_as_text(value) -> str:
    """Normalize partial TimeoutExpired output for text-mode callers."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def kill_process_group_and_collect(process, cleanup_timeout: float = 3.0):
    """Kill a subprocess session and collect output without an unbounded wait.

    The subprocess must have been created with ``start_new_session=True`` (or
    an equivalent ``setsid`` call).  A killed shell/curl can otherwise leave a
    pipe descriptor open in a descendant, causing a bare ``communicate()`` to
    block forever during timeout cleanup.

    Returns ``(stdout, stderr, cleanup_complete)``.  Partial output is returned
    if the pipes still do not close within ``cleanup_timeout``.
    """
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            process.kill()
        except (ProcessLookupError, OSError):
            pass

    try:
        stdout, stderr = process.communicate(timeout=cleanup_timeout)
        return stdout or "", stderr or "", True
    except subprocess.TimeoutExpired as exc:
        stdout = _subprocess_output_as_text(exc.output)
        stderr = _subprocess_output_as_text(exc.stderr)

        # Do not call communicate() again: a descendant may still own one of
        # the pipe descriptors.  Closing our readers guarantees bounded local
        # cleanup even in that case.
        for stream in (getattr(process, "stdout", None), getattr(process, "stderr", None)):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

        try:
            process.kill()
        except (ProcessLookupError, OSError):
            pass
        try:
            process.wait(timeout=1.0)
        except (subprocess.TimeoutExpired, ChildProcessError):
            pass

        return stdout, stderr, False


def check_beacon_detection(token: str, log_file: str = "http_captured.txt") -> bool:
    """
    Check if beacon log contains the specified token

    Used for CMDI/SSRF verification: checks if beacon received callback with token

    Args:
        token: token string to search for
        log_file: beacon log file path (default: http_captured.txt)

    Returns:
        True if token found in log, False otherwise
    """
    candidates = []

    for env_name in ("SEMSCANNER_XSS_BEACON_LOG", "XSS_BEACON_LOG", "BEACON_LOG_FILE"):
        env_value = os.environ.get(env_name)
        if env_value:
            candidates.append(Path(env_value))

    if log_file:
        candidates.append(Path(log_file))

    seen = set()
    paths = []
    for path in candidates:
        key = str(path)
        if key not in seen:
            paths.append(path)
            seen.add(key)

    if not paths:
        return False

    for log_path in paths:
        if not log_path.exists():
            continue

        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                content = f.read()
                if token in content:
                    return True
        except Exception:
            continue

    return False


def append_credentials_to_command(base_command: str, credentials: Dict,
                                   command_type: str = "curl") -> str:
    """
    Append credentials to a command (supports curl and sqlmap)

    Args:
        base_command: base command (without auth)
        credentials: account credentials {cookies, headers, localStorage, sessionStorage}
        command_type: "curl" or "sqlmap"

    Returns:
        Returns complete command with credentials
    """
    if not base_command:
        return base_command

    if command_type == "curl" and base_command.strip().startswith("curl"):
        if not ("-s " in base_command or " -s" in base_command or "--silent" in base_command):
            base_command = base_command.replace("curl ", "curl -s ", 1)

        if not ("--compressed" in base_command):
            base_command = base_command.replace("curl ", "curl --compressed ", 1)

        if not ("-w " in base_command or "--write-out" in base_command):
            base_command = base_command.rstrip() + ' -w "\\nHTTP_STATUS:%{http_code}"'

    parts = [base_command.rstrip()]

    if not credentials:
        return " ".join(parts)

    has_cookie = "-H \"Cookie:" in base_command or "-H 'Cookie:" in base_command or "--cookie" in base_command.lower()
    has_auth = "Authorization:" in base_command

    cookies = credentials.get("cookies", [])
    if cookies and not has_cookie:
        cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
        if command_type == "sqlmap":
            parts.append(f'--cookie "{cookie_str}"')
        else:  # curl
            parts.append(f'-H "Cookie: {cookie_str}"')

    headers = credentials.get("headers", {})
    if "Authorization" in headers and not has_auth:
        parts.append(f'-H "Authorization: {headers["Authorization"]}"')
    elif not has_auth:
        token = extract_auth_token(credentials)
        if token:
            parts.append(f'-H "Authorization: Bearer {token}"')

    return " ".join(parts)


def append_credentials_to_curl(curl_command: str, credentials: Dict) -> str:
    """
    Append credentials to curl command (compatibility wrapper)

    Args:
        curl_command: curl command (without auth)
        credentials: account credentials

    Returns:
        Returns complete command with credentials
    """
    return append_credentials_to_command(curl_command, credentials, command_type="curl")


def extract_auth_token(credentials: Dict) -> Optional[str]:
    """
    Smart extraction of auth token from localStorage/sessionStorage
    
    Improvements:
    1. Priority-based: prefer explicit fields like access_token, authorization
    2. Validation: filter out JSON objects, short strings, refresh_token
    3. Exclusion: skip unrelated fields like auth_time, token_type
    
    Returns:
        Returns extracted token string or None
    """
    all_storage = {}
    all_storage.update(credentials.get("localStorage", {}))
    all_storage.update(credentials.get("sessionStorage", {}))
    
    if not all_storage:
        return None

    def _is_valid_token_format(value: Any) -> bool:
        if not isinstance(value, str):
            return False
        
        val = value.strip()
        
        if val.startswith('{') or val.startswith('['):
            return False
            
        if val.lower() in ['true', 'false', 'null', 'undefined', 'nan']:
            return False
            
        if len(val) < 10 or len(val) > 5000:
            return False
            
        return True

    # =======================================================
    # =======================================================
    high_priority_keywords = ['access_token', 'id_token', 'authorization', 'bearer_token']
    
    for key, value in all_storage.items():
        k_lower = key.lower()
        
        if 'refresh' in k_lower:
            continue
            
        if any(keyword == k_lower or k_lower.endswith(f"_{keyword}") or k_lower.endswith(f".{keyword}") for keyword in high_priority_keywords):
            if _is_valid_token_format(value):
                return value.strip('"').strip("'")

    # =======================================================
    # =======================================================
    for key, value in all_storage.items():
        if isinstance(value, str) and value.strip().startswith('eyJh'):  # JWT Header "{"alg"..." base64 coded
            if _is_valid_token_format(value):
                return value.strip('"').strip("'")

    # =======================================================
    # =======================================================
    low_priority_keywords = ['token', 'auth', 'jwt', 'session', 'key']
    
    for key, value in all_storage.items():
        k_lower = key.lower()
        
        if any(x in k_lower for x in ['refresh', 'type', 'time', 'date', 'expire', 'config', 'user_info']):
            continue
            
        if any(keyword in k_lower for keyword in low_priority_keywords):
            if _is_valid_token_format(value):
                return value.strip('"').strip("'")
    
    return None


def format_credentials_for_display(credentials: Dict) -> str:
    """
    Format credentials for log display
    
    Returns:
        Returns a human-readable credentials summary
    """
    lines = []
    
    # Cookies
    cookies = credentials.get("cookies", [])
    if cookies:
        lines.append(f"Cookies ({len(cookies)}):")
        for c in cookies[:3]:
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


def safe_replace_payload(template: str, payload: str) -> str:
    """
    Safely replace {PAYLOAD} in a curl command template

    Strategy:
    - Detect if {PAYLOAD} is in the URL
    - If in URL: apply URL encoding
    - If in body/header: no encoding

    Args:
        template: curl command template containing {PAYLOAD}
        payload: payload string to insert

    Returns:
        Returns command string with payload inserted
    """
    from urllib.parse import quote
    import shlex

    try:
        args = shlex.split(template)
    except ValueError:
        return template.replace('{PAYLOAD}', payload)

    for i, arg in enumerate(args):
        if '{PAYLOAD}' not in arg:
            continue

        if arg.startswith('http://') or arg.startswith('https://'):
            safe_payload = quote(payload, safe='')
            args[i] = arg.replace('{PAYLOAD}', safe_payload)

        elif i > 0 and args[i-1] in ['-d', '--data', '--data-raw', '--data-binary']:
            args[i] = arg.replace('{PAYLOAD}', payload)

        elif i > 0 and args[i-1] in ['-H', '--header']:
            args[i] = arg.replace('{PAYLOAD}', payload)

        else:
            args[i] = arg.replace('{PAYLOAD}', payload)

    return ' '.join(shlex.quote(arg) for arg in args)


def execute_curl_safe(template: str, payload: str, credentials: Dict,
                      timeout: int = None) -> tuple:
    """
    Execute curl command safely (avoids shell injection and quoting issues)

    Workflow:
    1. Safe payload replacement (URL-encode if in URL)
    2. Parse command with shlex.split
    3. Append credentials as separate args
    4. Execute with shell=False

    Args:
        template: curl template containing {PAYLOAD}
        payload: payload to insert
        credentials:
        timeout: ()

    Returns:
        (stdout, stderr, returncode, final_cmd)
        - final_cmd  curl ( shell )
    """
    import subprocess
    import shlex

    filled_cmd = safe_replace_payload(template, payload)

    final_cmd = filled_cmd

    try:
        args = shlex.split(filled_cmd)
    except ValueError as e:
        return "", f"Failed to parse command: {e}", 1, final_cmd

    args = _append_credentials_to_args(args, credentials)

    final_cmd = " ".join(shlex.quote(a) for a in args)

    try:
        process = subprocess.Popen(
            args,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate(timeout=timeout) if timeout is not None else process.communicate()
        return stdout, stderr, process.returncode, final_cmd

    except subprocess.TimeoutExpired:
        process.kill()
        return "", "Timeout expired", 124, final_cmd
    except Exception as e:
        return "", f"Execution failed: {e}", 1, final_cmd



def _append_credentials_to_args(args: List[str], credentials: Dict) -> List[str]:
    """


    Args:
        args:
        credentials:

    Returns:

    """
    result = args.copy()

    has_cookie = any('-H' in arg or '--header' in arg for arg in args) and \
                 any('Cookie:' in arg for arg in args)
    has_auth = any('Authorization:' in arg for arg in args)

    cookies = credentials.get("cookies", [])
    if cookies and not has_cookie:
        cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
        result.extend(['-H', f'Cookie: {cookie_str}'])

    headers = credentials.get("headers", {})
    if "Authorization" in headers and not has_auth:
        result.extend(['-H', f'Authorization: {headers["Authorization"]}'])
    elif not has_auth:
        token = extract_auth_token(credentials)
        if token:
            result.extend(['-H', f'Authorization: Bearer {token}'])

    return result


def parse_http_status_from_response(response: str) -> tuple:
    """
    curlHTTP

    curl -w "\\nHTTP_STATUS:%{http_code}", 
    , :HTTP_STATUS:200

    Args:
        response: curlstdout

    Returns:
        (http_status_code: int, response_body: str)
        ,  (None, response)
    """
    import re

    pattern = r'\r?\nHTTP_STATUS:(\d{3})\s*$'
    match = re.search(pattern, response)

    if match:
        http_code = int(match.group(1))
        response_body = response[:match.start()]
        return (http_code, response_body)
    else:
        return (None, response)


def extract_useful_response(response: str, max_length: int = 3000) -> str:
    """
    HTTP, token

    LLMHTML、CSS、JS。

    Strategy:
    1.
    2. (HTML / JSON / )
    3. HTML:, , 
    4. JSON:JSON()
    6. max_length

    Args:
        response: HTTP
        max_length: (3000)

    Returns:
        (≤ max_length)

    Examples:
        >>> html = "<html><title>Error</title><body>Invalid input</body></html>"
        >>> extract_useful_response(html, 100)
        '[Title] Error\\n\\n[Error/Alert] Invalid input'
    """
    import re

    max_length = 10000

    if not response:
        return ""

    if not isinstance(response, str):
        response = str(response)

    if len(response) <= max_length:
        if _is_html_response(response):
            return _extract_from_html_response(response, max_length)
        return response

    if _is_html_response(response):
        return _extract_from_html_response(response, max_length)
    elif _is_json_response(response):
        return response[:max_length]
    else:
        return response[:max_length]


def _is_html_response(text: str) -> bool:
    """
    HTML


    Args:
        text:

    Returns:
        True if HTML, False otherwise
    """
    if not text:
        return False

    text_lower = text.lower()

    html_indicators = [
        '<!doctype' in text_lower,
        '<html' in text_lower,
        '<head>' in text_lower or '<head ' in text_lower,
        '<body>' in text_lower or '<body ' in text_lower,
        '<div' in text_lower,
        '<script' in text_lower,
        '<style' in text_lower,
    ]

    match_count = sum(html_indicators)

    return match_count >= 2


def _is_json_response(text: str) -> bool:
    """
    JSON

    Args:
        text:

    Returns:
        True if JSON, False otherwise
    """
    if not text:
        return False

    text_stripped = text.strip()

    if not (text_stripped.startswith('{') or text_stripped.startswith('[')):
        return False

    try:
        json.loads(text_stripped)
        return True
    except (json.JSONDecodeError, ValueError):
        return False


def _extract_from_html_response(html: str, max_length: int) -> str:
    """
    HTML

    1. <title>
    2. /
    3. (script, style)

    Args:
        html: HTML
        max_length:

    Returns:

    """
    import re

    extracted_parts = []
    remaining_length = max_length

    title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    if title_match:
        title = title_match.group(1).strip()
        if title:
            title_clean = _clean_html_text(title)
            extracted_parts.append(f"[Title] {title_clean}")
            remaining_length -= len(extracted_parts[-1]) + 2  # +2 for \n\n

    error_keywords = [
        'error', 'exception', 'invalid', 'forbidden', 'denied',
        'failed', 'alert', 'warning', 'violation', 'rejected',
        'unauthorized', 'not found', 'bad request'
    ]

    error_pattern = r'<(?:div|p|span|li|td|h\d)[^>]*?(?:class|id)=["\']?[^"\']*(?:' + '|'.join(error_keywords) + r')[^"\']*["\']?[^>]*>(.*?)</(?:div|p|span|li|td|h\d)>'

    error_matches = re.finditer(error_pattern, html, re.IGNORECASE | re.DOTALL)

    for match in error_matches:
        if remaining_length <= 100:
            break

        error_text = match.group(1)
        error_clean = _clean_html_text(error_text)

        if 5 < len(error_clean) < 500:
            extracted_parts.append(f"[Error/Alert] {error_clean}")
            remaining_length -= len(extracted_parts[-1]) + 2

    if not extracted_parts or remaining_length > 500:
        html_cleaned = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.IGNORECASE | re.DOTALL)
        html_cleaned = re.sub(r'<style[^>]*>.*?</style>', '', html_cleaned, flags=re.IGNORECASE | re.DOTALL)
        html_cleaned = re.sub(r'<!--.*?-->', '', html_cleaned, flags=re.DOTALL)

        body_match = re.search(r'<body[^>]*>(.*?)</body>', html_cleaned, re.IGNORECASE | re.DOTALL)
        if body_match:
            body_html = body_match.group(1)
        else:
            body_html = html_cleaned

        body_text = _clean_html_text(body_html)

        lines = [line.strip() for line in body_text.split('\n') if line.strip()]

        body_preview_lines = []
        current_length = 0
        for line in lines[:30]:
            if current_length + len(line) + 1 > remaining_length:
                break
            body_preview_lines.append(line)
            current_length += len(line) + 1

        if body_preview_lines:
            body_preview = '\n'.join(body_preview_lines)
            if not extracted_parts:
                extracted_parts.append(body_preview)
            else:
                extracted_parts.append(f"[Body Preview]\n{body_preview}")

    result = '\n\n'.join(extracted_parts)

    if len(result) > max_length:
        result = result[:max_length]

    return result


def _clean_html_text(html: str) -> str:
    """
    HTML, 

    Args:
        html: HTML

    Returns:

    """
    import re

    text = re.sub(r'<[^>]+>', '', html)

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

    text = re.sub(r'\s+', ' ', text)
    text = text.strip()

    return text
