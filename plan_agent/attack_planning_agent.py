"""
Attack Planning Agent - Refactored version (only plans tasks, does not generate specific commands)
"""

import json
import re
from typing import List, Dict, Tuple, Optional, Set, Any
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from openai import OpenAI
from crawl.crawler import Crawler
from config.llm_config import get_model_name, get_temperature
from utils.token_tracker import tracker


class ActionType(Enum):
    """Action types the Attack Planning Agent can execute"""
    FORMULATE_TASKS = "formulate_tasks"
    SKIP_REQUESTS = "skip_requests"  # New: skip requests that cannot be attacked
    FINISH = "finish"


@dataclass
class AttackTask:
    """
    Attack task (descriptive)

    No longer contains specific payloads, but task descriptions
    """
    task_id: str  # e.g. "TASK001"
    task_description: str  # Task description, e.g. "Test if the user ID parameter is vulnerable to SQL injection"
    vuln_type: str  # Vulnerability type label (SQL_INJECTION, XSS, IDOR, etc.)
    target_request: Dict[str, Any]  # Complete request object (including response)
    account_identifier: str  # Account to use (auto-assigned: deep crawl uses deep account, shallow uses unauthenticated)


@dataclass
class AttackState:
    """Attack state, tracking which requests have been tested"""
    tested_requests: Set[Tuple[str, str]] = field(default_factory=set)  # (method, url)
    attack_history: List[Dict[str, str]] = field(default_factory=list)
    total_tasks_generated: int = 0


class AttackPlanningAgent:
    """
    Attack Planning Agent - Refactored version

    Responsibilities:
    1. Analyze request graph, identify potential vulnerability points
    2. Generate attack task descriptions (not specific commands)
    3. Provide complete request information to downstream Agent
    """
    
    def __init__(self, client: OpenAI, crawler: Crawler,
                 account_manager,
                 prompt_file: str = "prompt/audit_task_formulation.txt",
                 ctf_description: Optional[str] = None,
                 default_account: str = None,
                 include_trace_requests: bool = True):  # Default: enable trace requests
        self.client = client
        self.crawler = crawler
        self.state = AttackState()
        self.account_manager = account_manager
        self.ctf_description = ctf_description  # CTF description info (optional)
        self.default_account = default_account  # Default account (deep uses deep account, shallow uses unauthenticated)
        self.include_trace_requests = include_trace_requests  # Whether to include trace requests

        # Set up logging
        log_base = Path(self.crawler.root_dir) / "attack_agent"
        log_base.mkdir(parents=True, exist_ok=True)
        self._log_path = log_base / "attack_plan.log"

        # Task records
        attack_planning_dir = Path(self.crawler.root_dir) / "attack_planning"
        attack_planning_dir.mkdir(parents=True, exist_ok=True)
        self._tasks_json_path = attack_planning_dir / "planned_attacks.json"
        self.planned_attacks: List[Dict[str, Any]] = []  # Store all planned attack tasks
        self._cached_graph = None

        with open(prompt_file, 'r', encoding='utf-8') as f:
            self.prompt_template = f.read()
    
    def _log(self, *args, sep=" ", end="\n"):
        """Unified logging function"""
        msg = sep.join(str(a) for a in args)
        try:
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(msg + end)
        except Exception as e:
            print(f"[Log Error] {e}")
    
    def _record_action(self, task_count: int):
        """Record historical action"""
        self.state.attack_history.append({
            "action": "PLANNED_TASKS",
            "task_count": task_count
        })
    
    def _format_attack_history(self) -> str:
        """Format attack history as string"""
        if not self.state.attack_history:
            return "No tasks planned yet."

        lines = []
        for i, record in enumerate(self.state.attack_history, 1):
            action = record["action"]
        # Compatible with both task_count and request_count formats
            count = record.get("task_count") or record.get("request_count", 0)
            lines.append(f"{i}. {action}: {count} tasks" if "TASK" in action else f"{i}. {action}: {count} requests")
        return "\n".join(lines)
    
    def _load_attack_graph(self) -> Dict:
        # If self._cached_graph exists and not expired (keeping it simple, no expiry since graph doesn't change within one planning round), return directly
        if hasattr(self, '_cached_graph') and self._cached_graph:
            return self._cached_graph

        full_graph = self.crawler._generate_execution_graph_with_requests(
            include_trace_requests=self.include_trace_requests
        )
        filtered_graph = self._filter_graph_requests(full_graph, max_requests=80)
        
        self._cached_graph = filtered_graph # Cache it
        return filtered_graph

    def _identify_request(self, request_dict: Dict) -> str:
        return request_dict["id"]

    def _calculate_priority(self, request: Dict, node: Dict) -> float:
        """
        Calculate request priority (for sorting during filtering)

        Considers multiple factors:
        1. HTTP method (POST > PUT/PATCH > DELETE > GET)
        2. Parameter structure (has body_schema > has URL params > no params)
        3. URL path sensitivity (API paths, admin paths, etc.)
        4. Request type (modification > query)
        5. URL depth (deeper paths may be more important)

        Args:
            request: Request dictionary
            node: Parent node (for context judgment)

        Returns:
            Priority score (higher is more important, range ~0-30)
        """
        priority = 0.0

        method = request.get("method", "GET").upper()
        url = request.get("url", "")
        body_schema = request.get("body_schema", "")

        # ========== Rule 1: HTTP method priority ==========
        # POST highest (possible injection, business logic vulnerabilities)
        if method == "POST":
            priority += 12.0
        # PUT/PATCH next (modification operations)
        elif method in ["PUT", "PATCH"]:
            priority += 10.0
        # DELETE higher (dangerous operations)
        elif method == "DELETE":
            priority += 8.0
        # GET lowest (but GET with parameters still has value)
        elif method == "GET":
            priority += 2.0
        else:
            # HEAD, OPTIONS, etc.
            priority += 1.0

        # ========== Rule 2: Parameter structure complexity ==========
        # Requests with body_schema (structured data, large injection surface)
        if body_schema:
            field_count = len(body_schema.split(','))
            # More fields = higher priority (with upper limit)
            priority += min(5.0 + field_count * 0.5, 10.0)

        # GET requests with URL parameters
        if method == "GET" and "?" in url:
            from urllib.parse import urlparse, parse_qs
            try:
                parsed = urlparse(url)
                # Check traditional parameters
                query_params = parse_qs(parsed.query)
                # Check SPA parameters (? in fragment)
                fragment_params = {}
                if parsed.fragment and '?' in parsed.fragment:
                    fragment_query = parsed.fragment.split('?', 1)[1]
                    fragment_params = parse_qs(fragment_query)

                total_params = len(query_params) + len(fragment_params)
                # More parameters = higher priority
                priority += min(3.0 + total_params * 0.3, 6.0)
            except Exception:
                # Parse failed, give a base score
                priority += 3.0

        # ========== Rule 3: URL path sensitivity ==========
        url_lower = url.lower()

        # Critical sensitivity paths (admin, delete, upload, etc.)
        critical_paths = [
            "/admin", "/delete", "/remove", "/upload", "/exec",
            "/cmd", "/shell", "/eval", "/system"
        ]
        for path in critical_paths:
            if path in url_lower:
                priority += 5.0
                break

        # High sensitivity paths (API, user, auth, etc.)
        high_sensitive_paths = [
            "/api/", "/user", "/auth", "/register",
            "/account", "/profile", "/settings"
        ]
        for path in high_sensitive_paths:
            if path in url_lower:
                priority += 3.0
                break

        # Medium sensitivity paths (search, comment, file, etc.)
        medium_sensitive_paths = [
            "/search", "/query", "/comment", "/post", "/file",
            "/download", "/view", "/edit", "/update"
        ]
        for path in medium_sensitive_paths:
            if path in url_lower:
                priority += 2.0
                break

        # ========== Rule 6: Special file extensions (lower priority) ==========
        # Static resource files get lower priority
        static_extensions = [
            ".js", ".css", ".jpg", ".jpeg", ".png", ".gif",
            ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot"
        ]
        for ext in static_extensions:
            if url_lower.endswith(ext):
                priority -= 5.0
                break

        # ========== Rule 7: Common business logic vulnerability paths ==========
        # IDOR, privilege escalation, etc. commonly found in these paths
        idor_paths = [
            "/view", "/detail", "/info", "/get",
            "/user/", "/profile/", "/order/", "/message/"
        ]
        for path in idor_paths:
            if path in url_lower and ("id=" in url_lower or "?" in url):
                priority += 2.5
                break

        # Ensure priority is not negative (shouldn't happen theoretically, but just in case)
        return max(priority, 0.0)

    def _filter_graph_requests(self, graph: Dict, max_requests: int = 80) -> Dict:
        """
        Filter graph, keep at most max_requests requests

        Core logic:
        1. Traverse all nodes, collect all 5 types of requests
        2. Calculate unique identifier (dedup_key) and priority for each request
        3. Sort by priority, select top max_requests
        4. Filter original graph, keep only selected requests
        5. Remove empty nodes where all requests were filtered out

        Important: Preserve all original node fields (e.g. description, abstract_page), only filter requests

        Supported request types:
        - page_requests: network requests during page load
        - tasks[].requests: requests generated during task execution (nested structure)
        - outgoing_links: external links and dynamic navigation (including SPA routes)
        - trace_requests: isolated requests extracted from trace files
        - pre_navigation_requests: pre-navigation requests (e.g. login)

        Args:
            graph: Original graph (from _generate_execution_graph_with_requests)
            max_requests: Maximum number of requests to keep

        Returns:
            Filtered graph (same structure as original, but fewer requests)
        """
        self._log(f"\n[Filter] ===== Starting request filtering =====")

        # ========== Step 1: Collect all requests ==========
        all_requests = []

        for node_idx, node in enumerate(graph["nodes"]):
            node_url = node.get("url", "")

            # Location 1: page_requests
            for req_idx, req in enumerate(node.get("page_requests", [])):
                try:
                    key = self._identify_request(req)
                    priority = self._calculate_priority(req, node)
                    all_requests.append({
                        "key": key,
                        "node_idx": node_idx,
                        "node_url": node_url,
                        "location": "page_requests",
                        "req_idx": req_idx,
                        "priority": priority,
                        "request": req
                    })
                except Exception as e:
                    self._log(f"[Filter] Warning: Cannot identify request in page_requests: {e}")
                    continue

            # Location 2: tasks[].requests (nested structure)
            for task_idx, task in enumerate(node.get("tasks", [])):
                task_desc = task.get("description", "")
                for req_idx, req in enumerate(task.get("requests", [])):
                    try:
                        key = self._identify_request(req)
                        priority = self._calculate_priority(req, node)
                        all_requests.append({
                            "key": key,
                            "node_idx": node_idx,
                            "node_url": node_url,
                            "location": "tasks",
                            "task_idx": task_idx,
                            "task_desc": task_desc,
                            "req_idx": req_idx,
                            "priority": priority,
                            "request": req
                        })
                    except Exception as e:
                        self._log(f"[Filter] Warning: Cannot identify request in tasks: {e}")
                        continue

            # Location 3: outgoing_links
            for req_idx, req in enumerate(node.get("outgoing_links", [])):
                try:
                    key = self._identify_request(req)
                    # [Fix] If request has already been tested, do not add to candidate list
                    # This way in the next iteration, ranks 81-160 will automatically move up to become Top 80
                    if key in self.state.tested_requests:
                        continue

                    priority = self._calculate_priority(req, node)
                    all_requests.append({
                        "key": key,
                        "node_idx": node_idx,
                        "node_url": node_url,
                        "location": "outgoing_links",
                        "req_idx": req_idx,
                        "priority": priority,
                        "request": req
                    })
                except Exception as e:
                    self._log(f"[Filter] Warning: Cannot identify request in outgoing_links: {e}")
                    continue

            # Location 4: trace_requests
            for req_idx, req in enumerate(node.get("trace_requests", [])):
                try:
                    key = self._identify_request(req)
                    priority = self._calculate_priority(req, node)
                    all_requests.append({
                        "key": key,
                        "node_idx": node_idx,
                        "node_url": node_url,
                        "location": "trace_requests",
                        "req_idx": req_idx,
                        "priority": priority,
                        "request": req
                    })
                except Exception as e:
                    self._log(f"[Filter] Warning: Cannot identify request in trace_requests: {e}")
                    continue

            # Location 5: pre_navigation_requests
            for req_idx, req in enumerate(node.get("pre_navigation_requests", [])):
                try:
                    key = self._identify_request(req)
                    priority = self._calculate_priority(req, node)
                    all_requests.append({
                        "key": key,
                        "node_idx": node_idx,
                        "node_url": node_url,
                        "location": "pre_navigation_requests",
                        "req_idx": req_idx,
                        "priority": priority,
                        "request": req
                    })
                except Exception as e:
                    self._log(f"[Filter] Warning: Cannot identify request in pre_navigation_requests: {e}")
                    continue

        total_requests = len(all_requests)

        # Count requests by type
        location_stats = {}
        for req_info in all_requests:
            loc = req_info["location"]
            location_stats[loc] = location_stats.get(loc, 0) + 1

        self._log(f"[Filter] Collected {total_requests} requests")
        self._log(f"[Filter] Request distribution:")
        for loc, count in sorted(location_stats.items()):
            self._log(f"[Filter]   - {loc}: {count}")

        # ========== Step 2: Check if filtering is needed ==========
        if total_requests <= max_requests:
            self._log(f"[Filter] No filtering needed ({total_requests} <= {max_requests})")
            self._log(f"[Filter] ===== Filtering complete =====\n")
            return graph

        # ========== Step 3: Sort by priority ==========
        all_requests.sort(key=lambda x: x["priority"], reverse=True)

        # ========== Step 4: Select top max_requests ==========
        selected_requests = all_requests[:max_requests]
        selected_keys = set(req["key"] for req in selected_requests)

        filtered_count = total_requests - max_requests
        self._log(f"[Filter] Filtered out {filtered_count} low-priority requests")

        # Log: output highest and lowest priority requests (for debugging)
        self._log(f"[Filter] Top 3 highest priority requests:")
        for i, req_info in enumerate(selected_requests[:3], 1):
            req = req_info["request"]
            self._log(f"[Filter]   {i}. [{req_info['priority']:.1f}] {req.get('method')} {req.get('url')[:70]}...")

        self._log(f"[Filter] Top 3 filtered out requests:")
        filtered_out = all_requests[max_requests:]
        for i, req_info in enumerate(filtered_out[:3], 1):
            req = req_info["request"]
            self._log(f"[Filter]   {i}. [{req_info['priority']:.1f}] {req.get('method')} {req.get('url')[:70]}...")

        # ========== Step 5: Filter original graph ==========
        filtered_graph = {"nodes": []}

        for node in graph["nodes"]:
            # Key fix: copy all node fields (preserve description, abstract_page, etc.)
            filtered_node = dict(node)

            # Then only replace request-related fields
            filtered_node["page_requests"] = []
            filtered_node["tasks"] = []
            filtered_node["outgoing_links"] = []
            filtered_node["trace_requests"] = []
            filtered_node["pre_navigation_requests"] = []

            # Filter page_requests
            for req in node.get("page_requests", []):
                try:
                    if self._identify_request(req) in selected_keys:
                        filtered_node["page_requests"].append(req)
                except Exception:
                    pass

            # Filter tasks (only keep tasks with requests)
            for task in node.get("tasks", []):
                filtered_task_requests = []
                for req in task.get("requests", []):
                    try:
                        if self._identify_request(req) in selected_keys:
                            filtered_task_requests.append(req)
                    except Exception:
                        pass

                # Only keep this task if it still has requests
                if filtered_task_requests:
                    filtered_node["tasks"].append({
                        "description": task["description"],
                        "requests": filtered_task_requests
                    })

            # Filter outgoing_links
            for req in node.get("outgoing_links", []):
                try:
                    if self._identify_request(req) in selected_keys:
                        filtered_node["outgoing_links"].append(req)
                except Exception:
                    pass

            # Filter trace_requests
            for req in node.get("trace_requests", []):
                try:
                    if self._identify_request(req) in selected_keys:
                        filtered_node["trace_requests"].append(req)
                except Exception:
                    pass

            # Filter pre_navigation_requests
            for req in node.get("pre_navigation_requests", []):
                try:
                    if self._identify_request(req) in selected_keys:
                        filtered_node["pre_navigation_requests"].append(req)
                except Exception:
                    pass

            # ========== Step 6: Only keep nodes with requests ==========
            has_requests = (
                len(filtered_node["page_requests"]) > 0 or
                len(filtered_node["tasks"]) > 0 or
                len(filtered_node["outgoing_links"]) > 0 or
                len(filtered_node["trace_requests"]) > 0 or
                len(filtered_node["pre_navigation_requests"]) > 0
            )

            if has_requests:
                filtered_graph["nodes"].append(filtered_node)

        # Count nodes after filtering
        original_node_count = len(graph["nodes"])
        filtered_node_count = len(filtered_graph["nodes"])
        removed_node_count = original_node_count - filtered_node_count

        self._log(f"[Filter] Node statistics: {original_node_count} -> {filtered_node_count} (removed {removed_node_count} empty nodes)")
        self._log(f"[Filter] ===== Filtering complete =====\n")

        return filtered_graph

    def _count_pending_requests(self, graph: Dict) -> int:
        """
        Count pending requests in graph

        Supports new request fields: trace_requests, pre_navigation_requests
        Uses new dedup key
        """
        total = 0
        for node in graph.get("nodes", []):
            # Original field: page_requests
            for req in node.get("page_requests", []):
                key = self._identify_request(req)
                if key not in self.state.tested_requests:
                    total += 1

            # Original field: requests in tasks
            for task in node.get("tasks", []):
                for req in task.get("requests", []):
                    key = self._identify_request(req)
                    if key not in self.state.tested_requests:
                        total += 1

            # Original field: outgoing_links
            for req in node.get("outgoing_links", []):
                key = self._identify_request(req)
                if key not in self.state.tested_requests:
                    total += 1

            # New field: trace_requests (isolated requests from trace files)
            for req in node.get("trace_requests", []):
                key = self._identify_request(req)
                if key not in self.state.tested_requests:
                    total += 1

            # New field: pre_navigation_requests (pre-navigation requests, e.g. login)
            for req in node.get("pre_navigation_requests", []):
                key = self._identify_request(req)
                if key not in self.state.tested_requests:
                    total += 1

        return total

    def _is_request_in_current_graph(self, method: str, url: str, body_schema: Optional[str] = None) -> bool:
        """
        Check if request exists in current graph
        Supports checking: page_requests, tasks, outgoing_links, trace_requests, pre_navigation_requests
        Supports fuzzy matching: if strict match fails, try field similarity matching (>80%)
        
        Args:
            method: HTTP method
            url: URL
            body_schema: Optional body_schema (for POST/PUT/PATCH)
        Returns:
            True if request exists in current graph
        """
        # ========== Step 1: Strict matching ==========
        # Construct correct dedup_key
        if body_schema and method.upper() in ["POST", "PUT", "PATCH"]:
            # Construct fake_body from body_schema
            keys = [k.strip() for k in body_schema.split(',')]
            body = json.dumps({k: "" for k in keys}, sort_keys=True)
        else:
            body = None
        
        # Check request_mapping with correct dedup_key
        key = self.crawler._make_dedup_key(method, url, body)
        if key in self.crawler.request_mapping:
            return True
        
        # Check if in current graph (including new fields)
        graph = self._load_attack_graph()
        for node in graph.get("nodes", []):
            # Check outgoing_links
            for link in node.get("outgoing_links", []):
                if link.get("method") == method and link.get("url") == url:
                    return True
            # Check trace_requests
            for req in node.get("trace_requests", []):
                if req.get("method") == method and req.get("url") == url:
                    return True
            for req in node.get("pre_navigation_requests", []):
                if req.get("method") == method and req.get("url") == url:
                    return True
        
        if body_schema and method.upper() in ["POST", "PUT", "PATCH"]:
            self._log(f"[Fuzzy Match] Strict match failed, trying fuzzy match for {method} {url}")
            
            llm_fields = set(k.strip() for k in body_schema.split(','))
            
            for map_key, request in self.crawler.request_mapping.items():
                req_method, req_url, req_body = map_key
                
                if req_method != method or req_url != url:
                    continue
                
                if req_body:
                    try:
                        actual_fields = set(json.loads(req_body).keys())
                        
                        intersection = llm_fields & actual_fields
                        union = llm_fields | actual_fields
                        max_len = max(len(llm_fields), len(actual_fields))
                        
                        if max_len > 0:
                            similarity = len(intersection) / max_len
                            
                            self._log(f"[Fuzzy Match] Similarity: {similarity:.1%} (LLM: {len(llm_fields)} fields, Actual: {len(actual_fields)} fields, Common: {len(intersection)})")
                            
                            if similarity >= 0.8:
                                diff_llm = llm_fields - actual_fields
                                diff_actual = actual_fields - llm_fields
                                if diff_llm:
                                    self._log(f"[Fuzzy Match] LLM extra fields: {list(diff_llm)[:5]}{'...' if len(diff_llm) > 5 else ''}")
                                if diff_actual:
                                    self._log(f"[Fuzzy Match] Actual extra fields: {list(diff_actual)[:5]}{'...' if len(diff_actual) > 5 else ''}")
                                
                                self._log(f"[Fuzzy Match] [OK] Match found with {similarity:.1%} similarity")
                                return True
                            else:
                                self._log(f"[Fuzzy Match] [FAIL] Similarity {similarity:.1%} < 80%, skipping")
                    
                    except json.JSONDecodeError as e:
                        self._log(f"[Fuzzy Match] Failed to parse body as JSON: {e}")
                        continue
            
            self._log(f"[Fuzzy Match] No fuzzy match found for {method} {url}")
        
        return False

    def _get_or_create_request(self, method: str, url: str, body_schema: Optional[str] = None) -> Optional[Dict]:
        """
        Get or create a request object

        For requests in request_mapping, return full data
        For outgoing_links, construct a minimal request object

        Args:
            method: HTTP method
            url: URL
            body_schema: optional body_schema (for POST/PUT/PATCH)

        Returns:
            Returns request dict or None if not found
        """
        if body_schema and method.upper() in ["POST", "PUT", "PATCH"]:
            keys = [k.strip() for k in body_schema.split(',')]
            fake_body = json.dumps({k: "" for k in keys}, sort_keys=True)
            target_request = self.crawler.lookup_request(method, url, fake_body)
        else:
            target_request = self.crawler.lookup_request(method, url, None)

        if target_request:
            return target_request

        if body_schema and method.upper() in ["POST", "PUT", "PATCH"]:
            try:
                schema_keys = set(k.strip() for k in body_schema.split(','))
                
                for (r_method, r_url, r_body), req_data in self.crawler.request_mapping.items():
                    if r_method == method and r_url == url and r_body:
                        try:
                            real_keys = set(json.loads(r_body).keys())
                            
                            if schema_keys.issubset(real_keys) or len(schema_keys & real_keys) / len(schema_keys) > 0.8:
                                self._log(f"[Fuzzy Match] Found request via schema matching for {url}")
                                return req_data
                        except:
                            continue
            except Exception as e:
                self._log(f"[Fuzzy Match] Error: {e}")

        # if self._is_request_in_current_graph(method, url):
        if self._is_request_in_current_graph(method, url, body_schema):
            self._log(f"[Info] Creating simple request object for outgoing_link: {method} {url}")
            return {
                "method": method,
                "url": url,
                "headers": {},
                "body": None,
                "response_status": None,
                "response_body": None,
                "note": "Generated from outgoing_link"
            }

        return None

    def _call_llm(self, prompt: str) -> str:
        """Call large language model"""
        try:
            with tracker.phase("attack_planning"):
                response = self.client.chat.completions.create(
                    model=get_model_name("attack_planning"),
                    messages=[
                        {"role": "system", "content": "You are a security testing expert for web applications."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=get_temperature("attack_planning")
                )
                return response.choices[0].message.content
        except Exception as e:
            self._log(f"[AttackPlanningAgent] LLM call failed: {e}")
            return ""
    
    def _parse_id_list(self, text: str) -> List[str]:
        """Helper function: extract all REF_IDs from text block"""
        ids = []
        for line in text.splitlines():
            match = re.search(r'(?:REF_)?ID:\s*([a-fA-F0-9]+)', line, re.IGNORECASE)
            if match:
                ids.append(match.group(1).strip())
        return ids

    def _parse_llm_response(self, response: str) -> Tuple[ActionType, Optional[object]]:
        """
        Parse LLM response (ID-based version)
        """
        try:
            self._log("[AttackPlanningAgent] Parsing LLM response...")
            response = response.replace("**", "")

            action_match = re.search(r'Action:\s*(.+?)(?:\n|$)', response, re.IGNORECASE)
            if not action_match:
                if "Audit_Tasks:" in response:
                    action_type = "formulate_tasks"
                elif "Skipped_Requests:" in response:
                    action_type = "skip_requests"
                else:
                    self._log("[AttackPlanningAgent] No Action field found")
                    return (None, None)
            else:
                action_type = action_match.group(1).strip().lower()
                self._log(f"[AttackPlanningAgent] Detected action: {action_type}")

            if "analyze" in action_type:
                requests_match = re.search(
                    r'Selected_Requests:\s*\n(.*?)\n\s*(?:Reasoning|Audit_Tasks)',
                    response, re.DOTALL | re.IGNORECASE
                )
                selected_ids = []
                if requests_match:
                    selected_ids = self._parse_id_list(requests_match.group(1))

                reasoning = ""
                reasoning_match = re.search(r'Reasoning:\s*\n(.*?)\n\s*Audit_Tasks', response, re.DOTALL | re.IGNORECASE)
                if reasoning_match:
                    reasoning = reasoning_match.group(1).strip()

                task_lines = []
                lines = response.splitlines()
                start_idx = -1
                for i, line in enumerate(lines):
                    if "Audit_Tasks:" in line:
                        start_idx = i
                        break
                
                if start_idx != -1:
                    for line in lines[start_idx+1:]:
                        line = line.strip()
                        if not line or line.startswith("```"): continue
                        if line.startswith("[TASK"):
                            task_lines.append(line)
                
                if not task_lines:
                    self._log("[AttackPlanningAgent] No valid task lines found")
                    return (None, None)

                return (ActionType.FORMULATE_TASKS, {
                    "selected_ids": selected_ids,
                    "reasoning": reasoning,
                    "task_lines": task_lines
                })

            elif "skip" in action_type:
                requests_match = re.search(
                    r'Skipped_Requests:\s*\n(.*?)\n\s*(?:Reasoning|$)', 
                    response, re.DOTALL | re.IGNORECASE
                )
                if not requests_match:
                    self._log("[AttackPlanningAgent] No Skipped_Requests section found")
                    return (None, None)
                
                skipped_ids = self._parse_id_list(requests_match.group(1))
                
                reasoning = ""
                reasoning_match = re.search(r'Reasoning:\s*\n(.*?)(?:\n|$)', response, re.DOTALL | re.IGNORECASE)
                if reasoning_match:
                    reasoning = reasoning_match.group(1).strip()

                return (ActionType.SKIP_REQUESTS, {
                    "skipped_ids": skipped_ids,
                    "reasoning": reasoning
                })

            elif "finish" in action_type:
                return (ActionType.FINISH, None)

            else:
                self._log(f"[AttackPlanningAgent] Unknown action: {action_type}")
                return (None, None)

        except Exception as e:
            self._log(f"[AttackPlanningAgent] Parse error: {e}")
            import traceback
            self._log(traceback.format_exc())
            return (None, None)

    def _parse_task_line(self, task_line: str) -> Optional[Dict]:
        """
        Parse format: [TASK_ID] VULN_TYPE | REF_ID: <ID> | DESCRIPTION
        """
        match = re.match(
            r'\[(\w+)\]\s+([A-Z_]+)\s+\|\s+(?:REF_)?ID:\s*([a-fA-F0-9]+)\s+\|\s+(.+)',
            task_line.strip(),
            re.IGNORECASE
        )

        if not match:
            return None

        task_id, vuln_type, ref_id, description = match.groups()

        return {
            "task_id": task_id.strip(),
            "vuln_type": vuln_type.strip().upper(),
            "ref_id": ref_id.strip(),
            "description": description.strip()
        }

    def _execute_analyze_action(self, action_data: Dict) -> List[AttackTask]:
        """
         (ID )
        """
        task_lines = action_data.get("task_lines", [])
        reasoning = action_data.get("reasoning", "")
        
        self._log(f"\n[AttackPlanningAgent] Processing {len(task_lines)} tasks")
        if reasoning:
            self._log(f"[AttackPlanningAgent] Reasoning: {reasoning}")

        attack_tasks = []
        
        current_batch_processed_ids = set()

        for task_line in task_lines:
            parsed = self._parse_task_line(task_line)
            if not parsed: 
                continue
            
            task_id = parsed["task_id"]
            ref_id = parsed["ref_id"]
            description = parsed["description"]
            vuln_type = parsed["vuln_type"]

            if ref_id in self.state.tested_requests:
                self._log(f"[Warning] Request {ref_id} already tested (history), skipping task {task_id}")
                continue

            target_request = self.crawler.request_id_map.get(ref_id)
            if not target_request:
                self._log(f"[Error] Task {task_id}: Invalid REF_ID '{ref_id}'")
                continue
            
            account = self.default_account if self.default_account else "default_account"
            task = AttackTask(
                task_id=task_id,
                task_description=description,
                vuln_type=vuln_type,
                target_request=target_request, 
                account_identifier=account
            )
            attack_tasks.append(task)
            
            self._log(f"  [{task_id}] {vuln_type} | ID:{ref_id} | {target_request.get('method')} {target_request.get('url')[:50]}...")

            self.planned_attacks.append({
                "task_id": task_id,
                "ref_id": ref_id,
                "task_description": description,
                "vuln_type": vuln_type,
                "account": account,
                "status": "planned",
                "target_request": {
                    # ...
                    "method": target_request.get("method"),
                    "url": target_request.get("url"),
                    "headers": target_request.get("headers", {}),
                    "query_params": target_request.get("query_params", {}),
                    "body": target_request.get("body"),
                    "response_body": (target_request.get("response_body", "") or "")[:200] 
                }
            })
            
            current_batch_processed_ids.add(ref_id)
            
            if hasattr(self.crawler, 'processed_requests'):
                key = self.crawler._make_dedup_key(target_request['method'], target_request['url'], target_request.get('body'))
                self.crawler.processed_requests.add(key) 

        if current_batch_processed_ids:
            self._log(f"[AttackPlanningAgent] Marking {len(current_batch_processed_ids)} requests as tested.")
            self.state.tested_requests.update(current_batch_processed_ids)

        self._record_action(len(attack_tasks))
        self.state.total_tasks_generated += len(attack_tasks)
        self._save_tasks_to_json()

        return attack_tasks
    
    def _execute_skip_action(self, action_data: Dict) -> int:
        """
         Skip  (ID )
         ID 。
        """
        skipped_ids = action_data.get("skipped_ids", [])
        reasoning = action_data.get("reasoning", "")
        
        self._log(f"\n[AttackPlanningAgent] Skipping {len(skipped_ids)} requests")
        if reasoning:
            self._log(f"[AttackPlanningAgent] Reasoning: {reasoning}")
            
        valid_count = 0
        for ref_id in skipped_ids:
            if ref_id in self.state.tested_requests:
                continue
            
            target_request = self.crawler.request_id_map.get(ref_id)
            if not target_request:
                self._log(f"[Warning] Cannot skip invalid ID: {ref_id}")
                continue
                
            self.state.tested_requests.add(ref_id)
            
            if hasattr(self.crawler, 'processed_requests'):
                key = self.crawler._make_dedup_key(target_request['method'], target_request['url'], target_request.get('body'))
                self.crawler.processed_requests.add(key)
                
            valid_count += 1
            self._log(f"  [SKIPPED] ID: {ref_id}")
            
        self._log(f"[AttackPlanningAgent] Successfully skipped {valid_count}/{len(skipped_ids)} requests")
        
        self.state.attack_history.append({
            "action": "SKIPPED_REQUESTS",
            "request_count": valid_count
        })
        
        return valid_count
    
    def plan_and_execute(self, max_iterations: int = 100) -> Dict:
        """
        Plan and execute attacks using LLM intelligent planning.

        Returns:
            {
                "iterations": int,
                "tested_requests": int,
                "all_tasks": List[AttackTask],
                "attack_history": List[Dict]
            }
        """
        self._cached_graph = None

        self._log("[AttackPlanningAgent] Using LLM mode (intelligent planning)")
        self._log("[AttackPlanningAgent] Starting attack planning")

        all_tasks = []

        iteration = 0
        while iteration < max_iterations:
            iteration += 1
            self._log(f"\n{'='*60}")
            self._log(f"[AttackPlanningAgent] Iteration {iteration}")

            self._cached_graph = None 

            graph = self._load_attack_graph()
            
            pending = self._count_pending_requests(graph)
            
            if pending == 0:
                self._log("[AttackPlanningAgent] No pending requests, finishing")
                break

            attack_history_str = self._format_attack_history()

            ctf_context = ""
            if self.ctf_description:
                ctf_context = f"\n\n=== CTF CHALLENGE DESCRIPTION ===\n{self.ctf_description}\n\nIMPORTANT: Focus on vulnerabilities that might be related to achieving the goal described above. Think divergently - if the description mentions 'login as admin', consider not just SQL injection, but also SSRF (to modify admin password), IDOR (to access admin resources), business logic flaws, etc."

            graph_json = json.dumps(graph, indent=2, ensure_ascii=False)
            prompt = self.prompt_template.format(
                graph_json=graph_json,
                total_requests=len(self.crawler.request_mapping),
                tested_requests=len(self.state.tested_requests),
                pending_requests=pending,
                attack_history=attack_history_str
            ) + ctf_context
            
            llm_response = self._call_llm(prompt)
            
            self._log("\n[LLM input]:")
            self._log(prompt)
            self._log("\n[LLM Response]:")
            self._log(llm_response)
            self._log("\n" + "="*60)
            
            if not llm_response:
                break
            
            action_type, action_data = self._parse_llm_response(llm_response)

            
            if action_type is None:
                self._log(f"[AttackPlanningAgent] Invalid response")
            elif action_type == ActionType.FORMULATE_TASKS:
                tasks = self._execute_analyze_action(action_data)
                all_tasks.extend(tasks)
            elif action_type == ActionType.SKIP_REQUESTS:
                self._execute_skip_action(action_data)
            elif action_type == ActionType.FINISH:
                self._log("[AttackPlanningAgent] Planning completed")
                break

        
        self._log(f"\n{'='*60}")
        self._log("[AttackPlanningAgent] Final Statistics:")
        self._log(f"  - Total iterations: {iteration}")
        self._log(f"  - Requests tested: {len(self.state.tested_requests)}")
        self._log(f"  - Total tasks generated: {len(all_tasks)}")
        self._log(f"\n[AttackPlanningAgent] Attack History:")
        self._log(self._format_attack_history())
        
        return {
            "iterations": iteration,
            "tested_requests": len(self.state.tested_requests),
            "all_tasks": all_tasks,
            "attack_history": self.state.attack_history
        }
    
    def _save_tasks_to_json(self):
        """
        JSON

        {
            "total_tasks": int,
            "tasks": [
                {
                    "task_id": str,
                    "task_description": str,
                    "vuln_type": str,
                    "target_url": str,
                    "method": str,
                    "account": str,
                    "status": str
                },
                ...
            ]
        }
        """
        try:
            with open(self._tasks_json_path, 'w', encoding='utf-8') as f:
                json.dump({
                    "total_tasks": len(self.planned_attacks),
                    "tasks": self.planned_attacks
                }, f, ensure_ascii=False, indent=2)
            self._log(f"[AttackPlanningAgent] Saved tasks to JSON: {self._tasks_json_path} ({len(self.planned_attacks)} tasks)")
        except Exception as e:
            self._log(f"[AttackPlanningAgent] Failed to save tasks JSON: {e}")

    def plan_and_stream(self, task_queue, max_iterations: int = 100):
        """
        Plan attacks using LLM mode, streaming tasks into the queue as they are generated.

        Args:
            task_queue: queue.Queue to push tasks into
            max_iterations: Maximum planning iterations

        Returns None
        """
        self._log("[AttackPlanningAgent] Using LLM mode (streaming)")
        self._log("[AttackPlanningAgent] Starting streaming attack planning")

        iteration = 0
        total_tasks_generated = 0
        consecutive_invalid_responses = 0

        try:
            while iteration < max_iterations:
                iteration += 1
                self._log(f"\n{'='*60}")
                self._log(f"[AttackPlanningAgent] Iteration {iteration}")

                self._cached_graph = None
                graph = self._load_attack_graph()
                pending = self._count_pending_requests(graph)

                if pending == 0:
                    self._log("[AttackPlanningAgent] No pending requests, finishing")
                    break

                attack_history_str = self._format_attack_history()

                ctf_context = ""
                if self.ctf_description:
                    ctf_context = f"\n\n=== CTF CHALLENGE DESCRIPTION ===\n{self.ctf_description}\n\nIMPORTANT: Focus on vulnerabilities that might be related to achieving the goal described above. Think divergently - if the description mentions 'login as admin', consider not just SQL injection, but also SSRF (to modify admin password), IDOR (to access admin resources), business logic flaws, etc."

                graph_json = json.dumps(graph, indent=2, ensure_ascii=False)
                prompt = self.prompt_template.format(
                    graph_json=graph_json,
                    total_requests=len(self.crawler.request_mapping),
                    tested_requests=len(self.state.tested_requests),
                    pending_requests=pending,
                    attack_history=attack_history_str
                ) + ctf_context

                llm_response = self._call_llm(prompt)

                self._log("\n[LLM input]:")
                self._log(prompt)
                self._log("\n[LLM Response]:")
                self._log(llm_response)
                self._log("\n" + "="*60)

                if not llm_response:
                    break

                action_type, action_data = self._parse_llm_response(llm_response)

                if action_type is None:
                    consecutive_invalid_responses += 1
                    self._log(f"[AttackPlanningAgent] Invalid response (consecutive: {consecutive_invalid_responses})")
                    self._log("[AttackPlanningAgent] → Skipping this iteration, will retry in next iteration")

                    if consecutive_invalid_responses >= 5:
                        self._log("[AttackPlanningAgent] Too many consecutive invalid responses (5+), stopping")
                        break

                    continue

                consecutive_invalid_responses = 0

                if action_type == ActionType.FORMULATE_TASKS:
                    tasks = self._execute_analyze_action(action_data)

                    for task in tasks:
                        task_queue.put(task)
                        self._log(f"[Stream] Task {task.task_id} pushed to queue")

                    total_tasks_generated += len(tasks)

                elif action_type == ActionType.SKIP_REQUESTS:
                    self._execute_skip_action(action_data)

                elif action_type == ActionType.FINISH:
                    self._log("[AttackPlanningAgent] Planning completed")
                    break

            self._log(f"\n{'='*60}")
            self._log("[AttackPlanningAgent] Final Statistics:")
            self._log(f"  - Total iterations: {iteration}")
            self._log(f"  - Requests tested: {len(self.state.tested_requests)}")
            self._log(f"  - Total tasks generated: {total_tasks_generated}")
            self._log(f"\n[AttackPlanningAgent] Attack History:")
            self._log(self._format_attack_history())

        except Exception as e:
            self._log(f"[AttackPlanningAgent] Error during streaming: {e}")
            import traceback
            self._log(traceback.format_exc())

        finally:
            try:
                task_queue.put(None, timeout=30)
                self._log("[AttackPlanningAgent] Streaming complete - sent termination signal")
            except Exception as e:
                self._log(f"[AttackPlanningAgent] Failed to send termination signal (queue full?): {e}")
                self._log("[AttackPlanningAgent] Executor should detect planning thread completion via join()")

            return {
                "iterations": iteration,
                "tested_requests": len(self.state.tested_requests),
                "total_tasks_generated": total_tasks_generated,
                "attack_history": self.state.attack_history
            }