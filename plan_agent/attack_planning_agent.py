"""
Attack Planning Agent - 改造版（只规划任务，不生成具体命令）
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


class ActionType(Enum):
    """攻击规划 Agent 可以执行的操作类型"""
    ANALYZE_REQUESTS = "analyze_requests"
    SKIP_REQUESTS = "skip_requests"  # ← 新增：跳过无法攻击的请求
    FINISH = "finish"


@dataclass
class AttackTask:
    """
    攻击任务（描述化）

    不再包含具体的payload，而是任务描述
    """
    task_id: str  # 如 "TASK001"
    task_description: str  # 任务描述，如"测试用户ID参数是否存在SQL注入漏洞"
    vuln_type: str  # 漏洞类型标签（SQL_INJECTION, XSS, IDOR等）
    target_request: Dict[str, Any]  # 完整请求对象（含response）
    account_identifier: str  # 使用的账户（自动分配：深度爬取用深度账户，浅层用unauthenticated）


@dataclass
class AttackState:
    """攻击状态，追踪哪些请求已被测试"""
    tested_requests: Set[Tuple[str, str]] = field(default_factory=set)  # (method, url)
    attack_history: List[Dict[str, str]] = field(default_factory=list)
    total_tasks_generated: int = 0


class AttackPlanningAgent:
    """
    攻击规划 Agent - 改造版
    
    职责：
    1. 分析请求图，识别潜在漏洞点
    2. 生成攻击任务描述（而非具体命令）
    3. 提供完整请求信息给下游Agent
    """
    
    def __init__(self, client: OpenAI, crawler: Crawler,
                 account_manager,
                 prompt_file: str = "prompt/attack_plan_agent.txt",
                 ctf_description: Optional[str] = None,
                 default_account: str = None,
                 include_trace_requests: bool = True,  # 🆕 默认启用trace请求
                 planning_mode: str = "llm"):  # 🆕 规划模式："llm" 或 "exhaustive"
        self.client = client
        self.crawler = crawler
        self.state = AttackState()
        self.account_manager = account_manager
        self.ctf_description = ctf_description  # ✅ CTF 描述信息（可选）
        self.default_account = default_account  # ✅ 默认账户（深度用深度账户，浅层用unauthenticated）
        self.include_trace_requests = include_trace_requests  # 🆕 是否包含trace请求
        self.planning_mode = planning_mode  # 🆕 规划模式：llm（LLM智能规划）或 exhaustive（穷举全测）

        # 设置日志
        log_base = Path(self.crawler.root_dir) / "attack_agent"
        log_base.mkdir(parents=True, exist_ok=True)
        self._log_path = log_base / "attack_plan.log"

        # 🆕 任务记录
        attack_planning_dir = Path(self.crawler.root_dir) / "attack_planning"
        attack_planning_dir.mkdir(parents=True, exist_ok=True)
        self._tasks_json_path = attack_planning_dir / "planned_attacks.json"
        self.planned_attacks: List[Dict[str, Any]] = []  # 存储所有规划的攻击任务
        self._cached_graph = None

        # 🆕 消融实验：定义所有漏洞类型（用于穷举模式）
        self.all_vuln_types = [
            "SQL_INJECTION",         # SQL注入
            "XSS",                   # 跨站脚本
            "XXE",                   # XML外部实体注入
            "SSTI",                  # 服务端模板注入
            "SSRF",                  # 服务端请求伪造
            "CMDI",                  # 命令注入
            "PATH_TRAVERSAL",        # 路径遍历
            "BUSINESS_LOGIC"         # 业务逻辑漏洞（包括IDOR、越权、认证绕过等）
        ]

        # 只有在llm模式下才加载prompt模板
        if self.planning_mode == "llm":
            with open(prompt_file, 'r', encoding='utf-8') as f:
                self.prompt_template = f.read()
        else:
            self.prompt_template = None
    
    def _log(self, *args, sep=" ", end="\n"):
        """统一日志函数"""
        msg = sep.join(str(a) for a in args)
        try:
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(msg + end)
        except Exception as e:
            print(f"[Log Error] {e}")
    
    def _record_action(self, task_count: int):
        """记录历史操作"""
        self.state.attack_history.append({
            "action": "PLANNED_TASKS",
            "task_count": task_count
        })
    
    def _format_attack_history(self) -> str:
        """格式化攻击历史为字符串"""
        if not self.state.attack_history:
            return "No tasks planned yet."

        lines = []
        for i, record in enumerate(self.state.attack_history, 1):
            action = record["action"]
            # 兼容task_count和request_count两种格式
            count = record.get("task_count") or record.get("request_count", 0)
            lines.append(f"{i}. {action}: {count} tasks" if "TASK" in action else f"{i}. {action}: {count} requests")
        return "\n".join(lines)
    
    def _load_attack_graph(self) -> Dict:
        # 如果 self._cached_graph 存在且未过期（简单点就不设过期了，毕竟一轮规划中图是不变的），直接返回
        if hasattr(self, '_cached_graph') and self._cached_graph:
            return self._cached_graph

        full_graph = self.crawler._generate_execution_graph_with_requests(
            include_trace_requests=self.include_trace_requests
        )
        filtered_graph = self._filter_graph_requests(full_graph, max_requests=80)
        
        self._cached_graph = filtered_graph # 缓存起来
        return filtered_graph

    def _identify_request(self, request_dict: Dict) -> str:
        return request_dict["id"]

    def _calculate_priority(self, request: Dict, node: Dict) -> float:
        """
        计算请求优先级（用于过滤时排序）
        
        综合考虑多个因素：
        1. HTTP方法（POST > PUT/PATCH > DELETE > GET）
        2. 参数结构（有body_schema > 有URL参数 > 无参数）
        3. URL路径敏感度（API路径、管理路径等）
        4. 请求类型（修改操作 > 查询操作）
        5. URL深度（深层路径可能更重要）
        
        Args:
            request: 请求字典
            node: 所属节点（可用于上下文判断）
        
        Returns:
            优先级分数（越高越优先，范围约 0-30）
        """
        priority = 0.0

        method = request.get("method", "GET").upper()
        url = request.get("url", "")
        body_schema = request.get("body_schema", "")

        # ========== 规则1: HTTP方法优先级 ==========
        # POST最高（可能有注入、业务逻辑漏洞）
        if method == "POST":
            priority += 12.0
        # PUT/PATCH次之（修改操作）
        elif method in ["PUT", "PATCH"]:
            priority += 10.0
        # DELETE较高（危险操作）
        elif method == "DELETE":
            priority += 8.0
        # GET最低（但有参数的GET仍有价值）
        elif method == "GET":
            priority += 2.0
        else:
            # HEAD, OPTIONS等
            priority += 1.0

        # ========== 规则2: 参数结构复杂度 ==========
        # 有body_schema的请求（结构化数据，注入面大）
        if body_schema:
            field_count = len(body_schema.split(','))
            # 字段数越多，优先级越高（但有上限）
            priority += min(5.0 + field_count * 0.5, 10.0)

        # 有URL参数的GET请求
        if method == "GET" and "?" in url:
            from urllib.parse import urlparse, parse_qs
            try:
                parsed = urlparse(url)
                # 检查传统参数
                query_params = parse_qs(parsed.query)
                # 检查SPA参数（fragment中的?）
                fragment_params = {}
                if parsed.fragment and '?' in parsed.fragment:
                    fragment_query = parsed.fragment.split('?', 1)[1]
                    fragment_params = parse_qs(fragment_query)

                total_params = len(query_params) + len(fragment_params)
                # 参数数量越多，优先级越高
                priority += min(3.0 + total_params * 0.3, 6.0)
            except Exception:
                # 解析失败，给个基础分
                priority += 3.0

        # ========== 规则3: URL路径敏感度 ==========
        url_lower = url.lower()

        # 超高敏感路径（管理、删除、上传等）
        critical_paths = [
            "/admin", "/delete", "/remove", "/upload", "/exec",
            "/cmd", "/shell", "/eval", "/system"
        ]
        for path in critical_paths:
            if path in url_lower:
                priority += 5.0
                break

        # 高敏感路径（API、用户、认证等）
        high_sensitive_paths = [
            "/api/", "/user", "/auth", "/register",
            "/account", "/profile", "/settings"
        ]
        for path in high_sensitive_paths:
            if path in url_lower:
                priority += 3.0
                break

        # 中敏感路径（搜索、评论、文件等）
        medium_sensitive_paths = [
            "/search", "/query", "/comment", "/post", "/file",
            "/download", "/view", "/edit", "/update"
        ]
        for path in medium_sensitive_paths:
            if path in url_lower:
                priority += 2.0
                break

        # ========== 规则6: 特殊文件扩展名（降低优先级）==========
        # 静态资源文件优先级降低
        static_extensions = [
            ".js", ".css", ".jpg", ".jpeg", ".png", ".gif",
            ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot"
        ]
        for ext in static_extensions:
            if url_lower.endswith(ext):
                priority -= 5.0
                break

        # ========== 规则7: 常见业务逻辑漏洞路径 ==========
        # IDOR、越权等常见于这些路径
        idor_paths = [
            "/view", "/detail", "/info", "/get",
            "/user/", "/profile/", "/order/", "/message/"
        ]
        for path in idor_paths:
            if path in url_lower and ("id=" in url_lower or "?" in url):
                priority += 2.5
                break

        # 确保优先级不为负（理论上不会，但保险起见）
        return max(priority, 0.0)

    def _filter_graph_requests(self, graph: Dict, max_requests: int = 80) -> Dict:
        """
        🆕 过滤图，保留最多max_requests个请求
        
        核心逻辑：
        1. 遍历所有节点，收集所有5种类型的请求
        2. 为每个请求计算唯一标识（dedup_key）和优先级
        3. 按优先级排序，选择前max_requests个
        4. 过滤原图，只保留被选中的请求
        5. 移除所有请求都被过滤掉的空节点
        
        ⚠️ 重要：保留节点的所有原始字段（如description、abstract_page等），只过滤请求
        
        支持的请求类型：
        - page_requests: 页面加载时的网络请求
        - tasks[].requests: 任务执行时产生的请求（嵌套结构）
        - outgoing_links: 外链和动态跳转（包括SPA路由）
        - trace_requests: 从trace文件提取的孤立请求
        - pre_navigation_requests: 预跳转请求（如登录）
        
        Args:
            graph: 原始图（从_generate_execution_graph_with_requests生成）
            max_requests: 最多保留的请求数量
        
        Returns:
            过滤后的图（结构与原图相同，但请求数量减少）
        """
        self._log(f"\n[Filter] ===== 开始过滤请求 =====")

        # ========== 第1步：收集所有请求 ==========
        all_requests = []

        for node_idx, node in enumerate(graph["nodes"]):
            node_url = node.get("url", "")

            # 位置1: page_requests
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
                    self._log(f"[Filter] Warning: 无法识别page_requests中的请求: {e}")
                    continue

            # 位置2: tasks[].requests（嵌套结构）
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
                        self._log(f"[Filter] Warning: 无法识别tasks中的请求: {e}")
                        continue

            # 位置3: outgoing_links
            for req_idx, req in enumerate(node.get("outgoing_links", [])):
                try:
                    key = self._identify_request(req)
                    # 🆕 [修复] 如果请求已经测试过，就不要加入候选列表了
                    # 这样下一轮迭代时，第 81-160 名就会自动替补上来变成 Top 80
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
                    self._log(f"[Filter] Warning: 无法识别outgoing_links中的请求: {e}")
                    continue

            # 位置4: trace_requests
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
                    self._log(f"[Filter] Warning: 无法识别trace_requests中的请求: {e}")
                    continue

            # 位置5: pre_navigation_requests
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
                    self._log(f"[Filter] Warning: 无法识别pre_navigation_requests中的请求: {e}")
                    continue

        total_requests = len(all_requests)

        # 统计各类型请求数量
        location_stats = {}
        for req_info in all_requests:
            loc = req_info["location"]
            location_stats[loc] = location_stats.get(loc, 0) + 1

        self._log(f"[Filter] 收集到 {total_requests} 个请求")
        self._log(f"[Filter] 请求分布:")
        for loc, count in sorted(location_stats.items()):
            self._log(f"[Filter]   - {loc}: {count}")

        # ========== 第2步：检查是否需要过滤 ==========
        if total_requests <= max_requests:
            self._log(f"[Filter] 无需过滤 ({total_requests} <= {max_requests})")
            self._log(f"[Filter] ===== 过滤完成 =====\n")
            return graph

        # ========== 第3步：按优先级排序 ==========
        all_requests.sort(key=lambda x: x["priority"], reverse=True)

        # ========== 第4步：选择前max_requests个 ==========
        selected_requests = all_requests[:max_requests]
        selected_keys = set(req["key"] for req in selected_requests)

        filtered_count = total_requests - max_requests
        self._log(f"[Filter] 过滤掉 {filtered_count} 个低优先级请求")

        # 日志：输出优先级最高和最低的请求（用于调试）
        self._log(f"[Filter] Top 3 优先级最高的请求:")
        for i, req_info in enumerate(selected_requests[:3], 1):
            req = req_info["request"]
            self._log(f"[Filter]   {i}. [{req_info['priority']:.1f}] {req.get('method')} {req.get('url')[:70]}...")

        self._log(f"[Filter] Top 3 被过滤掉的请求:")
        filtered_out = all_requests[max_requests:]
        for i, req_info in enumerate(filtered_out[:3], 1):
            req = req_info["request"]
            self._log(f"[Filter]   {i}. [{req_info['priority']:.1f}] {req.get('method')} {req.get('url')[:70]}...")

        # ========== 第5步：过滤原图 ==========
        filtered_graph = {"nodes": []}

        for node in graph["nodes"]:
            # ✅ 关键修复：复制节点的所有字段（保留description、abstract_page等）
            filtered_node = dict(node)

            # ✅ 然后只替换请求相关的字段
            filtered_node["page_requests"] = []
            filtered_node["tasks"] = []
            filtered_node["outgoing_links"] = []
            filtered_node["trace_requests"] = []
            filtered_node["pre_navigation_requests"] = []

            # 过滤 page_requests
            for req in node.get("page_requests", []):
                try:
                    if self._identify_request(req) in selected_keys:
                        filtered_node["page_requests"].append(req)
                except Exception:
                    pass

            # 过滤 tasks（只保留有请求的任务）
            for task in node.get("tasks", []):
                filtered_task_requests = []
                for req in task.get("requests", []):
                    try:
                        if self._identify_request(req) in selected_keys:
                            filtered_task_requests.append(req)
                    except Exception:
                        pass

                # 只有任务中还有请求时，才保留这个任务
                if filtered_task_requests:
                    filtered_node["tasks"].append({
                        "description": task["description"],
                        "requests": filtered_task_requests
                    })

            # 过滤 outgoing_links
            for req in node.get("outgoing_links", []):
                try:
                    if self._identify_request(req) in selected_keys:
                        filtered_node["outgoing_links"].append(req)
                except Exception:
                    pass

            # 过滤 trace_requests
            for req in node.get("trace_requests", []):
                try:
                    if self._identify_request(req) in selected_keys:
                        filtered_node["trace_requests"].append(req)
                except Exception:
                    pass

            # 过滤 pre_navigation_requests
            for req in node.get("pre_navigation_requests", []):
                try:
                    if self._identify_request(req) in selected_keys:
                        filtered_node["pre_navigation_requests"].append(req)
                except Exception:
                    pass

            # ========== 第6步：只保留有请求的节点 ==========
            has_requests = (
                len(filtered_node["page_requests"]) > 0 or
                len(filtered_node["tasks"]) > 0 or
                len(filtered_node["outgoing_links"]) > 0 or
                len(filtered_node["trace_requests"]) > 0 or
                len(filtered_node["pre_navigation_requests"]) > 0
            )

            if has_requests:
                filtered_graph["nodes"].append(filtered_node)

        # 统计过滤后的节点数
        original_node_count = len(graph["nodes"])
        filtered_node_count = len(filtered_graph["nodes"])
        removed_node_count = original_node_count - filtered_node_count

        self._log(f"[Filter] 节点统计: {original_node_count} -> {filtered_node_count} (移除 {removed_node_count} 个空节点)")
        self._log(f"[Filter] ===== 过滤完成 =====\n")

        return filtered_graph

    def _count_pending_requests(self, graph: Dict) -> int:
        """
        统计图中待测试的请求数量

        ✅ 支持新增的请求字段：trace_requests、pre_navigation_requests
        ✅ 使用新的去重键
        """
        total = 0
        for node in graph.get("nodes", []):
            # 原有字段：page_requests
            for req in node.get("page_requests", []):
                key = self._identify_request(req)
                if key not in self.state.tested_requests:
                    total += 1

            # 原有字段：tasks中的requests
            for task in node.get("tasks", []):
                for req in task.get("requests", []):
                    key = self._identify_request(req)
                    if key not in self.state.tested_requests:
                        total += 1

            # 原有字段：outgoing_links
            for req in node.get("outgoing_links", []):
                key = self._identify_request(req)
                if key not in self.state.tested_requests:
                    total += 1

            # 🆕 新增字段：trace_requests（从trace文件提取的孤立请求）
            for req in node.get("trace_requests", []):
                key = self._identify_request(req)
                if key not in self.state.tested_requests:
                    total += 1

            # 🆕 新增字段：pre_navigation_requests（跳转前的请求，如登录）
            for req in node.get("pre_navigation_requests", []):
                key = self._identify_request(req)
                if key not in self.state.tested_requests:
                    total += 1

        return total

    def _is_request_in_current_graph(self, method: str, url: str, body_schema: Optional[str] = None) -> bool:
        """
        检查请求是否在当前图中
        ✅ 支持检查：page_requests, tasks, outgoing_links, trace_requests, pre_navigation_requests
        ✅ 支持模糊匹配：如果严格匹配失败，尝试字段相似度匹配（>80%）
        
        Args:
            method: HTTP方法
            url: URL
            body_schema: 可选的body_schema（用于POST/PUT/PATCH）
        Returns:
            True if request exists in current graph
        """
        # ========== 步骤1：严格匹配 ==========
        # 构造正确的dedup_key
        if body_schema and method.upper() in ["POST", "PUT", "PATCH"]:
            # 从body_schema构造fake_body
            keys = [k.strip() for k in body_schema.split(',')]
            body = json.dumps({k: "" for k in keys}, sort_keys=True)
        else:
            body = None
        
        # 使用正确的dedup_key检查request_mapping
        key = self.crawler._make_dedup_key(method, url, body)
        if key in self.crawler.request_mapping:
            return True
        
        # 检查是否在当前图中（包括新增字段）
        graph = self._load_attack_graph()
        for node in graph.get("nodes", []):
            # 检查 outgoing_links
            for link in node.get("outgoing_links", []):
                if link.get("method") == method and link.get("url") == url:
                    return True
            # 检查 trace_requests
            for req in node.get("trace_requests", []):
                if req.get("method") == method and req.get("url") == url:
                    return True
            # 检查 pre_navigation_requests
            for req in node.get("pre_navigation_requests", []):
                if req.get("method") == method and req.get("url") == url:
                    return True
        
        # ========== 步骤2：模糊匹配（仅对POST/PUT/PATCH且有body_schema的情况） ==========
        if body_schema and method.upper() in ["POST", "PUT", "PATCH"]:
            self._log(f"[Fuzzy Match] Strict match failed, trying fuzzy match for {method} {url}")
            
            llm_fields = set(k.strip() for k in body_schema.split(','))
            
            # 遍历 request_mapping，查找字段相似的请求
            for map_key, request in self.crawler.request_mapping.items():
                req_method, req_url, req_body = map_key
                
                # 先检查 method 和 url 是否匹配
                if req_method != method or req_url != url:
                    continue
                
                # 如果 method 和 url 匹配，检查字段相似度
                if req_body:
                    try:
                        actual_fields = set(json.loads(req_body).keys())
                        
                        # 计算字段交集
                        intersection = llm_fields & actual_fields
                        union = llm_fields | actual_fields
                        max_len = max(len(llm_fields), len(actual_fields))
                        
                        # 计算相似度（使用交集/最大值）
                        if max_len > 0:
                            similarity = len(intersection) / max_len
                            
                            self._log(f"[Fuzzy Match] Similarity: {similarity:.1%} (LLM: {len(llm_fields)} fields, Actual: {len(actual_fields)} fields, Common: {len(intersection)})")
                            
                            # 如果相似度超过80%，认为匹配
                            if similarity >= 0.8:
                                # 输出差异字段（帮助调试）
                                diff_llm = llm_fields - actual_fields
                                diff_actual = actual_fields - llm_fields
                                if diff_llm:
                                    self._log(f"[Fuzzy Match] LLM extra fields: {list(diff_llm)[:5]}{'...' if len(diff_llm) > 5 else ''}")
                                if diff_actual:
                                    self._log(f"[Fuzzy Match] Actual extra fields: {list(diff_actual)[:5]}{'...' if len(diff_actual) > 5 else ''}")
                                
                                self._log(f"[Fuzzy Match] ✓ Match found with {similarity:.1%} similarity")
                                return True
                            else:
                                self._log(f"[Fuzzy Match] ✗ Similarity {similarity:.1%} < 80%, skipping")
                    
                    except json.JSONDecodeError as e:
                        self._log(f"[Fuzzy Match] Failed to parse body as JSON: {e}")
                        continue
            
            self._log(f"[Fuzzy Match] No fuzzy match found for {method} {url}")
        
        return False

    def _get_or_create_request(self, method: str, url: str, body_schema: Optional[str] = None) -> Optional[Dict]:
        """
        获取或创建请求对象

        对于request_mapping中存在的请求，返回完整数据
        对于outgoing_links，构造简单的请求对象

        Args:
            method: HTTP方法
            url: URL
            body_schema: 可选的body_schema (用于POST/PUT/PATCH)

        Returns:
            请求对象字典，如果无法获取则返回None
        """
        # 1. 尝试精确匹配（保留原有逻辑，万一正好有空值的呢）
        if body_schema and method.upper() in ["POST", "PUT", "PATCH"]:
            keys = [k.strip() for k in body_schema.split(',')]
            fake_body = json.dumps({k: "" for k in keys}, sort_keys=True)
            target_request = self.crawler.lookup_request(method, url, fake_body)
        else:
            target_request = self.crawler.lookup_request(method, url, None)

        if target_request:
            return target_request

        # 2. [关键修复] 添加模糊匹配逻辑
        # 如果精确匹配失败，且有 body_schema，遍历 crawler 记录寻找 Key 相同的请求
        if body_schema and method.upper() in ["POST", "PUT", "PATCH"]:
            try:
                schema_keys = set(k.strip() for k in body_schema.split(','))
                
                # 遍历 crawler 中所有请求 (注意：这可能有点慢，但对于几十个请求的规模完全没问题)
                for (r_method, r_url, r_body), req_data in self.crawler.request_mapping.items():
                    # 先比对 Method 和 URL
                    if r_method == method and r_url == url and r_body:
                        try:
                            # 解析真实请求的 keys
                            real_keys = set(json.loads(r_body).keys())
                            
                            # 计算重合度（允许 LLM 漏掉一两个非关键字段）
                            if schema_keys.issubset(real_keys) or len(schema_keys & real_keys) / len(schema_keys) > 0.8:
                                self._log(f"[Fuzzy Match] Found request via schema matching for {url}")
                                return req_data
                        except:
                            continue
            except Exception as e:
                self._log(f"[Fuzzy Match] Error: {e}")

        # 检查是否是outgoing_link
        # if self._is_request_in_current_graph(method, url):
        if self._is_request_in_current_graph(method, url, body_schema):
            # 构造简单的请求对象（用于outgoing_links）
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
        """调用大语言模型"""
        try:
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
        """辅助函数：从文本块中提取所有 REF_ID"""
        ids = []
        for line in text.splitlines():
            # 匹配 "REF_ID: a1b2c3d4" 或 "ID: a1b2c3d4"
            match = re.search(r'(?:REF_)?ID:\s*([a-fA-F0-9]+)', line, re.IGNORECASE)
            if match:
                ids.append(match.group(1).strip())
        return ids

    def _parse_llm_response(self, response: str) -> Tuple[ActionType, Optional[object]]:
        """
        解析 LLM 响应 (ID 化版本)
        """
        try:
            self._log("[AttackPlanningAgent] Parsing LLM response...")
            # 移除加粗标记，干扰正则
            response = response.replace("**", "")

            # 1. 提取 Action
            action_match = re.search(r'Action:\s*(.+?)(?:\n|$)', response, re.IGNORECASE)
            if not action_match:
                # 尝试根据内容推断
                if "Attack_Tasks:" in response:
                    action_type = "analyze_requests"
                elif "Skipped_Requests:" in response:
                    action_type = "skip_requests"
                else:
                    self._log("[AttackPlanningAgent] No Action field found")
                    return (None, None)
            else:
                action_type = action_match.group(1).strip().lower()
                self._log(f"[AttackPlanningAgent] Detected action: {action_type}")

            # 2. 分支处理
            if "analyze" in action_type:
                # A. 提取 Selected Requests (仅作参考/日志，主要逻辑依赖 Attack_Tasks)
                requests_match = re.search(
                    r'Selected_Requests:\s*\n(.*?)\n\s*(?:Reasoning|Attack_Tasks)', 
                    response, re.DOTALL | re.IGNORECASE
                )
                selected_ids = []
                if requests_match:
                    selected_ids = self._parse_id_list(requests_match.group(1))

                # B. 提取 Reasoning
                reasoning = ""
                reasoning_match = re.search(r'Reasoning:\s*\n(.*?)\n\s*Attack_Tasks', response, re.DOTALL | re.IGNORECASE)
                if reasoning_match:
                    reasoning = reasoning_match.group(1).strip()

                # C. 提取 Attack Tasks (核心)
                # 找到 "Attack_Tasks:" 之后的区域
                task_lines = []
                lines = response.splitlines()
                start_idx = -1
                for i, line in enumerate(lines):
                    if "Attack_Tasks:" in line:
                        start_idx = i
                        break
                
                if start_idx != -1:
                    for line in lines[start_idx+1:]:
                        line = line.strip()
                        if not line or line.startswith("```"): continue
                        # 只提取以 [TASK 开头的行
                        if line.startswith("[TASK"):
                            task_lines.append(line)
                
                if not task_lines:
                    self._log("[AttackPlanningAgent] ⚠️ No valid task lines found")
                    return (None, None)

                return (ActionType.ANALYZE_REQUESTS, {
                    "selected_ids": selected_ids,
                    "reasoning": reasoning,
                    "task_lines": task_lines
                })

            elif "skip" in action_type:
                # A. 提取 Skipped Requests
                requests_match = re.search(
                    r'Skipped_Requests:\s*\n(.*?)\n\s*(?:Reasoning|$)', 
                    response, re.DOTALL | re.IGNORECASE
                )
                if not requests_match:
                    self._log("[AttackPlanningAgent] No Skipped_Requests section found")
                    return (None, None)
                
                skipped_ids = self._parse_id_list(requests_match.group(1))
                
                # B. 提取 Reasoning
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

    # [attack_planning_agent.py] 修改 _parse_task_line
    def _parse_task_line(self, task_line: str) -> Optional[Dict]:
        """
        解析格式：[TASK_ID] VULN_TYPE | REF_ID: <ID> | DESCRIPTION
        """
        # 🆕 新正则
        match = re.match(
            r'\[(\w+)\]\s+([A-Z_]+)\s+\|\s+(?:REF_)?ID:\s*([a-fA-F0-9]+)\s+\|\s+(.+)',
            task_line.strip(),
            re.IGNORECASE
        )

        if not match:
            # 兼容旧逻辑或报错
            return None

        task_id, vuln_type, ref_id, description = match.groups()

        return {
            "task_id": task_id.strip(),
            "vuln_type": vuln_type.strip().upper(),
            "ref_id": ref_id.strip(), # 👈 拿到 ID
            "description": description.strip()
        }

    def _parse_task_line_legacy(self, task_line: str) -> Optional[Dict]:
        """
        兼容旧格式的解析（没有METHOD URL）

        旧格式: [TASK001] SQL_INJECTION | admin | Test description
        """
        match = re.match(
            r'\[(\w+)\]\s+([A-Z_]+)\s+\|\s+(.+?)\s+\|\s+(.+)',
            task_line.strip()
        )

        if not match:
            self._log(f"[Warning] Cannot parse task line (tried both new and legacy formats): {task_line}")
            return None

        task_id, vuln_type, account_part, description = match.groups()

        # 解析账户部分
        if '->' in account_part:
            accounts = [a.strip() for a in account_part.split('->')]
        else:
            accounts = [account_part.strip()]

        return {
            "task_id": task_id.strip(),
            "vuln_type": vuln_type.strip().upper(),
            "method": None,  # 旧格式没有method
            "url": None,     # 旧格式没有url
            "accounts": accounts,
            "description": description.strip()
        }

    def _execute_analyze_action(self, action_data: Dict) -> List[AttackTask]:
        """
        执行分析动作 (ID 化版本)
        """
        task_lines = action_data.get("task_lines", [])
        reasoning = action_data.get("reasoning", "")
        
        self._log(f"\n[AttackPlanningAgent] Processing {len(task_lines)} tasks")
        if reasoning:
            self._log(f"[AttackPlanningAgent] Reasoning: {reasoning}")

        attack_tasks = []
        
        # 🆕 临时集合：记录本轮涉及的 ID，防止循环内自己阻塞自己
        # 但同时也要防止本轮内的重复（虽然不致命，但为了逻辑严谨）
        current_batch_processed_ids = set()

        for task_line in task_lines:
            # ... (解析逻辑不变) ...
            parsed = self._parse_task_line(task_line)
            if not parsed: 
                continue
            
            task_id = parsed["task_id"]
            ref_id = parsed["ref_id"]
            description = parsed["description"]
            vuln_type = parsed["vuln_type"]

            # 1. 检查是否在【历史】中已处理 (防止处理上一轮的老请求)
            if ref_id in self.state.tested_requests:
                self._log(f"[Warning] Request {ref_id} already tested (history), skipping task {task_id}")
                continue

            # 2. 获取原始请求 (逻辑不变)
            target_request = self.crawler.request_id_map.get(ref_id)
            if not target_request:
                self._log(f"[Error] Task {task_id}: Invalid REF_ID '{ref_id}'")
                continue
            
            # 3. 生成 AttackTask 对象 (逻辑不变)
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

            # 4. 记录到 JSON (逻辑不变)
            self.planned_attacks.append({
                # ... (字段省略，保持原样) ...
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
            
            # ✅ 关键修改：不要在这里更新 self.state.tested_requests
            # 而是记录到临时集合中
            current_batch_processed_ids.add(ref_id)
            
            # 同步更新 crawler 的 processed 集合 (如果 crawler 支持)
            # 这里可以保留，因为 crawler 的 lookup 不会影响当前的循环逻辑
            if hasattr(self.crawler, 'processed_requests'):
                key = self.crawler._make_dedup_key(target_request['method'], target_request['url'], target_request.get('body'))
                self.crawler.processed_requests.add(key) 

        # ✅ 循环结束后，统一更新全局状态
        # 这样同一个 ID 的 6 个任务都能顺利通过循环，最后 ID 才会被标记为“已测试”
        if current_batch_processed_ids:
            self._log(f"[AttackPlanningAgent] Marking {len(current_batch_processed_ids)} requests as tested.")
            self.state.tested_requests.update(current_batch_processed_ids)

        # 记录统计
        self._record_action(len(attack_tasks))
        self.state.total_tasks_generated += len(attack_tasks)
        self._save_tasks_to_json()

        return attack_tasks
    
    def _find_matching_request(self, selected_requests: List[Tuple[str, str, str]],
                               description: str) -> Optional[Dict]:
        """
        根据任务描述找到匹配的完整请求

        策略：
        1. 从描述中提取HTTP方法和URL路径
        2. 在selected_requests中找到匹配的请求
        3. 如果找不到精确匹配，返回 None（不再乱匹配）

        Args:
            selected_requests: List of (method, url, body_schema) tuples

        Returns:
            完整请求对象（含response）或None
        """
        if not selected_requests:
            return None

        # 智能匹配：从描述中提取HTTP方法和URL
        import re

        # 匹配模式：GET /path、POST /path 等
        method_url_pattern = r'\b(GET|POST|PUT|DELETE|PATCH)\s+([/\w\-\.?=&]+)'
        matches = re.findall(method_url_pattern, description, re.IGNORECASE)

        if matches:
            # 尝试匹配每个提取出的方法+URL
            for desc_method, desc_url in matches:
                desc_method = desc_method.upper()

                # ✅ 修复：解包三元组 (method, url, body_schema)
                for req_tuple in selected_requests:
                    if len(req_tuple) == 3:
                        req_method, req_url, body_schema = req_tuple
                    else:
                        # 兼容旧格式
                        req_method, req_url = req_tuple[0], req_tuple[1]
                        body_schema = None

                    # 精确匹配或路径包含匹配
                    if req_method.upper() == desc_method and (
                        desc_url in req_url or req_url.endswith(desc_url)
                    ):
                        # 找到匹配！
                        # ✅ 使用 body_schema 来查找完整请求
                        full_request = self._get_or_create_request(req_method, req_url, body_schema)
                        if full_request:
                            return full_request

        # ✅ 没有找到匹配，返回 None（不再乱匹配）
        return None

    def _execute_skip_action(self, action_data: Dict) -> int:
        """
        执行 Skip 动作 (ID 化版本)
        直接通过 ID 标记请求为已处理。
        """
        skipped_ids = action_data.get("skipped_ids", [])
        reasoning = action_data.get("reasoning", "")
        
        self._log(f"\n[AttackPlanningAgent] Skipping {len(skipped_ids)} requests")
        if reasoning:
            self._log(f"[AttackPlanningAgent] Reasoning: {reasoning}")
            
        valid_count = 0
        for ref_id in skipped_ids:
            # 1. 检查是否已处理
            if ref_id in self.state.tested_requests:
                continue
            
            # 2. 校验 ID 是否有效 (存在于 Crawler 中)
            target_request = self.crawler.request_id_map.get(ref_id)
            if not target_request:
                self._log(f"[Warning] Cannot skip invalid ID: {ref_id}")
                continue
                
            # 3. 标记为已处理
            self.state.tested_requests.add(ref_id)
            
            # 同步 Crawler 状态 (防止下一轮继续出现)
            if hasattr(self.crawler, 'processed_requests'):
                key = self.crawler._make_dedup_key(target_request['method'], target_request['url'], target_request.get('body'))
                self.crawler.processed_requests.add(key)
                
            valid_count += 1
            self._log(f"  [SKIPPED] ID: {ref_id}")
            
        self._log(f"[AttackPlanningAgent] Successfully skipped {valid_count}/{len(skipped_ids)} requests")
        
        # 记录历史
        self.state.attack_history.append({
            "action": "SKIPPED_REQUESTS",
            "request_count": valid_count
        })
        
        return valid_count
    
    def plan_and_execute(self, max_iterations: int = 100) -> Dict:
        """
        主规划循环 - 收集所有攻击任务

        🆕 支持两种模式：
        - llm: 使用LLM智能规划（原有逻辑）
        - exhaustive: 穷举模式，为每个请求生成所有漏洞类型的任务

        Returns:
            {
                "iterations": int,
                "tested_requests": int,
                "all_tasks": List[AttackTask],
                "attack_history": List[Dict]
            }
        """
        self._cached_graph = None

        # 🆕 根据模式选择实现
        if self.planning_mode == "exhaustive":
            self._log("[AttackPlanningAgent] Using EXHAUSTIVE mode (no LLM)")
            return self.plan_exhaustive(max_requests=None)

        # 原有的LLM模式逻辑
        self._log("[AttackPlanningAgent] Using LLM mode (intelligent planning)")
        self._log("[AttackPlanningAgent] Starting attack planning")

        all_tasks = []  # 收集所有任务

        iteration = 0
        while iteration < max_iterations:
            iteration += 1
            self._log(f"\n{'='*60}")
            self._log(f"[AttackPlanningAgent] Iteration {iteration}")

            # ✅ 修复：每一轮迭代都必须强制清除缓存的图
            # 这样 _load_attack_graph 才会重新过滤，把已经测试过的 Top 10 排除，
            # 让第 11-20 名浮上来变成新的 Top 10。
            self._cached_graph = None 

            # 加载当前图
            graph = self._load_attack_graph()
            
            pending = self._count_pending_requests(graph)
            
            if pending == 0:
                self._log("[AttackPlanningAgent] No pending requests, finishing")
                break

            # 格式化历史
            attack_history_str = self._format_attack_history()

            # ✅ 构造 CTF 描述部分（如果提供）
            ctf_context = ""
            if self.ctf_description:
                ctf_context = f"\n\n=== CTF CHALLENGE DESCRIPTION ===\n{self.ctf_description}\n\nIMPORTANT: Focus on vulnerabilities that might be related to achieving the goal described above. Think divergently - if the description mentions 'login as admin', consider not just SQL injection, but also SSRF (to modify admin password), IDOR (to access admin resources), business logic flaws, etc."

            # 构造prompt
            graph_json = json.dumps(graph, indent=2, ensure_ascii=False)
            prompt = self.prompt_template.format(
                graph_json=graph_json,
                total_requests=len(self.crawler.request_mapping),
                tested_requests=len(self.state.tested_requests),
                pending_requests=pending,
                attack_history=attack_history_str
            ) + ctf_context  # ✅ 拼接 CTF 描述
            
            # 调用LLM
            llm_response = self._call_llm(prompt)
            
            self._log("\n[LLM input]:")
            self._log(prompt)
            self._log("\n[LLM Response]:")
            self._log(llm_response)
            self._log("\n" + "="*60)
            
            if not llm_response:
                break
            
            # 解析响应
            action_type, action_data = self._parse_llm_response(llm_response)

            
            if action_type is None:
                self._log(f"[AttackPlanningAgent] ⚠️ Invalid response")
                # 不做任何标记、不生成任务
            elif action_type == ActionType.ANALYZE_REQUESTS:
                tasks = self._execute_analyze_action(action_data)
                all_tasks.extend(tasks)
            elif action_type == ActionType.SKIP_REQUESTS:
                # ========== 新增：处理skip_requests ==========
                self._execute_skip_action(action_data)
            elif action_type == ActionType.FINISH:
                self._log("[AttackPlanningAgent] Planning completed")
                break

        
        # 输出统计
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
            "all_tasks": all_tasks,  # 返回AttackTask对象列表
            "attack_history": self.state.attack_history
        }
    
    def plan_exhaustive(self, max_requests: Optional[int] = None) -> Dict:
        """
        🆕 穷举模式 - 为每个请求生成所有漏洞类型的任务（消融实验用）

        不使用LLM，直接为每个请求生成所有漏洞类型的测试任务

        Args:
            max_requests: 最大处理请求数（None表示处理所有请求）

        Returns:
            {
                "tested_requests": int,
                "all_tasks": List[AttackTask],
                "attack_history": List[Dict]
            }
        """
        self._log("[AttackPlanningAgent - EXHAUSTIVE MODE] Starting exhaustive attack planning")
        self._log(f"[Mode] Exhaustive (generate all vulnerability types for each request)")

        all_tasks = []
        task_counter = 0

        # 获取所有请求
        all_requests = list(self.crawler.request_mapping.items())
        total_requests = len(all_requests)

        if max_requests:
            all_requests = all_requests[:max_requests]
            self._log(f"[Limit] Processing {len(all_requests)}/{total_requests} requests")
        else:
            self._log(f"[Processing] All {total_requests} requests")

        self._log(f"[Vulnerability Types] {len(self.all_vuln_types)} types: {', '.join(self.all_vuln_types)}")
        self._log(f"[Expected Tasks] {len(all_requests)} requests × {len(self.all_vuln_types)} types = {len(all_requests) * len(self.all_vuln_types)} tasks\n")

        # 遍历所有请求
        for idx, ((method, url), target_request) in enumerate(all_requests, 1):
            self._log(f"[{idx}/{len(all_requests)}] Processing: {method} {url}")

            # 为每个请求生成所有漏洞类型的任务
            for vuln_type in self.all_vuln_types:
                task_counter += 1
                task_id = f"TASK{task_counter:03d}"

                # 🆕 生成硬编码的任务描述
                task_description = self._generate_hardcoded_description(vuln_type, method, url)

                # 创建AttackTask
                task = AttackTask(
                    task_id=task_id,
                    task_description=task_description,
                    vuln_type=vuln_type,
                    target_request=target_request,
                    account_identifier=self.default_account if self.default_account else "default_account"
                )

                all_tasks.append(task)

                # 记录到planned_attacks列表（用于JSON导出）
                self.planned_attacks.append({
                    "task_id": task_id,
                    "task_description": task_description,
                    "vuln_type": vuln_type,
                    "account": task.account_identifier,
                    "status": "planned",
                    "target_request": {
                        "method": target_request.get("method"),
                        "url": target_request.get("url"),
                        "headers": target_request.get("headers", {}),
                        "query_params": target_request.get("query_params", {}),
                        "body": target_request.get("body"),
                        "response_status": target_request.get("response_status"),
                        "response_headers": target_request.get("response_headers", {}),
                        # 修改后：保留完整内容（或者限制放宽到 50KB）
                        "response_body": target_request.get("response_body", "")
                    }
                })

            # 标记请求为已处理
            body = target_request.get("body") if target_request else None
            self.crawler.mark_request_processed(method, url, body)
            key = self.crawler._make_dedup_key(method, url, body)
            self.state.tested_requests.add(key)

            # 每10个请求输出一次进度
            if idx % 10 == 0:
                self._log(f"  → Generated {len(all_tasks)} tasks so far...")

        # 记录操作历史
        self._record_action(len(all_tasks))
        self.state.total_tasks_generated = len(all_tasks)

        # 保存任务到JSON
        self._save_tasks_to_json()

        # 输出统计
        self._log(f"\n{'='*60}")
        self._log("[AttackPlanningAgent - EXHAUSTIVE MODE] Final Statistics:")
        self._log(f"  - Mode: Exhaustive (no LLM)")
        self._log(f"  - Requests processed: {len(all_requests)}")
        self._log(f"  - Vulnerability types: {len(self.all_vuln_types)}")
        self._log(f"  - Total tasks generated: {len(all_tasks)}")
        self._log(f"  - Average tasks/request: {len(all_tasks)/len(all_requests):.1f}")
        self._log(f"{'='*60}\n")

        return {
            "tested_requests": len(self.state.tested_requests),
            "all_tasks": all_tasks,
            "attack_history": self.state.attack_history
        }

    def _generate_hardcoded_description(self, vuln_type: str, method: str, url: str) -> str:
        """
        🆕 生成硬编码的任务描述（消融实验用）

        Args:
            vuln_type: 漏洞类型
            method: HTTP方法
            url: URL

        Returns:
            任务描述字符串
        """
        # 根据漏洞类型生成标准描述
        descriptions = {
            "SQL_INJECTION": f"Test if the {method} request to {url} is vulnerable to SQL injection",
            "XSS": f"Test if the {method} request to {url} is vulnerable to Cross-Site Scripting (XSS)",
            "XXE": f"Test if the {method} request to {url} is vulnerable to XML External Entity (XXE) injection",
            "SSTI": f"Test if the {method} request to {url} is vulnerable to Server-Side Template Injection (SSTI)",
            "SSRF": f"Test if the {method} request to {url} is vulnerable to Server-Side Request Forgery (SSRF)",
            "CMDI": f"Test if the {method} request to {url} is vulnerable to Command Injection",
            "PATH_TRAVERSAL": f"Test if the {method} request to {url} is vulnerable to Path Traversal",
            "BUSINESS_LOGIC": f"Test if the {method} request to {url} has business logic vulnerabilities (IDOR, privilege escalation, authentication bypass, etc.)"
        }

        return descriptions.get(vuln_type, f"Test if the {method} request to {url} is vulnerable to {vuln_type}")

    def plan_exhaustive_stream(self, task_queue):
        """
        🆕 穷举模式流式版本 - 为每个请求生成所有漏洞类型的任务并放入队列（消融实验用）

        不使用LLM，直接为每个请求生成所有漏洞类型的测试任务，并实时放入队列

        Args:
            task_queue: queue.Queue对象，用于传递任务

        执行完成后会向队列放入None作为结束信号
        """
        self._log("[AttackPlanningAgent - EXHAUSTIVE STREAMING] Starting")
        self._log(f"[Mode] Exhaustive streaming (generate all vulnerability types for each request)")

        task_counter = 0
        total_tasks_generated = 0

        try:
            # 获取所有请求
            all_requests = list(self.crawler.request_mapping.items())
            total_requests = len(all_requests)

            self._log(f"[Processing] All {total_requests} requests")
            self._log(f"[Vulnerability Types] {len(self.all_vuln_types)} types: {', '.join(self.all_vuln_types)}")
            self._log(f"[Expected Tasks] {total_requests} requests × {len(self.all_vuln_types)} types = {total_requests * len(self.all_vuln_types)} tasks\n")

            # 遍历所有请求
            for idx, ((method, url), target_request) in enumerate(all_requests, 1):
                self._log(f"[{idx}/{total_requests}] Processing: {method} {url}")

                # 为每个请求生成所有漏洞类型的任务
                for vuln_type in self.all_vuln_types:
                    task_counter += 1
                    task_id = f"TASK{task_counter:03d}"

                    # 生成硬编码的任务描述
                    task_description = self._generate_hardcoded_description(vuln_type, method, url)

                    # 创建AttackTask
                    task = AttackTask(
                        task_id=task_id,
                        task_description=task_description,
                        vuln_type=vuln_type,
                        target_request=target_request,
                        account_identifier=self.default_account if self.default_account else "default_account"
                    )

                    # ✅ 立即将任务放入队列（供执行器消费）
                    task_queue.put(task)
                    total_tasks_generated += 1

                    # 记录到planned_attacks列表（用于JSON导出）
                    self.planned_attacks.append({
                        "task_id": task_id,
                        "task_description": task_description,
                        "vuln_type": vuln_type,
                        "account": task.account_identifier,
                        "status": "planned",
                        "target_request": {
                            "method": target_request.get("method"),
                            "url": target_request.get("url"),
                            "headers": target_request.get("headers", {}),
                            "query_params": target_request.get("query_params", {}),
                            "body": target_request.get("body"),
                            "response_status": target_request.get("response_status"),
                            "response_headers": target_request.get("response_headers", {}),
                            # 修改后：保留完整内容（或者限制放宽到 50KB）
                            "response_body": target_request.get("response_body", "")
                        }
                    })

                # 标记请求为已处理
                body = target_request.get("body") if target_request else None
                self.crawler.mark_request_processed(method, url, body)
                key = self.crawler._make_dedup_key(method, url, body)
                self.state.tested_requests.add(key)

                # 每10个请求输出一次进度
                if idx % 10 == 0:
                    self._log(f"  → Pushed {total_tasks_generated} tasks to queue so far...")

            # 记录操作历史
            self._record_action(total_tasks_generated)
            self.state.total_tasks_generated = total_tasks_generated

            # 保存任务到JSON
            self._save_tasks_to_json()

            # 输出统计
            self._log(f"\n{'='*60}")
            self._log("[AttackPlanningAgent - EXHAUSTIVE STREAMING] Final Statistics:")
            self._log(f"  - Mode: Exhaustive streaming (no LLM)")
            self._log(f"  - Requests processed: {total_requests}")
            self._log(f"  - Vulnerability types: {len(self.all_vuln_types)}")
            self._log(f"  - Total tasks generated: {total_tasks_generated}")
            self._log(f"  - Average tasks/request: {total_tasks_generated/total_requests:.1f}")
            self._log(f"{'='*60}\n")

        except Exception as e:
            self._log(f"[AttackPlanningAgent - EXHAUSTIVE STREAMING] Error: {e}")
            import traceback
            self._log(traceback.format_exc())

        finally:
            # ✅ 发送结束信号
            try:
                task_queue.put(None, timeout=30)
                self._log("[AttackPlanningAgent - EXHAUSTIVE STREAMING] Complete - sent termination signal")
            except Exception as e:
                self._log(f"[AttackPlanningAgent - EXHAUSTIVE STREAMING] ⚠️ Failed to send termination signal: {e}")

            return {
                "tested_requests": len(self.state.tested_requests),
                "total_tasks_generated": total_tasks_generated,
                "attack_history": self.state.attack_history
            }

    def reset_state(self):
        """重置攻击状态"""
        self.state = AttackState()
        self._log("[AttackPlanningAgent] State reset")

    def _save_tasks_to_json(self):
        """
        保存所有规划的攻击任务到JSON文件

        格式：
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
            self._log(f"[AttackPlanningAgent] 保存任务到JSON: {self._tasks_json_path} (共{len(self.planned_attacks)}个任务)")
        except Exception as e:
            self._log(f"[AttackPlanningAgent] 保存任务JSON失败: {e}")

    def plan_and_stream(self, task_queue, max_iterations: int = 100):
        """
        🆕 流式规划模式 - 持续生成任务并放入队列（用于流水线并行）

        🆕 支持两种模式：
        - llm: 每次LLM生成一批任务后，立即放入队列供执行器消费
        - exhaustive: 穷举模式，流式生成所有请求的所有漏洞类型任务

        Args:
            task_queue: queue.Queue对象，用于传递任务
            max_iterations: 最大迭代次数（仅llm模式使用）

        执行完成后会向队列放入None作为结束信号
        """
        # 🆕 根据模式选择实现
        if self.planning_mode == "exhaustive":
            self._log("[AttackPlanningAgent] Using EXHAUSTIVE mode (streaming, no LLM)")
            return self.plan_exhaustive_stream(task_queue)

        # 原有的LLM流式模式逻辑
        self._log("[AttackPlanningAgent] Using LLM mode (streaming)")
        self._log("[AttackPlanningAgent] Starting streaming attack planning")

        iteration = 0
        total_tasks_generated = 0
        consecutive_invalid_responses = 0  # 连续无效响应计数器

        try:
            while iteration < max_iterations:
                iteration += 1
                self._log(f"\n{'='*60}")
                self._log(f"[AttackPlanningAgent] Iteration {iteration}")

                # 🚨🚨🚨 【这里漏了！必须补上这一行】 🚨🚨🚨
                self._cached_graph = None
                # 加载当前图
                graph = self._load_attack_graph()
                pending = self._count_pending_requests(graph)

                if pending == 0:
                    self._log("[AttackPlanningAgent] No pending requests, finishing")
                    break

                # 格式化历史
                attack_history_str = self._format_attack_history()

                # 构造 CTF 描述部分（如果提供）
                ctf_context = ""
                if self.ctf_description:
                    ctf_context = f"\n\n=== CTF CHALLENGE DESCRIPTION ===\n{self.ctf_description}\n\nIMPORTANT: Focus on vulnerabilities that might be related to achieving the goal described above. Think divergently - if the description mentions 'login as admin', consider not just SQL injection, but also SSRF (to modify admin password), IDOR (to access admin resources), business logic flaws, etc."

                # 构造prompt
                graph_json = json.dumps(graph, indent=2, ensure_ascii=False)
                prompt = self.prompt_template.format(
                    graph_json=graph_json,
                    total_requests=len(self.crawler.request_mapping),
                    tested_requests=len(self.state.tested_requests),
                    pending_requests=pending,
                    attack_history=attack_history_str
                ) + ctf_context

                # 调用LLM
                llm_response = self._call_llm(prompt)

                self._log("\n[LLM input]:")
                self._log(prompt)
                self._log("\n[LLM Response]:")
                self._log(llm_response)
                self._log("\n" + "="*60)

                if not llm_response:
                    break

                # 解析响应
                action_type, action_data = self._parse_llm_response(llm_response)

                # ✅ 处理无效响应（LLM 格式错误但意图继续工作）
                if action_type is None:
                    consecutive_invalid_responses += 1
                    self._log(f"[AttackPlanningAgent] ⚠️ Invalid response (consecutive: {consecutive_invalid_responses})")
                    self._log("[AttackPlanningAgent] → Skipping this iteration, will retry in next iteration")

                    # 如果连续失败超过 5 次，才真正结束
                    if consecutive_invalid_responses >= 5:
                        self._log("[AttackPlanningAgent] ⚠️ Too many consecutive invalid responses (5+), stopping")
                        break

                    # 否则继续下一次迭代（不标记任何请求，不做任何操作）
                    continue

                # 重置连续失败计数器（收到有效响应）
                consecutive_invalid_responses = 0

                if action_type == ActionType.ANALYZE_REQUESTS:
                    # 生成任务
                    tasks = self._execute_analyze_action(action_data)

                    # ✅ 立即将任务放入队列（供执行器消费）
                    for task in tasks:
                        task_queue.put(task)
                        self._log(f"[Stream] Task {task.task_id} pushed to queue")

                    total_tasks_generated += len(tasks)

                elif action_type == ActionType.SKIP_REQUESTS:
                    self._execute_skip_action(action_data)

                elif action_type == ActionType.FINISH:
                    self._log("[AttackPlanningAgent] Planning completed")
                    break

            # 输出统计
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
            # ✅ 发送结束信号（带超时，避免队列满时阻塞）
            try:
                task_queue.put(None, timeout=30)
                self._log("[AttackPlanningAgent] Streaming complete - sent termination signal")
            except Exception as e:
                self._log(f"[AttackPlanningAgent] ⚠️ Failed to send termination signal (queue full?): {e}")
                self._log("[AttackPlanningAgent] Executor should detect planning thread completion via join()")

            return {
                "iterations": iteration,
                "tested_requests": len(self.state.tested_requests),
                "total_tasks_generated": total_tasks_generated,
                "attack_history": self.state.attack_history
            }