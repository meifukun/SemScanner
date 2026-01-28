# -*- coding: utf-8 -*-
# crawl/webapp_store.py
from __future__ import annotations
from typing import Dict, List, Optional, Tuple, Iterable
from pathlib import Path
import json
import threading  # 🆕 线程安全
from app_info.models import PageInfo, Edge, TaskRunTrace
from urllib.parse import urlparse


class WebAppStore:
    """
    Web 应用信息存储（🆕 线程安全版本）
    - 节点（PageInfo）
    - 边（Edge）
    - 任务运行轨迹（TaskRunTrace）
    - 可选导出图快照（graph.json / mermaid）
    持久化策略：内存为主，追加 JSONL 便于复盘/可视化
    """

    def __init__(self, root_dir: str = "output/webapp_store"):
        self.root = Path(root_dir)
        self.root.mkdir(parents=True, exist_ok=True)

        # 内存态
        self.pages: Dict[str, PageInfo] = {}         # url -> PageInfo
        self.edges: List[Edge] = []                  # 边的顺序列表（便于回放）
        self._edge_keys: set[Tuple[str, str, int, str, str]] = set()  # 去重键 (from,to,action_id,via_repr,jump_kind)

        # 🆕 线程安全：保护共享数据结构
        self._lock = threading.RLock()  # 使用递归锁，支持同一线程多次获取

        # 落盘路径
        self.pages_jsonl = self.root / "pages.jsonl"
        self.edges_jsonl = self.root / "edges.jsonl"
        self.graph_json = self.root / "graph.json"
        self.graph_mermaid = self.root / "graph.mmd"
        self.traces_dir = self.root / "traces"
        self.traces_dir.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------------------
    # Pages
    # ---------------------------------------------------------------------
    def has_page(self, url: str) -> bool:
        """严格按 URL（含 query）判断是否已有该页面节点"""
        return url in self.pages

    def has_main_page(self, url: str) -> bool:
        """
        忽略 query 判断是否已有“主页面”（用于避免 query 变体造成重复页面）
        """
        cleaned_url = url.split('?', 1)[0]
        for page_url in self.pages:
            if page_url.split('?', 1)[0] == cleaned_url:
                return True
        return False

    def get_page(self, url: str) -> Optional[PageInfo]:
        return self.pages.get(url)

    def add_page(self, info: PageInfo, persist: bool = True) -> None:
        """
        直接写入（覆盖同 URL 的旧值）；一般建议用 upsert_page() 做合并。
        🆕 线程安全版本
        """
        with self._lock:
            self.pages[info.url] = info
            if persist:
                with self.pages_jsonl.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(info.to_dict(), ensure_ascii=False) + "\n")

    def upsert_page(
        self,
        info: PageInfo,
        merge_outgoing_links: bool = True,
        merge_requests: bool = True,
        persist: bool = True,
    ) -> None:
        """
        插入或合并页面信息（🆕 线程安全版本）

        改进：
        - 支持 logic_tasks 的合并
        - persist=True 时，先清理旧记录再追加（可选，防止JSONL膨胀）
        """
        with self._lock:
            if info.url not in self.pages:
                self.add_page(info, persist=persist)
                return

            old = self.pages[info.url]

            title = info.title or old.title
            abstract_page = info.abstract_page or old.abstract_page
            description = info.description or old.description

            # ✅ 新增：logic_tasks 直接覆盖（由规划agent管理）
            logic_tasks = info.logic_tasks if info.logic_tasks else old.logic_tasks

            # ✅ 保留 actions_mapping（修复任务执行时找不到映射的问题）
            actions_mapping = info.actions_mapping if info.actions_mapping else old.actions_mapping

            # 🆕 保留 event_mapping（事件映射）
            event_mapping = info.event_mapping if info.event_mapping else old.event_mapping

            if merge_outgoing_links:
                old_links = list(dict.fromkeys(old.outgoing_links))
                new_links = list(dict.fromkeys(info.outgoing_links or []))
                merged_links = list(dict.fromkeys(old_links + new_links))
            else:
                merged_links = info.outgoing_links or old.outgoing_links

            if merge_requests:
                def _key(r) -> Tuple[str, str, Optional[int]]:
                    try:
                        return (r.method, r.url, getattr(r, "response_status", None))
                    except AttributeError:
                        return (r.get("method"), r.get("url"), r.get("response_status"))
                seen = {_key(r) for r in (old.network_requests or [])}
                merged_reqs = list(old.network_requests or [])
                for r in info.network_requests or []:
                    k = _key(r)
                    if k not in seen:
                        merged_reqs.append(r)
                        seen.add(k)
            else:
                merged_reqs = info.network_requests or old.network_requests

            updated = PageInfo(
                url=info.url,
                title=title,
                abstract_page=abstract_page,
                description=description,
                outgoing_links=merged_links,
                network_requests=merged_reqs,
                logic_tasks=logic_tasks,
                actions_mapping=actions_mapping,
                event_mapping=event_mapping  # 🆕 添加事件映射
            )
            self.pages[info.url] = updated

            if persist:
                with self.pages_jsonl.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(updated.to_dict(), ensure_ascii=False) + "\n")

    def list_pages(self) -> Iterable[PageInfo]:
        return self.pages.values()

    # ---------------------------------------------------------------------
    # Edges
    # ---------------------------------------------------------------------
    def _edge_key(self, e: Edge) -> Tuple[str, str, int, str, str]:
        return (e.from_url, e.to_url, e.via_action_id, e.via_repr, e.jump_kind)

    def has_to_url(self, to_url: str) -> bool:
        """是否已有指向该 to_url 的任何边（你原来 has_edge 的语义）"""
        return any(e.to_url == to_url for e in self.edges)

    def has_edge_pair(self, from_url: str, to_url: str) -> bool:
        """严格判断是否已存在 from→to 的边"""
        return any(e.from_url == from_url and e.to_url == to_url for e in self.edges)

    # 为了向后兼容：保留 has_edge，并保持你原先“只看 to_url”的行为
    def has_edge(self, from_url: str, to_url: str) -> bool:
        """
        兼容旧逻辑：仅根据 to_url 判断是否“出现过该目标 URL”
        如需严格判断是否已存在 from→to，请使用 has_edge_pair()
        """
        return self.has_to_url(to_url)

    def add_edge(self, edge: Edge, persist: bool = True) -> bool:
        """
        加入一条边；若重复（按 from,to,action_id,via_repr,jump_kind），则忽略并返回 False
        🆕 线程安全版本
        """
        with self._lock:
            k = self._edge_key(edge)
            if k in self._edge_keys:
                return False
            self._edge_keys.add(k)
            self.edges.append(edge)

            if persist:
                with self.edges_jsonl.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(edge.to_dict(), ensure_ascii=False) + "\n")
            return True

    def list_edges(self) -> Iterable[Edge]:
        return self.edges

    # ---------------------------------------------------------------------
    # Graph Export (可选)
    # ---------------------------------------------------------------------
    def export_graph(self) -> None:
        """
        导出一个包含更多节点属性的快照（非必须，仅用于可视化或给其他 agent 冷启动）
        """
        nodes = []
        for url, p in self.pages.items():
            nodes.append({
                "id": url,
                "title": p.title,
                "abstract_page": p.abstract_page,
                "outgoing_count": len(p.outgoing_links or []),
                "request_count": len(p.network_requests or []),
            })

        edges = []
        for e in self.edges:
            edges.append({
                "source": e.from_url,
                "target": e.to_url,
                "label": e.via_repr,
                "kind": e.jump_kind,
            })

        graph = {"nodes": nodes, "edges": edges}
        self.graph_json.write_text(json.dumps(graph, ensure_ascii=False, indent=2), encoding="utf-8")

    def export_mermaid(self, max_nodes: int = 500) -> None:
        """
        快速导出 Mermaid 流程图（仅结构，不含属性），便于 README/问题复现
        """
        lines = ["graph LR"]
        # 节点限额避免极大图导致渲染卡顿
        count = 0
        for e in self.edges:
            lines.append(f'    "{e.from_url}" -- "{e.via_repr or e.jump_kind}" --> "{e.to_url}"')
            count += 1
            if count >= max_nodes:
                lines.append("    %% ... truncated ...")
                break
        self.graph_mermaid.write_text("\n".join(lines), encoding="utf-8")

    # ---------------------------------------------------------------------
    # Task Trace
    # ---------------------------------------------------------------------
    def save_trace(self, trace: TaskRunTrace) -> None:
        p = self.traces_dir / f"task_{trace.task_id}.json"
        p.write_text(json.dumps(trace.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")

    # ---------------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------------
    def summary(self) -> Dict[str, int]:
        """返回一个轻量摘要，便于日志打印或监控"""
        return {
            "pages": len(self.pages),
            "edges": len(self.edges),
            "domains": len({urlparse(u).netloc for u in self.pages.keys()}),
        }

    def clear_memory(self) -> None:
        """仅清理内存中的图（不删除已落盘文件）"""
        self.pages.clear()
        self.edges.clear()
        self._edge_keys.clear()
