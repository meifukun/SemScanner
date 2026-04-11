# -*- coding: utf-8 -*-
# crawl/webapp_store.py
from __future__ import annotations
from typing import Dict, List, Optional, Tuple, Iterable
from pathlib import Path
import json
import threading  # Thread safety
from app_info.models import PageInfo, Edge, TaskRunTrace
from urllib.parse import urlparse


class WebAppStore:
    """
    Web application information store (thread-safe version)
    - Nodes (PageInfo)
    - Edges (Edge)
    - Task run traces (TaskRunTrace)
    - Optional graph snapshot export (graph.json / mermaid)
    Persistence strategy: primarily in-memory, with JSONL append for review/visualization
    """

    def __init__(self, root_dir: str = "output/webapp_store"):
        self.root = Path(root_dir)
        self.root.mkdir(parents=True, exist_ok=True)

        # In-memory state
        self.pages: Dict[str, PageInfo] = {}         # url -> PageInfo
        self.edges: List[Edge] = []                  # Ordered list of edges (for replay)
        self._edge_keys: set[Tuple[str, str, int, str, str]] = set()  # Dedup key (from,to,action_id,via_repr,jump_kind)

        # Thread safety: protect shared data structures
        self._lock = threading.RLock()  # Use reentrant lock, supports same thread acquiring multiple times

        # Persistence paths
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
        """Strictly check by URL (including query) whether the page node exists"""
        return url in self.pages

    def has_main_page(self, url: str) -> bool:
        """
        Ignore query to check if the "main page" already exists (to avoid duplicate pages from query variants)
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
        Write directly (overwrite old value for same URL); generally recommended to use upsert_page() for merging.
        Thread-safe version
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
        Insert or merge page information (thread-safe version)

        Improvements:
        - Supports merging of logic_tasks
        - When persist=True, cleans old records before appending (optional, prevents JSONL bloat)
        """
        with self._lock:
            if info.url not in self.pages:
                self.add_page(info, persist=persist)
                return

            old = self.pages[info.url]

            title = info.title or old.title
            abstract_page = info.abstract_page or old.abstract_page
            description = info.description or old.description

            # New: logic_tasks directly overwritten (managed by planning agent)
            logic_tasks = info.logic_tasks if info.logic_tasks else old.logic_tasks

            # Preserve actions_mapping (fix: mapping not found during task execution)
            actions_mapping = info.actions_mapping if info.actions_mapping else old.actions_mapping

            # Preserve event_mapping
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
                event_mapping=event_mapping  # Add event mapping
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
        """Whether there is any edge pointing to this to_url (the original has_edge semantics)"""
        return any(e.to_url == to_url for e in self.edges)

    def has_edge_pair(self, from_url: str, to_url: str) -> bool:
        """Strictly check if a from->to edge already exists"""
        return any(e.from_url == from_url and e.to_url == to_url for e in self.edges)

    # For backward compatibility: keep has_edge with original "only check to_url" behavior
    def has_edge(self, from_url: str, to_url: str) -> bool:
        """
        Backward compatible: only checks to_url to determine if "the target URL has appeared"
        For strict from->to check, use has_edge_pair()
        """
        return self.has_to_url(to_url)

    def add_edge(self, edge: Edge, persist: bool = True) -> bool:
        """
        Add an edge; if duplicate (by from,to,action_id,via_repr,jump_kind), ignore and return False
        Thread-safe version
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
    # Graph Export (optional)
    # ---------------------------------------------------------------------
    def export_graph(self) -> None:
        """
        Export a snapshot with more node attributes (not required, only for visualization or cold-starting other agents)
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
        Quick export of Mermaid flowchart (structure only, no attributes), for README/issue reproduction
        """
        lines = ["graph LR"]
        # Node limit to avoid rendering lag for very large graphs
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
        """Return a lightweight summary for logging or monitoring"""
        return {
            "pages": len(self.pages),
            "edges": len(self.edges),
            "domains": len({urlparse(u).netloc for u in self.pages.keys()}),
        }

    def clear_memory(self) -> None:
        """Only clear the in-memory graph (does not delete persisted files)"""
        self.pages.clear()
        self.edges.clear()
        self._edge_keys.clear()
