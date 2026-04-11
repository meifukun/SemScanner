# -*- coding: utf-8 -*-
"""
ExecutionTracer (single-file, no inheritance)
- Records task traces (TaskRunTrace / TraceStep)
- Writes navigation edges to WebAppStore (Edge)
- Triggers on_new_page callback when a new page is discovered (Crawler caches page and generates tasks)
- Optionally integrates network_capture to record network requests for each step
- Compatible with both model variants: works whether TraceStep/Edge includes network_requests or not
"""

from __future__ import annotations
from typing import Optional, List, Dict, Any, Callable

from app_info.models import (
    TaskRunTrace, TraceStep, Edge, NetworkRequest  # if NetworkRequest is unavailable, keep import error-free or use fallback below
)
from app_info.webapp_store import WebAppStore


class ExecutionTracer:
    """
    Unified execution tracer (no inheritance).

    Args:
        store: WebAppStore instance
        network_capture: Optional network capturer; must provide capture_current(url, exclude_static, exclude_main_doc) and export_to_har() interfaces
        on_new_page: Optional callback, signature on_new_page(url: str) -> None
        on_new_edge: Optional callback, signature on_new_edge(edge: Edge) -> None
        debug: Print debug information
    """
    def __init__(
        self,
        store: WebAppStore,
        network_capture: Optional[Any] = None,
        on_new_page: Optional[Callable[[str], None]] = None,
        construct_edge: Optional[Callable[[str], None]] = None,
        debug: bool = True,
    ):
        self.store = store
        self.network_capture = network_capture
        self.on_new_page = on_new_page
        self.debug = debug
        self.construct_edge = construct_edge

        self.trace: Optional[TaskRunTrace] = None

        # Dynamically detect whether the model supports the network_requests field (compatible with both dataclass forms)
        self._trace_step_supports_net = hasattr(TraceStep, "__dataclass_fields__") and (
            "network_requests" in getattr(TraceStep, "__dataclass_fields__", {})
        )
        self._edge_supports_net = hasattr(Edge, "__dataclass_fields__") and (
            "network_requests" in getattr(Edge, "__dataclass_fields__", {})
        )

    # ----------------------------
    # Lifecycle
    # ----------------------------
    def start_task(self, task_id: str, description: str):
        """
        Start a new task trace
        """
        if self.debug:
            print(f"[ExecutionTracer] start_task: {task_id} | {description}")

        # Some TaskRunTrace need steps=[], others have default values; handle both
        try:
            self.trace = TaskRunTrace(task_id=str(task_id), description=description, steps=[])
        except TypeError:
            self.trace = TaskRunTrace(task_id=str(task_id), description=description)

    def end_task(self) -> Optional[TaskRunTrace]:
        """
        End the current task trace and return it
        """
        if self.debug:
            print(f"[ExecutionTracer] end_task; has_trace={self.trace is not None}")
        t = self.trace
        self.trace = None
        return t

    # ----------------------------
    # Core: called after each browser action step
    # ----------------------------
    def step(
        self,
        from_url: str,
        to_url: str,
        action_id: int,
        action_repr: str,
        command_kind: str,
        jump_kind: str,
        raw_cmd: str,
        logging_in: bool = False
    ):
        """
        Record a from_url -> to_url navigation and action, and write the edge to the graph.
        If a new page is discovered (to_url not in store), trigger the on_new_page callback.
        """
        if self.trace is None:
            if self.debug:
                print("[ExecutionTracer] step() called but no active trace; did you call start_task()?")
            return

        if self.debug:
            print(f"[ExecutionTracer] step: {from_url} -> {to_url} | action_id={action_id} kind={command_kind}")

        # # 1) Optional: capture current relevant network requests
        # 2) Record a TraceStep (compatible with or without network_requests field)
        step_kwargs = dict(
            from_url=from_url,
            to_url=to_url,
            action_id=action_id,
            action_repr=action_repr,
            command_kind=command_kind,
            jump_kind=jump_kind,
            raw_cmd=raw_cmd,
        )

        # Capture current network requests
        network_requests = []
        if self.network_capture:
            captured = self.network_capture.capture_current(
                to_url,
                exclude_static=True,
                exclude_main_doc=False  # include main document on page load
            )
            network_requests = self._convert_to_model_requests(captured)

        if self._trace_step_supports_net:
            step_kwargs["network_requests"] = network_requests

        try:
            step_obj = TraceStep(**step_kwargs)
        except TypeError as e:
            # Edge case: dataclass field naming mismatch; fallback by removing network_requests
            if "network_requests" in step_kwargs:
                step_kwargs.pop("network_requests", None)
                step_obj = TraceStep(**step_kwargs)
            else:
                raise e

        # Add step to current trace
        if hasattr(self.trace, "steps") and isinstance(self.trace.steps, list):
            self.trace.steps.append(step_obj)

        # 3) Write Edge (compatible with or without network_requests field)
        edge_kwargs = dict(
            from_url=from_url,
            to_url=to_url,
            via_action_id=action_id,
            via_repr=action_repr,
            jump_kind=jump_kind,
        )

        try:
            edge_obj = Edge(**edge_kwargs)
        except TypeError as e:
            if "network_requests" in edge_kwargs:
                edge_kwargs.pop("network_requests", None)
                edge_obj = Edge(**edge_kwargs)
            else:
                raise e

        if not self.store.has_edge(from_url, to_url):
            self.store.add_edge(edge_obj)

        # 4) Notify external handler when a new page is discovered (external code caches page and spawns tasks)
        try:
            if not self.store.has_page(to_url) and self.on_new_page and not from_url==to_url:
                if "login" in from_url or logging_in==True:
                    print(f"[ExecutionTracer] Login successful, no need to generate new tasks")
                else:
                    if self.store.has_main_page(to_url):
                        print(f"[ExecutionTracer] new page discovered -> {to_url}, but no need to generate new tasks")
                    else:
                        print(f"[ExecutionTracer] new page discovered -> {to_url}, spawning new task")
                        self.on_new_page(to_url)
        except Exception as e:
            if self.debug:
                print(f"[ExecutionTracer] on_new_page check/notify error: {e}")

        # Supplement with any new links found
        self.construct_edge(to_url)

        if self.network_capture:
            self.network_capture.clear_requests()

    # ----------------------------
    # Helper: convert captured requests to model objects
    # ----------------------------
    def _convert_to_model_requests(self, captured_requests: List[Dict[str, Any]]) -> List[Any]:
        """
        Convert raw requests returned by network_capture to NetworkRequest objects (or dict if incompatible).
        Each element of captured_requests is expected to contain:
          - method, url, headers, query_params, body
          - response: { status, headers, body }
          - duration_ms
        """
        out: List[Any] = []
        supports_network_request = hasattr(NetworkRequest, "__call__") or hasattr(NetworkRequest, "__dataclass_fields__")
        for req in captured_requests or []:
            # Normalize field names
            method = req.get("method", "")
            url = req.get("url", "")
            headers = req.get("headers", {}) or {}
            query_params = req.get("query_params", {}) or {}
            body = req.get("body", None)

            resp = req.get("response", {}) or {}
            response_status = resp.get("status", None)
            response_headers = resp.get("headers", {}) or {}
            response_body = resp.get("body", None)

            if supports_network_request:
                try:
                    nr = NetworkRequest(
                        method=method,
                        url=url,
                        headers=headers,
                        query_params=query_params,
                        body=body,
                        response_status=response_status,
                        response_headers=response_headers,
                        response_body=response_body
                    )
                    out.append(nr)
                    continue
                except Exception:
                    # Fall back to dict
                    pass

            out.append({
                "method": method,
                "url": url,
                "headers": headers,
                "query_params": query_params,
                "body": body,
                "response_status": response_status,
                "response_headers": response_headers,
                "response_body": response_body,
            })
        return out
