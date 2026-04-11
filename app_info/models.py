# -*- coding: utf-8 -*-
# app_info/models_extended.py
from __future__ import annotations
from dataclasses import dataclass, asdict, field
from typing import List, Optional, Dict, Any
from datetime import datetime

# ========== New: Network request record ==========

@dataclass
class NetworkRequest:
    """Record of a single network request"""
    method: str
    url: str
    headers: Dict[str, str]
    query_params: Dict[str, Any] = field(default_factory=dict)
    body: Optional[str] = None
    response_status: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: Optional[str] = None

    def is_api_request(self) -> bool:
        """Determine if this is an API request (not a static resource)"""
        static_extensions = {'.js', '.css', '.png', '.jpg', '.jpeg', '.gif',
                           '.ico', '.woff', '.woff2', '.ttf', '.svg', '.webp'}
        url_lower = self.url.lower()
        return not any(url_lower.endswith(ext) for ext in static_extensions)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

# ========== Extended models ==========
@dataclass
class PageInfo:
    """Enhanced web page info node"""
    url: str
    title: str
    abstract_page: str
    outgoing_links: List[str] = field(default_factory=list)  # New: all links on the page
    network_requests: List[NetworkRequest] = field(default_factory=list)  # New: network requests during visit
    description: str = ""  # New: one-sentence functional description of the page
    logic_tasks: List[str] = field(default_factory=list)  # New: store logic tasks
    actions_mapping: Dict[int, Dict[str, Any]] = field(default_factory=dict)  # Element locator mapping
    event_mapping: Dict[int, Dict[str, Any]] = field(default_factory=dict)  # Event locator mapping

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "title": self.title,
            "abstract_page": self.abstract_page,
            "description": self.description,
            "outgoing_links": self.outgoing_links,
            "network_requests": [r.to_dict() for r in self.network_requests],
            "logic_tasks": self.logic_tasks,
            "actions_mapping": self.actions_mapping,
            "event_mapping": self.event_mapping  # Serialize event mapping
        }

@dataclass
class Edge:
    """Page transition edge: from from_url to to_url"""
    from_url: str
    to_url: str
    via_action_id: int
    via_repr: str
    jump_kind: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_url": self.from_url,
            "to_url": self.to_url,
            "via_action_id": self.via_action_id,
            "via_repr": self.via_repr,
            "jump_kind": self.jump_kind,
            # "network_requests": [r.to_dict() for r in self.network_requests],
        }

@dataclass
class TraceStep:
    """Enhanced single execution trace step"""
    from_url: str
    to_url: str
    action_id: int
    action_repr: str
    command_kind: str
    jump_kind: str
    raw_cmd: str
    network_requests: List[NetworkRequest] = field(default_factory=list)  # New

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_url": self.from_url,
            "to_url": self.to_url,
            "action_id": self.action_id,
            "action_repr": self.action_repr,
            "command_kind": self.command_kind,
            "jump_kind": self.jump_kind,
            "raw_cmd": self.raw_cmd,
            "network_requests": [r.to_dict() for r in self.network_requests],
        }

@dataclass
class TaskRunTrace:
    task_id: str  # Changed to str to support hierarchical IDs
    description: str
    steps: List[TraceStep] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "description": self.description,
            "steps": [s.to_dict() for s in self.steps],
        }
