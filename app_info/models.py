# -*- coding: utf-8 -*-
# app_info/models_extended.py
from __future__ import annotations
from dataclasses import dataclass, asdict, field
from typing import List, Optional, Dict, Any
from datetime import datetime

# ========== 新增：网络请求记录 ==========

@dataclass
class NetworkRequest:
    """单个网络请求的记录"""
    method: str
    url: str
    headers: Dict[str, str]
    query_params: Dict[str, Any] = field(default_factory=dict)
    body: Optional[str] = None
    response_status: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: Optional[str] = None

    def is_api_request(self) -> bool:
        """判断是否为API请求（非静态资源）"""
        static_extensions = {'.js', '.css', '.png', '.jpg', '.jpeg', '.gif', 
                           '.ico', '.woff', '.woff2', '.ttf', '.svg', '.webp'}
        url_lower = self.url.lower()
        return not any(url_lower.endswith(ext) for ext in static_extensions)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

# ========== 扩展的模型 ==========
@dataclass
class PageInfo:
    """增强的网页信息节点"""
    url: str
    title: str
    abstract_page: str
    outgoing_links: List[str] = field(default_factory=list)  # 新增：页面上的所有链接
    network_requests: List[NetworkRequest] = field(default_factory=list)  # 新增：访问时的网络请求
    description: str = ""  # 新增：页面的一句话功能描述
    logic_tasks: List[str] = field(default_factory=list)  # 👈 新增：存储逻辑任务
    actions_mapping: Dict[int, Dict[str, Any]] = field(default_factory=dict)  # ✅ 元素定位映射
    event_mapping: Dict[int, Dict[str, Any]] = field(default_factory=dict)  # 🆕 事件定位映射

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
            "event_mapping": self.event_mapping  # 🆕 序列化事件映射
        }

@dataclass
class Edge:
    """页面跳转边：从 from_url 到 to_url"""
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
    """增强的单步执行轨迹"""
    from_url: str
    to_url: str
    action_id: int
    action_repr: str
    command_kind: str
    jump_kind: str
    raw_cmd: str
    network_requests: List[NetworkRequest] = field(default_factory=list)  # 新增

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
    task_id: str  # 改为str以支持层级ID
    description: str
    steps: List[TraceStep] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "description": self.description,
            "steps": [s.to_dict() for s in self.steps],
        }

