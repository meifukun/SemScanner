"""
Token Usage Tracker - Unified tracker for all LLM call token consumption and cost.

Usage:
  1. Wrap the OpenAI client with make_tracked_client(client) in autonomous_test.py
  2. Set the category at each phase entry via tracker.set_category("xxx") or tracker.phase("xxx")
  3. The final report automatically includes a token_usage field; also see token_usage.json

Category reference:
  login_bridge         : Phase 1  Login Bridge decisions
  crawl_bridge         : Phase 2  Crawl Bridge decisions (most frequent)
  crawl_taskgen_nav    : Phase 2  Navigation task generation
  crawl_taskgen_logic  : Phase 2  Business-logic task generation
  task_planning        : Phase 3  Task planning agent decisions
  task_exec_bridge     : Phase 3  Task execution Bridge decisions
  attack_planning      : Phase 4  Attack planning agent decisions
  attack_sqli          : Phase 5  SQL injection attacks
  attack_xss           : Phase 5  XSS attacks
  attack_ssti          : Phase 5  SSTI attacks
  attack_ssrf          : Phase 5  SSRF attacks
  attack_cmdi          : Phase 5  Command injection attacks
  attack_path_traversal: Phase 5  Path traversal attacks
  attack_xxe           : Phase 5  XXE attacks
  attack_business      : Phase 5  Business logic / IDOR / privilege escalation attacks
  attack_executor      : Phase 5  AttackExecutor internal calls

Pricing note:
  Update MODEL_PRICING below to match your API provider's pricing.
  Default values are placeholders (USD per token).
"""

import threading
from contextvars import ContextVar
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Dict, Optional
import json

# ========== Global context variable (thread-isolated, inherits parent context) ==========
_current_category: ContextVar[str] = ContextVar("token_tracker_category", default="unknown")

# ========== Model pricing configuration (USD per token) ==========
# Update these values to match your API provider's pricing.
MODEL_PRICING: Dict[str, Dict[str, float]] = {
    "default": {
        "input":        2.0 / 1_000_000,
        "input_cached": 0.2 / 1_000_000,
        "output":       3.0 / 1_000_000,
    },
}


@dataclass
class CategoryStats:
    """Token statistics for a single category"""
    call_count: int = 0
    prompt_tokens: int = 0
    cached_tokens: int = 0      # Cached input tokens (billed at discounted rate)
    completion_tokens: int = 0
    reasoning_tokens: int = 0   # Reasoning tokens from CoT models (included in completion_tokens)
    total_tokens: int = 0
    cost_usd: float = 0.0


class TokenTracker:
    """
    Thread-safe token usage tracker (global singleton).

    Core design:
    - ContextVar handles thread-isolated category labels (child threads inherit from parent, then operate independently)
    - threading.Lock protects concurrent writes to statistics data
    - TrackedClient wrapper automatically calls record_usage() after each create()
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._stats: Dict[str, CategoryStats] = {}
        self._default_model: str = "default"

    # ------------------------------------------------------------------ #
    #  Category Management                                                 #
    # ------------------------------------------------------------------ #

    def set_category(self, category: str):
        """
        Set the tracking category for the current thread (non-restoring).

        Suitable for calling at the entry point of a phase; all subsequent LLM calls
        in this thread will be attributed to this category until the next call to
        set_category() or until a phase() context exits.
        """
        _current_category.set(category)

    @contextmanager
    def phase(self, category: str):
        """
        Context manager: temporarily switch category, automatically restore on exit.

        Used to temporarily switch to a sub-category (e.g., task_planning) within a
        larger context (e.g., task_exec_bridge), and automatically restore on exit.

        Usage:
            with tracker.phase("task_planning"):
                response = client.chat.completions.create(...)
        """
        token = _current_category.set(category)
        try:
            yield
        finally:
            _current_category.reset(token)

    def get_current_category(self) -> str:
        """Get the tracking category for the current thread"""
        return _current_category.get()

    def set_default_model(self, model: str):
        """Set the default model name (used for billing when model cannot be inferred from response)"""
        self._default_model = model

    # ------------------------------------------------------------------ #
    #  Recording and Statistics                                            #
    # ------------------------------------------------------------------ #

    def record_usage(self, usage, model: str = None, category: str = None):
        """
        Record token usage for a single LLM call (automatically called by TrackedClient).

        Args:
            usage:    OpenAI response.usage object
            model:    Model name (used for pricing lookup)
            category: Override current category (None uses the current ContextVar value)
        """
        if usage is None:
            return

        cat = category or _current_category.get()
        model_name = model or self._default_model

        # Extract token counts
        prompt_tokens     = int(getattr(usage, "prompt_tokens", 0) or 0)
        completion_tokens = int(getattr(usage, "completion_tokens", 0) or 0)
        total_tokens      = int(getattr(usage, "total_tokens", 0) or 0)

        # Reasoning tokens from CoT models (already included in completion_tokens)
        reasoning_tokens = 0
        details = getattr(usage, "completion_tokens_details", None)
        if details:
            reasoning_tokens = int(getattr(details, "reasoning_tokens", 0) or 0)

        # Cached input tokens (for accurate billing)
        cached_tokens = 0
        prompt_details = getattr(usage, "prompt_tokens_details", None)
        if prompt_details:
            cached_tokens = int(getattr(prompt_details, "cached_tokens", 0) or 0)

        cost_usd = self._calculate_cost(model_name, prompt_tokens, completion_tokens, cached_tokens)

        with self._lock:
            if cat not in self._stats:
                self._stats[cat] = CategoryStats()
            s = self._stats[cat]
            s.call_count        += 1
            s.prompt_tokens     += prompt_tokens
            s.cached_tokens     += cached_tokens
            s.completion_tokens += completion_tokens
            s.reasoning_tokens  += reasoning_tokens
            s.total_tokens      += total_tokens
            s.cost_usd          += cost_usd

    def _calculate_cost(self, model: str, prompt_tokens: int,
                        completion_tokens: int, cached_tokens: int = 0) -> float:
        """Calculate cost for this call based on model pricing (USD)"""
        pricing = MODEL_PRICING.get(model, MODEL_PRICING["default"])
        non_cached = max(0, prompt_tokens - cached_tokens)
        input_cost  = (non_cached * pricing["input"]
                       + cached_tokens * pricing.get("input_cached", pricing["input"]))
        output_cost = completion_tokens * pricing["output"]
        return input_cost + output_cost

    def get_summary(self) -> Dict:
        """
        Get a statistics summary for all categories.

        Returns:
            dict, keys are category names, values are statistics dicts; the last item '__total__' is the grand total
        """
        # Predefined display order by phase
        _ORDER = [
            "login_bridge",
            "crawl_bridge",
            "crawl_taskgen_nav",
            "crawl_taskgen_logic",
            "task_planning",
            "task_exec_bridge",
            "attack_planning",
            "attack_sqli",
            "attack_xss",
            "attack_ssti",
            "attack_ssrf",
            "attack_cmdi",
            "attack_path_traversal",
            "attack_xxe",
            "attack_business",
            "attack_executor",
        ]

        with self._lock:
            result = {}
            grand = CategoryStats()

            # First output existing entries in predefined order
            for cat in _ORDER:
                if cat in self._stats:
                    s = self._stats[cat]
                    result[cat] = self._stats_to_dict(s)
                    self._accumulate(grand, s)

            # Then output unknown categories not in predefined order
            for cat, s in sorted(self._stats.items()):
                if cat not in result:
                    result[cat] = self._stats_to_dict(s)
                    self._accumulate(grand, s)

            result["__total__"] = self._stats_to_dict(grand)
            return result

    @staticmethod
    def _stats_to_dict(s: CategoryStats) -> Dict:
        cache_rate = (s.cached_tokens / s.prompt_tokens * 100) if s.prompt_tokens > 0 else 0.0
        return {
            "call_count":         s.call_count,
            "prompt_tokens":      s.prompt_tokens,
            "cached_tokens":      s.cached_tokens,
            "cache_hit_rate":     round(cache_rate, 1),
            "completion_tokens":  s.completion_tokens,
            "reasoning_tokens":   s.reasoning_tokens,
            "total_tokens":       s.total_tokens,
            "cost_usd":           round(s.cost_usd, 6),
        }

    @staticmethod
    def _accumulate(total: CategoryStats, s: CategoryStats):
        total.call_count        += s.call_count
        total.prompt_tokens     += s.prompt_tokens
        total.cached_tokens     += s.cached_tokens
        total.completion_tokens += s.completion_tokens
        total.reasoning_tokens  += s.reasoning_tokens
        total.total_tokens      += s.total_tokens
        total.cost_usd          += s.cost_usd

    def print_summary(self):
        """Print statistics summary to console"""
        summary = self.get_summary()
        total = summary.pop("__total__", None)

        print("\n" + "=" * 95)
        print("📊  Token Usage & Cost Summary")
        print("=" * 95)
        print(f"{'Category':<28} {'Calls':>5} {'Input':>10} {'Cached':>10} "
              f"{'Cache%':>7} {'Output':>10} {'Reason':>10} {'Cost(USD)':>11}")
        print("-" * 95)

        for cat, s in summary.items():
            print(f"{cat:<28} {s['call_count']:>5} {s['prompt_tokens']:>10,} "
                  f"{s['cached_tokens']:>10,} {s['cache_hit_rate']:>6.1f}% "
                  f"{s['completion_tokens']:>10,} {s['reasoning_tokens']:>10,} "
                  f"${s['cost_usd']:>10.4f}")

        if total:
            print("=" * 95)
            print(f"{'TOTAL':<28} {total['call_count']:>5} {total['prompt_tokens']:>10,} "
                  f"{total['cached_tokens']:>10,} {total['cache_hit_rate']:>6.1f}% "
                  f"{total['completion_tokens']:>10,} {total['reasoning_tokens']:>10,} "
                  f"${total['cost_usd']:>10.4f}")
        print("=" * 95 + "\n")

        # Restore __total__
        if total:
            summary["__total__"] = total

    def reset(self):
        """Reset all statistics data (for testing)"""
        with self._lock:
            self._stats.clear()


# ========== Global Singleton ==========
tracker = TokenTracker()


# ========== TrackedClient Wrapper ==========

class _TrackedCompletions:
    """Wraps chat.completions, intercepts create() calls, and automatically records token usage"""

    def __init__(self, completions, tracker_instance: TokenTracker):
        self._completions = completions
        self._tracker = tracker_instance

    def create(self, *args, **kwargs):
        response = self._completions.create(*args, **kwargs)
        usage = getattr(response, "usage", None)
        if usage:
            model = kwargs.get("model") or (args[0] if args else None)
            self._tracker.record_usage(usage, model=model)
        return response

    def __getattr__(self, name):
        return getattr(self._completions, name)


class _TrackedChat:
    """Wraps chat, replacing completions with the tracked version"""

    def __init__(self, chat, tracker_instance: TokenTracker):
        self._chat = chat
        self.completions = _TrackedCompletions(chat.completions, tracker_instance)

    def __getattr__(self, name):
        return getattr(self._chat, name)


class TrackedClient:
    """
    Tracking wrapper for OpenAI client (fully compatible interface).

    Created via make_tracked_client(client). All subsequent
    chat.completions.create() calls through this client will be
    automatically recorded in the global tracker.
    """

    def __init__(self, client, tracker_instance: TokenTracker):
        self._client = client
        self.chat = _TrackedChat(client.chat, tracker_instance)

    def __getattr__(self, name):
        return getattr(self._client, name)


def make_tracked_client(client) -> TrackedClient:
    """
    Wrap an OpenAI client with token tracking.

    Args:
        client: Original OpenAI client instance

    Returns:
        TrackedClient instance (fully compatible interface, can directly replace the original client)
    """
    return TrackedClient(client, tracker)
