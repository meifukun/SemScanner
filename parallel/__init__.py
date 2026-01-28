# -*- coding: utf-8 -*-
"""
Parallel execution components for Web-Agent

This package contains tools for parallel task execution using independent driver instances.
"""

from .parallel_driver_manager import ParallelDriverManager
from .driver_pool import DriverPool
from .task_executor import IndependentTaskExecutor
from .parallel_task_scheduler import ParallelTaskScheduler

__all__ = [
    'ParallelDriverManager',
    'DriverPool',
    'IndependentTaskExecutor',
    'ParallelTaskScheduler'
]
