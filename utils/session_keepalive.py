# -*- coding: utf-8 -*-
"""
Session Keep-Alive Thread - 保持主driver的session活跃
"""

import time
import threading
import random
from pathlib import Path
from typing import Optional
from datetime import datetime
from seleniumwire import webdriver


class SessionKeepAliveThread:
    """
    Session 保活线程

    功能：
    1. 在后台线程中每隔N秒访问一个随机页面
    2. 保持主driver的登录session活跃
    3. 截图保存，方便监控状态

    使用场景：
    - Phase 4+5 攻击阶段，主driver可能长时间不活动
    - 避免session超时导致后续操作失败
    """

    def __init__(self,
                 driver: webdriver.Chrome,
                 initial_url: str,  # 🆕 固定访问的页面URL（登录后的初始页面）
                 screenshot_dir: str,
                 interval: int = 60):
        """
        初始化保活线程

        Args:
            driver: 主driver实例（共享资源）
            initial_url: 固定访问的页面URL（通常是登录后跳转的初始页面）
            screenshot_dir: 截图保存目录
            interval: 访问间隔（秒），默认60秒
        """
        self.driver = driver
        self.initial_url = initial_url  # 🆕 固定的URL
        self.screenshot_dir = Path(screenshot_dir)
        self.interval = interval

        # 确保截图目录存在
        self.screenshot_dir.mkdir(parents=True, exist_ok=True)

        # 线程控制
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.driver_lock = threading.Lock()  # 默认使用独立锁

        # 统计信息
        self.visit_count = 0
        self.last_visit_time = None

        print(f"[KeepAlive] 初始化完成")
        print(f"[KeepAlive] - 访问间隔: {interval}秒")
        print(f"[KeepAlive] - 截图目录: {screenshot_dir}")
        print(f"[KeepAlive] - 保活页面: {initial_url}")  # 🆕 打印固定页面

    def start(self):
        """启动保活线程"""
        if self.running:
            print(f"[KeepAlive] 警告：线程已在运行")
            return

        self.running = True
        self.thread = threading.Thread(
            target=self._keep_alive_loop,
            name="SessionKeepAliveThread",
            daemon=True  # 守护线程，主程序退出时自动结束
        )
        self.thread.start()
        print(f"[KeepAlive] ✅ 保活线程已启动")

    def stop(self):
        """停止保活线程"""
        if not self.running:
            print(f"[KeepAlive] 警告：线程未在运行")
            return

        self.running = False
        if self.thread:
            self.thread.join(timeout=10)  # 等待最多10秒
            if self.thread.is_alive():
                print(f"[KeepAlive] ⚠️ 线程未在10秒内结束")
            else:
                print(f"[KeepAlive] ✅ 保活线程已停止")

        # 输出统计
        print(f"[KeepAlive] 统计：总共访问了 {self.visit_count} 次页面")

    def set_driver_lock(self, lock: threading.Lock):
        """
        设置外部提供的driver锁（如果主程序已有锁）

        Args:
            lock: 外部的driver锁
        """
        self.driver_lock = lock
        print(f"[KeepAlive] 使用外部提供的driver锁")

    def _keep_alive_loop(self):
        """保活循环（在独立线程中运行）"""
        print(f"[KeepAlive] 保活循环开始运行\n")

        while self.running:
            try:
                # 等待指定间隔（可中断）
                for _ in range(self.interval):
                    if not self.running:
                        break
                    time.sleep(1)

                if not self.running:
                    break

                # 执行保活访问（固定访问初始页面）
                self._visit_page()

            except Exception as e:
                print(f"[KeepAlive] ✗ 保活循环出错: {e}")
                import traceback
                traceback.print_exc()
                # 出错后继续运行，不中断保活

        print(f"[KeepAlive] 保活循环结束")

    def _visit_page(self):
        """访问固定的初始页面并截图"""
        try:
            # 加锁访问页面（线程安全）
            with self.driver_lock:
                print(f"\n[KeepAlive] 访问保活页面: {self.initial_url}")

                try:
                    # 访问页面
                    self.driver.get(self.initial_url)
                    time.sleep(1.5)  # 等待页面加载

                    # 截图
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    screenshot_path = self.screenshot_dir / f"keepalive_{timestamp}.png"
                    self.driver.save_screenshot(str(screenshot_path))

                    # 更新统计
                    self.visit_count += 1
                    self.last_visit_time = datetime.now()

                    # 获取页面标题（验证session是否有效）
                    page_title = self.driver.title if self.driver.title else "(无标题)"

                    print(f"[KeepAlive] ✅ 截图已保存: {screenshot_path.name}")
                    print(f"[KeepAlive] 页面标题: {page_title}")
                    print(f"[KeepAlive] 统计：第 {self.visit_count} 次访问，下次访问将在 {self.interval} 秒后\n")

                except Exception as e:
                    print(f"[KeepAlive] ✗ 访问/截图失败: {e}")
                    # 失败不中断，继续下一次保活

        except Exception as e:
            print(f"[KeepAlive] ✗ 保活失败: {e}")

    def get_status(self):
        """
        获取保活线程的状态信息

        Returns:
            dict: 状态信息
        """
        return {
            "running": self.running,
            "visit_count": self.visit_count,
            "last_visit_time": self.last_visit_time.isoformat() if self.last_visit_time else None,
            "initial_url": self.initial_url,  # 🆕 固定访问的URL
            "interval": self.interval
        }
