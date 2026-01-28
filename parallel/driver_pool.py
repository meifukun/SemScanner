# -*- coding: utf-8 -*-
"""
Driver Pool - 管理独立driver实例的对象池
"""

import time
from queue import Queue, Empty
from typing import Dict, List, Optional
from seleniumwire import webdriver  # ✅ 使用selenium-wire以支持网络请求捕获

from parallel.parallel_driver_manager import ParallelDriverManager


class DriverPool:
    """
    Driver池管理器

    功能：
    1. 预创建指定数量的独立driver
    2. 线程安全的driver借用/归还
    3. 统一清理所有driver

    使用场景：
    - 并行任务执行时，避免频繁创建/销毁driver
    - 复用driver减少启动开销（每个driver启动约2-3秒）
    """

    def __init__(self, size: int = 10):
        """
        初始化Driver池

        Args:
            size: Driver池大小（默认10个）
        """
        self.size = size
        self.drivers: List[webdriver.Chrome] = []  # 所有driver的引用
        self.available: Queue = Queue()  # 可用driver队列（线程安全）
        self.in_use: Dict[str, webdriver.Chrome] = {}  # 正在使用的driver映射
        self.created = False

        print(f"[DriverPool] 初始化完成，池大小: {size}")

    def create(self, account_manager, base_url: str, chrome_options=None, main_driver=None, target_domain: str = None):
        """
        预创建driver池

        注意：这是一个耗时操作（约3秒/driver）

        Args:
            account_manager: AccountManager实例
            base_url: 基础URL
            chrome_options: Chrome选项
            main_driver: 可选的主driver，如果提供则加入池中作为普通worker
        """
        if self.created:
            print(f"[DriverPool] 警告：Driver池已创建，跳过")
            return

        # ✅ 增加文件描述符限制（避免selenium-wire的select()错误）
        try:
            import resource
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            print(f"[DriverPool] 当前文件描述符限制: soft={soft}, hard={hard}")

            if soft < 4096:
                resource.setrlimit(resource.RLIMIT_NOFILE, (4096, hard))
                print(f"[DriverPool] ✅ 已提高文件描述符限制至 4096")
            else:
                print(f"[DriverPool] ✓ 文件描述符限制已足够")
        except Exception as e:
            print(f"[DriverPool] ⚠️ 设置文件描述符限制失败: {e}")
            print(f"[DriverPool] 提示：可手动执行 'ulimit -n 4096'")

        print(f"\n{'='*70}")
        if main_driver:
            print(f"[DriverPool] 开始创建driver池: 1个主driver + {self.size - 1} 个子driver = {self.size} 个")
        else:
            print(f"[DriverPool] 开始创建 {self.size} 个独立driver")
        print(f"[DriverPool] 预计耗时: {self.size * 3}秒")
        print(f"{'='*70}\n")

        start_time = time.time()

        # 🆕 如果提供了主driver，先将其加入池中
        if main_driver:
            main_driver._pool_index = "main"  # 标记为主driver
            self.drivers.append(main_driver)
            self.available.put(main_driver)
            print(f"[DriverPool] ✅ 主driver已加入池 (标识: main)\n")

        # 创建ParallelDriverManager
        manager = ParallelDriverManager(
            account_manager=account_manager,
            base_url=base_url,
            chrome_options=chrome_options,
            target_domain=target_domain
        )

        # 🆕 计算需要创建的子driver数量
        sub_driver_count = self.size - 1 if main_driver else self.size
        start_index = 1

        # 批量创建子driver
        for i in range(start_index, sub_driver_count + start_index):
            try:
                current_num = i + 1 if main_driver else i
                print(f"[DriverPool] 创建第 {current_num}/{self.size} 个driver...")
                driver = manager.create_cloned_driver("default_account")

                # 🆕 给每个driver添加池索引标识（方便追踪）
                driver._pool_index = i

                self.drivers.append(driver)
                self.available.put(driver)  # 放入可用队列

                print(f"[DriverPool] ✅ 第 {current_num}/{self.size} 个driver创建完成 (索引: {i})\n")

            except Exception as e:
                print(f"[DriverPool] ✗ 第 {i}/{self.size} 个driver创建失败: {e}")
                import traceback
                traceback.print_exc()

        elapsed = time.time() - start_time

        print(f"\n{'='*70}")
        print(f"[DriverPool] Driver池创建完成")
        print(f"[DriverPool] 成功创建: {len(self.drivers)}/{self.size}")
        print(f"[DriverPool] 总耗时: {elapsed:.1f}秒")
        print(f"{'='*70}\n")

        self.created = True

    def acquire(self, task_id: str, timeout: int = 300) -> Optional[webdriver.Chrome]:
        """
        获取一个可用的driver

        线程安全：使用Queue.get()自动阻塞直到有可用driver

        Args:
            task_id: 任务ID（用于跟踪）
            timeout: 超时时间（秒），默认300秒

        Returns:
            webdriver.Chrome实例，如果超时返回None
        """
        try:
            driver = self.available.get(timeout=timeout)
            self.in_use[task_id] = driver

            print(f"[DriverPool] Driver已分配给任务 {task_id} (池中剩余: {self.available.qsize()})")

            return driver

        except Empty:
            print(f"[DriverPool] ✗ 获取driver超时（{timeout}秒），任务: {task_id}")
            return None

    def release(self, task_id: str, cleanup: bool = False):
        """
        归还driver到池中

        Args:
            task_id: 任务ID
            cleanup: 是否清理driver状态（cookies, storage等）
        """
        if task_id not in self.in_use:
            print(f"[DriverPool] 警告：任务 {task_id} 没有分配的driver")
            return

        driver = self.in_use.pop(task_id)

        # 可选：清理driver状态
        if cleanup:
            try:
                self._cleanup_driver_state(driver)
            except Exception as e:
                print(f"[DriverPool] 警告：清理driver状态失败: {e}")

        # 归还到可用队列
        self.available.put(driver)

        print(f"[DriverPool] Driver已归还（任务 {task_id}），池中可用: {self.available.qsize()}")

    def _cleanup_driver_state(self, driver: webdriver.Chrome):
        """
        清理driver状态（可选）

        清理内容：
        - Cookies
        - LocalStorage
        - SessionStorage

        注意：这会增加一定开销（约0.5秒）
        """
        try:
            # 清理cookies
            driver.delete_all_cookies()

            # 清理localStorage
            driver.execute_script("localStorage.clear();")

            # 清理sessionStorage
            driver.execute_script("sessionStorage.clear();")

        except Exception as e:
            print(f"[DriverPool] 清理状态出错: {e}")

    def get_stats(self) -> Dict[str, int]:
        """
        获取池状态统计

        Returns:
            {
                "total": 总数,
                "available": 可用数,
                "in_use": 使用中数量
            }
        """
        return {
            "total": len(self.drivers),
            "available": self.available.qsize(),
            "in_use": len(self.in_use)
        }

    def cleanup_all(self, keep_main_driver: bool = False):
        """
        清理所有driver

        Args:
            keep_main_driver: 是否保留主driver不关闭（默认False）
                             如果为True，主driver会被移除出池但不会quit()

        注意：应该在所有任务完成后调用
        """
        print(f"\n[DriverPool] 开始清理 {len(self.drivers)} 个driver...")

        if keep_main_driver:
            print(f"[DriverPool] 保留主driver模式：主driver将被移除但不关闭")

        cleaned_count = 0
        skipped_count = 0

        for i, driver in enumerate(self.drivers, 1):
            try:
                # 检查是否是主driver
                pool_index = getattr(driver, '_pool_index', None)
                is_main = (pool_index == "main")

                if is_main and keep_main_driver:
                    # 跳过主driver，不关闭
                    print(f"  [{i}/{len(self.drivers)}] 主driver已移除（保持运行）")
                    skipped_count += 1
                else:
                    # 关闭driver
                    driver.quit()
                    print(f"  [{i}/{len(self.drivers)}] Driver已关闭")
                    cleaned_count += 1
            except Exception as e:
                print(f"  [{i}/{len(self.drivers)}] 关闭失败: {e}")
                cleaned_count += 1  # 即使失败也算已处理

        self.drivers.clear()
        self.in_use.clear()

        # 清空队列
        while not self.available.empty():
            try:
                self.available.get_nowait()
            except Empty:
                break

        print(f"[DriverPool] ✅ 清理完成 (关闭: {cleaned_count}, 保留: {skipped_count})\n")

        self.created = False
