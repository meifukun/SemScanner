# -*- coding: utf-8 -*-
"""
Driver Pool - Object pool for managing independent driver instances
"""

import time
from queue import Queue, Empty
from typing import Dict, List, Optional
from seleniumwire import webdriver  # Use selenium-wire to support network request capture

from parallel.parallel_driver_manager import ParallelDriverManager


class DriverPool:
    """
    Driver pool manager

    Features:
    1. Pre-create a specified number of independent drivers
    2. Thread-safe driver borrowing/returning
    3. Unified cleanup of all drivers

    Use cases:
    - Avoid frequent creation/destruction of drivers during parallel task execution
    - Reuse drivers to reduce startup overhead (each driver takes ~2-3 seconds to start)
    """

    def __init__(self, size: int = 10):
        """
        Initialize the Driver pool

        Args:
            size: Driver pool size (default 10)
        """
        self.size = size
        self.drivers: List[webdriver.Chrome] = []  # References to all drivers
        self.available: Queue = Queue()  # Available driver queue (thread-safe)
        self.in_use: Dict[str, webdriver.Chrome] = {}  # Mapping of drivers in use
        self.created = False

        print(f"[DriverPool] Initialization complete, pool size: {size}")

    def create(self, account_manager, base_url: str, chrome_options=None, main_driver=None, target_domain: str = None):
        """
        Pre-create the driver pool

        Note: This is a time-consuming operation (~3 seconds/driver)

        Args:
            account_manager: AccountManager instance
            base_url: Base URL
            chrome_options: Chrome options
            main_driver: Optional main driver; if provided, it joins the pool as a regular worker
        """
        if self.created:
            print(f"[DriverPool] Warning: Driver pool already created, skipping")
            return

        # Increase file descriptor limit (avoid selenium-wire's select() error)
        try:
            import resource
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            print(f"[DriverPool] Current file descriptor limit: soft={soft}, hard={hard}")

            if soft < 4096:
                resource.setrlimit(resource.RLIMIT_NOFILE, (4096, hard))
                print(f"[DriverPool] File descriptor limit increased to 4096")
            else:
                print(f"[DriverPool] File descriptor limit is already sufficient")
        except Exception as e:
            print(f"[DriverPool] Failed to set file descriptor limit: {e}")
            print(f"[DriverPool] Hint: you can manually run 'ulimit -n 4096'")

        print(f"\n{'='*70}")
        if main_driver:
            print(f"[DriverPool] Starting driver pool creation: 1 main driver + {self.size - 1} sub-drivers = {self.size} total")
        else:
            print(f"[DriverPool] Starting creation of {self.size} independent drivers")
        print(f"[DriverPool] Estimated time: {self.size * 3} seconds")
        print(f"{'='*70}\n")

        start_time = time.time()

        # If main driver is provided, add it to the pool first
        if main_driver:
            main_driver._pool_index = "main"  # Mark as main driver
            self.drivers.append(main_driver)
            self.available.put(main_driver)
            print(f"[DriverPool] Main driver added to pool (identifier: main)\n")

        # Create ParallelDriverManager
        manager = ParallelDriverManager(
            account_manager=account_manager,
            base_url=base_url,
            chrome_options=chrome_options,
            target_domain=target_domain
        )

        # Calculate the number of sub-drivers to create
        sub_driver_count = self.size - 1 if main_driver else self.size
        start_index = 1

        # Batch create sub-drivers
        for i in range(start_index, sub_driver_count + start_index):
            try:
                current_num = i + 1 if main_driver else i
                print(f"[DriverPool] Creating driver {current_num}/{self.size}...")
                driver = manager.create_cloned_driver("default_account")

                # Add pool index identifier to each driver (for tracking)
                driver._pool_index = i

                self.drivers.append(driver)
                self.available.put(driver)  # Put into available queue

                print(f"[DriverPool] Driver {current_num}/{self.size} created successfully (index: {i})\n")

            except Exception as e:
                print(f"[DriverPool] Driver {i}/{self.size} creation failed: {e}")
                import traceback
                traceback.print_exc()

        elapsed = time.time() - start_time

        print(f"\n{'='*70}")
        print(f"[DriverPool] Driver pool creation complete")
        print(f"[DriverPool] Successfully created: {len(self.drivers)}/{self.size}")
        print(f"[DriverPool] Total time: {elapsed:.1f} seconds")
        print(f"{'='*70}\n")

        self.created = True

    def acquire(self, task_id: str, timeout: int = 300) -> Optional[webdriver.Chrome]:
        """
        Get an available driver

        Thread-safe: uses Queue.get() to automatically block until a driver is available

        Args:
            task_id: Task ID (for tracking)
            timeout: Timeout in seconds (default 300 seconds)

        Returns:
            webdriver.Chrome instance, or None if timeout
        """
        try:
            driver = self.available.get(timeout=timeout)
            self.in_use[task_id] = driver

            print(f"[DriverPool] Driver assigned to task {task_id} (remaining in pool: {self.available.qsize()})")

            return driver

        except Empty:
            print(f"[DriverPool] Driver acquisition timed out ({timeout} seconds), task: {task_id}")
            return None

    def release(self, task_id: str, cleanup: bool = False):
        """
        Return driver to the pool

        Args:
            task_id: Task ID
            cleanup: Whether to clean driver state (cookies, storage, etc.)
        """
        if task_id not in self.in_use:
            print(f"[DriverPool] Warning: Task {task_id} has no assigned driver")
            return

        driver = self.in_use.pop(task_id)

        # Optional: clean driver state
        if cleanup:
            try:
                self._cleanup_driver_state(driver)
            except Exception as e:
                print(f"[DriverPool] Warning: Failed to clean driver state: {e}")

        # Return to available queue
        self.available.put(driver)

        print(f"[DriverPool] Driver returned (task {task_id}), available in pool: {self.available.qsize()}")

    def _cleanup_driver_state(self, driver: webdriver.Chrome):
        """
        Clean driver state (optional)

        Cleans:
        - Cookies
        - LocalStorage
        - SessionStorage

        Note: This adds some overhead (~0.5 seconds)
        """
        try:
            # Clean cookies
            driver.delete_all_cookies()

            # Clean localStorage
            driver.execute_script("localStorage.clear();")

            # Clean sessionStorage
            driver.execute_script("sessionStorage.clear();")

        except Exception as e:
            print(f"[DriverPool] Error cleaning state: {e}")

    def get_stats(self) -> Dict[str, int]:
        """
        Get pool status statistics

        Returns:
            {
                "total": total count,
                "available": available count,
                "in_use": in-use count
            }
        """
        return {
            "total": len(self.drivers),
            "available": self.available.qsize(),
            "in_use": len(self.in_use)
        }

    def cleanup_all(self, keep_main_driver: bool = False):
        """
        Clean up all drivers

        Args:
            keep_main_driver: Whether to keep the main driver open (default False)
                             If True, the main driver will be removed from the pool but not quit()

        Note: Should be called after all tasks are complete
        """
        print(f"\n[DriverPool] Starting cleanup of {len(self.drivers)} drivers...")

        if keep_main_driver:
            print(f"[DriverPool] Keep main driver mode: main driver will be removed but not closed")

        cleaned_count = 0
        skipped_count = 0

        for i, driver in enumerate(self.drivers, 1):
            try:
                # Check if this is the main driver
                pool_index = getattr(driver, '_pool_index', None)
                is_main = (pool_index == "main")

                if is_main and keep_main_driver:
                    # Skip main driver, do not close
                    print(f"  [{i}/{len(self.drivers)}] Main driver removed (kept running)")
                    skipped_count += 1
                else:
                    # Close driver
                    driver.quit()
                    print(f"  [{i}/{len(self.drivers)}] Driver closed")
                    cleaned_count += 1
            except Exception as e:
                print(f"  [{i}/{len(self.drivers)}] Close failed: {e}")
                cleaned_count += 1  # Count as processed even if failed

        self.drivers.clear()
        self.in_use.clear()

        # Empty the queue
        while not self.available.empty():
            try:
                self.available.get_nowait()
            except Empty:
                break

        print(f"[DriverPool] Cleanup complete (closed: {cleaned_count}, kept: {skipped_count})\n")

        self.created = False
