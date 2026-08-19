import tempfile
import unittest
import subprocess
from unittest.mock import Mock, patch

from attack_agent.attack_executor import AttackExecutor, _TASK_TIMEOUT_DEFAULTS


class _Driver:
    def __init__(self, cookies):
        self.cookies = cookies
        self.quit_called = False

    def get_cookies(self):
        return self.cookies

    def quit(self):
        self.quit_called = True


class _AccountManager:
    @staticmethod
    def _extract_credentials(driver):
        return {
            "cookies": driver.get_cookies(),
            "localStorage": {},
            "sessionStorage": {},
            "headers": {},
        }


class AttackExecutorDriverRegistryTests(unittest.TestCase):
    def test_xss_default_task_timeout_is_300_seconds(self):
        self.assertEqual(_TASK_TIMEOUT_DEFAULTS["XSS"], 300)

    def test_register_replacement_updates_worker_and_main_driver(self):
        old_driver = object()
        new_driver = object()

        with tempfile.TemporaryDirectory() as temp_dir:
            executor = AttackExecutor(
                account_manager=None,
                crawler=None,
                client=None,
                log_dir=temp_dir,
                driver=old_driver,
                worker_drivers=[old_driver],
            )

            executor._register_replacement_driver(
                0,
                object(),
                new_driver,
                was_main_driver=True,
            )

            self.assertIs(executor.worker_drivers[0], new_driver)
            self.assertIs(executor.driver, new_driver)

    @patch("attack_agent.attack_executor.kill_process_group_and_collect")
    @patch("attack_agent.attack_executor.subprocess.Popen")
    def test_replay_timeout_is_explicit_and_cleanup_is_bounded(self, popen, cleanup):
        process = Mock()
        process.communicate.side_effect = subprocess.TimeoutExpired("curl", 1)
        popen.return_value = process
        cleanup.return_value = ("partial", "", True)

        with tempfile.TemporaryDirectory() as temp_dir:
            executor = AttackExecutor(
                account_manager=None,
                crawler=None,
                client=None,
                log_dir=temp_dir,
            )
            with patch.dict("os.environ", {"SEMSCANNER_REPLAY_TIMEOUT": "1"}):
                result = executor._execute_replay_curl("curl http://example.invalid")

        self.assertTrue(result["timeout"])
        self.assertFalse(result["success"])
        cleanup.assert_called_once_with(process)

    def test_replay_timeout_rotates_current_and_shared_idle_sessions(self):
        stale_cookie = [{"name": "app_session", "value": "same-session"}]
        other_cookie = [{"name": "app_session", "value": "different-session"}]
        fresh_cookie = [{"name": "app_session", "value": "fresh-session"}]
        current = _Driver(stale_cookie)
        shared_idle = _Driver(stale_cookie)
        distinct_idle = _Driver(other_cookie)
        fresh = _Driver(fresh_cookie)

        with tempfile.TemporaryDirectory() as temp_dir:
            executor = AttackExecutor(
                account_manager=_AccountManager(),
                crawler=None,
                client=None,
                log_dir=temp_dir,
                driver=current,
                worker_drivers=[current, shared_idle, distinct_idle],
                initial_url="http://example.invalid/",
                login_task=object(),
            )
            for worker_id, cookies in enumerate((stale_cookie, stale_cookie, other_cookie)):
                executor.worker_stores[worker_id].credentials = {"cookies": cookies}

            acquired_worker_id, acquired_driver = executor.driver_queue.get_nowait()
            self.assertEqual(acquired_worker_id, 0)
            self.assertIs(acquired_driver, current)

            with patch.object(executor, "_create_new_driver", return_value=fresh), patch.object(
                executor,
                "_restore_login_status",
                return_value=True,
            ):
                restored, replacement = executor._recover_session_after_replay_timeout(
                    0,
                    current,
                    lambda *args: None,
                    executor.log_dir,
                )

            queued = []
            while not executor.driver_queue.empty():
                queued.append(executor.driver_queue.get_nowait())

        self.assertTrue(restored)
        self.assertIs(replacement, fresh)
        self.assertTrue(current.quit_called)
        self.assertTrue(shared_idle.quit_called)
        self.assertFalse(distinct_idle.quit_called)
        self.assertIs(executor.worker_drivers[0], fresh)
        self.assertIsNone(executor.worker_drivers[1])
        self.assertIs(executor.worker_drivers[2], distinct_idle)
        self.assertEqual(queued, [(2, distinct_idle)])


if __name__ == "__main__":
    unittest.main()
