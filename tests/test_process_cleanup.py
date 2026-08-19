import io
import subprocess
import unittest
from unittest.mock import patch

from attack_agent.request_utils import kill_process_group_and_collect


class _NeverClosingProcess:
    pid = 12345

    def __init__(self):
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()
        self.communicate_calls = 0
        self.kill_calls = 0
        self.wait_calls = 0

    def communicate(self, timeout=None):
        self.communicate_calls += 1
        raise subprocess.TimeoutExpired(
            cmd="curl",
            timeout=timeout,
            output="partial stdout",
            stderr="partial stderr",
        )

    def kill(self):
        self.kill_calls += 1

    def wait(self, timeout=None):
        self.wait_calls += 1
        return -9


class ProcessCleanupTests(unittest.TestCase):
    @patch("attack_agent.request_utils.os.killpg")
    def test_cleanup_never_performs_an_unbounded_communicate(self, killpg):
        process = _NeverClosingProcess()

        stdout, stderr, complete = kill_process_group_and_collect(
            process,
            cleanup_timeout=0.01,
        )

        killpg.assert_called_once_with(process.pid, 9)
        self.assertEqual(process.communicate_calls, 1)
        self.assertEqual(stdout, "partial stdout")
        self.assertEqual(stderr, "partial stderr")
        self.assertFalse(complete)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)
        self.assertEqual(process.kill_calls, 1)
        self.assertEqual(process.wait_calls, 1)


if __name__ == "__main__":
    unittest.main()
