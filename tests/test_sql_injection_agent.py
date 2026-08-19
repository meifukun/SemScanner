import tempfile
import unittest
from pathlib import Path
import subprocess
from unittest.mock import Mock, patch

from attack_agent.sql_injection_agent import SQLInjectionAgent, classify_sqlmap_output


def _agent_without_init(temp_dir: str) -> SQLInjectionAgent:
    agent = SQLInjectionAgent.__new__(SQLInjectionAgent)
    agent._log_path = Path(temp_dir) / "sql_agent.log"
    return agent


class SQLInjectionAgentRequestFileTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.agent = _agent_without_init(self.temp_dir.name)

    def test_request_file_strips_gpt4o_markdown_hard_break_spaces(self):
        output = "\n".join([
            "Analysis:  ",
            "Multipart request.  ",
            "",
            "Request_File_Content:  ",
            "POST /ajax.php?action=save_plan HTTP/1.1  ",
            "Host: 127.0.0.1:8082  ",
            "Content-Type: multipart/form-data; boundary=----Boundary123  ",
            "  ",
            "------Boundary123  ",
            'Content-Disposition: form-data; name="id"  ',
            "  ",
            "1  ",
            "------Boundary123--  ",
            "",
            "SQLMap_Command:  ",
            f'sqlmap -r "{self.temp_dir.name}/target.req" --batch -v 6 --risk=3 --flush-session  ',
            "",
        ])

        command = self.agent._parse_and_handle_file(output, self.temp_dir.name)

        self.assertTrue(command.startswith("sqlmap -r "))
        content = (Path(self.temp_dir.name) / "target.req").read_text(encoding="utf-8")
        self.assertEqual(
            content.splitlines()[0],
            "POST /ajax.php?action=save_plan HTTP/1.1",
        )
        self.assertTrue(all(line == line.rstrip(" \t") for line in content.splitlines()))

    def test_request_file_rejects_malformed_request_line(self):
        output = f"""Request_File_Content:
POST /ajax.php?action=save_plan HTTP/1.1 extra
Host: 127.0.0.1:8082

id=1

SQLMap_Command:
sqlmap -r "{self.temp_dir.name}/target.req" --batch
"""

        self.assertEqual(
            self.agent._parse_and_handle_file(output, self.temp_dir.name),
            "",
        )
        self.assertFalse((Path(self.temp_dir.name) / "target.req").exists())

    def test_sqlmap_unusable_request_is_execution_error(self):
        stdout = "[CRITICAL] specified file 'target.req' does not contain a usable HTTP request (with parameters)"

        error = self.agent._detect_sqlmap_execution_error(stdout, "")

        self.assertEqual(
            error,
            "SQLMap execution failed: does not contain a usable http request",
        )

    def test_normal_negative_sqlmap_conclusion_is_not_execution_error(self):
        stdout = "[CRITICAL] all tested parameters do not appear to be injectable"

        self.assertEqual(self.agent._detect_sqlmap_execution_error(stdout, ""), "")


class SQLMapOutputClassificationTests(unittest.TestCase):
    def test_complete_identified_finding_is_positive(self):
        stdout = """sqlmap identified the following injection point(s) with a total of 42 HTTP(s) requests:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: username=admin' AND 1=1-- -
---
[INFO] the back-end DBMS is SQLite
"""

        result = classify_sqlmap_output(stdout)

        self.assertIs(result["vulnerable"], True)
        self.assertIn("username (POST)", result["evidence"])

    def test_complete_resumed_finding_is_positive(self):
        stdout = """sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: id=-1 UNION ALL SELECT NULL,NULL,NULL-- -
---
"""

        self.assertIs(classify_sqlmap_output(stdout)["vulnerable"], True)

    def test_positive_header_and_parameter_are_positive_without_optional_details(self):
        stdout = """sqlmap identified the following injection point(s) with a total of 42 HTTP(s) requests:
---
Parameter: username (POST)
"""

        self.assertIs(classify_sqlmap_output(stdout)["vulnerable"], True)

    def test_positive_header_without_parameter_is_not_overridden_by_negative_text(self):
        stdout = """[CRITICAL] all tested parameters do not appear to be injectable.
sqlmap identified the following injection point(s) with a total of 42 HTTP(s) requests:
---
"""

        self.assertIsNone(classify_sqlmap_output(stdout)["vulnerable"])

    def test_explicit_all_parameters_negative_is_negative(self):
        stdout = "[CRITICAL] all tested parameters do not appear to be injectable."

        self.assertIs(classify_sqlmap_output(stdout)["vulnerable"], False)

    def test_incomplete_execution_is_inconclusive(self):
        stdout = "[INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'"

        self.assertIsNone(classify_sqlmap_output(stdout)["vulnerable"])

    def test_false_positive_injection_point_message_is_inconclusive(self):
        stdout = """[INFO] checking if the injection point on parameter 'id' is a false positive
[WARNING] false positive or unexploitable injection point detected
"""

        self.assertIsNone(classify_sqlmap_output(stdout)["vulnerable"])

    def test_structured_appears_to_be_injectable_signal_is_positive(self):
        stdout = """[13:42:25] [INFO] POST parameter 'id' appears to be 'Boolean-based blind - Parameter replace (original value)' injectable
[13:49:56] [CRITICAL] connection timed out to the target URL
"""

        result = classify_sqlmap_output(stdout)

        self.assertIs(result["vulnerable"], True)
        self.assertEqual(
            result["detection_method"],
            "sqlmap_structured_injection_signal",
        )
        self.assertIn("POST Parameter: id", result["evidence"])

    def test_structured_signal_allows_sqlmap_comparison_suffix(self):
        stdout = """[15:06:56] [INFO] GET parameter 'classCode' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --string="sit")
"""

        self.assertIs(classify_sqlmap_output(stdout)["vulnerable"], True)

    def test_later_false_positive_rejection_overrides_structured_signal(self):
        stdout = """[13:42:25] [INFO] POST parameter 'id' appears to be 'Boolean-based blind' injectable
[13:42:30] [INFO] checking if the injection point on POST parameter 'id' is a false positive
[13:42:35] [WARNING] false positive or unexploitable injection point detected
"""

        self.assertIsNone(classify_sqlmap_output(stdout)["vulnerable"])

    def test_later_final_negative_overrides_structured_signal(self):
        stdout = """[13:42:25] [INFO] POST parameter 'id' appears to be 'Boolean-based blind' injectable
[13:42:35] [CRITICAL] all tested parameters do not appear to be injectable
"""

        self.assertIs(classify_sqlmap_output(stdout)["vulnerable"], False)
        self.assertIsNone(
            classify_sqlmap_output(stdout, allow_negative=False)["vulnerable"]
        )

    def test_partial_execution_cannot_be_classified_negative(self):
        stdout = "[CRITICAL] all tested parameters do not appear to be injectable."

        self.assertIsNone(
            classify_sqlmap_output(stdout, allow_negative=False)["vulnerable"]
        )

    def test_complete_positive_finding_takes_priority_over_negative_marker(self):
        stdout = """[CRITICAL] all tested parameters do not appear to be injectable.
sqlmap identified the following injection point(s) with a total of 15 HTTP(s) requests:
---
Parameter: item (POST)
    Type: error-based
    Title: MySQL error-based
    Payload: item=1'
---
"""

        self.assertIs(classify_sqlmap_output(stdout)["vulnerable"], True)


class SQLMapTimeoutClassificationTests(unittest.TestCase):
    @patch("attack_agent.sql_injection_agent.kill_process_group_and_collect")
    @patch("attack_agent.sql_injection_agent.subprocess.Popen")
    def test_framework_timeout_preserves_confirmed_partial_finding(self, popen, cleanup):
        process = Mock()
        process.communicate.side_effect = subprocess.TimeoutExpired("sqlmap", 1)
        popen.return_value = process
        cleanup.return_value = (
            """sqlmap identified the following injection point(s) with a total of 42 HTTP(s) requests:
---
Parameter: id (POST)
""",
            "",
            True,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            agent = _agent_without_init(temp_dir)
            with patch.dict("os.environ", {"SEMSCANNER_SQLMAP_TIMEOUT": "1"}):
                result = agent._execute_sqlmap(
                    "sqlmap -u http://example.invalid/?id=1",
                    Path(temp_dir) / "sqlmap.log",
                )

        self.assertIs(result["vulnerable"], True)
        self.assertTrue(result["timeout"])
        self.assertNotIn("error", result)
        self.assertIn("warning", result)

    @patch("attack_agent.sql_injection_agent.kill_process_group_and_collect")
    @patch("attack_agent.sql_injection_agent.subprocess.Popen")
    def test_framework_timeout_preserves_structured_candidate_signal(self, popen, cleanup):
        process = Mock()
        process.communicate.side_effect = subprocess.TimeoutExpired("sqlmap", 1)
        popen.return_value = process
        cleanup.return_value = (
            """[13:42:25] [INFO] POST parameter 'id' appears to be 'Boolean-based blind' injectable
""",
            "",
            True,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            agent = _agent_without_init(temp_dir)
            with patch.dict("os.environ", {"SEMSCANNER_SQLMAP_TIMEOUT": "1"}):
                result = agent._execute_sqlmap(
                    "sqlmap -u http://example.invalid/?id=1",
                    Path(temp_dir) / "sqlmap.log",
                )

        self.assertIs(result["vulnerable"], True)
        self.assertTrue(result["timeout"])
        self.assertNotIn("error", result)


if __name__ == "__main__":
    unittest.main()
