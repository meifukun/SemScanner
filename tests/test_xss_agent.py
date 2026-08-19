import shlex
import tempfile
import unittest
from unittest.mock import patch

from attack_agent.xss_agent import XSSAgent


class FakeDriver:
    def __init__(self, xss_array=None):
        self.visited = []
        self.xss_array = list(xss_array or [])

    def get(self, url):
        self.visited.append(url)

    def execute_script(self, script):
        return self.xss_array

    def save_screenshot(self, path):
        return True


class XSSAgentTemplateTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.agent = XSSAgent(
            client=None,
            driver=None,
            log_dir=self.temp_dir.name,
        )

    def test_parses_single_line_without_commands_heading(self):
        output = "curl -X GET 'https://example.test/?q={PAYLOAD}'"

        self.assertEqual(
            self.agent._parse_curl_templates(output),
            [output],
        )

    def test_parses_markdown_fenced_multiline_curl(self):
        output = """### Commands:
```bash
curl -X POST 'https://example.test/settings' \\
-H 'Content-Type: application/x-www-form-urlencoded' \\
-d 'application-notification_urls={PAYLOAD}&save=Save'
```
"""

        templates = self.agent._parse_curl_templates(output)

        self.assertEqual(len(templates), 1)
        self.assertFalse(templates[0].endswith('\\'))
        self.assertIn("application-notification_urls={PAYLOAD}", templates[0])
        self.assertEqual(shlex.split(templates[0])[0], "curl")

    def test_parses_multiple_numbered_commands_and_preserves_order(self):
        output = """Commands:
1. curl 'https://example.test/a?q={PAYLOAD}'
2. curl -X POST 'https://example.test/b' \\
   -d 'name={PAYLOAD}'
3. curl 'https://example.test/c?q={PAYLOAD}'
"""

        templates = self.agent._parse_curl_templates(output)

        self.assertEqual(len(templates), 3)
        self.assertIn("/a?", templates[0])
        self.assertIn("/b", templates[1])
        self.assertIn("/c?", templates[2])

    def test_rejects_incomplete_or_invalid_templates(self):
        output = """Commands:
curl -X POST 'https://example.test/settings' \\
```
curl -X POST -d 'name={PAYLOAD}'
curl 'https://example.test/no-placeholder'
"""

        self.assertEqual(self.agent._parse_curl_templates(output), [])

    def test_payload_injection_preserves_single_quotes(self):
        template = "curl -d 'name={PAYLOAD}&save=1' 'https://example.test/'"
        payload = "';xss(123456);//"

        command = self.agent._inject_payload(template, payload)
        args = shlex.split(command)

        self.assertIn(payload, args[2])
        self.assertEqual(args[-1], "https://example.test/")

    def test_payload_library_is_small_and_context_diverse(self):
        payloads = self.agent._get_xss_payloads(123456)

        self.assertEqual(len(payloads), 10)
        self.assertTrue(payloads[0].startswith("<img src=x onerror="))
        self.assertTrue(any("<svg" in payload for payload in payloads))
        self.assertTrue(any("</textarea>" in payload for payload in payloads))
        self.assertTrue(any("</script>" in payload for payload in payloads))
        self.assertTrue(any(payload.startswith("';") for payload in payloads))
        self.assertTrue(any(payload.startswith('";') for payload in payloads))
        self.assertTrue(any(payload.startswith("-->") for payload in payloads))

    def test_payload_first_pair_order(self):
        pairs = list(self.agent._iter_payload_template_pairs(
            ["payload-1", "payload-2"],
            ["template-a", "template-b"],
        ))

        self.assertEqual(pairs, [
            ("payload-1", "template-a"),
            ("payload-1", "template-b"),
            ("payload-2", "template-a"),
            ("payload-2", "template-b"),
        ])

    def test_stored_xss_candidate_uses_same_origin_referer(self):
        request = {
            "method": "POST",
            "url": "http://example.test/ajax.php?action=save_item",
            "headers": {"Referer": "http://example.test/index.php?page=items"},
        }

        self.assertEqual(
            self.agent._stored_xss_candidate_urls(request),
            ["http://example.test/index.php?page=items"],
        )

    def test_stored_xss_candidate_rejects_cross_origin_and_destructive_referers(self):
        base_request = {
            "method": "POST",
            "url": "http://example.test/ajax.php?action=save_item",
        }

        cross_origin = dict(base_request, headers={"Referer": "http://attacker.test/view"})
        destructive = dict(base_request, headers={"Referer": "http://example.test/logout.php"})

        self.assertEqual(self.agent._stored_xss_candidate_urls(cross_origin), [])
        self.assertEqual(self.agent._stored_xss_candidate_urls(destructive), [])

    def test_immediate_stored_xss_verification_visits_referer_and_checks_array(self):
        driver = FakeDriver(xss_array=[123456])
        agent = XSSAgent(client=None, driver=driver, log_dir=self.temp_dir.name)
        request = {
            "method": "POST",
            "url": "http://example.test/ajax.php?action=save_item",
            "headers": {"referer": "http://example.test/index.php?page=items"},
        }

        triggered = agent._visit_stored_xss_candidates(request, 123456)

        self.assertTrue(triggered)
        self.assertEqual(driver.visited, ["http://example.test/index.php?page=items"])
        self.assertEqual(
            agent.stored_verification_hits[123456],
            "http://example.test/index.php?page=items",
        )

    def test_stage1_immediately_verifies_successful_stored_write(self):
        driver = FakeDriver(xss_array=[123456])
        agent = XSSAgent(client=None, driver=driver, log_dir=self.temp_dir.name)
        agent._generate_curl_templates = lambda request: (
            ["curl -X POST 'http://example.test/ajax.php?action=save_item' -d 'name={PAYLOAD}'"],
            "test analysis",
        )
        agent._get_xss_payloads = lambda random_id: [f"<img src=x onerror=xss({random_id})>"]
        agent._execute_curl_command = lambda command: (
            "HTTP/1.1 200 OK\nContent-Type: text/plain\n\n1",
            "",
            0,
        )
        request = {
            "method": "POST",
            "url": "http://example.test/ajax.php?action=save_item",
            "headers": {"Referer": "http://example.test/index.php?page=items"},
            "response_body": "1",
        }

        with patch("attack_agent.xss_agent.random.randint", return_value=123456):
            result = agent._execute_stage1(request, credentials={})

        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["detection_method"], "immediate_stored_referer")
        self.assertEqual(result["payloads_tested"], 1)


if __name__ == "__main__":
    unittest.main()
