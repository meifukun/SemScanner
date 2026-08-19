import unittest

from attack_agent.business_logic_agent import BusinessLogicAgent


class BusinessLogicCurlTests(unittest.TestCase):
    def test_prepare_curl_args_preserves_request(self):
        agent = BusinessLogicAgent.__new__(BusinessLogicAgent)
        agent._log = lambda *args: None

        args = agent._prepare_curl_args(
            "curl --compressed -s -i http://example.test/",
        )

        self.assertEqual(
            args,
            ["curl", "--compressed", "-s", "-i", "http://example.test/"],
        )


if __name__ == "__main__":
    unittest.main()
