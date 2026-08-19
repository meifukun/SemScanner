import unittest

from utils.url_scope import UrlScope


class UrlScopeTests(unittest.TestCase):
    def setUp(self):
        self.scope = UrlScope(
            "http://web:5000/login",
            request_exception_urls=("http://127.0.0.1:9091/",),
        )

    def test_allows_same_origin_navigation(self):
        self.assertTrue(self.scope.allows_navigation("http://web:5000/settings"))
        self.assertTrue(self.scope.allows_navigation("/preview/123#screenshot"))
        self.assertTrue(self.scope.allows_navigation("?op=pause&uuid=123"))

    def test_normalizes_default_ports(self):
        default_scope = UrlScope("http://web/login.php")
        self.assertTrue(default_scope.allows_navigation("http://web:80/index.php"))

    def test_rejects_external_urls_containing_short_hostname(self):
        rejected = (
            "https://chromewebstore.google.com/example",
            "https://oxylabs.io/products/web-unblocker",
            "https://example.com/?target=web",
            "http://web.evil.example/",
            "http://evil.example/web:5000/settings",
        )
        for url in rejected:
            with self.subTest(url=url):
                self.assertFalse(self.scope.allows_navigation(url))

    def test_rejects_wrong_scheme_or_port(self):
        self.assertFalse(self.scope.allows_navigation("https://web:5000/settings"))
        self.assertFalse(self.scope.allows_navigation("http://web:5001/settings"))

    def test_beacon_is_request_only_exception(self):
        beacon = "http://127.0.0.1:9091/?data=123456"
        self.assertTrue(self.scope.allows_request(beacon))
        self.assertFalse(self.scope.allows_navigation(beacon))

    def test_rejects_non_http_and_userinfo_urls(self):
        self.assertFalse(self.scope.allows_navigation("javascript:alert(1)"))
        self.assertFalse(self.scope.allows_navigation("http://user@web:5000/settings"))


if __name__ == "__main__":
    unittest.main()
