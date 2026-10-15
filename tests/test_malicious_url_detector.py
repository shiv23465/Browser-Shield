
import unittest
from modules.malicious_url_detector import analyze_malicious_url


class TestMaliciousURLDetector(unittest.TestCase):

    def test_empty_input(self):
        result = analyze_malicious_url("")
        self.assertEqual(result["status"], "Invalid Input")

    def test_http_url(self):
        result = analyze_malicious_url("http://example.com/")
        self.assertGreater(result["risk_score"], 0)

    def test_ip_address(self):
        result = analyze_malicious_url("http://192.0.2.1/sample.exe")
        self.assertTrue(
            any("IP address" in item for item in result["indicators"])
        )

    def test_risky_extension(self):
        result = analyze_malicious_url("https://example.com/sample.exe")
        self.assertTrue(
            any("file extension" in item for item in result["indicators"])
        )

    def test_common_output(self):
        result = analyze_malicious_url("https://example.com/")
        self.assertIn("risk_score", result)
        self.assertIn("status", result)
        self.assertIn("indicators", result)


if __name__ == "__main__":
    unittest.main()
