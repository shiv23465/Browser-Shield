import unittest
from modules.phishing_detector import analyze_phishing_url

class TestPhishingDetection(unittest.TestCase):

    def test_invalid_input(self):
        result = analyze_phishing_url("")
        self.assertEqual(result["status"], "Invalid Input")

    def test_http_url(self):
        result = analyze_phishing_url("http://example.com/")
        self.assertGreater(result["risk_score"], 0)

    def test_ip_address(self):
        result = analyze_phishing_url("http://192.0.2.1/login")
        self.assertTrue(
            any("IP address" in item for item in result["indicators"])
        )

    def test_result_schema(self):
        result = analyze_phishing_url("https://example.com/")
        self.assertIn("risk_score", result)
        self.assertIn("status", result)
        self.assertIn("indicators", result)

if __name__ == "__main__":
    unittest.main()
