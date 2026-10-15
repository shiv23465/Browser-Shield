
import unittest

from modules.drive_by_download_detector import analyze_download_risk


class TestDriveByDownloadDetector(unittest.TestCase):

    def test_invalid_url(self):
        result = analyze_download_risk("hello")
        self.assertEqual(result["status"], "Invalid Input")

    def test_normal_url(self):
        result = analyze_download_risk("https://example.com/")
        self.assertEqual(result["risk_score"], 0)

    def test_executable_file(self):
        result = analyze_download_risk(
            "https://example.com/installer.exe",
            filename="installer.exe"
        )
        self.assertIn(
            "Executable or script extension: .exe",
            result["indicators"]
        )

    def test_archive_file(self):
        result = analyze_download_risk(
            "https://example.com/archive.zip",
            filename="archive.zip"
        )
        self.assertIn(
            "Archive extension: .zip",
            result["indicators"]
        )

    def test_unexpected_download(self):
        result = analyze_download_risk(
            "https://example.com/report.pdf",
            filename="report.pdf",
            user_initiated=False
        )
        self.assertIn(
            "Download not marked as user-initiated",
            result["indicators"]
        )

    def test_payload_url(self):
        result = analyze_download_risk(
            "https://example.com/payload"
        )
        self.assertIn(
            "Suspicious URL term: payload",
            result["indicators"]
        )

    def test_negative_file_size(self):
        result = analyze_download_risk(
            "https://example.com/file",
            file_size=-1
        )
        self.assertEqual(result["status"], "Invalid Input")

    def test_result_schema(self):
        result = analyze_download_risk("https://example.com/")
        expected_keys = [
            "module",
            "threat",
            "risk_score",
            "status",
            "indicators",
            "explanation",
            "recommendations",
            "url",
            "filename"
        ]

        for key in expected_keys:
            self.assertIn(key, result)


if __name__ == "__main__":
    unittest.main()
