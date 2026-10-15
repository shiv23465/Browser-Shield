

from modules.phishing_detector import analyze_phishing_url
from modules.malicious_url_detector import analyze_malicious_url
from modules.information_stealer_detector import analyze_stealer_risk
from modules.drive_by_download_detector import analyze_download_risk


def analyze_url(url, page_text="", download_metadata=None):
    if not isinstance(url, str) or not url.strip():
        return {
            "project": "Browser Shield",
            "status": "Invalid Input",
            "risk_score": 0,
            "modules_checked": 0,
            "module_results": {},
            "indicators": [],
            "recommendations": ["Please provide a valid URL."],
        }

    metadata = dict(download_metadata or {})
    metadata.pop("url", None)

    results = {
        "phishing_detection": analyze_phishing_url(url),
        "malicious_url_detection": analyze_malicious_url(url),
        "information_stealer_detection": analyze_stealer_risk(
            url, page_text
        ),
        "drive_by_download_detection": analyze_download_risk(
            url, **metadata
        ),
    }

    scores = [
        max(0, min(100, int(result.get("risk_score", 0))))
        for result in results.values()
    ]

    baseline = max(scores, default=0)
    supporting_modules = sum(score >= 30 for score in scores)
    combined_score = min(
        100, baseline + max(0, supporting_modules - 1) * 5
    )

    if any(
        result.get("status") == "Invalid Input"
        for result in results.values()
    ):
        status = "Invalid Input"
    elif combined_score >= 60:
        status = "High Risk"
    elif combined_score >= 30:
        status = "Suspicious"
    elif combined_score > 0:
        status = "Needs Review"
    else:
        status = "No Configured Red Flags Found"

    indicators = []
    recommendations = []

    for module_name, result in results.items():
        for indicator in result.get("indicators", []):
            item = f"{module_name}: {indicator}"
            if item not in indicators:
                indicators.append(item)

        for recommendation in result.get("recommendations", []):
            if recommendation not in recommendations:
                recommendations.append(recommendation)

    return {
        "project": "Browser Shield",
        "status": status,
        "risk_score": combined_score,
        "modules_checked": len(results),
        "module_results": results,
        "indicators": indicators,
        "recommendations": recommendations,
    }


if __name__ == "__main__":
    report = analyze_url("https://example.com/")
    print("Browser Shield - Combined Risk Report")
    print("Status:", report["status"])
    print("Risk score:", report["risk_score"])
    print("Modules checked:", report["modules_checked"])

    for name, result in report["module_results"].items():
        print(
            name,
            "=>",
            result.get("status"),
            result.get("risk_score"),
        )