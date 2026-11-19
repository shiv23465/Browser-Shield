
from modules.phishing_detector import analyze_phishing_url
from modules.malicious_url_detector import analyze_malicious_url
from modules.information_stealer_detector import analyze_stealer_risk
from modules.drive_by_download_detector import analyze_download_risk
from modules.urlhaus_client import check_urlhaus
from backend.database import save_threat_intelligence


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

    # Run existing detection modules
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

    # URLhaus Threat Intelligence Integration
    urlhaus_result = check_urlhaus(url)

        # Save URLhaus threat into SQLite
    if urlhaus_result.get("is_malicious") is True:
        save_threat_intelligence(url, urlhaus_result)

    if urlhaus_result.get("is_malicious") is True:

        urlhaus_result["risk_score"] = 100

        urlhaus_result["indicators"] = [
            "URL matched in URLhaus threat intelligence database."
        ]

        urlhaus_result["recommendations"] = [
            "Do not visit this known malicious URL."
        ]

    else:
        urlhaus_result["risk_score"] = 0

        urlhaus_result["indicators"] = []

        urlhaus_result["recommendations"] = [
            "No URLhaus match found. This does not guarantee safety."
        ]

    # Add URLhaus to module results
    results["urlhaus_threat_intelligence"] = urlhaus_result

    # Calculate combined risk score
    scores = [
        max(0, min(100, int(result.get("risk_score", 0))))
        for result in results.values()
    ]

    baseline = max(scores, default=0)

    supporting_modules = sum(
        score >= 30 for score in scores
    )

    combined_score = min(
        100,
        baseline + max(0, supporting_modules - 1) * 5
    )

    # Determine overall status
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

    # Collect indicators and recommendations
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

    # API availability information
    urlhaus_status = urlhaus_result.get("status")

    if urlhaus_status in ("API Error", "API Key Missing"):
        recommendations.append(
            "URLhaus verification was unavailable. "
            "The URL has not been verified against this threat source."
        )

    # Final report
    return {
        "project": "Browser Shield",
        "status": status,
        "risk_score": combined_score,
        "modules_checked": len(results),
        "module_results": results,
        "indicators": indicators,
        "recommendations": recommendations,
        "threat_intelligence": {
            "urlhaus": urlhaus_status,
            "verified": urlhaus_status in ("Threat Found", "No Match"),
        },
    }


if __name__ == "__main__":

    report = analyze_url("https://example.com/")

    print("\nBrowser Shield - Combined Risk Report")
    print("-------------------------------------")

    print("Status:", report["status"])
    print("Risk score:", report["risk_score"])
    print("Modules checked:", report["modules_checked"])

    print("\nThreat Intelligence:")
    print(report["threat_intelligence"])

    print("\nIndividual Module Results:")

    for name, result in report["module_results"].items():

        print(
            name,
            "=>",
            result.get("status"),
            result.get("risk_score"),
        )
