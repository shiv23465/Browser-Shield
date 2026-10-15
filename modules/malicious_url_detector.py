
"""Browser Shield - Module 2: Malicious URL Detection."""

import ipaddress
import re
from urllib.parse import urlsplit, unquote


MODULE_NAME = "malicious_url_detection"

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".msi", ".bat", ".cmd",
    ".ps1", ".vbs", ".js", ".jar", ".hta"
}

SUSPICIOUS_PATH_WORDS = {
    "payload", "malware", "dropper", "exploit",
    "cmd", "powershell", "download"
}


def is_ip_address(hostname):
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


def analyze_malicious_url(raw_url):
    """Return a transparent heuristic assessment of a URL."""

    if not isinstance(raw_url, str) or not raw_url.strip():
        return {
            "module": MODULE_NAME,
            "threat": "Malicious URL",
            "risk_score": 0,
            "status": "Invalid Input",
            "indicators": ["A non-empty URL is required."],
            "explanation": "No URL was analyzed.",
            "recommendations": ["Enter a complete HTTP or HTTPS URL."]
        }

    url = unquote(raw_url.strip())

    try:
        parsed = urlsplit(url)

        if (
            parsed.scheme.lower() not in {"http", "https"}
            or not parsed.hostname
            or not parsed.netloc
        ):
            raise ValueError("Invalid URL")

        _ = parsed.port

    except ValueError:
        return {
            "module": MODULE_NAME,
            "threat": "Malicious URL",
            "risk_score": 0,
            "status": "Invalid Input",
            "indicators": [
                "URL must be a valid absolute HTTP or HTTPS URL."
            ],
            "explanation": "The URL could not be parsed correctly.",
            "recommendations": ["Check the URL format."]
        }

    hostname = (parsed.hostname or "").lower().rstrip(".")
    path = parsed.path.lower()
    decoded_path = unquote(path)
    full_text = f"{hostname} {decoded_path} {parsed.query}".lower()

    indicators = []
    recommendations = []
    score = 0

    def add_indicator(message, points):
        nonlocal score
        indicators.append(message)
        score += points

    # 1. IP address in place of a domain name
    if is_ip_address(hostname):
        add_indicator("Hostname is an IP address.", 20)

    # 2. Suspicious file extension in URL path
    last_segment = decoded_path.rsplit("/", 1)[-1].lower()
    if any(last_segment.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
        add_indicator(
            "URL path ends with a potentially risky executable or script file extension.",
            25
        )

    # 3. Encoded or repeated URL encoding may obscure the path
    if re.search(r"%[0-9a-fA-F]{2}", raw_url):
        add_indicator("URL contains percent-encoded characters.", 5)

    # 4. Multiple subdomain levels
    if hostname.count(".") >= 4:
        add_indicator("Hostname has many subdomain levels.", 10)

    # 5. Suspicious path terms (weak indicators, not proof)
    path_hits = sorted(word for word in SUSPICIOUS_PATH_WORDS if word in full_text)
    if path_hits:
        add_indicator(
            "Potentially suspicious URL terms found: " + ", ".join(path_hits[:5]),
            min(15, 5 + 2 * (len(path_hits) - 1))
        )

    # 6. Very long URL
    if len(url) >= 150:
        add_indicator("URL is unusually long (150+ characters).", 10)

    # 7. Plain HTTP is a weak contextual signal only
    if parsed.scheme.lower() == "http":
        add_indicator("URL uses HTTP rather than HTTPS.", 5)

    score = min(score, 100)

    if score >= 60:
        status = "High Risk"
        recommendations.append(
            "Avoid opening the link or downloading files until verified."
        )
    elif score >= 30:
        status = "Suspicious"
        recommendations.append(
            "Verify the destination using a trusted source before opening."
        )
    elif score > 0:
        status = "Needs Review"
        recommendations.append(
            "Review the indicators; a low score does not prove safety."
        )
    else:
        status = "No URL Red Flags Found"
        recommendations.append(
            "No configured rules matched; this is not a safety guarantee."
        )

    return {
        "module": MODULE_NAME,
        "threat": "Malicious URL",
        "risk_score": score,
        "status": status,
        "indicators": indicators,
        "explanation": (
            f"Rule-based heuristic score: {score}/100. "
            "This is not a probability or a verified malware verdict."
        ),
        "recommendations": recommendations,
        "url": url
    }


if __name__ == "__main__":
    print("=" * 50)
    print("     BROWSER SHIELD - MALICIOUS URL DETECTOR")
    print("=" * 50)

    user_url = input("Enter URL to analyze: ").strip()
    result = analyze_malicious_url(user_url)

    print("\n--- SCAN RESULT ---")
    print("Risk Score:", result["risk_score"], "/ 100")
    print("Status:", result["status"])
    print("Explanation:", result["explanation"])

    print("\nIndicators:")
    for item in result["indicators"] or ["No configured indicators matched."]:
        print("-", item)

    print("\nRecommendations:")
    for item in result["recommendations"]:
        print("-", item)
