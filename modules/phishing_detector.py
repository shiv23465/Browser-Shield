
"""Browser Shield - Module 1: Phishing URL Detection"""

import ipaddress
from urllib.parse import urlsplit, unquote


MODULE_NAME = "phishing_detection"

SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "verification",
    "account", "password", "update", "wallet",
    "payment", "confirm", "authenticate", "secure"
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co",
    "is.gd", "cutt.ly", "shorturl.at"
}

BRAND_NAMES = {
    "paypal", "google", "microsoft", "apple",
    "amazon", "facebook", "instagram", "netflix"
}


def is_ip_address(hostname):
    """Check whether the hostname is an IP address."""
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


def analyze_phishing_url(raw_url):
    """Analyze URL patterns and return a standardized result."""

    if not isinstance(raw_url, str) or not raw_url.strip():
        return {
            "module": MODULE_NAME,
            "threat": "Phishing",
            "risk_score": 0,
            "status": "Invalid Input",
            "indicators": ["A valid URL string is required."],
            "explanation": "No URL was analyzed.",
            "recommendations": ["Enter a complete URL."]
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

        # Accessing port also detects malformed port syntax.
        _ = parsed.port

    except ValueError:
        return {
            "module": MODULE_NAME,
            "threat": "Phishing",
            "risk_score": 0,
            "status": "Invalid Input",
            "indicators": [
                "URL must be a valid absolute HTTP or HTTPS URL."
            ],
            "explanation": "The URL could not be parsed correctly.",
            "recommendations": ["Check the URL format."]
        }

    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower().rstrip(".")
    authority = parsed.netloc.lower()

    inspected_text = unquote(
        f"{authority} {parsed.path} {parsed.query}"
    ).lower()

    indicators = []
    recommendations = []
    score = 0

    def add_indicator(message, points):
        nonlocal score
        indicators.append(message)
        score += points

    # 1. Connection scheme
    if scheme == "http":
        add_indicator(
            "Connection uses HTTP instead of HTTPS.", 10
        )

    # 2. URL authority can contain misleading user information.
    if "@" in authority:
        add_indicator(
            "URL contains an @ symbol in its authority section.", 25
        )

    # 3. IP address used as hostname
    if is_ip_address(hostname):
        add_indicator(
            "Hostname is an IP address rather than a domain name.", 20
        )

    # 4. Unusually long URL
    if len(url) >= 100:
        add_indicator("URL is unusually long.", 10)

    # 5. Many subdomain levels
    if hostname.count(".") >= 4:
        add_indicator(
            "Hostname contains many subdomain levels.", 10
        )

    # 6. Internationalized/punycode hostname
    if hostname.startswith("xn--") or ".xn--" in hostname:
        add_indicator(
            "Hostname contains a punycode label.", 10
        )

    # 7. Account-related words
    keyword_hits = sorted(
        word for word in SUSPICIOUS_KEYWORDS
        if word in inspected_text
    )

    if keyword_hits:
        add_indicator(
            "Account/security-related words found: "
            + ", ".join(keyword_hits[:5]),
            min(15, 5 + 2 * (len(keyword_hits) - 1))
        )

    # 8. URL shortener
    if hostname in SHORTENER_DOMAINS:
        add_indicator(
            "URL uses a known shortening service.", 10
        )

    # 9. Brand-like text in a hostname
    labels = hostname.split(".")
    brand_hits = sorted(
        brand for brand in BRAND_NAMES
        if any(brand in label for label in labels[:-1])
        and not hostname.endswith("." + brand)
    )

    if brand_hits:
        add_indicator(
            "Hostname contains brand-like text; verify the real domain.",
            10
        )

    score = min(score, 100)

    if score >= 60:
        status = "High Risk"
        recommendations.append(
            "Avoid entering credentials or payment details until verified."
        )
    elif score >= 30:
        status = "Suspicious"
        recommendations.append(
            "Verify the domain through an official website or bookmark."
        )
    elif score > 0:
        status = "Needs Review"
        recommendations.append(
            "Review the indicators before trusting this URL."
        )
    else:
        status = "No URL Red Flags Found"
        recommendations.append(
            "No configured rules matched; safety is not guaranteed."
        )

    return {
        "module": MODULE_NAME,
        "threat": "Phishing",
        "risk_score": score,
        "status": status,
        "indicators": indicators,
        "explanation": (
            f"Rule-based heuristic score: {score}/100. "
            "This is not a probability or a verified threat verdict."
        ),
        "recommendations": recommendations,
        "url": url
    }


# Compatibility with the earlier prototype
def detect_phishing(url):
    return analyze_phishing_url(url)


if __name__ == "__main__":
    print("=" * 50)
    print("       BROWSER SHIELD - PHISHING DETECTOR")
    print("=" * 50)

    user_url = input("Enter URL to analyze: ").strip()
    result = analyze_phishing_url(user_url)

    print("\n--- SCAN RESULT ---")
    print("Module:", result["module"])
    print("Risk Score:", result["risk_score"], "/ 100")
    print("Status:", result["status"])
    print("Explanation:", result["explanation"])

    print("\nIndicators:")
    if result["indicators"]:
        for indicator in result["indicators"]:
            print("-", indicator)
    else:
        print("- No configured indicators matched.")

    print("\nRecommendations:")
    for recommendation in result["recommendations"]:
        print("-", recommendation)
